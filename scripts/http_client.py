"""Bounded HTTPS transport with validators, retry/backoff and safe Range resume."""
import hashlib
import http.client
import json
import os
import socket
import time
import re
import urllib.error
import urllib.request
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from urllib.parse import urlparse

from scripts.common import write_json, read_json


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlparse(newurl).scheme != 'https':
            raise ValueError('Insecure source redirect')
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and urlparse(newurl).netloc != urlparse(req.full_url).netloc:
            for name in list(redirected.headers):
                if name.lower() in ('authorization', 'apikey'):
                    redirected.remove_header(name)
        return redirected


class Client:
    def __init__(self, cache, timeout=45, retries=2, sleep=time.sleep, opener=None):
        self.cache = cache
        cache.mkdir(parents=True, exist_ok=True)
        self.timeout, self.retries, self.sleep = timeout, retries, sleep
        self.opener = opener or urllib.request.build_opener(SafeRedirect()).open
        self.last_request = {}

    def get(self, url, headers=None, limit=250 * 1024 * 1024, interval=0):
        if urlparse(url).scheme != 'https':
            raise ValueError('Only HTTPS sources are allowed')
        key = hashlib.sha256(url.encode()).hexdigest()
        target, part, meta_path = [self.cache / (key + suffix) for suffix in ('.body', '.part', '.json')]
        meta = read_json(meta_path, {})
        for attempt in range(self.retries + 1):
            request_headers = {'User-Agent': 'tempest-cve-intelligence/2.0', **(headers or {})}
            size = part.stat().st_size if part.exists() else 0
            # Resume only when the partial representation has a strong validator.
            validator = meta.get('partial_etag')
            if size and validator and not validator.startswith('W/'):
                request_headers.update({'Range': f'bytes={size}-', 'If-Range': validator})
            else:
                size = 0
                if target.exists() and meta.get('etag'):
                    request_headers['If-None-Match'] = meta['etag']
                elif target.exists() and meta.get('modified'):
                    request_headers['If-Modified-Since'] = meta['modified']
            host = urlparse(url).netloc
            self.sleep(max(0, interval - (time.monotonic() - self.last_request.get(host, 0))))
            try:
                self.last_request[host] = time.monotonic()
                with self.opener(urllib.request.Request(url, headers=request_headers), timeout=self.timeout) as response:
                    if urlparse(response.geturl()).scheme != 'https':
                        raise ValueError('Insecure source redirect')
                    resumed = response.status == 206
                    if resumed and (not size or not response.headers.get('Content-Range', '').startswith(f'bytes {size}-') or response.headers.get('ETag') != validator):
                        raise ValueError('Invalid range response')
                    range_match = re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)', response.headers.get('Content-Range', '')) if resumed else None
                    if resumed and (not range_match or int(range_match[3]) != int(range_match[2]) + 1):
                        raise ValueError('Incomplete resumed range')
                    if not resumed:
                        size = 0
                    meta['partial_etag'] = response.headers.get('ETag')
                    write_json(meta_path, meta)
                    received = 0
                    with part.open('ab' if resumed else 'wb') as output:
                        while chunk := response.read(1024 * 1024):
                            received += len(chunk)
                            if size + received > limit:
                                raise ValueError('Download exceeds configured bound')
                            output.write(chunk)
                    length = response.headers.get('Content-Length')
                    if length is not None and received != int(length):
                        raise OSError('Incomplete response')
                    if resumed and size + received != int(range_match[3]):
                        raise OSError('Incomplete resumed representation')
                    if part.stat().st_size == 0:
                        raise ValueError('Empty response')
                    os.replace(part, target)
                    write_json(meta_path, {'etag': response.headers.get('ETag'), 'modified': response.headers.get('Last-Modified'), 'sha256': hashlib.sha256(target.read_bytes()).hexdigest()})
                    return target
            except urllib.error.HTTPError as exc:
                if exc.code == 304 and target.exists():
                    if hashlib.sha256(target.read_bytes()).hexdigest() != meta.get('sha256'):
                        raise ValueError('Cached response integrity failure')
                    return target
                if exc.code == 416:
                    part.unlink(missing_ok=True)
                    meta.pop('partial_etag', None)
                elif exc.code not in (403, 408, 429, 500, 502, 503, 504):
                    raise
                if attempt == self.retries:
                    raise
                delay = 2 ** (attempt + 1)
                retry_after = exc.headers.get('Retry-After')
                reset = exc.headers.get('X-RateLimit-Reset')
                try:
                    if retry_after:
                        delay = float(retry_after) if retry_after.isdigit() else (parsedate_to_datetime(retry_after) - datetime.now(timezone.utc)).total_seconds()
                    elif reset:
                        delay = float(reset) - time.time()
                except (ValueError, TypeError):
                    pass
                # Do not violate a rate limit by retrying before a long requested wait.
                if delay > 120:
                    raise RuntimeError('Rate limit wait exceeds run budget; retry next run') from None
                self.sleep(max(0, delay))
            except (OSError, socket.timeout, http.client.HTTPException):
                if attempt == self.retries:
                    raise
                self.sleep(2 ** (attempt + 1))

    def json(self, url, **kwargs):
        return json.loads(self.get(url, **kwargs).read_text(encoding='utf-8-sig'))

    def post_json(self, url, payload):
        if url != 'https://api.osv.dev/v1/query':
            raise ValueError('Unsupported query endpoint')
        for attempt in range(self.retries + 1):
            try:
                request = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json', 'User-Agent': 'tempest-cve-intelligence/2.0'})
                with self.opener(request, timeout=self.timeout) as response:
                    body = response.read(8 * 1024 * 1024 + 1)
                    if len(body) > 8 * 1024 * 1024:
                        raise ValueError('OSV response exceeds bound')
                    result = json.loads(body)
                    if not isinstance(result, dict):
                        raise ValueError('Invalid OSV query result')
                    return result
            except urllib.error.HTTPError as exc:
                if exc.code not in (429, 500, 502, 503, 504) or attempt == self.retries:
                    raise
                delay = exc.headers.get('Retry-After', str(2 ** (attempt + 1)))
                if not delay.isdigit() or int(delay) > 120:
                    raise RuntimeError('OSV retry deferred') from None
                self.sleep(int(delay))
            except (OSError, http.client.HTTPException):
                if attempt == self.retries:
                    raise
                self.sleep(2 ** (attempt + 1))

    def prune(self, retention_days=7, max_bytes=512 * 1024 * 1024):
        """Retain bounded regenerable HTTP snapshots; source database is never pruned."""
        cutoff = time.time() - retention_days * 86400
        files = sorted((p for p in self.cache.iterdir() if p.is_file() and re.fullmatch(r'[a-f0-9]{64}\.(body|json|part)', p.name)), key=lambda p: p.stat().st_mtime)
        total = sum(p.stat().st_size for p in files)
        for path in files:
            size = path.stat().st_size
            if path.stat().st_mtime < cutoff or total > max_bytes:
                path.unlink()
                total -= size

#!/usr/bin/env python3
"""Validate, package and publish recoverable monthly dataset releases."""
import argparse
import calendar
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import quote, urlencode

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.common import ROOT, digest, encode, read_json, write_json, safe_id
from scripts.http_client import SafeRedirect
from scripts.normalize import normalize
from scripts.store import connect, validate_record

IST = timezone(timedelta(hours=5, minutes=30))
MAX_ASSET = 1024 * 1024 * 1024  # Conservative 1 GiB ceiling, below GitHub's 2 GiB.
PART_BYTES = 128 * 1024 * 1024
MAX_RECORD = 45 * 1024 * 1024
MAX_ASSETS = 900  # GitHub permits up to 1,000 assets per release.
MAX_TOTAL_ASSETS = 4 * 1024 * 1024 * 1024
NOTICE_URLS = {
    'cwe': 'https://cwe.mitre.org/about/termsofuse.html',
    'capec': 'https://capec.mitre.org/about/termsofuse.html',
    'attack-enterprise': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/LICENSE.txt',
    'attack-ics': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/LICENSE.txt',
    'github-advisories': 'https://raw.githubusercontent.com/github/advisory-database/main/LICENSE.md',
    'cisa-kev': 'https://raw.githubusercontent.com/cisagov/kev-data/main/LICENSE',
}
OSV_NOTICE_URLS = {
    'GHSA-': ('github-LICENSE.md', 'https://raw.githubusercontent.com/github/advisory-database/main/LICENSE.md'),
    'PYSEC-': ('pypa-LICENSE', 'https://raw.githubusercontent.com/pypa/advisory-database/main/LICENSE'),
}


def utc(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Timestamp must include a timezone')
    return result.astimezone(timezone.utc)


def version(moment):
    if moment.tzinfo is None:
        raise ValueError('Release timestamp requires timezone')
    local = moment.astimezone(IST)
    return local.strftime('%Y.%m'), 'v' + local.strftime('%Y.%m'), f'THREAT-BASE — {calendar.month_name[local.month]} {local.year}'


def file_hash(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


class APIError(RuntimeError):
    def __init__(self, status):
        self.status = status
        super().__init__(f'GitHub API HTTP {status}; check permissions, rate limits and release/tag rules')


class GitHub:
    def __init__(self, repository, token, opener=None, sleep=time.sleep):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
            raise ValueError('Invalid repository name')
        self.repository, self.base = repository, '/repos/' + repository
        self.token, self.sleep = token, sleep
        self.open = opener or urllib.request.build_opener(SafeRedirect()).open

    def request(self, path, payload=None, method=None, missing_ok=False):
        if not path.startswith(self.base + '/') and path != self.base:
            raise ValueError('Cross-repository API request refused')
        method = method or ('POST' if payload is not None else 'GET')
        # GET/PATCH are repeatable. Ambiguous creation POSTs recover through GET.
        attempts = 3 if method in ('GET', 'PATCH') else 1
        for attempt in range(attempts):
            try:
                headers = self.headers()
                req = urllib.request.Request('https://api.github.com' + path,
                    data=encode(payload) if payload is not None else None, headers=headers, method=method)
                with self.open(req, timeout=60) as response:
                    body = response.read(8 * 1024 * 1024 + 1)
                    if len(body) > 8 * 1024 * 1024:
                        raise ValueError('GitHub JSON response too large')
                    return json.loads(body)
            except urllib.error.HTTPError as exc:
                status, headers = exc.code, exc.headers
                exc.close()
                if status == 404 and missing_ok and method == 'GET':
                    return None
                if status not in (403, 408, 429, 500, 502, 503, 504) or attempt == attempts - 1:
                    raise APIError(status) from None
                wait = headers.get('Retry-After')
                reset = headers.get('X-RateLimit-Reset')
                delay = 2 ** (attempt + 1)
                if wait:
                    delay = float(wait) if wait.isdigit() else (parsedate_to_datetime(wait) - datetime.now(timezone.utc)).total_seconds()
                elif reset:
                    delay = float(reset) - time.time()
                elif status == 403:
                    raise APIError(status) from None
                if delay > 120:
                    raise APIError(status) from None
                self.sleep(max(0, delay))
            except OSError:
                if attempt == attempts - 1:
                    raise RuntimeError('GitHub connection failed; rerun after checking connectivity') from None
                self.sleep(2 ** (attempt + 1))

    def headers(self):
        return {'Authorization': 'Bearer ' + self.token, 'User-Agent': 'threat-base-release',
                'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json',
                'X-GitHub-Api-Version': '2022-11-28'}

    def assets(self, release_id):
        result, page = [], 1
        while True:
            rows = self.request(f'{self.base}/releases/{int(release_id)}/assets?per_page=100&page={page}')
            if not isinstance(rows, list):
                raise ValueError('Invalid release asset list')
            result.extend(rows)
            if len(rows) < 100:
                return result
            if len(result) >= 1000:
                raise ValueError('Release asset listing exceeds budget')
            page += 1

    def download(self, asset_id, target, limit=MAX_ASSET):
        target = Path(target)
        partial = target.with_suffix(target.suffix + '.part')
        try:
            for attempt in range(3):
                try:
                    req = urllib.request.Request(f'https://api.github.com{self.base}/releases/assets/{int(asset_id)}',
                        headers={**self.headers(), 'Accept': 'application/octet-stream'})
                    received = 0
                    with self.open(req, timeout=60) as response, partial.open('wb') as output:
                        for chunk in iter(lambda: response.read(1024 * 1024), b''):
                            received += len(chunk)
                            if received > limit:
                                raise ValueError('Downloaded asset exceeds bound')
                            output.write(chunk)
                        if response.headers.get('Content-Length') and received != int(response.headers['Content-Length']):
                            raise OSError('Interrupted asset download')
                    partial.replace(target)
                    return
                except urllib.error.HTTPError as exc:
                    code = exc.code
                    exc.close()
                    raise APIError(code) from None
                except OSError:
                    if attempt == 2:
                        raise RuntimeError('Interrupted asset download; draft retained') from None
                    self.sleep(2 ** (attempt + 1))
        finally:
            partial.unlink(missing_ok=True)

    def upload(self, release_id, path):
        path = Path(path)
        if not 0 < path.stat().st_size < MAX_ASSET:
            raise ValueError('Release asset violates size budget')
        url = f'https://uploads.github.com{self.base}/releases/{int(release_id)}/assets?' + urlencode({'name': path.name})
        with path.open('rb') as stream:
            req = urllib.request.Request(url, data=stream, method='POST', headers={**self.headers(),
                'Content-Type': 'application/octet-stream', 'Content-Length': str(path.stat().st_size)})
            try:
                with self.open(req, timeout=180) as response:
                    return json.loads(response.read(2 * 1024 * 1024))
            except urllib.error.HTTPError as exc:
                code = exc.code
                exc.close()
                raise APIError(code) from None


def latest_sync(api, branch, commit, moment):
    repo = api.request(api.base)
    if repo['full_name'].lower() != api.repository.lower() or repo['default_branch'] != branch:
        raise ValueError('Repository/default branch identity mismatch')
    result = api.request(api.base + '/actions/workflows/sync.yml/runs?' + urlencode({'branch': branch, 'per_page': 1}))
    runs = result['workflow_runs']
    if not runs:
        raise ValueError('No daily synchronization run exists; run sync.yml successfully first')
    run = runs[0]
    if run['status'] != 'completed' or run['conclusion'] != 'success' or run['event'] not in ('schedule', 'workflow_dispatch'):
        raise ValueError('Latest daily synchronization is not completed/successful; resolve it before release')
    if run['head_branch'] != branch or run['head_repository']['full_name'].lower() != api.repository.lower():
        raise ValueError('Daily sync belongs to another branch or repository')
    if not re.fullmatch(r'[a-f0-9]{40}', run['head_sha']):
        raise ValueError('Invalid daily-sync commit')
    if not timedelta(0) <= moment - utc(run['updated_at']) <= timedelta(hours=36):
        raise ValueError('Latest successful daily synchronization is stale')
    # Data bot commits may follow the run's original checkout; unrelated later code is not validated by that run.
    if run['head_sha'] != commit:
        compare = api.request(api.base + f'/compare/{run["head_sha"]}...{commit}')
        if compare['status'] not in ('ahead', 'identical'):
            raise ValueError('Release commit is not a descendant of the successful sync')
        # The compare API truncates file lists; inspect the complete checked-out history instead.
        subprocess.run(['git', 'merge-base', '--is-ancestor', run['head_sha'], commit], check=True, capture_output=True)
        paths = subprocess.check_output(['git', 'diff', '--name-only', '-z', run['head_sha'], commit]).decode().split('\0')
        if any(path and not path.startswith(('data/curated/', 'data/cisa-kev/', 'metadata/')) for path in paths):
            raise ValueError('Code/config changed since successful sync; rerun daily sync before release')
    return {key: run[key] for key in ('id', 'run_attempt', 'head_sha', 'run_started_at', 'updated_at')}


def verify_published(api, release):
    assets = api.assets(release['id'])
    names = {asset['name']: asset for asset in assets}
    if release.get('prerelease') or not {'manifest.json', 'SHA256SUMS'} <= names.keys():
        raise ValueError('Existing published release lacks expected metadata; nothing will be overwritten')
    with tempfile.TemporaryDirectory() as temp:
        manifest_path = Path(temp) / 'manifest.json'
        api.download(names['manifest.json']['id'], manifest_path, limit=8 * 1024 * 1024)
        manifest = read_json(manifest_path)
        sums_path = Path(temp) / 'SHA256SUMS'
        api.download(names['SHA256SUMS']['id'], sums_path, limit=1024 * 1024)
        checksums = parse_sums(sums_path.read_text())
        if checksums.get('manifest.json') != file_hash(manifest_path) or not manifest.get('assets') or manifest.get('tag') != release['tag_name']:
            raise ValueError('Existing published release manifest/checksums are invalid')
        for item in manifest['assets']:
            remote = names.get(item['name'])
            if not remote or remote['state'] != 'uploaded' or remote['size'] != item['bytes'] or checksums.get(item['name']) != item['sha256']:
                raise ValueError('Existing published release has missing/incomplete assets; manual review required')
            if remote.get('digest') and remote['digest'] != 'sha256:' + item['sha256']:
                raise ValueError('Published asset digest mismatch')
            if not remote.get('digest'):
                downloaded = Path(temp) / 'asset'
                api.download(remote['id'], downloaded)
                if file_hash(downloaded) != item['sha256']:
                    raise ValueError('Published asset checksum mismatch')


def plan_release(api, branch, commit, moment):
    if not re.fullmatch(r'[a-f0-9]{40}', commit):
        raise ValueError('Release target must be an immutable SHA')
    number, tag, title = version(moment)
    # Public duplicate check is safe and precedes the state-cache requirement.
    release = api.request(api.base + '/releases/tags/' + tag, missing_ok=True)
    if release and not release['draft']:
        verify_published(api, release)
        return {'skip': True, 'tag': tag, 'result': 'already published'}
    run = latest_sync(api, branch, commit, moment)
    if not release and api.request(api.base + '/git/ref/tags/' + tag, missing_ok=True):
        raise ValueError('Version tag already exists without a release; no tag will be changed')
    snapshot_at = moment.isoformat()
    if release:
        stamp = re.search(r'^Snapshot \(UTC\): ([^\r\n]+)$', release.get('body') or '', re.MULTILINE)
        if release.get('target_commitish') != commit or not stamp or version(utc(stamp[1]))[1] != tag:
            raise ValueError('Existing draft is from a different snapshot; rerun its original workflow attempt')
        snapshot_at = utc(stamp[1]).isoformat()
    return {'skip': False, 'version': number, 'tag': tag, 'title': title, 'commit': commit,
            'snapshot_at': snapshot_at, 'repository': api.repository, 'branch': branch,
            'sync': run, 'cache_key': f'intel-v1-{branch}-{run["id"]}-{run["run_attempt"]}'}


def validate_sources(root, plan, moment):
    database = root / 'indexes/intelligence.sqlite'
    if not database.is_file():
        raise ValueError('Missing daily-sync database; restore the exact successful-run cache')
    cfg = read_json(root / 'config/sources.json')['sources']
    status = read_json(root / 'metadata/sync-status.json')['sources']
    required = {key: value for key, value in cfg.items() if value.get('enabled')}
    if not required:
        raise ValueError('No required sources configured')
    result = {}
    db = connect(database, readonly=True)
    try:
        db.execute('BEGIN')
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('SQLite integrity failure')
        for source, config in sorted(required.items()):
            safe_id(source)
            item = status.get(source, {})
            if str(item.get('status', '')).lower() not in ('ok', 'success', 'unchanged'):
                raise ValueError(f'Required source {source} is failed, partial or missing')
            success = utc(item['last_success'])
            if not timedelta(0) <= moment - success <= timedelta(hours=36):
                raise ValueError(f'Required source {source} is stale')
            if not utc(plan['sync']['run_started_at']) <= success <= utc(plan['sync']['updated_at']) + timedelta(minutes=2):
                raise ValueError(f'Source {source} was not validated in the latest successful daily run')
            checkpoint = db.execute('SELECT * FROM checkpoints WHERE source=?', (source,)).fetchone()
            if not checkpoint or utc(checkpoint['watermark']) != success:
                raise ValueError(f'Source {source} metadata/database checkpoint mismatch')
            count = 0
            origin_prefixes = set()
            checksum = hashlib.sha256()
            for row in db.execute('SELECT * FROM records WHERE source=? ORDER BY id', (source,)):
                raw = json.loads(row['raw'])
                validate_record(row['kind'], row['id'], raw)
                if row['kind'] != config['kind'] or digest(raw) != row['hash']:
                    raise ValueError(f'Source {source} record integrity failure')
                if normalize(source, row['kind'], row['id'], raw) != json.loads(row['normalized']):
                    raise ValueError(f'Source {source} normalization mismatch; rebuild and validate before sync')
                if row['kind'] == 'epss' and not timedelta(0) <= moment - utc(raw['date'] if 'T' in raw['date'] else raw['date'] + 'T00:00:00Z') <= timedelta(hours=48):
                    raise ValueError('EPSS contains stale or future score dates')
                if row['kind'] == 'osv' and not row['id'].startswith(('GHSA-', 'PYSEC-')):
                    raise ValueError('Additional OSV origin requires a reviewed redistribution/notice implementation before release')
                if row['kind'] == 'osv':
                    origin_prefixes.add(next(prefix for prefix in OSV_NOTICE_URLS if row['id'].startswith(prefix)))
                checksum.update(encode([row['id'], row['hash']]))
                count += 1
            if count == 0:
                raise ValueError(f'Required source {source} has no dataset')
            result[source] = {'records': count, 'last_success': item['last_success'],
                'upstream_version': item.get('upstream_version'), 'snapshot_sha256': checksum.hexdigest(),
                'coverage': config.get('coverage', 'Configured scope'), 'kind': config['kind']}
            if origin_prefixes:
                result[source]['origin_prefixes'] = sorted(origin_prefixes)
    finally:
        db.close()
    return result


def add_tar(archive, name, payload):
    info = tarfile.TarInfo(name)
    info.size, info.mtime, info.mode = len(payload), 0, 0o644
    archive.addfile(info, io.BytesIO(payload))


def group_name(source, kind):
    return {'cve': 'cve', 'nvd': 'nvd', 'kev': 'kev', 'epss': 'epss',
            'catalog': 'classifications', 'stix': 'classifications'}.get(kind, 'advisories')


def verify_archive(path):
    records = 0
    with tarfile.open(path, 'r:gz') as archive:
        for item in archive:
            if not item.isfile() or item.name.startswith('/') or '..' in Path(item.name).parts:
                raise ValueError('Unsafe archive member')
            if item.name.endswith('.jsonl'):
                with archive.extractfile(item) as stream:
                    for line in stream:
                        json.loads(line)
                        records += 1
    if not records:
        raise ValueError('Empty dataset archive')
    return records


def notice_files(source, payload):
    if isinstance(payload, bytes):
        payload = {source + '-upstream-license.txt': payload}
    if not isinstance(payload, dict) or not payload:
        raise ValueError('Missing upstream notice text: ' + source)
    for filename, contents in payload.items():
        safe_id(filename)
        if not isinstance(contents, bytes) or not contents:
            raise ValueError('Empty or invalid upstream notice: ' + source)
    return payload


def release_attribution(config, sources, notices):
    required = ('publisher', 'publisher_urls', 'dataset_urls', 'license_name', 'license_urls',
                'attribution_requirements', 'modifications', 'redistribution_restrictions', 'last_verified')
    result = {}
    for source, info in sorted(sources.items()):
        item = config[source].get('attribution', {})
        if any(not item.get(field) for field in required):
            raise ValueError('Incomplete original-publisher attribution: ' + source)
        if config[source]['url'] not in item['dataset_urls']:
            raise ValueError('Attribution does not match the configured dataset URL: ' + source)
        entry = json.loads(encode(item))
        if source == 'osv':
            actual = set(info.get('origin_prefixes', []))
            originals = [p for p in entry.get('original_publishers', []) if p['id_prefix'] in actual]
            if not actual or {p['id_prefix'] for p in originals} != actual:
                raise ValueError('OSV origin attribution is incomplete')
            entry['original_publishers'] = originals
            files = notice_files(source, notices.get(source))
            if any(OSV_NOTICE_URLS[prefix][0] not in files for prefix in actual):
                raise ValueError('OSV original-publisher license text is missing')
        entry['upstream_notice_sha256'] = {name: hashlib.sha256(body).hexdigest()
            for name, body in sorted(notice_files(source, notices[source]).items())} if source in notices else {}
        result[source] = entry
    return result


def prepare_assets(root, plan, sources, notice_payloads, part_bytes=PART_BYTES):
    output = root / 'dist'
    output.mkdir(exist_ok=True)
    month = plan['version'].replace('.', '-')
    manifest = {'schema_version': 1, 'tag': plan['tag'], 'commit': plan['commit'],
                'snapshot_at': plan['snapshot_at'], 'daily_sync_run': plan['sync']['id'],
                'sources': sources, 'assets': [], 'scope': 'Current records for configured enabled sources; historical revisions remain in retained SQLite backups.'}
    docs = {}
    for source in sources:
        if source in NOTICE_URLS and not notice_payloads.get(source):
            raise ValueError('Required upstream notice text missing: ' + source)
    config = read_json(root / 'config/sources.json')['sources']
    attribution = release_attribution(config, sources, notice_payloads)
    manifest['source_attribution'] = attribution
    for filename in ('LICENSE', 'DATA_SOURCES.md', 'docs/SOURCES.md'):
        path = root / filename
        if not path.is_file():
            raise ValueError('Required attribution file missing: ' + filename)
        docs[filename] = path.read_bytes()
    groups = {}
    for source, info in sources.items():
        groups.setdefault(group_name(source, info['kind']), []).append(source)
    database = connect(root / 'indexes/intelligence.sqlite', readonly=True)
    try:
        for group, identifiers in sorted(groups.items()):
            with tempfile.TemporaryDirectory(dir=output) as temporary:
                jsonl = Path(temporary) / 'records.jsonl'
                part, size, count = 1, 0, 0
                stream = jsonl.open('wb')

                def finish():
                    nonlocal part, count, size, stream
                    stream.close()
                    if not count:
                        return
                    path = output / f'threat-base-{group}-{month}-part{part:03d}.tar.gz'
                    temp = path.with_suffix(path.suffix + '.tmp')
                    try:
                        # Fixed gzip/tar timestamps make draft recovery byte-identical.
                        with temp.open('wb') as raw_stream, gzip.GzipFile(filename='', mode='wb', fileobj=raw_stream, mtime=0) as compressed, tarfile.open(fileobj=compressed, mode='w|') as archive:
                            info = tarfile.TarInfo('records.jsonl')
                            info.size, info.mtime, info.mode = jsonl.stat().st_size, 0, 0o644
                            with jsonl.open('rb') as data:
                                archive.addfile(info, data)
                            for name, body in sorted(docs.items()):
                                add_tar(archive, name, body)
                            for source in identifiers:
                                add_tar(archive, f'attribution/{source}.json', encode(attribution[source]))
                                if source in notice_payloads:
                                    for filename, payload in sorted(notice_files(source, notice_payloads[source]).items()):
                                        add_tar(archive, f'attribution/{source}/{filename}', payload)
                        if not 0 < temp.stat().st_size < MAX_ASSET or verify_archive(temp) != count:
                            raise ValueError('Archive size or record-count validation failed')
                        temp.replace(path)
                    finally:
                        temp.unlink(missing_ok=True)
                    manifest['assets'].append({'name': path.name, 'bytes': path.stat().st_size,
                        'sha256': file_hash(path), 'records': count, 'group': group})
                    if len(manifest['assets']) > MAX_ASSETS - 3:
                        raise ValueError('Release partition count exceeds asset budget; use reviewed external storage')
                    if sum(item['bytes'] for item in manifest['assets']) > MAX_TOTAL_ASSETS:
                        raise ValueError('Release exceeds hosted-runner storage budget; use reviewed external storage')
                    part += 1
                    size = count = 0

                try:
                    for source in sorted(identifiers):
                        for row in database.execute('SELECT * FROM records WHERE source=? ORDER BY id', (source,)):
                            line = encode({'source': source, 'id': row['id'], 'content_hash': row['hash'],
                                'last_synchronized': row['synced_at'], 'raw': json.loads(row['raw']), 'normalized': json.loads(row['normalized'])})
                            if len(line) > MAX_RECORD:
                                raise ValueError('A single dataset record exceeds the release record budget')
                            if count and size + len(line) > part_bytes:
                                finish()
                                stream = jsonl.open('wb')
                            stream.write(line)
                            size += len(line)
                            count += 1
                    finish()
                finally:
                    stream.close()
    finally:
        database.close()
    metadata = output / f'threat-base-metadata-{month}.tar.gz'
    temporary_metadata = metadata.with_suffix(metadata.suffix + '.tmp')
    try:
        with temporary_metadata.open('wb') as raw_stream, gzip.GzipFile(filename='', mode='wb', fileobj=raw_stream, mtime=0) as compressed, tarfile.open(fileobj=compressed, mode='w|') as archive:
            for filename in ('metadata/sync-status.json', 'metadata/sources.json', 'config/sources.json'):
                payload = (root / filename).read_bytes()
                json.loads(payload)
                add_tar(archive, filename, payload)
            for name, body in sorted(docs.items()):
                add_tar(archive, name, body)
            add_tar(archive, 'attribution.json', encode(attribution))
            for source, payload in sorted(notice_payloads.items()):
                if source in sources:
                    for filename, contents in sorted(notice_files(source, payload).items()):
                        add_tar(archive, f'attribution/{source}/{filename}', contents)
        if not 0 < temporary_metadata.stat().st_size < MAX_ASSET:
            raise ValueError('Metadata asset exceeds release size budget')
        with tarfile.open(temporary_metadata, 'r:gz') as archive:
            for member in archive:
                if member.name.endswith('.json'):
                    json.load(archive.extractfile(member))
        temporary_metadata.replace(metadata)
    finally:
        temporary_metadata.unlink(missing_ok=True)
    manifest['assets'].append({'name': metadata.name, 'bytes': metadata.stat().st_size,
                               'sha256': file_hash(metadata), 'group': 'metadata'})
    if sum(item['bytes'] for item in manifest['assets']) > MAX_TOTAL_ASSETS:
        raise ValueError('Release assets exceed the hosted-runner storage budget')
    write_json(output / 'manifest.json', manifest)
    sums = ''.join(f'{item["sha256"]}  {item["name"]}\n' for item in manifest['assets'])
    sums += f'{file_hash(output / "manifest.json")}  manifest.json\n'
    (output / 'SHA256SUMS').write_bytes(sums.encode())
    notes = [plan['title'], '', f'Snapshot (UTC): {plan["snapshot_at"]}', f'Validated commit: `{plan["commit"]}`', '',
        '| Source | Records | Last successful sync (UTC) | Upstream version |', '| --- | ---: | --- | --- |']
    for source, info in sorted(sources.items()):
        notes.append(f'| {source} | {info["records"]} | {info["last_success"]} | {info["upstream_version"] or "Not recorded"} |')
    notes.extend(['', '### Original data publishers', ''])
    for source, info in sorted(attribution.items()):
        publishers = '; '.join(f'[{info["publisher"]}]({url})' for url in info['publisher_urls'])
        datasets = ', '.join(info['dataset_urls'])
        licenses = ', '.join(info['license_urls'])
        notes.extend([f'- **{source}** — {publishers}. Dataset: {datasets}.',
            f'  Terms: {info["license_name"]} ({licenses}).',
            f'  Attribution: {info["attribution_requirements"]}',
            f'  Modifications: {info["modifications"]}',
            f'  Restrictions: {info["redistribution_restrictions"]}'])
        for origin in info.get('original_publishers', []):
            notes.append(f'  Original {origin["id_prefix"]} publisher: [{origin["publisher"]}]({origin["publisher_url"]}); dataset {origin["dataset_url"]}; {origin["license_name"]} ({origin["license_url"]}).')
        if info.get('required_notice'):
            notes.append('  ' + info['required_notice'])
    notes.extend(['', 'Validation: latest successful daily run, required-source status/freshness, SQLite integrity, raw content hashes, normalized projections, archive counts and SHA-256 checksums passed.',
        '', 'New/updated counts are not measured against an earlier monthly snapshot; they are not inferred from record totals.',
        '', 'Coverage is limited to the configured scope listed in manifest.json. Historical revisions remain in retained database backups. Upstream versions are not invented where absent.',
        '', f'Attribution and terms: https://github.com/{plan["repository"]}/blob/{plan["commit"]}/DATA_SOURCES.md',
        'Each data archive includes source configuration, project/source attribution and available upstream notice texts.',
        '', marker(plan, manifest)])
    (output / 'release-notes.md').write_bytes(('\n'.join(notes) + '\n').encode())
    verify_local(output, manifest)
    return manifest


def parse_sums(text):
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})  ([A-Za-z0-9._-]+)', line)
        if not match or match[2] in result:
            raise ValueError('Invalid or duplicate checksum entry')
        result[match[2]] = match[1]
    return result


def verify_local(output, manifest):
    sums = parse_sums((output / 'SHA256SUMS').read_text())
    expected = {item['name']: item['sha256'] for item in manifest['assets']}
    expected['manifest.json'] = file_hash(output / 'manifest.json')
    if sums != expected:
        raise ValueError('Checksum manifest does not match asset inventory')
    for name, checksum in sums.items():
        path = output / name
        if not path.is_file() or file_hash(path) != checksum:
            raise ValueError('Local asset checksum mismatch: ' + name)


def marker(plan, manifest):
    return f'<!-- threat-base-release commit={plan["commit"]} manifest={digest(manifest)} -->'


def ensure_draft(api, plan, manifest, notes):
    path = api.base + '/releases/tags/' + plan['tag']
    for attempt in range(3):
        existing = api.request(path, missing_ok=True)
        if existing:
            if not existing['draft']:
                verify_published(api, existing)
                return existing
            if existing.get('target_commitish') != plan['commit'] or marker(plan, manifest) not in (existing.get('body') or ''):
                raise ValueError('Existing draft belongs to another snapshot; rerun its original workflow attempt')
            return existing
        if api.request(api.base + '/git/ref/tags/' + plan['tag'], missing_ok=True):
            raise ValueError('Version tag exists; no tag will be overwritten')
        try:
            created = api.request(api.base + '/releases', {'tag_name': plan['tag'], 'target_commitish': plan['commit'],
                'name': plan['title'], 'body': notes, 'draft': True, 'prerelease': False})
            if not created.get('draft') or created.get('tag_name') != plan['tag'] or created.get('target_commitish') != plan['commit']:
                raise ValueError('Draft creation returned an unexpected identity')
            return created
        except (APIError, OSError, RuntimeError) as exc:
            if isinstance(exc, APIError) and exc.status not in (408, 422, 429, 500, 502, 503, 504):
                raise
            if attempt == 2:
                raise RuntimeError('Draft creation could not be confirmed; rerun to recover without duplicating') from None
            api.sleep(2 ** (attempt + 1))
    raise RuntimeError('Draft creation failed')


def verify_remote_asset(api, asset, path):
    if asset.get('state') != 'uploaded' or asset.get('size') != path.stat().st_size:
        raise ValueError('Incomplete/conflicting draft asset; no existing asset will be overwritten: ' + path.name)
    expected = file_hash(path)
    if asset.get('digest'):
        if asset['digest'] != 'sha256:' + expected:
            raise ValueError('Remote asset digest mismatch: ' + path.name)
    else:
        with tempfile.TemporaryDirectory() as temporary:
            downloaded = Path(temporary) / 'asset'
            api.download(asset['id'], downloaded)
            if file_hash(downloaded) != expected:
                raise ValueError('Downloaded remote asset checksum mismatch: ' + path.name)


def publish_assets(api, plan, output, manifest):
    verify_local(output, manifest)
    notes = (output / 'release-notes.md').read_text(encoding='utf-8')
    release = ensure_draft(api, plan, manifest, notes)
    if not release['draft']:
        return 'already published'
    if release.get('tag_name') != plan['tag'] or release.get('target_commitish') != plan['commit']:
        raise ValueError('Unexpected draft identity')
    paths = [output / item['name'] for item in manifest['assets']] + [output / 'manifest.json', output / 'SHA256SUMS']
    for path in paths:
        for attempt in range(3):
            assets = {item['name']: item for item in api.assets(release['id'])}
            if path.name in assets:
                verify_remote_asset(api, assets[path.name], path)
                break
            try:
                uploaded = api.upload(release['id'], path)
                verify_remote_asset(api, uploaded, path)
                break
            except APIError as exc:
                if exc.status not in (408, 422, 429, 500, 502, 503, 504):
                    raise
            except OSError:
                pass
            if attempt == 2:
                raise RuntimeError('Upload could not be confirmed; draft retained for recovery: ' + path.name)
            api.sleep(2 ** (attempt + 1))
    remote = {item['name']: item for item in api.assets(release['id'])}
    if set(remote) != {path.name for path in paths}:
        raise ValueError('Draft has missing or unexpected assets; publication stopped')
    for path in paths:
        verify_remote_asset(api, remote[path.name], path)
    # Last identity check avoids publishing a draft changed by an external actor.
    latest = api.request(api.base + '/releases/tags/' + plan['tag'])
    if latest['id'] != release['id'] or marker(plan, manifest) not in (latest.get('body') or ''):
        raise ValueError('Draft changed during upload; publication stopped')
    if not latest['draft']:
        verify_published(api, latest)
        return 'already published'
    tag_ref = api.request(api.base + '/git/ref/tags/' + plan['tag'], missing_ok=True)
    if tag_ref and (tag_ref['object']['type'] != 'commit' or tag_ref['object']['sha'] != plan['commit']):
        raise ValueError('Version tag points to another commit; publication stopped')
    published = api.request(api.base + f'/releases/{release["id"]}', {'draft': False}, method='PATCH')
    if published['draft'] or published['tag_name'] != plan['tag']:
        raise ValueError('Publication not confirmed; inspect release and rerun')
    return 'published'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('plan', 'publish'))
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_EVENT_NAME') not in ('schedule', 'workflow_dispatch'):
        raise RuntimeError('Release publication runs only through the approved GitHub Actions workflow')
    branch = os.environ.get('DEFAULT_BRANCH')
    if not branch or os.environ.get('GITHUB_REF_TYPE') != 'branch' or os.environ.get('GITHUB_REF_NAME') != branch:
        raise ValueError('Release must use the default branch')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    if commit != os.environ.get('GITHUB_SHA'):
        raise ValueError('Checkout and event commit differ')
    token = os.environ.get('GH_TOKEN')
    if not token:
        raise ValueError('Built-in GitHub token is required')
    api = GitHub(os.environ['GITHUB_REPOSITORY'], token)
    moment = datetime.now(timezone.utc)
    plan = plan_release(api, branch, commit, moment)
    output = ROOT / 'dist'
    output.mkdir(exist_ok=True)
    if args.phase == 'plan':
        write_json(output / 'release-plan.json', plan)
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
            stream.write(f'skip={str(plan["skip"]).lower()}\ncache_key={plan.get("cache_key", "")}\n')
        print(plan.get('result', f'Validated latest daily run for {plan["tag"]}'))
        return
    original = read_json(output / 'release-plan.json')
    if plan['skip']:
        print('Already published; existing assets were checked and will not be overwritten')
        return
    for key in ('commit', 'tag', 'sync', 'cache_key'):
        if original.get(key) != plan.get(key):
            raise ValueError('Daily sync or snapshot changed after planning; rerun release workflow')
    plan = original  # Preserve timestamp and deterministic assets across job phases.
    sources = validate_sources(ROOT, plan, moment)
    notices = {}
    # Fetch notice text only; never execute downloaded content. No extra mirror is created in Git.
    from scripts.http_client import Client
    client = Client(ROOT / '.cache/release-notices')
    for source in sources:
        if source == 'osv':
            notices[source] = {OSV_NOTICE_URLS[prefix][0]: client.get(OSV_NOTICE_URLS[prefix][1], limit=2 * 1024 * 1024).read_bytes()
                for prefix in sources[source]['origin_prefixes']}
        elif source in NOTICE_URLS:
            notices[source] = client.get(NOTICE_URLS[source], limit=2 * 1024 * 1024).read_bytes()
    manifest = prepare_assets(ROOT, plan, sources, notices)
    result = publish_assets(api, plan, output, manifest)
    print(plan['tag'] + ': ' + result)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as stream:
            stream.write(f'### {plan["title"]}\n\n{result}; {len(manifest["assets"])} data/metadata assets plus manifest and checksums.\n')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'Release stopped: {exc}', file=sys.stderr)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as summary:
                summary.write(f'### Release stopped\n\n{type(exc).__name__}; inspect the job error. Any created draft remains unpublished.\n')
        raise SystemExit(1)

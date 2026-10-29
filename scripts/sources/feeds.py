import csv
import gzip
import io
import re
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, quote

from scripts.common import CVE, safe_id


def xml_root(payload):
    text = payload.decode('utf-8-sig')
    if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
        raise ValueError('DTD and entities are prohibited')
    return ET.fromstring(text)


def records(source, client, since, until, config):
    kind, url = config['kind'], config['url']
    if kind == 'kev':
        feed = client.json(url)
        rows = feed['vulnerabilities']
        if not isinstance(rows, list) or not rows or feed.get('count') != len(rows):
            raise ValueError('Invalid KEV catalog count')
        for row in rows:
            if not CVE.fullmatch(row['cveID']):
                raise ValueError('Invalid KEV CVE')
            yield row['cveID'], row
    elif kind == 'epss':
        path = client.get(url)
        with gzip.open(path, 'rt', encoding='utf-8') as stream:
            first = stream.readline()
            metadata = re.search(r'score_date[:=]([^,\s]+)', first)
            if not first.startswith('#') or not metadata:
                raise ValueError('Missing EPSS score date')
            date = metadata.group(1)
            datetime.fromisoformat(date.replace('Z', '+00:00'))
            count = 0
            for row in csv.DictReader(stream):
                if not CVE.fullmatch(row['cve']):
                    raise ValueError('Invalid EPSS identifier')
                score, percentile = float(row['epss']), float(row['percentile'])
                if not (0 <= score <= 1 and 0 <= percentile <= 1):
                    raise ValueError('Invalid EPSS probability')
                count += 1
                yield row['cve'], {**row, 'date': date, 'epss': score, 'percentile': percentile}
            if not count:
                raise ValueError('Empty EPSS feed')
    elif kind == 'cve':
        logs = client.json(url)
        if not isinstance(logs, list) or not logs:
            raise ValueError('Invalid CVE delta log')
        parse = lambda value: datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parse(since) < min(parse(entry['fetchTime']) for entry in logs):
            raise ValueError('CVE delta coverage gap: import official baseline or choose an explicit recent --start')
        identifiers = set()
        for entry in logs:
            if parse(since) <= parse(entry['fetchTime']) <= parse(until):
                if entry.get('error'):
                    raise ValueError('CVE delta log contains upstream errors')
                for row in entry['new'] + entry['updated']:
                    identifier = row['cveId']
                    if not CVE.fullmatch(identifier):
                        raise ValueError('Invalid CVE delta identifier')
                    identifiers.add(identifier)
        for identifier in sorted(identifiers):
            year, number = identifier.split('-')[1:]
            path = f'{year}/{number[:-3]}xxx/{identifier}.json'
            yield identifier, client.json('https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/' + path)
    elif kind in ('nvd', 'github'):
        start = datetime.fromisoformat(since.replace('Z', '+00:00'))
        end = datetime.fromisoformat(until.replace('Z', '+00:00'))
        while start < end:
            stop = min(start + timedelta(days=119), end)
            offset = 0
            while True:
                if kind == 'nvd':
                    params = {'lastModStartDate': start.isoformat(timespec='seconds'), 'lastModEndDate': stop.isoformat(timespec='seconds'), 'startIndex': offset, 'resultsPerPage': 2000}
                    headers = {'apiKey': config['api_key']} if config.get('api_key') else {}
                    page = client.json(url + '?' + urlencode(params), headers=headers, interval=0.7 if headers else 6.1)
                    rows = page['vulnerabilities']
                    if page['startIndex'] != offset or not isinstance(rows, list):
                        raise ValueError('Invalid NVD pagination')
                    for row in rows:
                        yield row['cve']['id'], row['cve']
                    offset += len(rows)
                    if offset >= page['totalResults']:
                        break
                    if not rows:
                        raise ValueError('NVD pagination stalled')
                else:
                    params = {'modified': f'{start.isoformat(timespec="seconds")}..{stop.isoformat(timespec="seconds")}', 'per_page': 100, 'page': offset + 1, 'sort': 'updated', 'direction': 'asc', 'type': 'reviewed'}
                    headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
                    if config.get('token'):
                        headers['Authorization'] = 'Bearer ' + config['token']
                    rows = client.json(url + '?' + urlencode(params), headers=headers, interval=1.1)
                    if not isinstance(rows, list):
                        raise ValueError('Invalid GitHub page')
                    for row in rows:
                        yield row['ghsa_id'], row
                    if len(rows) < 100:
                        break
                    offset += 1
            start = stop
    elif kind == 'osv':
        # Exact configured advisory IDs and package/version watches; never a full bulk dump.
        ids = set(config.get('ids', []))
        for package in config.get('packages', []):
            # GET advisory retrieval is separate from OSV's version-aware query endpoint.
            import json
            import urllib.request
            payload = json.dumps({'package': {'name': package['name'], 'ecosystem': package['ecosystem']}, 'version': package['version']}).encode()
            # Querying is implemented by Client.post_json, including retry and timeout.
            result = client.post_json('https://api.osv.dev/v1/query', payload)
            for row in result.get('vulns', []):
                ids.add(row['id'])
            while result.get('next_page_token'):
                body = json.loads(payload)
                body['page_token'] = result['next_page_token']
                result = client.post_json('https://api.osv.dev/v1/query', json.dumps(body).encode())
                ids.update(row['id'] for row in result.get('vulns', []))
        for identifier in sorted(ids):
            safe_id(identifier)
            row = client.json(url + '/' + quote(identifier, safe=''))
            if row['id'] != identifier:
                raise ValueError('OSV identifier mismatch')
            yield identifier, row
    elif kind in ('rss', 'catalog', 'stix'):
        payload = client.get(url).read_bytes()
        if kind == 'stix':
            import json
            bundle = json.loads(payload)
            if bundle['type'] != 'bundle' or not bundle['objects']:
                raise ValueError('Invalid STIX bundle')
            for row in bundle['objects']:
                yield row['id'], row
        else:
            if config.get('zip'):
                with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                    entries = [x for x in archive.infolist() if x.filename.endswith('.xml')]
                    if len(entries) != 1 or entries[0].file_size > 150 * 1024 * 1024:
                        raise ValueError('Invalid catalog archive')
                    payload = archive.read(entries[0])
            root = xml_root(payload)
            if kind == 'rss':
                tag = root.tag.rsplit('}', 1)[-1]
                if tag not in ('rss', 'feed'):
                    raise ValueError('Not RSS or Atom')
                items = root.findall('.//item') if tag == 'rss' else root.findall('{*}entry')
                if not items:
                    raise ValueError('Empty advisory feed')
                for item in items:
                    fields = {child.tag.rsplit('}', 1)[-1]: child.text or child.attrib.get('href', '') for child in item}
                    identifier = fields.get('guid') or fields.get('id') or fields.get('link')
                    if not identifier:
                        raise ValueError('Advisory lacks stable identifier')
                    import hashlib
                    yield hashlib.sha256(identifier.encode()).hexdigest(), fields
            else:
                entry_tag, prefix = ('Weakness', 'CWE') if source == 'cwe' else ('Attack_Pattern', 'CAPEC')
                items = root.findall('.//{*}' + entry_tag)
                if not items:
                    raise ValueError('Empty classification catalog')
                for item in items:
                    # CAPEC procedural attack instructions and examples are excluded.
                    description = item.find('{*}Description')
                    row = {'id': prefix + '-' + item.attrib['ID'], 'name': item.attrib['Name'], 'description': ''.join(description.itertext()) if description is not None else '', 'status': item.attrib.get('Status')}
                    yield row['id'], row
    else:
        raise ValueError('Unknown source kind')

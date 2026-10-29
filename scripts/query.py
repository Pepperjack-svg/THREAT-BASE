#!/usr/bin/env python3
"""Read-only local interface for Kakashi, Itachi and human defenders."""
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.common import ROOT, read_json
from scripts.store import connect
from scripts.risk import prioritize


def semver(value):
    match = re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?', value)
    if not match:
        raise ValueError('Unsupported SemVer')
    major, minor, patch, pre = match.groups()
    parts = tuple((0, int(x)) if x.isdigit() else (1, x) for x in pre.split('.')) if pre else ()
    return (int(major), int(minor), int(patch), 0 if pre else 1, parts)


def affected(package, version):
    """True/false only with supported evidence; None explicitly means unknown."""
    if version in package.get('versions', []):
        return True
    unknown = False
    known = False
    for span in package.get('ranges', []):
        if span.get('type') != 'SEMVER':
            unknown = True
            continue
        try:
            value = semver(version)
            inside = False
            for event in span['events']:
                if 'introduced' in event:
                    inside = event['introduced'] == '0' or value >= semver(event['introduced'])
                elif 'fixed' in event or 'limit' in event or 'last_affected' in event:
                    key = next(k for k in ('fixed', 'limit', 'last_affected') if k in event)
                    end = semver(event[key])
                    if inside and (value <= end if key == 'last_affected' else value < end):
                        return True
                    inside = False
                else:
                    unknown = True
            if inside:
                return True
            known = True
        except (ValueError, KeyError, TypeError):
            unknown = True
    return None if unknown or not known else False


class Reader:
    def __init__(self, database):
        self.db = connect(database, readonly=True)
        self.status = read_json(Path(database).resolve().parent.parent / 'metadata/sync-status.json', {'sources': {}})

    def close(self):
        self.db.close()

    def search(self, field, value, limit=100):
        allowed = {'id', 'cve', 'ghsa', 'osv', 'vendor', 'product', 'package', 'cwe', 'severity', 'kev', 'published'}
        if field not in allowed or not 1 <= limit <= 1000:
            raise ValueError('Invalid query field or limit')
        if field == 'id':
            rows = self.db.execute("SELECT DISTINCT r.* FROM records r JOIN terms t ON r.source=t.source AND r.id=t.id WHERE t.value=? AND t.field IN ('id','cve','ghsa','osv') ORDER BY r.source,r.id LIMIT ?", (value, limit)).fetchall()
        else:
            rows = self.db.execute('SELECT r.* FROM records r JOIN terms t ON r.source=t.source AND r.id=t.id WHERE t.field=? AND t.value=? ORDER BY r.source,r.id LIMIT ?', (field, value, limit)).fetchall()
        return [self.document(row) for row in rows]

    def document(self, row):
        result = json.loads(row['normalized'])
        result['last_synchronized'] = row['synced_at']
        checkpoint = self.db.execute('SELECT checked_at FROM checkpoints WHERE source=?', (row['source'],)).fetchone()
        result['source_last_checked'] = checkpoint[0] if checkpoint else None
        result['source_status'] = self.status.get('sources', {}).get(row['source'], {}).get('status', 'unknown')
        result['coverage'] = self.status.get('sources', {}).get(row['source'], {}).get('coverage', 'unknown')
        result['stale'] = not checkpoint or (datetime.now(timezone.utc) - datetime.fromisoformat(checkpoint[0])).total_seconds() > 172800
        return result

    def report(self, identifier, weights=None, exposed=None):
        found, visited, pending = {}, set(), [identifier]
        while pending:
            alias = pending.pop()
            if alias in visited:
                continue
            visited.add(alias)
            if len(visited) > 1000:
                raise ValueError('Alias correlation budget exceeded')
            for row in self.search('id', alias, 1000):
                key = row['source'], row['id']
                if key not in found:
                    found[key] = row
                    pending.extend(row['aliases'])
        rows = list(found.values())
        risk = prioritize(rows, weights, exposed)
        return {'requested_id': identifier, 'records': rows, 'risk': risk, 'incomplete': not rows or bool(risk['missing']) or any(r['stale'] or r['source_status'] != 'ok' for r in rows), 'coverage_note': 'See metadata/sync-status.json for failures and partial coverage.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, default=ROOT / 'indexes/intelligence.sqlite')
    parser.add_argument('--field', default='id')
    parser.add_argument('--value', required=True)
    parser.add_argument('--version', help='Package version; unsupported ranges return unknown')
    parser.add_argument('--ecosystem')
    parser.add_argument('--report', action='store_true')
    parser.add_argument('--exposed', action='store_true', default=None, help='Explicit assertion from your asset inventory; no scanning')
    parser.add_argument('--agent', choices=['kakashi', 'itachi'], help='Attribution only; both are read-only')
    args = parser.parse_args()
    reader = Reader(args.database)
    try:
        if args.report:
            result = reader.report(args.value, read_json(ROOT / 'config/risk.json'), args.exposed)
        else:
            result = reader.search(args.field, args.value)
            if args.version:
                if args.field != 'package' or not args.ecosystem:
                    parser.error('--version requires --field package and --ecosystem')
                result = [{'record': row, 'matches': [{'package': p, 'affected': affected(p, args.version)} for p in row['packages'] if p.get('name') == args.value and p.get('ecosystem') == args.ecosystem]} for row in result]
        print(json.dumps(result, indent=2, ensure_ascii=False))
    finally:
        reader.close()


if __name__ == '__main__':
    main()

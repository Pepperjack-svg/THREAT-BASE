#!/usr/bin/env python3
"""Bounded, isolated incremental ingestion. No publish operations."""
import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.common import ROOT, now, read_json, write_json, record_path
from scripts.http_client import Client
from scripts.sources.feeds import records
from scripts.store import connect, ingest


def export_curated(db, root, config):
    identifiers = set(config.get('curated_ids', []))
    if config.get('export_kev', True):
        identifiers.update(r[0] for r in db.execute("SELECT id FROM records WHERE kind='kev'"))
    count = 0
    for identifier in sorted(identifiers):
        matches = db.execute("SELECT DISTINCT r.* FROM records r JOIN terms t ON r.source=t.source AND r.id=t.id WHERE t.value=? AND t.field IN ('cve','ghsa','osv','id')", (identifier,)).fetchall()
        for row in matches:
            document = json.loads(row['normalized'])
            document.update(last_synchronized=row['synced_at'], content_hash=row['hash'], original_source_identifier=row['id'])
            count += 1
            if count > config.get('max_curated_records', 20000):
                raise ValueError('Curated export budget exceeded')
            write_json(record_path(root, 'curated', row['source'], row['id']), document)
    kev = [json.loads(row[0]) for row in db.execute("SELECT raw FROM records WHERE kind='kev' ORDER BY id")]
    if kev:
        write_json(root / 'data/cisa-kev/latest.json', {'count': len(kev), 'vulnerabilities': kev, 'note': 'Accumulated observations; delistings retained. See source checkpoint.'})
    return count


def synchronize(root, selected=None, start=None, client=None, config=None):
    config = config or read_json(root / 'config/sources.json')
    source_configs = config['sources']
    selected = selected or [key for key, value in source_configs.items() if value.get('enabled')]
    if set(selected) - source_configs.keys():
        raise ValueError('Unknown source selection')
    client = client or Client(root / '.cache/http')
    db = connect(root / 'indexes/intelligence.sqlite')
    status = read_json(root / 'metadata/sync-status.json', {'sources': {}})
    until = now()
    failed = False
    try:
        for source in selected:
            cfg = dict(source_configs[source])
            checkpoint = db.execute('SELECT * FROM checkpoints WHERE source=?', (source,)).fetchone()
            since = start or (checkpoint['watermark'] if checkpoint else (datetime.now(timezone.utc) - timedelta(days=config.get('bootstrap_days', 1))).isoformat())
            if checkpoint and not start:
                since = (datetime.fromisoformat(since.replace('Z', '+00:00')) - timedelta(minutes=5)).isoformat()
            previous = status['sources'].get(source, {})
            try:
                if datetime.fromisoformat(since.replace('Z', '+00:00')) >= datetime.fromisoformat(until):
                    raise ValueError('Start must precede current UTC time')
                if source == 'nvd':
                    cfg['api_key'] = os.environ.get('NVD_API_KEY')
                if source == 'github-advisories':
                    cfg['token'] = os.environ.get('GITHUB_TOKEN')
                result = ingest(db, source, cfg['kind'], records(source, client, since, until, cfg), until, cfg.get('max_records', 600000))
                status['sources'][source] = {'status': 'ok', 'last_success': until, 'window_start': since, 'coverage_start': min(since, previous.get('coverage_start', since)), 'coverage': cfg['coverage'], **result}
                print(f'{source}: validated {result["received"]}, changed {result["changed"]}', flush=True)
            except Exception as exc:
                failed = True
                status['sources'][source] = {**previous, 'status': 'error', 'attempted_at': until, 'error_type': type(exc).__name__}
                print(f'{source}: failed ({type(exc).__name__}); prior records/checkpoint retained', file=sys.stderr, flush=True)
        status['curated_records'] = export_curated(db, root, config)
        status['attempted_at'] = until
        write_json(root / 'metadata/sync-status.json', status)
        write_json(root / 'metadata/sources.json', {'sources': source_configs})
        if isinstance(client, Client):
            client.prune(config.get('http_cache_retention_days', 7), config.get('http_cache_max_bytes', 512 * 1024 * 1024))
    finally:
        db.close()
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--sources', help='Comma-separated source IDs')
    parser.add_argument('--start', help='Explicit ISO8601 UTC start; initial default is a recent partial window')
    parser.add_argument('--import-dir', type=Path, help='Import an official CVE/OSV JSON tree without deleting it')
    parser.add_argument('--import-source', choices=['cve', 'osv'], default='cve')
    args = parser.parse_args()
    root = args.root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    lock = root / '.cache/sync.lock'
    lock.parent.mkdir(exist_ok=True)
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        raise SystemExit('Sync lock exists: verify no sync is active before removing .cache/sync.lock')
    os.close(fd)
    try:
        if args.import_dir:
            def imported():
                for path in sorted(args.import_dir.rglob('*.json')):
                    raw = read_json(path)
                    if args.import_source == 'cve' and raw.get('dataType') == 'CVE_RECORD':
                        yield raw['cveMetadata']['cveId'], raw
                    elif args.import_source == 'osv' and raw.get('id'):
                        yield raw['id'], raw
            db = connect(root / 'indexes/intelligence.sqlite')
            try:
                ingest(db, args.import_source, args.import_source, imported(), args.start or '1970-01-01T00:00:00+00:00', max_records=5000000)
            finally:
                db.close()
            return 0
        return synchronize(root, args.sources.split(',') if args.sources else None, args.start)
    finally:
        lock.unlink(missing_ok=True)


if __name__ == '__main__':
    raise SystemExit(main())

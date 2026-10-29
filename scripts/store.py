"""Transactional source checkpoints and reproducible indexed projections."""
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from scripts.common import digest, encode, now, safe_id, CVE
from scripts.normalize import normalize

SCHEMA = '''
CREATE TABLE IF NOT EXISTS records(source TEXT, id TEXT, kind TEXT, hash TEXT, raw TEXT, normalized TEXT, synced_at TEXT, PRIMARY KEY(source,id));
CREATE TABLE IF NOT EXISTS checkpoints(source TEXT PRIMARY KEY, watermark TEXT, checked_at TEXT);
CREATE TABLE IF NOT EXISTS history(source TEXT, id TEXT, hash TEXT, raw TEXT, observed_at TEXT, PRIMARY KEY(source,id,hash));
CREATE TABLE IF NOT EXISTS terms(field TEXT, value TEXT, source TEXT, id TEXT, PRIMARY KEY(field,value,source,id));
CREATE INDEX IF NOT EXISTS terms_lookup ON terms(field,value);
CREATE INDEX IF NOT EXISTS terms_value ON terms(value,field);
CREATE INDEX IF NOT EXISTS terms_record ON terms(source,id);
'''


def connect(path, readonly=False):
    path = Path(path).resolve()
    if readonly:
        connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
        connection.execute('PRAGMA query_only=ON')
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path)
        connection.execute('PRAGMA journal_mode=WAL')
        connection.executescript(SCHEMA)
    connection.row_factory = sqlite3.Row
    return connection


def validate_record(kind, identifier, raw):
    safe_id(identifier)
    if not isinstance(raw, dict):
        raise ValueError('Record must be an object')
    if kind in ('kev', 'epss', 'cve', 'nvd') and not CVE.fullmatch(identifier):
        raise ValueError('Invalid CVE identifier')
    if kind == 'cve' and raw.get('cveMetadata', {}).get('state') not in ('PUBLISHED', 'REJECTED', 'RESERVED'):
        raise ValueError('Unknown CVE state')
    if kind == 'github' and not identifier.startswith('GHSA-'):
        raise ValueError('Invalid GHSA identifier')


def index_record(db, source, identifier, row):
    terms = set()
    for alias in row['aliases']:
        field = 'cve' if CVE.fullmatch(alias) else 'ghsa' if alias.startswith('GHSA-') else 'osv' if row['source'] == 'osv' else 'id'
        terms.add((field, alias))
    for field, values in [('vendor', row['vendors']), ('product', row['products']), ('cwe', row['cwes']), ('package', [p['name'] for p in row['packages'] if p.get('name')])]:
        terms.update((field, value) for value in values)
    if row['severity']:
        terms.add(('severity', row['severity']))
    if row['kev']:
        terms.add(('kev', 'true'))
    if row['published']:
        terms.add(('published', row['published'][:10]))
    db.execute('DELETE FROM terms WHERE source=? AND id=?', (source, identifier))
    db.executemany('INSERT INTO terms VALUES(?,?,?,?)', [(field, value, source, identifier) for field, value in terms])


def ingest(db, source, kind, rows, watermark, max_records=600000):
    count = changed = 0
    timestamp = now()
    # Entire source is one transaction: parser/network errors preserve old data AND watermark.
    with db:
        for identifier, raw in rows:
            count += 1
            if count > max_records:
                raise ValueError('Source record budget exceeded; use a smaller time window')
            validate_record(kind, identifier, raw)
            row = normalize(source, kind, identifier, raw)
            checksum = digest(raw)
            old = db.execute('SELECT hash,raw,synced_at FROM records WHERE source=? AND id=?', (source, identifier)).fetchone()
            if old and old['hash'] == checksum:
                continue
            if old and kind in ('cve', 'nvd', 'github', 'osv'):
                db.execute('INSERT OR IGNORE INTO history VALUES(?,?,?,?,?)', (source, identifier, old['hash'], old['raw'], old['synced_at']))
            db.execute('INSERT OR REPLACE INTO records VALUES(?,?,?,?,?,?,?)', (source, identifier, kind, checksum, encode(raw).decode(), encode(row).decode(), timestamp))
            index_record(db, source, identifier, row)
            changed += 1
        db.execute('INSERT OR REPLACE INTO checkpoints VALUES(?,?,?)', (source, watermark, timestamp))
    return {'received': count, 'changed': changed}


def rebuild(db):
    with db:
        db.execute('DELETE FROM terms')
        for record in db.execute('SELECT * FROM records'):
            row = normalize(record['source'], record['kind'], record['id'], json.loads(record['raw']))
            db.execute('UPDATE records SET normalized=? WHERE source=? AND id=?', (encode(row).decode(), record['source'], record['id']))
            index_record(db, record['source'], record['id'], row)

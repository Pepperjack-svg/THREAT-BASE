import gzip
import io
import json
import sqlite3
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from scripts.common import atomic, digest, now, write_json, read_json, MAX_FILE
from scripts.http_client import Client
from scripts.normalize import normalize
from scripts.query import Reader, affected
from scripts.risk import prioritize
from scripts.sources.feeds import records, xml_root
from scripts.store import connect, ingest, rebuild
from scripts.sync import synchronize, export_curated
from scripts.validate import validate

CVE = 'CVE-2025-12345'
RAW = {'cveMetadata': {'cveId': CVE, 'state': 'PUBLISHED'}, 'containers': {'cna': {'descriptions': [{'lang': 'en', 'value': 'Synthetic vulnerability'}], 'affected': [{'vendor': 'Example', 'product': 'Widget'}]}}}
KEV = {'cveID': CVE, 'vendorProject': 'Example', 'product': 'Widget', 'vulnerabilityName': 'Example', 'requiredAction': 'Update', 'notes': 'https://example.org/patch'}


class Response(io.BytesIO):
    def __init__(self, payload=b'{}', status=200, headers=None):
        super().__init__(payload)
        self.status = status
        self.headers = headers or {}

    def geturl(self):
        return 'https://example.org/feed'


class FakeClient:
    def __init__(self, data=None, path=None):
        self.data, self.path, self.urls = data, path, []

    def json(self, url, **kwargs):
        self.urls.append(url)
        if isinstance(self.data, Exception):
            raise self.data
        return self.data

    def get(self, url, **kwargs):
        return self.path


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / 'indexes/intelligence.sqlite'
        self.db = connect(self.path)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def put(self, source='cve', kind='cve', raw=None):
        return ingest(self.db, source, kind, [(CVE, raw or RAW)], now())

    def test_idempotent_duplicate_cves(self):
        self.put()
        self.assertEqual(self.put()['changed'], 0)
        self.assertEqual(self.db.execute('SELECT count(*) FROM records').fetchone()[0], 1)

    def test_interrupted_source_rolls_back_data_and_checkpoint(self):
        self.put()
        old = tuple(self.db.execute('SELECT * FROM checkpoints').fetchone())
        def interrupted():
            yield CVE, {**RAW, 'test': 'new'}
            raise OSError('interruption')
        with self.assertRaises(OSError):
            ingest(self.db, 'cve', 'cve', interrupted(), now())
        self.assertEqual(tuple(self.db.execute('SELECT * FROM checkpoints').fetchone()), old)
        self.assertEqual(self.db.execute('SELECT hash FROM records').fetchone()[0], digest(RAW))

    def test_missing_fields_rollback(self):
        with self.assertRaises((ValueError, KeyError)):
            self.put(raw={'cveMetadata': {}})
        self.assertEqual(self.db.execute('SELECT count(*) FROM records').fetchone()[0], 0)

    def test_rejected_and_reserved_no_invented_cvss(self):
        for state in ('REJECTED', 'RESERVED'):
            raw = {**RAW, 'cveMetadata': {'cveId': CVE, 'state': state}}
            self.put(raw=raw)
            row = json.loads(self.db.execute('SELECT normalized FROM records').fetchone()[0])
            self.assertEqual(row['state'], state)
            self.assertEqual(row['cvss'], [])
            self.assertIsNone(row['severity'])

    def test_path_traversal_rejected(self):
        with self.assertRaises(ValueError):
            ingest(self.db, 'cve', 'cve', [('../../bad', RAW)], now())

    def test_kev_enrichment_and_readonly(self):
        self.put()
        self.put('cisa-kev', 'kev', KEV)
        reader = Reader(self.path)
        try:
            report = reader.report(CVE)
            self.assertTrue(report['risk']['confirmed_exploitation'])
            self.assertEqual(len(report['records']), 2)
            with self.assertRaises(sqlite3.OperationalError):
                reader.db.execute('DELETE FROM records')
        finally:
            reader.close()

    def test_index_generation(self):
        self.put()
        rebuild(self.db)
        self.assertEqual(self.db.execute("SELECT value FROM terms WHERE field='vendor'").fetchone()[0], 'Example')

    def test_unchanged_record_sync_time_stable(self):
        self.put()
        old = self.db.execute('SELECT synced_at FROM records').fetchone()[0]
        self.put()
        self.assertEqual(self.db.execute('SELECT synced_at FROM records').fetchone()[0], old)

    def test_export_idempotence(self):
        self.put('cisa-kev', 'kev', KEV)
        export_curated(self.db, self.root, {})
        snapshot = {p: p.read_bytes() for p in (self.root / 'data').rglob('*.json')}
        export_curated(self.db, self.root, {})
        self.assertEqual(snapshot, {p: p.read_bytes() for p in (self.root / 'data').rglob('*.json')})

    def test_source_isolation_and_failure_status(self):
        cfg = {'sources': {'good': {'kind': 'kev', 'url': 'https://example.org', 'coverage': 'test', 'enabled': True}, 'bad': {'kind': 'unknown', 'url': 'https://example.org', 'coverage': 'test', 'enabled': True}}}
        result = synchronize(self.root, client=FakeClient({'count': 1, 'vulnerabilities': [KEV]}), config=cfg)
        self.assertEqual(result, 1)
        status = read_json(self.root / 'metadata/sync-status.json')['sources']
        self.assertEqual(status['good']['status'], 'ok')
        self.assertEqual(status['bad']['status'], 'error')

    def test_record_budget_rollback(self):
        with self.assertRaises(ValueError):
            ingest(self.db, 'cve', 'cve', [(CVE, RAW)] * 2, now(), 1)
        self.assertEqual(self.db.execute('SELECT count(*) FROM records').fetchone()[0], 0)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_rate_limit_retry(self):
        error = urllib.error.HTTPError('https://example.org', 429, 'Rate limit', {'Retry-After': '2'}, None)
        with patch('time.sleep') as sleep:
            opener = unittest.mock.Mock(side_effect=[error, Response()])
            client = Client(self.root, sleep=sleep, opener=opener)
            self.assertEqual(client.json('https://example.org'), {})
            self.assertEqual(opener.call_count, 2)
            sleep.assert_any_call(2)

    def test_long_rate_limit_not_retried_early(self):
        error = urllib.error.HTTPError('https://example.org', 429, 'Rate limit', {'Retry-After': '300'}, None)
        opener = unittest.mock.Mock(side_effect=error)
        with self.assertRaises(RuntimeError):
            Client(self.root, sleep=lambda _: None, opener=opener).get('https://example.org')
        self.assertEqual(opener.call_count, 1)

    def test_failures_bounded(self):
        opener = unittest.mock.Mock(side_effect=OSError('down'))
        with self.assertRaises(OSError):
            Client(self.root, sleep=lambda _: None, opener=opener).get('https://example.org')
        self.assertEqual(opener.call_count, 3)

    def test_malformed_json(self):
        with self.assertRaises(ValueError):
            Client(self.root, opener=lambda *a, **kw: Response(b'{bad')).json('https://example.org')

    def test_https_only(self):
        with self.assertRaises(ValueError):
            Client(self.root).get('http://example.org')

    def test_size_guard(self):
        with self.assertRaises(ValueError):
            Client(self.root, opener=lambda *a, **kw: Response(b'1234')).get('https://example.org', limit=3)

    def test_conditional_cache_integrity(self):
        first = Response(b'{"a":1}', headers={'ETag': '"one"'})
        not_modified = urllib.error.HTTPError('https://example.org', 304, 'unchanged', {}, None)
        opener = unittest.mock.Mock(side_effect=[first, not_modified])
        client = Client(self.root, opener=opener)
        path = client.get('https://example.org')
        self.assertEqual(client.get('https://example.org'), path)
        self.assertEqual(opener.call_args.args[0].get_header('If-none-match'), '"one"')

    def test_interrupted_range_resume(self):
        class Interrupted(Response):
            def read(self, amount=-1):
                if self.tell():
                    raise OSError('interrupted')
                return super().read(3)
        opener = unittest.mock.Mock(side_effect=[Interrupted(b'abcdef', headers={'ETag': '"v1"', 'Content-Length': '6'}), Response(b'def', status=206, headers={'ETag': '"v1"', 'Content-Range': 'bytes 3-5/6', 'Content-Length': '3'})])
        client = Client(self.root, sleep=lambda _: None, opener=opener)
        self.assertEqual(client.get('https://example.org').read_bytes(), b'abcdef')
        self.assertEqual(opener.call_args.args[0].get_header('Range'), 'bytes=3-')

    def test_invalid_range_rejected(self):
        with self.assertRaises(ValueError):
            Client(self.root, opener=lambda *a, **kw: Response(b'abc', status=206)).get('https://example.org')

    def test_atomic_size_and_old_file_preserved(self):
        path = self.root / 'old'
        path.write_bytes(b'old')
        with patch('scripts.common.MAX_FILE', 2), self.assertRaises(ValueError):
            atomic(path, b'big')
        self.assertEqual(path.read_bytes(), b'old')


class AdapterTests(unittest.TestCase):
    def test_epss(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'scores.gz'
            path.write_bytes(gzip.compress(b'#model_version=v4,score_date=2025-01-01\ncve,epss,percentile\nCVE-2025-12345,0.2,0.9\n'))
            rows = list(records('first-epss', FakeClient(path=path), '', '', {'kind': 'epss', 'url': 'https://example.org'}))
            self.assertEqual(rows[0][1]['epss'], 0.2)
            path.write_bytes(gzip.compress(b'#score_date=2025-01-01\ncve,epss,percentile\nCVE-2025-12345,2,0.9\n'))
            with self.assertRaises(ValueError):
                list(records('first-epss', FakeClient(path=path), '', '', {'kind': 'epss', 'url': 'https://example.org'}))

    def test_kev_count_integrity(self):
        with self.assertRaises(ValueError):
            list(records('kev', FakeClient({'count': 2, 'vulnerabilities': [KEV]}), '', '', {'kind': 'kev', 'url': 'https://example.org'}))

    def test_cve_delta_gap(self):
        logs = [{'fetchTime': '2025-01-02T00:00:00Z', 'new': [], 'updated': []}]
        with self.assertRaises(ValueError):
            list(records('cve', FakeClient(logs), '2025-01-01T00:00:00Z', '2025-01-03T00:00:00Z', {'kind': 'cve', 'url': 'https://example.org'}))

    def test_nvd_pagination(self):
        client = FakeClient({'startIndex': 0, 'totalResults': 1, 'vulnerabilities': [{'cve': {'id': CVE}}]})
        rows = list(records('nvd', client, '2025-01-01T00:00:00+00:00', '2025-01-02T00:00:00+00:00', {'kind': 'nvd', 'url': 'https://example.org'}))
        self.assertEqual(rows[0][0], CVE)
        self.assertIn('lastModStartDate=', client.urls[0])

    def test_xml_entities_rejected(self):
        with self.assertRaises(ValueError):
            xml_root(b'<!DOCTYPE x [<!ENTITY y "bad">]><x/>')

    def test_ghsa_patched_version_string(self):
        row = normalize('github-advisories', 'github', 'GHSA-test-test-test', {'ghsa_id': 'GHSA-test-test-test', 'vulnerabilities': [{'package': {'name': 'widget'}, 'first_patched_version': '1.2.3'}]})
        self.assertEqual(row['fixed_versions'], ['1.2.3'])

    def test_public_exploit_does_not_confirm_exploitation(self):
        row = normalize('nvd', 'nvd', CVE, {'id': CVE, 'references': [{'url': 'https://example.org', 'tags': ['Exploit']}]})
        self.assertEqual(len(row['exploit_references']), 1)
        self.assertFalse(prioritize([row])['confirmed_exploitation'])

    def test_version_boundaries_and_unknown(self):
        pkg = {'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}]}]}
        self.assertTrue(affected(pkg, '1.5.0'))
        self.assertFalse(affected(pkg, '2.0.0'))
        self.assertFalse(affected(pkg, '0.9.0'))
        self.assertTrue(affected(pkg, '2.0.0-rc.1'))
        self.assertIsNone(affected({'ranges': [{'type': 'ECOSYSTEM'}]}, '1.0'))
        self.assertIsNone(affected({'vulnerable_version_range': '< 2'}, '1'))


if __name__ == '__main__':
    unittest.main()

import gzip
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts.common import now, write_json
from scripts.http_client import Client, SafeRedirect
from scripts.normalize import normalize
from scripts.sources.feeds import records
from scripts.store import connect, ingest
from scripts.validate import validate
from scripts.sync import synchronize
from test_intelligence import CVE, RAW, FakeClient


class SafeguardTests(unittest.TestCase):
    def test_sync_trigger_gate_allows_manual_bootstrap_and_restricts_schedules(self):
        root = Path(__file__).resolve().parents[1]
        workflow = json.loads((root / '.github/workflows/sync.yml').read_text())
        condition = workflow['jobs']['sync']['if']
        # Exercise the actual workflow expression across unset/disabled/enabled
        # variables, manual/scheduled events, non-default branches and tags.
        for enabled in ('', 'false', 'true'):
            for event in ('workflow_dispatch', 'schedule'):
                for ref, ref_type in (('main', 'branch'), ('feature', 'branch'), ('main', 'tag')):
                    with self.subTest(enabled=enabled, event=event, ref=ref, ref_type=ref_type):
                        expression = condition
                        context = {
                            'github.event.repository.default_branch': 'main',
                            'github.event_name': event,
                            'github.ref_name': ref,
                            'github.ref_type': ref_type,
                            'vars.SYNC_ENABLED': enabled,
                        }
                        for key, value in context.items():
                            expression = expression.replace(key, repr(value))
                        expression = expression.replace('&&', ' and ').replace('||', ' or ')
                        actual = eval(expression, {'__builtins__': {}}, {})
                        expected = ref == 'main' and ref_type == 'branch' and (event == 'workflow_dispatch' or enabled == 'true')
                        self.assertEqual(actual, expected)

    def test_public_query_help_uses_generic_terminology(self):
        import subprocess
        import sys
        root = Path(__file__).resolve().parents[1]
        output = subprocess.check_output([sys.executable, 'scripts/query.py', '--help'], cwd=root, text=True)
        self.assertIn('Read-only local vulnerability search', output)
        for name in ('Kakashi', 'Itachi', 'kakashi', 'itachi'):
            self.assertNotIn(name, output)

    def test_legacy_query_client_argument_still_works(self):
        import contextlib
        import io
        from scripts import query
        for legacy in ('kakashi', 'itachi'):
            with patch('sys.argv', ['query.py', '--agent', legacy, '--value', CVE]), patch('scripts.query.Reader') as reader, contextlib.redirect_stdout(io.StringIO()) as output:
                reader.return_value.search.return_value = []
                query.main()
                self.assertEqual(json.loads(output.getvalue()), [])
                reader.return_value.search.assert_called_once_with('id', CVE)
                reader.return_value.close.assert_called_once()

    def test_incremental_watermark_uses_last_success_with_overlap(self):
        from datetime import datetime, timedelta, timezone
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = {'sources': {'nvd': {'kind': 'nvd', 'url': 'https://example.org', 'coverage': 'test', 'enabled': True}}}
            prior = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            db = connect(root / 'indexes/intelligence.sqlite')
            ingest(db, 'nvd', 'nvd', [(CVE, {'id': CVE})], prior)
            db.close()
            with patch('scripts.sync.records', return_value=iter([])) as adapter:
                self.assertEqual(synchronize(root, config=cfg, client=FakeClient()), 0)
                since = adapter.call_args.args[2]
                self.assertEqual(datetime.fromisoformat(since), datetime.fromisoformat(prior) - timedelta(minutes=5))

    def test_gitignore_keeps_curated_and_excludes_local_state(self):
        import subprocess
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(['git', 'init', '-q', str(repo)], check=True, capture_output=True)
            (repo / '.gitignore').write_bytes((root / '.gitignore').read_bytes())
            for candidate in ('indexes/intelligence.sqlite', '.cache/http/test.body', 'backups/snapshot.zip', '.env.local', 'dist/release.json', 'build/package.py', '.release/notes.md', 'example.egg-info/PKG-INFO', 'docs/internal/README.private.md', 'debug.bak'):
                check = subprocess.run(['git', 'check-ignore', candidate], cwd=repo, capture_output=True)
                self.assertEqual(check.returncode, 0, candidate)
            for candidate in ('data/curated/source/aa/CVE-2025-12345.json', 'metadata/sync-status.json', 'config/sources.json'):
                check = subprocess.run(['git', 'check-ignore', candidate], cwd=repo, capture_output=True)
                self.assertEqual(check.returncode, 1, candidate)

    def test_redirect_downgrade_rejected_and_credentials_stripped(self):
        import urllib.request
        request = urllib.request.Request('https://api.example.org', headers={'Authorization': 'Bearer synthetic', 'apiKey': 'synthetic'})
        handler = SafeRedirect()
        with self.assertRaises(ValueError):
            handler.redirect_request(request, None, 302, '', {}, 'http://example.org')
        redirected = handler.redirect_request(request, None, 302, '', {}, 'https://other.example.org')
        self.assertFalse(any(k.lower() in ('authorization', 'apikey') for k in redirected.headers))

    def test_previous_cve_revision_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            db = connect(Path(directory) / 'intel.sqlite')
            try:
                ingest(db, 'cve', 'cve', [(CVE, RAW)], now())
                ingest(db, 'cve', 'cve', [(CVE, {**RAW, 'revision': 2})], now())
                self.assertEqual(json.loads(db.execute('SELECT raw FROM history').fetchone()[0]), RAW)
            finally:
                db.close()

    def test_epss_current_colon_header(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'scores.gz'
            path.write_bytes(gzip.compress(b'#model_version:v2026.06.15,score_date:2026-10-28T12:03:13Z\ncve,epss,percentile\nCVE-2025-12345,0.2,0.9\n'))
            rows = list(records('epss', FakeClient(path=path), '', '', {'kind': 'epss', 'url': 'https://example.org'}))
            self.assertEqual(rows[0][1]['date'], '2026-10-28T12:03:13Z')

    def test_cve_delta_exact_identifier_and_timezone(self):
        logs = [{'fetchTime': '2025-01-02T00:00:00Z', 'new': [{'cveId': CVE}], 'updated': [], 'error': []}]
        client = FakeClient()
        client.json = Mock(side_effect=[logs, RAW])
        rows = list(records('cve', client, '2025-01-02T00:00:00+00:00', '2025-01-03T00:00:00Z', {'kind': 'cve', 'url': 'https://example.org'}))
        self.assertEqual(rows[0][0], CVE)
        self.assertIn('/2025/12xxx/', client.json.call_args.args[0])

    def test_osv_package_query_and_pagination(self):
        client = FakeClient()
        client.post_json = Mock(side_effect=[{'vulns': [{'id': 'OSV-2025-1'}], 'next_page_token': 'next'}, {'vulns': [{'id': 'OSV-2025-2'}]}])
        client.json = Mock(side_effect=[{'id': 'OSV-2025-1'}, {'id': 'OSV-2025-2'}])
        cfg = {'kind': 'osv', 'url': 'https://api.osv.dev/v1/vulns', 'packages': [{'name': 'widget', 'ecosystem': 'npm', 'version': '1.0.0'}]}
        self.assertEqual(len(list(records('osv', client, '', '', cfg))), 2)
        self.assertEqual(client.post_json.call_count, 2)

    def test_corruption_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = connect(root / 'indexes/intelligence.sqlite')
            ingest(db, 'cve', 'cve', [(CVE, RAW)], now())
            with db:
                db.execute("UPDATE records SET hash='bad'")
            db.close()
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                validate(root)

    def test_git_size_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'large.json').write_bytes(b'0' * 100)
            with patch('scripts.validate.MAX_FILE', 50), self.assertRaisesRegex(ValueError, 'Oversized'):
                validate(root)

    def test_secret_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'unsafe.txt').write_text('gh' + 'p_' + 'A' * 36)
            with self.assertRaisesRegex(ValueError, 'Possible secret'):
                validate(root)

    def test_yaml_workflow_and_action_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'workflow.yml'
            write_json(path, {'on': {'push': {}}, 'jobs': {'test': {'steps': [{'uses': 'actions/checkout@v4'}]}}})
            with self.assertRaisesRegex(ValueError, 'unpinned'):
                validate(root)
            write_json(path, {'on': {'push': {}}, 'jobs': {'test': {'steps': [{'uses': 'actions/checkout@' + 'a' * 40}]}}})
            validate(root)

    def test_disputed_flag(self):
        raw = {**RAW, 'containers': {'cna': {'tags': ['disputed']}}}
        self.assertTrue(normalize('cve', 'cve', CVE, raw)['disputed'])

    def test_regenerable_cache_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / ('a' * 64 + '.body')
            path.write_bytes(b'download')
            unrelated = root / 'user.txt'
            unrelated.write_text('keep')
            Client(root).prune(retention_days=7, max_bytes=1)
            self.assertFalse(path.exists())
            self.assertTrue(unrelated.exists())


if __name__ == '__main__':
    unittest.main()

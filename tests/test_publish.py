import subprocess
import os
import unittest
from unittest.mock import patch
from scripts.publish_data import main


def result(code=0, output=''):
    return subprocess.CompletedProcess([], code, output, '')


@patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'})
class PublishTests(unittest.TestCase):
    @patch('scripts.publish_data.git')
    def test_unrelated_changes_stop_before_staging(self, git):
        git.return_value = result(output=' M README.md\n')
        with self.assertRaises(RuntimeError):
            main()
        self.assertFalse(any(c.args and c.args[0] == 'add' for c in git.call_args_list))

    @patch('scripts.publish_data.git')
    def test_bounded_push_rebase_retries(self, git):
        def command(*args, **kwargs):
            if args[0] == 'status':
                return result()
            if args[0] == 'diff':
                return result(1)
            if args[0] == 'branch':
                return result(output='main\n')
            if args[0] == 'push':
                return result(1)
            return result()
        git.side_effect = command
        with self.assertRaisesRegex(RuntimeError, 'three attempts'):
            main()
        self.assertEqual(sum(c.args[0] == 'push' for c in git.call_args_list), 3)
        self.assertEqual(sum(c.args[0] == 'fetch' for c in git.call_args_list), 2)
        self.assertFalse(any('--force' in c.args for c in git.call_args_list))

    @patch('scripts.publish_data.git')
    def test_rebase_conflict_aborts(self, git):
        def command(*args, **kwargs):
            if args[0] == 'diff' or args[0] == 'push':
                return result(1)
            if args[0] == 'branch':
                return result(output='main\n')
            if args[0] == 'rebase' and args[1] != '--abort':
                return result(1)
            return result()
        git.side_effect = command
        with self.assertRaisesRegex(RuntimeError, 'Rebase conflict'):
            main()
        git.assert_any_call('rebase', '--abort')

    @patch('scripts.publish_data.git')
    def test_no_changes_no_commit(self, git):
        git.return_value = result()
        main()
        self.assertFalse(any(c.args[0] in ('push', 'commit') for c in git.call_args_list))

import copy
import io
import json
import hashlib
import tempfile
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock
from scripts import release as rel
from scripts.common import write_json, read_json
from scripts.store import connect, ingest
from test_intelligence import CVE, RAW, KEV, Response

REPOSITORY = 'Pepperjack-svg/THREAT-BASE'
COMMIT = 'a' * 40
SNAPSHOT = datetime(2026, 10, 31, 19, 30, tzinfo=timezone.utc)
SUCCESS = '2026-10-31T18:45:00+00:00'
RUN = {'id': 123, 'run_attempt': 1, 'head_sha': COMMIT,
       'run_started_at': '2026-10-31T18:30:00+00:00', 'updated_at': '2026-10-31T19:00:00+00:00'}


def plan_fixture():
    return {'skip': False, 'version': '2026.11', 'tag': 'v2026.11',
            'title': 'THREAT-BASE November 2026', 'commit': COMMIT,
            'snapshot_at': SNAPSHOT.isoformat(), 'repository': REPOSITORY,
            'branch': 'main', 'sync': copy.deepcopy(RUN), 'cache_key': 'intel-v1-main-123-1'}


class Remote:
    """In-memory GitHub API with no live network operations."""
    def __init__(self):
        self.repository = REPOSITORY
        self.base = '/repos/' + REPOSITORY
        self.release = None
        self.files = {}
        self.payloads = {}
        self.upload_calls = []
        self.sleep = Mock()
        self.create_timeout = False
        self.upload_timeout = None
        self.upload_fail = None
        self.orphan_tag = False
        self.patches = 0
        self.get_run = {**copy.deepcopy(RUN), 'status': 'completed', 'conclusion': 'success',
                        'event': 'schedule', 'head_branch': 'main', 'head_repository': {'full_name': REPOSITORY}}

    def request(self, path, payload=None, method=None, missing_ok=False):
        if path == self.base:
            return {'full_name': REPOSITORY, 'default_branch': 'main'}
        if '/actions/workflows/' in path:
            return {'workflow_runs': [self.get_run]}
        if '/compare/' in path:
            return {'status': 'ahead', 'files': []}
        if '/releases/tags/' in path:
            return copy.deepcopy(self.release)
        if '/git/ref/tags/' in path:
            return {'object': {'type': 'commit', 'sha': COMMIT}} if self.orphan_tag else None
        if path == self.base + '/releases' and payload is not None:
            self.release = {**payload, 'id': 1, 'html_url': 'https://github.com/' + REPOSITORY + '/releases/tag/' + payload['tag_name']}
            if self.create_timeout:
                self.create_timeout = False
                raise OSError('creation succeeded, connection interrupted')
            return copy.deepcopy(self.release)
        if method == 'PATCH':
            self.patches += 1
            self.release.update(payload)
            return copy.deepcopy(self.release)
        raise AssertionError('Unexpected API operation: ' + path)

    def assets(self, release_id):
        return copy.deepcopy(list(self.files.values()))

    def upload(self, release_id, path):
        self.upload_calls.append(path.name)
        if path.name == self.upload_fail:
            raise OSError('upload interrupted before completion')
        body = path.read_bytes()
        item = {'id': len(self.files) + 1, 'name': path.name, 'size': len(body),
                'state': 'uploaded', 'digest': 'sha256:' + hashlib.sha256(body).hexdigest()}
        self.files[path.name] = item
        self.payloads[item['id']] = body
        if path.name == self.upload_timeout:
            self.upload_timeout = None
            raise OSError('upload accepted, response interrupted')
        return copy.deepcopy(item)

    def download(self, asset_id, target, limit=rel.MAX_ASSET):
        body = self.payloads[asset_id]
        if len(body) > limit:
            raise ValueError('download exceeds limit')
        Path(target).write_bytes(body)


class MonthlyDataReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.plan = plan_fixture()
        self.remote = Remote()
        (self.root / 'docs').mkdir()
        for filename in ('LICENSE', 'DATA_SOURCES.md', 'docs/SOURCES.md'):
            (self.root / filename).write_text('Synthetic test attribution, not production data.\n')
        config = {'sources': {name: {'enabled': True, 'kind': kind, 'coverage': 'Synthetic test scope'}
                             for name, kind in [('cve', 'cve'), ('kev', 'kev'), ('epss', 'epss')]}}
        for name, value in config['sources'].items():
            value['url'] = 'https://example.org/' + name
            value['attribution'] = {
                'publisher': 'Synthetic test publisher ' + name,
                'publisher_urls': ['https://example.org/'],
                'dataset_urls': [value['url']], 'license_name': 'Synthetic test-only terms',
                'license_urls': ['https://example.org/terms'],
                'attribution_requirements': 'Retain the synthetic test credit.',
                'modifications': 'Synthetic fixtures normalized and partitioned.',
                'redistribution_restrictions': 'Fixture only; not a production rights assertion.',
                'last_verified': '2026-10-29'}
        write_json(self.root / 'config/sources.json', config)
        write_json(self.root / 'metadata/sources.json', config)
        write_json(self.root / 'metadata/sync-status.json', {'sources': {
            key: {'status': 'ok', 'last_success': SUCCESS, 'received': 1} for key in config['sources']}})
        db = connect(self.root / 'indexes/intelligence.sqlite')
        try:
            with patch('scripts.store.now', return_value=SUCCESS):
                ingest(db, 'cve', 'cve', [(CVE, RAW)], SUCCESS)
                ingest(db, 'kev', 'kev', [(CVE, KEV)], SUCCESS)
                ingest(db, 'epss', 'epss', [(CVE, {'cve': CVE, 'epss': 0.2, 'percentile': 0.9, 'date': '2026-10-31T12:00:00Z'})], SUCCESS)
        finally:
            db.close()

    def tearDown(self):
        self.temp.cleanup()

    def prepared(self, **kwargs):
        sources = rel.validate_sources(self.root, self.plan, SNAPSHOT)
        manifest = rel.prepare_assets(self.root, self.plan, sources, {}, **kwargs)
        return self.root / 'dist', manifest

    def change_status(self, source, **changes):
        path = self.root / 'metadata/sync-status.json'
        value = read_json(path)
        value['sources'][source].update(changes)
        write_json(path, value)

    def test_ist_month_and_calendar_tags(self):
        before = datetime(2026, 10, 31, 18, 29, tzinfo=timezone.utc)
        after = before + timedelta(minutes=1)
        self.assertEqual(rel.version(before)[1], 'v2026.10')
        self.assertEqual(rel.version(after)[0:2], ('2026.11', 'v2026.11'))
        self.assertIn('November 2026', rel.version(after)[2])
        with self.assertRaises(ValueError):
            rel.version(datetime(2026, 11, 1))

    def test_plan_binds_exact_sync_cache(self):
        plan = rel.plan_release(self.remote, 'main', COMMIT, SNAPSHOT)
        self.assertEqual(plan['cache_key'], 'intel-v1-main-123-1')
        self.assertEqual(plan['tag'], 'v2026.11')

    def test_failed_or_running_latest_sync_is_rejected(self):
        for status, conclusion in [('completed', 'failure'), ('in_progress', None)]:
            self.remote.get_run.update(status=status, conclusion=conclusion)
            with self.assertRaisesRegex(ValueError, 'not completed/successful'):
                rel.plan_release(self.remote, 'main', COMMIT, SNAPSHOT)

    def test_stale_latest_sync_is_rejected(self):
        self.remote.get_run['updated_at'] = '2026-10-01T00:00:00Z'
        with self.assertRaisesRegex(ValueError, 'stale'):
            rel.plan_release(self.remote, 'main', COMMIT, SNAPSHOT)

    def test_missing_daily_run_is_rejected(self):
        api = Mock(base=self.remote.base, repository=REPOSITORY)
        api.request.side_effect = [{'full_name': REPOSITORY, 'default_branch': 'main'}, {'workflow_runs': []}]
        with self.assertRaisesRegex(ValueError, 'No daily'):
            rel.latest_sync(api, 'main', COMMIT, SNAPSHOT)

    def test_code_changes_after_successful_sync_are_rejected(self):
        self.remote.get_run['head_sha'] = 'b' * 40
        with patch('scripts.release.subprocess.run'), patch('scripts.release.subprocess.check_output', return_value=b'config/sources.json\0'):
            with self.assertRaisesRegex(ValueError, 'Code/config changed'):
                rel.latest_sync(self.remote, 'main', COMMIT, SNAPSHOT)

    def test_data_bot_commit_uses_complete_git_diff(self):
        self.remote.get_run['head_sha'] = 'b' * 40
        paths = b'\0'.join(f'data/curated/epss/{number}.json'.encode() for number in range(1000))
        with patch('scripts.release.subprocess.run'), patch('scripts.release.subprocess.check_output', return_value=paths) as diff:
            result = rel.latest_sync(self.remote, 'main', COMMIT, SNAPSHOT)
            self.assertEqual(result['id'], RUN['id'])
            self.assertIn('--name-only', diff.call_args.args[0])

    def test_missing_dataset_is_rejected(self):
        db = connect(self.root / 'indexes/intelligence.sqlite')
        with db:
            db.execute("DELETE FROM records WHERE source='cve'")
        db.close()
        with self.assertRaisesRegex(ValueError, 'no dataset'):
            rel.validate_sources(self.root, self.plan, SNAPSHOT)

    def test_missing_database_is_rejected(self):
        with tempfile.TemporaryDirectory() as empty:
            with self.assertRaisesRegex(ValueError, 'Missing daily-sync database'):
                rel.validate_sources(Path(empty), self.plan, SNAPSHOT)

    def test_required_failed_partial_or_missing_source_is_rejected(self):
        for status in ('FAILED', 'error', 'PARTIAL', 'not_implemented'):
            self.change_status('cve', status=status)
            with self.assertRaisesRegex(ValueError, 'failed, partial or missing'):
                rel.validate_sources(self.root, self.plan, SNAPSHOT)

    def test_stale_source_metadata_is_rejected(self):
        self.change_status('cve', last_success='2026-10-01T00:00:00Z')
        with self.assertRaisesRegex(ValueError, 'stale'):
            rel.validate_sources(self.root, self.plan, SNAPSHOT)

    def test_source_outside_daily_run_is_rejected(self):
        self.change_status('cve', last_success='2026-10-31T17:00:00Z')
        with self.assertRaisesRegex(ValueError, 'not validated in the latest'):
            rel.validate_sources(self.root, self.plan, SNAPSHOT)

    def test_checkpoint_mismatch_is_rejected(self):
        self.change_status('cve', last_success='2026-10-31T18:46:00Z')
        with self.assertRaisesRegex(ValueError, 'checkpoint mismatch'):
            rel.validate_sources(self.root, self.plan, SNAPSHOT)

    def test_corrupted_raw_and_normalized_records_are_rejected(self):
        db = connect(self.root / 'indexes/intelligence.sqlite')
        with db:
            db.execute("UPDATE records SET normalized='{}' WHERE source='cve'")
        db.close()
        with self.assertRaisesRegex(ValueError, 'normalization mismatch'):
            rel.validate_sources(self.root, self.plan, SNAPSHOT)

    def test_raw_content_hash_failure_is_rejected(self):
        db = connect(self.root / 'indexes/intelligence.sqlite')
        with db:
            db.execute("UPDATE records SET hash='bad' WHERE source='cve'")
        db.close()
        with self.assertRaisesRegex(ValueError, 'integrity failure'):
            rel.validate_sources(self.root, self.plan, SNAPSHOT)

    def test_stale_epss_score_date_is_rejected_even_when_source_check_is_fresh(self):
        db = connect(self.root / 'indexes/intelligence.sqlite')
        raw = {'cve': CVE, 'epss': 0.2, 'percentile': 0.9, 'date': '2026-10-01T12:00:00Z'}
        ingest(db, 'epss', 'epss', [(CVE, raw)], SUCCESS)
        db.close()
        with self.assertRaisesRegex(ValueError, 'stale or future score dates'):
            rel.validate_sources(self.root, self.plan, SNAPSHOT)

    def test_required_notices_cannot_be_omitted(self):
        with self.assertRaisesRegex(ValueError, 'Required upstream notice'):
            rel.prepare_assets(self.root, self.plan, {'cwe': {'kind': 'catalog'}}, {})

    def test_archive_contents_checksums_and_notes_are_valid(self):
        output, manifest = self.prepared()
        self.assertEqual(sum(x.get('records', 0) for x in manifest['assets']), 3)
        for item in manifest['assets']:
            if item['group'] != 'metadata':
                self.assertEqual(rel.verify_archive(output / item['name']), item['records'])
        self.assertTrue({'cve', 'kev', 'epss', 'metadata'} == {x['group'] for x in manifest['assets']})
        rel.verify_local(output, manifest)
        notes = (output / 'release-notes.md').read_text()
        self.assertIn('Not recorded', notes)
        self.assertIn('New/updated counts are not measured', notes)
        self.assertIn(SUCCESS, notes)
        self.assertFalse(any('private' in p.name for p in output.iterdir()))

    def test_original_publishers_are_embedded_in_manifest_metadata_and_notes(self):
        import tarfile
        output, manifest = self.prepared()
        self.assertEqual(set(manifest['source_attribution']), {'cve', 'kev', 'epss'})
        self.assertIn('Synthetic test publisher cve', (output / 'release-notes.md').read_text())
        self.assertIn('https://example.org/cve', (output / 'release-notes.md').read_text())
        metadata = next(x for x in manifest['assets'] if x['group'] == 'metadata')
        with tarfile.open(output / metadata['name'], 'r:gz') as archive:
            attribution = json.load(archive.extractfile('attribution.json'))
        self.assertEqual(attribution, manifest['source_attribution'])
        self.assertEqual(attribution['cve']['modifications'], 'Synthetic fixtures normalized and partitioned.')

    def test_upstream_copyright_and_license_bytes_are_preserved(self):
        import tarfile
        notice = b'Copyright original publisher\r\nOriginal license and disclaimer.\r\n'
        sources = rel.validate_sources(self.root, self.plan, SNAPSHOT)
        manifest = rel.prepare_assets(self.root, self.plan, sources, {'kev': notice})
        path = self.root / 'dist'
        for item in manifest['assets']:
            if item['group'] not in ('kev', 'metadata'):
                continue
            with tarfile.open(path / item['name'], 'r:gz') as archive:
                actual = archive.extractfile('attribution/kev/kev-upstream-license.txt').read()
            self.assertEqual(actual, notice)
        self.assertEqual(manifest['source_attribution']['kev']['upstream_notice_sha256'],
                         {'kev-upstream-license.txt': hashlib.sha256(notice).hexdigest()})

    def test_missing_original_publisher_attribution_stops_packaging(self):
        config = read_json(self.root / 'config/sources.json')
        config['sources']['cve']['attribution'].pop('publisher')
        write_json(self.root / 'config/sources.json', config)
        with self.assertRaisesRegex(ValueError, 'Incomplete original-publisher'):
            self.prepared()

    def test_disabled_source_not_added_to_release_attribution(self):
        config = read_json(self.root / 'config/sources.json')
        config['sources']['disabled'] = {'enabled': False, 'kind': 'rss'}
        write_json(self.root / 'config/sources.json', config)
        _, manifest = self.prepared()
        self.assertNotIn('disabled', manifest['source_attribution'])

    def test_osv_original_publisher_and_notice_are_selected_by_actual_origin(self):
        root = Path(__file__).resolve().parents[1]
        config = read_json(root / 'config/sources.json')['sources']
        sources = {'osv': {'kind': 'osv', 'origin_prefixes': ['PYSEC-']}}
        notices = {'osv': {'pypa-LICENSE': b'Original PyPA notice'}}
        value = rel.release_attribution(config, sources, notices)['osv']
        self.assertEqual([o['id_prefix'] for o in value['original_publishers']], ['PYSEC-'])
        self.assertIn('PyPA', value['original_publishers'][0]['publisher'])
        with self.assertRaisesRegex(ValueError, 'license text is missing'):
            rel.release_attribution(config, sources, {'osv': {'github-LICENSE.md': b'GitHub license'}})

    def test_source_credit_registry_matches_public_docs_and_configured_urls(self):
        root = Path(__file__).resolve().parents[1]
        config = read_json(root / 'config/sources.json')['sources']
        readme = (root / 'README.md').read_text(encoding='utf-8')
        docs = (root / 'DATA_SOURCES.md').read_text(encoding='utf-8')
        for name, value in config.items():
            info = value['attribution']
            self.assertIn(value['url'], docs)
            self.assertIn(value['url'], info['dataset_urls'])
            for url in info['publisher_urls']:
                self.assertIn(url, readme)
                self.assertIn(url, docs)
            for original in info.get('original_publishers', []):
                self.assertIn(original['publisher_url'], readme)
                self.assertIn(original['license_url'], docs)
        self.assertEqual(read_json(root / 'metadata/sources.json')['sources'], config)

    def test_archive_preparation_is_deterministic(self):
        output, first = self.prepared()
        before = {p.name: p.read_bytes() for p in output.iterdir() if p.is_file()}
        _, second = self.prepared()
        self.assertEqual(first, second)
        self.assertEqual(before, {p.name: p.read_bytes() for p in output.iterdir() if p.is_file()})

    def test_asset_partitioning(self):
        db = connect(self.root / 'indexes/intelligence.sqlite')
        raw = copy.deepcopy(RAW)
        raw['cveMetadata']['cveId'] = 'CVE-2025-12346'
        ingest(db, 'cve', 'cve', [('CVE-2025-12346', raw)], SUCCESS)
        db.close()
        _, manifest = self.prepared(part_bytes=1)
        self.assertEqual(len([x for x in manifest['assets'] if x['group'] == 'cve']), 2)

    def test_invalid_archive_and_modified_checksum_are_rejected(self):
        import tarfile
        output, manifest = self.prepared()
        path = output / manifest['assets'][0]['name']
        path.write_bytes(b'corrupted archive')
        with self.assertRaises((ValueError, tarfile.TarError, OSError)):
            rel.verify_archive(path)
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            rel.verify_local(output, manifest)

    def test_duplicate_checksum_names_are_rejected(self):
        line = 'a' * 64 + '  example.tar.gz\n'
        with self.assertRaises(ValueError):
            rel.parse_sums(line + line)

    def test_draft_is_published_only_after_all_assets_verify(self):
        output, manifest = self.prepared()
        self.assertEqual(rel.publish_assets(self.remote, self.plan, output, manifest), 'published')
        self.assertFalse(self.remote.release['draft'])
        self.assertEqual(self.remote.patches, 1)
        self.assertEqual(len(self.remote.files), len(manifest['assets']) + 2)

    def test_published_duplicate_skips_without_uploads(self):
        output, manifest = self.prepared()
        rel.publish_assets(self.remote, self.plan, output, manifest)
        count = len(self.remote.upload_calls)
        plan = rel.plan_release(self.remote, 'main', COMMIT, SNAPSHOT)
        self.assertTrue(plan['skip'])
        self.assertEqual(len(self.remote.upload_calls), count)

    def test_published_release_missing_assets_fails_without_overwrite(self):
        output, manifest = self.prepared()
        rel.publish_assets(self.remote, self.plan, output, manifest)
        del self.remote.files[manifest['assets'][0]['name']]
        with self.assertRaisesRegex(ValueError, 'missing/incomplete'):
            rel.plan_release(self.remote, 'main', COMMIT, SNAPSHOT)
        self.assertEqual(self.remote.patches, 1)

    def test_existing_tag_is_not_overwritten(self):
        self.remote.orphan_tag = True
        with self.assertRaisesRegex(ValueError, 'tag already exists'):
            rel.plan_release(self.remote, 'main', COMMIT, SNAPSHOT)
        self.assertIsNone(self.remote.release)

    def test_ambiguous_creation_recovers_same_draft(self):
        output, manifest = self.prepared()
        self.remote.create_timeout = True
        self.assertEqual(rel.publish_assets(self.remote, self.plan, output, manifest), 'published')
        self.assertEqual(self.remote.patches, 1)

    def test_draft_creation_race_reuses_verified_draft(self):
        output, manifest = self.prepared()
        original = self.remote.request
        raced = False
        def request(path, payload=None, **kwargs):
            nonlocal raced
            value = original(path, payload, **kwargs)
            if path == self.remote.base + '/releases' and payload and not raced:
                raced = True
                raise rel.APIError(422)
            return value
        self.remote.request = request
        self.assertEqual(rel.publish_assets(self.remote, self.plan, output, manifest), 'published')
        self.assertTrue(raced)
        self.assertEqual(self.remote.patches, 1)

    def test_interrupted_upload_that_succeeded_is_not_reuploaded(self):
        output, manifest = self.prepared()
        name = manifest['assets'][0]['name']
        self.remote.upload_timeout = name
        rel.publish_assets(self.remote, self.plan, output, manifest)
        self.assertEqual(self.remote.upload_calls.count(name), 1)

    def test_failed_upload_leaves_recoverable_draft(self):
        output, manifest = self.prepared()
        name = manifest['assets'][1]['name']
        self.remote.upload_fail = name
        with self.assertRaisesRegex(RuntimeError, 'draft retained'):
            rel.publish_assets(self.remote, self.plan, output, manifest)
        self.assertTrue(self.remote.release['draft'])
        self.assertEqual(self.remote.patches, 0)
        recovered = rel.plan_release(self.remote, 'main', COMMIT, SNAPSHOT + timedelta(minutes=5))
        self.assertEqual(recovered['snapshot_at'], self.plan['snapshot_at'])
        self.remote.upload_fail = None
        self.assertEqual(rel.publish_assets(self.remote, self.plan, output, manifest), 'published')
        self.assertEqual(self.remote.upload_calls.count(manifest['assets'][0]['name']), 1)

    def test_foreign_draft_is_not_modified(self):
        output, manifest = self.prepared()
        self.remote.release = {'id': 1, 'draft': True, 'target_commitish': COMMIT, 'body': 'someone else'}
        with self.assertRaisesRegex(ValueError, 'another snapshot'):
            rel.publish_assets(self.remote, self.plan, output, manifest)
        self.assertEqual(self.remote.patches, 0)
        self.assertEqual(self.remote.upload_calls, [])

    def test_partial_existing_asset_is_not_overwritten(self):
        output, manifest = self.prepared()
        rel.ensure_draft(self.remote, self.plan, manifest, (output / 'release-notes.md').read_text())
        name = manifest['assets'][0]['name']
        self.remote.files[name] = {'id': 99, 'name': name, 'state': 'starter', 'size': 0}
        with self.assertRaisesRegex(ValueError, 'Incomplete/conflicting'):
            rel.publish_assets(self.remote, self.plan, output, manifest)
        self.assertEqual(self.remote.upload_calls, [])
        self.assertTrue(self.remote.release['draft'])

    def test_remote_checksum_mismatch_leaves_draft(self):
        output, manifest = self.prepared()
        rel.ensure_draft(self.remote, self.plan, manifest, (output / 'release-notes.md').read_text())
        name = manifest['assets'][0]['name'];path = output / name
        self.remote.files[name] = {'id': 99, 'name': name, 'state': 'uploaded', 'size': path.stat().st_size, 'digest': 'sha256:' + '0' * 64}
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            rel.publish_assets(self.remote, self.plan, output, manifest)
        self.assertEqual(self.remote.patches, 0)

    def test_server_without_asset_digest_is_verified_by_download(self):
        output, manifest = self.prepared()
        original = self.remote.upload
        def upload(release_id, path):
            value = original(release_id, path)
            value.pop('digest')
            self.remote.files[path.name].pop('digest')
            return value
        self.remote.upload = upload
        self.assertEqual(rel.publish_assets(self.remote, self.plan, output, manifest), 'published')
        self.assertTrue(rel.plan_release(self.remote, 'main', COMMIT, SNAPSHOT)['skip'])

    def test_manual_workflow_uses_same_plan_and_duplicate_rules(self):
        env = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
               'GITHUB_REF_TYPE': 'branch', 'GITHUB_REF_NAME': 'main', 'DEFAULT_BRANCH': 'main',
               'GITHUB_SHA': COMMIT, 'GH_TOKEN': 'synthetic', 'GITHUB_REPOSITORY': REPOSITORY,
               'GITHUB_OUTPUT': str(self.root / 'outputs')}
        with patch.dict(os.environ, env), patch('scripts.release.ROOT', self.root), patch('sys.argv', ['release.py', 'plan']), patch('scripts.release.subprocess.check_output', return_value=COMMIT), patch('scripts.release.GitHub', return_value=self.remote), patch('scripts.release.plan_release', return_value=self.plan) as planner:
            rel.main()
            planner.assert_called_once()
        self.assertIn('cache_key=intel-v1-main-123-1', (self.root / 'outputs').read_text())

    def test_local_publication_refused(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), patch('sys.argv', ['release.py', 'publish']):
            with self.assertRaisesRegex(RuntimeError, 'approved GitHub Actions'):
                rel.main()

    def test_workflow_daily_monthly_permissions_and_exact_state_restore(self):
        root = Path(__file__).resolve().parents[1]
        workflow = json.loads((root / '.github/workflows/release.yml').read_text())
        self.assertEqual(workflow['on']['schedule'], [{'cron': '0 1 1 * *', 'timezone': 'Asia/Kolkata'}])
        self.assertIn('workflow_dispatch', workflow['on'])
        self.assertEqual(workflow['permissions'], {'contents': 'read', 'actions': 'read'})
        self.assertFalse(workflow['concurrency']['cancel-in-progress'])
        self.assertEqual(workflow['jobs']['release']['permissions']['contents'], 'write')
        restore = next(s for s in workflow['jobs']['release']['steps'] if s.get('name') == 'Restore exact successful daily-sync state')
        self.assertTrue(restore['with']['fail-on-cache-miss'])
        self.assertNotIn('restore-keys', restore['with'])
        daily = json.loads((root / '.github/workflows/sync.yml').read_text())
        self.assertEqual(daily['on']['schedule'], [{'cron': '0 0 * * *', 'timezone': 'Asia/Kolkata'}])


class GitHubReleaseAPITests(unittest.TestCase):
    def test_get_rate_limit_retries(self):
        error = urllib.error.HTTPError('https://api.github.com', 429, 'rate limit', {'Retry-After': '2'}, None)
        opener = Mock(side_effect=[error, Response(b'{"ok":true}')])
        client = rel.GitHub(REPOSITORY, 'synthetic', opener=opener, sleep=Mock())
        self.assertEqual(client.request(client.base), {'ok': True})
        self.assertEqual(opener.call_count, 2)
        client.sleep.assert_called_once_with(2)

    def test_long_rate_limit_does_not_retry_early(self):
        error = urllib.error.HTTPError('https://api.github.com', 429, 'rate limit', {'Retry-After': '600'}, None)
        opener = Mock(side_effect=error)
        client = rel.GitHub(REPOSITORY, 'synthetic', opener=opener, sleep=Mock())
        with self.assertRaises(rel.APIError):
            client.request(client.base)
        self.assertEqual(opener.call_count, 1)

    def test_permission_failure_is_not_missing_release(self):
        error = urllib.error.HTTPError('https://api.github.com', 403, 'forbidden', {}, None)
        client = rel.GitHub(REPOSITORY, 'synthetic', opener=Mock(side_effect=error), sleep=Mock())
        with self.assertRaises(rel.APIError):
            client.request(client.base + '/releases/tags/v2026.11', missing_ok=True)

    def test_temporary_api_failures_are_bounded(self):
        opener = Mock(side_effect=OSError('unreachable'))
        client = rel.GitHub(REPOSITORY, 'synthetic', opener=opener, sleep=Mock())
        with self.assertRaisesRegex(RuntimeError, 'connection failed'):
            client.request(client.base)
        self.assertEqual(opener.call_count, 3)

    def test_creation_post_is_not_blindly_retried(self):
        opener = Mock(side_effect=OSError('ambiguous'))
        client = rel.GitHub(REPOSITORY, 'synthetic', opener=opener, sleep=Mock())
        with self.assertRaises(RuntimeError):
            client.request(client.base + '/releases', {'draft': True})
        self.assertEqual(opener.call_count, 1)


if __name__ == '__main__':
    unittest.main()

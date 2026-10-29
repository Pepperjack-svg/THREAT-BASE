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


if __name__ == '__main__':
    unittest.main()

"""Workflow-only scoped commit with bounded non-fast-forward recovery."""
import subprocess
import os


def git(*args, check=True):
    return subprocess.run(['git', *args], check=check, text=True, capture_output=True)


def main():
    # This helper is never called by sync.py. Run only in an approved Actions deployment.
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('Publication is restricted to the approved GitHub Actions workflow')
    if git('status', '--porcelain').stdout.strip():
        lines = git('status', '--porcelain', '-uall').stdout.splitlines()
        for line in lines:
            path = line[3:].strip('"')
            if not path.startswith(('data/curated/', 'data/cisa-kev/', 'metadata/')):
                raise RuntimeError('Unrelated working changes; refusing to stage or publish')
    git('config', 'user.name', 'github-actions[bot]')
    git('config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com')
    git('add', '--', 'data/curated', 'data/cisa-kev', 'metadata')
    if git('diff', '--cached', '--quiet', check=False).returncode == 0:
        return
    git('commit', '-m', 'data: refresh validated vulnerability intelligence')
    branch = git('branch', '--show-current').stdout.strip()
    if not branch:
        raise RuntimeError('Detached HEAD; refusing to push')
    for attempt in range(3):
        if git('push', 'origin', 'HEAD:' + branch, check=False).returncode == 0:
            return
        if attempt == 2:
            break
        git('fetch', 'origin', branch)
        rebased = git('rebase', 'origin/' + branch, check=False)
        if rebased.returncode:
            git('rebase', '--abort')
            raise RuntimeError('Rebase conflict; no remote changes overwritten')
    raise RuntimeError('Push failed after three attempts; inspect workflow artifact')


if __name__ == '__main__':
    main()

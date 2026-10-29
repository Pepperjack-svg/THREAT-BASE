#!/usr/bin/env python3
"""Offline integrity, repository budget, JSON/YAML-subset and secret checks."""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.common import ROOT, MAX_FILE, digest
from scripts.store import connect, validate_record

SECRET = re.compile(rb'(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16})')


def candidates(root):
    result = subprocess.run(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=root, capture_output=True)
    if result.returncode == 0:
        return [root / p for p in result.stdout.decode().split('\0') if p]
    return [p for p in root.rglob('*') if p.is_file() and not any(part in ('.cache', '.venv', '__pycache__', '.git') for part in p.relative_to(root).parts) and p.suffix not in ('.sqlite', '.pyc')]


def validate(root, max_total=250 * 1024 * 1024):
    errors = []
    total = 0
    for path in candidates(root):
        if not path.is_file():
            continue
        size = path.stat().st_size
        total += size
        if size > MAX_FILE:
            errors.append(f'Oversized Git candidate: {path.relative_to(root)}')
            continue
        payload = path.read_bytes()
        if SECRET.search(payload):
            errors.append(f'Possible secret in {path.relative_to(root)}')
        if path.suffix == '.json':
            try:
                json.loads(payload)
            except (ValueError, UnicodeError):
                errors.append(f'Invalid JSON: {path.relative_to(root)}')
        if path.suffix in ('.yml', '.yaml'):
            # Workflows deliberately use JSON, a strict YAML 1.2 subset.
            try:
                workflow = json.loads(payload)
                if not isinstance(workflow.get('on'), (dict, list)) or not workflow.get('jobs'):
                    raise ValueError('Invalid workflow structure')
                for job in workflow['jobs'].values():
                    for step in job.get('steps', []):
                        if 'uses' in step and not re.fullmatch(r'[^@]+@[a-f0-9]{40}', step['uses']):
                            raise ValueError('Action must use immutable SHA')
            except (ValueError, KeyError, AttributeError):
                errors.append(f'Invalid JSON-form YAML workflow or unpinned Action: {path.relative_to(root)}')
    if total > max_total:
        errors.append('Git candidate size exceeds repository budget')
    database = root / 'indexes/intelligence.sqlite'
    if database.exists():
        db = connect(database, readonly=True)
        try:
            if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                errors.append('SQLite integrity check failed')
            for row in db.execute('SELECT * FROM records'):
                raw = json.loads(row['raw'])
                validate_record(row['kind'], row['id'], raw)
                if digest(raw) != row['hash']:
                    errors.append(f'Content hash mismatch: {row["source"]}/{row["id"]}')
        finally:
            db.close()
    if errors:
        raise ValueError('\n'.join(errors))
    return {'candidate_bytes': total, 'file_limit_bytes': MAX_FILE, 'secret_check': 'heuristic patterns only'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(validate(args.root.resolve()), indent=2))

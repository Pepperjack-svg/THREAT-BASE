"""Atomic persistence and resource bounds shared by ingestion and indexing."""
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE = 45 * 1024 * 1024
CVE = re.compile(r'^CVE-\d{4}-\d{4,}$')


def now():
    return datetime.now(timezone.utc).isoformat()


def encode(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def atomic(path, payload):
    path = Path(path)
    if len(payload) > MAX_FILE:
        raise ValueError(f'File exceeds {MAX_FILE} byte safety limit: {path.name}')
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() == payload:
        return False
    fd, name = tempfile.mkstemp(dir=path.parent, suffix='.tmp')
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)
    return True


def write_json(path, value):
    return atomic(path, encode(value))


def read_json(path, default=None):
    return json.loads(Path(path).read_text(encoding='utf-8')) if Path(path).exists() else default


def safe_id(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:#-]{0,240}', value):
        raise ValueError('Unsafe or missing record identifier')
    return value.replace(':', '_').replace('#', '_')


def record_path(root, category, source, identifier):
    name = safe_id(identifier)
    shard = hashlib.sha256(name.encode()).hexdigest()[:2]
    return Path(root) / 'data' / category / source / shard / (name + '.json')

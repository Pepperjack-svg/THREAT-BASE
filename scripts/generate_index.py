#!/usr/bin/env python3
"""Rebuild SQLite term indexes from preserved source records."""
import sys
from pathlib import Path
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.common import ROOT
from scripts.store import connect, rebuild

if __name__ == '__main__':
    db = connect(ROOT / 'indexes/intelligence.sqlite')
    try:
        rebuild(db)
        print('Indexes rebuilt')
    finally:
        db.close()

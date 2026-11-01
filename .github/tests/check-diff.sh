#!/usr/bin/env bash
set -Eeuo pipefail
source "$(git rev-parse --show-toplevel)/.github/scripts/check-diff.sh"
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
cd "$fixture"
git init --quiet
git config user.name 'Whitespace fixture'
git config user.email 'fixture@example.invalid'
python3 - <<'PY'
from pathlib import Path
for number in range(2001):
    Path(f'{number:04}.txt').write_text('original\n')
Path('[literal] name.txt').write_text('original\n')
PY
git add -- .
git commit --quiet -m fixture
python3 - <<'PY'
from pathlib import Path
for path in Path('.').glob('*.txt'):
    path.write_text('changed\n')
PY
check_git_whitespace
printf 'bad whitespace \n' > '2000.txt'
if check_git_whitespace; then echo 'Missed whitespace in final batch' >&2; exit 1; fi
printf 'changed\n' > '2000.txt'
printf 'bad whitespace \n' > '[literal] name.txt'
if check_git_whitespace; then echo 'Missed literal filename' >&2; exit 1; fi
git add -- .
if check_git_whitespace --staged; then echo 'Missed staged whitespace' >&2; exit 1; fi
printf 'changed\n' > '[literal] name.txt'
git add -- .
check_git_whitespace --staged
echo 'Batched whitespace checks passed for clean, dirty, staged, and literal paths across 2,002 files.'

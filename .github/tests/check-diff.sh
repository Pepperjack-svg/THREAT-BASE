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
for number in range(20001):
    Path(f'{number:05}.txt').write_text('original\n')
for prefix in ('[literal] ', 'back\\slash ', ':(exclude) ', 'é', 'ê', 'line\nbreak '):
    for suffix in ('name', 'other'):
        Path(prefix + suffix + '.txt').write_text('original\n')
Path('nested/deep').mkdir(parents=True)
Path('nested/deep/record.txt').write_text('original\n')
PY
git add -- .
git commit --quiet -m fixture
python3 - <<'PY'
from pathlib import Path
for path in Path('.').rglob('*.txt'):
    path.write_text('changed\n')
PY
check_git_whitespace
GIT_NOGLOB_PATHSPECS=1 GIT_LITERAL_PATHSPECS=1 check_git_whitespace
printf 'bad whitespace \n' > '20000.txt'
if check_git_whitespace; then echo 'Missed whitespace in final batch' >&2; exit 1; fi
printf 'changed\n' > '20000.txt'
for file in '[literal] name.txt' 'back\slash name.txt' ':(exclude) name.txt' 'éname.txt' 'nested/deep/record.txt'; do
  printf 'bad whitespace \n' > "$file"
  if GIT_NOGLOB_PATHSPECS=1 GIT_LITERAL_PATHSPECS=1 check_git_whitespace; then
    echo "Missed literal filename: $file" >&2; exit 1
  fi
  printf 'changed\n' > "$file"
done
printf 'bad whitespace \n' > '[literal] name.txt'
git add -- .
if check_git_whitespace --staged; then echo 'Missed staged whitespace' >&2; exit 1; fi
printf 'changed\n' > '[literal] name.txt'
git add -- .
check_git_whitespace --staged
echo 'Prefix whitespace checks passed for clean, dirty, staged, nested, and unusual paths across 20,014 files.'

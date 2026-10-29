#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
git diff --check
for script in .github/scripts/*.sh; do bash -n "$script"; done
# Check tracked/candidate project files without opening ignored private files.
if git ls-files --cached --others --exclude-standard | grep -E '^(scripts|tests|vault|docs/internal)/|\.py$|\.sqlite(3)?$|(^|/)\.env($|\.)'; then
  echo 'Unexpected application, private or generated file in Git candidates' >&2
  exit 1
fi
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
git ls-files --cached --others --exclude-standard -z > "$work/files"
git ls-files --cached --others --exclude-standard -z -- '*.json' > "$work/json"
for file in .github/workflows/*.yml; do
  jq -e '.on and .jobs and ([.jobs[].steps[]? | select(has("uses")) | .uses | test("@[a-f0-9]{40}$")] | all)' "$file" >/dev/null
done
xargs -0 -r -n 200 jq -e . < "$work/json" >/dev/null
xargs -0 -r -n 200 stat -c '%s %n' < "$work/files" | awk '$1 >= 95000000 {print "Oversized Git file: " $0; bad=1} END {exit bad}'
xargs -0 -r bash -c 'grep -IlE -- '\''-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}'\'' "$@" || [[ $? == 1 ]]' _ < "$work/files" > "$work/secrets"
if [[ -s $work/secrets ]]; then
  cat "$work/secrets"
  echo 'Possible secret in Git candidates' >&2
  exit 1
fi
echo 'Project layout, JSON, workflow structure, shell syntax and file sizes passed.'

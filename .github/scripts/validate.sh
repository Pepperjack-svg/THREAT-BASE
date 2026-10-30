#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
scope=(--cached)
[[ ${1:-} == --staged ]] || scope+=(--others --exclude-standard)
git diff --check
git diff --cached --check
for script in .github/scripts/*.sh; do bash -n "$script"; done
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
git ls-files "${scope[@]}" -z > "$work/files"
# Enumerate candidates once; large source trees can contain a million files.
if tr '\0' '\n' < "$work/files" | grep -E '^(scripts|tests|vault|docs/internal)/|\.py$|\.sqlite(3)?$|(^|/)\.env($|\.)'; then
  echo 'Unexpected application, private or generated file in Git candidates' >&2
  exit 1
fi
grep -zE '\.json$' < "$work/files" > "$work/json" || [[ $? == 1 ]]
for file in .github/workflows/*.yml; do
  jq -e '.on and .jobs and ([.jobs[].steps[]? | select(has("uses")) | .uses | test("@[a-f0-9]{40}$")] | all)' "$file" >/dev/null
done
xargs -0 -r -n 200 jq -e 'true' < "$work/json" >/dev/null
xargs -0 -r -n 200 stat -c '%s %n' < "$work/files" | awk '$1 >= 95000000 {print "Oversized Git file: " $0; bad=1} END {exit bad}'
xargs -0 -r bash -c 'grep -IlE -- '\''-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}'\'' "$@" || [[ $? == 1 ]]' _ < "$work/files" > "$work/secrets"
if [[ -s $work/secrets ]]; then
  while IFS= read -r file; do
    hash=$(sha256sum --binary "$file" | cut -d ' ' -f1)
    fingerprint="$hash  $file"
    if [[ -f .github/secret-scan-allowlist.txt ]] && tr -d '\r' < .github/secret-scan-allowlist.txt | grep -Fxq -- "$fingerprint"; then
      continue
    fi
    echo "Possible secret in Git candidate: $file" >&2
    exit 1
  done < "$work/secrets"
fi
echo 'Project layout, JSON, workflow structure, shell syntax and file sizes passed.'

#!/usr/bin/env bash
# Calendar releases contain the committed source directories and attribution.
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
bash .github/scripts/validate.sh
version=$(TZ=Asia/Kolkata date +%Y.%m)
tag="v$version"
sha=$(git rev-parse HEAD)
dist=$(mktemp -d)
trap 'rm -rf -- "$dist"' EXIT
if gh api "repos/$GITHUB_REPOSITORY/releases/tags/$tag" > "$dist/existing.json" 2> "$dist/error"; then
  if [[ $(jq -r .draft "$dist/existing.json") == false ]]; then
    echo "$tag already published; preserving it."
    exit 0
  fi
  echo 'Existing draft requires review; no assets or tags will be replaced.' >&2
  exit 1
else
  grep -q 'HTTP 404' "$dist/error" || { cat "$dist/error" >&2; exit 1; }
fi
[[ -z $(git ls-remote --tags origin "refs/tags/$tag") ]] || { echo 'Version tag already exists; review it manually' >&2; exit 1; }
# Release only a fresh, completed daily synchronization of this code/data lineage.
branch=${GITHUB_REF_NAME:?}
gh api "repos/$GITHUB_REPOSITORY/actions/workflows/sync.yml/runs?branch=$branch&per_page=1" > "$dist/runs.json"
jq -e --arg branch "$branch" '.workflow_runs[0] | .status == "completed" and .conclusion == "success" and .head_branch == $branch and (.event == "schedule" or .event == "workflow_dispatch")' "$dist/runs.json" >/dev/null
updated=$(jq -r '.workflow_runs[0].updated_at' "$dist/runs.json")
age=$(( $(date -u +%s) - $(date -u -d "$updated" +%s) ))
(( age >= 0 && age <= 129600 )) || { echo 'Daily synchronization is stale' >&2; exit 1; }
base=$(jq -r '.workflow_runs[0].head_sha' "$dist/runs.json")
[[ $base =~ ^[a-f0-9]{40}$ ]]
git merge-base --is-ancestor "$base" "$sha"
if git diff --name-only "$base" "$sha" | grep -Ev '^(cvelistV5/|nvd-json-data-feeds/|github-advisory-database/|pypa-advisory-database/|mitre-attack/|cisa-advisories/|cisa-kev/|epss/|cwe/|capec/|redhat-advisories/|\.upstream-state$)'; then
  echo 'Code changed since the successful sync; run daily sync again' >&2
  exit 1
fi
for dir in cvelistV5 nvd-json-data-feeds github-advisory-database pypa-advisory-database mitre-attack cisa-kev epss cwe capec cisa-advisories redhat-advisories; do
  git ls-tree -d --name-only HEAD -- "$dir" | grep -qx "$dir" || { echo "Missing committed dataset: $dir" >&2; exit 1; }
  git archive HEAD -- "$dir" DATA_SOURCES.md LICENSE | gzip -n | split -b 900M - "$dist/$dir-$version.tar.gz.part-"
done
printf 'commit=%s\nversion=%s\n' "$sha" "$version" > "$dist/snapshot.txt"
(cd "$dist"; sha256sum -- *.part-* snapshot.txt > SHA256SUMS)
cat > "$dist/notes.md" <<EOF
Source-organized snapshot of THREAT-BASE at commit $sha.

Verify with sha256sum -c SHA256SUMS. For each dataset, concatenate its .part-* files
in filename order, then extract the resulting tar.gz. Datasets retain their original
publishers and terms; DATA_SOURCES.md and upstream notices are included.

This is the committed database snapshot, not a claim of complete upstream history.
EOF
gh release create "$tag" --draft --target "$sha" --title "THREAT-BASE $version" --notes-file "$dist/notes.md"
gh release upload "$tag" "$dist"/*.part-* "$dist/snapshot.txt" "$dist/SHA256SUMS"
# Verify uploaded sizes before making the draft visible.
gh api "repos/$GITHUB_REPOSITORY/releases/tags/$tag" > "$dist/release.json"
for asset in "$dist"/*.part-* "$dist/snapshot.txt" "$dist/SHA256SUMS"; do
  name=$(basename "$asset")
  expected=$(wc -c < "$asset")
  actual=$(jq -r --arg name "$name" '.assets[] | select(.name == $name) | .size' "$dist/release.json")
  [[ $actual == "$expected" ]] || { echo "Upload incomplete: $name; draft retained" >&2; exit 1; }
  expected_hash=$(sha256sum "$asset" | cut -d ' ' -f1)
  asset_id=$(jq -r --arg name "$name" '.assets[] | select(.name == $name) | .id' "$dist/release.json")
  gh api -H 'Accept: application/octet-stream' "repos/$GITHUB_REPOSITORY/releases/assets/$asset_id" > "$dist/verify"
  [[ $(sha256sum "$dist/verify" | cut -d ' ' -f1) == "$expected_hash" ]] || { echo "Upload digest mismatch: $name" >&2; exit 1; }
done
gh release edit "$tag" --draft=false

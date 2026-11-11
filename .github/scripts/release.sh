#!/usr/bin/env bash
# Calendar releases contain the committed source directories and attribution.
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
# Catch up after the midnight sync completes, including a repaired run on day one.
if [[ ${GITHUB_EVENT_NAME:-} == workflow_run && $(TZ=Asia/Kolkata date +%d) != 01 ]]; then
  echo 'Automatic monthly catch-up only runs on the first day in Asia/Kolkata.'
  exit 0
fi
version=$(TZ=Asia/Kolkata date +%Y.%m)
tag="v$version"
sha=$(git rev-parse HEAD)
dist=$(mktemp -d)
trap 'rm -rf -- "$dist"' EXIT
# List releases rather than resolving a REST tag: a pending draft has no Git tag yet.
gh api --paginate "repos/$GITHUB_REPOSITORY/releases?per_page=100" > "$dist/release-pages.json"
jq -s --arg tag "$tag" '[.[][] | select(.tag_name == $tag)]' "$dist/release-pages.json" > "$dist/existing.json"
existing_count=$(jq length "$dist/existing.json")
if (( existing_count > 0 )); then
  (( existing_count == 1 )) || { echo 'Multiple releases match this month; review required' >&2; exit 1; }
  if [[ $(jq -r '.[0].draft' "$dist/existing.json") == false ]]; then
    echo "$tag already published; preserving it."
    exit 0
  fi
  echo 'Existing draft requires review; no assets or tags will be replaced.' >&2
  exit 1
fi
remote_tags=$(git ls-remote --tags origin "refs/tags/$tag")
[[ -z $remote_tags ]] || { echo 'Version tag already exists; review it manually' >&2; exit 1; }
# Release only a fresh, completed daily synchronization of this code/data lineage.
branch=${GITHUB_REF_NAME:?}
gh api "repos/$GITHUB_REPOSITORY/actions/workflows/sync.yml/runs?branch=$branch&per_page=1" > "$dist/runs.json"
jq -e --arg branch "$branch" '.workflow_runs[0] | .status == "completed" and .conclusion == "success" and .head_branch == $branch and (.event == "schedule" or .event == "workflow_dispatch" or .event == "push")' "$dist/runs.json" >/dev/null || {
  echo 'Release blocked: latest daily sync has not completed successfully. Run sync.yml first.' >&2
  exit 1
}
updated=$(jq -r '.workflow_runs[0].updated_at' "$dist/runs.json")
age=$(( $(date -u +%s) - $(date -u -d "$updated" +%s) ))
(( age >= 0 && age <= 129600 )) || { echo 'Daily synchronization is stale' >&2; exit 1; }
base=$(jq -r '.workflow_runs[0].head_sha' "$dist/runs.json")
[[ $base =~ ^[a-f0-9]{40}$ ]]
git merge-base --is-ancestor "$base" "$sha"
git diff --no-renames --name-only "$base" "$sha" > "$dist/changed-paths"
if grep -Ev '^(cvelistV5/|nvd-json-data-feeds/|github-advisory-database/|pypa-advisory-database/|mitre-attack/|cisa-advisories/|cisa-kev/|epss/|cwe/|capec/|redhat-advisories/|\.upstream-state$|\.upstream-feeds\.json$)' "$dist/changed-paths"; then
  echo 'Code changed since the successful sync; run daily sync again' >&2
  exit 1
fi
bash .github/scripts/validate.sh
for dir in cvelistV5 nvd-json-data-feeds github-advisory-database pypa-advisory-database mitre-attack cisa-kev epss cwe capec cisa-advisories redhat-advisories; do
  git ls-tree -d --name-only HEAD -- "$dir" | grep -qx "$dir" || { echo "Missing committed dataset: $dir" >&2; exit 1; }
  git archive HEAD -- "$dir" DATA_SOURCES.md LICENSE .upstream-state .upstream-feeds.json | gzip -n | split -b 900M - "$dist/$dir-$version.tar.gz.part-"
done
printf 'commit=%s\nversion=%s\nsync_run=%s\n' "$sha" "$version" "$(jq -r '.workflow_runs[0].html_url' "$dist/runs.json")" > "$dist/snapshot.txt"
(cd "$dist"; sha256sum -- *.part-* snapshot.txt > SHA256SUMS)
cat > "$dist/notes.md" <<EOF
Source-organized snapshot of THREAT-BASE at commit $sha.

Verify with sha256sum -c SHA256SUMS. For each dataset, concatenate its .part-* files
in filename order, then extract the resulting tar.gz. Datasets retain their original
publishers and terms; DATA_SOURCES.md and upstream notices are included.

This is the committed database snapshot, not a claim of complete upstream history.
EOF
if [[ -f .upstream-feeds.json ]]; then
  jq -r '.feeds[] | select(.status == "retained") | "Supplemental RSS retained after endpoint failure: \(.path); last successful download: \(.last_success_at // "unknown"). See .upstream-feeds.json in the archives for hashes and endpoints."' .upstream-feeds.json >> "$dist/notes.md"
fi
gh release create "$tag" --draft --target "$sha" --title "THREAT-BASE $version" --notes-file "$dist/notes.md"
release_api=$(gh release view "$tag" --json apiUrl --jq .apiUrl)
release_id=${release_api##*/}
[[ $release_id =~ ^[0-9]+$ ]] || { echo 'Cannot resolve created draft ID; draft retained' >&2; exit 1; }
gh release upload "$tag" "$dist"/*.part-* "$dist/snapshot.txt" "$dist/SHA256SUMS"
# Verify uploaded sizes before making the draft visible.
gh api "repos/$GITHUB_REPOSITORY/releases/$release_id" > "$dist/release.json"
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

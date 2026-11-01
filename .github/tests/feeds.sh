#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
source .github/scripts/feeds.sh
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
target="$work/retained.xml"
printf 'original' > "$target"
curl() {
  local url output
  while (( $# )); do
    case $1 in
      -o) output=$2; shift 2 ;;
      https:*) url=$1; shift ;;
      *) shift ;;
    esac
  done
  case $url in
    */blocked) return 22 ;;
    */html) printf '<?xml version="1.0"?><html>Denied</html>' > "$output" ;;
    */broken) printf '<rss><channel>' > "$output" ;;
    */empty) : > "$output" ;;
    */valid) printf '<rss><channel><title>Current</title></channel></rss>' > "$output" ;;
    */large) python3 -c 'print("<rss><channel>" + "<item>advisory</item>" * 10000 + "</channel></rss>")' > "$output" ;;
    *) return 1 ;;
  esac
}
for failure in blocked html broken empty; do
  if fetch "https://fixture/$failure" "$target" xml; then
    echo "Unexpected success: $failure" >&2; exit 1
  fi
  [[ $(cat "$target") == original ]]
done
fetch https://fixture/blocked "$target" xml https://fixture/valid
grep -q Current "$target"
grep -q 'https://fixture/valid' "$work/feed-state"
fetch https://fixture/large "$target" xml
[[ $(wc -c < "$target") -gt 100000 ]]
printf 'not gzip' > "$work/bad.gz"
if validate_feed gzip "$work/bad.gz"; then exit 1; fi
rm "$work/feed-state"
fetch_supplemental https://fixture/blocked "$target" xml
write_feed_state "$work/missing.json" "$work/first.json"
python3 - "$work/first.json" <<'PY'
import json, sys
entry = json.load(open(sys.argv[1]))['feeds'][0]
assert entry['status'] == 'retained' and entry['last_success_at'] is None
PY
rm "$work/feed-state"
fetch_supplemental https://fixture/valid "$target" xml
write_feed_state "$work/first.json" "$work/fresh.json"
rm "$work/feed-state"
fetch_supplemental https://fixture/blocked "$target" xml
write_feed_state "$work/fresh.json" "$work/retained.json"
python3 - "$work/fresh.json" "$work/retained.json" <<'PY'
import json, sys
fresh, retained = [json.load(open(path))['feeds'][0] for path in sys.argv[1:]]
assert fresh['status'] == 'refreshed' and fresh['last_success_at']
assert retained['status'] == 'retained'
assert retained['last_success_at'] == fresh['last_success_at']
assert retained['sha256'] == fresh['sha256']
PY
if fetch_supplemental https://fixture/blocked "$work/missing.xml" xml; then exit 1; fi
printf '<html>Denied</html>' > "$target"
if fetch_supplemental https://fixture/blocked "$target" xml; then exit 1; fi
echo 'Feed regression checks passed: HTTP failures, HTML, malformed/empty XML, fallback, large XML, corrupt gzip.'

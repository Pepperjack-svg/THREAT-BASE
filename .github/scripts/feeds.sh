#!/usr/bin/env bash
# Download and validate before replacing a retained feed. Sourced by sync.sh.
validate_feed() {
  local kind=$1 file=$2
  [[ -s $file ]] || return 1
  case $kind in
    json) jq -e . "$file" >/dev/null ;;
    gzip) gzip -t "$file" ;;
    zip) unzip -tq "$file" >/dev/null ;;
    xml) python3 - "$file" <<'PY'
import sys
import xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
if root.tag.rsplit('}', 1)[-1] not in {'rss', 'feed', 'Attack_Pattern_Catalog', 'Weakness_Catalog'}:
    raise SystemExit('Unexpected XML document root: ' + root.tag)
PY
      ;;
    text) return 0 ;;
    *) echo "Unknown feed format: $kind" >&2; return 1 ;;
  esac
}

fetch() {
  local url=$1 target=$2 kind=$3 file="$work/feed" candidate
  shift 3
  for candidate in "$url" "$@"; do
    echo "Fetching $target from $candidate"
    if curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
      --user-agent 'THREAT-BASE/1.0 (+https://github.com/Pepperjack-svg/THREAT-BASE)' \
      --retry 2 --connect-timeout 30 --max-time 180 "$candidate" -o "$file"; then
      if validate_feed "$kind" "$file"; then
        mkdir -p "$(dirname "$target")" || return 1
        cp "$file" "$target" || return 1
        printf '%s\t%s\t%s\trefreshed\n' "$target" "$candidate" "$(sha256sum "$file" | cut -d ' ' -f1)" >> "$work/feed-state" || return 1
        return 0
      fi
      echo "Invalid $kind response for $target" >&2
    fi
    echo "Feed endpoint failed: $candidate" >&2
  done
  echo "No valid endpoint for $target; retained file was not replaced" >&2
  return 1
}

# RSS is supplemental to the required publisher-maintained CISA CSAF mirror.
# A runner-side outage may retain valid RSS, with an explicit warning and receipt.
fetch_supplemental() {
  local url=$1 target=$2 kind=$3
  if fetch "$@"; then return 0; fi
  validate_feed "$kind" "$target" || return 1
  printf '%s\t%s\t%s\tretained\n' "$target" "$url" "$(sha256sum "$target" | cut -d ' ' -f1)" >> "$work/feed-state" || return 1
  echo "::warning file=$target::RSS download unavailable; valid previous feed retained. See .upstream-feeds.json for last successful download."
  if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then
    printf '%s\n' "- Supplemental RSS unavailable: \`$target\`. Previous validated feed retained; see provenance manifest." >> "$GITHUB_STEP_SUMMARY"
  fi
}

write_feed_state() {
  python3 - "$work/feed-state" "$1" "$2" <<'PY'
import datetime, json, pathlib, sys
now = datetime.datetime.now(datetime.timezone.utc).isoformat()
previous_path = pathlib.Path(sys.argv[2])
previous = json.loads(previous_path.read_text()) if previous_path.exists() else {}
old = {entry['path']: entry for entry in previous.get('feeds', [])}
feeds = []
with open(sys.argv[1]) as source:
    for line in source:
        entry = dict(zip(('path', 'url', 'sha256', 'status'), line.rstrip('\n').split('\t')))
        prior = old.get(entry['path'], {})
        entry['last_success_at'] = now if entry['status'] == 'refreshed' else (
            prior.get('last_success_at') if prior.get('sha256') == entry['sha256'] else None)
        feeds.append(entry)
with open(sys.argv[3], 'w') as output:
    json.dump({'synced_at': now, 'feeds': feeds}, output, indent=2)
    output.write('\n')
PY
}

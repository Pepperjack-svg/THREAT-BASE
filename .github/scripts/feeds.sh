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
        printf '%s\t%s\t%s\n' "$target" "$candidate" "$(sha256sum "$file" | cut -d ' ' -f1)" >> "$work/feed-state"
        return 0
      fi
      echo "Invalid $kind response for $target" >&2
    fi
    echo "Feed endpoint failed: $candidate" >&2
  done
  echo "No valid endpoint for $target; retained file was not replaced" >&2
  return 1
}

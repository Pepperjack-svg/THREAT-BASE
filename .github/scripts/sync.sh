#!/usr/bin/env bash
# Mirror source records only; upstream code is never run.
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
state="$work/upstream-state"
mirror() {
  local repo=$1 branch=$2 target=$3 mode=$4 head previous clone from count old
  head=$(git ls-remote "https://github.com/$repo.git" "refs/heads/$branch" | cut -f1)
  [[ $head =~ ^[a-f0-9]{40}$ ]] || { echo "Cannot resolve $repo" >&2; return 1; }
  previous=$(awk -v key="$target" '$1 == key {print $2}' .upstream-state 2>/dev/null || true)
  if [[ $previous == "$head" && -d $target ]]; then
    printf '%s %s\n' "$target" "$head" >> "$state"
    return
  fi
  clone="$work/${target//\//-}"
  git -c core.hooksPath=/dev/null clone --quiet --depth=1 --no-tags --single-branch --branch "$branch" "https://github.com/$repo.git" "$clone"
  [[ $(git -C "$clone" rev-parse HEAD) == "$head" ]] || { echo 'Upstream changed during clone; retry sync' >&2; return 1; }
  from=$clone
  [[ $mode != cve ]] || from="$clone/cves"
  [[ $mode != advisories ]] || from="$clone/advisories"
  [[ $mode != csaf ]] || from="$clone/csaf_files"
  [[ $mode != pypa ]] || from="$clone/vulns"
  [[ -d $from ]] || { echo "Missing data in $repo" >&2; return 1; }
  [[ -z $(find "$from" -path '*/.git' -prune -o -type l -print -quit) ]] || { echo 'Unexpected upstream symlink' >&2; return 1; }
  count=$(find "$from" -path '*/.git' -prune -o -type f \( -name '*.json' -o -name '*.yaml' \) -print | wc -l)
  old=$(find "$target" -type f \( -name '*.json' -o -name '*.yaml' \) 2>/dev/null | wc -l || true)
  (( count > 0 && (old == 0 || count * 100 >= old * 95) )) || { echo "Unexpected record count in $repo" >&2; return 1; }
  mkdir -p "$target"
  # Never delete retained data. Keep original records and notices, omit tooling.
  rsync -a --prune-empty-dirs --exclude='.git/' --exclude='.github/' \
    --exclude='_scripts/' --exclude='tools/' --include='*/' --include='*.json' --include='*.yaml' \
    --include='LICENSE*' --include='COPYING*' --include='NOTICE*' --exclude='*' "$from/" "$target/"
  for notice in "$clone"/LICENSE* "$clone"/COPYING* "$clone"/NOTICE*; do
    [[ ! -f $notice ]] || cp "$notice" "$target/"
  done
  [[ ! -f $clone/README.md ]] || cp "$clone/README.md" "$target/README.upstream.md"
  printf '%s %s\n' "$target" "$head" >> "$state"
}

mirror CVEProject/cvelistV5 main cvelistV5 cve
mirror fkie-cad/nvd-json-data-feeds main nvd-json-data-feeds all
mirror github/advisory-database main github-advisory-database advisories
mirror pypa/advisory-database main pypa-advisory-database pypa
mirror mitre-attack/attack-stix-data master mitre-attack all
mirror cisagov/CSAF develop cisa-advisories csaf

fetch() {
  local url=$1 target=$2 kind=$3 file="$work/feed"
  curl --fail --location --proto '=https' --proto-redir '=https' --retry 2 --connect-timeout 30 --max-time 600 "$url" -o "$file"
  [[ -s $file ]]
  case $kind in
    json) jq -e . "$file" >/dev/null ;;
    gzip) gzip -t "$file" ;;
    zip) unzip -tq "$file" >/dev/null ;;
    xml) head -c 200 "$file" | grep -Eiq '<\?xml|<rss|<feed|<Attack_Pattern_Catalog|<Weakness_Catalog' ;;
  esac
  mkdir -p "$(dirname "$target")"
  cp "$file" "$target"
}
fetch https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json cisa-kev/known_exploited_vulnerabilities.json json
fetch https://epss.empiricalsecurity.com/epss_scores-current.csv.gz epss/epss_scores-current.csv.gz gzip
fetch https://cwe.mitre.org/data/xml/cwec_latest.xml.zip cwe/cwec_latest.xml.zip zip
fetch https://capec.mitre.org/data/xml/capec_latest.xml capec/capec_latest.xml xml
fetch https://www.cisa.gov/cybersecurity-advisories/all.xml cisa-advisories/all.xml xml
fetch https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml cisa-advisories/ics.xml xml
fetch https://security.access.redhat.com/data/metrics/rhsa.rss redhat-advisories/rhsa.rss xml
fetch https://cwe.mitre.org/about/termsofuse.html cwe/TERMS.html text
fetch https://capec.mitre.org/about/termsofuse.html capec/TERMS.html text
bash .github/scripts/validate.sh
sort "$state" > .upstream-state

#!/usr/bin/env bash
set -Eeuo pipefail
source "$(git rev-parse --show-toplevel)/.github/scripts/notices.sh"
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
mkdir "$fixture/clone"
printf 'synthetic private configuration\n' > "$fixture/private"
for name in LICENSE COPYING.txt NOTICE README.md; do
  ln -s "$fixture/private" "$fixture/clone/$name"
  if copy_upstream_notices "$fixture/clone" "$fixture/target"; then
    echo "Followed upstream symlink: $name" >&2; exit 1
  fi
  [[ ! -e $fixture/target ]]
  rm "$fixture/clone/$name"
done
ln -s "$fixture/missing" "$fixture/clone/README.md"
if copy_upstream_notices "$fixture/clone" "$fixture/target"; then exit 1; fi
rm "$fixture/clone/README.md"
printf 'publisher license\n' > "$fixture/clone/LICENSE"
printf 'publisher readme\n' > "$fixture/clone/README.md"
copy_upstream_notices "$fixture/clone" "$fixture/target"
cmp "$fixture/clone/LICENSE" "$fixture/target/LICENSE"
cmp "$fixture/clone/README.md" "$fixture/target/README.upstream.md"
echo 'Notice checks passed: real notices preserved; root and dangling symlinks rejected.'

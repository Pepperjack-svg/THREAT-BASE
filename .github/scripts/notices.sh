#!/usr/bin/env bash
copy_upstream_notices() {
  local clone=$1 target=$2 notice
  # Root notices are outside some selected data subtrees. Never follow their links.
  for notice in "$clone"/LICENSE* "$clone"/COPYING* "$clone"/NOTICE* "$clone/README.md"; do
    if [[ -L $notice ]]; then
      echo "Unexpected upstream notice symlink: $notice" >&2
      return 1
    fi
  done
  mkdir -p "$target" || return 1
  for notice in "$clone"/LICENSE* "$clone"/COPYING* "$clone"/NOTICE*; do
    [[ ! -f $notice ]] || cp "$notice" "$target/" || return 1
  done
  [[ ! -f $clone/README.md ]] || cp "$clone/README.md" "$target/README.upstream.md" || return 1
}

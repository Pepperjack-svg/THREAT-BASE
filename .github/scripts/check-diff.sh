#!/usr/bin/env bash
# Bound diff memory for million-file source mirrors, including stat-only changes.
check_git_whitespace() {
  local paths result=0
  local staged=()
  paths=$(mktemp) || return 1
  if [[ ${1:-} == --staged ]]; then
    staged=(--cached)
    git diff-index --cached --no-renames --name-only -z HEAD -- > "$paths" || result=$?
  else
    git diff-files --no-renames --name-only -z -- > "$paths" || result=$?
  fi
  if (( result == 0 )); then
    xargs -0 -r -n 1000 git --literal-pathspecs diff --no-renames --no-ext-diff --no-textconv \
      "${staged[@]}" --check -- < "$paths" || result=$?
  fi
  rm -f -- "$paths"
  return "$result"
}

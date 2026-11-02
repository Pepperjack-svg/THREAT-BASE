#!/usr/bin/env bash
# Bound diff memory for million-file source mirrors, including stat-only changes.
check_git_whitespace() {
  local paths groups result=0
  local staged=()
  paths=$(mktemp) || return 1
  groups=$(mktemp) || { rm -f -- "$paths"; return 1; }
  if [[ ${1:-} == --staged ]]; then
    staged=(--cached)
    git diff-index --cached --no-renames --name-only -z HEAD -- > "$paths" || result=$?
  else
    git diff-files --no-renames --name-only -z -- > "$paths" || result=$?
  fi
  if (( result == 0 )); then
    # Thousands of literal pathspecs repeatedly scan the full index. Partition
    # sorted changed names into prefix groups, at most 16,384 candidates each.
    python3 - "$paths" "$groups" <<'PY'
import os, sys
with open(sys.argv[1], 'rb') as source:
    paths = sorted(set(source.read().split(b'\0')) - {b''})
pending = [(0, len(paths))] if paths else []
count = 0
with open(sys.argv[2], 'wb') as output:
    while pending:
        start, end = pending.pop()
        prefix = os.path.commonprefix((paths[start], paths[end - 1]))
        if end - start <= 16384:
            if end - start == 1:
                patterns = [b':(top,literal)' + paths[start]] * 2
            else:
                escaped = b''.join(b'\\' + bytes([c]) if c in b'\\*?[' else bytes([c]) for c in prefix)
                # Explicit glob magic overrides ambient no-glob settings. Match
                # both files and descendants of directories sharing the prefix.
                patterns = [b':(top,glob)' + escaped + b'*', b':(top,glob)' + escaped + b'*/**']
            output.write(b'\0'.join(patterns) + b'\0')
            count += 1
        else:
            depth = len(prefix)
            boundaries = [start]
            for index in range(start + 1, end):
                if paths[index][depth:depth + 1] != paths[index - 1][depth:depth + 1]:
                    boundaries.append(index)
            boundaries.append(end)
            pending.extend(reversed(list(zip(boundaries, boundaries[1:]))))
print(f'Git whitespace: {len(paths)} changed paths in {count} bounded prefix groups.', file=sys.stderr)
PY
    result=$?
  fi
  if (( result == 0 )); then
    xargs -0 -r -n 2 env -u GIT_LITERAL_PATHSPECS -u GIT_GLOB_PATHSPECS \
      -u GIT_NOGLOB_PATHSPECS -u GIT_ICASE_PATHSPECS git diff \
      --no-renames --no-ext-diff --no-textconv "${staged[@]}" --check -- < "$groups" || result=$?
  fi
  rm -f -- "$paths" "$groups"
  return "$result"
}

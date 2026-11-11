#!/usr/bin/env bash
# Exercise the real release script against a local repository and a fake GitHub CLI.
set -Eeuo pipefail
release_script="$(git rev-parse --show-toplevel)/.github/scripts/release.sh"
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
export REAL_GIT
REAL_GIT=$(command -v git)
mkdir -p "$fixture/bin" "$fixture/repo/.github/scripts"
cp "$release_script" "$fixture/repo/.github/scripts/release.sh"
printf '#!/usr/bin/env bash\nexit 0\n' > "$fixture/repo/.github/scripts/validate.sh"
cat > "$fixture/bin/git" <<'SH'
#!/usr/bin/env bash
if [[ $SCENARIO == tag-error && $1 == ls-remote ]]; then exit 128; fi
if [[ $SCENARIO == diff-error && $1 == diff ]]; then exit 128; fi
exec "$REAL_GIT" "$@"
SH
cat > "$fixture/bin/gh" <<'PY'
#!/usr/bin/env python3
import datetime, json, os, pathlib, shutil, sys
args = sys.argv[1:]
state = pathlib.Path(os.environ['TEST_STATE'])
scenario = os.environ['SCENARIO']
endpoint = args[-1]
def operation(name):
    with (state / 'operations').open('a') as output:
        output.write(name + '\n')
if args[0] == 'api' and '--paginate' in args:
    if scenario == 'list-error': sys.exit(1)
    entries = []
    if scenario in ('published', 'draft', 'duplicate'):
        entries = [{'tag_name': os.environ['TEST_TAG'], 'draft': scenario != 'published'}]
    if scenario == 'duplicate': entries *= 2
    print(json.dumps(entries))
    print('[]')  # A second page verifies JSON page aggregation.
elif args[0] == 'api' and '/actions/workflows/sync.yml/runs?' in endpoint:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(json.dumps({'workflow_runs': [{'status': 'completed', 'conclusion': 'success',
        'head_branch': 'main', 'event': 'push', 'head_sha': os.environ['TEST_SHA'],
        'updated_at': now, 'html_url': 'https://example.invalid/sync/1'}]}))
elif args[:2] == ['release', 'create']:
    operation('create')
elif args[:2] == ['release', 'view']:
    assert args[-4:] == ['--json', 'apiUrl', '--jq', '.apiUrl']
    print('https://api.github.com/repos/fixture/repo/releases/123')
elif args[:2] == ['release', 'upload']:
    assets = []
    for number, source in enumerate(args[3:], 1):
        source = pathlib.Path(source)
        destination = state / str(number)
        shutil.copyfile(source, destination)
        assets.append({'id': number, 'name': source.name, 'size': destination.stat().st_size})
    if scenario == 'size-mismatch': assets[0]['size'] += 1
    (state / 'assets.json').write_text(json.dumps({'assets': assets}))
elif args[0] == 'api' and endpoint.endswith('/releases/123'):
    print((state / 'assets.json').read_text())
elif args[0] == 'api' and '/releases/assets/' in endpoint:
    content = (state / endpoint.rsplit('/', 1)[-1]).read_bytes()
    sys.stdout.buffer.write(content + (b'corrupt' if scenario == 'digest-mismatch' else b''))
elif args[:2] == ['release', 'edit']:
    assert args[-1] == '--draft=false'
    operation('publish')
else:
    raise SystemExit('Unexpected GitHub CLI request: ' + repr(args))
PY
chmod +x "$fixture/bin/gh" "$fixture/bin/git"
cd "$fixture/repo"
git init --quiet -b main
git config user.name 'Release fixture'
git config user.email 'fixture@example.invalid'
git init --quiet --bare "$fixture/remote.git"
git remote add origin "$fixture/remote.git"
for dir in cvelistV5 nvd-json-data-feeds github-advisory-database pypa-advisory-database mitre-attack cisa-kev epss cwe capec cisa-advisories redhat-advisories; do
  mkdir "$dir"
  printf '{}\n' > "$dir/record.json"
done
printf 'Attribution\n' > DATA_SOURCES.md
printf 'License\n' > LICENSE
printf 'cvelistV5 fixture\n' > .upstream-state
printf '{"feeds": []}\n' > .upstream-feeds.json
git add -- .
git commit --quiet -m fixture
export TEST_SHA TEST_TAG GITHUB_REPOSITORY=fixture/repo GITHUB_REF_NAME=main GITHUB_EVENT_NAME=workflow_dispatch
TEST_SHA=$(git rev-parse HEAD)
TEST_TAG="v$(TZ=Asia/Kolkata date +%Y.%m)"
export PATH="$fixture/bin:$PATH"
for scenario in published draft duplicate list-error tag-error diff-error size-mismatch digest-mismatch success; do
  export SCENARIO=$scenario TEST_STATE="$fixture/$scenario"
  mkdir "$TEST_STATE"
  if bash .github/scripts/release.sh > "$TEST_STATE/log" 2>&1; then
    [[ $scenario == published || $scenario == success ]] || { cat "$TEST_STATE/log"; exit 1; }
  else
    [[ $scenario != published && $scenario != success ]] || { cat "$TEST_STATE/log"; exit 1; }
  fi
  if [[ $scenario == success ]]; then
    grep -qx publish "$TEST_STATE/operations"
  elif [[ -f $TEST_STATE/operations ]] && grep -qx publish "$TEST_STATE/operations"; then
    echo "Unexpected publication: $scenario" >&2; exit 1
  fi
done
echo 'Release checks passed: draft/published discovery, pagination, Git/API errors, verified uploads, size/digest mismatches.'

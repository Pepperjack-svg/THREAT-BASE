# Cybersecurity Intelligence Database

Defensive vulnerability metadata ingestion, normalization, correlation, prioritization,
and local search for researchers and Tempest's Kakashi and Itachi agents.
Python 3.12+; standard library only. No paid APIs, exploit execution, external scans,
payload downloads, malware binaries, or automatic upstream code execution.

**Implementation is local and awaiting independent review, not production certified.**
Automatic publication is disabled unless repository variable `SYNC_ENABLED=true`.
Nothing was committed, pushed, published, or provisioned during implementation.
The local repository tracks `origin/main` at
`https://github.com/Pepperjack-svg/VULN-INTEL.git`; its existing LICENSE was preserved.
Full historical coverage is not claimed.

## Source status and coverage

The implementation audit and live checks took place on 29 October 2026.
`metadata/sync-status.json` records actual outcomes; an adapter existing does not
mean its upstream has been synchronized. Counts below describe the initial validation.

| Source | Implementation / test status | Coverage and limitations |
| --- | --- | --- |
| CVE Program / cvelistV5 | Implemented; live record validated; fixtures tested | Delta log; initial recent window only; 1 record in explicit smoke window. Import baseline for history. Gaps fail closed. |
| NVD API 2.0 | Implemented; live validated | 2,168 observations (2,158 unique CVEs) in initial modification window; overlapping records deduplicated. Not complete NVD history. |
| CISA KEV / cisagov/kev-data | Implemented; live validated | 1,762 entries in catalog; historical observations retained after delisting. |
| GitHub Advisory Database API | Implemented; parser and pagination tested; full live window failed | Official API for reviewed non-malware advisories. Unauthenticated rate limit prevented completion; checkpoint did not advance. Requires successful token-enabled validation before enabling automation. |
| OSV | Implemented; live validated | 7 advisory records from configured IDs and requests 2.31.0 watch; package queries use official version semantics upstream. Not all ecosystems mirrored. |
| FIRST EPSS | Implemented; live validated | 396,966 daily rows; probability, percentile, and score date retained. Full daily CSV is the supported bulk mechanism. |
| CISA advisories | Implemented; live validated | 30 RSS entries; metadata and references, no historical scraping or prose-based CVE correlation. |
| CISA ICS advisories | Implemented; live validated | 30 official RSS entries; metadata; CSAF product/range ingestion not implemented. |
| CERT/CC | Optional; Atom adapter live validated | 15 entries; disabled by default pending redistribution review. Not a complete VU archive. |
| Red Hat advisories | Implemented; live validated | 158 recent RHSA RSS entries; OS/container advisory metadata; no complete container image database or RPM range evaluation. |
| MITRE CWE | Implemented; live validated | 984 weakness summaries; latest official XML ZIP; source examples excluded. |
| MITRE CAPEC | Implemented; live validated | 615 classification summaries; latest XML; execution flows excluded. |
| ATT&CK Enterprise / ICS | Implemented; live validated | 26,690 / 2,566 STIX objects, including relationships and markings; counts are objects, not techniques. No linked tools downloaded. |
| Exploit references | Implemented; fixtures tested | Only upstream references explicitly tagged Exploit; no URL crawling or payload fetching. |
| Other vendors, complete OSV dumps, distro CSAF/OVAL, container inventory | Not integrated; optional extensions | No universal feed is fabricated. Red Hat RSS and OSV watches provide bounded existing coverage. |

Official URLs, rights, authentication, pacing, and update cadence are documented
in [the source audit](docs/SOURCES.md) and `config/sources.json`.

## Architecture and storage

```text
config/                      source registry, watch scope, risk weights
scripts/sources/feeds.py      bounded official API / CSV / XML / STIX adapters
scripts/http_client.py       timeout, validators, retry and safe Range resume
scripts/store.py             atomic per-source transactions, hashes, checkpoints
scripts/normalize.py         common schema without invented values
scripts/query.py             read-only agent and human CLI
indexes/intelligence.sqlite  raw source records, normalized records, term indexes
data/curated/<source>/<shard> selected normalized JSON, eligible for Git
data/cisa-kev/latest.json    compatible small KEV output, accumulated observations
metadata/                    source outcomes, coverage, source attribution
.cache/http/                 regenerable HTTP representations and partial downloads
tests/                       offline fixtures and mocks
```

SQLite holds full source-specific JSON alongside normalized records. A single
source transaction updates records, indexed terms, and its checkpoint together.
A failed request, parser, record budget, or validation rolls back that source;
successful independent sources remain usable. WAL permits readers during ingestion.
Older CVE, NVD, GHSA and OSV revisions are kept in SQLite's `history` table.
No existing CVE IDs or rejected records are deleted. Daily EPSS values keep the
latest observation per CVE; long-term score history requires external archives.
CWE/CAPEC raw rows are explicit metadata projections, not complete original XML.

Records use source and verified identifiers as identity; CVE/GHSA/OSV alias links
correlate exact upstream IDs. Descriptions and similar package names never merge
records. Conflicting assessments remain separate. Reserved/rejected/withdrawn and
disputed states remain visible. Missing CVSS and unknown exposure remain unknown.

Indexes cover ID, CVE, GHSA, OSV, vendor, product, package, CWE, severity, KEV and
publication day. Values are exact and case sensitive. Search returns up to 100
records by default (Python API supports 1,000). This is not a fuzzy search engine.

## Install and run locally

An existing Python 3.12+ interpreter is sufficient; `requirements.txt` has no packages.

```powershell
python -m unittest discover -s tests -v
python scripts/sync.py --sources cisa-kev,osv
python scripts/query.py --field cve --value CVE-2021-44228 --report
python scripts/sync.py
python scripts/validate.py
```

Default initial CVE, NVD and GitHub windows start one day ago. Other sources use
current feeds or explicitly configured OSV watches. `--sources` selects a comma
separated subset, including optional adapters. Edit `config/sources.json` to set
enabled sources, IDs, package/version watches, record and curated-export budgets.
There are no API keys in the registry. Optional `NVD_API_KEY` and `GITHUB_TOKEN`
are read only from the process environment. None were configured during this task.

```powershell
python scripts/sync.py --sources nvd --start 2026-10-01T00:00:00+00:00
python scripts/sync.py --import-dir C:\datasets\cvelistV5\cves --import-source cve --start 2026-10-28T00:00:00+00:00
python scripts/sync.py --sources cve
python scripts/generate_index.py
```

Imports never delete the supplied tree. `--start` on an import is your assertion
of the snapshot's complete coverage boundary, not an upstream verification.
Verify that boundary yourself, use a retained official baseline, and catch up from
it immediately. Without an explicit boundary an import uses 1970, causing CVE
gap detection to stop an unsafe delta-only continuation. Backfills use bounded
119-day NVD windows. Large requested runs can exceed source budgets; narrow the
requested interval and resume. HTTP page caches and validated Range downloads
survive interruptions; uncommitted source rows are replayed on the next attempt.

The old starter's `data/first-epss/latest.csv.gz`, advisory tarball and
`data/sync-status.json` are not deleted if present. Canonical status is now in
`metadata/`. Full advisory tarballs are no longer produced or staged.

## Tempest read-only use

```powershell
python scripts/query.py --agent kakashi --value CVE-2021-44228 --report
python scripts/query.py --agent itachi --field kev --value true
python scripts/query.py --field package --value requests --ecosystem PyPI --version 2.31.0
python scripts/query.py --value CVE-2021-44228 --report --exposed
```

`Reader` opens SQLite using `mode=ro` and `PRAGMA query_only=ON`; mutation attempts
fail. `--agent` labels intended use; it does not activate a specialist or create an
authentication boundary. OS file permissions must restrict agents to read-only
access if they also have independent shell tools. No memory gateway was connected.

Reports return separate source evidence, references, CVSS assessments, EPSS date,
historical KEV observation, risk inputs, last checked time, failure/coverage status,
and incomplete/stale indicators. Read-only clients use the last successful source
checkpoint; records unchanged for years can still have a fresh source check.
48 hours without a successful check marks a record stale. Coverage is always
limited to the configured watch/window and must be considered separately.

Offline package matching supports exact OSV listed versions and SemVer intervals
including prerelease bounds. Unsupported PEP 440, RPM, Debian, Git and GHSA textual
ranges return `null` (unknown), never a fabricated affected/unaffected decision.
Configure a watch and synchronize through OSV for authoritative version-aware
queries. Package names and ecosystem must match exactly; `pip` and `PyPI` are
kept as supplied by their sources. No ecosystem equivalence is silently assumed.

`config/risk.json` configures an additive policy score: KEV 50, EPSS probability
times 25, technical CVSS/10 times 15, explicitly asserted exposure 10, missing
remediation evidence 5, and stale source evidence 5. This is a policy ranking,
not a percentage; it can exceed 100. CVSS is technical severity, EPSS is a model
estimate, and KEV is evidence of known exploitation. Public exploit links do not
confirm exploitation. `--exposed` is an explicit inventory assertion, not a scan.
Rejected/withdrawn conflicting records suppress scoring. No asset inventory is
invented, and a zero score does not mean a vulnerability is safe.

## GitHub Actions and deployment

Workflows are JSON-form YAML 1.2 for dependency-free syntax validation. All Actions
are pinned to verified commit SHAs. Validation runs on PRs/pushes using read-only
contents access, with checkout credentials disabled. Sync is scheduled daily at
**12:00 AM IST (00:00, Asia/Kolkata)**, equivalent to **18:30 UTC on the preceding
day**, or by manual dispatch on the default branch. The schedule uses
`cron: '0 0 * * *'` with `timezone: 'Asia/Kolkata'`; cron times are interpreted in
that timezone. Only the sync job requests `contents: write`. Branch concurrency
prevents competing scheduled runs. GitHub may delay or skip scheduled runs; use
**Actions > Sync vulnerability intelligence > Run workflow** for manual recovery.

Exact deployment steps, to perform **only after explicit approval**:

1. Have an independent reviewer inspect this implementation and its evidence,
   source licensing, retention, and recovery plan. This review is still pending.
2. The local repository is already linked to `Pepperjack-svg/VULN-INTEL` at your
   request. Obtain approval to commit/push this reviewed revision; no new commit
   or push has been performed.
3. Establish a complete retained baseline if historical coverage is required.
   Choose approved durable storage for SQLite/backups; no storage service is configured.
4. Publish the approved files to your chosen repository/default branch. Keep
   `SYNC_ENABLED` unset while reviewing Actions permissions and branch rules.
5. Allow the workflow's scoped token write permission if organization policy
   permits it. No PAT is required. Optionally configure free `NVD_API_KEY` as an
   Actions secret; GitHub supplies `GITHUB_TOKEN` automatically.
6. Set `SYNC_ENABLED=true`, set optional `INTEL_RETENTION_DAYS` (default 7), and
   manually dispatch. Inspect **every source** outcome; resolve GitHub's live
   pagination validation failure before declaring the source operational.
7. Verify the generated commit, backup artifact and a full restore drill, then
   allow the next scheduled run. A protected branch that blocks bot pushes needs
   a reviewed PR publication process; do not bypass protections.

Sync errors fail the workflow and prevent the publication step. Failure evidence
and SQLite are uploaded even on failure. Publishing stages only curated data,
small KEV output and metadata; unrelated working changes stop it. Push recovery
uses at most three ordinary pushes with fetch/rebase; conflicts abort without
force pushes or remote history rewrites. This helper was tested with mocked Git,
not against a live remote. Manual local sync never commits or pushes.

## Repository limits, retention and recovery

Full SQLite and HTTP snapshots are ignored by Git. Git receives curated KEV-linked
records and configured IDs only; exports default to at most 20,000 records. Git
candidate files must be under 45 MiB, with a 250 MiB aggregate working-tree budget.
These are conservative gates below GitHub's 100 MiB per-file limit, not a promise
that Git history stays small. Repeated curated EPSS updates still grow history;
monitor repository size and reduce watch/export scope before the budget is reached.
No automated history rewriting is performed.

HTTP representations have configurable 7-day/512 MiB retention and are regenerable.
SQLite source records and vulnerability revisions are never subject to cache
pruning. Actions snapshots use `INTEL_RETENTION_DAYS`; caches are optimizations,
not permanent archives. A scheduled run with no restored SQLite fails instead of
silently resetting coverage. Manual dispatch permits an intentional partial
bootstrap; examine its declared coverage before using it.

Download an approved state artifact and restore `intelligence.sqlite` into
`indexes/` while ingestion is stopped, restore its matching `metadata/`, validate,
and resume. Cache restoration alone cannot recover after cache eviction or artifact
expiry. Preserve long-term snapshots in an approved external archive or a persistent
runner with backups. A full baseline is otherwise needed after a long CVE gap.
No external archive integration is implemented. Do not pay for or configure one
without approval. Git LFS is intentionally not used: it does not solve daily full
snapshot history, and its quotas/billing need separate approval.

Plan approximately 1–5 GB for the first million metadata records and indexes,
plus source-dependent revision history and backup copies. Large NVD/CVE descriptions
and repeated revisions can exceed this estimate. The verification report records
actual sample sizes; it is not a complete-dataset benchmark. The Actions job has a
90-minute budget; full historical backfills belong on a persistent local runner.

## Licensing and attribution

The existing repository LICENSE applies to project code. Source data retains
upstream rights; the repository license does not relicense those datasets. Retain
source registry, record identifiers, references and [attribution notices](docs/SOURCES.md)
with any export. GitHub Advisory data is CC-BY-4.0, CISA's KEV repository is CC0,
and Red Hat security data is CC-BY-4.0. OSV data inherits originating database
licenses; inspect each newly configured ecosystem. EPSS is publicly provided by
FIRST and Empirical Security with attribution requested; a blanket SPDX license
is not asserted. MITRE datasets require their copyright and license notices in
distributed copies. CERT/CC redistribution review remains open.

This product uses the NVD API but is not endorsed or certified by the NVD.
No upstream organization endorses this repository. Source changes or updated terms
require review before broader redistribution.

## Validation and troubleshooting

```powershell
python -m compileall -q scripts tests
python -m unittest discover -s tests -v
python scripts/validate.py
git diff --check
```

Tests use synthetic fixtures/mocks, not live APIs. Validation checks candidate file
sizes, JSON-form YAML workflow syntax, immutable Action pins, common secret patterns,
SQLite integrity and source content hashes. Secret patterns are heuristic and cannot
prove absence of every secret. `git diff --check` checks tracked changes; the new
implementation is currently untracked, so it also requires direct file inspection
before staging. The validator scans tracked and nonignored untracked candidates.

- `status: error`: prior source transaction/checkpoint is preserved; inspect source
  configuration, network availability, upstream schema and rate limits. Status logs
  store exception types rather than potentially sensitive authenticated request text.
- HTTP 429/403: bounded retry honors `Retry-After`/reset; waits above 120 seconds
  defer the source to a later run. Use the built-in workflow token for GitHub.
- CVE coverage gap: import an independently verified official baseline and resume
  from its boundary. Do not simply advance the checkpoint to hide missing records.
- Interrupted process: first verify no sync is active, then remove only the stale
  `.cache/sync.lock`. Partial downloads with strong ETags can resume safely.
- Missing SQLite after cloning: run ingestion or restore the approved archive;
  Git's curated files are a subset and cannot reconstruct the full raw database.
- Budget failure: existing database remains intact; reduce window/watch/export scope
  or arrange approved archival storage. Do not delete vulnerability history to pass.

See [engineering decisions and traceability](vault/Projects/cve-intelligence-build.md)
and [verification evidence](metadata/verification.json) for remaining review gates.

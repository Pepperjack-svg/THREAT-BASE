# THREAT-BASE

An open-source cybersecurity intelligence database aggregating vulnerability records, security advisories, exploitation intelligence, and attack-pattern datasets from trusted public sources.

## Project overview

THREAT-BASE provides Python tools to collect, validate, normalize and search public
security metadata. It is intended for cybersecurity researchers, security engineers,
developers, analysts and students who need attributable vulnerability evidence.

The project combines a local SQLite database with a bounded set of curated JSON
records in Git. It is a metadata resource: it does not scan external systems,
execute exploits or download linked malware, exploit payloads or offensive tools.

Coverage depends on configured sources, watches and import boundaries. Check
[per-source synchronization status](metadata/sync-status.json) before relying on a
record. An implemented adapter does not establish complete or current coverage.

## Key features

- Official JSON, CSV, XML, RSS/Atom and STIX metadata adapters.
- Incremental modification windows, conditional HTTP requests, bounded retries,
  timeouts and strong-ETag download resumption where supported.
- Atomic source transactions, content hashes, retained vulnerability revisions and
  checkpoints that preserve earlier data when a source fails.
- Normalized records with exact upstream identifier correlation and separate evidence.
- Read-only local search, defensive reports and configurable risk prioritization.
- Daily synchronization and monthly release workflows with manual triggers.
- File-size gates, curated exports, ignored local databases and source attribution.

## Supported intelligence sources

These statuses describe the implementation and recorded local validation, not a
claim that a live GitHub Actions synchronization has succeeded.

| Source | Data category | Integration status | Update mechanism |
| --- | --- | --- | --- |
| CVE Program / cvelistV5 | CVE records | Implemented; live record sample validated; historical baseline required | Rolling delta log and local baseline import |
| NIST NVD | CVSS, CPE and vulnerability metadata | Implemented; recent live window validated; partial history | Paginated API 2.0 modification windows |
| CISA KEV | Known exploitation evidence | Implemented; live catalog validated; delisted observations retained | Official JSON catalog |
| FIRST EPSS | Exploitation probability estimates | Implemented; live daily file validated | Daily gzip CSV |
| GitHub Advisory Database | Reviewed package advisories | Implemented; full live window remains unverified after a rate-limit failure | Paginated REST API modification windows |
| OSV | Open-source package vulnerabilities | Implemented; configured watches live validated; limited scope | Version-aware package queries and advisory retrieval |
| CISA advisories and ICS | Security and industrial advisories | Implemented; current feeds live validated | RSS metadata and references |
| CERT/CC | Vulnerability notes | Optional; feed tested; disabled pending redistribution review | Atom metadata |
| Red Hat | OS and container-related advisories | Implemented; recent feed live validated; no image inventory | RHSA RSS metadata |
| MITRE CWE and CAPEC | Weakness and attack-pattern classifications | Implemented; catalogs live validated; examples/procedures excluded | Official XML/ZIP downloads |
| MITRE ATT&CK Enterprise and ICS | Threat knowledge | Implemented; bundles live validated | Official STIX JSON bundles |
| Public exploit references | Defensive reference metadata | Implemented for explicitly tagged upstream references | Extracted from source records; links are not fetched |

Full OSV mirroring, additional vendor feeds, CSAF/OVAL product matching and
container-image matching are not implemented. See [DATA_SOURCES.md](DATA_SOURCES.md)
for providers and terms, [the source audit](docs/SOURCES.md) for API details, and
[the source registry](config/sources.json) for exact enabled scope.

## Repository structure

```text
.github/workflows/     Validation, daily synchronization and monthly releases
config/                Source URLs, enabled feeds, watches and risk weights
scripts/               Ingestion, normalization, validation, indexing and search
scripts/sources/       Upstream format adapters
data/curated/          Partitioned normalized records selected for Git
data/cisa-kev/         Compatible small KEV export
metadata/              Source attribution, outcomes and verification summaries
docs/                  Public source documentation
tests/                 Offline tests with fixtures and mocks
indexes/               Local generated SQLite database; ignored by Git
```

[Technical design notes](vault/Projects/cve-intelligence-build.md) describe storage,
trust boundaries and recovery. Optional generated paths appear only when used.

## Getting started

```sh
git clone https://github.com/Pepperjack-svg/THREAT-BASE.git
cd THREAT-BASE
python -m unittest discover -s tests -v
python scripts/sync.py --sources cisa-kev,osv
python scripts/query.py --value CVE-2021-44228 --report
```

The local SQLite database is created during ingestion. A clone includes curated
records, not the full raw database. Restore a retained database snapshot or run
synchronization before using the local search CLI.

## Installation and requirements

Use Python **3.12 or later** and Git. Runtime and tests use the Python standard
library; no dependency-installation step or requirements file is needed. Workflows
use Python 3.12 on GitHub-hosted Ubuntu runners.

Optional environment variables are `NVD_API_KEY` for NVD and `GITHUB_TOKEN` for
GitHub API access. Public access works within upstream limits; no paid API is
required. Keep credentials in environment variables or GitHub Actions secrets.

## Data synchronization

```sh
python scripts/sync.py
python scripts/sync.py --sources cisa-kev,first-epss
python scripts/sync.py --sources nvd --start 2026-10-01T00:00:00+00:00
python scripts/validate.py
python scripts/generate_index.py
```

Edit [config/sources.json](config/sources.json) to select enabled sources, OSV
package/version watches, curated IDs, record budgets and HTTP-cache retention.
`--sources` explicitly selects adapters, including optional ones.

CVE, NVD and GitHub initially use a recent one-day window. Later runs use successful
source checkpoints with a five-minute overlap. NVD requests use bounded date windows;
EPSS uses its complete current daily CSV; catalogs and feeds use HTTP validators.
Unchanged source records keep stable content hashes and synchronization timestamps.

For existing official CVE or OSV trees:

```sh
python scripts/sync.py --import-dir /datasets/cvelistV5/cves --import-source cve --start 2026-10-28T00:00:00+00:00
```

An import boundary is the operator's assertion that the retained snapshot is
complete through that time. Verify it independently. Imports do not delete the
supplied tree. CVE delta gaps fail instead of silently treating missing history as
covered. A default undated import starts at 1970 and cannot safely continue a recent
delta stream without a verified boundary.

Each source is transactional. Failures preserve its earlier records and watermark,
are recorded in [metadata/sync-status.json](metadata/sync-status.json), and make the
sync command fail. Successful independent sources remain stored. HTTP state can be
reused after interruption; an uncommitted source transaction is replayed.

## Automated updates and GitHub Actions

| Workflow | Schedule | Manual trigger |
| --- | --- | --- |
| [Synchronization](.github/workflows/sync.yml) | Daily at **12:00 AM IST**, `Asia/Kolkata` (18:30 UTC on the preceding day) | Run workflow |
| [Monthly release](.github/workflows/release.yml) | First day of each month at **1:00 AM IST** (19:30 UTC on the preceding day) | Run workflow |
| [Validation](.github/workflows/validate.yml) | Pushes and pull requests | Run workflow |

Timezone-aware cron expressions are `0 0 * * *` for sync and `0 1 1 * *` for releases,
with `timezone: Asia/Kolkata`. GitHub may delay or skip scheduled executions; use
**Actions > workflow name > Run workflow** to recover. Schedules use the default branch.

To configure a fork or deployment:

1. Allow GitHub Actions and the workflows' job-scoped `contents: write` permissions.
2. Establish a retained baseline if historical coverage is required. Scheduled sync
   fails if its local database state cannot be restored; manual dispatch permits
   an intentional partial bootstrap.
3. Set repository variable `SYNC_ENABLED=true` to enable scheduled daily data publication.
   Manual **Run workflow** dispatches on the default branch work without this variable,
   including the initial bootstrap. Both triggers publish validated data changes.
   GitHub supplies the built-in token; optional `NVD_API_KEY` is an Actions secret.
4. Set optional `INTEL_RETENTION_DAYS` for state artifacts (default seven days).
5. Manually run sync and inspect every source outcome, job log and resulting commit.
   Verify restoration from a retained snapshot before relying on unattended updates.

If an earlier manual run was skipped, start a new **Run workflow** on the default
branch after updating the workflow. Re-running the old run uses its original revision.

Only jobs that publish data or releases request write access. Actions are pinned
by commit SHA. Concurrency controls prevent competing runs within each workflow.
Validation precedes publication. Source failures prevent data publication, while
failure artifacts preserve evidence. Git pushes use bounded fetch/rebase recovery;
conflicts stop without force-pushing or overwriting unrelated changes. Protected
branches may require a separately configured PR-based publication process.

Monthly publication requires a completed, successful latest daily sync on the same
default branch. It uses that exact run/attempt cache key and rejects missing state,
failed/in-progress syncs, stale sources, absent datasets, checkpoint mismatches and
corrupted records. Code/config changes after the validated run require another daily
sync. A 1:00 AM release may stop if the midnight sync is still running; rerun after
it completes. Releases do not start a fresh sync or establish full historical coverage.

Workflow configuration has been checked locally. Successful live source synchronization
and monthly publication through GitHub Actions have **not been verified** here.

## Releases

The workflow uses [scripts/release.py](scripts/release.py) for validated snapshot
preparation, draft recovery and publication; it does not alter the daily sync logic.

[GitHub Releases](https://github.com/Pepperjack-svg/THREAT-BASE/releases) use calendar
versions `YYYY.MM`, tags such as `v2026.11`, and titles such as
**THREAT-BASE — November 2026**. Versions use the date in Asia/Kolkata. A published
month is never replaced, even if no new records were added during that month.

Compressed snapshots contain current records for enabled, successfully validated
sources. Assets are grouped as CVE, NVD, KEV, EPSS, advisories, classifications and
metadata; for example, `threat-base-kev-2026-11-part001.tar.gz`. Groups are partitioned
around 128 MiB of uncompressed JSONL. Empty data archives are not created. Each asset
is limited to 1 GiB and generated data assets to 4 GiB per run; larger deployments
require a separately reviewed storage plan. Generated assets remain in ignored `dist/`.

Data archives include JSONL source records and normalized projections, configuration,
attribution and required available upstream notice texts. Metadata archives contain
source status and configuration. `manifest.json` records the validated Git commit,
UTC snapshot time, daily run, source counts, coverage, snapshot hashes and recorded
upstream versions. Notes disclose unavailable versions or new/updated-record counts
rather than guessing. Older revisions remain in retained SQLite backups; these assets
snapshot current records rather than duplicating repository history. OSV archive
support currently covers GHSA/PyPI origins; others require reviewed redistribution
and notice support. Review [source terms](DATA_SOURCES.md) before full-data distribution.

Download all archives, `manifest.json` and `SHA256SUMS` from the same release into
one directory and verify them:

```sh
sha256sum -c SHA256SUMS
# macOS alternative:
shasum -a 256 -c SHA256SUMS
```

On PowerShell, use `Get-FileHash -Algorithm SHA256 <downloaded-file>` and compare
the result with its `SHA256SUMS` line. The checksum list covers every data archive
and `manifest.json`; it does not recursively checksum itself. After checking hashes,
inspect an archive with `tar -tzf <archive.tar.gz>` before extracting it.

Publication creates an owned draft at the exact validated commit, uploads assets,
and verifies their sizes and SHA-256 digests. Assets without an API-provided digest
are downloaded for hashing. Only a complete verified draft becomes public. Transient
API/upload errors use bounded retries and GET-based recovery; completed uploads are
reused without overwriting. Missing/conflicting published assets produce an error
without modifying the existing release.

Use **Actions > Monthly THREAT-BASE release > Run workflow** for manual execution.
After an interrupted upload, prefer **Re-run jobs** on the original attempt so its
commit remains unchanged. Recovery preserves the original draft timestamp and
requires the same manifest and still-fresh daily state. Drafts from another snapshot,
orphaned tags and partial/conflicting existing assets require manual review. Automation
does not remove assets or move tags; failures retain an unpublished draft.

The release job requires built-in-token `contents: write` and `actions: read`; other
workflow permissions remain read-only. No PAT or additional Python dependency is
needed. Deploy only after reviewing the code and redistribution rights, pushing the
approved revision, and completing a successful daily sync. Then manually verify a
release, its assets and publication, and inspect repository/tag rules and actual
Actions results before relying on scheduled execution. Private development notes
are excluded from all dataset archives.

## Searching and using the data

```sh
python scripts/query.py --field cve --value CVE-2021-44228
python scripts/query.py --field package --value requests --ecosystem PyPI --version 2.31.0
python scripts/query.py --field kev --value true
python scripts/query.py --value CVE-2021-44228 --report --exposed
```

Search supports ID, CVE, GHSA, OSV, vendor, product, package, CWE, severity, KEV and
publication day. Values are exact and case sensitive. The CLI returns up to 100
records; the Python Reader API supports a configurable limit up to 1,000.

Reports correlate verified aliases and return source evidence, CVSS assessments,
EPSS dates, historical KEV observations, remediation references, stale/incomplete
flags and risk inputs. A source without a successful check for 48 hours is stale.
`--exposed` is an explicit asset-inventory assertion, not a network scan.

Offline matching handles exact listed OSV versions and SemVer intervals. Unsupported
PEP 440, RPM, Debian, Git and GHSA textual ranges return `null` (unknown). Configure
an OSV package/version watch for upstream version-aware evaluation. Ecosystems remain
as supplied; names such as `pip` and `PyPI` are not silently equated.

The [risk policy](config/risk.json) combines KEV, EPSS, CVSS, asserted exposure,
missing remediation evidence and freshness. Its score is an additive ranking, not
a probability, and can exceed 100. Public exploit references do not confirm active
exploitation; CVSS is technical severity. Reader uses SQLite `mode=ro` and
`query_only=ON`; independent filesystem access still needs operating-system controls.

## Data formats and schemas

Upstream source-specific JSON and normalized records are stored together in SQLite.
Classification XML is reduced to explicitly selected metadata, not stored as complete
original XML. Normalization and term indexes are implemented in
[scripts/normalize.py](scripts/normalize.py) and [scripts/store.py](scripts/store.py).

| Record fields | Meaning |
| --- | --- |
| `id`, `source`, `aliases` | Original identity, provider key and exact identifier links |
| `title`, `description`, `published`, `modified`, `state`, `disputed` | Available source narrative, timestamps and status |
| `cvss`, `severity`, `cwes`, `cpes` | Separate technical assessments and classifications |
| `vendors`, `products`, `affected`, `packages`, `fixed_versions` | Available software and remediation evidence |
| `kev`, `epss` | Known-exploitation observation and dated probability/percentile |
| `references`, `exploit_references` | Attributed upstream links; linked content is not fetched |
| `last_synchronized`, `content_hash`, `original_source_identifier` | Curated export provenance and integrity fields |

Missing values remain `null` or empty collections. Rejected, reserved, disputed and
withdrawn records remain distinguishable. Older CVE/NVD/GHSA/OSV revisions remain in
SQLite history; EPSS retains the latest observed score per CVE. Source outcomes and
coverage are JSON in `metadata/`. This is a documented implementation schema; no
separate formal JSON Schema or public HTTP service is currently supplied.

## Source attribution and licensing

THREAT-BASE credits the original publishers below. It collects and transforms their
metadata; it does not own or independently originate their security assessments.

| Original publisher | Integrated data / official URL |
| --- | --- |
| [CVE Program and contributing CNAs](https://www.cve.org/) | [Official CVE List V5](https://github.com/CVEProject/cvelistV5) |
| [National Institute of Standards and Technology](https://www.nist.gov/) | [NIST National Vulnerability Database](https://nvd.nist.gov/) |
| [Cybersecurity and Infrastructure Security Agency](https://www.cisa.gov/) | [KEV](https://github.com/cisagov/kev-data), [CISA advisories](https://www.cisa.gov/cybersecurity-advisories) and [ICS advisories](https://www.cisa.gov/cybersecurity-advisories/ics-advisories) |
| [FIRST EPSS Special Interest Group](https://www.first.org/epss/) and [Empirical Security](https://www.empiricalsecurity.com/) | Daily EPSS probability and percentile data |
| [GitHub and advisory contributors](https://github.com/github/advisory-database) | GitHub Advisory Database; also original GHSA records returned through OSV |
| [OSV project / Google](https://osv.dev/) | OSV API aggregation and version-aware queries; original dataset rights remain separate |
| [Python Packaging Authority and advisory contributors](https://github.com/pypa/advisory-database) | Original PyPI/PYSEC advisory records returned through OSV |
| [The MITRE Corporation and contributors](https://www.mitre.org/) | [CWE](https://cwe.mitre.org/), [CAPEC](https://capec.mitre.org/) and [ATT&CK](https://attack.mitre.org/) Enterprise/ICS |
| [CERT Coordination Center](https://www.kb.cert.org/vuls/), [Carnegie Mellon University SEI](https://www.sei.cmu.edu/) | Implemented CERT/CC Atom adapter; disabled pending redistribution review |
| [Red Hat Product Security](https://access.redhat.com/security/data) | Official RHSA advisory feed |

Original CNA, vendor and advisory-author references and supplied credit/copyright
fields remain in source records. Crediting a database does not transfer those
authors' rights or imply endorsement. Only implemented adapters and the actual
GitHub/PyPA origins used by the OSV integration are credited here.

Source data remains subject to upstream terms; public accessibility does not make
it unrestricted. Preserve provider identities, references, licenses and required
notices with redistributed data. See [DATA_SOURCES.md](DATA_SOURCES.md) for providers,
rights and verification limits, and [docs/SOURCES.md](docs/SOURCES.md) for the existing
audit. Optional CERT/CC mirroring remains disabled pending redistribution review.

Monthly `manifest.json`, the metadata archive's `attribution.json`, and release
notes identify the publishers, official and dataset URLs, terms, transformations
and restrictions for the included sources. Available upstream notice texts are
copied verbatim into data and metadata archives with their SHA-256 digests recorded.
GitHub and PyPA OSV-origin notices are kept separately. Existing project and upstream
copyright/license notices are preserved; normalization does not relicense them.

This product uses the NVD API but is not endorsed or certified by the NVD.
No upstream organization is represented as endorsing this project.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for validation commands and contribution
requirements. Include reproducible evidence for parser, source and coverage changes.
Preserve historical records, source attribution and existing workflow entry points.

## Security policy

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities and handling upstream
metadata safely. Use the project only for authorized research and defensive analysis.

## Limitations and disclaimers

- Initial historical coverage is partial; optional and failed sources remain explicit.
- Upstream data can be incomplete, stale, corrected or unavailable. A missing record,
  low policy score or public exploit link does not establish safety or exploitation.
- Git contains curated records, not a complete raw database. Backups and recovery
  require retained SQLite snapshots or an independently verified upstream baseline.
- Cache and Actions artifacts expire. HTTP cache retention defaults to seven days
  and 512 MiB; artifact retention is configurable. No durable external archive is configured.
- Curated exports default to 20,000 records. Validation gates Git candidates at
  45 MiB per file and 250 MiB total; repeated updates can still grow repository history.
- Full backfills can exceed the 90-minute sync job budget. No history rewriting or
  paid storage is configured to work around these limits.
- Automated secret checks are heuristic. Tests and static checks do not establish
  a security certification, independent review, upstream completeness or live availability.

## License

Eligible original project contributions are made available under the
[Apache License 2.0](LICENSE) where contributors hold the necessary rights.
Third-party code and vulnerability datasets retain their respective terms; the
project does not claim ownership of imported intelligence. No additional personal
copyright assertion is made.

This project may include AI-assisted development. Copyright and licensing claims
apply only to material for which the relevant contributors hold the necessary rights.

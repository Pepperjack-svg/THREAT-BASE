# THREAT-BASE

A source-organized collection of vulnerability records and threat intelligence.
Browse the original JSON files directly; no Python application or SQLite setup is required.

The CVE/NVD layout follows [Navin Hariharan's CVE-DATABASE](https://github.com/navin-hariharan/CVE-DATABASE).
Data comes from its original publishers, who retain their rights and attribution.

## Database layout

| Folder | Contents / original publisher |
| --- | --- |
| `cvelistV5/<year>/<bucket>/CVE-*.json` | Official CVE Program and CNA records |
| `nvd-json-data-feeds/CVE-<year>/<bucket>/CVE-*.json` | NIST NVD records; automated mirror supplied by FKIE CAD |
| `github-advisory-database/` | GitHub reviewed, unreviewed and malware advisories |
| `pypa-advisory-database/` | PyPA/PYSEC package advisories |
| `mitre-attack/` | MITRE ATT&CK STIX datasets and supplied versions |
| `cisa-kev/` | CISA Known Exploited Vulnerabilities catalog |
| `cisa-advisories/` | CISA IT/ICS CSAF advisories and current RSS feeds |
| `epss/` | FIRST / Empirical Security probability scores |
| `cwe/`, `capec/` | MITRE weakness and attack-pattern catalogs |
| `redhat-advisories/` | Red Hat RHSA feed and local CSAF/VEX history |
| `osv/` | Local full OSV export across all ecosystems |

Original source fields are preserved. Older revisions in upstream Git history are
not included in a current repository snapshot. Feed-only endpoints cannot establish
full history. See [DATA_SOURCES.md](DATA_SOURCES.md) for original sources and terms.

## Use the database

```sh
git clone https://github.com/Pepperjack-svg/THREAT-BASE.git
cd THREAT-BASE
find cvelistV5 -name 'CVE-2021-44228.json'
```

Open a JSON file directly, or use `jq` to inspect its original fields.
Large historical ZIP/CSV/CSAF archives are retained locally and excluded from ordinary
Git commits. The full OSV archive exceeds GitHub's individual release-asset limit.
Downloading an archive does not automatically publish or import it.

## Updates

[Daily sync](.github/workflows/sync.yml) runs at midnight Asia/Kolkata when repository
variable `SYNC_ENABLED=true`. **Run workflow** works on the default branch without
that variable. Start a new run after a workflow fix; old runs use their old revision.

The sync mirrors CVE, the FKIE NVD reconstruction, GitHub/PyPA advisories, ATT&CK and
CISA CSAF records, plus current KEV, EPSS, CWE, CAPEC and advisory feeds.
Upstream code is excluded and never executed. Failed downloads stop publication;
previous records are retained. Git pushes use bounded reconciliation.
Large OSV and EPSS historical archives are local bulk downloads, not daily Git mirrors.

[Monthly releases](.github/workflows/release.yml) run on the first day of the month
at 1 AM Asia/Kolkata and can be started manually. They package committed source
folders with attribution, use `vYYYY.MM` tags, and never replace a published month.
Publication requires a successful daily sync within the preceding 36 hours; code
changes after that run require another sync.
Archives are split below the per-file limit. Verify `SHA256SUMS`, concatenate each
dataset's `.part-*` files in filename order, then extract its tar.gz. A failed upload
leaves a draft for review. Live execution of the replacement workflows is unverified.

## Contributing and licensing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
Original eligible project contributions retain the [Apache 2.0 license](LICENSE).
Upstream data has its own terms; public access does not grant unrestricted redistribution.
This product uses NVD data but is not endorsed or certified by NVD.

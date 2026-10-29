# Source audit and attribution

Audit date: 2026-10-29. Upstream content is untrusted data. No linked payload is
downloaded. Each URL below was checked against the official provider's published
documentation or repository. Availability checks do not guarantee continuing access.
See [DATA_SOURCES.md](../DATA_SOURCES.md) for the consolidated provider and rights
register, including unresolved redistribution and verification limits.

| Source / official documentation | Format / cadence | Authentication and pacing | Rights / limitations |
| --- | --- | --- | --- |
| [CVE Program](https://github.com/CVEProject/cvelistV5) | CVE JSON 5; delta log updated roughly every few minutes | Public GitHub raw files; no API key; conditional requests; no published raw-host SLA assumed | [CVE terms](https://www.cve.org/Legal/TermsOfUse); retain CVE attribution. Rolling delta log is not full history. Gaps rejected. |
| [NVD developers](https://nvd.nist.gov/developers/start-here), [API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | Paginated JSON; continuous modifications | Free optional key; implementation conservatively spaces calls 6.1 seconds without key / 0.7 with key (nominal 5 / 50 per 30 seconds); honor actual responses | US government data; API non-endorsement notice required; analysis can be incomplete/delayed; max date window respected. |
| [CISA KEV repository](https://github.com/cisagov/kev-data) | JSON catalog; as updated by CISA | Public raw file; validators and bounded retries | [CC0-1.0](https://raw.githubusercontent.com/cisagov/kev-data/main/LICENSE); linked third-party material has separate rights; no CISA logo/endorsement granted. |
| [GitHub Advisory Database](https://github.com/github/advisory-database), [global API](https://docs.github.com/en/rest/security-advisories/global-advisories) | JSON REST pages; modified-time windows | Public access or optional token; 1.1-second spacing; nominal unauthenticated 60 requests/hour; built-in Actions token nominal 1,000/hour/repository; secondary limits apply | [CC-BY-4.0](https://github.com/github/advisory-database/blob/main/LICENSE.md); reviewed, non-malware only; live completion blocked by unauthenticated rate limit. |
| [OSV supported sources/downloads](https://google.github.io/osv.dev/data/), [query API](https://google.github.io/osv.dev/post-v1-query/) | OSV JSON; continuous upstream updates; configured watches checked daily | Public GET advisory and POST version queries; no paid key; no fixed capacity assumption; bounded retry and pagination | Actual configured GHSA/PYSEC origins are GitHub and the PyPA PyPI Advisory Database, both CC-BY-4.0. No other origin or full bulk mirroring is claimed; additional origins require their own rights review. |
| [FIRST EPSS data](https://www.first.org/epss/data), [FAQ](https://www.first.org/epss/faq) | Gzip CSV; daily snapshot; header includes model/date | Public unauthenticated download; one bulk file, not hundreds of thousands of lookup API calls | FIRST/Empirical Security attribution requested; public/free does not establish an SPDX license. Latest scores retained; model estimates are not confirmation of exploitation. |
| [CISA advisory feed](https://www.cisa.gov/cybersecurity-advisories/all.xml), [ICS feed](https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml) | RSS XML; as issued; recent entries | Public supported feeds; conditional requests; no fixed rate allowance asserted | Government material with possible third-party rights. Metadata only; no full historical guarantee or CSAF product extraction. |
| [CERT/CC notes](https://www.kb.cert.org/vuls/), [Atom](https://www.kb.cert.org/vulfeed/) | Atom XML; as issued; recent notes | Public; conditional requests | [CMU/SEI terms](https://www.sei.cmu.edu/legal/); live tested, optional and disabled until redistribution reviewed. |
| [Red Hat security data](https://access.redhat.com/security/data), [RHSA RSS](https://security.access.redhat.com/data/metrics/rhsa.rss) | RSS XML; as issued; OS and container-related advisories | Public; conditional requests | CC-BY-4.0; attribute Red Hat and link original. Metadata only; no RPM/container-image matching. |
| [CWE downloads](https://cwe.mitre.org/data/downloads.html) | XML ZIP; versioned releases | Public download; validators; reject oversized ZIP entries | [CWE terms](https://cwe.mitre.org/about/termsofuse.html): reproduce MITRE copyright designation and license with copies. Weakness summaries retained. |
| [CAPEC downloads](https://capec.mitre.org/data/index.html) | XML; versioned releases | Public; conditional requests | [CAPEC terms](https://capec.mitre.org/about/termsofuse.html): reproduce MITRE copyright designation and license. Classification metadata only, no attack procedures/examples. |
| [ATT&CK STIX](https://github.com/mitre-attack/attack-stix-data) | STIX 2.1 JSON bundles; versioned releases | Public GitHub raw; validators | [MITRE license](https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt); reproduce copyright and license with distribution. Objects contain knowledge descriptions, not downloaded software. |

MITRE source data remains copyright The MITRE Corporation. Retain the exact
upstream license files and applicable copyright designation with any distributed
copies of CWE, CAPEC or ATT&CK. These datasets are held in ignored SQLite locally;
they are not part of the default curated Git export. Before publishing a full
database artifact, include those notices and review all configured source rights.
The repository has no authority to grant those rights itself.

GitHub/OSV derived normalized data is attributed to its original source in every
record and to the official database in `metadata/sources.json`. The normalization
is a transformation; upstream records remain separately available in SQLite.
CVSS, EPSS, KEV, advisory texts and references remain upstream assessments.

Other vendors, full CERT archive ingestion, CSAF/OVAL product matching, complete
OSV ecosystem dumps and image-specific container matching are optional future
integrations. Their absence must not be described as synchronized coverage.

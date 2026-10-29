# Data sources and original publisher attribution

Reviewed: **2026-10-29**. Only adapters present in `config/sources.json` and the
originating advisory databases actually used by the configured OSV integration
are listed. Implemented does not mean fully synchronized. CERT/CC is implemented
but disabled; disabled sources are not packaged in monthly releases.

Source data is not relicensed under the project Apache license. Original authors,
CNAs, vendors and advisory contributors retain their rights; record-level credits,
references and supplied notices remain part of the source evidence.
These summaries do not grant rights or replace the linked full terms.

## attack-enterprise

**Original publisher:** The MITRE Corporation and contributing ATT&CK Enterprise community.

**Official publisher URLs:** [https://www.mitre.org/](https://www.mitre.org/).

**Integration status:** Enabled adapter; coverage is limited to the configured scope.

**Exact dataset endpoints:**
- [https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json)

**License / terms:** MITRE ATT&CK Enterprise terms of use. [https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt](https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt).

**Attribution requirements:** Credit MITRE and contributors. Reproduce the applicable MITRE copyright designation, complete license and disclaimers with copies; preserve source markings and notices.

**THREAT-BASE modifications:** STIX bundle objects are stored separately with relationships, markings and original object fields retained; normalized summaries are added. No linked tools are downloaded.

**Redistribution restrictions:** Royalty-free use is conditional on preserving the required notices. Trademark and endorsement rights are not granted; the root project Apache license does not replace these terms.

**Last verification / review:** 2026-10-29.

## attack-ics

**Original publisher:** The MITRE Corporation and contributing ATT&CK ICS community.

**Official publisher URLs:** [https://www.mitre.org/](https://www.mitre.org/).

**Integration status:** Enabled adapter; coverage is limited to the configured scope.

**Exact dataset endpoints:**
- [https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json)

**License / terms:** MITRE ATT&CK ICS terms of use. [https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt](https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt).

**Attribution requirements:** Credit MITRE and contributors. Reproduce the applicable MITRE copyright designation, complete license and disclaimers with copies; preserve source markings and notices.

**THREAT-BASE modifications:** STIX bundle objects are stored separately with relationships, markings and original object fields retained; normalized summaries are added. No linked tools are downloaded.

**Redistribution restrictions:** Royalty-free use is conditional on preserving the required notices. Trademark and endorsement rights are not granted; the root project Apache license does not replace these terms.

**Last verification / review:** 2026-10-29.

## capec

**Original publisher:** The MITRE Corporation and contributing CAPEC community.

**Official publisher URLs:** [https://www.mitre.org/](https://www.mitre.org/).

**Integration status:** Enabled adapter; coverage is limited to the configured scope.

**Exact dataset endpoints:**
- [https://capec.mitre.org/data/xml/capec_latest.xml](https://capec.mitre.org/data/xml/capec_latest.xml)

**License / terms:** MITRE CAPEC terms of use. [https://capec.mitre.org/about/termsofuse.html](https://capec.mitre.org/about/termsofuse.html).

**Attribution requirements:** Credit MITRE and contributors. Reproduce the applicable MITRE copyright designation, complete license and disclaimers with copies; preserve source markings and notices.

**THREAT-BASE modifications:** Official XML is parsed to attack-pattern ID, name, description and status. Execution flows/examples are excluded; the stored source row is a metadata projection, not full original XML.

**Redistribution restrictions:** Royalty-free use is conditional on preserving the required notices. Trademark and endorsement rights are not granted; the root project Apache license does not replace these terms.

**Last verification / review:** 2026-10-29.

## cert-cc

**Original publisher:** CERT Coordination Center, Carnegie Mellon University Software Engineering Institute.

**Official publisher URLs:** [https://www.kb.cert.org/vuls/](https://www.kb.cert.org/vuls/), [https://www.sei.cmu.edu/](https://www.sei.cmu.edu/).

**Integration status:** Implemented and feed-tested; disabled pending rights review.

**Exact dataset endpoints:**
- [https://www.kb.cert.org/vulfeed/](https://www.kb.cert.org/vulfeed/)

**License / terms:** CMU/SEI terms; redistribution permission unresolved. [https://www.sei.cmu.edu/legal/](https://www.sei.cmu.edu/legal/).

**Attribution requirements:** Credit CERT/CC and Carnegie Mellon University; preserve source links and any supplied third-party notices.

**THREAT-BASE modifications:** Recent Atom entries are projected to advisory metadata and normalized records. No complete vulnerability-note archive is mirrored.

**Redistribution restrictions:** Adapter is implemented and feed-tested but disabled by default. Do not add mirrored content or include it in releases until redistribution permission is reviewed.

**Last verification / review:** 2026-10-29.

## cisa-advisories

**Original publisher:** Cybersecurity and Infrastructure Security Agency (CISA) and identified advisory contributors.

**Official publisher URLs:** [https://www.cisa.gov/](https://www.cisa.gov/).

**Integration status:** Enabled adapter; coverage is limited to the configured scope.

**Exact dataset endpoints:**
- [https://www.cisa.gov/cybersecurity-advisories/all.xml](https://www.cisa.gov/cybersecurity-advisories/all.xml)

**License / terms:** US government material plus applicable third-party terms. [https://www.cisa.gov/about/website-policies](https://www.cisa.gov/about/website-policies).

**Attribution requirements:** Credit CISA and identified vendor/advisory authors; retain original links and supplied notices.

**THREAT-BASE modifications:** Recent official RSS entries are projected to advisory metadata. Descriptions/references are retained; no full historical scraping, prose-based CVE matching or CSAF product matching is performed.

**Redistribution restrictions:** No blanket license is asserted for third-party content, logos or vendor text. The policy page denied automated access during review; verify intended redistribution against the official policies.

**Last verification / review:** 2026-10-29.

## cisa-ics

**Original publisher:** Cybersecurity and Infrastructure Security Agency (CISA) and identified advisory contributors.

**Official publisher URLs:** [https://www.cisa.gov/](https://www.cisa.gov/).

**Integration status:** Enabled adapter; coverage is limited to the configured scope.

**Exact dataset endpoints:**
- [https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml](https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml)

**License / terms:** US government material plus applicable third-party terms. [https://www.cisa.gov/about/website-policies](https://www.cisa.gov/about/website-policies).

**Attribution requirements:** Credit CISA and identified vendor/advisory authors; retain original links and supplied notices.

**THREAT-BASE modifications:** Recent official RSS entries are projected to advisory metadata. Descriptions/references are retained; no full historical scraping, prose-based CVE matching or CSAF product matching is performed.

**Redistribution restrictions:** No blanket license is asserted for third-party content, logos or vendor text. The policy page denied automated access during review; verify intended redistribution against the official policies.

**Last verification / review:** 2026-10-29.

## cisa-kev

**Original publisher:** Cybersecurity and Infrastructure Security Agency (CISA).

**Official publisher URLs:** [https://www.cisa.gov/](https://www.cisa.gov/).

**Integration status:** Enabled adapter; coverage is limited to the configured scope.

**Exact dataset endpoints:**
- [https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json](https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json)

**License / terms:** CC0-1.0. [https://github.com/cisagov/kev-data/blob/main/LICENSE](https://github.com/cisagov/kev-data/blob/main/LICENSE).

**Attribution requirements:** Credit CISA; preserve the original repository license/disclaimer and third-party advisory references.

**THREAT-BASE modifications:** Selected source metadata is normalized to the common schema, indexed and partitioned for release. Raw JSON is preserved where supplied; no missing values or upstream assessments are invented. Catalog entries are accumulated; delisted entries remain historical observations.

**Redistribution restrictions:** CC0 applies to the catalog, not linked websites. No CISA logo, DHS seal or endorsement rights are granted.

**Last verification / review:** 2026-10-29.

## cve

**Original publisher:** CVE Program and contributing CVE Numbering Authorities (CNAs).

**Official publisher URLs:** [https://www.cve.org/](https://www.cve.org/).

**Integration status:** Enabled adapter; coverage is limited to the configured scope.

**Exact dataset endpoints:**
- [https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json)

**Record URL templates:**
- `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{prefix}xxx/{CVE-ID}.json`

**License / terms:** CVE Program terms of use; current text requires manual verification. [https://www.cve.org/Legal/TermsOfUse](https://www.cve.org/Legal/TermsOfUse).

**Attribution requirements:** Credit the CVE Program and original CNA/advisory authors; retain identifiers, references and any supplied notices.

**THREAT-BASE modifications:** Selected source metadata is normalized to the common schema, indexed and partitioned for release. Raw JSON is preserved where supplied; no missing values or upstream assessments are invented. Recent delta selection and exact-ID correlation; rejected/reserved/disputed evidence remains explicit.

**Redistribution restrictions:** No blanket SPDX license is asserted. The current legal page requires JavaScript and its text was not retrieved; verify intended redistribution against the official terms before expanding distribution.

**Last verification / review:** 2026-10-29.

## cwe

**Original publisher:** The MITRE Corporation and contributing CWE community.

**Official publisher URLs:** [https://www.mitre.org/](https://www.mitre.org/).

**Integration status:** Enabled adapter; coverage is limited to the configured scope.

**Exact dataset endpoints:**
- [https://cwe.mitre.org/data/xml/cwec_latest.xml.zip](https://cwe.mitre.org/data/xml/cwec_latest.xml.zip)

**License / terms:** MITRE CWE terms of use. [https://cwe.mitre.org/about/termsofuse.html](https://cwe.mitre.org/about/termsofuse.html).

**Attribution requirements:** Credit MITRE and contributors. Reproduce the applicable MITRE copyright designation, complete license and disclaimers with copies; preserve source markings and notices.

**THREAT-BASE modifications:** Official XML ZIP is parsed to weakness ID, name, description and status. Other XML content/examples are excluded; the stored source row is a metadata projection, not full original XML.

**Redistribution restrictions:** Royalty-free use is conditional on preserving the required notices. Trademark and endorsement rights are not granted; the root project Apache license does not replace these terms.

**Last verification / review:** 2026-10-29.

## first-epss

**Original publisher:** FIRST EPSS Special Interest Group and Empirical Security.

**Official publisher URLs:** [https://www.first.org/epss/](https://www.first.org/epss/), [https://www.empiricalsecurity.com/](https://www.empiricalsecurity.com/).

**Integration status:** Enabled adapter; coverage is limited to the configured scope.

**Exact dataset endpoints:**
- [https://epss.empiricalsecurity.com/epss_scores-current.csv.gz](https://epss.empiricalsecurity.com/epss_scores-current.csv.gz)

**License / terms:** Official EPSS usage guidance; no blanket SPDX license asserted. [https://www.first.org/epss/data](https://www.first.org/epss/data), [https://www.first.org/epss/faq](https://www.first.org/epss/faq).

**Attribution requirements:** Attribute FIRST EPSS and Empirical Security, and retain the score date. Attribution is requested in the official FAQ.

**THREAT-BASE modifications:** The daily gzip CSV is parsed into per-CVE records; score/percentile strings become numeric values and the header date is retained. Only the latest observed score is stored; the model header version is not currently stored.

**Redistribution restrictions:** Freely published does not establish an unrestricted redistribution license. Review current terms for the intended redistribution; do not present estimates as confirmed exploitation.

**Last verification / review:** 2026-10-29.

## github-advisories

**Original publisher:** GitHub Advisory Database and advisory contributors.

**Official publisher URLs:** [https://github.com/github/advisory-database](https://github.com/github/advisory-database).

**Integration status:** Enabled adapter; coverage is limited to the configured scope.

**Exact dataset endpoints:**
- [https://api.github.com/advisories](https://api.github.com/advisories)

**License / terms:** CC-BY-4.0. [https://github.com/github/advisory-database/blob/main/LICENSE.md](https://github.com/github/advisory-database/blob/main/LICENSE.md).

**Attribution requirements:** Attribute the original publisher and contributors, retain source and license links and existing notices, identify selection/normalization as modifications, and do not imply endorsement.

**THREAT-BASE modifications:** Selected source metadata is normalized to the common schema, indexed and partitioned for release. Raw JSON is preserved where supplied; no missing values or upstream assessments are invented. The REST integration selects reviewed non-malware advisories; package ranges and patch metadata are projected.

**Redistribution restrictions:** Redistribution must satisfy CC-BY-4.0 attribution and modification requirements. Linked vendor material remains subject to its own rights.

**Last verification / review:** 2026-10-29.

## nvd

**Original publisher:** National Institute of Standards and Technology (NIST).

**Official publisher URLs:** [https://www.nist.gov/](https://www.nist.gov/).

**Integration status:** Enabled adapter; coverage is limited to the configured scope.

**Exact dataset endpoints:**
- [https://services.nvd.nist.gov/rest/json/cves/2.0](https://services.nvd.nist.gov/rest/json/cves/2.0)

**License / terms:** NIST/NVD public-data terms; third-party rights may apply. [https://www.nist.gov/open/license](https://www.nist.gov/open/license), [https://nvd.nist.gov/developers/start-here](https://nvd.nist.gov/developers/start-here).

**Attribution requirements:** Credit NIST NVD and retain the required non-endorsement statement. Preserve CNA/vendor references and third-party notices.

**THREAT-BASE modifications:** Selected source metadata is normalized to the common schema, indexed and partitioned for release. Raw JSON is preserved where supplied; no missing values or upstream assessments are invented. Modification-window selection; separate CVSS assessments, CPEs and explicitly tagged exploit references are projected.

**Redistribution restrictions:** Do not claim NIST endorsement or assume referenced third-party works are unrestricted.

**Last verification / review:** 2026-10-29.

**Required notice:** This product uses the NVD API but is not endorsed or certified by the NVD.

## osv

**Original publisher:** OSV project / Google (aggregator); original publishers identified below.

**Official publisher URLs:** [https://osv.dev/](https://osv.dev/).

**Integration status:** Enabled adapter; coverage is limited to the configured scope.

**Exact dataset endpoints:**
- [https://api.osv.dev/v1/vulns](https://api.osv.dev/v1/vulns)
- [https://api.osv.dev/v1/query](https://api.osv.dev/v1/query)

**Record URL templates:**
- `https://api.osv.dev/v1/vulns/{id}`

**License / terms:** Per-origin terms; configured GHSA and PYSEC datasets use CC-BY-4.0. [https://google.github.io/osv.dev/data/](https://google.github.io/osv.dev/data/).

**Attribution requirements:** Attribute the original publisher and contributors, retain source and license links and existing notices, identify selection/normalization as modifications, and do not imply endorsement. Credit the originating database as well as OSV.

**THREAT-BASE modifications:** Selected source metadata is normalized to the common schema, indexed and partitioned for release. Raw JSON is preserved where supplied; no missing values or upstream assessments are invented. Only configured advisory IDs and package/version query results are fetched; verified aliases and package ranges are retained.

**Redistribution restrictions:** OSV is not one uniformly licensed dataset. Release support is restricted to reviewed GHSA/PYSEC origins; adding other origins requires a separate license/notice review.

**Last verification / review:** 2026-10-29.

### Original OSV data publisher: GitHub Advisory Database and advisory contributors

- Identifier family: `GHSA-`.
- Official publisher: [https://github.com/github/advisory-database](https://github.com/github/advisory-database).
- Original dataset: [https://github.com/github/advisory-database/tree/main/advisories](https://github.com/github/advisory-database/tree/main/advisories).
- License: [CC-BY-4.0](https://github.com/github/advisory-database/blob/main/LICENSE.md).
- Exact notice text: [https://raw.githubusercontent.com/github/advisory-database/main/LICENSE.md](https://raw.githubusercontent.com/github/advisory-database/main/LICENSE.md).
- Modifications: selected through OSV; source references, aliases and credits retained; normalized and partitioned.
- Redistribution: CC-BY-4.0 attribution, license links and identification of changes are required; linked vendor material has separate rights.

### Original OSV data publisher: Python Packaging Authority (PyPA), PyPI Advisory Database and contributors

- Identifier family: `PYSEC-`.
- Official publisher: [https://github.com/pypa/advisory-database](https://github.com/pypa/advisory-database).
- Original dataset: [https://github.com/pypa/advisory-database/tree/main/vulns](https://github.com/pypa/advisory-database/tree/main/vulns).
- License: [CC-BY-4.0](https://github.com/pypa/advisory-database/blob/main/LICENSE).
- Exact notice text: [https://raw.githubusercontent.com/pypa/advisory-database/main/LICENSE](https://raw.githubusercontent.com/pypa/advisory-database/main/LICENSE).
- Modifications: selected through OSV; source references, aliases and credits retained; normalized and partitioned.
- Redistribution: CC-BY-4.0 attribution, license links and identification of changes are required; linked vendor material has separate rights.

## redhat-advisories

**Original publisher:** Red Hat Product Security.

**Official publisher URLs:** [https://access.redhat.com/security/data](https://access.redhat.com/security/data).

**Integration status:** Enabled adapter; coverage is limited to the configured scope.

**Exact dataset endpoints:**
- [https://security.access.redhat.com/data/metrics/rhsa.rss](https://security.access.redhat.com/data/metrics/rhsa.rss)

**License / terms:** CC-BY-4.0 as stated on the Red Hat Security Data page. [https://access.redhat.com/security/data](https://access.redhat.com/security/data), [https://creativecommons.org/licenses/by/4.0/](https://creativecommons.org/licenses/by/4.0/).

**Attribution requirements:** Attribute the original publisher and contributors, retain source and license links and existing notices, identify selection/normalization as modifications, and do not imply endorsement. Attribute Red Hat and link the original security data.

**THREAT-BASE modifications:** Selected source metadata is normalized to the common schema, indexed and partitioned for release. Raw JSON is preserved where supplied; no missing values or upstream assessments are invented. Recent RHSA RSS entries are stored as advisory metadata; no RPM-range or image-inventory interpretation is added.

**Redistribution restrictions:** Retain Red Hat attribution and license information; distinguish changes and respect separate rights in referenced material.

**Last verification / review:** 2026-10-29.

## Notice preservation and release attribution

The root LICENSE and existing upstream notice documents are preserved. Ingested
source JSON is retained alongside normalized projections; XML classification
projections are identified explicitly above. New representations and risk rankings
are project transformations, not upstream endorsements.

Monthly release metadata records only the included sources, their original
publishers, official/dataset URLs, terms, attribution requirements, transformations
and restrictions. Notes credit those publishers directly. Raw upstream license
texts are copied without editing and their SHA-256 digests are recorded. OSV
archives include distinct GitHub and PyPA notices, rather than substituting one
publisher license for the other. Disabled sources are excluded.

CVE current legal-page text, CISA advisory-policy access and CERT/CC redistribution
remain review limitations. EPSS public availability is not described as an SPDX
license. Confirm unresolved rights before expanding redistribution; no new mirror
was fetched for this attribution update. Adding a new source or OSV origin requires
its own verified terms and notice support.

For formats, pacing and update mechanisms see [the technical audit](docs/SOURCES.md).

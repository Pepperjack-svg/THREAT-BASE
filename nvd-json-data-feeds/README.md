# NVD vulnerability records

Original publisher: National Institute of Standards and Technology, National
Vulnerability Database. This product is not endorsed or certified by NVD.

Records are organized as `CVE-<year>/<identifier-prefix>xx/CVE-*.json`.
The initial historical baseline was downloaded directly from NIST's 25 yearly
JSON 2.0 feeds (2002 through 2026; the 2002 feed also includes earlier CVEs),
verified against the published SHA-256 metadata, and split into individual records.
Each record retains the original NVD fields.

Daily automation uses the [FKIE CAD mirror](https://github.com/fkie-cad/nvd-json-data-feeds),
matching the directory organization of the reference CVE-DATABASE repository.
That community reconstruction can include fields different from the official feed.
Original compressed feeds remain locally under `archives/` and are excluded from Git.

Source: https://nvd.nist.gov/vuln/data-feeds
Terms and attribution: [DATA_SOURCES.md](../DATA_SOURCES.md).

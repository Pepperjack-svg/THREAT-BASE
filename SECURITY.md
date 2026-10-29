# Security policy

THREAT-BASE processes public metadata for authorized research and defensive use.
Upstream descriptions, identifiers, XML, archives and links are untrusted input.
Dataset content must not become executable code, shell commands or trusted policy.

## Reporting a vulnerability

If GitHub's private vulnerability reporting is enabled, use the repository's
**Security > Report a vulnerability** option. Availability is not assumed. If it
is unavailable, request a private reporting channel from a maintainer without
posting exploit details, credentials or private data in a public issue.

Include the affected commit, component, expected and observed behavior, impact,
and a minimal safe reproduction using synthetic data. Do not attach live malware,
exploit payloads, private databases, access tokens or customer information.
There is no guaranteed response deadline, bounty or security certification.

## Scope

Report flaws in this repository's ingestion, validation, storage, indexing,
reporting or automation. Vulnerabilities in upstream products should follow the
relevant vendor or advisory provider's disclosure process. Incorrect records should
identify their source and supporting evidence without asserting unverified coverage.

The project has no established supported-release matrix. Use the current default
branch, review fixes and source terms, and validate updates before operational use.
Passing tests does not replace a security review or prove that datasets are complete.

## Operating guidance

- Keep secrets in environment variables or approved GitHub Actions secrets; never
  put them in data exports, source configuration or development documentation.
- Keep source attribution, state and verified historical baselines. Do not bypass
  gap detection or replace known-good data with unvalidated responses.
- Inspect source-specific status and freshness. CVSS, EPSS, KEV and asset exposure
  describe different evidence; public exploit references do not prove active exploitation.
- The query interface opens SQLite read-only. Apply operating-system permissions
  to clients that also have independent filesystem or shell access.
- Do not scan external systems or execute exploits using this project without
  separate authorization. The repository itself performs metadata ingestion only.

Credential exposure requires revocation/rotation and a reviewed recovery plan.
Deleting a file or adding it to `.gitignore` does not remove earlier Git history.

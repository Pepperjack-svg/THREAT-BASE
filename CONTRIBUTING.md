# Contributing to THREAT-BASE

Contributions should improve reliable, attributable defensive security metadata.
Open a focused issue or pull request describing the problem, expected behavior,
affected sources and reproducible evidence. Keep changes small enough to review.

## Development setup

Use Python 3.12+ and Git. Runtime and tests use the standard library; no dependency
installation is required. Tests use synthetic fixtures and mocks, not live APIs.

```sh
python -m compileall -q scripts tests
python -m unittest discover -s tests -v
python scripts/validate.py
git diff --check
```

Run relevant CLI help commands and check Markdown links after changing entry points
or documentation. Include actual test outcomes and limitations in your pull request.
The monthly publisher is exercised from its workflow by the existing test suite.

## Source and data changes

- Use supported official endpoints; document authentication, rate limits, format,
  update behavior and known coverage limits.
- Verify rights and attribution in [DATA_SOURCES.md](DATA_SOURCES.md). Do not add
  mirrored material with unresolved redistribution rights.
- Preserve source records, stable identifiers, historical revisions, checkpoints
  and previously published vulnerability data.
- Keep missing values and unsupported version semantics explicit. Do not correlate
  records by description similarity or equate exploit links with exploitation.
- Add focused tests for parser boundaries, failed downloads, validation and recovery.
  Do not fetch or execute linked payloads or tools.
- Keep SQLite databases, raw archives, credentials and generated build output out
  of ordinary Git commits. Respect the existing export and repository budgets.

## Documentation and privacy

Public documentation should describe reproducible project behavior and supported
interfaces. Keep local development notes under ignored `docs/internal/`; verify
they are not tracked before staging. Gitignore does not remove prior commits or
make an already-exposed file private. Review `git diff --cached` before committing.

## Review and licensing

Submit only material you have the right to contribute under the project's existing
licensing scope. Preserve third-party notices and identify upstream or AI-assisted
provenance when relevant. Commit authorship alone does not prove ownership.
Do not add unsupported personal copyright statements.

Workflow publication, repository settings and protected-branch changes require
maintainer review. Do not bypass protections, force-push shared history or rewrite
historical records to resolve synchronization failures. Security reports follow
[SECURITY.md](SECURITY.md), rather than public exploit disclosure in an issue.

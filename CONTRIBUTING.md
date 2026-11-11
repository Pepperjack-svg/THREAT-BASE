# Contributing

Keep this repository focused on source-organized datasets and minimal GitHub Actions
automation. Preserve original identifiers, record fields, references and upstream notices.
Do not add an application framework, normalization pipeline or generated database.

Validate changes on Linux with Bash, Git and jq:

```sh
bash .github/scripts/validate.sh
```

Describe the source, intended coverage, actual validation and licensing implications.
Keep private notes, credentials, temporary downloads and large archives out of Git.
Do not delete historical records to make synchronization pass. Upstream scripts must
never be executed during imports. Do not force-push or replace existing release tags.
Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

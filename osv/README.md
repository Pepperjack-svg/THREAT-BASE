# OSV bulk data

Original publisher: [OSV / Google](https://osv.dev/) and the originating advisory databases.

The complete local export is `archives/all.zip`, downloaded from
https://storage.googleapis.com/osv-vulnerabilities/all.zip. It includes all exported
ecosystems and withdrawn records. The archive remains outside ordinary Git commits
because of its size and the separate terms of its originating datasets.

To download a fresh copy:

```sh
mkdir -p osv/archives
curl --fail --location --proto '=https' --proto-redir '=https' \
  https://storage.googleapis.com/osv-vulnerabilities/all.zip -o osv/archives/all.zip
unzip -t osv/archives/all.zip
```

Record-level source references and licenses remain applicable. See
[DATA_SOURCES.md](../DATA_SOURCES.md).

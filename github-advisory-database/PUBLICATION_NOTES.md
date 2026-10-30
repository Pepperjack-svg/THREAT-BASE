# Publication notes

The full upstream download contains 397,093 advisory JSON files. Three original
records remain available locally and in the downloaded archive but are excluded
from Git publication because their reproduction examples contain encoded private
keys or an unverified token:

- GHSA-ffqj-6fqr-9h24
- GHSA-5wf9-h793-w73c
- GHSA-xxh2-68g9-8jqr

Published records preserve their upstream fields. The scanner also recognizes
reviewed documentation examples, dummy credentials and bare key-header markers
through exact-file SHA-256 exceptions. Any change to those files requires review.
No credentials were tested against external services.

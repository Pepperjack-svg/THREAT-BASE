# Upstream history gaps

The official repository snapshot downloaded on 2026-10-29 contains 2,016 uniquely
dated production snapshots, covering 2021-04-14 through 2026-10-29. It also includes
18 separately named beta-score files. Production and beta scores remain distinct.

The following production dates have no dated file in that repository snapshot:

- 2021-04-22 through 2021-04-26
- 2021-06-07
- 2021-06-18
- 2022-07-14
- 2024-12-01

The official dated bulk endpoints were also unavailable for these dates. Sample
FIRST API queries for 2021-04-22, 2022-07-14 and 2024-12-01 returned HTTP 422.
Missing snapshots are recorded as gaps; adjacent days are not substituted.

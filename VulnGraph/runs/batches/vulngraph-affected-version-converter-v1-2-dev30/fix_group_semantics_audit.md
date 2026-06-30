# Fix Group Semantics Audit

- Multi-branch cases: 4
- Relation distribution: `{"branch_local_single": 41}`
- Unknown relation cases: none

Grouping uses Git ancestry, merge-base, containing refs, stable patch-id, and explicit series metadata. It does not use affected-version ground truth.

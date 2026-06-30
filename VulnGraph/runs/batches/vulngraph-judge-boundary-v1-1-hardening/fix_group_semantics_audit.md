# Fix Group Semantics Audit

## Audited sources

- `BaseDataSet_30.json`: outer `fixing_commits` lists define wrapper-owned fix sets.
- Root Cause/SZZ `candidate_inventory.json`: stable `git patch-id` defines patch families.
- Judge blind packets: candidate-to-fix and Root Cause bindings.
- Ground-truth affected versions were not used to infer groups.

## Dataset findings

- Cases: 30
- Cases with more than one outer fix set: 0
- Cases with multi-commit fix sets: 5
- Maximum commits in one fix set: 15

| CVE | fix commits | patch families | family member sizes | Applied semantics |
|---|---:|---:|---|---|
| CVE-2020-12284 | 3 | 1 | 3 | AND across families; OR within family |
| CVE-2020-13904 | 15 | 5 | 5+6+2+1+1 | AND across families; OR within family |
| CVE-2020-14212 | 2 | 1 | 2 | AND across families; OR within family |
| CVE-2020-11984 | 2 | 2 | 1+1 | AND across families; OR within family |
| CVE-2020-11993 | 2 | 2 | 1+1 | AND across families; OR within family |

## Semantics

1. Conjunctive fix series: distinct patch families inside one fix set must all be complete on a tag.
2. Equivalent fixes: commits sharing a stable patch family are alternatives; any reachable member completes that family.
3. Branch-local/backport fixes: a reachable equivalent member can complete the family on its branch even when another member is unreachable.
4. Unmapped commits: the wrapper creates a singleton family rather than guessing equivalence.
5. Multiple outer fix sets: separate IDs are preserved, but dev30 contains no such case. Alternative-set semantics remain unvalidated and are not claimed.

## Concrete checks

- CVE-2020-14212: two equivalent fixes, one patch family.
- CVE-2020-11984 and CVE-2020-11993: two fixes in two distinct families; both families are required.
- CVE-2020-12284: three equivalent fixes, one patch family.
- CVE-2020-13904: 15 fixes grouped into five families with member sizes 5, 6, 2, 1, 1.

No grouping rule was inferred from affected-version ground truth.

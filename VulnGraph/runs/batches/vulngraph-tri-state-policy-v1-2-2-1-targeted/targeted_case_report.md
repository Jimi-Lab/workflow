# v1.2.2.1 Targeted Tri-State Replay

- Unique cases: 5
- Unknown-included FP top-3: CVE-2020-14212, CVE-2020-11984, CVE-2020-11993
- CVE-2020-11993 overlaps the required list and top-3 list.

| CVE | Tags | Confirmed affected | Confirmed unaffected | Unknown |
|---|---:|---:|---:|---:|
| CVE-2020-11647 | 739 | 531 | 79 | 129 |
| CVE-2020-11993 | 215 | 32 | 18 | 165 |
| CVE-2020-27814 | 22 | 0 | 0 | 22 |
| CVE-2020-14212 | 388 | 1 | 53 | 334 |
| CVE-2020-11984 | 215 | 14 | 23 | 178 |

## State Sources

### CVE-2020-11647

- all_branch_contexts_unknown:branch_context_membership_unverified: 129
- at_least_one_branch_context_confirmed_affected: 531
- at_least_one_branch_context_confirmed_unaffected: 79

### CVE-2020-11993

- all_branch_contexts_unknown:branch_context_membership_unverified: 165
- at_least_one_branch_context_confirmed_affected: 32
- at_least_one_branch_context_confirmed_unaffected: 18

### CVE-2020-27814

- missing_frozen_tag_local_evidence: 22

### CVE-2020-14212

- all_branch_contexts_unknown:branch_context_membership_unverified: 310
- all_branch_contexts_unknown:branch_context_membership_unverified|weak_predicate_evidence: 24
- at_least_one_branch_context_confirmed_affected: 1
- at_least_one_branch_context_confirmed_unaffected: 53

### CVE-2020-11984

- all_branch_contexts_unknown:branch_context_membership_unverified: 178
- at_least_one_branch_context_confirmed_affected: 14
- at_least_one_branch_context_confirmed_unaffected: 23

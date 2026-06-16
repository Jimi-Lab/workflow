# Root Cause Contract Alignment Report

## Scope

This pass only aligns Root Cause Agent v2 output contract with the strict evidence gate. It does not run Judge Agent, BIC ranking, affected-version conversion, or 10/30-CVE experiments.

## Before

- Source: `runs\batches\root-cause-v2-native-pilot-3`
- Total taxonomy: `{'semantic_node_without_shared_observation': 2, 'missing_fix_commit_id': 2, 'missing_patch_hunk_id': 2, 'explanatory_anchor_in_required_refs': 1}`

| CVE | Status | Taxonomy | Gate errors |
| --- | --- | --- | --- |
| CVE-2020-24020 | rejected | `{'semantic_node_without_shared_observation': 2}` | `['references evidence-gate-rejected vulnerable_predicate_id: pred-vuln-missing-length-check', 'references evidence-gate-rejected fix_predicate_id: pred-fix-length-post-check', 'references evidence-gate-rejected guard_condition_id: guard-negative-length-reject']` |
| CVE-2022-3109 | rejected | `{'missing_fix_commit_id': 1, 'missing_patch_hunk_id': 1, 'explanatory_anchor_in_required_refs': 1}` | `['references evidence-gate-rejected anchor_id: ca-CVE-2022-3109-deref']` |
| CVE-2023-47342 | rejected | `{'missing_fix_commit_id': 1, 'missing_patch_hunk_id': 1}` | `['references evidence-gate-rejected vulnerable_predicate_id: vuln-pred:CVE-2023-47342:001', 'references evidence-gate-rejected guard_condition_id: guard:CVE-2023-47342:001', 'references evidence-gate-rejected negative_condition_id: neg:CVE-2023-47342:001']` |

## After Smoke

- Accepted / ingested_raw: 1/1
- Contract errors: 0
- Contract taxonomy: `{}`
- Evidence-backed hypotheses: 1
- Legacy adapter count: 0

## After Pilot

- Accepted / ingested_raw: 3/3
- Rejected: 0
- Contract errors: 0
- Contract taxonomy: `{}`
- Evidence-backed hypotheses: 3
- Invented ID cases: `[]`
- Legacy adapter count: 0

| CVE | Status | Contract OK | Contract Errors | Evidence-backed | Fix-set complete | Legacy |
| --- | --- | --- | ---: | ---: | --- | ---: |
| CVE-2020-24020 | ingested_raw | True | 0 | 1 | True | 0 |
| CVE-2022-3109 | ingested_raw | True | 0 | 1 | True | 0 |
| CVE-2023-47342 | ingested_raw | True | 0 | 1 | True | 0 |

## Decision

The contract failure class dropped from semantic/anchor binding errors to zero in the final 3-CVE pilot. The run satisfies the local gate for moving to a 10-CVE Root Cause semantic evaluation, with semantic correctness still requiring human review or a later verifier.

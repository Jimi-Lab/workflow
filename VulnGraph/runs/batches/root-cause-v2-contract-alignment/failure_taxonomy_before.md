# Root Cause Contract Failure Taxonomy Before

- Source run: `runs\batches\root-cause-v2-native-pilot-3`
- Total taxonomy: `{'semantic_node_without_shared_observation': 2, 'missing_fix_commit_id': 2, 'missing_patch_hunk_id': 2, 'explanatory_anchor_in_required_refs': 1}`

| CVE | Status | Taxonomy | Gate errors |
| --- | --- | --- | --- |
| CVE-2020-24020 | rejected | `{'semantic_node_without_shared_observation': 2}` | `['references evidence-gate-rejected vulnerable_predicate_id: pred-vuln-missing-length-check', 'references evidence-gate-rejected fix_predicate_id: pred-fix-length-post-check', 'references evidence-gate-rejected guard_condition_id: guard-negative-length-reject']` |
| CVE-2022-3109 | rejected | `{'missing_fix_commit_id': 1, 'missing_patch_hunk_id': 1, 'explanatory_anchor_in_required_refs': 1}` | `['references evidence-gate-rejected anchor_id: ca-CVE-2022-3109-deref']` |
| CVE-2023-47342 | rejected | `{'missing_fix_commit_id': 1, 'missing_patch_hunk_id': 1}` | `['references evidence-gate-rejected vulnerable_predicate_id: vuln-pred:CVE-2023-47342:001', 'references evidence-gate-rejected guard_condition_id: guard:CVE-2023-47342:001', 'references evidence-gate-rejected negative_condition_id: neg:CVE-2023-47342:001']` |

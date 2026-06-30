# VulnGraph History Root Boundary Minimal Contract Correction v1.1.1

本轮只处理 GitGraph-verified history/root boundary evidence，不调用模型，不运行 Judge，不运行 converter。

## CVE-2020-19667 Before / After

- Before: root/import commit was carried as an ordinary promoted history candidate, and invalid structural anchors such as `}` could dominate the evidence surface.
- After: packet rank 1 is a synthetic case-level `history_root_boundary` event, accepted only after GitGraph root and root-to-fix ancestry verification plus bounded source relevance checks.
- Boundary commit: `3ed852eea50f9d4cd633efb8c2b054b8e33c2530`
- Synthetic candidate: `history-boundary:CVE-2020-19667:root:3ed852eea50f`
- Invalid structural anchors downgraded: `2`
- GitGraph parent_count: `0`
- GitGraph is_repo_root: `True`
- path_exists_at_root: `True`
- path_exists_at_fix_parent: `True`
- source relevance at boundary: `vulnerability_relevant_code_present_at_root`
- vulnerable predicate state at root: `not_verified`
- fix predicate state at root: `not_verified`

## Stop Gates

- cve_2020_8231_target_in_topk: `True`
- cve_2020_13904_target_in_topk: `True`
- cve_2020_15466_target_in_topk: `True`
- cve_2022_0286_target_in_topk: `True`
- cve_2020_19667_detected_history_root_boundary: `True`
- cve_2020_19667_git_graph_parent_count_zero: `True`
- cve_2020_19667_git_graph_is_repo_root: `True`
- cve_2020_19667_root_to_fix_ancestry_true: `True`
- cve_2020_19667_path_exists_at_root: `True`
- cve_2020_19667_path_exists_at_fix_parent: `True`
- cve_2020_19667_relevant_code_present_at_root: `True`
- cve_2020_19667_predicates_not_claimed_verified: `True`
- blind_packet_contains_git_graph_evidence: `True`
- blind_packet_contains_source_state_evidence: `True`
- cve_2020_19667_has_synthetic_root_boundary_event: `True`
- cve_2020_19667_no_candidate_role_vulnerability_introduction: `True`
- root_snapshot_not_called_introduction: `True`
- cve_2020_19667_introduction_commit_not_verified: `True`
- cve_2020_19667_root_cause_binding_nonempty: `True`
- cve_2020_19667_vulnerable_predicate_binding_nonempty: `True`
- cve_2020_19667_fix_predicate_binding_nonempty: `False`
- invalid_structural_anchors_not_primary_evidence: `True`
- related_13aeafe_not_ordinary_introduction: `True`

## Future Converter Consumption

- `history_root_boundary` means vulnerability-relevant code is present at the earliest visible local Git history boundary; term/excerpt matches do not verify either predicate.
- `projection_hint.first_observed_vulnerable_boundary` is a censored history boundary fact, not a validated introduction event.
- Related parser-state commits remain secondary evidence and need separate Judge reasoning if used.

## Explicit Scope

- This is only a history-root boundary contract correction.
- This run does not validate BIC/VIC and does not output affected_versions.
- model_invocation_count: `0`
- judge_invocation_count: `0`
- converter_invocation_count: `0`

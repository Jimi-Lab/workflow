# VulnGraph History Root Boundary Evidence Hardening v1.1

本轮只处理 GitGraph-verified history/root boundary evidence，不调用模型，不运行 Judge，不运行 converter。

## CVE-2020-19667 Before / After

- Before: root/import commit was carried as an ordinary promoted history candidate, and invalid structural anchors such as `}` could dominate the evidence surface.
- After: packet rank 1 is a synthetic case-level `history_root_boundary` event, accepted only after GitGraph root verification and bounded source-state verification.
- Boundary commit: `3ed852eea50f9d4cd633efb8c2b054b8e33c2530`
- Synthetic candidate: `history-boundary:CVE-2020-19667:root:3ed852eea50f`
- Invalid structural anchors downgraded: `2`
- GitGraph parent_count: `0`
- GitGraph is_repo_root: `True`
- path_exists_at_root: `True`
- path_exists_at_fix_parent: `True`
- source state at boundary: `vulnerable_state_observed`

## Stop Gates

- cve_2020_8231_target_in_topk: `True`
- cve_2020_13904_target_in_topk: `True`
- cve_2020_15466_target_in_topk: `True`
- cve_2022_0286_target_in_topk: `True`
- cve_2020_19667_detected_history_root_boundary: `True`
- cve_2020_19667_git_graph_parent_count_zero: `True`
- cve_2020_19667_git_graph_is_repo_root: `True`
- cve_2020_19667_path_exists_at_root: `True`
- cve_2020_19667_path_exists_at_fix_parent: `True`
- blind_packet_contains_git_graph_evidence: `True`
- blind_packet_contains_source_state_evidence: `True`
- cve_2020_19667_has_synthetic_root_boundary_event: `True`
- cve_2020_19667_no_candidate_role_vulnerability_introduction: `True`
- root_snapshot_not_called_introduction: `True`
- invalid_structural_anchors_not_primary_evidence: `True`
- related_13aeafe_not_ordinary_introduction: `True`

## Future Converter Consumption

- `history_root_boundary` means the vulnerable state is already present at the earliest visible local Git history boundary.
- A future converter may use `projection_hint.activation_lower_bound=repo_root_commit` as an internal lower-bound hint, but it must not treat the root commit as a validated introduction event.
- Related parser-state commits remain secondary evidence and need separate Judge reasoning if used.

## Explicit Scope

- This run does not validate BIC/VIC and does not output affected_versions.
- model_invocation_count: `0`
- judge_invocation_count: `0`
- converter_invocation_count: `0`

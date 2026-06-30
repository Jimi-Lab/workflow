# VulnGraph V3 Semantic-Chain Gate dev30 Feasibility Replay

本轮只验证 candidate generation feasibility：没有调用 OpenCode/DeepSeek，没有运行 Judge，没有运行 affected-version converter。
V3 gate 规则沿用 dev13 ablation 的冻结实现，本报告只做 dev30 批处理和诊断统计。

## Summary

- cases total: `30`
- cases with candidates: `30`
- total V3 candidates: `178`
- candidate count p50/p90/max: `8.0` / `8` / `8`
- pre-truncation promoted p90/max: `30` / `57`
- truncated event count: `281`
- dev13 regression R@1/R@3/R@5: `0.4` / `0.8` / `1.0`

## Feasibility Gates

- processed_30_of_30: `True`
- no_backend_model_judge_converter_invocation: `True`
- production_inputs_only: `True`
- label_leakage_free: `True`
- forbidden_field_scan_clean: `True`
- dev13_recall_at_5_not_below_previous_v3: `True`
- cve_2020_15466_target_retained: `True`
- cve_2022_0286_target_retained: `True`
- cve_2020_19667_no_plain_intro: `True`
- post_truncation_max_le_8: `True`

## Answers

1. 当前 V3 是否泛化到 dev30：初步可行，30/30 processed 且 hard gates 通过。
2. V3 是否仍控制在 Judge 可处理范围：post-truncation max=`8`，top-k=`8`。
3. 最需要人工审计的 CVE：
   - CVE-2020-8169: score=71, reasons=truncated;trace_only_candidates;invalid_anchor_pressure;noise_path_pressure
   - CVE-2020-19667: score=61, reasons=unresolved;truncated;trace_only_candidates;invalid_anchor_pressure
   - CVE-2020-11647: score=60, reasons=truncated;trace_only_candidates;invalid_anchor_pressure
   - CVE-2020-13904: score=58, reasons=truncated;trace_only_candidates;invalid_anchor_pressure
   - CVE-2022-0286: score=38, reasons=truncated;trace_only_candidates
4. 最常见 gate/rejection reason：case_root_boundary_mode=14, follow_history_evidence_only=550, invalid_structural_anchor_penalty=72, log_l_semantic_region_evidence=7, root_or_import_boundary_source=32, test_doc_build_path_rejected=26, trace_only_follow_not_candidate=550
5. 是否可以进入 Top-k Judge Packet v1：可以进入输入包冻结阶段，但仍需人工重点审计高 priority case。

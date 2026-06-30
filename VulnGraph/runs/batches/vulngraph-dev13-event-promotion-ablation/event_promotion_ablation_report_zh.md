# VulnGraph dev13 Semantic Event Promotion Ablation

本轮验证 B+A：root-cause-guided semantic event-chain search + evidence-constrained promotion gate。
没有调用模型，没有运行 Judge，没有运行 affected-version converter。所有输出仍是 raw_history_event_candidate。

## Key Results

- V0 direct total candidates: 46
- V1 broad total candidates: 580
- V2 gate-only total candidates: 43
- V3 B+A total candidates: 92
- V3 Recall@5: 1.0
- V3 max candidates per CVE: 8

## Answers

1. V3 是否比 V0 找到更多正确 event：`True`。
2. V3 是否比 V1 显著减少噪声：`True`。
3. V2 是否证明 gate-only 不足以补 recall：`True`。
4. 剩余失败：[]
5. 下一步建议：V3 passes dev13 gates; run dev30 only after freezing this promotion contract.

## Hard Gates

- v3_total_candidates_le_100: `True`
- v3_per_cve_candidates_le_10: `True`
- v3_recall_at_5_ge_0_85: `True`
- cve_2020_15466_target_retained: `True`
- cve_2022_0286_target_retained: `True`
- cve_2020_15389_target_top5: `True`
- cve_2020_19667_no_plain_intro: `True`
- production_candidate_label_leakage_free: `True`
- forbidden_field_scan_clean: `True`

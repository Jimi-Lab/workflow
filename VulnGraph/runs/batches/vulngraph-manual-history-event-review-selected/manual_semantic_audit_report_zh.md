# Manual Semantic Audit v1 汇总

本报告聚合各 CVE 子目录中已经冻结的 `manual_semantic_labels_v1.json`。
它不重新执行 Root Cause、SZZ、Judge 或版本转换，也不改写逐案例判断。

## 总体统计

- CVE cases：`13`
- candidate labels：`34`
- candidate 中被推荐为 introduction：`9`
- 存在推荐 boundary 的 cases：`10/13`
- source lane：`fallback=12`，`strong=17`，`unknown=5`

## Case 结论

| CVE | Repo | Candidates | Recommended boundary | Case verdict |
|---|---|---:|---|---|
| [CVE-2020-11647](CVE-2020-11647/manual_semantic_audit_v1_zh.md) | wireshark | 3 | none | `candidate_recall_failure` |
| [CVE-2020-11984](CVE-2020-11984/manual_semantic_audit_v1_zh.md) | httpd | 3 | `da54e90ddaa01c02a68fda8dc08004c97cb4aa2b`<br>`99c59e098103ccf13b833281ec08493e042dfee0` | `strong_pool_contains_branch_specific_introductions` |
| [CVE-2020-12284](CVE-2020-12284/manual_semantic_audit_v1_zh.md) | FFmpeg | 1 | `525de2000b018c659c5dd472610305cb2ffb9edc` | `correct_introduction_commit_reached_by_invalid_structural_anchor` |
| [CVE-2020-13904](CVE-2020-13904/manual_semantic_audit_v1_zh.md) | FFmpeg | 5 | `6cc7f1398257d4ffa89f79d52f10b2cabd9ad232` | `noisy_fallback_pool_contains_high_confidence_introduction` |
| [CVE-2020-15389](CVE-2020-15389/manual_semantic_audit_v1_zh.md) | openjpeg | 3 | `27e255fa75b7b9e989de3ec379c9de2b7462983b` | `strong_pool_contains_primary_and_secondary_resource_lifetime_introductions` |
| [CVE-2020-15466](CVE-2020-15466/manual_semantic_audit_v1_zh.md) | wireshark | 2 | `1e630b42e1f0573ca549643952017da315e695a0` | `candidate_pool_misses_true_loop_progress_introduction_event` |
| [CVE-2020-19667](CVE-2020-19667/manual_semantic_audit_v1_zh.md) | ImageMagick | 3 | none | `history_censored_at_repository_root_no_validated_introduction_candidate` |
| [CVE-2020-1971](CVE-2020-1971/manual_semantic_audit_v1_zh.md) | openssl | 2 | `c7235be6e36c4bef84594aa3b2f0561db84b63d8` | `fallback_pool_contains_primary_and_secondary_introduction` |
| [CVE-2020-25663](CVE-2020-25663/manual_semantic_audit_v1_zh.md) | ImageMagick | 2 | `8ed707a93fc4c7b3193dd562f07c4a1cc63cc19d` | `strong_pool_contains_high_confidence_statement_order_introduction` |
| [CVE-2020-8169](CVE-2020-8169/manual_semantic_audit_v1_zh.md) | curl | 4 | `46e164069d1a5230e4e64cbd2ff46c46cce056bb` | `noisy_fallback_pool_contains_high_confidence_introduction` |
| [CVE-2020-8231](CVE-2020-8231/manual_semantic_audit_v1_zh.md) | curl | 2 | `d021f2e8a0067fc769652f27afec9024c0d02b3d` | `candidate_pool_contains_high_confidence_introduction` |
| [CVE-2022-0171](CVE-2022-0171/manual_semantic_audit_v1_zh.md) | linux | 2 | none | `candidate_pool_misses_early_sev_feature_series_boundary` |
| [CVE-2022-0286](CVE-2022-0286/manual_semantic_audit_v1_zh.md) | linux | 2 | `18cb261afd7bf50134e5ccacc5ec91ea16efadd4` | `candidate_materialization_misses_explicit_fixes_introduction_commit` |

## Candidate 标签分布

| Label | Count |
|---|---:|
| `branch_local_vulnerability_introduction` | 1 |
| `history_boundary_censored` | 1 |
| `prerequisite` | 1 |
| `prerequisite_event_parser_extension` | 1 |
| `prerequisite_hazardous_guard` | 1 |
| `prerequisite_lock_optimization` | 1 |
| `prerequisite_mmu_notifier_refactor` | 1 |
| `prerequisite_or_refactor` | 1 |
| `prerequisite_or_unrelated` | 1 |
| `prerequisite_safe_cache_view_structure` | 1 |
| `refactor` | 1 |
| `refactor_api_rename` | 1 |
| `refactor_field_rename` | 1 |
| `refactor_formatting` | 1 |
| `refactor_or_lifecycle_event` | 1 |
| `refactor_or_prerequisite` | 1 |
| `refactor_rcu_access` | 1 |
| `refactor_type_alias` | 1 |
| `related_input_validation_hardening` | 1 |
| `secondary_vulnerability_introduction` | 2 |
| `unrelated_invalid_anchor` | 3 |
| `unrelated_or_broad_redirect_prerequisite` | 1 |
| `unrelated_refactor` | 1 |
| `vulnerability_introduction` | 8 |

## 关键失败类型

- Candidate materialization 已发现历史信号但遗漏正确事件：`CVE-2020-15466`、`CVE-2022-0286`
- 当前证据无法给出唯一 recommended boundary：`CVE-2020-11647`、`CVE-2020-19667`、`CVE-2022-0171`
- 其他 case 的详细 anchor、event-chain 和 commit 语义依据见各 CVE 中文审计文件。

## 使用边界

- 这些标签是 AI-assisted expert audit，不因文件名为 manual 就自动成为论文 gold。
- `recommended_introduction_commits` 可以作为工程回归门，但不等同于最终 affected versions。
- root/history-censored 与 feature-series case 不应被强制压成单一 BIC。
- 聚合 CSV 只包含输入 candidate；`missing_history_event` 等非候选事件保留在 JSON 和逐案例报告中。

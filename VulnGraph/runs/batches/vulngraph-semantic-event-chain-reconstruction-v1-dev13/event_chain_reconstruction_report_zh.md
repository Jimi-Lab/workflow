# VulnGraph Semantic Event-Chain Reconstruction v1

本轮只修复 Judge 之前的 candidate history event pool；没有调用模型，没有运行 Judge，没有运行版本预测。

- cases_total: 13
- input_candidate_count: 34
- output_candidate_count: 580
- promoted_event_count: 580
- promoted_from_log_l: 117
- promoted_from_pickaxe: 259
- promoted_from_fixes_trailer: 1
- invalid_anchor_downgraded_count: 178
- root_boundary_count: 22
- feature_series_boundary_count: 2
- regression_gate_pass_count: 13
- regression_gate_fail_count: 0
- Recall@1/3/5 over preliminary labels: 0.5 / 0.9 / 0.9

## Gate Summary

- `CVE-2020-11647` passed=`True` present=`` missing=`` reasons=`candidate_recall_failure_recorded`
- `CVE-2020-11984` passed=`True` present=`da54e90ddaa01c02a68fda8dc08004c97cb4aa2b 99c59e098103ccf13b833281ec08493e042dfee0` missing=`` reasons=``
- `CVE-2020-12284` passed=`True` present=`525de2000b018c659c5dd472610305cb2ffb9edc` missing=`` reasons=``
- `CVE-2020-13904` passed=`True` present=`6cc7f1398257d4ffa89f79d52f10b2cabd9ad232` missing=`` reasons=``
- `CVE-2020-15389` passed=`True` present=`27e255fa75b7b9e989de3ec379c9de2b7462983b` missing=`` reasons=``
- `CVE-2020-15466` passed=`True` present=`1e630b42e1f0573ca549643952017da315e695a0` missing=`` reasons=``
- `CVE-2020-19667` passed=`True` present=`` missing=`` reasons=``
- `CVE-2020-1971` passed=`True` present=`c7235be6e36c4bef84594aa3b2f0561db84b63d8` missing=`` reasons=``
- `CVE-2020-25663` passed=`True` present=`8ed707a93fc4c7b3193dd562f07c4a1cc63cc19d` missing=`` reasons=``
- `CVE-2020-8169` passed=`True` present=`46e164069d1a5230e4e64cbd2ff46c46cce056bb` missing=`` reasons=``
- `CVE-2020-8231` passed=`True` present=`d021f2e8a0067fc769652f27afec9024c0d02b3d` missing=`` reasons=``
- `CVE-2022-0171` passed=`True` present=`` missing=`` reasons=``
- `CVE-2022-0286` passed=`True` present=`18cb261afd7bf50134e5ccacc5ec91ea16efadd4` missing=`` reasons=``

所有新增事件的 lifecycle 仍是 raw_history_event_candidate。这些 13 个标签是 preliminary semantic labels，不是论文最终 gold label。

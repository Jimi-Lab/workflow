# Selection Algorithm Notes

## 输入

- dev30 Judge-readiness / anchor relocation artifacts
- History Event reconstruction artifacts
- BaseDataSet_30 中的 repo / CWE / fixing_commits 元数据
- 既有 3-CVE manual semantic labels 仅作为 taxonomy reference，不参与打标签

## 特征

- `strong_lane_ready`: strong lane 候选可用样本
- `fallback_only`: fallback-only 样本
- `mixed_strong_fallback`: strong + fallback 混合样本
- `blame_variant_disagreement`: blame variant 分歧样本
- `whitespace_sensitive`: whitespace-sensitive 样本
- `move_copy_sensitive`: move/copy-sensitive 样本
- `relocation_problem`: relocation ambiguous / not_found / path_missing 样本
- `add_only_or_weak_old_side`: add-only 或 weak old-side evidence 样本
- `merge_equivalent_or_multi_fix`: merge / equivalent-fix / multi-fix 样本
- `multi_branch_or_release_line_complex`: multi-branch / release-line complex 样本
- `clean_low_noise`: clean low-noise sanity 样本

## 贪心策略

1. 默认排除已审计的 CVE-2020-8231、CVE-2020-11647、CVE-2020-13904。
2. 每轮选择能带来最多新增 coverage type 的 CVE。
3. 对 blame/move-copy/relocation 这类稀有问题给轻微 bonus。
4. 对同 repo 过度集中做 penalty。
5. 如果 dev30 不能选满，才复用已审计 CVE，并在 manifest 中记录。

## 禁止事项

- 不调用模型。
- 不运行 Judge 或 converter。
- 不使用标签真值或版本标签构造规则。

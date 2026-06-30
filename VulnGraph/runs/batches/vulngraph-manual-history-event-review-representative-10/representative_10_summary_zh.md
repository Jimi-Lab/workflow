# representative 10 HistoryEvent 人工审计集

> 本目录是 deterministic artifact selection 结果；未调用模型，未运行 Judge/converter，未生成版本预测。

## 已审计参考 taxonomy

- `CVE-2020-8231` repo=`curl` verdict=`candidate_pool_contains_high_confidence_introduction` risk=`secondary candidate is a later lifecycle/refactor event and should not outrank the true introduction`
- `CVE-2020-11647` repo=`wireshark` verdict=`candidate_recall_failure` risk=`Current candidates stop at later refactor/prerequisite commits; the actual recursive parser introduction is absent from the pool.`
- `CVE-2020-13904` repo=`FFmpeg` verdict=`noisy_fallback_pool_contains_high_confidence_introduction` risk=`Fallback candidates are noisy and include invalid structural anchors; Judge must distinguish the URL-copy introduction event from broad HLS prerequisites.`

## 入选 CVE

- `CVE-2020-11984` repo=`httpd` candidates=3 strong=3 fallback=0 types=`add_only_or_weak_old_side;blame_variant_disagreement;merge_equivalent_or_multi_fix;multi_branch_or_release_line_complex;relocation_problem;strong_lane_ready;whitespace_sensitive`
- `CVE-2020-15466` repo=`wireshark` candidates=2 strong=0 fallback=2 types=`add_only_or_weak_old_side;blame_variant_disagreement;fallback_only;move_copy_sensitive;whitespace_sensitive`
- `CVE-2022-0286` repo=`linux` candidates=2 strong=2 fallback=0 types=`add_only_or_weak_old_side;blame_variant_disagreement;move_copy_sensitive;strong_lane_ready`
- `CVE-2020-25663` repo=`ImageMagick` candidates=2 strong=2 fallback=0 types=`blame_variant_disagreement;merge_equivalent_or_multi_fix;move_copy_sensitive;multi_branch_or_release_line_complex;relocation_problem;strong_lane_ready`
- `CVE-2022-0171` repo=`linux` candidates=2 strong=2 fallback=0 types=`add_only_or_weak_old_side;blame_variant_disagreement;move_copy_sensitive;strong_lane_ready`
- `CVE-2020-1971` repo=`openssl` candidates=2 strong=0 fallback=2 types=`add_only_or_weak_old_side;blame_variant_disagreement;fallback_only;whitespace_sensitive`
- `CVE-2020-19667` repo=`ImageMagick` candidates=3 strong=0 fallback=3 types=`add_only_or_weak_old_side;blame_variant_disagreement;fallback_only;merge_equivalent_or_multi_fix;multi_branch_or_release_line_complex;relocation_problem;whitespace_sensitive`
- `CVE-2020-15389` repo=`openjpeg` candidates=3 strong=3 fallback=0 types=`add_only_or_weak_old_side;blame_variant_disagreement;relocation_problem;strong_lane_ready;whitespace_sensitive`
- `CVE-2020-12284` repo=`FFmpeg` candidates=1 strong=0 fallback=1 types=`add_only_or_weak_old_side;fallback_only;merge_equivalent_or_multi_fix;multi_branch_or_release_line_complex`
- `CVE-2020-8169` repo=`curl` candidates=4 strong=0 fallback=4 types=`add_only_or_weak_old_side;fallback_only`

## Coverage Matrix

- strong lane 候选可用样本: `CVE-2020-11984`、`CVE-2022-0286`、`CVE-2020-25663`、`CVE-2022-0171`、`CVE-2020-15389`
- fallback-only 样本: `CVE-2020-15466`、`CVE-2020-1971`、`CVE-2020-19667`、`CVE-2020-12284`、`CVE-2020-8169`
- strong + fallback 混合样本: dev30 排除已审 CVE 后无可选样本
- blame variant 分歧样本: `CVE-2020-11984`、`CVE-2020-15466`、`CVE-2022-0286`、`CVE-2020-25663`、`CVE-2022-0171`、`CVE-2020-1971`、`CVE-2020-19667`、`CVE-2020-15389`
- whitespace-sensitive 样本: `CVE-2020-11984`、`CVE-2020-15466`、`CVE-2020-1971`、`CVE-2020-19667`、`CVE-2020-15389`
- move/copy-sensitive 样本: `CVE-2020-15466`、`CVE-2022-0286`、`CVE-2020-25663`、`CVE-2022-0171`
- relocation ambiguous / not_found / path_missing 样本: `CVE-2020-11984`、`CVE-2020-25663`、`CVE-2020-19667`、`CVE-2020-15389`
- add-only 或 weak old-side evidence 样本: `CVE-2020-11984`、`CVE-2020-15466`、`CVE-2022-0286`、`CVE-2022-0171`、`CVE-2020-1971`、`CVE-2020-19667`、`CVE-2020-15389`、`CVE-2020-12284`、`CVE-2020-8169`
- merge / equivalent-fix / multi-fix 样本: `CVE-2020-11984`、`CVE-2020-25663`、`CVE-2020-19667`、`CVE-2020-12284`
- multi-branch / release-line complex 样本: `CVE-2020-11984`、`CVE-2020-25663`、`CVE-2020-19667`、`CVE-2020-12284`
- clean low-noise sanity 样本: dev30 排除已审 CVE 后无可选样本

## Reference Reuse

- reused_count: 0
- reused_cves: `[]`

## 审计边界

- 不替人工填写 event_label。
- 不把候选历史事件解释为最终结论。
- 不使用标签真值写 selection 规则。
- fallback、ambiguous、not_found、path_missing 不隐藏，保留给人工判断。

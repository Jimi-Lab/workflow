# selected CVE HistoryEvent 人工审计总报告

> 本报告只汇总候选历史事件的人工审计材料；未调用模型，未运行 Judge/converter，未生成版本预测。

## 本次整理的 CVE

- `CVE-2020-8231` repo=`curl` candidates=2 strong=2 fallback=0 P0/P1/P2=2/0/0 ambiguous/not_found/path_missing=0/0/0 weak_evidence=否
- `CVE-2020-11647` repo=`wireshark` candidates=3 strong=3 fallback=0 P0/P1/P2=2/1/0 ambiguous/not_found/path_missing=1/2/0 weak_evidence=是
- `CVE-2020-13904` repo=`FFmpeg` candidates=5 strong=0 fallback=5 P0/P1/P2=5/0/0 ambiguous/not_found/path_missing=0/0/2 weak_evidence=是

## 最建议优先人工看的 candidate

1. `CVE-2020-13904` `pre-fix-line:0212df27dff8436a9635c5c2b67af43e482b17e54c8d835a002e7b64cf3f33f9` priority=`P0` lane=`fallback` relocation=`parent=path_missing/unavailable; candidate=path_missing/unavailable` flags=`anchor_diff_not_found;candidate_context_not_found;fallback_weakness;parent_context_not_found`
2. `CVE-2020-11647` `pre-fix-line:963caef4d423e31d032535d30db5320e09ef77a739c2ccdefe5855b706593487` priority=`P0` lane=`strong` relocation=`parent=not_found/unavailable; candidate=not_found/unavailable` flags=`blame_variant_disagreement;candidate_context_not_found;parent_context_not_found;whitespace_sensitive`
3. `CVE-2020-13904` `pre-fix-line:0002f876f690452bb4401c02c7e8701cc5f7eb36c88f5eccd0f2b611ddcb2838` priority=`P0` lane=`fallback` relocation=`parent=absent_by_event/diff_hunk_mapped; candidate=found/exact_hash` flags=`fallback_weakness;parent_context_not_found`
4. `CVE-2020-13904` `pre-fix-line:0008c6bffbde88d7382eb138aad9bb4d426b586bac7abdffae88b3c77895a821` priority=`P0` lane=`fallback` relocation=`parent=absent_by_event/diff_hunk_mapped; candidate=found/exact_hash` flags=`fallback_weakness;parent_context_not_found`
5. `CVE-2020-13904` `pre-fix-line:00df78cbf490f771e8e032a5947b9d72d89dec748867aff3cbf303b50c622abd` priority=`P0` lane=`fallback` relocation=`parent=absent_by_event/diff_hunk_mapped; candidate=found/exact_hash` flags=`fallback_weakness;parent_context_not_found`
6. `CVE-2020-13904` `pre-fix-line:02183be7a8cd9b3868eef1d3c1081242f980cf85a5befda2723d4557b9004400` priority=`P0` lane=`fallback` relocation=`parent=absent_by_event/diff_hunk_mapped; candidate=found/exact_hash` flags=`fallback_weakness;parent_context_not_found`
7. `CVE-2020-8231` `pre-fix-line:58fa8338ad3ea672acd04e48ca778e35489ce37c52567992e431acf7f5bd245a` priority=`P0` lane=`strong` relocation=`parent=absent_by_event/diff_hunk_mapped; candidate=found/exact_hash` flags=`parent_context_not_found`
8. `CVE-2020-11647` `pre-fix-line:621c3ba57093f96bb40f689abf99bfd08e12935484a28d4425302ddf543e6438` priority=`P0` lane=`strong` relocation=`parent=ambiguous/unavailable; candidate=found/blame_coordinate_verified` flags=`parent_context_not_found`
9. `CVE-2020-8231` `pre-fix-line:96e2823d262eba5fab1e424346eba3b286e2e1397a371c9d9f8e0cbfdd8a56b8` priority=`P0` lane=`strong` relocation=`parent=found/exact_hash; candidate=found/exact_hash` flags=`blame_variant_disagreement;log_L_disagreement;whitespace_sensitive`
10. `CVE-2020-11647` `pre-fix-line:1021db2626542faddcf7bd535202532487e758f6a0ae59c25681f489e97f5a88` priority=`P1` lane=`strong` relocation=`parent=found/normalized_unique; candidate=found/blame_coordinate_verified` flags=`none`

## 候选质量较弱的 CVE

- `CVE-2020-11647`、`CVE-2020-13904`

## 审计边界

- 不把 raw / judge-ready candidate 解释为最终引入提交。
- 不输出正式版本预测。
- 不使用 ground truth。
- fallback、ambiguous、not_found、path_missing 均保留给人工判断。

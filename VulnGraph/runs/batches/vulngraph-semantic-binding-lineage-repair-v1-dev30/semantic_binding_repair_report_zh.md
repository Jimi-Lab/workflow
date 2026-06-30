# VulnGraph Semantic Binding Lineage Repair v1

本轮只修复 wrapper/harness 层的 Root Cause semantic binding 血缘传递，不调用模型，不运行 Judge/converter，不输出版本预测。

## Source Selection Policy

- 优先级：`root-cause-v2-optimized-contract-30-deepseek` -> `root-cause-v2-optimized-contract-10` -> `root-cause-v2-semantic-baseline-10` -> fallback scan。
- 只有 `ingestion_result.status == ingested_raw` 的 artifact 进入 semantic binding index。
- 多个同优先级 accepted artifact 若语义 fingerprint 冲突，则该 CVE fail-closed，不静默选择。

## Coverage

- strong: candidates=74, fix before/after=0.622/0.676, root before/after=1.000/1.000, vuln before/after=1.000/1.000
- fallback: candidates=48, fix before/after=0.000/0.500, root before/after=0.000/0.500, vuln before/after=0.000/0.500
- total: candidates=251, fix before/after=0.359/0.590, root before/after=0.570/0.785, vuln before/after=0.570/0.785

## CVE-2020-19667

- candidate_count: `22`
- fix predicate coverage before/after: `0.0` / `1.0`
- missing reason distribution: `{}`

## Stop Boundary

- 输出仍是 repaired copies；旧 artifacts 未覆盖。
- 回填只使用已存在的 RootCauseHypothesis / VulnerablePredicate / FixPredicate ID。
- forbidden exact key scan 结果见 `forbidden_field_scan.json`。

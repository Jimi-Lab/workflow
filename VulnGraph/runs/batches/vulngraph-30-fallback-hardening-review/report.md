# VulnGraph 30-CVE Fallback Hardening Review

This review is an engineering diagnostic. It did not call OpenCode/DeepSeek, did not regenerate root causes or model-selected SZZ anchors, and did not implement Judge/BIC/affected-version inference.

All commit outputs remain `raw_candidate`. The oracle score is only a raw candidate-pool upper bound.

## Metric Delta

- old reported all-case release top1 F1: 0.8536
- corrected all-case release top1 F1: 0.5536
- accepted-only release top1 F1: 0.7909
- fallback-enhanced all-case release top1 F1: 0.7780
- fallback-only release top1 F1: 0.8414
- strong+fallback candidate-ready release top1 F1: 0.8048

## Coverage

- cases_total: 30
- candidate-ready before fallback: 21/30
- candidate-ready after fallback: 29/30
- strong_candidate_ready_count: 21
- fallback_candidate_ready_count: 8
- judge_input_ready_count: 29
- no_candidate_count: 1
- strong_raw_candidate_commit_count: 37
- fallback_raw_candidate_commit_count: 42
- candidate_generation_mode_distribution: `{'fallback_inventory_anchor': 8, 'strong_model_anchor': 21}`
- evidence_level_distribution: `{'fallback': 8, 'strong': 21}`

## Blocked Case Fallback Results

| CVE | status | candidate_count | mode | evidence | no_candidate_reason | blame_status |
|---|---|---:|---|---|---|---|
| CVE-2020-12284 | ingested_raw_candidate | 1 | fallback_inventory_anchor | fallback |  | success |
| CVE-2020-13904 | ingested_raw_candidate | 24 | fallback_inventory_anchor | fallback |  | success |
| CVE-2020-14212 | ingested_raw_candidate | 3 | fallback_inventory_anchor | fallback |  | success |
| CVE-2020-19667 | ingested_raw_candidate | 3 | fallback_inventory_anchor | fallback |  | success |
| CVE-2020-8169 | ingested_raw_candidate | 4 | fallback_inventory_anchor | fallback |  | success |
| CVE-2022-0433 | ingested_raw_candidate | 3 | fallback_inventory_anchor | fallback |  | success |
| CVE-2020-27814 | raw_candidate_censored | 0 | fallback_inventory_anchor | fallback | no_blameable_old_side | not_run |
| CVE-2020-1971 | ingested_raw_candidate | 2 | fallback_inventory_anchor | fallback |  | success |
| CVE-2020-15466 | ingested_raw_candidate | 2 | fallback_inventory_anchor | fallback |  | success |

## Risk Notes

- `strong_model_anchor` candidates preserve the accepted DeepSeek SZZ handoff path and are higher-quality inputs for the next Judge.
- `fallback_inventory_anchor` candidates are deterministic wrapper-owned recovery candidates for blocked cases. They improve candidate coverage but carry weaker semantic precision risk.
- The fallback lane is closer to a MAS-SZZ-style line-candidate generator than a complete BIC method: it supplies auditable parent-side lines and blame commits, but does not decide canonical BIC or affected versions.
- The remaining no-candidate case should enter Judge as censored/unknown unless a later root-cause or inventory fix supplies a blameable parent-side line.

## Next Judge Input Recommendation

- Pass `candidate_generation_mode`, `evidence_level`, `anchor_source`, line provenance, exclusion reasons, and raw candidate commits to Judge.
- Judge should prioritize strong candidates, use fallback candidates as recall-oriented alternatives, and keep branch-local/equivalent-introduction reasoning separate from version conversion.
- Do not treat oracle, fallback, or raw candidate commits as final BICs.

## No-Candidate Cases

- CVE-2020-27814: no_blameable_old_side

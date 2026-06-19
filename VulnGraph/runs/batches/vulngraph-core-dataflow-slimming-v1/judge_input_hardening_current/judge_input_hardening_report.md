# VulnGraph Judge Input Hardening v1

This is a deterministic engineering artifact. It does not call OpenCode/DeepSeek, does not regenerate Root Cause or SZZ anchors, and does not validate BICs or infer formal affected versions.

## Summary

- cases_total: 30
- blind_packet_cases: 30
- audit_packet_cases: 30
- judge_ready_cases_after_hardening: 30
- strong_ready_cases: 21
- fallback_ready_cases: 9
- no_candidate_cases: `[]`
- strong_raw_candidate_count: 37
- fallback_raw_candidate_count: 43
- max_fallback_candidates_before: 24
- max_fallback_candidates_after: 5
- cve_2020_27814_repaired: True
- blind forbidden scan ok: True
- model_invocation_count: 0
- lifecycle: raw_candidate

## Per-CVE Readiness

| CVE | status | candidates | strong | fallback | risks |
|---|---|---:|---:|---:|---|
| CVE-2020-12284 | judge_ready_fallback_only | 1 | 0 | 1 | add_only_semantic_anchor;broad_candidate_range;fallback_candidate;no_model_anchor;non_release_tag_noise;weak_root_cause_binding |
| CVE-2020-13904 | judge_ready_fallback_only | 5 | 0 | 5 | add_only_semantic_anchor;broad_candidate_range;fallback_candidate;no_model_anchor;non_release_tag_noise;weak_root_cause_binding |
| CVE-2020-14212 | judge_ready_fallback_only | 3 | 0 | 3 | fallback_candidate;no_model_anchor;non_release_tag_noise;weak_root_cause_binding |
| CVE-2020-10251 | judge_ready | 2 | 2 | 0 | release_line_overreach |
| CVE-2020-19667 | judge_ready_fallback_only | 3 | 0 | 3 | add_only_semantic_anchor;broad_candidate_range;fallback_candidate;no_model_anchor;weak_root_cause_binding |
| CVE-2020-25663 | judge_ready | 2 | 2 | 0 | add_only_semantic_anchor;release_line_overreach |
| CVE-2020-8169 | judge_ready_fallback_only | 4 | 0 | 4 | add_only_semantic_anchor;fallback_candidate;no_model_anchor;weak_root_cause_binding |
| CVE-2020-8177 | judge_ready | 3 | 3 | 0 | add_only_semantic_anchor |
| CVE-2020-8231 | judge_ready | 2 | 2 | 0 |  |
| CVE-2020-11984 | judge_ready | 3 | 3 | 0 | non_release_tag_noise |
| CVE-2020-11985 | judge_ready | 1 | 1 | 0 |  |
| CVE-2020-11993 | judge_ready | 1 | 1 | 0 | non_release_tag_noise |
| CVE-2022-0171 | judge_ready | 2 | 2 | 0 | add_only_semantic_anchor;non_release_tag_noise |
| CVE-2022-0185 | judge_ready | 1 | 1 | 0 | non_release_tag_noise |
| CVE-2022-0264 | judge_ready | 1 | 1 | 0 | non_release_tag_noise |
| CVE-2022-0286 | judge_ready | 2 | 2 | 0 | add_only_semantic_anchor;non_release_tag_noise |
| CVE-2022-0322 | judge_ready | 1 | 1 | 0 | non_release_tag_noise |
| CVE-2022-0433 | judge_ready_fallback_only | 3 | 0 | 3 | add_only_semantic_anchor;broad_candidate_range;fallback_candidate;no_model_anchor;non_release_tag_noise;weak_root_cause_binding |
| CVE-2020-15389 | judge_ready | 3 | 3 | 0 | non_release_tag_noise |
| CVE-2020-27814 | judge_ready_fallback_only | 1 | 0 | 1 | fallback_candidate;no_model_anchor;weak_root_cause_binding |
| CVE-2020-27823 | judge_ready | 1 | 1 | 0 |  |
| CVE-2020-1967 | judge_ready | 1 | 1 | 0 |  |
| CVE-2020-1971 | judge_ready_fallback_only | 2 | 0 | 2 | add_only_semantic_anchor;fallback_candidate;no_model_anchor;non_release_tag_noise;weak_root_cause_binding |
| CVE-2021-23840 | judge_ready | 2 | 2 | 0 | add_only_semantic_anchor;non_release_tag_noise;release_line_overreach |
| CVE-2020-10702 | judge_ready | 1 | 1 | 0 | non_release_tag_noise;release_line_overreach |
| CVE-2020-11869 | judge_ready | 2 | 2 | 0 | non_release_tag_noise;release_line_overreach |
| CVE-2020-11947 | judge_ready | 1 | 1 | 0 | non_release_tag_noise |
| CVE-2020-11647 | judge_ready | 3 | 3 | 0 | add_only_semantic_anchor;non_release_tag_noise;release_line_overreach |
| CVE-2020-13164 | judge_ready | 2 | 2 | 0 | non_release_tag_noise;release_line_overreach |
| CVE-2020-15466 | judge_ready_fallback_only | 2 | 0 | 2 | fallback_candidate;no_model_anchor;non_release_tag_noise;weak_root_cause_binding |

## CVE-2020-27814 Repair

- status: repaired_raw_candidate
- candidate_count: 1
- impossible_reason: 

All candidate commits remain `raw_candidate`; this report is a Judge-input readiness artifact, not a BIC or affected-version result.

# VulnGraph Judge Input Readiness

This is a frozen Judge input packet audit. It does not call a model, does not validate BICs, and does not infer formal affected-version results.

## Summary

- cases_total: 30
- judge-ready cases: 29/30
- candidate_ready_before_fallback: 21
- candidate_ready_after_fallback: 29
- strong_candidate_ready: 21
- fallback_candidate_ready: 8
- no_candidate_cases: `[{'cve_id': 'CVE-2020-27814', 'no_fallback_candidate_reason': 'no_blameable_old_side'}]`
- strong_raw_candidate_count: 37
- fallback_raw_candidate_count: 42
- avg_candidates_per_strong_case: 1.76
- avg_candidates_per_fallback_case: 5.25
- max_candidates_per_case: 24

## Judge Use Guidance

- fallback / weak evidence cases: `['CVE-2020-12284', 'CVE-2020-13904', 'CVE-2020-14212', 'CVE-2020-15466', 'CVE-2020-19667', 'CVE-2020-1971', 'CVE-2020-8169', 'CVE-2022-0433']`
- manual anchor review cases: `['CVE-2020-10251', 'CVE-2020-10702', 'CVE-2020-11647', 'CVE-2020-11869', 'CVE-2020-11947', 'CVE-2020-11984', 'CVE-2020-11985', 'CVE-2020-11993', 'CVE-2020-12284', 'CVE-2020-13164', 'CVE-2020-13904', 'CVE-2020-14212', 'CVE-2020-15389', 'CVE-2020-15466', 'CVE-2020-19667', 'CVE-2020-1967', 'CVE-2020-1971', 'CVE-2020-25663', 'CVE-2020-27823', 'CVE-2020-8169', 'CVE-2020-8177', 'CVE-2020-8231', 'CVE-2021-23840', 'CVE-2022-0171', 'CVE-2022-0185', 'CVE-2022-0264', 'CVE-2022-0286', 'CVE-2022-0322', 'CVE-2022-0433']`
- failure-analysis-only cases: `['CVE-2020-27814']`

## Main Error Sources

- fallback candidates improve coverage but can be broad candidate ranges or weakly bound to root-cause predicates.
- release conversion noise remains visible as release-line overreach and non-release tag noise diagnostics.
- no-candidate cases should stay out of Judge result metrics unless the upstream anchor inventory is repaired.

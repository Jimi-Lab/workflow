# VulnGraph Judge Agent v0 Full Stress Evaluation

This is an engineering stress run for evidence-backed raw candidate boundary ranking. It does not validate BICs and does not perform affected-version conversion.

- input_case_count_10: 10
- input_case_count_30: 30
- total_input_cases: 40
- unique_cve_count: 30
- duplicate_cve_count: 10
- duplicate_cves: ['CVE-2020-11869', 'CVE-2020-11984', 'CVE-2020-13164', 'CVE-2020-14212', 'CVE-2020-15389', 'CVE-2020-19667', 'CVE-2020-1967', 'CVE-2020-8231', 'CVE-2022-0171', 'CVE-2022-0286']
- provider/model: deepseek/deepseek-v4-pro
- model_invocation_count: 56
- parse_ok_count: 40
- contract_ok_count: 39
- backend_failed_count: 0
- empty_response_count: 0
- repair_retry_count: 16
- forbidden_violation_count: 0
- attacker_context_available_count: 0
- attacker_context_unavailable_count: 40
- attacker_unavailable_but_used_count: 0
- strong_candidate_count: 54
- fallback_candidate_count: 30
- ranked_count: 84
- excluded_count: 0
- uncertain_count: 35
- all_candidates_accounted_rate: 1.0
- prompt_byte_statistics: {'min': 3717, 'median': 7816.0, 'max': 15858, 'total': 326689}
- lifecycle: raw_candidate_judged

Per-CVE top candidate is reported only as `top1_raw_candidate_judgment`; it is not a final introduction commit.

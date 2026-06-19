# VulnGraph Judge Agent v0 Clean Smoke

Judge v0 ranks evidence-backed raw candidates only. It does not output BICs and does not perform affected-version conversion.

- cases_total: 3
- parse_ok_count: 3
- contract_ok_count: 3
- backend_failed_count: 0
- empty_message_count: 0
- forbidden_field_scan_ok: True
- attacker_context_available_count: 0
- attacker_context_unavailable_count: 3
- attacker_unavailable_but_used_count: 0
- lifecycle: raw_candidate_judged

| CVE | parse | contract | disposition | candidates | rankings |
|---|---|---:|---|---:|---|
| CVE-2020-1967 | fenced_json | True | ranked | 1 | `[{'candidate_id': 'pre-fix-line:e5ecd537cb332ded9cf6af2e2da76689c6d7230c05b896ee3dd7ad5d25ee50af', 'candidate_commit_sha': '604ba26560ca71bf8a1c127da96727b5b2b077e1', 'rank': 1, 'judgment': 'plausible_introduction_boundary', 'confidence': 'medium'}]` |
| CVE-2020-8231 | fenced_json | True | uncertain | 2 | `[{'candidate_id': 'pre-fix-line:96e2823d262eba5fab1e424346eba3b286e2e1397a371c9d9f8e0cbfdd8a56b8', 'candidate_commit_sha': '07cb27c98e92649e74a312faf976271fa7da609c', 'rank': 1, 'judgment': 'uncertain_boundary', 'confidence': 'low'}, {'candidate_id': 'pre-fix-line:58fa8338ad3ea672acd04e48ca778e35489ce37c52567992e431acf7f5bd245a', 'candidate_commit_sha': 'd021f2e8a0067fc769652f27afec9024c0d02b3d', 'rank': 2, 'judgment': 'uncertain_boundary', 'confidence': 'low'}]` |
| CVE-2020-11984 | fenced_json | True | ranked | 3 | `[{'candidate_id': 'pre-fix-line:b84ff9c1c671c0c3e4b8dc7d92e6a218a3c08161feddc92e0a8820193a2c77a1', 'candidate_commit_sha': '23394f444cc73d6b01af5a8109f79c156a26607c', 'rank': 1, 'judgment': 'plausible_introduction_boundary', 'confidence': 'high'}, {'candidate_id': 'pre-fix-line:99b806cf39616c1c0676142bd2bc96cd1d3cc1a99fbfe114fad9c4efd7a1973d', 'candidate_commit_sha': '99c59e098103ccf13b833281ec08493e042dfee0', 'rank': 2, 'judgment': 'plausible_introduction_boundary', 'confidence': 'medium'}, {'candidate_id': 'pre-fix-line:ee07dfbbcdcd44a10b6fc69641be54ba4a4b23bc3787b9390e7fff4211e06c42', 'candidate_commit_sha': 'da54e90ddaa01c02a68fda8dc08004c97cb4aa2b', 'rank': 3, 'judgment': 'uncertain_boundary', 'confidence': 'low'}]` |

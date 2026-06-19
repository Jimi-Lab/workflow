# SZZ Anchor Audit Fallback Artifact

This engineering artifact does not call a model and does not validate BICs or infer affected versions.
Strong cases preserve model-selected anchors; blocked cases use deterministic wrapper-owned fallback candidates.

- cases_total: 30
- strong_candidate_ready_count: 21
- fallback_candidate_ready_count: 8
- judge_input_ready_count: 29
- no_candidate_count: 1
- strong_raw_candidate_commit_count: 37
- fallback_raw_candidate_commit_count: 42
- candidate_generation_mode_distribution: `{'fallback_inventory_anchor': 9, 'strong_model_anchor': 21}`
- evidence_level_distribution: `{'fallback': 9, 'strong': 21}`

## Blocked Case Fallback Results

- CVE-2020-12284: status=ingested_raw_candidate; candidates=1; reason=
- CVE-2020-13904: status=ingested_raw_candidate; candidates=24; reason=
- CVE-2020-14212: status=ingested_raw_candidate; candidates=3; reason=
- CVE-2020-19667: status=ingested_raw_candidate; candidates=3; reason=
- CVE-2020-8169: status=ingested_raw_candidate; candidates=4; reason=
- CVE-2022-0433: status=ingested_raw_candidate; candidates=3; reason=
- CVE-2020-27814: status=raw_candidate_censored; candidates=0; reason=no_blameable_old_side
- CVE-2020-1971: status=ingested_raw_candidate; candidates=2; reason=
- CVE-2020-15466: status=ingested_raw_candidate; candidates=2; reason=

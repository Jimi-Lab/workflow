# VET Taxonomy Corpus

This corpus is a stratified case-study set for deriving VET archetypes from the VulnVersion dataset.
All archetypes in this report are heuristic seeds and must be reviewed before becoming Step2 rules.

## Summary

- total_cves: 20
- completed_cves: 20
- failed_cves: 0
- selected_cases: 12
- target_size: 12

## Selected Cases

| repo | CVE | patch_type | chunks | family | archetype_seed |
| --- | --- | --- | ---: | --- | --- |
| FFmpeg | CVE-2020-14212 | mixed | 46 | multi_commit | bounds_length_check |
| FFmpeg | CVE-2020-13904 | mixed | 30 | multi_commit | parser_state_or_protocol_invariant |
| FFmpeg | CVE-2020-20451 | add_only | 6 | multi_commit | unknown_requires_manual_review |
| FFmpeg | CVE-2020-12284 | add_only | 3 | multi_commit | bounds_length_check |
| FFmpeg | CVE-2020-20450 | mixed | 16 | multi_commit | null_lifetime_refcount |
| FFmpeg | CVE-2020-35964 | mixed | 15 | multi_commit | bounds_length_check |
| FFmpeg | CVE-2020-20453 | mixed | 14 | multi_commit | unknown_requires_manual_review |
| FFmpeg | CVE-2022-48434 | mixed | 14 | multi_commit | parser_state_or_protocol_invariant |
| FFmpeg | CVE-2020-24020 | mixed | 9 | single_commit | bounds_length_check |
| FFmpeg | CVE-2020-20446 | mixed | 8 | multi_commit | unknown_requires_manual_review |
| FFmpeg | CVE-2020-35965 | mixed | 8 | multi_commit | bounds_length_check |
| FFmpeg | CVE-2020-20448 | mixed | 7 | multi_commit | status_error_handling_or_logic_correction |

## Use

- Use `selected_dataset.json` for compact multi-stage case studies.
- Use `vet_archetype_seed.jsonl` as Step2 VET drafting input.
- Do not treat `vet_archetype_seed` as ground truth; it is a deterministic seed for manual/agent review.
# SZZ Anchor to Version Probe v2

This is an engineering diagnostic over the current SZZ anchor raw candidate pool. It does not validate BICs and does not implement a formal affected-version system.

Primary metrics use `release_tag_universe`. `diagnostic_all_tags` is retained only to measure non-release tag noise.

Oracle metrics are a raw candidate-pool upper bound, not a system result. All candidate commits remain `raw_candidate`.

## Summary

- cases_total: 10
- anchors_total: 35
- candidates_total: 23
- release top1 macro P/R/F1: 0.8473 / 1.0000 / 0.8849
- release topk macro P/R/F1: 0.8223 / 1.0000 / 0.8659
- release oracle macro P/R/F1: 0.9353 / 0.9563 / 0.9360
- diagnostic all-tags top1 F1: 0.6673
- diagnostic all-tags oracle F1: 0.6828
- oracle improvement over top1 F1: 0.0511
- top1 false-positive cases: `['CVE-2020-14212', 'CVE-2022-0171', 'CVE-2022-0286', 'CVE-2020-15389', 'CVE-2020-11869', 'CVE-2020-13164']`
- oracle false-positive cases: `['CVE-2020-14212', 'CVE-2022-0171', 'CVE-2022-0286', 'CVE-2020-15389', 'CVE-2020-11869', 'CVE-2020-13164']`
- any-candidate false-positive cases: `['CVE-2020-14212', 'CVE-2020-11984', 'CVE-2022-0171', 'CVE-2022-0286', 'CVE-2020-15389', 'CVE-2020-11869', 'CVE-2020-13164']`
- any-candidate non-release tag noise cases: `['CVE-2020-14212', 'CVE-2020-11984', 'CVE-2022-0171', 'CVE-2022-0286', 'CVE-2020-15389', 'CVE-2020-11869', 'CVE-2020-13164']`
- dominant non-release tag noise cases: `['CVE-2020-14212', 'CVE-2022-0171', 'CVE-2022-0286', 'CVE-2020-15389']`
- manual anchor review required cases: `['CVE-2020-14212', 'CVE-2020-19667', 'CVE-2020-8231', 'CVE-2020-11984', 'CVE-2022-0171', 'CVE-2022-0286', 'CVE-2020-15389', 'CVE-2020-1967', 'CVE-2020-11869', 'CVE-2020-13164']`
- dominant requires-manual-review cases: `['CVE-2020-19667', 'CVE-2020-8231', 'CVE-2020-11984', 'CVE-2020-1967']`

## Per-CVE

| CVE | Release Top1 F1 | Release TopK F1 | Release Oracle F1 | Oracle candidate | Error bucket |
|---|---:|---:|---:|---|---|
| CVE-2020-14212 | 1.0000 | 1.0000 | 1.0000 | `2558e62713ebc5f3ea22c1a28d8e9cf3249badaf` | non_release_tag_noise |
| CVE-2020-19667 | 1.0000 | 1.0000 | 1.0000 | `151b66dffc9e3c2e8c4f8cdaca37ff987ca0f497` | requires_manual_review |
| CVE-2020-8231 | 1.0000 | 1.0000 | 1.0000 | `d021f2e8a0067fc769652f27afec9024c0d02b3d` | requires_manual_review |
| CVE-2020-11984 | 1.0000 | 1.0000 | 1.0000 | `99c59e098103ccf13b833281ec08493e042dfee0` | requires_manual_review |
| CVE-2022-0171 | 0.2667 | 0.2667 | 0.7692 | `8931a454aea03bab21b3b8fcdc94f674eebd1c5d` | non_release_tag_noise |
| CVE-2022-0286 | 1.0000 | 1.0000 | 1.0000 | `bdfd2d1fa79acd03e18d1683419572f3682b39fd` | non_release_tag_noise |
| CVE-2020-15389 | 1.0000 | 1.0000 | 1.0000 | `055d429ae11ad98dfd3dc68d188ec538588d805c` | non_release_tag_noise |
| CVE-2020-1967 | 1.0000 | 1.0000 | 1.0000 | `604ba26560ca71bf8a1c127da96727b5b2b077e1` | requires_manual_review |
| CVE-2020-11869 | 0.8571 | 0.6667 | 0.8571 | `584acf34cb05f16e13a46d666196a7583d232616` | release_line_overreach |
| CVE-2020-13164 | 0.7257 | 0.7257 | 0.7338 | `c38eb2f027ace5a85007fb67084d2fa927467540` | release_line_overreach |

## Error Buckets

- candidate_pool_has_signal: 0 cases `[]`
- anchor_or_blame_likely_problem: 0 cases `[]`
- conversion_likely_problem: 0 cases `[]`
- dataset_or_tag_mapping_problem: 0 cases `[]`
- non_release_tag_noise: 4 cases `['CVE-2020-14212', 'CVE-2022-0171', 'CVE-2022-0286', 'CVE-2020-15389']`
- release_line_overreach: 2 cases `['CVE-2020-11869', 'CVE-2020-13164']`
- requires_manual_review: 4 cases `['CVE-2020-19667', 'CVE-2020-8231', 'CVE-2020-11984', 'CVE-2020-1967']`

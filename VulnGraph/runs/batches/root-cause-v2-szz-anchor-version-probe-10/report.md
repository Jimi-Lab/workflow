# SZZ Anchor to Affected-Version Diagnostic Upper-Bound Probe

This stage measures the affected-version diagnostic upper bound of the current SZZ anchor/blame raw candidate pool. It is not a BIC Judge and not a formal affected-version system.

Oracle metrics use ground truth only to estimate candidate-pool potential. A high oracle score means the pool contains useful signal; it does not mean the system can select that candidate without a Judge. A low oracle score points first to anchor/blame review. Top1/topk are deterministic no-Judge heuristic baselines.

All commits remain `raw_candidate`; raw candidates must not be interpreted as validated BICs.

## Summary

- cases_total: 10
- anchors_total: 35
- candidates_total: 23
- top1 macro P/R/F1: 0.6057 / 1.0000 / 0.6673
- topk macro P/R/F1: 0.5944 / 1.0000 / 0.6567
- oracle macro P/R/F1: 0.6161 / 0.9563 / 0.6828
- oracle exact matches: 4
- dataset/tag mapping problem cases: `[]`
- branch/backport limit cases: `['CVE-2020-14212', 'CVE-2020-11984', 'CVE-2022-0171', 'CVE-2022-0286', 'CVE-2020-15389', 'CVE-2020-11869', 'CVE-2020-13164']`

## Per-CVE

| CVE | Top1 F1 | TopK F1 | Oracle F1 | Oracle candidate | Error bucket |
|---|---:|---:|---:|---|---|
| CVE-2020-14212 | 0.6667 | 0.6667 | 0.6667 | `2558e62713ebc5f3ea22c1a28d8e9cf3249badaf` | conversion_likely_problem |
| CVE-2020-19667 | 1.0000 | 1.0000 | 1.0000 | `151b66dffc9e3c2e8c4f8cdaca37ff987ca0f497` | requires_manual_review |
| CVE-2020-8231 | 1.0000 | 1.0000 | 1.0000 | `d021f2e8a0067fc769652f27afec9024c0d02b3d` | requires_manual_review |
| CVE-2020-11984 | 1.0000 | 0.9655 | 1.0000 | `99c59e098103ccf13b833281ec08493e042dfee0` | requires_manual_review |
| CVE-2022-0171 | 0.0354 | 0.0354 | 0.1887 | `8931a454aea03bab21b3b8fcdc94f674eebd1c5d` | anchor_or_blame_likely_problem |
| CVE-2022-0286 | 0.2041 | 0.2041 | 0.2041 | `bdfd2d1fa79acd03e18d1683419572f3682b39fd` | conversion_likely_problem |
| CVE-2020-15389 | 0.9412 | 0.9412 | 0.9412 | `055d429ae11ad98dfd3dc68d188ec538588d805c` | requires_manual_review |
| CVE-2020-1967 | 1.0000 | 1.0000 | 1.0000 | `604ba26560ca71bf8a1c127da96727b5b2b077e1` | requires_manual_review |
| CVE-2020-11869 | 0.2857 | 0.2143 | 0.2857 | `584acf34cb05f16e13a46d666196a7583d232616` | conversion_likely_problem |
| CVE-2020-13164 | 0.5399 | 0.5399 | 0.5419 | `c38eb2f027ace5a85007fb67084d2fa927467540` | conversion_likely_problem |

## Error Buckets

- candidate_pool_has_signal: 0 cases `[]`
- anchor_or_blame_likely_problem: 1 cases `['CVE-2022-0171']`
- conversion_likely_problem: 4 cases `['CVE-2020-14212', 'CVE-2022-0286', 'CVE-2020-11869', 'CVE-2020-13164']`
- dataset_or_tag_mapping_problem: 0 cases `[]`
- no_candidate_commits: 0 cases `[]`
- requires_manual_review: 5 cases `['CVE-2020-19667', 'CVE-2020-8231', 'CVE-2020-11984', 'CVE-2020-15389', 'CVE-2020-1967']`

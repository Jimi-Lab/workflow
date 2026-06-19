# SZZ Anchor to Version Probe v2

This is an engineering diagnostic over the current SZZ anchor raw candidate pool. It does not validate BICs and does not implement a formal affected-version system.

Primary metrics use `release_tag_universe`. `diagnostic_all_tags` is retained only to measure non-release tag noise.

Oracle metrics are a raw candidate-pool upper bound, not a system result. All candidate commits remain `raw_candidate`.

## Summary

- cases_total: 30
- anchors_total: 171
- candidates_total: 79
- release top1 macro P/R/F1: 0.8391 / 0.7934 / 0.7780
- release topk macro P/R/F1: 0.7861 / 0.8693 / 0.7846
- release oracle macro P/R/F1: 0.8546 / 0.8422 / 0.8243
- diagnostic all-tags top1 F1: 0.5371
- diagnostic all-tags oracle F1: 0.5763
- oracle improvement over top1 F1: 0.0463
- top1 false-positive cases: `['CVE-2020-12284', 'CVE-2020-13904', 'CVE-2020-14212', 'CVE-2020-10251', 'CVE-2020-11993', 'CVE-2022-0171', 'CVE-2022-0185', 'CVE-2022-0264', 'CVE-2022-0286', 'CVE-2022-0322', 'CVE-2022-0433', 'CVE-2020-15389', 'CVE-2020-1971', 'CVE-2020-10702', 'CVE-2020-11869', 'CVE-2020-11947', 'CVE-2020-11647', 'CVE-2020-13164', 'CVE-2020-15466']`
- oracle false-positive cases: `['CVE-2020-12284', 'CVE-2020-13904', 'CVE-2020-14212', 'CVE-2020-10251', 'CVE-2020-11993', 'CVE-2022-0171', 'CVE-2022-0185', 'CVE-2022-0264', 'CVE-2022-0286', 'CVE-2022-0322', 'CVE-2022-0433', 'CVE-2020-15389', 'CVE-2020-1971', 'CVE-2020-10702', 'CVE-2020-11869', 'CVE-2020-11947', 'CVE-2020-11647', 'CVE-2020-13164', 'CVE-2020-15466']`
- any-candidate false-positive cases: `['CVE-2020-12284', 'CVE-2020-13904', 'CVE-2020-14212', 'CVE-2020-10251', 'CVE-2020-25663', 'CVE-2020-11984', 'CVE-2020-11993', 'CVE-2022-0171', 'CVE-2022-0185', 'CVE-2022-0264', 'CVE-2022-0286', 'CVE-2022-0322', 'CVE-2022-0433', 'CVE-2020-15389', 'CVE-2020-1971', 'CVE-2021-23840', 'CVE-2020-10702', 'CVE-2020-11869', 'CVE-2020-11947', 'CVE-2020-11647', 'CVE-2020-13164', 'CVE-2020-15466']`
- any-candidate non-release tag noise cases: `['CVE-2020-12284', 'CVE-2020-13904', 'CVE-2020-14212', 'CVE-2020-11984', 'CVE-2020-11993', 'CVE-2022-0171', 'CVE-2022-0185', 'CVE-2022-0264', 'CVE-2022-0286', 'CVE-2022-0322', 'CVE-2022-0433', 'CVE-2020-15389', 'CVE-2020-1971', 'CVE-2021-23840', 'CVE-2020-10702', 'CVE-2020-11869', 'CVE-2020-11947', 'CVE-2020-11647', 'CVE-2020-13164', 'CVE-2020-15466']`
- dominant non-release tag noise cases: `['CVE-2020-12284', 'CVE-2020-13904', 'CVE-2020-14212', 'CVE-2022-0171', 'CVE-2022-0185', 'CVE-2022-0264', 'CVE-2022-0286', 'CVE-2022-0322', 'CVE-2022-0433', 'CVE-2020-15389', 'CVE-2020-11947']`
- manual anchor review required cases: `['CVE-2020-12284', 'CVE-2020-13904', 'CVE-2020-14212', 'CVE-2020-10251', 'CVE-2020-19667', 'CVE-2020-25663', 'CVE-2020-8169', 'CVE-2020-8177', 'CVE-2020-8231', 'CVE-2020-11984', 'CVE-2020-11985', 'CVE-2020-11993', 'CVE-2022-0171', 'CVE-2022-0185', 'CVE-2022-0264', 'CVE-2022-0286', 'CVE-2022-0322', 'CVE-2022-0433', 'CVE-2020-15389', 'CVE-2020-27823', 'CVE-2020-1967', 'CVE-2020-1971', 'CVE-2021-23840', 'CVE-2020-10702', 'CVE-2020-11869', 'CVE-2020-11947', 'CVE-2020-11647', 'CVE-2020-13164', 'CVE-2020-15466']`
- dominant requires-manual-review cases: `['CVE-2020-19667', 'CVE-2020-25663', 'CVE-2020-8169', 'CVE-2020-8177', 'CVE-2020-8231', 'CVE-2020-11984', 'CVE-2020-11985', 'CVE-2020-27823', 'CVE-2020-1967', 'CVE-2021-23840']`

## Per-CVE

| CVE | Release Top1 F1 | Release TopK F1 | Release Oracle F1 | Oracle candidate | Error bucket |
|---|---:|---:|---:|---|---|
| CVE-2020-12284 | 1.0000 | 1.0000 | 1.0000 | `525de2000b018c659c5dd472610305cb2ffb9edc` | non_release_tag_noise |
| CVE-2020-13904 | 1.0000 | 1.0000 | 1.0000 | `cd223e0b4e1371d12d6cbb36bb66afdc40fd6281` | non_release_tag_noise |
| CVE-2020-14212 | 1.0000 | 1.0000 | 1.0000 | `2558e62713ebc5f3ea22c1a28d8e9cf3249badaf` | non_release_tag_noise |
| CVE-2020-10251 | 0.8293 | 0.8293 | 0.8293 | `8c69a644b1a32dd032541d123d232003f05887f8` | release_line_overreach |
| CVE-2020-19667 | 0.3158 | 1.0000 | 1.0000 | `3ed852eea50f9d4cd633efb8c2b054b8e33c2530` | requires_manual_review |
| CVE-2020-25663 | 1.0000 | 0.1290 | 1.0000 | `8ed707a93fc4c7b3193dd562f07c4a1cc63cc19d` | requires_manual_review |
| CVE-2020-8169 | 1.0000 | 1.0000 | 1.0000 | `46e164069d1a5230e4e64cbd2ff46c46cce056bb` | requires_manual_review |
| CVE-2020-8177 | 0.3415 | 0.5376 | 0.5376 | `4dc8499494dc16bf336c1055f2ae4b78c709c87d` | requires_manual_review |
| CVE-2020-8231 | 1.0000 | 1.0000 | 1.0000 | `d021f2e8a0067fc769652f27afec9024c0d02b3d` | requires_manual_review |
| CVE-2020-11984 | 1.0000 | 1.0000 | 1.0000 | `99c59e098103ccf13b833281ec08493e042dfee0` | requires_manual_review |
| CVE-2020-11985 | 0.7937 | 0.7937 | 0.7937 | `f3f2abdb9eddec36f839ce870a32f6d6916fe49d` | requires_manual_review |
| CVE-2020-11993 | 0.0000 | 0.0000 | 0.0000 | `c671673db96e286e2321d5babf05c767cb76a1ef` | anchor_or_blame_likely_problem |
| CVE-2022-0171 | 0.7692 | 0.7692 | 0.7692 | `f922bd9bf33bd5a8c6694927f010f32127810fbf` | non_release_tag_noise |
| CVE-2022-0185 | 1.0000 | 1.0000 | 1.0000 | `3e1aeb00e6d132efc151dacc062b38269bc9eccc` | non_release_tag_noise |
| CVE-2022-0264 | 1.0000 | 1.0000 | 1.0000 | `37086bfdc737ea6f66bf68dcf16757004d68e1e1` | non_release_tag_noise |
| CVE-2022-0286 | 1.0000 | 1.0000 | 1.0000 | `bdfd2d1fa79acd03e18d1683419572f3682b39fd` | non_release_tag_noise |
| CVE-2022-0322 | 1.0000 | 1.0000 | 1.0000 | `cc16f00f6529aa2378f2b949a6f68e9dc6dec363` | non_release_tag_noise |
| CVE-2022-0433 | 1.0000 | 1.0000 | 1.0000 | `6fdc348006fe2c8f0765f6eecf2e3cbab06c60b5` | non_release_tag_noise |
| CVE-2020-15389 | 1.0000 | 1.0000 | 1.0000 | `055d429ae11ad98dfd3dc68d188ec538588d805c` | non_release_tag_noise |
| CVE-2020-27814 | 0.0000 | 0.0000 | 0.0000 | `` | anchor_or_blame_likely_problem |
| CVE-2020-27823 | 0.7500 | 0.7500 | 0.7500 | `563bd8499e63db976ca8358216138647593354bc` | requires_manual_review |
| CVE-2020-1967 | 1.0000 | 1.0000 | 1.0000 | `604ba26560ca71bf8a1c127da96727b5b2b077e1` | requires_manual_review |
| CVE-2020-1971 | 0.6960 | 0.6960 | 0.6960 | `c7235be6e36c4bef84594aa3b2f0561db84b63d8` | conversion_likely_problem |
| CVE-2021-23840 | 0.4000 | 0.2783 | 0.4000 | `fa75ee1aecda0da96216440aa4ea91d4a17e8244` | requires_manual_review |
| CVE-2020-10702 | 0.9091 | 0.9091 | 0.9091 | `990870b205ddfdba3fd3c1321e6083005ef59d1a` | release_line_overreach |
| CVE-2020-11869 | 0.6667 | 0.6667 | 0.8571 | `584acf34cb05f16e13a46d666196a7583d232616` | release_line_overreach |
| CVE-2020-11947 | 1.0000 | 1.0000 | 1.0000 | `983924532f61091fd90d1f2fafa4aa938c414dbb` | non_release_tag_noise |
| CVE-2020-11647 | 0.4229 | 0.7341 | 0.7341 | `809fb769b4b903c1f1e003dcd24e7ab1b15402e8` | release_line_overreach |
| CVE-2020-13164 | 0.7257 | 0.7257 | 0.7338 | `c38eb2f027ace5a85007fb67084d2fa927467540` | release_line_overreach |
| CVE-2020-15466 | 0.7198 | 0.7198 | 0.7198 | `babe895d3a0d16346c500e397661c3fc580ee7e6` | conversion_likely_problem |

## Error Buckets

- candidate_pool_has_signal: 0 cases `[]`
- anchor_or_blame_likely_problem: 2 cases `['CVE-2020-11993', 'CVE-2020-27814']`
- conversion_likely_problem: 2 cases `['CVE-2020-1971', 'CVE-2020-15466']`
- dataset_or_tag_mapping_problem: 0 cases `[]`
- non_release_tag_noise: 11 cases `['CVE-2020-12284', 'CVE-2020-13904', 'CVE-2020-14212', 'CVE-2022-0171', 'CVE-2022-0185', 'CVE-2022-0264', 'CVE-2022-0286', 'CVE-2022-0322', 'CVE-2022-0433', 'CVE-2020-15389', 'CVE-2020-11947']`
- release_line_overreach: 5 cases `['CVE-2020-10251', 'CVE-2020-10702', 'CVE-2020-11869', 'CVE-2020-11647', 'CVE-2020-13164']`
- requires_manual_review: 10 cases `['CVE-2020-19667', 'CVE-2020-25663', 'CVE-2020-8169', 'CVE-2020-8177', 'CVE-2020-8231', 'CVE-2020-11984', 'CVE-2020-11985', 'CVE-2020-27823', 'CVE-2020-1967', 'CVE-2021-23840']`

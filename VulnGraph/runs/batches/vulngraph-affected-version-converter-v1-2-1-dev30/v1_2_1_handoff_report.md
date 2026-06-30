# VulnGraph v1.2.1 Deterministic Semantic-State Reconstruction Handoff

## Scope

- Dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json`
- Boundary input: `runs\batches\vulngraph-judge-boundary-v1-2-dev30`
- Output: `runs\batches\vulngraph-affected-version-converter-v1-2-1-dev30`
- Model calls: `0`
- Neo4j calls: `0`
- 100-CVE validation: not run

## Stop Gates

| Gate | Result |
|---|---:|
| Fix universe coverage | `49/49` |
| Missing declared fixes | `0` |
| Unresolved declared fixes | `0` |
| Raw-top1 Exact | `15/30` |
| Raw-top1 micro F1 | `0.7048723897911834` |
| Targeted replay gate | passed |

## Targeted Replay

| CVE | Status | Affected Count | Note |
|---|---|---:|---|
| CVE-2020-11647 | `unknown_state` | 552 | hash recovery and semantic state replay completed |
| CVE-2020-11993 | `unknown_state` | 46 | two declared fixes represented; predicate state remains partially unknown |
| CVE-2020-27814 | `unresolved_boundary` | 0 | merge/content alias preserved; frozen Judge remained uncertain |

## Dev30 Metrics

| Metric | v1.2 | v1.2.1 | raw-top1 |
|---|---:|---:|---:|
| Exact | `10/30` | `11/30` | `15/30` |
| NMR | `0.4666666666666667` | `0.6333333333333333` | not primary |
| Micro Precision | `0.7462809917355372` | `0.6192893401015228` | `0.6624509376362844` |
| Micro Recall | `0.4476945959345563` | `0.6653445711452652` | `0.7530986613782846` |
| Micro F1 | `0.559652928416486` | `0.6414913957934989` | `0.7048723897911834` |
| TP / FP / FN | `903 / 307 / 1114` | `1342 / 825 / 675` | `1519 / 774 / 498` |

## Status Counts

- converted: `6`
- unknown_state: `20`
- unresolved_boundary: `4`
- blocked: `0`

## Engineering Changes Validated

- Bounded semantic verifier now uses `git cat-file --batch-check` before `git cat-file --batch`; oversized blobs are not read and become `unknown/blob_too_large`.
- Fix reachability now prefers `git tag --contains <sha>` through the runner cache, avoiding per tag `merge-base --is-ancestor` loops.
- CVE-2020-13904 no longer stalls on FFmpeg multi-fix reachability.

## Stop Decision

v1.2.1 improves over v1.2 but does not reach the raw-top1 gate:

- Required: `Exact >= 15/30` and `micro F1 >= 0.7048723897911834`
- Observed: `Exact = 11/30`, `micro F1 = 0.6414913957934989`

Per the v1.2.1 plan, the pipeline must stop here and must not proceed to 100-CVE validation.

## Remaining Blockers

- The dominant remaining failure mode is conservative `unknown_state`: `20/30` cases.
- Stage attribution reports `predicate_state_unknown` in 17 cases and unresolved Judge boundary in 4 cases.
- Semantic state recovery improved recall, but it still over-produces unknown/FP-heavy tag sets in large branch histories.
- Next fix should target predicate-state equivalence and branch-local fix completion precision, not model prompting or GT-derived rules.

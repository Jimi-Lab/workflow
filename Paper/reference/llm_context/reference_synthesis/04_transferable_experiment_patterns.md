# Transferable Experiment Patterns

## Main Evaluation

Use p01 as the main benchmark and baseline source:

- Dataset: p01 benchmark of CVE/project/fixing-patch/released-version cases.
- Baselines: tracing-based and matching-based baselines from p01.
- Metrics: CVE-level Accuracy, CVE-level No-Miss Ratio, version-level Precision/Recall/F1.
- Status: [NEEDS EXPERIMENT] for VulnVersion results; [NEEDS TABLE REPAIR] for exact p01 numbers.

## Robustness/Sensitivity

Recommended subsets:

- Patch type: add-only, delete-only, mixed. Sources: p01, p06, p09, p14.
- Modification scope: single-function, multi-function single-file, multi-function multi-file. Source: p01.
- Branch/release setting: single-branch vs multi-branch, line-family categories. Sources: p01, p32.
- Evidence availability: deleted-line available vs no deleted-line; fix-commit message available vs withheld. Sources: p04, p06, p25.
- LLM/model sensitivity: agent backend or model choice. Sources: p04, p20, p25, p33.

## Ablation

Minimum ablations to plan:

| Ablation | Motivation sources | Expected paper role |
| --- | --- | --- |
| Full VulnVersion | p01 | Main result |
| No Step1 patch-family filtering | p01, p05, p14 | Tests noisy-patch handling |
| Raw touched-code instead of Step2 VET | p06, p20, p33 | Tests root-cause evidence extraction |
| Simple global tag ordering instead of release-line planning | p32, p19 | Tests repository-aware version structure |
| Deterministic matching only, no agent verdict | p07, p13, p10 | Tests semantic judgment value |
| Agent without scoped evidence/context compression | p16, p25 | Tests cost and noise control |
| Different model/backend | p04, p20, p25, p33 | Tests model sensitivity |

## Cost and Efficiency

Report:

- Average time per CVE.
- Average input/output/total tokens per CVE.
- Average cost per CVE.
- Agent calls per CVE.
- Probe tags per CVE.
- Execution failure rate and timeout rate.

Sources:
- p16 and p25: tokens, turns/tool calls, cost, behavior analysis.
- p20 and p33: LLM resource tables.
- p02/p05/p07/p13: scalability and staged filtering.
- p32: manual workload when full automated verification is hard.

## Error Analysis

Recommended error buckets:

- Patch-family error.
- Root-cause evidence error.
- Release-line/version-tree planning error.
- Agent tag-verdict error.
- Static prefilter false positive.
- Static prefilter false negative.
- Timeout/runtime failure.
- Missing artifact or repository state.

Sources:
- p01: FP/FN root-cause analysis.
- p04/p06/p16/p25: commit-localization failures and agent errors.
- p07/p13: syntactic clone false positives/negatives.
- p11: noisy labels.
- p32: repatch/partial matching/manual verification.

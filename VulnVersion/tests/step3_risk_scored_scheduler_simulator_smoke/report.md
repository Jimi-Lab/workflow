# Step3 Risk-Scored Vuln Graph Simulator

Dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataOrder.json`.

This is a GT-oracle experiment. GT is used only for simulated probe verdicts and final metrics.

## Graph Model

- Layer 1: TDSC-style release-version graph: release tags, line/family groups, family-local neighbors, branch edges.
- Layer 2: Beyond-Blame-style evidence graph: fix reachability, touched files, patch tokens, hunk functions, fix/vulnerable token hits.
- Agent is not used in this simulator; selected probes are answered by GT oracle.

## Score Separability

- affected line avg score: `0.923`
- unaffected line avg score: `0.5107`
- affected line p10 score: `0.88`
- unaffected line p90 score: `0.92`

## Best Configs By Recall-Constrained Cost

| config | avg probes | p95 | exact CVEs | FN CVEs | version FN | recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| risk_h0.30_m0.20_s6 | 117.05 | 163.00 | 20/1128 | 0 | 0 | 1.000000 | 1.000000 |
| risk_h0.40_m0.20_s6 | 117.05 | 163.00 | 20/1128 | 0 | 0 | 1.000000 | 1.000000 |
| risk_h0.30_m0.20_s4 | 120.05 | 163.00 | 20/1128 | 0 | 0 | 1.000000 | 1.000000 |
| risk_h0.40_m0.20_s4 | 120.05 | 163.00 | 20/1128 | 0 | 0 | 1.000000 | 1.000000 |
| risk_h0.30_m0.10_s4 | 148.55 | 165.00 | 20/1128 | 0 | 0 | 1.000000 | 1.000000 |
| risk_h0.30_m0.10_s6 | 148.55 | 165.00 | 20/1128 | 0 | 0 | 1.000000 | 1.000000 |
| risk_h0.40_m0.10_s4 | 148.55 | 165.00 | 20/1128 | 0 | 0 | 1.000000 | 1.000000 |
| risk_h0.40_m0.10_s6 | 148.55 | 165.00 | 20/1128 | 0 | 0 | 1.000000 | 1.000000 |

## Current Control

- control avg probes: `123.3`, exact CVEs: `20/1128`, recall: `1.0`, F1: `1.0`.

## Interpretation Rule

- A lower-probe config is not eligible if it introduces unacceptable affected-line skips.
- Low-score lines are treated as deferred in planning experiments, not as proven NOT_AFFECTED.
- A config can enter production only after case-level FN review and small real-agent validation.

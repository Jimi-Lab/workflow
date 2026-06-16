# Step3 Risk-Scored Vuln Graph Simulator

Dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataOrder.json`.

This is a GT-oracle experiment. GT is used only for simulated probe verdicts and final metrics.

## Graph Model

- Layer 1: TDSC-style release-version graph: release tags, line/family groups, family-local neighbors, branch edges.
- Layer 2: Beyond-Blame-style evidence graph: fix reachability, touched files, patch tokens, hunk functions, fix/vulnerable token hits.
- Agent is not used in this simulator; selected probes are answered by GT oracle.

## Score Separability

- affected line avg score: `0.8074`
- unaffected line avg score: `0.5149`
- affected line p10 score: `0.62`
- unaffected line p90 score: `0.92`

## Best Configs By Recall-Constrained Cost

| config | avg probes | p95 | exact CVEs | FN CVEs | version FN | recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| risk_h0.50_m0.20_s0 | 59.46 | 116.00 | 1110/1128 | 10 | 53 | 0.999104 | 0.999450 |
| risk_h0.30_m0.20_s0 | 59.47 | 116.00 | 1110/1128 | 10 | 53 | 0.999104 | 0.999450 |
| risk_h0.40_m0.20_s0 | 59.47 | 116.00 | 1110/1128 | 10 | 53 | 0.999104 | 0.999450 |
| risk_h0.20_m0.20_s0 | 59.56 | 116.00 | 1110/1128 | 10 | 53 | 0.999104 | 0.999450 |
| risk_h0.50_m0.20_s6 | 65.61 | 121.00 | 1110/1128 | 10 | 53 | 0.999104 | 0.999450 |
| risk_h0.30_m0.20_s6 | 65.62 | 121.00 | 1110/1128 | 10 | 53 | 0.999104 | 0.999450 |
| risk_h0.40_m0.20_s6 | 65.62 | 121.00 | 1110/1128 | 10 | 53 | 0.999104 | 0.999450 |
| risk_h0.20_m0.20_s6 | 65.71 | 121.00 | 1110/1128 | 10 | 53 | 0.999104 | 0.999450 |
| risk_h0.30_m0.20_s4 | 67.33 | 122.00 | 1110/1128 | 10 | 53 | 0.999104 | 0.999450 |
| risk_h0.40_m0.20_s4 | 67.33 | 122.00 | 1110/1128 | 10 | 53 | 0.999104 | 0.999450 |

## Current Control

- control avg probes: `68.36`, exact CVEs: `1112/1128`, recall: `0.999848`, F1: `0.999822`.

## Interpretation Rule

- A lower-probe config is not eligible if it introduces unacceptable affected-line skips.
- Low-score lines are treated as deferred in planning experiments, not as proven NOT_AFFECTED.
- A config can enter production only after case-level FN review and small real-agent validation.

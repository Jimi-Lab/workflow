# VET Admission Gate Simulator Report

cases: 27

## Strategy Metrics

| strategy | cleared tags | true clear | wrong affected clear | clear precision | wrong cases |
| --- | ---: | ---: | ---: | ---: | ---: |
| `raw_agent_flags_any` | 891 | 521 | 370 | 0.584736 | 10 |
| `raw_fixed_token` | 593 | 237 | 356 | 0.399663 | 10 |
| `raw_absent_scope_or_vuln` | 349 | 335 | 14 | 0.959885 | 2 |
| `strict_fixed_token` | 106 | 74 | 32 | 0.698113 | 3 |
| `strict_fixed_token_and_vuln_absent` | 0 | 0 | 0 | 0.000000 | 0 |
| `strict_absent_scope_only` | 46 | 46 | 0 | 1.000000 | 0 |
| `strict_gate_any` | 152 | 120 | 32 | 0.789474 | 3 |
| `ultra_strict_gate_any` | 46 | 46 | 0 | 1.000000 | 0 |

## Gate Conclusion

- raw_agent_certificates_safe_for_hard_decision: False
- strict_gate_safe_on_p1b: False
- strict_gate_has_coverage: True

## Dominant Blockers

- `absent:negative_evidence_missing`: 12
- `absent:quality_uncertainty`: 12
- `absent:uncertainty_present`: 12
- `fixed:negative_evidence_missing`: 12
- `fixed:quality_uncertainty`: 12
- `fixed:uncertainty_present`: 12
- `absent:agent_did_not_allow_cert_absent`: 9
- `absent:line_risk_signals_missing`: 2
- `fixed:agent_did_not_allow_cert_fixed`: 2

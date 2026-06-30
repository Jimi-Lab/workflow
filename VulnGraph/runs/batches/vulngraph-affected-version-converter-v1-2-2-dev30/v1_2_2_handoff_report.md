# VulnGraph v1.2.2 Function-Scope Predicate/Fix-State Verification

This run is deterministic and made **0 model calls**. It does not use GT in converter input; GT is used only for offline paper metrics.

## Stop Gates

- fix universe coverage: 49/49
- raw-top1 reproduction: Exact 15/30, micro F1 0.7048723897911834
- v1.2.2 unknown_state: 3/30
- model_invocation_count: 0

## Metrics

| run | Exact | NMR | micro P | micro R | micro F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| v1.2 | 0.3333333333333333 | 0.4666666666666667 | 0.7462809917355372 | 0.4476945959345563 | 0.559652928416486 | 903 | 307 | 1114 |
| v1.2.1 | 0.36666666666666664 | 0.6333333333333333 | 0.6192893401015228 | 0.6653445711452652 | 0.6414913957934989 | 1342 | 825 | 675 |
| v1.2.2 | 0.03333333333333333 | 0.36666666666666664 | 0.2490527040992077 | 0.35845314823996033 | 0.2939024390243902 | 723 | 2180 | 1294 |
| raw-top1 diagnostic | 15/30 | n/a | 0.6624509376362844 | 0.7530986613782846 | 0.7048723897911834 | 1519 | 774 | 498 |

## Interpretation

v1.2.2 reduces pure unknown_state from 20/30 to 3/30, but its current deterministic metric policy includes many unknown versions as predicted affected. That creates 2180 FP and lowers micro F1 below v1.2.1 and raw-top1. Per the advancement gate, this blocks 100-CVE validation.

## Main Remaining Blockers

- unknown_included_by_policy dominates FP expansion.
- selected events frequently lack function_id/function_name, so function-scope verification cannot localize enough cases.
- unresolved Judge boundary remains for 4 cases.
- fix-state reachability is represented, but fix-predicate semantic verification is still shallow.

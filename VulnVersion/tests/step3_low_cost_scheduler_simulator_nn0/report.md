# Step3 Low-Cost Scheduler Simulator Report

Dataset: `DataSet/BaseDataOrder.json`.

This is a GT-oracle simulator. GT is used only to emulate selected probe verdicts and compute metrics.

## Evidence Table

| Method | Transferable idea | Probe-reduction help | Risk | Validation needed |
| --- | --- | --- | --- | --- |
| How-far-are-we tracing-based / V-SZZ | Git reachability, duplicate patch, temporal boundary | Use fix-containing tags as fixed-side evidence and segment boundaries | Hard fix filtering misses affected tags; VIC recovery is unstable | Already validated as soft evidence only; retested here in current baseline |
| How-far-are-we matching-based | Tag snapshot vulnerability existence matching | Keep agent verdict only on selected probes instead of all tags | Full matching scan is too expensive; exact signatures are brittle | Simulate selected probes, not full scan |
| TDSC | Version tree and boundary-first search | Prioritize family/line boundary and fix-transition lines | Patch presence is not sufficient, so boundary evidence cannot hard skip | Strategy C in this simulator |
| AgentSZZ / SZZ-Agent | git grep, git log -S/-G, file/function history, scoped tools | Patch-derived greppable tokens rank active lines before agent | Tokens can be generic, renamed, or absent in old tags | Strategy D in this simulator |
| VicDiff / differential patching patterns | Critical statement sequence instead of raw patch lines | Patch-semantic tokens and hunk functions become cheap risk signals | Statement-level criticality is approximate without full semantic engine | Strategy B in this simulator |
| CaVulner | tags_containing(VIC cluster) - tags_containing(fix cluster) | Batch reachability and duplicate evidence inspire segmentation | VulnVersion cannot assume reliable VIC seed on 1128 CVE | Do not use VIC as planning input in this simulator |
| Beyond Blame | Knowledge-graph candidate ranking over commit/file/function nodes | Use line/family graph plus evidence edges for staged expansion | Graph priors can skip isolated affected lines if made hard | Hybrid strategy and skipped-line dump |

## Strategy Summary

| Strategy | avg probes | p50 | p95 | exact CVEs | FN CVEs | FP CVEs | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| agentszz_greppable | 59.50 | 64.00 | 103.00 | 1105/1128 | 15 | 4 | 0.999797 | 0.997007 | 0.998400 |
| current_staged_nofix_stride3_file | 61.33 | 66.00 | 105.00 | 1107/1128 | 13 | 4 | 0.999797 | 0.997751 | 0.998773 |
| hybrid_low_cost | 60.49 | 65.00 | 105.00 | 1105/1128 | 15 | 4 | 0.999797 | 0.997007 | 0.998400 |
| patch_semantics_cheap | 59.59 | 64.00 | 103.00 | 1105/1128 | 15 | 4 | 0.999797 | 0.997007 | 0.998400 |
| tdsc_boundary_first | 38.76 | 32.00 | 80.00 | 1097/1128 | 23 | 4 | 0.999796 | 0.994031 | 0.996905 |

## Interpretation

- A strategy is not eligible for the production path unless its FN/FP case dump is acceptable.
- Lower avg probes alone is not sufficient; skipped affected lines are treated as first-class failures.
- `current_staged_nofix_stride3_file` remains the control strategy.


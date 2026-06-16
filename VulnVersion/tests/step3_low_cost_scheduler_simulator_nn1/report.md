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
| agentszz_greppable | 61.95 | 67.50 | 112.00 | 1110/1128 | 10 | 4 | 0.999797 | 0.999070 | 0.999433 |
| current_staged_nofix_stride3_file | 63.90 | 70.00 | 114.00 | 1112/1128 | 8 | 4 | 0.999797 | 0.999814 | 0.999806 |
| hybrid_low_cost | 63.00 | 69.00 | 112.00 | 1110/1128 | 10 | 4 | 0.999797 | 0.999070 | 0.999433 |
| patch_semantics_cheap | 62.04 | 68.00 | 112.00 | 1110/1128 | 10 | 4 | 0.999797 | 0.999070 | 0.999433 |
| tdsc_boundary_first | 40.60 | 35.00 | 86.00 | 1102/1128 | 18 | 4 | 0.999796 | 0.996094 | 0.997942 |

## Interpretation

- A strategy is not eligible for the production path unless its FN/FP case dump is acceptable.
- Lower avg probes alone is not sufficient; skipped affected lines are treated as first-class failures.
- `current_staged_nofix_stride3_file` remains the control strategy.


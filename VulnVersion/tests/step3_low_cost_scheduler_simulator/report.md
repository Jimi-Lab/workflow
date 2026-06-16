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
| agentszz_greppable | 66.26 | 72.00 | 120.00 | 1110/1128 | 10 | 4 | 0.999797 | 0.999104 | 0.999450 |
| current_staged_nofix_stride3_file | 68.36 | 75.50 | 123.00 | 1112/1128 | 8 | 4 | 0.999797 | 0.999848 | 0.999822 |
| hybrid_low_cost | 67.41 | 74.00 | 122.00 | 1110/1128 | 10 | 4 | 0.999797 | 0.999104 | 0.999450 |
| patch_semantics_cheap | 66.35 | 72.00 | 120.00 | 1110/1128 | 10 | 4 | 0.999797 | 0.999104 | 0.999450 |
| tdsc_boundary_first | 43.86 | 37.00 | 91.00 | 1102/1128 | 18 | 4 | 0.999796 | 0.996127 | 0.997959 |

## Interpretation

- A strategy is not eligible for the production path unless its FN/FP case dump is acceptable.
- Lower avg probes alone is not sufficient; skipped affected lines are treated as first-class failures.
- `current_staged_nofix_stride3_file` remains the control strategy.

## Parameter Sensitivity

Current strategy with `AA_SENTINEL_COUNT=1`, `FIXED_SEG_SENTINEL=1`, `expansion_radius=1`:

| NN sentinel | avg probes/CVE | p95 | exact CVEs | FN CVEs | version FN | recall | F1 | judgment |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 3 | 68.36 | 123 | 1112/1128 | 8 | 9 | 0.999848 | 0.999822 | safest current profile |
| 2 | 66.18 | 119 | 1113/1128 | 7 | 10 | 0.999831 | 0.999814 | small cost drop; candidate for real-agent check |
| 1 | 63.90 | 114 | 1112/1128 | 8 | 11 | 0.999814 | 0.999806 | moderate cost drop; minor recall loss |
| 0 | 61.33 | 105 | 1107/1128 | 13 | 133 | 0.997751 | 0.998773 | rejected negative result |

## Case-Level Findings

- `tdsc_boundary_first` reduces average probes to 43.86 but increases FN CVEs to 18 and version FN to 229. The largest misses are concentrated in OpenSSL affected-line skips, so this is not production-ready.
- `patch_semantics_cheap`, `agentszz_greppable`, and `hybrid_low_cost` reduce only 1-2 probes on average while introducing 44 additional version FN compared with the control.
- `NN_SENTINEL_COUNT=0` fails on middle-interval cases, especially httpd large intervals. Middle sentinels cannot be removed safely.
- Current evidence supports `NN=2/1` only as a parameter trade-off, not as a new algorithmic breakthrough.


# Root Cause v2 Optimized Contract 10-CVE Report

## Scope

This run optimizes Root Cause Agent v2 contract/prompt/linter behavior against the frozen 10-CVE semantic baseline. It does not run Judge, SZZ/BIC, or affected-version conversion. The frozen baseline directory was read only and was not overwritten.

## Changed Contract Behavior

- Canonical-only prompt fields: `hypothesis_id`, `anchor_id`, `predicate_id`, `anchor_ids`, `description`, `function`, `path`.
- CodeAnchor path is mandatory and must be copied from packet/evidence inventory.
- Function names require matching `function_id`; unresolved PatchHunk functions must omit both.
- VulnerablePredicate/FixPredicate require at least one `patch_diff` GitObservation; `patch_stat` and `file_history` are contextual only.
- Added non-gating taxonomy for function-hunk coverage and unsupported/broad consequence language.

## Frozen Baseline Comparison

| Metric | Frozen baseline | Optimized run |
| --- | ---: | ---: |
| schema acceptance | 8/10 | 10/10 |
| valid JSON | 9/10 | 10/10 |
| parse errors | 1/10 | 0/10 |
| structural rejections | 1/10 | 0/10 |
| evidence-backed hypotheses | 8 | 10 |
| accepted semantic correctness | 6/8 | pending manual labels |
| all-case correctness | 6/10 | pending manual labels |
| evidence link precision | 4/10 | pending manual labels |
| unsupported inference rate | 6/10 | pending manual labels |
| semantic multi-fix coverage | 1/2 | pending manual labels |

## Optimized Structural Summary

- real_opencode_invocation_count: 10
- ingested_raw_count: 10
- structurally_rejected_count: 0
- parse_error_count: 0
- backend_failed_count: 0
- valid_json_count: 10
- evidence_backed_hypothesis_count: 10
- lint_ingestion_parity_count: 10/10
- invented_id_cases: `[]`
- contract_taxonomy: `{'consequence_stated_as_root_cause': 6, 'overbroad_vulnerability_effect': 5, 'incomplete_function_hunk_coverage': 1, 'hypothesis_mentions_unanchored_function': 2, 'broad_anchor_coverage': 1}`
- total_duration_s: 290.501

## Per-CVE Optimized Status

| CVE | Status | JSON | Contract OK | Evidence-backed | Fix commits | Multi-fix mapping | Taxonomy |
| --- | --- | --- | --- | ---: | ---: | --- | --- |
| CVE-2020-14212 | ingested_raw | fenced_json | True | 1 | 2 | True | `{'consequence_stated_as_root_cause': 1, 'overbroad_vulnerability_effect': 1}` |
| CVE-2020-19667 | ingested_raw | fenced_json | True | 1 | 1 | None | `{'consequence_stated_as_root_cause': 1, 'overbroad_vulnerability_effect': 1}` |
| CVE-2020-8231 | ingested_raw | fenced_json | True | 1 | 1 | None | `{'consequence_stated_as_root_cause': 1}` |
| CVE-2020-11984 | ingested_raw | fenced_json | True | 1 | 2 | True | `{'consequence_stated_as_root_cause': 1, 'overbroad_vulnerability_effect': 1}` |
| CVE-2022-0171 | ingested_raw | fenced_json | True | 1 | 1 | None | `{'incomplete_function_hunk_coverage': 1, 'hypothesis_mentions_unanchored_function': 2, 'broad_anchor_coverage': 1}` |
| CVE-2022-0286 | ingested_raw | fenced_json | True | 1 | 1 | None | `{}` |
| CVE-2020-15389 | ingested_raw | fenced_json | True | 1 | 1 | None | `{}` |
| CVE-2020-1967 | ingested_raw | fenced_json | True | 1 | 1 | None | `{}` |
| CVE-2020-11869 | ingested_raw | fenced_json | True | 1 | 1 | None | `{'consequence_stated_as_root_cause': 1, 'overbroad_vulnerability_effect': 1}` |
| CVE-2020-13164 | ingested_raw | fenced_json | True | 1 | 1 | None | `{'consequence_stated_as_root_cause': 1, 'overbroad_vulnerability_effect': 1}` |

## Interpretation Boundary

The optimized run fixed the structural/schema failures observed in the frozen baseline: `CVE-2020-19667` is no longer structurally rejected and `CVE-2022-0171` no longer fails schema validation. However, semantic quality has not been re-labeled yet. The optimized `evaluation.csv` must be manually reviewed before claiming improvements in root-cause correctness, evidence precision, unsupported inference, or semantic multi-fix coverage.

## Artifacts

- Optimized summary: `summary.json`
- Optimized metrics placeholder: `metrics_summary.json`
- Optimized review packet: `compact_review_packet.json` / `compact_review_packet.md`
- Optimized evaluation sheet: `evaluation.csv`
- Frozen manual metrics: `E:\AI\Agent\workflow\VulnGraph\runs\batches\root-cause-v2-semantic-baseline-10\manual_metrics_summary.json`

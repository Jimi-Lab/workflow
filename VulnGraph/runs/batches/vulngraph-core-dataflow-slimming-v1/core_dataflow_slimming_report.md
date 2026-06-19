# VulnGraph Core Dataflow Slimming v1

This is a deterministic refactor/report artifact. It does not call OpenCode/DeepSeek, does not regenerate Root Cause or SZZ anchors, and does not implement Judge/BIC/formal affected-version conversion.

## Phase 0 Empirical Basis

- analyzed_cve_artifact_count: 40
- largest redundancy sources: full candidate inventories, pre-fix candidate inventories, full evidence traces, structural/ingestion audit payloads, and full release-tag lists in blind packets.
- fields safe to ref: wrapper-owned path/line/SHA/function/candidate facts, full tool outputs, full candidate inventories, full release tag lists, and audit diagnostics.
- fields retained in compact model view: CVE/CWE summary, fix commit summary, hunk semantic summary, old/new key lines, function IDs/names, observation IDs, candidate IDs, risk flags, and evidence/ref bindings.

## Size Results

| Surface | Before bytes | After bytes | Reduction |
|---|---:|---:|---:|
| Root Cause prompts | 5125784 | 2050724 | 0.600 |
| SZZ Anchor prompts | 1759329 | 1701420 | 0.033 |
| Judge blind packets | 331561 | 269737 | 0.186 |

## Ownership Contract

Wrapper-owned facts are no longer requested as model-generated facts: repo, fix/parent SHAs, patch family/hunk IDs, candidate IDs, path/line/hash/function IDs, observation IDs, blame results, and release tag universe. Model-owned judgments remain root cause interpretation, predicate decisions, anchor/candidate selection, rationale, and uncertainty.

## Safety Checks

GT diagnostics are counted by exact JSON key scan over compact model views and blind packets; plain prose/schema substrings are not counted as leakage.

- full_evidence_trace_in_prompt_before: 40
- full_evidence_trace_in_prompt_after: 0
- full_candidate_inventory_in_prompt_before: 37
- full_candidate_inventory_in_prompt_after: 0
- gt_diagnostics_in_model_input_before: 37
- gt_diagnostics_in_model_input_after: 0
- blind_packet_forbidden_scan_ok: True
- fallback_max_candidates_before: 5
- fallback_max_candidates_after: 5

## Precision Protection

- patch_family_coverage_preserved: True
- fix_commit_coverage_preserved: True
- judge_raw_candidate_ready_cases_after: 30
- CVE-2020-13904 blind candidates are capped by ranked top-k; audit packet keeps full provenance.
- CVE-2020-27814 candidate_ready: True via generic equivalent-fix materialization; lifecycle remains raw_candidate.

## Verification

- pytest: 199 passed
- compileall: exit_code_0

## Remaining Blockers Before Judge Agent

- Candidate commits are still raw candidates, not validated BICs.
- Fallback candidates need Judge-side semantic validation and risk-aware scoring.
- Release-tag projection remains diagnostic and must not be treated as formal affected-version conversion.
- Manual review is still needed for broad fallback/context anchors and release-line overreach cases.

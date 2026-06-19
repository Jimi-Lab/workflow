# Phase 0 Large Field Necessity Review

This analysis reads frozen 10-CVE and 30-CVE artifacts before source-code slimming. It classifies fields by use, not by size alone.

## Largest Artifact Files

| Artifact | Stage | CVE | File | Bytes |
|---|---|---|---|---:|
| rootcause30 | other |  | `graph_store/events.jsonl` | 12497235 |
| rootcause30 | other |  | `graph_store/nodes.jsonl` | 5228905 |
| szz30 | candidate_inventory | CVE-2020-13904 | `CVE-2020-13904/candidate_inventory.json` | 4969477 |
| szz10 | candidate_inventory | CVE-2020-13164 | `CVE-2020-13164/candidate_inventory.json` | 4263088 |
| szz10 | candidate_inventory | CVE-2020-13164 | `CVE-2020-13164/pre_fix_candidate_inventory.json` | 4263088 |
| szz30 | candidate_inventory | CVE-2020-13164 | `CVE-2020-13164/candidate_inventory.json` | 4263088 |
| szz30 | candidate_inventory | CVE-2020-13164 | `CVE-2020-13164/pre_fix_candidate_inventory.json` | 4263088 |
| rootcause30 | diagnostic_summary |  | `summary.json` | 4085136 |
| rootcause30 | other |  | `graph_store/edges.jsonl` | 3426418 |
| szz30 | candidate_inventory | CVE-2020-8177 | `CVE-2020-8177/candidate_inventory.json` | 2785880 |
| szz30 | candidate_inventory | CVE-2020-8177 | `CVE-2020-8177/pre_fix_candidate_inventory.json` | 2785880 |
| szz30 | candidate_inventory | CVE-2020-11647 | `CVE-2020-11647/candidate_inventory.json` | 2109262 |
| szz30 | candidate_inventory | CVE-2020-11647 | `CVE-2020-11647/pre_fix_candidate_inventory.json` | 2109262 |
| version30 | diagnostic_summary |  | `per_candidate_probe.json` | 1603013 |
| szz10 | candidate_inventory | CVE-2020-14212 | `CVE-2020-14212/candidate_inventory.json` | 1249581 |
| szz10 | candidate_inventory | CVE-2020-14212 | `CVE-2020-14212/pre_fix_candidate_inventory.json` | 1249581 |
| szz30 | candidate_inventory | CVE-2020-14212 | `CVE-2020-14212/candidate_inventory.json` | 1249581 |
| szz30 | candidate_inventory | CVE-2020-14212 | `CVE-2020-14212/pre_fix_candidate_inventory.json` | 1249581 |
| rootcause30 | prompt | CVE-2020-11993 | `CVE-2020-11993/prompt.txt` | 1137637 |
| szz30 | candidate_inventory | CVE-2020-11993 | `CVE-2020-11993/candidate_inventory.json` | 1096169 |

## Stage Size Totals

| Artifact | Stage | Files | Bytes |
|---|---|---:|---:|
| judge30 | blame_trace | 1 | 6447 |
| judge30 | candidate_commits | 1 | 3116 |
| judge30 | candidate_inventory | 1 | 4362 |
| judge30 | diagnostic_summary | 2 | 47020 |
| judge30 | ingestion | 1 | 359 |
| judge30 | other | 7 | 124611 |
| judge30 | packet | 61 | 2217941 |
| rootcause30 | contract_validation | 60 | 3297506 |
| rootcause30 | diagnostic_summary | 1 | 4085136 |
| rootcause30 | evidence_trace | 30 | 1859646 |
| rootcause30 | ingestion | 30 | 3658678 |
| rootcause30 | model_io | 59 | 480858 |
| rootcause30 | other | 38 | 21206852 |
| rootcause30 | packet | 30 | 2193993 |
| rootcause30 | prompt | 30 | 3902153 |
| szz10 | blame_trace | 10 | 148701 |
| szz10 | candidate_commits | 10 | 50288 |
| szz10 | candidate_inventory | 30 | 16802407 |
| szz10 | contract_validation | 10 | 83045 |
| szz10 | diagnostic_summary | 1 | 22667 |
| szz10 | ingestion | 10 | 17994 |
| szz10 | model_io | 40 | 161122 |
| szz10 | other | 46 | 182567 |
| szz10 | prompt | 10 | 573173 |
| szz30 | blame_trace | 30 | 823496 |
| szz30 | candidate_commits | 30 | 354351 |
| szz30 | candidate_inventory | 84 | 37461160 |
| szz30 | contract_validation | 29 | 116710 |
| szz30 | diagnostic_summary | 1 | 82447 |
| szz30 | ingestion | 30 | 46723 |
| szz30 | model_io | 106 | 339198 |
| szz30 | other | 127 | 951772 |
| szz30 | prompt | 27 | 1186156 |
| version10 | diagnostic_summary | 6 | 1089875 |
| version10 | other | 3 | 6756 |
| version30 | diagnostic_summary | 6 | 3353593 |
| version30 | other | 3 | 15340 |

## Answers Required by Plan

1. Largest repeated objects are `candidate_inventory` / `pre_fix_candidate_inventory`, root-cause `evidence_trace`, `structural_validation`, `ingestion_result`, and prompt files that embed these structures. SZZ candidate inventories are the largest single redundancy source.
2. Fields that model generally only needs by ID/ref include `candidate_id`, `patch_hunk_id`, `patch_family_id`, `fix_commit_id`, `observation_id`, `tool_output_ref`, line hashes, and provenance lists. Full path/line/SHA values are wrapper-owned and should be resolved by the wrapper.
3. Large but semantically necessary information should survive as compact summaries: CVE/CWE context, fix commit message, hunk semantic summary, key old/new code lines, function identity/name, candidate role and selection mode, risk/uncertainty flags, and predicate/root-cause binding refs.
4. GT, F1, precision/recall, overlap diagnostics, false-positive taxonomy, release conversion metrics, and manual-review diagnostics are audit-only and must not enter model input.
5. Wrapper-owned facts are repo, fix/parent SHAs, patch family/hunk IDs, candidate IDs, path/line/hash/function IDs, evidence observation IDs, blame results, and release tag universe. Model output should select or reason over IDs, not restate these facts.
6. Model-owned judgments are root-cause interpretation, vulnerable/fix predicate decisions, attacker trigger/exploit preconditions, anchor selection among candidate IDs, rationale, and uncertainty reasons. Later BIC likelihood remains an interface only.

## Field Classification Policy

- `keep_in_model_view`: compact semantic summaries needed by the model.
- `replace_with_ref`: large structured object preserved locally and referenced by artifact/evidence ID.
- `audit_only`: GT, metrics, overlap, and false-positive diagnostics.
- `wrapper_owned_not_model_output`: trusted facts resolved by wrapper, never trusted from model text.
- `deprecated_backward_compat`: accepted for old artifacts but excluded from model input when redundant.

## Exact Duplicate Files

- 1682e086de39: 8 files; examples: `['szz30:CVE-2020-12284/contract_lint.json', 'szz30:CVE-2020-13904/contract_lint.json', 'szz30:CVE-2020-14212/contract_lint.json', 'szz30:CVE-2020-15466/contract_lint.json']`
- 0813f02bb83a: 4 files; examples: `['szz10:CVE-2020-15389/candidate_inventory.json', 'szz10:CVE-2020-15389/pre_fix_candidate_inventory.json', 'szz30:CVE-2020-15389/candidate_inventory.json', 'szz30:CVE-2020-15389/pre_fix_candidate_inventory.json']`
- 7d05972cdb3b: 4 files; examples: `['szz10:CVE-2020-1967/candidate_inventory.json', 'szz10:CVE-2020-1967/pre_fix_candidate_inventory.json', 'szz30:CVE-2020-1967/candidate_inventory.json', 'szz30:CVE-2020-1967/pre_fix_candidate_inventory.json']`
- d778866c2539: 4 files; examples: `['szz10:CVE-2022-0286/candidate_inventory.json', 'szz10:CVE-2022-0286/pre_fix_candidate_inventory.json', 'szz30:CVE-2022-0286/candidate_inventory.json', 'szz30:CVE-2022-0286/pre_fix_candidate_inventory.json']`
- c9c0aa8a1d17: 3 files; examples: `['szz30:CVE-2020-12284/fallback_resolved_pre_fix_anchors.json', 'szz30:CVE-2020-12284/resolved_anchors.json', 'szz30:CVE-2020-12284/resolved_pre_fix_anchors.json']`
- 9d0e846eabdd: 3 files; examples: `['szz30:CVE-2020-12284/manual_anchor_review_template.csv', 'szz30:CVE-2020-15466/manual_anchor_review_template.csv', 'szz30:CVE-2022-0433/manual_anchor_review_template.csv']`
- 4dfdc458aa93: 3 files; examples: `['szz30:CVE-2020-13904/fallback_resolved_pre_fix_anchors.json', 'szz30:CVE-2020-13904/resolved_anchors.json', 'szz30:CVE-2020-13904/resolved_pre_fix_anchors.json']`
- c609ad040fa7: 3 files; examples: `['szz30:CVE-2020-14212/fallback_resolved_pre_fix_anchors.json', 'szz30:CVE-2020-14212/resolved_anchors.json', 'szz30:CVE-2020-14212/resolved_pre_fix_anchors.json']`
- c74aa854ff0a: 3 files; examples: `['szz30:CVE-2020-15466/fallback_resolved_pre_fix_anchors.json', 'szz30:CVE-2020-15466/resolved_anchors.json', 'szz30:CVE-2020-15466/resolved_pre_fix_anchors.json']`
- 443d04f33388: 3 files; examples: `['szz30:CVE-2020-19667/fallback_resolved_pre_fix_anchors.json', 'szz30:CVE-2020-19667/resolved_anchors.json', 'szz30:CVE-2020-19667/resolved_pre_fix_anchors.json']`

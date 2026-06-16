# 30-CVE SZZ Anchor Audit Engineering Final

This is a deterministic consolidation artifact. No OpenCode/DeepSeek call was made while creating this final directory.

## Scope

- Source Root Cause run: `runs\batches\root-cause-v2-optimized-contract-30-deepseek`
- Source SZZ Anchor Audit run: `runs\batches\root-cause-v2-szz-anchor-audit-engineering-deepseek-30`
- Output: `runs\batches\root-cause-v2-szz-anchor-audit-engineering-deepseek-30-final`
- Lifecycle maximum: `raw_candidate`
- No Judge, no BIC validation, no formal affected-version conversion.
- Raw candidate commits must not be interpreted as validated BICs.

## Counts

| Metric | Value |
|---|---:|
| cases_total | 30 |
| root_cause_accepted_count | 27 |
| root_cause_blocked_count | 3 |
| szz_runnable_count | 27 |
| szz_handoff_accepted_count | 21 |
| szz_handoff_blocked_count | 6 |
| resolved_anchor_count | 46 |
| raw_candidate_commit_count_unique | 37 |
| raw_candidate_commit_rows | 37 |
| blame_success_rate | 1.0 |
| blame_success_rate_denominator | 46 |
| blocked_cases_not_in_blame_denominator | 9 |

## Blocked Cases

Root Cause blocked: CVE-2020-13904, CVE-2020-19667, CVE-2020-27814

SZZ handoff blocked: CVE-2020-12284, CVE-2020-14212, CVE-2020-8169, CVE-2022-0433, CVE-2020-1971, CVE-2020-15466

## Taxonomy

```json
{
  "add_only_context_only": 3,
  "consequence_stated_as_root_cause": 1,
  "explanatory_anchor_in_required_refs": 1,
  "fix_commit_incomplete": 6,
  "fix_family_incomplete": 4,
  "fix_set_incomplete": 3,
  "missing_patch_hunk_id": 1,
  "no_blameable_anchor_selected": 3,
  "observation_provenance": 4,
  "predicate_without_anchor": 2,
  "root_cause_not_ingested_raw": 1,
  "root_cause_structural_blocked": 2,
  "szz_handoff_blocked": 6,
  "weak_predicate_evidence": 2,
  "weak_root_cause_binding": 6
}
```

## Artifacts

- `summary.json`
- `szz_anchor_audit.csv`
- `manual_anchor_review_template.csv`
- `provenance_manifest.json`
- Per-CVE directories with preserved accepted artifacts or censored empty candidate artifacts.

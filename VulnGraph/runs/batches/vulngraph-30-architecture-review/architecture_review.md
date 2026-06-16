# VulnGraph 30-CVE Architecture Review

This is a review-only artifact. No refactor, model call, Judge, BIC validation, or formal version inference was implemented in this step.

## Current Pipeline Boundary

```text
CVE / fix commits
  -> Root Cause Agent v2
  -> evidence / contract gate
  -> Root Cause semantic baseline
  -> SZZ Anchor Audit
  -> raw candidate commits
  -> diagnostic Version Probe
  -> no BIC Judge yet
  -> no formal affected-version conversion yet
```

## What Works

- The 30-CVE run now has a consolidated artifact with every CVE represented, including censored artifacts for blocked cases.
- Root Cause/SZZ/Version Probe boundaries are still separated by lifecycle: highest lifecycle is `raw_candidate`.
- The release-tag universe filter is active and diagnostic tag counts are recorded per repo.
- Manual review can now prioritize the 9 blocked cases and the non-exact release-probe cases.

## Main Design Risks

1. `src/vulngraph/workflows/szz_anchor_audit.py` is large (57345 bytes) and mixes inventory construction, compaction, prompt assembly, contract validation, resolving, blame, and reporting. It should later be split after the 30-CVE artifact is frozen.
2. `src/vulngraph/workflows/szz_anchor_version_probe.py` is also large (45302 bytes) and mixes tag filtering, reachability, metrics, and attribution. The release tag universe should become a reusable service.
3. Diagnostic version probe currently assigns good-looking metrics to empty candidate cases in some fields; the postprocess report therefore separates all-case vs accepted-only denominators.
4. Manual anchor correctness is still unreviewed. `candidate_inventory_coverage` is not statement localization precision.
5. The current raw candidate pool is not a BIC result. A BIC Boundary Judge still needs its own evidence contract.

## Suggested Next Refactor Units

- `workflows/szz_anchor_inventory.py`: candidate inventory and semantic-preserving compaction.
- `workflows/szz_anchor_resolution.py`: model selection resolution and pre-fix line validation.
- `services/version_tags.py`: release tag filtering and diagnostics.
- `evaluation/version_probe_metrics.py`: macro metrics and blocked denominator handling.
- `evaluation/error_attribution.py`: root-cause/SZZ/conversion error taxonomy.

## Next Judge Input Contract

A future Judge should consume only:

- Root Cause hypothesis ids and gated anchors.
- Resolved pre-fix line anchors with exact parent-side text hash.
- Candidate commits with blame trace and uncertainty/exclusion reasons.
- Fix family / fix commit coverage metadata.

It should not consume raw release-probe predictions as evidence. Version conversion must remain downstream of BIC boundary judgment.

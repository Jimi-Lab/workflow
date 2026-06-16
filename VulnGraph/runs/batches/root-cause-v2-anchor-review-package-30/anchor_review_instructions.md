# Anchor Review Instructions

This package is for manual review of the 30-CVE Root Cause -> SZZ Anchor -> Version Probe engineering run.

## Boundary

- Review raw candidate quality only.
- Do not treat raw candidate commits as validated BICs.
- Do not treat version-probe output as formal affected-version inference.
- Do not use this review to rewrite frozen Root Cause semantic labels.

## Recommended Review Order

1. `priority=1`: Root Cause blocked. Check whether the Root Cause contract/gate failure is a valid block.
2. `priority=2`: SZZ handoff blocked. Check model-selected anchors against `candidate_inventory.json` and contract errors.
3. `priority=3`: accepted metadata but no candidate commits. Check resolve/blame traces.
4. `priority=4`: candidate pool exists but release probe is not exact. Check whether anchors are semantically correct and whether version conversion overreaches.
5. `priority=5`: spot-check exact-match cases for hidden anchor overfitting.

## Per-CVE Checks

- Does the selected pre-fix line actually correspond to the Root Cause mechanism?
- Is add-only handling using protected parent-side code, not newly added guard lines?
- Is the blame target line text exact and traceable?
- Are candidate commits fix-family or refactor noise?
- Is the release version error caused by anchor quality, raw candidate ranking, or conversion overreach?

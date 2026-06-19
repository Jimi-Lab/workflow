# CVE-2020-27814 Deterministic Repair

This local repair does not call a model and does not fabricate candidates. It materializes the equivalent second-parent fix commit, builds parent-side candidates, and runs local blame only if a parent-side line exists.

- attempted: True
- repo: openjpeg
- equivalent_fix_commit: 4ce7d285a55d29b79880d0566d4b010fe1907aa9
- status: repaired_raw_candidate
- candidate_inventory_count: 1
- selected_anchor_count: 1
- candidate_count: 1
- impossible_reason: 
- errors: `[]`

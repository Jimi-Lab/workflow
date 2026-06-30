# History Event Anchor Relocation Hardening v1

This deterministic artifact relocates immutable anchor references independently in each candidate parent and candidate revision before materializing Judge-ready context.

- Cases total: 30
- Candidates accounted: 61 / 61
- Blind packets: 61
- Audit packets: 61
- Strong/Fallback: 37 / 24
- Old context found (unverified coordinate behavior): 83
- Old context text/hash verified: 12
- Old false same-line accepts: 71
- New verified contexts: 63
- Parent/Candidate resolutions: 60 / 61
- Parent relocation statuses: {"absent_by_event": 44, "ambiguous": 5, "found": 8, "not_found": 1, "path_missing": 2}
- Candidate relocation statuses: {"ambiguous": 4, "found": 55, "not_found": 1, "path_missing": 1}
- Relocation strategies: {"blame_coordinate_verified": 8, "context_fingerprint": 4, "exact_hash": 44, "normalized_unique": 7}
- False same-line accepts: 0
- Candidate accounting rate: 1.000000
- Anchor-local diff found: 59
- Function context available: 0

No model call, Judge invocation, or downstream conversion is performed. Lifecycles remain `judge_ready_history_event_candidate`.
A found relocation proves only a text/hash/diff relationship at a bounded provenance path; it does not prove that the event is a true vulnerability introduction.

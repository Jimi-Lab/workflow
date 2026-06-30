# History Event Anchor Relocation Hardening v1

This deterministic artifact relocates immutable anchor references independently in each candidate parent and candidate revision before materializing Judge-ready context.

- Cases total: 7
- Candidates accounted: 17 / 17
- Blind packets: 17
- Audit packets: 17
- Strong/Fallback: 10 / 7
- Old context found (unverified coordinate behavior): 9
- New verified contexts: 17
- Parent relocation statuses: {"absent_by_event": 11, "ambiguous": 1, "found": 3, "not_found": 1, "path_missing": 1}
- Candidate relocation statuses: {"ambiguous": 1, "found": 14, "not_found": 1, "path_missing": 1}
- Relocation strategies: {"blame_coordinate_verified": 2, "context_fingerprint": 1, "exact_hash": 10, "normalized_unique": 4}
- False same-line accepts: 0
- Candidate accounting rate: 1.000000
- Anchor-local diff found: 16
- Function context available: 0

No model call, Judge invocation, or downstream conversion is performed. Lifecycles remain `judge_ready_history_event_candidate`.
A found relocation proves only a text/hash/diff relationship at a bounded provenance path; it does not prove that the event is a true vulnerability introduction.

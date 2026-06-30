# VulnGraph v1.2.2.1 Tri-State Decision Policy

## Evidence Boundary

- Input is frozen v1.2.2 tag-local state evidence. No Git or model evidence is recomputed.
- present_exact and present_normalized are strong vulnerability-predicate presence.
- present_predicate_equivalent is a function-structural token fingerprint, not semantic equivalence, and cannot confirm affected.
- weak fingerprints, reordered tokens, unavailable paths/functions, and missing evidence remain unknown.

## State Transitions

- confirmed_affected: strong predicate presence, complete prerequisite state, confirmed branch context, absent branch-local fix completion, and no conflicting fix evidence.
- confirmed_unaffected: branch-local fix completion is present, or the vulnerability predicate is strongly absent in readable scope.
- all remaining combinations are unknown.
- the public affected_versions field contains only confirmed_affected tags.

## Known Evidence Limitation

- Independent fix-predicate evidence rows: 0.
- Fix-absence reachability proxies: 2021.
- Frozen v1.2.2 does not independently prove code-level fix-predicate absence; it records fix completion through branch-local commit/equivalence reachability.


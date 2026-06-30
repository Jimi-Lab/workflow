# VulnGraph v1.2.2 State Audit

This is a deterministic no-model audit of v1.2.1 unknown-state cases before v1.2.2 replay.

- cases audited: 21
- unknown_state cases: 20
- model_invocation_count: 0
- FP contribution: 643
- FN contribution: 317

## Focus Cases

- CVE-2020-11647: status=unknown_state, selected_events=2, predicate_unknown={'path_unavailable': 146}, fix_unknown={}, FP=222, FN=0
- CVE-2020-11993: status=unknown_state, selected_events=1, predicate_unknown={'path_unavailable': 165}, fix_unknown={}, FP=23, FN=5
- CVE-2020-13904: status=unknown_state, selected_events=8, predicate_unknown={'path_unavailable': 198}, fix_unknown={}, FP=0, FN=0
- CVE-2020-27814: status=unresolved_boundary, selected_events=0, predicate_unknown={}, fix_unknown={}, FP=0, FN=5

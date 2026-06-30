# Boundary State Transition Specification

- Each branch context is evaluated independently from wrapper-owned Git DAG facts.
- `primary_boundary` and `branch_equivalent_boundary` may activate vulnerability state.
- `conjunctive_prerequisite` is mandatory only when explicitly selected; supporting evidence is never mandatory.
- A release is affected only when a branch-local activation event is reachable, its code line survives, all explicit prerequisites hold, and the branch-local fix group is incomplete.
- Same-patch-id fixes are OR-equivalent. Only an explicit linear series is AND. Unknown relations remain unknown.
- Uncertain Judge output becomes `unresolved_boundary`; indeterminate code/fix state becomes `unknown_state`. Neither is reported as converted.

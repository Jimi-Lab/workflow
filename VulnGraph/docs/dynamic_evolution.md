# Dynamic Evolution

VulnGraph evolves through append-only events. Agent output is not directly trusted as validated knowledge.

## Agent Output Contract

Every agent run should emit strict JSON with:

- `agent_run`
- `command_invocations`
- `git_observations`
- `predicate_evaluations`
- `target_verdict`
- `uncertainty_reasons`
- `learned_candidates`

`CommandInvocation` and `CommandOutput` are audit records. `GitObservation` and `PredicateEvaluation` are target-verdict evidence. `TargetVerdict` is stored as a runtime result but blocked from future packets by default.

## Self-Evolution

Learning is candidate-first:

```text
FailureCase
  -> candidate RepoMemory / CWEMemory / ProcedureMemory
  -> lifecycle_transition after replay or manual gate
  -> validated memory may enter navigation/procedure packet sections
```

No candidate memory, procedure, or skill is injected into production packets without a lifecycle transition to `validated`.

# VulnGraph Ontology v1

VulnGraph v1 is a JSONL event-sourced property graph. It is intentionally lightweight and independent from VulnVersion Step2.

## Node Families

- `ExternalContext`: `CVE`, `CWE`, `CAPEC`, `Advisory`, `Reference`, `ProductHint`
- `RepoContext`: `Repo`, `RepoComponent`, `FilePath`, `FunctionSymbol`, `PathAlias`, `BuildCondition`
- `PatchEvidence`: `FixCommit`, `PatchHunk`, `ChangedFile`, `ChangedFunction`, `CodeAnchor`
- `VulnerabilitySemantics`: `RootCauseHypothesis`, `VulnerablePredicate`, `FixPredicate`, `GuardCondition`, `NegativeApplicabilityCondition`, `RiskFlag`
- `AgentRuntime`: `AgentRun`, `AgentStep`, `CommandInvocation`, `CommandOutput`, `GitObservation`, `PredicateEvaluation`, `TargetVerdict`, `UncertaintyReason`
- `SelfEvolution`: `FailureCase`, `SuccessCase`, `RepoMemory`, `CWEMemory`, `PredicateMemory`, `ProcedureMemory`, `SkillProcedure`, `ArtifactRule`

## Allowed Use

- `context_only`: background only; cannot support a target verdict.
- `navigation_only`: repo search/navigation hints.
- `procedure_only`: checklist or operation procedure.
- `root_cause_evidence`: root-cause hypothesis evidence.
- `target_verdict_evidence`: target-local command/git evidence.
- `learning_candidate`: candidate memory or procedure; blocked from production packets.
- `offline_eval_only`: GT, historical verdicts, or offline records; blocked from runtime packets.

## Runtime Boundary

Default packet extraction blocks `learning_candidate` and `offline_eval_only`. A target verdict should cite `GitObservation` and `PredicateEvaluation`, not CVE text, CWE text, CAPEC text, GT labels, or neighbor verdicts.

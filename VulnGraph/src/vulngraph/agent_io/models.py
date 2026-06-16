from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from vulngraph.schema import GraphEdge, GraphEvent, GraphNode, SourceRef


class AgentRunPayload(BaseModel):
  run_id: str
  cve_id: str
  repo: str
  target: str
  backend: str = "opencode"


class CommandOutputPayload(BaseModel):
  output_id: str
  text: str = ""
  exit_code: int | None = None
  truncated: bool = False


class AgentCommandInvocation(BaseModel):
  invocation_id: str
  step_id: str
  command: str
  output: CommandOutputPayload | None = None


class AgentGitObservation(BaseModel):
  observation_id: str
  command_ref: str
  target: str
  path: str = ""
  claim: str
  snippet: str = ""


class AgentPredicateEvaluation(BaseModel):
  evaluation_id: str
  predicate_id: str
  result: Literal["satisfied", "not_satisfied", "unknown"]
  observation_ids: list[str] = Field(default_factory=list)
  polarity: Literal["supports", "contradicts", "neutral"] = "supports"


class AgentTargetVerdict(BaseModel):
  verdict_id: str
  target: str
  verdict: Literal["AFFECTED", "NOT_AFFECTED", "UNKNOWN"]
  evidence_evaluation_ids: list[str] = Field(default_factory=list)


class AgentUncertaintyReason(BaseModel):
  reason_id: str
  reason: str
  related_node_ids: list[str] = Field(default_factory=list)


class AgentLearnedCandidate(BaseModel):
  candidate_id: str
  memory_type: Literal["RepoMemory", "CWEMemory", "PredicateMemory", "ProcedureMemory", "SkillProcedure"]
  scope: Literal["repo", "cwe", "cve", "target", "experiment"]
  hint: str
  source_failure_id: str | None = None


class AgentOutput(BaseModel):
  agent_run: AgentRunPayload
  command_invocations: list[AgentCommandInvocation] = Field(default_factory=list)
  git_observations: list[AgentGitObservation] = Field(default_factory=list)
  predicate_evaluations: list[AgentPredicateEvaluation] = Field(default_factory=list)
  target_verdict: AgentTargetVerdict
  uncertainty_reasons: list[AgentUncertaintyReason] = Field(default_factory=list)
  learned_candidates: list[AgentLearnedCandidate] = Field(default_factory=list)


def agent_output_to_events(output: AgentOutput) -> list[GraphEvent]:
  run = output.agent_run
  source = [SourceRef(kind="agent_output", ref=f"agent-run:{run.run_id}")]
  events: list[GraphEvent] = []
  run_id = f"agent-run:{run.run_id}"

  events.append(
    GraphEvent.upsert_node(
      GraphNode(
        id=run_id,
        type="AgentRun",
        scope="agent_run",
        source_refs=source,
        allowed_use="context_only",
        confidence=1.0,
        lifecycle="raw",
        created_from="agent_output",
        content=run.model_dump(),
      ),
      created_from="agent_output",
    )
  )

  for command in output.command_invocations:
    step_id = f"agent-step:{command.step_id}"
    command_id = f"command:{command.invocation_id}"
    events.extend(
      [
        _node_event(step_id, "AgentStep", "agent_run", "context_only", source, {"step_id": command.step_id}),
        _edge_event("has_step", run_id, step_id, "agent_run", "context_only", source),
        _node_event(command_id, "CommandInvocation", "agent_run", "context_only", source, command.model_dump(exclude={"output"})),
        _edge_event("invokes", step_id, command_id, "agent_run", "context_only", source),
      ]
    )
    if command.output is not None:
      output_id = f"command-output:{command.output.output_id}"
      events.extend(
        [
          _node_event(output_id, "CommandOutput", "agent_run", "context_only", source, command.output.model_dump()),
          _edge_event("produces", command_id, output_id, "agent_run", "context_only", source),
        ]
      )

  command_output_by_invocation = {
    command.invocation_id: f"command-output:{command.output.output_id}"
    for command in output.command_invocations
    if command.output is not None
  }

  for observation in output.git_observations:
    observation_id = f"git-observation:{observation.observation_id}"
    events.append(
      _node_event(
        observation_id,
        "GitObservation",
        "target",
        "target_verdict_evidence",
        source,
        observation.model_dump(),
      )
    )
    output_id = command_output_by_invocation.get(observation.command_ref)
    if output_id:
      events.append(_edge_event("derives", output_id, observation_id, "target", "target_verdict_evidence", source))

  verdict_id = f"target-verdict:{output.target_verdict.verdict_id}"
  for evaluation in output.predicate_evaluations:
    evaluation_id = f"predicate-evaluation:{evaluation.evaluation_id}"
    events.append(
      _node_event(
        evaluation_id,
        "PredicateEvaluation",
        "target",
        "target_verdict_evidence",
        source,
        evaluation.model_dump(),
      )
    )
    edge_type = "contradicts" if evaluation.polarity == "contradicts" else "supports"
    for observation_id in evaluation.observation_ids:
      events.append(_edge_event(edge_type, f"git-observation:{observation_id}", evaluation_id, "target", "target_verdict_evidence", source))
    events.append(_edge_event(edge_type, evaluation_id, verdict_id, "target", "target_verdict_evidence", source))

  events.append(
    _node_event(
      verdict_id,
      "TargetVerdict",
      "target",
      "offline_eval_only",
      source,
      output.target_verdict.model_dump(),
    )
  )

  for reason in output.uncertainty_reasons:
    reason_id = f"uncertainty:{reason.reason_id}"
    events.append(_node_event(reason_id, "UncertaintyReason", "target", "offline_eval_only", source, reason.model_dump()))
    events.append(_edge_event("has_uncertainty", verdict_id, reason_id, "target", "offline_eval_only", source))

  for candidate in output.learned_candidates:
    candidate_id = f"memory:{candidate.candidate_id}"
    events.append(
      _node_event(
        candidate_id,
        candidate.memory_type,
        candidate.scope,
        "learning_candidate",
        source,
        candidate.model_dump(),
        lifecycle="candidate",
        confidence=0.3,
      )
    )
    events.append(_edge_event("candidate_updates", run_id, candidate_id, candidate.scope, "learning_candidate", source, confidence=0.3))

  return events


def _node_event(
  node_id: str,
  node_type: str,
  scope: str,
  allowed_use: str,
  source_refs: list[SourceRef],
  content: dict,
  *,
  lifecycle: str = "raw",
  confidence: float = 0.7,
) -> GraphEvent:
  return GraphEvent.upsert_node(
    GraphNode(
      id=node_id,
      type=node_type,
      scope=scope,
      source_refs=source_refs,
      allowed_use=allowed_use,
      confidence=confidence,
      lifecycle=lifecycle,
      created_from="agent_output",
      content=content,
    ),
    created_from="agent_output",
  )


def _edge_event(
  edge_type: str,
  source: str,
  target: str,
  scope: str,
  allowed_use: str,
  source_refs: list[SourceRef],
  *,
  confidence: float = 0.7,
) -> GraphEvent:
  return GraphEvent.upsert_edge(
    GraphEdge(
      id=f"edge:{source}:{edge_type}:{target}",
      type=edge_type,
      source=source,
      target=target,
      scope=scope,
      source_refs=source_refs,
      allowed_use=allowed_use,
      confidence=confidence,
      lifecycle="raw",
      created_from="agent_output",
    ),
    created_from="agent_output",
  )

from __future__ import annotations

from typing import Any

from vulngraph.schema import GraphEdge, GraphEvent, GraphNode, SourceRef

from .models import RootCauseAgentOutput, RootCausePredicate


def root_cause_output_to_events(output: RootCauseAgentOutput) -> list[GraphEvent]:
  run = output.agent_run
  source = [SourceRef(kind="agent_output", ref=f"root-cause-run:{run.run_id}")]
  events: list[GraphEvent] = []
  run_id = f"agent-run:{run.run_id}"
  events.append(_node(run_id, "AgentRun", "agent_run", "context_only", source, run.model_dump(), confidence=1.0))

  command_outputs: dict[str, str] = {}
  for command in output.command_invocations:
    step_id = f"agent-step:{run.run_id}:{command.step_id}"
    command_id = f"command:{run.run_id}:{command.invocation_id}"
    events.extend(
      [
        _node(step_id, "AgentStep", "agent_run", "context_only", source, {"step_id": command.step_id}),
        _edge("has_step", run_id, step_id, "agent_run", "context_only", source),
        _node(command_id, "CommandInvocation", "agent_run", "context_only", source, command.model_dump(exclude={"output"})),
        _edge("invokes", step_id, command_id, "agent_run", "context_only", source),
      ]
    )
    if command.output is not None:
      output_id = f"command-output:{run.run_id}:{command.output.output_id}"
      command_outputs[command.invocation_id] = output_id
      events.extend(
        [
          _node(output_id, "CommandOutput", "agent_run", "context_only", source, command.output.model_dump()),
          _edge("produces", command_id, output_id, "agent_run", "context_only", source),
        ]
      )

  for anchor in output.code_anchors:
    node_id = f"code-anchor:{anchor.anchor_id}"
    events.append(_semantic_node(node_id, "CodeAnchor", anchor.model_dump(), source, anchor.confidence))
    events.append(_edge("proposes", run_id, node_id, "cve", "root_cause_evidence", source, confidence=anchor.confidence))
    events.extend(_command_support_edges(anchor.command_refs, command_outputs, node_id, source, anchor.confidence))

  predicate_groups: tuple[tuple[str, list[RootCausePredicate]], ...] = (
    ("VulnerablePredicate", output.vulnerable_predicates),
    ("FixPredicate", output.fix_predicates),
    ("GuardCondition", output.guard_conditions),
    ("NegativeApplicabilityCondition", output.negative_applicability_conditions),
  )
  prefixes = {
    "VulnerablePredicate": "vulnerable-predicate",
    "FixPredicate": "fix-predicate",
    "GuardCondition": "guard-condition",
    "NegativeApplicabilityCondition": "negative-condition",
  }
  for node_type, predicates in predicate_groups:
    for predicate in predicates:
      node_id = f"{prefixes[node_type]}:{predicate.predicate_id}"
      events.append(_semantic_node(node_id, node_type, predicate.model_dump(), source, predicate.confidence))
      events.append(_edge("proposes", run_id, node_id, "cve", "root_cause_evidence", source, confidence=predicate.confidence))
      for anchor_id in predicate.anchor_ids:
        events.append(_edge("anchored_by", node_id, f"code-anchor:{anchor_id}", "cve", "root_cause_evidence", source, confidence=predicate.confidence))
      events.extend(_command_support_edges(predicate.command_refs, command_outputs, node_id, source, predicate.confidence))

  for flag in output.risk_flags:
    node_id = f"risk-flag:{flag.risk_flag_id}"
    events.append(_semantic_node(node_id, "RiskFlag", flag.model_dump(), source, flag.confidence))
    events.append(_edge("proposes", run_id, node_id, "cve", "root_cause_evidence", source, confidence=flag.confidence))
    events.extend(_command_support_edges(flag.command_refs, command_outputs, node_id, source, flag.confidence))

  for hypothesis in output.root_cause_hypotheses:
    node_id = f"root-cause-hypothesis:{hypothesis.hypothesis_id}"
    events.append(_semantic_node(node_id, "RootCauseHypothesis", hypothesis.model_dump(), source, hypothesis.confidence))
    events.append(_edge("proposes", run_id, node_id, "cve", "root_cause_evidence", source, confidence=hypothesis.confidence))
    events.extend(_command_support_edges(hypothesis.command_refs, command_outputs, node_id, source, hypothesis.confidence))
    for predicate_id in hypothesis.vulnerable_predicate_ids:
      events.append(_edge("requires", node_id, f"vulnerable-predicate:{predicate_id}", "cve", "root_cause_evidence", source, confidence=hypothesis.confidence))
    for predicate_id in hypothesis.fix_predicate_ids:
      events.append(_edge("blocked_by", node_id, f"fix-predicate:{predicate_id}", "cve", "root_cause_evidence", source, confidence=hypothesis.confidence))
    for condition_id in hypothesis.guard_condition_ids:
      events.append(_edge("constrained_by", node_id, f"guard-condition:{condition_id}", "cve", "root_cause_evidence", source, confidence=hypothesis.confidence))
    for condition_id in hypothesis.negative_condition_ids:
      events.append(_edge("excluded_by", node_id, f"negative-condition:{condition_id}", "cve", "root_cause_evidence", source, confidence=hypothesis.confidence))
    for flag_id in hypothesis.risk_flag_ids:
      events.append(_edge("constrained_by", node_id, f"risk-flag:{flag_id}", "cve", "root_cause_evidence", source, confidence=hypothesis.confidence))

  for candidate in output.learned_candidates:
    candidate_id = f"memory:{candidate.candidate_id}"
    events.append(
      _node(
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
    events.append(_edge("candidate_updates", run_id, candidate_id, candidate.scope, "learning_candidate", source, confidence=0.3))

  return events


def _command_support_edges(
  command_refs: list[str],
  command_outputs: dict[str, str],
  target: str,
  source_refs: list[SourceRef],
  confidence: float,
) -> list[GraphEvent]:
  return [
    _edge("supports", command_outputs[ref], target, "cve", "root_cause_evidence", source_refs, confidence=confidence)
    for ref in command_refs
    if ref in command_outputs
  ]


def _semantic_node(node_id: str, node_type: str, content: dict[str, Any], source_refs: list[SourceRef], confidence: float) -> GraphEvent:
  return _node(node_id, node_type, "cve", "root_cause_evidence", source_refs, content, confidence=confidence)


def _node(
  node_id: str,
  node_type: str,
  scope: str,
  allowed_use: str,
  source_refs: list[SourceRef],
  content: dict[str, Any],
  *,
  lifecycle: str = "raw",
  confidence: float = 0.7,
) -> GraphEvent:
  node = GraphNode(
    id=node_id,
    type=node_type,
    scope=scope,
    source_refs=source_refs,
    allowed_use=allowed_use,
    confidence=confidence,
    lifecycle=lifecycle,
    created_from="root_cause_agent",
    content=content,
  )
  return GraphEvent.upsert_node(node, created_from="root_cause_agent")


def _edge(
  edge_type: str,
  source: str,
  target: str,
  scope: str,
  allowed_use: str,
  source_refs: list[SourceRef],
  *,
  confidence: float = 0.7,
) -> GraphEvent:
  edge = GraphEdge(
    id=f"edge:{source}:{edge_type}:{target}",
    type=edge_type,
    source=source,
    target=target,
    scope=scope,
    source_refs=source_refs,
    allowed_use=allowed_use,
    confidence=confidence,
    lifecycle="raw",
    created_from="root_cause_agent",
  )
  return GraphEvent.upsert_edge(edge, created_from="root_cause_agent")

from __future__ import annotations

from typing import Any

from vulngraph.agent_io.root_cause_contract import validate_root_cause_structure
from vulngraph.schema import GraphEvent
from vulngraph.store import JsonlGraphStore

from .common import IngestionResult, edge_event, failure_case_event, node_event, safe_id, source_ref


def ingest_root_cause_output(
  store: JsonlGraphStore,
  cve_id: str,
  agent_output: dict[str, Any],
  *,
  trace: dict[str, Any] | None = None,
  packet: dict[str, Any] | None = None,
) -> IngestionResult:
  if not isinstance(agent_output, dict):
    return _reject_with_failure(store, cve_id, "root_cause", "malformed agent_output")

  trace = trace or {}
  packet = packet or {}
  run_payload = dict(agent_output.get("agent_run") or {})
  run_id = safe_id(str(run_payload.get("run_id") or f"{cve_id}:root-cause"))
  run_node_id = f"agent-run:{safe_id(cve_id)}:{run_id}"
  source = source_ref("service_root_cause_output", f"root-cause:{cve_id}:{run_id}")
  hypotheses = list(agent_output.get("root_cause_hypotheses") or [])
  validation = validate_root_cause_structure(agent_output, packet, trace)
  packet_index = validation.packet_index
  observation_payloads = validation.observation_payloads
  trusted_observations = validation.trusted_observations
  observation_rejections = validation.observation_rejections
  known_observation_ids = set(trusted_observations)

  events: list[GraphEvent] = [
    node_event(
      run_node_id,
      "AgentRun",
      "agent_run",
      "context_only",
      source,
      {"cve_id": cve_id, "stage": "root_cause", **run_payload},
      lifecycle="raw",
      confidence=1.0,
      created_from="service_ingestion",
    )
  ]
  command_to_output: dict[str, str] = {}
  output_refs: dict[str, str] = {}
  events.extend(
    _tool_trace_events(
      run_node_id,
      cve_id,
      trace,
      source,
      command_to_output,
      output_refs=output_refs,
      allowed_use="root_cause_evidence",
      run_id=run_id,
    )
  )
  observation_ids = _append_git_observations(
    events,
    cve_id,
    observation_payloads,
    source,
    command_to_output,
    output_refs=output_refs,
    allowed_use="root_cause_evidence",
    scope="cve",
    target_id=None,
    run_id=run_id,
    trusted_observation_ids=known_observation_ids,
  )

  anchor_map = validation.anchor_results
  vulnerable_map = validation.vulnerable_predicate_results
  fix_map = validation.fix_predicate_results
  guard_map = validation.guard_condition_results
  negative_map = validation.negative_condition_results
  hypothesis_results = validation.hypothesis_results
  raw_hypothesis_ids = set(validation.accepted_hypothesis_ids)
  raw_hypothesis_count = len(validation.accepted_hypothesis_ids)
  rejected_hypothesis_count = len(validation.rejected_hypothesis_ids)
  global_fix_set_results = validation.fix_set_results

  _finalize_semantic_lifecycles(hypotheses, raw_hypothesis_ids, anchor_map, vulnerable_map, fix_map, guard_map, negative_map)
  _append_prepared_semantic_nodes(events, cve_id, run_id, source, observation_ids, anchor_map, "CodeAnchor", "code-anchor")
  _append_prepared_semantic_nodes(events, cve_id, run_id, source, observation_ids, vulnerable_map, "VulnerablePredicate", "vulnerable-predicate")
  _append_prepared_semantic_nodes(events, cve_id, run_id, source, observation_ids, fix_map, "FixPredicate", "fix-predicate")
  _append_prepared_semantic_nodes(events, cve_id, run_id, source, observation_ids, guard_map, "GuardCondition", "guard-condition")
  _append_prepared_semantic_nodes(events, cve_id, run_id, source, observation_ids, negative_map, "NegativeCondition", "negative-condition")

  for predicate_map in (vulnerable_map, fix_map, guard_map, negative_map):
    for item in predicate_map.values():
      if item["lifecycle"] != "raw":
        continue
      for anchor_id in item["payload"].get("anchor_ids", []):
        anchor = anchor_map.get(str(anchor_id))
        if anchor and anchor["lifecycle"] == "raw":
          events.append(edge_event("anchored_by", item["node_id"], anchor["node_id"], "cve", "root_cause_evidence", source, lifecycle="raw", created_from="service_ingestion"))

  failure_case_ids: list[str] = []
  for hypothesis in hypotheses:
    hypothesis_id = _payload_id(hypothesis, "hypothesis_id")
    node_id = f"root-cause-hypothesis:{safe_id(cve_id)}:{run_id}:{safe_id(hypothesis_id)}"
    result = hypothesis_results[hypothesis_id]
    hypothesis_lifecycle = result["lifecycle"]
    events.append(
      node_event(
        node_id,
        "RootCauseHypothesis",
        "cve",
        "root_cause_evidence",
        source,
        {"cve_id": cve_id, "run_id": run_id, **hypothesis, "gate_errors": result["errors"], "fix_set_results": result["fix_set_results"]},
        lifecycle=hypothesis_lifecycle,
        confidence=float(hypothesis.get("confidence", 0.7) or 0.7),
        created_from="service_ingestion",
      )
    )
    events.append(edge_event("proposes", run_node_id, node_id, "cve", "root_cause_evidence", source, lifecycle=hypothesis_lifecycle, created_from="service_ingestion"))
    if hypothesis_lifecycle == "raw":
      for observation_ref in hypothesis.get("git_observation_refs", []):
        observation_id = observation_ids.get(str(observation_ref))
        if observation_id:
          events.append(edge_event("supports", observation_id, node_id, "cve", "root_cause_evidence", source, lifecycle="raw", created_from="service_ingestion"))
      _link_many(events, node_id, "requires", hypothesis.get("vulnerable_predicate_ids", []), vulnerable_map, source, "raw")
      _link_many(events, node_id, "blocked_by", hypothesis.get("fix_predicate_ids", []), fix_map, source, "raw")
      _link_many(events, node_id, "constrained_by", hypothesis.get("guard_condition_ids", []), guard_map, source, "raw")
      _link_many(events, node_id, "excluded_by", hypothesis.get("negative_condition_ids", []), negative_map, source, "raw")
      _link_many(events, node_id, "anchored_by", hypothesis.get("anchor_ids", []), anchor_map, source, "raw")
    else:
      reason = result["errors"][0] if result["errors"] else "RootCauseHypothesis failed evidence gate"
      failure = failure_case_event(
        cve_id=cve_id,
        stage="root_cause_evidence_gate",
        gate_stage="hypothesis_gate",
        reason=reason,
        source_refs=source,
        related_ids=[run_node_id, node_id],
        rejected_ids=result["rejected_ids"],
        run_id=run_id,
        hypothesis_id=hypothesis_id,
      )
      events.append(failure)
      if failure.node:
        failure_case_ids.append(failure.node.id)

  for risk in agent_output.get("risk_flags") or []:
    risk_id = safe_id(str(risk.get("risk_id") or risk.get("id") or risk.get("description") or "risk"))
    events.append(
      node_event(
        f"risk-flag:{safe_id(cve_id)}:{run_id}:{risk_id}",
        "RiskFlag",
        "cve",
        "learning_candidate",
        source,
        {"cve_id": cve_id, "run_id": run_id, **risk},
        lifecycle="candidate",
        confidence=0.3,
        created_from="service_ingestion",
      )
    )

  for reason in agent_output.get("uncertainty_reasons") or []:
    reason_id = safe_id(str(reason.get("reason_id") or reason.get("id") or reason.get("reason") or "uncertainty"))
    events.append(
      node_event(
        f"uncertainty:{safe_id(cve_id)}:{run_id}:{reason_id}",
        "UncertaintyReason",
        "cve",
        "context_only",
        source,
        {"cve_id": cve_id, "run_id": run_id, **reason},
        lifecycle="raw",
        confidence=0.5,
        created_from="service_ingestion",
      )
    )

  errors = list(dict.fromkeys(error for result in hypothesis_results.values() for error in result["errors"]))
  warnings: list[str] = []
  if raw_hypothesis_count and rejected_hypothesis_count:
    warnings.append(f"{rejected_hypothesis_count} RootCauseHypothesis nodes failed the evidence gate")
  store.append_events(events)
  graph = store.materialize()
  store.write_snapshot(graph)
  return IngestionResult(
    status="ingested_raw" if raw_hypothesis_count else "rejected",
    lifecycle="raw" if raw_hypothesis_count else "rejected",
    appended_events=len(events),
    errors=[] if raw_hypothesis_count else errors,
    warnings=warnings + (errors if raw_hypothesis_count else []),
    failure_case_id=failure_case_ids[0] if failure_case_ids else None,
    raw_hypothesis_count=raw_hypothesis_count,
    rejected_hypothesis_count=rejected_hypothesis_count,
    details={
      "hypothesis_results": hypothesis_results,
      "fix_set_results": global_fix_set_results,
      "trusted_observation_ids": sorted(trusted_observations),
      "observation_rejections": observation_rejections,
      "failure_case_ids": failure_case_ids,
      "structural_validation": validation.to_dict(),
    },
  )


def record_root_cause_failure(
  store: JsonlGraphStore,
  cve_id: str,
  *,
  reason: str,
  backend_name: str,
  raw_text: str = "",
  trace: dict[str, Any] | None = None,
) -> IngestionResult:
  trace = trace or {}
  source = source_ref("service_root_cause_failure", f"root-cause-failure:{cve_id}:{reason}")
  run_id = safe_id(str(trace.get("run_id") or f"{cve_id}:root-cause-failure:{reason}"))
  run_node_id = f"agent-run:{run_id}"
  events: list[GraphEvent] = [
    node_event(
      run_node_id,
      "AgentRun",
      "agent_run",
      "context_only",
      source,
      {
        "cve_id": cve_id,
        "stage": "root_cause",
        "status": "failed",
        "backend": backend_name,
        "reason": reason,
        "raw_text_excerpt": raw_text[:1000],
      },
      lifecycle="rejected",
      confidence=1.0,
      created_from="service_ingestion",
    )
  ]
  command_to_output: dict[str, str] = {}
  events.extend(_tool_trace_events(run_node_id, cve_id, trace, source, command_to_output, allowed_use="root_cause_evidence"))
  _append_git_observations(
    events,
    cve_id,
    _raw_trace_observations(trace),
    source,
    command_to_output,
    allowed_use="root_cause_evidence",
    scope="cve",
    target_id=None,
  )
  failure = failure_case_event(cve_id=cve_id, stage="root_cause", reason=reason, source_refs=source, related_ids=[run_node_id])
  failure_case_id = failure.node.id if failure.node else None
  events.append(failure)
  store.append_events(events)
  graph = store.materialize()
  store.write_snapshot(graph)
  return IngestionResult(
    status="rejected",
    lifecycle="rejected",
    appended_events=len(events),
    errors=[reason],
    failure_case_id=failure_case_id,
  )


def ingest_judge_output(
  store: JsonlGraphStore,
  cve_id: str,
  target_id: str,
  agent_output: dict[str, Any],
  *,
  trace: dict[str, Any] | None = None,
) -> IngestionResult:
  if not isinstance(agent_output, dict):
    return _reject_with_failure(store, cve_id, "judge", "malformed agent_output", target_id=target_id)

  trace = trace or {}
  source = source_ref("service_judge_output", f"judge:{cve_id}:{target_id}")
  run_payload = dict(agent_output.get("agent_run") or {})
  run_id = safe_id(str(run_payload.get("run_id") or f"{cve_id}:{target_id}:judge"))
  run_node_id = f"agent-run:{run_id}"
  verdict_payload = dict(agent_output.get("target_verdict") or {})
  verdict_id = safe_id(str(verdict_payload.get("verdict_id") or f"verdict:{target_id}"))
  verdict_node_id = f"target-verdict:{safe_id(cve_id)}:{safe_id(target_id)}:{verdict_id}"

  observation_payloads = _trace_observations(trace, agent_output)
  target_observations = [obs for obs in observation_payloads if str(obs.get("target_id") or obs.get("target") or "") == target_id]
  evaluations = list(agent_output.get("predicate_evaluations") or [])
  evidence_eval_ids = {str(value) for value in verdict_payload.get("evidence_evaluation_ids", [])}
  target_obs_ids = {str(obs.get("id") or obs.get("observation_id")) for obs in target_observations}
  evaluation_has_observation = any(
    str(evaluation.get("evaluation_id") or evaluation.get("id")) in evidence_eval_ids
    and target_obs_ids.intersection({str(value) for value in evaluation.get("observation_ids", [])})
    for evaluation in evaluations
  )
  accepted = bool(target_observations and evidence_eval_ids and evaluation_has_observation)
  lifecycle = "raw" if accepted else "rejected"
  errors = [] if accepted else ["TargetVerdict is not supported by target-local GitObservation"]

  events: list[GraphEvent] = [
    node_event(
      f"target:{safe_id(cve_id)}:{safe_id(target_id)}",
      "Target",
      "target",
      "context_only",
      source,
      {"cve_id": cve_id, "target_id": target_id},
      lifecycle="raw",
      confidence=1.0,
      created_from="service_ingestion",
    ),
    node_event(
      f"target-snapshot:{safe_id(cve_id)}:{safe_id(target_id)}",
      "TargetSnapshot",
      "target",
      "target_verdict_evidence",
      source,
      {"cve_id": cve_id, "target_id": target_id, "repo_ref": trace.get("repo_ref")},
      lifecycle=lifecycle,
      confidence=0.7,
      created_from="service_ingestion",
    ),
    node_event(
      run_node_id,
      "AgentRun",
      "agent_run",
      "context_only",
      source,
      {"cve_id": cve_id, "target_id": target_id, "stage": "judge", **run_payload},
      lifecycle="raw",
      confidence=1.0,
      created_from="service_ingestion",
    ),
  ]
  events.append(edge_event("has_snapshot", f"target:{safe_id(cve_id)}:{safe_id(target_id)}", f"target-snapshot:{safe_id(cve_id)}:{safe_id(target_id)}", "target", "target_verdict_evidence", source, lifecycle=lifecycle, created_from="service_ingestion"))
  command_to_output: dict[str, str] = {}
  events.extend(_tool_trace_events(run_node_id, cve_id, trace, source, command_to_output, allowed_use="target_verdict_evidence", target_id=target_id))
  _append_git_observations(
    events,
    cve_id,
    observation_payloads,
    source,
    command_to_output,
    allowed_use="target_verdict_evidence",
    scope="target",
    target_id=target_id,
  )

  evaluation_node_ids: dict[str, str] = {}
  for evaluation in evaluations:
    evaluation_id = safe_id(str(evaluation.get("evaluation_id") or evaluation.get("id") or "evaluation"))
    node_id = f"predicate-evaluation:{safe_id(cve_id)}:{safe_id(target_id)}:{evaluation_id}"
    evaluation_node_ids[evaluation_id] = node_id
    events.append(
      node_event(
        node_id,
        "PredicateEvaluation",
        "target",
        "target_verdict_evidence",
        source,
        {"cve_id": cve_id, "target_id": target_id, **evaluation},
        lifecycle=lifecycle,
        confidence=0.7,
        created_from="service_ingestion",
      )
    )
    edge_type = "contradicts" if evaluation.get("polarity") == "contradicts" else "supports"
    for obs_id in evaluation.get("observation_ids", []):
      obs_node_id = f"git-observation:{safe_id(cve_id)}:{safe_id(obs_id)}"
      events.append(edge_event(edge_type, obs_node_id, node_id, "target", "target_verdict_evidence", source, lifecycle=lifecycle, created_from="service_ingestion"))

  events.append(
    node_event(
      verdict_node_id,
      "TargetVerdict",
      "target",
      "target_verdict_evidence",
      source,
      {"cve_id": cve_id, "target_id": target_id, **verdict_payload},
      lifecycle=lifecycle,
      confidence=0.8 if accepted else 0.1,
      created_from="service_ingestion",
    )
  )
  for evaluation_id in evidence_eval_ids:
    if evaluation_id in evaluation_node_ids:
      events.append(edge_event("supports", evaluation_node_ids[evaluation_id], verdict_node_id, "target", "target_verdict_evidence", source, lifecycle=lifecycle, created_from="service_ingestion"))

  failure_case_id = None
  if not accepted:
    failure = failure_case_event(cve_id=cve_id, target_id=target_id, stage="judge", reason=errors[0], source_refs=source, related_ids=[verdict_node_id])
    failure_case_id = failure.node.id if failure.node else None
    events.append(failure)

  store.append_events(events)
  graph = store.materialize()
  store.write_snapshot(graph)
  return IngestionResult(
    status="accepted" if accepted else "rejected",
    lifecycle=lifecycle,
    appended_events=len(events),
    errors=errors,
    failure_case_id=failure_case_id,
  )


def _reject_with_failure(
  store: JsonlGraphStore,
  cve_id: str,
  stage: str,
  reason: str,
  *,
  target_id: str | None = None,
) -> IngestionResult:
  source = source_ref(f"service_{stage}_output", f"{stage}:{cve_id}")
  event = failure_case_event(cve_id=cve_id, target_id=target_id, stage=stage, reason=reason, source_refs=source)
  store.append_event(event)
  graph = store.materialize()
  store.write_snapshot(graph)
  return IngestionResult(status="rejected", lifecycle="rejected", appended_events=1, errors=[reason], failure_case_id=event.node.id if event.node else None)


def _trace_observations(trace: dict[str, Any], agent_output: dict[str, Any]) -> list[dict[str, Any]]:
  if trace is not None and "git_observations" in trace:
    return [dict(item) for item in trace.get("git_observations") or []]
  return [dict(item) for item in agent_output.get("git_observations") or []]


def _raw_trace_observations(trace: dict[str, Any]) -> list[dict[str, Any]]:
  observations = []
  for item in trace.get("git_observations") or []:
    observation = dict(item)
    observation.pop("supports", None)
    observation.pop("contradicts", None)
    observations.append(observation)
  return observations


def _trusted_trace_observations(
  trace: dict[str, Any],
  *,
  cve_id: str,
  packet_index: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, list[str]]]:
  """Validate wrapper provenance without trusting fields reported by the agent."""
  observations: list[dict[str, Any]] = []
  trusted: dict[str, dict[str, Any]] = {}
  rejected: dict[str, list[str]] = {}
  trace_source = str(trace.get("source") or "")
  trace_cve = str(trace.get("cve_id") or "")
  trace_run_id = str(trace.get("trace_run_id") or "")
  calls = _unique_payload_map(trace.get("tool_calls") or [], "id")
  outputs = _unique_payload_map(trace.get("tool_outputs") or [], "id")
  observation_counts: dict[str, int] = {}
  for raw in trace.get("git_observations") or []:
    observation_id = str(raw.get("id") or raw.get("observation_id") or "")
    if observation_id:
      observation_counts[observation_id] = observation_counts.get(observation_id, 0) + 1

  for raw in trace.get("git_observations") or []:
    observation = dict(raw)
    observation.pop("supports", None)
    observation.pop("contradicts", None)
    observation_id = str(observation.get("id") or observation.get("observation_id") or "unknown")
    errors: list[str] = []
    if trace_source != "wrapper_git_trace":
      errors.append("trace source is not wrapper_git_trace")
    if trace_cve != cve_id or not trace_run_id:
      errors.append("trace CVE/run scope does not match ingestion scope")
    if observation.get("source") != "wrapper_git_trace":
      errors.append("observation source is not wrapper_git_trace")
    if observation.get("valid_evidence") is not True:
      errors.append("observation valid_evidence is not true")
    if not observation.get("observation_kind"):
      errors.append("observation_kind is missing")
    if observation_counts.get(observation_id, 0) != 1:
      errors.append("observation id is ambiguous")
    if str(observation.get("cve_id") or "") != cve_id or str(observation.get("trace_run_id") or "") != trace_run_id:
      errors.append("observation CVE/run scope does not match trace")

    command_ref = str(observation.get("command_ref") or "")
    tool_output_ref = str(observation.get("tool_output_ref") or "")
    tool_call = calls.get(command_ref)
    tool_output = outputs.get(tool_output_ref)
    if not tool_call:
      errors.append(f"command_ref does not resolve to a unique ToolCall: {command_ref}")
    elif not _wrapper_payload_scope_matches(tool_call, cve_id, trace_run_id):
      errors.append(f"command_ref ToolCall has invalid wrapper scope: {command_ref}")
    if not tool_output:
      errors.append(f"tool_output_ref does not resolve to a unique ToolOutput: {tool_output_ref}")
    else:
      if not _wrapper_payload_scope_matches(tool_output, cve_id, trace_run_id):
        errors.append(f"tool_output_ref ToolOutput has invalid wrapper scope: {tool_output_ref}")
      if str(tool_output.get("command_ref") or "") != command_ref:
        errors.append(f"tool_output_ref does not belong to command_ref: {tool_output_ref}")

    errors.extend(_observation_scope_errors(observation, packet_index))
    observation["trusted_for_gate"] = not errors
    observation["trust_errors"] = errors
    observations.append(observation)
    if errors:
      rejected[observation_id] = errors
    else:
      trusted[observation_id] = observation
  return observations, trusted, rejected


def _unique_payload_map(payloads: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
  counts: dict[str, int] = {}
  values: dict[str, dict[str, Any]] = {}
  for payload in payloads:
    payload_id = str(payload.get(key) or "")
    if not payload_id:
      continue
    counts[payload_id] = counts.get(payload_id, 0) + 1
    values[payload_id] = dict(payload)
  return {payload_id: payload for payload_id, payload in values.items() if counts[payload_id] == 1}


def _wrapper_payload_scope_matches(payload: dict[str, Any], cve_id: str, trace_run_id: str) -> bool:
  return (
    payload.get("source") == "wrapper_git_trace"
    and str(payload.get("cve_id") or "") == cve_id
    and str(payload.get("trace_run_id") or "") == trace_run_id
  )


def _observation_scope_errors(observation: dict[str, Any], packet_index: dict[str, Any]) -> list[str]:
  errors: list[str] = []
  scope_fields = (
    ("fix_commit_ids", "fix_commits"),
    ("patch_hunk_ids", "patch_hunks"),
    ("file_ids", "files"),
    ("function_ids", "functions"),
  )
  for field_name, index_name in scope_fields:
    values = [str(value) for value in observation.get(field_name, []) if value]
    missing = sorted(set(values) - set(packet_index[index_name]))
    if missing:
      errors.append(f"observation {field_name} are outside packet scope: {missing}")
  fix_ids = {str(value) for value in observation.get("fix_commit_ids", []) if value}
  hunk_ids = {str(value) for value in observation.get("patch_hunk_ids", []) if value}
  file_ids = {str(value) for value in observation.get("file_ids", []) if value}
  function_ids = {str(value) for value in observation.get("function_ids", []) if value}
  if not fix_ids:
    errors.append("observation fix_commit_ids scope is empty")
  for hunk_id in hunk_ids:
    expected_fix = packet_index["hunk_to_fix"].get(hunk_id)
    if expected_fix and expected_fix not in fix_ids:
      errors.append(f"PatchHunk scope {hunk_id} is inconsistent with FixCommit {expected_fix}")
  for file_id in file_ids:
    file_hunks = packet_index["file_to_hunks"].get(file_id, set())
    if hunk_ids and file_hunks and not hunk_ids.intersection(file_hunks):
      errors.append(f"File scope {file_id} is inconsistent with PatchHunk scope")
  for function_id in function_ids:
    function_hunks = packet_index["function_to_hunks"].get(function_id, set())
    if hunk_ids and function_hunks and not hunk_ids.intersection(function_hunks):
      errors.append(f"Function scope {function_id} is inconsistent with PatchHunk scope")
  return errors


def _tool_trace_events(
  run_node_id: str,
  cve_id: str,
  trace: dict[str, Any],
  source,
  command_to_output: dict[str, str],
  *,
  output_refs: dict[str, str] | None = None,
  allowed_use: str,
  target_id: str | None = None,
  run_id: str | None = None,
) -> list[GraphEvent]:
  events: list[GraphEvent] = []
  output_refs = output_refs if output_refs is not None else {}
  for tool_call in trace.get("tool_calls") or trace.get("command_invocations") or []:
    call_id = safe_id(str(tool_call.get("id") or tool_call.get("invocation_id") or "tool-call"))
    run_segment = f":{safe_id(run_id)}" if run_id else ""
    tool_node_id = f"tool-call:{safe_id(cve_id)}{run_segment}:{call_id}"
    events.append(
      node_event(
        tool_node_id,
        "ToolCall",
        "agent_run",
        allowed_use,
        source,
        {"cve_id": cve_id, "target_id": target_id, "run_id": run_id, **tool_call},
        lifecycle="raw",
        confidence=0.9,
        created_from="service_ingestion",
      )
    )
    events.append(edge_event("invokes", run_node_id, tool_node_id, "agent_run", allowed_use, source, created_from="service_ingestion"))
  tool_outputs = list(trace.get("tool_outputs") or [])
  if not tool_outputs:
    tool_outputs = [
      {"id": f"legacy-output:{tool_call.get('id')}", "command_ref": tool_call.get("id"), "text": tool_call.get("output"), "exit_code": tool_call.get("exit_code")}
      for tool_call in trace.get("tool_calls") or []
      if "output" in tool_call
    ]
  for tool_output in tool_outputs:
      output_ref = str(tool_output.get("id") or "tool-output")
      command_ref = str(tool_output.get("command_ref") or "")
      output_node_id = f"tool-output:{safe_id(cve_id)}{f':{safe_id(run_id)}' if run_id else ''}:{safe_id(output_ref)}"
      output_refs[output_ref] = output_node_id
      if command_ref:
        command_to_output[command_ref] = output_node_id
      events.append(
        node_event(
          output_node_id,
          "ToolOutput",
          "agent_run" if target_id is None else "target",
          allowed_use,
          source,
          {
            "cve_id": cve_id,
            "target_id": target_id,
            "run_id": run_id,
            **tool_output,
          },
          lifecycle="raw",
          confidence=0.9,
          created_from="service_ingestion",
        )
      )
      tool_node_id = f"tool-call:{safe_id(cve_id)}{f':{safe_id(run_id)}' if run_id else ''}:{safe_id(command_ref)}"
      events.append(edge_event("produces", tool_node_id, output_node_id, "agent_run", allowed_use, source, created_from="service_ingestion"))
  return events


def _append_git_observations(
  events: list[GraphEvent],
  cve_id: str,
  observations: list[dict[str, Any]],
  source,
  command_to_output: dict[str, str],
  *,
  output_refs: dict[str, str] | None = None,
  allowed_use: str,
  scope: str,
  target_id: str | None,
  run_id: str | None = None,
  trusted_observation_ids: set[str] | None = None,
) -> dict[str, str]:
  observation_node_ids: dict[str, str] = {}
  output_refs = output_refs or {}
  trusted_observation_ids = trusted_observation_ids if trusted_observation_ids is not None else {
    str(item.get("id") or item.get("observation_id") or "") for item in observations
  }
  for observation in observations:
    raw_obs_id = str(observation.get("id") or observation.get("observation_id") or "observation")
    obs_id = safe_id(raw_obs_id)
    run_segment = f":{safe_id(run_id)}" if run_id else ""
    node_id = f"git-observation:{safe_id(cve_id)}{run_segment}:{obs_id}"
    observation_node_ids[raw_obs_id] = node_id
    sanitized = dict(observation)
    sanitized.pop("supports", None)
    sanitized.pop("contradicts", None)
    content = {"cve_id": cve_id, "target_id": target_id, "run_id": run_id, **sanitized}
    if target_id is not None and not content.get("target_id"):
      content["target_id"] = target_id
    events.append(
      node_event(
        node_id,
        "GitObservation",
        scope,
        allowed_use if raw_obs_id in trusted_observation_ids else "context_only",
        source,
        content,
        lifecycle="raw",
        confidence=0.8,
        created_from="service_ingestion",
      )
    )
    tool_output_ref = str(observation.get("tool_output_ref") or "")
    output_node_id = output_refs.get(tool_output_ref) or command_to_output.get(str(observation.get("command_ref") or ""))
    if output_node_id:
      events.append(edge_event("derives", output_node_id, node_id, scope, allowed_use if raw_obs_id in trusted_observation_ids else "context_only", source, created_from="service_ingestion"))
  return observation_node_ids


def _prepare_anchor_nodes(
  payloads: list[dict[str, Any]],
  packet_index: dict[str, Any],
  trusted_observations: dict[str, dict[str, Any]],
  observation_rejections: dict[str, list[str]],
) -> dict[str, dict[str, Any]]:
  result: dict[str, dict[str, Any]] = {}
  for payload in payloads:
    anchor_id = _payload_id(payload, "anchor_id")
    errors = _evidence_ref_errors(payload, trusted_observations, observation_rejections)
    fix_id = str(payload.get("fix_commit_id") or "")
    hunk_id = str(payload.get("patch_hunk_id") or "")
    path = str(payload.get("path") or "")
    function = str(payload.get("function") or payload.get("symbol") or "")
    if not fix_id or fix_id not in packet_index["fix_commits"]:
      errors.append(f"anchor {anchor_id} fix_commit_id does not exist in packet: {fix_id}")
    if not hunk_id or hunk_id not in packet_index["patch_hunks"]:
      errors.append(f"anchor {anchor_id} patch_hunk_id does not exist in packet: {hunk_id}")
    if fix_id and hunk_id and packet_index["hunk_to_fix"].get(hunk_id) != fix_id:
      errors.append(f"anchor {anchor_id} PatchHunk belongs to another FixCommit")
    expected_path = str((packet_index["patch_hunks"].get(hunk_id, {}).get("content") or {}).get("path") or "")
    if expected_path and path != expected_path:
      errors.append(f"anchor {anchor_id} path conflicts with PatchHunk path")
    functions = packet_index["hunk_to_functions"].get(hunk_id, set())
    if function and functions:
      known_symbols = {str((packet_index["functions"][item].get("content") or {}).get("symbol") or "") for item in functions}
      if function not in known_symbols:
        errors.append(f"anchor {anchor_id} function conflicts with ChangedFunction")
    refs = {str(value) for value in payload.get("git_observation_refs", []) if value}
    hunk_scoped_refs = []
    file_scoped_refs = []
    for observation_id in refs.intersection(trusted_observations):
      observation = trusted_observations[observation_id]
      if fix_id not in set(observation.get("fix_commit_ids") or []):
        errors.append(f"anchor {anchor_id} observation {observation_id} does not cover FixCommit {fix_id}")
      scoped_hunks = set(observation.get("patch_hunk_ids") or [])
      if scoped_hunks:
        hunk_scoped_refs.append(scoped_hunks)
      scoped_files = set(observation.get("file_ids") or [])
      if scoped_files:
        file_scoped_refs.append(scoped_files)
    if hunk_scoped_refs and not any(hunk_id in scoped_hunks for scoped_hunks in hunk_scoped_refs):
      errors.append(f"anchor {anchor_id} has no GitObservation covering PatchHunk {hunk_id}")
    expected_file = packet_index["hunk_to_file"].get(hunk_id)
    if expected_file and file_scoped_refs and not any(expected_file in scoped_files for scoped_files in file_scoped_refs):
      errors.append(f"anchor {anchor_id} has no GitObservation covering File {expected_file}")
    result[anchor_id] = {"payload": payload, "gate_errors": list(dict.fromkeys(errors)), "gate_valid": not errors}
  return result


def _prepare_predicate_nodes(
  payloads: list[dict[str, Any]],
  anchor_map: dict[str, dict[str, Any]],
  trusted_observations: dict[str, dict[str, Any]],
  observation_rejections: dict[str, list[str]],
) -> dict[str, dict[str, Any]]:
  result: dict[str, dict[str, Any]] = {}
  for payload in payloads:
    predicate_id = _payload_id(payload, "predicate_id")
    errors = _evidence_ref_errors(payload, trusted_observations, observation_rejections)
    anchor_ids = [str(value) for value in payload.get("anchor_ids", []) if value]
    if not anchor_ids:
      errors.append(f"predicate {predicate_id} anchor_ids is empty")
    refs = {str(value) for value in payload.get("git_observation_refs", []) if value}
    for anchor_id in anchor_ids:
      anchor = anchor_map.get(anchor_id)
      if not anchor:
        errors.append(f"predicate {predicate_id} references unknown anchor {anchor_id}")
      elif not anchor["gate_valid"]:
        errors.append(f"predicate {predicate_id} references rejected anchor {anchor_id}")
      elif not refs.intersection({str(value) for value in anchor["payload"].get("git_observation_refs", []) if value}):
        errors.append(f"predicate {predicate_id} has no shared GitObservation with anchor {anchor_id}")
    result[predicate_id] = {"payload": payload, "gate_errors": list(dict.fromkeys(errors)), "gate_valid": not errors}
  return result


def _evidence_ref_errors(
  payload: dict[str, Any],
  trusted_observations: dict[str, dict[str, Any]],
  observation_rejections: dict[str, list[str]],
) -> list[str]:
  refs = {str(value) for value in payload.get("git_observation_refs", []) if value}
  errors: list[str] = []
  if not refs:
    errors.append("missing GitObservation references")
  for observation_id in sorted(refs):
    if observation_id in observation_rejections:
      errors.extend(f"GitObservation {observation_id}: {reason}" for reason in observation_rejections[observation_id])
    elif observation_id not in trusted_observations:
      errors.append(f"references non-wrapper GitObservation id: {observation_id}")
  return errors


def _finalize_semantic_lifecycles(
  hypotheses: list[dict[str, Any]],
  raw_hypothesis_ids: set[str],
  anchor_map: dict[str, dict[str, Any]],
  vulnerable_map: dict[str, dict[str, Any]],
  fix_map: dict[str, dict[str, Any]],
  guard_map: dict[str, dict[str, Any]],
  negative_map: dict[str, dict[str, Any]],
) -> None:
  raw_refs: dict[str, set[str]] = {"anchor_ids": set(), "vulnerable_predicate_ids": set(), "fix_predicate_ids": set(), "guard_condition_ids": set(), "negative_condition_ids": set()}
  rejected_refs = {key: set() for key in raw_refs}
  for hypothesis in hypotheses:
    target = raw_refs if _payload_id(hypothesis, "hypothesis_id") in raw_hypothesis_ids else rejected_refs
    for field_name in target:
      target[field_name].update(str(value) for value in hypothesis.get(field_name, []) if value)
  mappings = (
    ("anchor_ids", anchor_map),
    ("vulnerable_predicate_ids", vulnerable_map),
    ("fix_predicate_ids", fix_map),
    ("guard_condition_ids", guard_map),
    ("negative_condition_ids", negative_map),
  )
  for field_name, node_map in mappings:
    for item_id, item in node_map.items():
      if item["gate_valid"] and item_id in raw_refs[field_name]:
        item["lifecycle"] = "raw"
      elif item_id in rejected_refs[field_name] or not item["gate_valid"]:
        item["lifecycle"] = "rejected"
      else:
        item["lifecycle"] = "candidate"


def _append_prepared_semantic_nodes(
  events: list[GraphEvent],
  cve_id: str,
  run_id: str,
  source,
  observation_node_ids: dict[str, str],
  node_map: dict[str, dict[str, Any]],
  node_type: str,
  prefix: str,
) -> None:
  for payload_id, item in node_map.items():
    node_id = f"{prefix}:{safe_id(cve_id)}:{safe_id(run_id)}:{safe_id(payload_id)}"
    item["node_id"] = node_id
    payload = item["payload"]
    events.append(
      node_event(
        node_id,
        node_type,
        "cve",
        "root_cause_evidence",
        source,
        {"cve_id": cve_id, "run_id": run_id, **payload, "gate_errors": item["gate_errors"]},
        lifecycle=item["lifecycle"],
        confidence=float(payload.get("confidence", 0.7) or 0.7),
        created_from="service_ingestion",
      )
    )
    if item["lifecycle"] == "raw":
      for observation_ref in payload.get("git_observation_refs", []) or []:
        observation_node_id = observation_node_ids.get(str(observation_ref))
        if observation_node_id:
          events.append(edge_event("supports", observation_node_id, node_id, "cve", "root_cause_evidence", source, lifecycle="raw", created_from="service_ingestion"))


def _payload_id(payload: dict[str, Any], key: str) -> str:
  fallbacks = [key, "hypothesis_id", "predicate_id", "anchor_id", "condition_id", "id"]
  for candidate in fallbacks:
    value = payload.get(candidate)
    if value:
      return str(value)
  return "unknown"


def _hypothesis_gate_errors(
  hypothesis: dict[str, Any],
  *,
  trusted_observations: dict[str, dict[str, Any]],
  observation_rejections: dict[str, list[str]],
  anchor_map: dict[str, dict[str, Any]],
  vulnerable_map: dict[str, dict[str, Any]],
  fix_map: dict[str, dict[str, Any]],
  guard_map: dict[str, dict[str, Any]],
  negative_map: dict[str, dict[str, Any]],
  packet_index: dict[str, Any],
) -> tuple[list[str], dict[str, dict[str, Any]]]:
  errors = _evidence_ref_errors(hypothesis, trusted_observations, observation_rejections)
  refs = {str(value) for value in hypothesis.get("git_observation_refs", []) if value}
  for required_field in ("anchor_ids", "vulnerable_predicate_ids", "fix_predicate_ids"):
    if not hypothesis.get(required_field):
      errors.append(f"minimum root cause contract requires non-empty {required_field}")
  related = (
    ("anchor_ids", anchor_map),
    ("vulnerable_predicate_ids", vulnerable_map),
    ("fix_predicate_ids", fix_map),
    ("guard_condition_ids", guard_map),
    ("negative_condition_ids", negative_map),
  )
  for field_name, node_map in related:
    for item_id in hypothesis.get(field_name, []) or []:
      item = node_map.get(str(item_id))
      if item is None:
        errors.append(f"references unknown {field_name[:-1]}: {item_id}")
      elif not item["gate_valid"]:
        errors.append(f"references evidence-gate-rejected {field_name[:-1]}: {item_id}")
      else:
        semantic_refs = {str(value) for value in item["payload"].get("git_observation_refs", []) if value}
        if refs and not refs.intersection(semantic_refs):
          errors.append(f"has no shared GitObservation with {field_name[:-1]}: {item_id}")
  selected_anchor_ids = {str(value) for value in hypothesis.get("anchor_ids", []) if value}
  fix_set_results = _fix_set_results(packet_index, anchor_map, selected_anchor_ids)
  declared_sets = {str(value) for value in hypothesis.get("fix_set_ids", []) if value}
  declared_commits = {str(value) for value in hypothesis.get("fix_commit_ids", []) if value}
  if not declared_sets:
    declared_sets = {packet_index["fix_to_set"].get(commit_id, "") for commit_id in declared_commits}
    declared_sets.discard("")
  if not declared_sets:
    errors.append("hypothesis must declare fix_set_ids or fix_commit_ids")
  unknown_sets = sorted(declared_sets - set(fix_set_results))
  if unknown_sets:
    errors.append(f"hypothesis declares unknown fix_set_ids: {unknown_sets}")
  if declared_commits:
    outside = sorted(commit_id for commit_id in declared_commits if packet_index["fix_to_set"].get(commit_id) not in declared_sets)
    if outside:
      errors.append(f"hypothesis fix_commit_ids are outside declared fix sets: {outside}")
  complete_declared = [fix_set_id for fix_set_id in declared_sets if fix_set_results.get(fix_set_id, {}).get("complete")]
  if declared_sets and not complete_declared:
    errors.append(f"no declared fix set has complete gated CodeAnchor coverage: {sorted(declared_sets)}")
  return list(dict.fromkeys(errors)), fix_set_results


def _packet_index(packet: dict[str, Any]) -> dict[str, Any]:
  nodes = list(packet.get("patch_evidence") or []) + list(packet.get("repo_navigation") or [])
  index = {
    "fix_commits": {}, "patch_hunks": {}, "files": {}, "functions": {},
    "hunk_to_fix": {}, "hunk_to_file": {}, "hunk_to_functions": {},
    "file_to_hunks": {}, "function_to_hunks": {}, "fix_sets": {}, "fix_to_set": {},
  }
  for node in nodes:
    node_id = str(node.get("id") or "")
    node_type = node.get("type")
    if node_type == "FixCommit":
      index["fix_commits"][node_id] = node
    elif node_type == "PatchHunk":
      index["patch_hunks"][node_id] = node
    elif node_type in {"File", "ChangedFile", "FilePath"}:
      index["files"][node_id] = node
    elif node_type in {"ChangedFunction", "Function", "FunctionSymbol"}:
      index["functions"][node_id] = node
  fix_by_sha = {str((node.get("content") or {}).get("commit_sha") or ""): node_id for node_id, node in index["fix_commits"].items()}
  files_by_path = {str((node.get("content") or {}).get("path") or ""): node_id for node_id, node in index["files"].items()}
  for hunk_id, hunk in index["patch_hunks"].items():
    content = hunk.get("content") or {}
    fix_id = fix_by_sha.get(str(content.get("commit_sha") or ""))
    if fix_id:
      index["hunk_to_fix"][hunk_id] = fix_id
    file_id = files_by_path.get(str(content.get("path") or ""))
    if file_id:
      index["hunk_to_file"][hunk_id] = file_id
      index["file_to_hunks"].setdefault(file_id, set()).add(hunk_id)
    explicit_function_id = str(content.get("function_id") or "")
    matching_functions = {explicit_function_id} if explicit_function_id in index["functions"] else set()
    index["hunk_to_functions"][hunk_id] = matching_functions
    for function_id in matching_functions:
      index["function_to_hunks"].setdefault(function_id, set()).add(hunk_id)
  missing_fix_set = []
  for fix_id, fix in index["fix_commits"].items():
    fix_set_id = str((fix.get("content") or {}).get("fix_set_id") or "")
    if not fix_set_id:
      missing_fix_set.append(fix_id)
      continue
    index["fix_sets"].setdefault(fix_set_id, []).append(fix_id)
    index["fix_to_set"][fix_id] = fix_set_id
  if missing_fix_set and len(index["fix_commits"]) == 1:
    fix_id = missing_fix_set[0]
    fix_set_id = f"single-fix:{fix_id}"
    index["fix_sets"][fix_set_id] = [fix_id]
    index["fix_to_set"][fix_id] = fix_set_id
  index["missing_fix_set_ids"] = missing_fix_set if len(index["fix_commits"]) > 1 else []
  for fix_set_id in index["fix_sets"]:
    index["fix_sets"][fix_set_id].sort(key=lambda fix_id: int((index["fix_commits"][fix_id].get("content") or {}).get("order") or 0))
  return index


def _fix_set_results(packet_index: dict[str, Any], anchor_map: dict[str, dict[str, Any]], selected_anchor_ids: set[str]) -> dict[str, dict[str, Any]]:
  covered: dict[str, set[str]] = {}
  invalid_by_set: dict[str, list[str]] = {}
  for anchor_id in selected_anchor_ids:
    anchor = anchor_map.get(anchor_id)
    if not anchor:
      continue
    fix_id = str(anchor["payload"].get("fix_commit_id") or "")
    fix_set_id = packet_index["fix_to_set"].get(fix_id)
    if not fix_set_id:
      continue
    if anchor["gate_valid"]:
      covered.setdefault(fix_set_id, set()).add(fix_id)
    else:
      invalid_by_set.setdefault(fix_set_id, []).append(anchor_id)
  results: dict[str, dict[str, Any]] = {}
  for fix_set_id, expected in packet_index["fix_sets"].items():
    expected_set = set(expected)
    covered_set = covered.get(fix_set_id, set())
    results[fix_set_id] = {
      "expected_fix_commits": list(expected),
      "covered_fix_commits": sorted(covered_set),
      "missing_fix_commits": sorted(expected_set - covered_set),
      "invalid_anchor_ids": sorted(invalid_by_set.get(fix_set_id, [])),
      "complete": expected_set == covered_set and bool(expected_set),
    }
  if packet_index["missing_fix_set_ids"]:
    results["legacy_unverifiable"] = {
      "expected_fix_commits": sorted(packet_index["missing_fix_set_ids"]),
      "covered_fix_commits": [],
      "missing_fix_commits": sorted(packet_index["missing_fix_set_ids"]),
      "invalid_anchor_ids": [],
      "complete": False,
    }
  return results


def _rejected_ids_from_errors(errors: list[str]) -> list[str]:
  ids: set[str] = set()
  for error in errors:
    for token in error.replace("[", " ").replace("]", " ").replace(",", " ").split():
      token = token.strip("'\"")
      if ":" in token or token.startswith(("obs-", "a-", "vp-", "fp-")):
        ids.add(token)
  return sorted(ids)


def _link_many(
  events: list[GraphEvent],
  source_node_id: str,
  edge_type: str,
  ids: list[str],
  node_map: dict[str, dict[str, Any]],
  source,
  lifecycle: str,
) -> None:
  for item_id in ids:
    if item_id in node_map:
      events.append(edge_event(edge_type, source_node_id, node_map[item_id]["node_id"], "cve", "root_cause_evidence", source, lifecycle=lifecycle, created_from="service_ingestion"))

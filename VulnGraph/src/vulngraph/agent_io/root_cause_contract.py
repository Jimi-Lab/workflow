from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any


TAXONOMY_KEYS = (
  "missing_anchor_path",
  "missing_fix_commit_id",
  "missing_patch_hunk_id",
  "anchor_hunk_commit_mismatch",
  "unknown_function_id",
  "function_name_without_function_id",
  "function_hunk_mismatch",
  "function_symbol_mismatch",
  "function_id_function_alias_mismatch",
  "predicate_without_anchor",
  "fix_predicate_without_anchor",
  "condition_without_anchor",
  "weak_predicate_evidence",
  "semantic_node_without_shared_observation",
  "explanatory_anchor_in_required_refs",
  "unknown_observation_ref",
  "observation_provenance",
  "observation_scope",
  "duplicate_semantic_id",
  "empty_semantic_id",
  "fix_set_incomplete",
  "incomplete_function_hunk_coverage",
  "hypothesis_mentions_unanchored_function",
  "broad_anchor_coverage",
  "consequence_stated_as_root_cause",
  "overbroad_vulnerability_effect",
  "unsupported_trigger_condition",
  "other",
)


@dataclass(frozen=True)
class StructuralValidationResult:
  packet_index: dict[str, Any]
  trusted_observations: dict[str, dict[str, Any]]
  observation_rejections: dict[str, list[str]]
  observation_payloads: list[dict[str, Any]]
  anchor_results: dict[str, dict[str, Any]]
  vulnerable_predicate_results: dict[str, dict[str, Any]]
  fix_predicate_results: dict[str, dict[str, Any]]
  guard_condition_results: dict[str, dict[str, Any]]
  negative_condition_results: dict[str, dict[str, Any]]
  hypothesis_results: dict[str, dict[str, Any]]
  fix_set_results: dict[str, dict[str, Any]]
  accepted_hypothesis_ids: list[str]
  rejected_hypothesis_ids: list[str]
  errors: list[str]
  taxonomy: dict[str, int]
  invented_ids: list[str]
  binding_complete_rate: float
  ok: bool

  def to_dict(self) -> dict[str, Any]:
    return _json_safe(
      {
        "packet_index": self.packet_index,
        "trusted_observations": self.trusted_observations,
        "observation_rejections": self.observation_rejections,
        "observation_payloads": self.observation_payloads,
        "anchor_results": self.anchor_results,
        "vulnerable_predicate_results": self.vulnerable_predicate_results,
        "fix_predicate_results": self.fix_predicate_results,
        "guard_condition_results": self.guard_condition_results,
        "negative_condition_results": self.negative_condition_results,
        "hypothesis_results": self.hypothesis_results,
        "fix_set_results": self.fix_set_results,
        "accepted_hypothesis_ids": self.accepted_hypothesis_ids,
        "rejected_hypothesis_ids": self.rejected_hypothesis_ids,
        "errors": self.errors,
        "taxonomy": self.taxonomy,
        "invented_ids": self.invented_ids,
        "binding_complete_rate": self.binding_complete_rate,
        "ok": self.ok,
      }
    )


@dataclass(frozen=True)
class ContractLintResult:
  ok: bool
  errors: list[str] = field(default_factory=list)
  taxonomy: dict[str, int] = field(default_factory=dict)
  invented_ids: list[str] = field(default_factory=list)
  binding_complete_rate: float = 0.0
  details: dict[str, Any] = field(default_factory=dict)

  def to_dict(self) -> dict[str, Any]:
    return {
      "ok": self.ok,
      "errors": list(self.errors),
      "taxonomy": dict(self.taxonomy),
      "invented_ids": list(self.invented_ids),
      "binding_complete_rate": self.binding_complete_rate,
      "details": self.details,
    }


def lint_root_cause_contract(agent_output: dict[str, Any], packet: dict[str, Any], trace: dict[str, Any]) -> ContractLintResult:
  validation = validate_root_cause_structure(agent_output, packet, trace)
  return ContractLintResult(
    ok=validation.ok,
    errors=list(validation.errors),
    taxonomy=dict(validation.taxonomy),
    invented_ids=list(validation.invented_ids),
    binding_complete_rate=validation.binding_complete_rate,
    details={
      "hypotheses": {key: value["gate_errors"] for key, value in validation.hypothesis_results.items()},
      "anchors": {key: value["gate_errors"] for key, value in validation.anchor_results.items()},
      "predicates": {
        **{f"vulnerable:{key}": value["gate_errors"] for key, value in validation.vulnerable_predicate_results.items()},
        **{f"fix:{key}": value["gate_errors"] for key, value in validation.fix_predicate_results.items()},
        **{f"guard:{key}": value["gate_errors"] for key, value in validation.guard_condition_results.items()},
        **{f"negative:{key}": value["gate_errors"] for key, value in validation.negative_condition_results.items()},
      },
    },
  )


def validate_root_cause_structure(
  agent_output: dict[str, Any],
  packet: dict[str, Any],
  trace: dict[str, Any],
) -> StructuralValidationResult:
  """Compute the complete Root Cause structural gate without side effects."""
  packet_index = build_packet_index(packet)
  cve_id = str(packet.get("cve_id") or (agent_output.get("agent_run") or {}).get("cve_id") or trace.get("cve_id") or "")
  observation_payloads, trusted_observations, observation_rejections = validate_wrapper_trace(
    trace,
    cve_id=cve_id,
    packet_index=packet_index,
  )
  taxonomy: Counter[str] = Counter()
  invented_ids: set[str] = set()
  global_errors = _semantic_id_errors(agent_output, taxonomy)

  hypotheses = list(agent_output.get("root_cause_hypotheses") or [])
  referenced_anchor_ids = {
    anchor_id for hypothesis in hypotheses for anchor_id in _list(hypothesis, "anchor_ids", "code_anchor_ids")
  }
  referenced_guard_ids = {item for hypothesis in hypotheses for item in _list(hypothesis, "guard_condition_ids")}
  referenced_negative_ids = {item for hypothesis in hypotheses for item in _list(hypothesis, "negative_condition_ids")}

  anchor_results = _prepare_anchor_results(
    list(agent_output.get("code_anchors") or []),
    packet_index,
    trusted_observations,
    observation_rejections,
    referenced_anchor_ids,
    taxonomy,
    invented_ids,
  )
  vulnerable_results = _prepare_predicate_results(
    list(agent_output.get("vulnerable_predicates") or []), anchor_results, trusted_observations,
    observation_rejections, taxonomy, invented_ids, kind="vulnerable", required_ids=None,
  )
  fix_results = _prepare_predicate_results(
    list(agent_output.get("fix_predicates") or []), anchor_results, trusted_observations,
    observation_rejections, taxonomy, invented_ids, kind="fix", required_ids=None,
  )
  guard_results = _prepare_predicate_results(
    list(agent_output.get("guard_conditions") or []), anchor_results, trusted_observations,
    observation_rejections, taxonomy, invented_ids, kind="guard", required_ids=referenced_guard_ids,
  )
  negative_results = _prepare_predicate_results(
    list(agent_output.get("negative_conditions") or agent_output.get("negative_applicability_conditions") or []),
    anchor_results, trusted_observations, observation_rejections, taxonomy, invented_ids,
    kind="negative", required_ids=referenced_negative_ids,
  )

  duplicate_ids = _duplicate_semantic_ids(agent_output)
  hypothesis_results: dict[str, dict[str, Any]] = {}
  accepted_hypothesis_ids: list[str] = []
  rejected_hypothesis_ids: list[str] = []
  hypothesis_counts = Counter(_raw_payload_id(item, "hypothesis_id") for item in hypotheses)
  for hypothesis in hypotheses:
    hypothesis_id = _payload_id(hypothesis, "hypothesis_id")
    errors = list(global_errors)
    if not hypothesis_id or hypothesis_counts[hypothesis_id] != 1 or hypothesis_id in duplicate_ids:
      errors.append(f"hypothesis {hypothesis_id or '<empty>'} has a duplicate or empty semantic ID")
    gate_errors, hypothesis_fix_sets = _hypothesis_errors(
      hypothesis,
      trusted_observations=trusted_observations,
      observation_rejections=observation_rejections,
      anchor_results=anchor_results,
      vulnerable_results=vulnerable_results,
      fix_results=fix_results,
      guard_results=guard_results,
      negative_results=negative_results,
      packet_index=packet_index,
      taxonomy=taxonomy,
      invented_ids=invented_ids,
    )
    _record_hypothesis_warnings(
      hypothesis,
      anchor_results=anchor_results,
      vulnerable_results=vulnerable_results,
      fix_results=fix_results,
      packet_index=packet_index,
      taxonomy=taxonomy,
    )
    errors.extend(gate_errors)
    errors = list(dict.fromkeys(errors))
    lifecycle = "raw" if not errors else "rejected"
    hypothesis_results[hypothesis_id or "<empty>"] = {
      "payload": hypothesis,
      "gate_valid": not errors,
      "gate_errors": errors,
      "lifecycle": lifecycle,
      "errors": errors,
      "fix_set_results": hypothesis_fix_sets,
      "rejected_ids": _rejected_ids(errors),
    }
    (accepted_hypothesis_ids if not errors else rejected_hypothesis_ids).append(hypothesis_id or "<empty>")

  required_errors: list[str] = list(global_errors)
  for anchor_id in referenced_anchor_ids:
    item = anchor_results.get(anchor_id)
    if item:
      required_errors.extend(item["gate_errors"])
  for results, required_ids in (
    (guard_results, referenced_guard_ids),
    (negative_results, referenced_negative_ids),
  ):
    for item_id in required_ids:
      item = results.get(item_id)
      if item:
        required_errors.extend(item["gate_errors"])
  required_errors.extend(error for item in hypothesis_results.values() for error in item["gate_errors"])
  errors = list(dict.fromkeys(required_errors))
  fix_set_results = fix_set_results_for_anchors(packet_index, anchor_results, set(anchor_results))
  binding_complete_rate = round(len(accepted_hypothesis_ids) / len(hypotheses), 3) if hypotheses else 0.0
  normalized_taxonomy = {key: int(taxonomy[key]) for key in TAXONOMY_KEYS if taxonomy[key]}
  return StructuralValidationResult(
    packet_index=packet_index,
    trusted_observations=trusted_observations,
    observation_rejections=observation_rejections,
    observation_payloads=observation_payloads,
    anchor_results=anchor_results,
    vulnerable_predicate_results=vulnerable_results,
    fix_predicate_results=fix_results,
    guard_condition_results=guard_results,
    negative_condition_results=negative_results,
    hypothesis_results=hypothesis_results,
    fix_set_results=fix_set_results,
    accepted_hypothesis_ids=accepted_hypothesis_ids,
    rejected_hypothesis_ids=rejected_hypothesis_ids,
    errors=errors,
    taxonomy=normalized_taxonomy,
    invented_ids=sorted(invented_ids),
    binding_complete_rate=binding_complete_rate,
    ok=bool(hypotheses) and not rejected_hypothesis_ids,
  )


def build_packet_index(packet: dict[str, Any]) -> dict[str, Any]:
  nodes = [node for section in ("patch_evidence", "repo_navigation") for node in packet.get(section) or []]
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
    function_id = str(content.get("function_id") or "")
    functions = {function_id} if function_id in index["functions"] else set()
    index["hunk_to_functions"][hunk_id] = functions
    for item in functions:
      index["function_to_hunks"].setdefault(item, set()).add(hunk_id)
  missing_fix_set_ids = []
  for fix_id, fix in index["fix_commits"].items():
    fix_set_id = str((fix.get("content") or {}).get("fix_set_id") or "")
    if not fix_set_id:
      missing_fix_set_ids.append(fix_id)
      continue
    index["fix_sets"].setdefault(fix_set_id, []).append(fix_id)
    index["fix_to_set"][fix_id] = fix_set_id
  if missing_fix_set_ids and len(index["fix_commits"]) == 1:
    fix_id = missing_fix_set_ids[0]
    fix_set_id = f"single-fix:{fix_id}"
    index["fix_sets"][fix_set_id] = [fix_id]
    index["fix_to_set"][fix_id] = fix_set_id
    missing_fix_set_ids = []
  index["missing_fix_set_ids"] = missing_fix_set_ids
  for fix_set_id, fix_ids in index["fix_sets"].items():
    fix_ids.sort(key=lambda item: int((index["fix_commits"][item].get("content") or {}).get("order") or 0))
  return index


def validate_wrapper_trace(
  trace: dict[str, Any], *, cve_id: str, packet_index: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, list[str]]]:
  observations: list[dict[str, Any]] = []
  trusted: dict[str, dict[str, Any]] = {}
  rejected: dict[str, list[str]] = {}
  trace_source = str(trace.get("source") or "")
  trace_cve = str(trace.get("cve_id") or "")
  trace_run_id = str(trace.get("trace_run_id") or "")
  calls = _unique_payload_map(trace.get("tool_calls") or [], "id")
  outputs = _unique_payload_map(trace.get("tool_outputs") or [], "id")
  counts = Counter(str(item.get("id") or item.get("observation_id") or "") for item in trace.get("git_observations") or [])
  for raw in trace.get("git_observations") or []:
    observation = dict(raw)
    observation.pop("supports", None)
    observation.pop("contradicts", None)
    observation_id = str(observation.get("id") or observation.get("observation_id") or "")
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
    if not observation_id or counts[observation_id] != 1:
      errors.append("observation id is empty or ambiguous")
    if str(observation.get("cve_id") or "") != cve_id or str(observation.get("trace_run_id") or "") != trace_run_id:
      errors.append("observation CVE/run scope does not match trace")
    command_ref = str(observation.get("command_ref") or "")
    output_ref = str(observation.get("tool_output_ref") or "")
    call = calls.get(command_ref)
    output = outputs.get(output_ref)
    if not call:
      errors.append(f"command_ref does not resolve to a unique ToolCall: {command_ref}")
    elif not _wrapper_scope_matches(call, cve_id, trace_run_id):
      errors.append(f"command_ref ToolCall has invalid wrapper scope: {command_ref}")
    if not output:
      errors.append(f"tool_output_ref does not resolve to a unique ToolOutput: {output_ref}")
    else:
      if not _wrapper_scope_matches(output, cve_id, trace_run_id):
        errors.append(f"tool_output_ref ToolOutput has invalid wrapper scope: {output_ref}")
      if str(output.get("command_ref") or "") != command_ref:
        errors.append(f"tool_output_ref does not belong to command_ref: {output_ref}")
    errors.extend(_observation_scope_errors(observation, packet_index))
    observation["trusted_for_gate"] = not errors
    observation["trust_errors"] = errors
    observations.append(observation)
    if errors:
      rejected[observation_id or "<empty>"] = errors
    else:
      trusted[observation_id] = observation
  return observations, trusted, rejected


def fix_set_results_for_anchors(
  packet_index: dict[str, Any], anchor_results: dict[str, dict[str, Any]], selected_anchor_ids: set[str]
) -> dict[str, dict[str, Any]]:
  covered: dict[str, set[str]] = {}
  invalid: dict[str, list[str]] = {}
  for anchor_id in selected_anchor_ids:
    anchor = anchor_results.get(anchor_id)
    if not anchor:
      continue
    fix_id = str(anchor["payload"].get("fix_commit_id") or "")
    fix_set_id = packet_index["fix_to_set"].get(fix_id)
    if not fix_set_id:
      continue
    if anchor["gate_valid"]:
      covered.setdefault(fix_set_id, set()).add(fix_id)
    else:
      invalid.setdefault(fix_set_id, []).append(anchor_id)
  results = {}
  for fix_set_id, expected in packet_index["fix_sets"].items():
    expected_set = set(expected)
    covered_set = covered.get(fix_set_id, set())
    results[fix_set_id] = {
      "expected_fix_commits": list(expected),
      "covered_fix_commits": sorted(covered_set),
      "missing_fix_commits": sorted(expected_set - covered_set),
      "invalid_anchor_ids": sorted(invalid.get(fix_set_id, [])),
      "complete": bool(expected_set) and expected_set == covered_set,
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


def _prepare_anchor_results(
  payloads: list[dict[str, Any]], packet_index: dict[str, Any], trusted: dict[str, dict[str, Any]],
  rejected: dict[str, list[str]], required_ids: set[str], taxonomy: Counter[str], invented_ids: set[str],
) -> dict[str, dict[str, Any]]:
  counts = Counter(_raw_payload_id(item, "anchor_id") for item in payloads)
  results: dict[str, dict[str, Any]] = {}
  for payload in payloads:
    anchor_id = _payload_id(payload, "anchor_id")
    errors = _evidence_ref_errors(payload, trusted, rejected, taxonomy, invented_ids)
    if not anchor_id:
      _add(errors, taxonomy, "empty_semantic_id", "CodeAnchor anchor_id is empty")
    elif counts[anchor_id] != 1:
      _add(errors, taxonomy, "duplicate_semantic_id", f"duplicate CodeAnchor ID: {anchor_id}")
    fix_id = str(payload.get("fix_commit_id") or "")
    hunk_id = str(payload.get("patch_hunk_id") or "")
    if not fix_id:
      _add(errors, taxonomy, "missing_fix_commit_id", f"anchor {anchor_id} missing fix_commit_id")
    elif fix_id not in packet_index["fix_commits"]:
      invented_ids.add(fix_id)
      _add(errors, taxonomy, "missing_fix_commit_id", f"anchor {anchor_id} references unknown fix_commit_id: {fix_id}")
    if not hunk_id:
      _add(errors, taxonomy, "missing_patch_hunk_id", f"anchor {anchor_id} missing patch_hunk_id")
    elif hunk_id not in packet_index["patch_hunks"]:
      invented_ids.add(hunk_id)
      _add(errors, taxonomy, "missing_patch_hunk_id", f"anchor {anchor_id} references unknown patch_hunk_id: {hunk_id}")
    if anchor_id in required_ids and (not fix_id or not hunk_id):
      _add(errors, taxonomy, "explanatory_anchor_in_required_refs", f"anchor {anchor_id} is required but is not patch-bound")
    if fix_id and hunk_id and packet_index["hunk_to_fix"].get(hunk_id) != fix_id:
      _add(errors, taxonomy, "anchor_hunk_commit_mismatch", f"anchor {anchor_id} PatchHunk does not belong to FixCommit")
    hunk_content = (packet_index["patch_hunks"].get(hunk_id, {}).get("content") or {})
    expected_path = str(hunk_content.get("path") or "")
    path = str(payload.get("path") or "")
    if not path:
      _add(errors, taxonomy, "missing_anchor_path", f"anchor {anchor_id} missing path")
    elif expected_path and path != expected_path:
      _add(errors, taxonomy, "other", f"anchor {anchor_id} path conflicts with PatchHunk path")
    file_id = str(payload.get("file_id") or "")
    if file_id:
      if file_id not in packet_index["files"]:
        invented_ids.add(file_id)
        _add(errors, taxonomy, "observation_scope", f"anchor {anchor_id} references unknown file_id: {file_id}")
      elif packet_index["hunk_to_file"].get(hunk_id) != file_id:
        _add(errors, taxonomy, "observation_scope", f"anchor {anchor_id} file_id does not belong to PatchHunk")
    function_id = str(payload.get("function_id") or "")
    function = str(payload.get("function") or payload.get("function_name") or "")
    if payload.get("function") and payload.get("function_name") and payload.get("function") != payload.get("function_name"):
      _add(errors, taxonomy, "function_id_function_alias_mismatch", f"anchor {anchor_id} function and function_name conflict")
    if function and not function_id:
      _add(errors, taxonomy, "function_name_without_function_id", f"anchor {anchor_id} names a function without function_id")
    if function_id:
      if function_id not in packet_index["functions"]:
        invented_ids.add(function_id)
        _add(errors, taxonomy, "unknown_function_id", f"anchor {anchor_id} function_id does not exist in packet: {function_id}")
      elif function_id not in packet_index["hunk_to_functions"].get(hunk_id, set()):
        _add(errors, taxonomy, "function_hunk_mismatch", f"anchor {anchor_id} function_id does not belong to PatchHunk")
      else:
        symbol = str((packet_index["functions"][function_id].get("content") or {}).get("symbol") or "")
        if function and function != symbol:
          _add(errors, taxonomy, "function_id_function_alias_mismatch", f"anchor {anchor_id} function conflicts with function_id symbol")
    refs = {str(item) for item in payload.get("git_observation_refs") or [] if item}
    covering = []
    for ref in refs.intersection(trusted):
      observation = trusted[ref]
      if fix_id in set(observation.get("fix_commit_ids") or []) and hunk_id in set(observation.get("patch_hunk_ids") or []):
        covering.append(observation)
    if fix_id and hunk_id and not covering:
      _add(errors, taxonomy, "semantic_node_without_shared_observation", f"anchor {anchor_id} has no trusted observation covering FixCommit and PatchHunk")
    if file_id and covering and not any(file_id in set(item.get("file_ids") or []) for item in covering):
      _add(errors, taxonomy, "observation_scope", f"anchor {anchor_id} has no trusted observation covering file_id")
    if function_id and covering and not any(function_id in set(item.get("function_ids") or []) for item in covering):
      _add(errors, taxonomy, "observation_scope", f"anchor {anchor_id} has no trusted observation covering function_id")
    results.setdefault(anchor_id or "<empty>", {"payload": payload, "gate_valid": not errors, "gate_errors": list(dict.fromkeys(errors))})
  return results


def _prepare_predicate_results(
  payloads: list[dict[str, Any]], anchor_results: dict[str, dict[str, Any]], trusted: dict[str, dict[str, Any]],
  rejected: dict[str, list[str]], taxonomy: Counter[str], invented_ids: set[str], *, kind: str,
  required_ids: set[str] | None,
) -> dict[str, dict[str, Any]]:
  counts = Counter(_raw_payload_id(item, "predicate_id") for item in payloads)
  results = {}
  for payload in payloads:
    predicate_id = _payload_id(payload, "predicate_id")
    required = required_ids is None or predicate_id in required_ids
    errors = _evidence_ref_errors(payload, trusted, rejected, taxonomy, invented_ids) if required else []
    if not predicate_id:
      _add(errors, taxonomy, "empty_semantic_id", f"{kind} predicate ID is empty")
    elif counts[predicate_id] != 1:
      _add(errors, taxonomy, "duplicate_semantic_id", f"duplicate predicate ID: {predicate_id}")
    anchor_ids = _list(payload, "anchor_ids", "code_anchor_ids")
    if required and not anchor_ids:
      category = "fix_predicate_without_anchor" if kind == "fix" else "condition_without_anchor" if kind in {"guard", "negative"} else "predicate_without_anchor"
      _add(errors, taxonomy, category, f"{kind} predicate {predicate_id} has no gated anchor")
    refs = {str(item) for item in payload.get("git_observation_refs") or [] if item}
    if required and kind in {"vulnerable", "fix"}:
      patch_diff_refs = [
        ref for ref in refs
        if ref in trusted and trusted[ref].get("observation_kind") == "patch_diff"
      ]
      if not patch_diff_refs:
        _add(errors, taxonomy, "weak_predicate_evidence", f"{kind} predicate {predicate_id} lacks patch_diff GitObservation evidence")
    for anchor_id in anchor_ids:
      anchor = anchor_results.get(anchor_id)
      if not anchor:
        invented_ids.add(anchor_id)
        _add(errors, taxonomy, "predicate_without_anchor", f"{kind} predicate {predicate_id} references unknown anchor {anchor_id}")
      elif not anchor["gate_valid"]:
        _add(errors, taxonomy, "predicate_without_anchor", f"{kind} predicate {predicate_id} references rejected anchor {anchor_id}")
      elif not refs.intersection(set(anchor["payload"].get("git_observation_refs") or [])):
        _add(errors, taxonomy, "semantic_node_without_shared_observation", f"{kind} predicate {predicate_id} has no shared GitObservation with anchor {anchor_id}")
    results.setdefault(predicate_id or "<empty>", {"payload": payload, "gate_valid": required and not errors, "gate_errors": list(dict.fromkeys(errors)), "required": required})
  return results


def _hypothesis_errors(
  hypothesis: dict[str, Any], *, trusted_observations: dict[str, dict[str, Any]], observation_rejections: dict[str, list[str]],
  anchor_results: dict[str, dict[str, Any]], vulnerable_results: dict[str, dict[str, Any]], fix_results: dict[str, dict[str, Any]],
  guard_results: dict[str, dict[str, Any]], negative_results: dict[str, dict[str, Any]], packet_index: dict[str, Any],
  taxonomy: Counter[str], invented_ids: set[str],
) -> tuple[list[str], dict[str, dict[str, Any]]]:
  hypothesis_id = _payload_id(hypothesis, "hypothesis_id")
  errors = _evidence_ref_errors(hypothesis, trusted_observations, observation_rejections, taxonomy, invented_ids)
  refs = {str(item) for item in hypothesis.get("git_observation_refs") or [] if item}
  required = (
    ("anchor_ids", anchor_results),
    ("vulnerable_predicate_ids", vulnerable_results),
    ("fix_predicate_ids", fix_results),
  )
  for field_name, result_map in required:
    if not hypothesis.get(field_name):
      _add(errors, taxonomy, "fix_predicate_without_anchor" if field_name == "fix_predicate_ids" else "predicate_without_anchor", f"minimum root cause contract requires non-empty {field_name}")
    _validate_hypothesis_refs(hypothesis_id, field_name, hypothesis.get(field_name) or [], result_map, refs, errors, taxonomy, invented_ids)
  _validate_hypothesis_refs(hypothesis_id, "guard_condition_ids", hypothesis.get("guard_condition_ids") or [], guard_results, refs, errors, taxonomy, invented_ids)
  _validate_hypothesis_refs(hypothesis_id, "negative_condition_ids", hypothesis.get("negative_condition_ids") or [], negative_results, refs, errors, taxonomy, invented_ids)
  selected_anchor_ids = {str(item) for item in hypothesis.get("anchor_ids") or [] if item}
  fix_sets = fix_set_results_for_anchors(packet_index, anchor_results, selected_anchor_ids)
  declared_sets = {str(item) for item in hypothesis.get("fix_set_ids") or [] if item}
  declared_commits = {str(item) for item in hypothesis.get("fix_commit_ids") or [] if item}
  if not declared_sets or not declared_commits:
    _add(errors, taxonomy, "fix_set_incomplete", f"hypothesis {hypothesis_id} missing fix_set_ids or fix_commit_ids")
  unknown_sets = declared_sets - set(packet_index["fix_sets"])
  unknown_commits = declared_commits - set(packet_index["fix_commits"])
  if unknown_sets:
    invented_ids.update(unknown_sets)
    _add(errors, taxonomy, "fix_set_incomplete", f"hypothesis {hypothesis_id} references unknown fix_set_ids: {sorted(unknown_sets)}")
  if unknown_commits:
    invented_ids.update(unknown_commits)
    _add(errors, taxonomy, "fix_set_incomplete", f"hypothesis {hypothesis_id} references unknown fix_commit_ids: {sorted(unknown_commits)}")
  outside = sorted(item for item in declared_commits if packet_index["fix_to_set"].get(item) not in declared_sets)
  if outside:
    _add(errors, taxonomy, "fix_set_incomplete", f"hypothesis {hypothesis_id} fix_commit_ids are outside declared fix sets: {outside}")
  if declared_sets and not any(fix_sets.get(item, {}).get("complete") for item in declared_sets):
    _add(errors, taxonomy, "fix_set_incomplete", f"no declared fix set has complete gated CodeAnchor coverage: {sorted(declared_sets)}")
  return list(dict.fromkeys(errors)), fix_sets


def _record_hypothesis_warnings(
  hypothesis: dict[str, Any], *, anchor_results: dict[str, dict[str, Any]],
  vulnerable_results: dict[str, dict[str, Any]], fix_results: dict[str, dict[str, Any]],
  packet_index: dict[str, Any], taxonomy: Counter[str],
) -> None:
  text_parts = [
    str(hypothesis.get("summary") or ""),
    str(hypothesis.get("mechanism") or ""),
  ]
  for field_name, results in (("vulnerable_predicate_ids", vulnerable_results), ("fix_predicate_ids", fix_results)):
    for item_id in hypothesis.get(field_name) or []:
      payload = (results.get(str(item_id)) or {}).get("payload") or {}
      text_parts.append(str(payload.get("description") or payload.get("statement") or ""))
  combined = "\n".join(text_parts)
  anchored_function_ids = {
    str((anchor_results.get(str(anchor_id)) or {}).get("payload", {}).get("function_id") or "")
    for anchor_id in hypothesis.get("anchor_ids") or []
  }
  anchored_function_ids.discard("")
  mentioned_unanchored = []
  for function_id, node in packet_index.get("functions", {}).items():
    symbol = str((node.get("content") or {}).get("symbol") or "")
    if symbol and _mentions_symbol(combined, symbol) and function_id not in anchored_function_ids:
      mentioned_unanchored.append(symbol)
  if mentioned_unanchored:
    taxonomy["hypothesis_mentions_unanchored_function"] += len(mentioned_unanchored)
    taxonomy["incomplete_function_hunk_coverage"] += 1
    if len(mentioned_unanchored) > 1 or len(mentioned_unanchored) >= len(anchored_function_ids):
      taxonomy["broad_anchor_coverage"] += 1
  lower = combined.lower()
  if any(phrase in lower for phrase in ("could lead to", "could cause", "potential ", "may lead to", "may cause")):
    taxonomy["consequence_stated_as_root_cause"] += 1
  if any(phrase in lower for phrase in ("buffer overflow", "out-of-bounds", "oob", "division by zero", "integer overflow", "cycle detection")):
    taxonomy["overbroad_vulnerability_effect"] += 1
  if any(phrase in lower for phrase in ("attacker can", "triggered when", "crafted input", "malicious input")) and "diff" not in lower and "patch" not in lower:
    taxonomy["unsupported_trigger_condition"] += 1


def _validate_hypothesis_refs(
  hypothesis_id: str, field_name: str, values: list[Any], result_map: dict[str, dict[str, Any]], refs: set[str],
  errors: list[str], taxonomy: Counter[str], invented_ids: set[str],
) -> None:
  for raw_id in values:
    item_id = str(raw_id)
    item = result_map.get(item_id)
    if not item:
      invented_ids.add(item_id)
      _add(errors, taxonomy, "other", f"hypothesis {hypothesis_id} references unknown {field_name[:-1]}: {item_id}")
    elif not item["gate_valid"]:
      errors.append(f"hypothesis {hypothesis_id} references rejected {field_name[:-1]}: {item_id}")
    elif not refs.intersection(set(item["payload"].get("git_observation_refs") or [])):
      _add(errors, taxonomy, "semantic_node_without_shared_observation", f"hypothesis {hypothesis_id} has no shared GitObservation with {field_name[:-1]}: {item_id}")


def _evidence_ref_errors(
  payload: dict[str, Any], trusted: dict[str, dict[str, Any]], rejected: dict[str, list[str]],
  taxonomy: Counter[str], invented_ids: set[str],
) -> list[str]:
  refs = _list(payload, "git_observation_refs")
  errors = []
  if not refs:
    _add(errors, taxonomy, "unknown_observation_ref", "semantic node missing git_observation_refs")
  for ref in refs:
    if ref in rejected:
      category = "observation_scope" if any("scope" in item or "outside packet" in item for item in rejected[ref]) else "observation_provenance"
      _add(errors, taxonomy, category, f"GitObservation {ref} is not trusted: {rejected[ref]}")
    elif ref not in trusted:
      invented_ids.add(ref)
      _add(errors, taxonomy, "unknown_observation_ref", f"references unknown GitObservation id: {ref}")
  return errors


def _observation_scope_errors(observation: dict[str, Any], packet_index: dict[str, Any]) -> list[str]:
  errors = []
  for field_name, index_name in (("fix_commit_ids", "fix_commits"), ("patch_hunk_ids", "patch_hunks"), ("file_ids", "files"), ("function_ids", "functions")):
    values = {str(item) for item in observation.get(field_name) or [] if item}
    missing = sorted(values - set(packet_index[index_name]))
    if missing:
      errors.append(f"observation {field_name} are outside packet scope: {missing}")
  fix_ids = {str(item) for item in observation.get("fix_commit_ids") or [] if item}
  hunk_ids = {str(item) for item in observation.get("patch_hunk_ids") or [] if item}
  file_ids = {str(item) for item in observation.get("file_ids") or [] if item}
  function_ids = {str(item) for item in observation.get("function_ids") or [] if item}
  if not fix_ids:
    errors.append("observation fix_commit_ids scope is empty")
  for hunk_id in hunk_ids:
    expected = packet_index["hunk_to_fix"].get(hunk_id)
    if expected and expected not in fix_ids:
      errors.append(f"PatchHunk scope {hunk_id} is inconsistent with FixCommit {expected}")
  for file_id in file_ids:
    hunk_scope = packet_index["file_to_hunks"].get(file_id, set())
    if hunk_ids and hunk_scope and not hunk_ids.intersection(hunk_scope):
      errors.append(f"File scope {file_id} is inconsistent with PatchHunk scope")
  for function_id in function_ids:
    hunk_scope = packet_index["function_to_hunks"].get(function_id, set())
    if hunk_ids and hunk_scope and not hunk_ids.intersection(hunk_scope):
      errors.append(f"Function scope {function_id} is inconsistent with PatchHunk scope")
  return errors


def _semantic_id_errors(agent_output: dict[str, Any], taxonomy: Counter[str]) -> list[str]:
  errors = []
  ids = _all_semantic_ids(agent_output)
  for item_id in ids:
    if not item_id:
      _add(errors, taxonomy, "empty_semantic_id", "semantic ID must not be empty")
  for item_id, count in Counter(ids).items():
    if item_id and count > 1:
      _add(errors, taxonomy, "duplicate_semantic_id", f"duplicate semantic ID: {item_id}")
  return list(dict.fromkeys(errors))


def _duplicate_semantic_ids(agent_output: dict[str, Any]) -> set[str]:
  return {item_id for item_id, count in Counter(_all_semantic_ids(agent_output)).items() if item_id and count > 1}


def _all_semantic_ids(agent_output: dict[str, Any]) -> list[str]:
  groups = (
    (agent_output.get("root_cause_hypotheses") or [], "hypothesis_id"),
    (agent_output.get("code_anchors") or [], "anchor_id"),
    (agent_output.get("vulnerable_predicates") or [], "predicate_id"),
    (agent_output.get("fix_predicates") or [], "predicate_id"),
    (agent_output.get("guard_conditions") or [], "predicate_id"),
    (agent_output.get("negative_conditions") or agent_output.get("negative_applicability_conditions") or [], "predicate_id"),
  )
  return [_raw_payload_id(item, key) for payloads, key in groups for item in payloads]


def _raw_payload_id(payload: dict[str, Any], key: str) -> str:
  return str(payload.get(key) or payload.get("id") or "").strip()


def _payload_id(payload: dict[str, Any], key: str) -> str:
  return _raw_payload_id(payload, key)


def _list(payload: dict[str, Any], *keys: str) -> list[str]:
  for key in keys:
    if isinstance(payload.get(key), list):
      return [str(item) for item in payload[key] if item]
  return []


def _unique_payload_map(payloads: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
  counts = Counter(str(item.get(key) or "") for item in payloads)
  return {str(item.get(key)): dict(item) for item in payloads if item.get(key) and counts[str(item.get(key))] == 1}


def _wrapper_scope_matches(payload: dict[str, Any], cve_id: str, trace_run_id: str) -> bool:
  return payload.get("source") == "wrapper_git_trace" and str(payload.get("cve_id") or "") == cve_id and str(payload.get("trace_run_id") or "") == trace_run_id


def _mentions_symbol(text: str, symbol: str) -> bool:
  if not text or not symbol:
    return False
  lowered = text.lower()
  target = symbol.lower()
  start = 0
  while True:
    index = lowered.find(target, start)
    if index < 0:
      return False
    before = lowered[index - 1] if index > 0 else " "
    after_index = index + len(target)
    after = lowered[after_index] if after_index < len(lowered) else " "
    if not (before.isalnum() or before == "_") and not (after.isalnum() or after == "_"):
      return True
    start = index + len(target)


def _rejected_ids(errors: list[str]) -> list[str]:
  return sorted({token.strip("[],:()'\"") for error in errors for token in error.split() if ":" in token})


def _add(errors: list[str], taxonomy: Counter[str], key: str, message: str) -> None:
  taxonomy[key if key in TAXONOMY_KEYS else "other"] += 1
  errors.append(message)


def _json_safe(value: Any) -> Any:
  if isinstance(value, dict):
    return {key: _json_safe(item) for key, item in value.items()}
  if isinstance(value, set):
    return sorted(_json_safe(item) for item in value)
  if isinstance(value, list):
    return [_json_safe(item) for item in value]
  return value

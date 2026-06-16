from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


SEMANTIC_TYPES = {
  "RootCauseHypothesis",
  "CodeAnchor",
  "VulnerablePredicate",
  "FixPredicate",
  "GuardCondition",
  "NegativeCondition",
  "NegativeApplicabilityCondition",
  "UncertaintyReason",
  "RiskFlag",
}


def main() -> None:
  parser = argparse.ArgumentParser(description="Audit a native Root Cause OpenCode run directory.")
  parser.add_argument("run_dir", type=Path)
  args = parser.parse_args()

  run_dir = args.run_dir
  summary = _load_json(run_dir / "summary.json")
  nodes = _load_jsonl(run_dir / "graph_store" / "nodes.jsonl")
  edges = _load_jsonl(run_dir / "graph_store" / "edges.jsonl")
  graph = {
    "nodes_by_id": {str(node.get("id")): node for node in nodes},
    "edges": edges,
  }

  audits = []
  for cve_dir in sorted(path for path in run_dir.iterdir() if path.is_dir() and path.name.startswith("CVE-")):
    result = next((item for item in summary.get("results", []) if item.get("cve_id") == cve_dir.name), {})
    audit = _audit_cve(cve_dir, result, graph)
    audits.append(audit)
    (cve_dir / "report.md").write_text(_render_cve_report(audit), encoding="utf-8")

  audit_summary = _summarize(audits, summary)
  audit_path = run_dir / "native_audit.json"
  audit_path.write_text(json.dumps(audit_summary, ensure_ascii=False, indent=2), encoding="utf-8")
  _append_batch_report(run_dir / "report.md", audit_summary)
  print(json.dumps(audit_summary, ensure_ascii=False, indent=2))


def _audit_cve(cve_dir: Path, result: dict[str, Any], graph: dict[str, Any]) -> dict[str, Any]:
  cve_id = cve_dir.name
  packet = _load_json(cve_dir / "root_cause_packet.json")
  trace = _load_json(cve_dir / "evidence_trace.json")
  ingestion = _load_json(cve_dir / "ingestion_result.json")
  parsed = _load_json(cve_dir / "parsed_output.json") if (cve_dir / "parsed_output.json").exists() else {}
  contract_lint = _load_json(cve_dir / "contract_lint.json") if (cve_dir / "contract_lint.json").exists() else (ingestion.get("details") or {}).get("contract_lint") or {}

  observations = list(trace.get("git_observations") or [])
  tool_calls = {str(call.get("id")): call for call in trace.get("tool_calls") or []}
  tool_outputs = {str(output.get("id")): output for output in trace.get("tool_outputs") or []}
  trusted_ids = set((ingestion.get("details") or {}).get("trusted_observation_ids") or [])
  packet_nodes = list(packet.get("context") or []) + list(packet.get("repo_navigation") or []) + list(packet.get("patch_evidence") or [])
  packet_by_id = {str(node.get("id")): node for node in packet_nodes if node.get("id")}

  provenance_errors: list[str] = []
  traceability_errors: list[str] = []
  scope_errors: list[str] = []
  valid_evidence_count = 0
  for obs in observations:
    obs_id = str(obs.get("id") or "")
    if trace.get("source") != "wrapper_git_trace":
      provenance_errors.append("trace source is not wrapper_git_trace")
    if obs.get("source") != "wrapper_git_trace":
      provenance_errors.append(f"{obs_id}: observation source is not wrapper_git_trace")
    if trace.get("legacy_reconstructed") or trace.get("created_from") == "legacy_replay_adapter":
      provenance_errors.append("legacy replay adapter participated")
    if "valid_evidence" not in obs or not isinstance(obs.get("valid_evidence"), bool):
      provenance_errors.append(f"{obs_id}: valid_evidence is missing or non-boolean")
    if obs.get("valid_evidence") is True:
      valid_evidence_count += 1
    if not obs.get("observation_kind"):
      provenance_errors.append(f"{obs_id}: observation_kind is missing")
    command_ref = str(obs.get("command_ref") or "")
    output_ref = str(obs.get("tool_output_ref") or "")
    if command_ref not in tool_calls:
      traceability_errors.append(f"{obs_id}: command_ref does not resolve to ToolCall: {command_ref}")
    if output_ref not in tool_outputs:
      traceability_errors.append(f"{obs_id}: tool_output_ref does not resolve to ToolOutput: {output_ref}")
    elif str(tool_outputs[output_ref].get("command_ref") or "") != command_ref:
      traceability_errors.append(f"{obs_id}: ToolOutput command_ref mismatch")
    for key in ("fix_commit_ids", "patch_hunk_ids", "file_ids", "function_ids"):
      if key not in obs or not isinstance(obs.get(key), list):
        scope_errors.append(f"{obs_id}: {key} missing or not a list")
    if obs.get("valid_evidence") is True and not obs.get("fix_commit_ids"):
      scope_errors.append(f"{obs_id}: valid evidence has no fix_commit_ids")

  agent_anchor_errors = _check_anchor_packet_consistency(parsed, packet_by_id)
  accepted_anchor_errors = _check_accepted_anchor_consistency(graph, cve_id, packet_by_id)
  supports_errors = _check_supports_edges(graph, cve_id, trusted_ids)
  lifecycle = _semantic_lifecycle(graph, cve_id)
  leakage_errors = _check_packet_leakage(packet)
  fix_set_results = (ingestion.get("details") or {}).get("fix_set_results") or {}
  fix_set_complete = bool(fix_set_results) and all(bool(item.get("complete")) for item in fix_set_results.values())

  return {
    "cve_id": cve_id,
    "backend_type": result.get("backend_type"),
    "backend_status": result.get("backend_status"),
    "status": result.get("status"),
    "json_parse_status": result.get("json_parse_status"),
    "raw_response_empty": int(result.get("raw_response_size_bytes") or 0) == 0,
    "valid_json": bool(result.get("valid_json")),
    "hypothesis_count": int(result.get("hypothesis_count") or 0),
    "evidence_backed_hypothesis_count": int(result.get("evidence_backed_hypothesis_count") or 0),
    "failure_case_count": 1 if ingestion.get("failure_case_id") else len((ingestion.get("details") or {}).get("failure_case_ids") or []),
    "contract_ok": bool(contract_lint.get("ok")) if contract_lint else bool(result.get("contract_ok")),
    "contract_error_count": len(contract_lint.get("errors") or []) if contract_lint else int(result.get("contract_error_count") or 0),
    "contract_taxonomy": dict(contract_lint.get("taxonomy") or result.get("contract_taxonomy") or {}),
    "binding_complete_rate": float(contract_lint.get("binding_complete_rate") or result.get("binding_complete_rate") or 0.0),
    "invented_ids": list(contract_lint.get("invented_ids") or []),
    "rejected_reasons": list(ingestion.get("errors") or []),
    "observation_count": len(observations),
    "valid_evidence_count": valid_evidence_count,
    "native_provenance_ok": not provenance_errors,
    "provenance_errors": sorted(set(provenance_errors)),
    "traceability_ok": not traceability_errors,
    "traceability_errors": sorted(set(traceability_errors)),
    "wrapper_scope_ok": not scope_errors,
    "scope_errors": sorted(set(scope_errors)),
    "accepted_anchor_packet_consistency_ok": not accepted_anchor_errors,
    "accepted_anchor_errors": accepted_anchor_errors,
    "all_agent_anchor_packet_consistency_ok": not agent_anchor_errors,
    "agent_anchor_errors": agent_anchor_errors,
    "supports_only_trusted_explicit_refs_ok": not supports_errors,
    "supports_errors": supports_errors,
    "fix_set_complete": fix_set_complete,
    "fix_set_results": fix_set_results,
    "multi_fix_commit": bool(result.get("multi_fix_commit")),
    "multi_fix_anchor_mapping_ok": result.get("multi_fix_anchor_mapping_ok"),
    "semantic_lifecycle": lifecycle,
    "semantic_lifecycle_ok": lifecycle["validated_count"] == 0,
    "production_packet_leakage_ok": not leakage_errors,
    "packet_leakage_errors": leakage_errors,
    "legacy_adapter_count": 1 if (trace.get("legacy_reconstructed") or trace.get("created_from") == "legacy_replay_adapter") else 0,
    "agent_command_invocations_used": bool(result.get("agent_command_invocations_used")),
    "packet_size_bytes": int(result.get("packet_size_bytes") or 0),
    "evidence_trace_size_bytes": int(result.get("evidence_trace_size_bytes") or 0),
    "raw_response_size_bytes": int(result.get("raw_response_size_bytes") or 0),
    "duration_s": float(result.get("duration_s") or 0.0),
  }


def _check_anchor_packet_consistency(parsed: dict[str, Any], packet_by_id: dict[str, dict[str, Any]]) -> list[str]:
  errors: list[str] = []
  for anchor in parsed.get("code_anchors") or []:
    anchor_id = str(anchor.get("anchor_id") or "")
    fix_commit_id = str(anchor.get("fix_commit_id") or "")
    patch_hunk_id = str(anchor.get("patch_hunk_id") or "")
    if not fix_commit_id and not patch_hunk_id:
      errors.append(f"{anchor_id}: no fix_commit_id/patch_hunk_id")
      continue
    fix_node = packet_by_id.get(fix_commit_id)
    hunk_node = packet_by_id.get(patch_hunk_id)
    if fix_commit_id and not fix_node:
      errors.append(f"{anchor_id}: fix_commit_id not in packet: {fix_commit_id}")
    if patch_hunk_id and not hunk_node:
      errors.append(f"{anchor_id}: patch_hunk_id not in packet: {patch_hunk_id}")
    if fix_node and hunk_node:
      fix_sha = str((fix_node.get("content") or {}).get("commit_sha") or "")
      hunk_sha = str((hunk_node.get("content") or {}).get("commit_sha") or "")
      if fix_sha and hunk_sha and fix_sha != hunk_sha:
        errors.append(f"{anchor_id}: PatchHunk commit does not match FixCommit")
  return errors


def _check_accepted_anchor_consistency(graph: dict[str, Any], cve_id: str, packet_by_id: dict[str, dict[str, Any]]) -> list[str]:
  errors: list[str] = []
  raw_hypothesis_anchor_ids: set[str] = set()
  accepted_anchors: dict[str, dict[str, Any]] = {}
  for node in graph["nodes_by_id"].values():
    if node.get("created_from") != "service_ingestion":
      continue
    content = node.get("content") or {}
    if content.get("cve_id") != cve_id:
      continue
    if node.get("type") == "RootCauseHypothesis" and node.get("lifecycle") == "raw":
      raw_hypothesis_anchor_ids.update(str(anchor_id) for anchor_id in content.get("anchor_ids") or [])
    if node.get("type") == "CodeAnchor" and node.get("lifecycle") == "raw":
      anchor_id = str(content.get("anchor_id") or "")
      if anchor_id:
        accepted_anchors[anchor_id] = content
  for anchor_id in sorted(raw_hypothesis_anchor_ids):
    anchor = accepted_anchors.get(anchor_id)
    if not anchor:
      errors.append(f"{anchor_id}: raw hypothesis anchor was not materialized as raw CodeAnchor")
      continue
    errors.extend(_check_one_anchor(anchor_id, anchor, packet_by_id))
  return errors


def _check_one_anchor(anchor_id: str, anchor: dict[str, Any], packet_by_id: dict[str, dict[str, Any]]) -> list[str]:
  errors: list[str] = []
  fix_commit_id = str(anchor.get("fix_commit_id") or "")
  patch_hunk_id = str(anchor.get("patch_hunk_id") or "")
  if not fix_commit_id or not patch_hunk_id:
    errors.append(f"{anchor_id}: accepted anchor lacks fix_commit_id or patch_hunk_id")
    return errors
  fix_node = packet_by_id.get(fix_commit_id)
  hunk_node = packet_by_id.get(patch_hunk_id)
  if not fix_node:
    errors.append(f"{anchor_id}: fix_commit_id not in packet: {fix_commit_id}")
  if not hunk_node:
    errors.append(f"{anchor_id}: patch_hunk_id not in packet: {patch_hunk_id}")
  if fix_node and hunk_node:
    fix_sha = str((fix_node.get("content") or {}).get("commit_sha") or "")
    hunk_sha = str((hunk_node.get("content") or {}).get("commit_sha") or "")
    if fix_sha and hunk_sha and fix_sha != hunk_sha:
      errors.append(f"{anchor_id}: PatchHunk commit does not match FixCommit")
  return errors


def _check_supports_edges(graph: dict[str, Any], cve_id: str, trusted_ids: set[str]) -> list[str]:
  errors: list[str] = []
  nodes_by_id: dict[str, dict[str, Any]] = graph["nodes_by_id"]
  for edge in graph["edges"]:
    if edge.get("type") != "supports":
      continue
    source = nodes_by_id.get(str(edge.get("source")))
    target = nodes_by_id.get(str(edge.get("target")))
    if not source or not target:
      continue
    if source.get("type") != "GitObservation":
      continue
    source_content = source.get("content") or {}
    target_content = target.get("content") or {}
    if source_content.get("cve_id") != cve_id or target_content.get("cve_id") != cve_id:
      continue
    obs_id = str(source_content.get("id") or "")
    if obs_id not in trusted_ids:
      errors.append(f"{edge.get('id')}: SUPPORTS source is not trusted observation")
    explicit_refs = {str(ref) for ref in target_content.get("git_observation_refs") or []}
    if obs_id not in explicit_refs:
      errors.append(f"{edge.get('id')}: SUPPORTS source was not explicitly referenced by target")
  return errors


def _semantic_lifecycle(graph: dict[str, Any], cve_id: str) -> dict[str, Any]:
  counts: Counter[str] = Counter()
  type_counts: Counter[str] = Counter()
  for node in graph["nodes_by_id"].values():
    if node.get("created_from") != "service_ingestion":
      continue
    if node.get("type") not in SEMANTIC_TYPES:
      continue
    content = node.get("content") or {}
    if content.get("cve_id") != cve_id:
      continue
    counts[str(node.get("lifecycle") or "unknown")] += 1
    type_counts[str(node.get("type") or "unknown")] += 1
  return {
    "counts": dict(counts),
    "type_counts": dict(type_counts),
    "validated_count": int(counts.get("validated", 0)),
  }


def _check_packet_leakage(packet: dict[str, Any]) -> list[str]:
  errors: list[str] = []
  for section, value in packet.items():
    if section == "forbidden":
      continue
    if not isinstance(value, list):
      continue
    for node in value:
      if not isinstance(node, dict):
        continue
      node_id = str(node.get("id") or "")
      allowed_use = str(node.get("allowed_use") or "")
      lifecycle = str(node.get("lifecycle") or "")
      node_type = str(node.get("type") or "")
      if allowed_use == "offline_eval_only":
        errors.append(f"{section}:{node_id}: offline_eval_only leaked into production packet")
      if lifecycle == "candidate":
        errors.append(f"{section}:{node_id}: candidate memory leaked into production packet")
      if section == "patch_evidence" and node_type in {"CWE", "CAPEC", "ATTACKTechnique"}:
        errors.append(f"{section}:{node_id}: context node appears as evidence")
  return errors


def _summarize(audits: list[dict[str, Any]], summary: dict[str, Any]) -> dict[str, Any]:
  status_counts = Counter(str(item["status"]) for item in audits)
  parse_counts = Counter(str(item["json_parse_status"]) for item in audits)
  rejected_reasons = Counter(reason for item in audits for reason in item["rejected_reasons"])
  return {
    "total": len(audits),
    "backend_type_counts": dict(Counter(str(item["backend_type"]) for item in audits)),
    "status_counts": dict(status_counts),
    "accepted_count": int(status_counts.get("ingested_raw", 0)),
    "rejected_count": int(status_counts.get("rejected", 0)),
    "partial_count": sum(1 for item in audits if item["status"] not in {"ingested_raw", "rejected", "failed", "parse_error", "empty"}),
    "json_parse_status_counts": dict(parse_counts),
    "raw_response_empty_count": sum(1 for item in audits if item["raw_response_empty"]),
    "evidence_backed_hypothesis_count": sum(item["evidence_backed_hypothesis_count"] for item in audits),
    "failure_case_count": sum(item["failure_case_count"] for item in audits),
    "contract_ok_count": sum(1 for item in audits if item["contract_ok"]),
    "contract_error_count": sum(int(item["contract_error_count"]) for item in audits),
    "contract_taxonomy": dict(Counter(key for item in audits for key, count in item["contract_taxonomy"].items() for _ in range(int(count)))),
    "invented_id_cases": [
      {"cve_id": item["cve_id"], "invented_ids": item["invented_ids"]}
      for item in audits
      if item["invented_ids"]
    ],
    "rejected_reasons": dict(rejected_reasons),
    "native_provenance_ok": all(item["native_provenance_ok"] for item in audits),
    "traceability_ok": all(item["traceability_ok"] for item in audits),
    "wrapper_scope_ok": all(item["wrapper_scope_ok"] for item in audits),
    "accepted_anchor_packet_consistency_ok": all(item["accepted_anchor_packet_consistency_ok"] for item in audits),
    "all_agent_anchor_packet_consistency_ok": all(item["all_agent_anchor_packet_consistency_ok"] for item in audits),
    "supports_only_trusted_explicit_refs_ok": all(item["supports_only_trusted_explicit_refs_ok"] for item in audits),
    "fix_set_complete_count": sum(1 for item in audits if item["fix_set_complete"]),
    "semantic_lifecycle_ok": all(item["semantic_lifecycle_ok"] for item in audits),
    "production_packet_leakage_ok": all(item["production_packet_leakage_ok"] for item in audits),
    "legacy_adapter_count": sum(item["legacy_adapter_count"] for item in audits),
    "agent_command_invocation_case_count": sum(1 for item in audits if item["agent_command_invocations_used"]),
    "avg_packet_size_bytes": summary.get("avg_packet_size_bytes"),
    "avg_evidence_trace_size_bytes": summary.get("avg_evidence_trace_size_bytes"),
    "avg_raw_response_size_bytes": summary.get("avg_raw_response_size_bytes"),
    "total_duration_s": summary.get("total_duration_s"),
    "cves": audits,
  }


def _render_cve_report(audit: dict[str, Any]) -> str:
  lines = [
    f"# Native Root Cause Audit: {audit['cve_id']}",
    "",
    f"- Backend type: `{audit['backend_type']}`",
    f"- Backend status: `{audit['backend_status']}`",
    f"- Ingestion status: `{audit['status']}`",
    f"- JSON parse status: `{audit['json_parse_status']}`",
    f"- Raw response empty: `{audit['raw_response_empty']}`",
    f"- Hypotheses: {audit['hypothesis_count']}",
    f"- Evidence-backed hypotheses: {audit['evidence_backed_hypothesis_count']}",
    f"- FailureCases: {audit['failure_case_count']}",
    f"- Contract OK: `{audit['contract_ok']}`",
    f"- Contract errors: {audit['contract_error_count']}",
    f"- Contract taxonomy: `{audit['contract_taxonomy']}`",
    f"- Binding complete rate: {audit['binding_complete_rate']:.3f}",
    f"- Invented IDs: `{audit['invented_ids']}`",
    f"- GitObservations: {audit['observation_count']} total / {audit['valid_evidence_count']} valid",
    "",
    "## Evidence Gate Checks",
    "",
    f"- Native wrapper provenance: `{audit['native_provenance_ok']}`",
    f"- ToolCall -> ToolOutput -> GitObservation traceability: `{audit['traceability_ok']}`",
    f"- Wrapper-generated scope fields: `{audit['wrapper_scope_ok']}`",
    f"- Accepted hypothesis Anchor -> PatchHunk -> FixCommit consistency: `{audit['accepted_anchor_packet_consistency_ok']}`",
    f"- All agent anchors Anchor -> PatchHunk -> FixCommit consistency: `{audit['all_agent_anchor_packet_consistency_ok']}`",
    f"- SUPPORTS only trusted explicit refs: `{audit['supports_only_trusted_explicit_refs_ok']}`",
    f"- fix_set_id coverage complete: `{audit['fix_set_complete']}`",
    f"- Semantic lifecycle has no validated nodes: `{audit['semantic_lifecycle_ok']}`",
    f"- Production packet leakage check: `{audit['production_packet_leakage_ok']}`",
    f"- Legacy adapter count: `{audit['legacy_adapter_count']}`",
    "",
    "## Details",
    "",
    f"- Rejected reasons: `{audit['rejected_reasons']}`",
    f"- Provenance errors: `{audit['provenance_errors']}`",
    f"- Traceability errors: `{audit['traceability_errors']}`",
    f"- Scope errors: `{audit['scope_errors']}`",
    f"- Accepted anchor errors: `{audit['accepted_anchor_errors']}`",
    f"- All agent anchor errors: `{audit['agent_anchor_errors']}`",
    f"- SUPPORTS errors: `{audit['supports_errors']}`",
    f"- Semantic lifecycle: `{audit['semantic_lifecycle']}`",
    f"- Fix-set results: `{audit['fix_set_results']}`",
  ]
  return "\n".join(lines) + "\n"


def _append_batch_report(report_path: Path, audit: dict[str, Any]) -> None:
  existing = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
  marker = "\n## Native Evidence Gate Audit\n"
  if marker in existing:
    existing = existing.split(marker, 1)[0].rstrip() + "\n"
  lines = [
    "",
    "## Native Evidence Gate Audit",
    "",
    f"- Accepted / ingested_raw: {audit['accepted_count']}",
    f"- Rejected: {audit['rejected_count']}",
    f"- Partial/other: {audit['partial_count']}",
    f"- Raw response empty count: {audit['raw_response_empty_count']}",
    f"- JSON parse status counts: `{audit['json_parse_status_counts']}`",
    f"- Evidence-backed RootCauseHypothesis count: {audit['evidence_backed_hypothesis_count']}",
    f"- FailureCase count: {audit['failure_case_count']}",
    f"- Contract OK count: {audit['contract_ok_count']}",
    f"- Contract error count: {audit['contract_error_count']}",
    f"- Contract taxonomy: `{audit['contract_taxonomy']}`",
    f"- Invented ID cases: `{audit['invented_id_cases']}`",
    f"- Rejected reason classes: `{audit['rejected_reasons']}`",
    f"- Native wrapper observation provenance: `{audit['native_provenance_ok']}`",
    f"- ToolCall -> ToolOutput -> GitObservation traceability: `{audit['traceability_ok']}`",
    f"- Accepted hypothesis Anchor -> PatchHunk -> FixCommit consistency: `{audit['accepted_anchor_packet_consistency_ok']}`",
    f"- All agent anchors Anchor -> PatchHunk -> FixCommit consistency: `{audit['all_agent_anchor_packet_consistency_ok']}`",
    f"- fix_set_id coverage complete cases: {audit['fix_set_complete_count']}/{audit['total']}",
    f"- SUPPORTS only trusted explicit refs: `{audit['supports_only_trusted_explicit_refs_ok']}`",
    f"- Semantic lifecycle no validated nodes: `{audit['semantic_lifecycle_ok']}`",
    f"- Production packet leakage: `{audit['production_packet_leakage_ok']}`",
    f"- Legacy adapter count: {audit['legacy_adapter_count']}",
    f"- Agent command invocation cases: {audit['agent_command_invocation_case_count']}",
    "",
    "| CVE | Status | Parse | Contract OK | Contract Errors | Hyp | Evidence-backed | Native Prov | Traceable | Accepted Anchor OK | All Agent Anchors OK | Fix-set Complete | Lifecycle OK | Leakage OK | Legacy | Main Rejection |",
    "| --- | --- | --- | --- | ---: | ---: | ---: | --- | --- | --- | --- | --- | --- | --- | ---: | --- |",
  ]
  for item in audit["cves"]:
    main_rejection = item["rejected_reasons"][0] if item["rejected_reasons"] else ""
    lines.append(
      f"| {item['cve_id']} | {item['status']} | {item['json_parse_status']} | {item['contract_ok']} | "
      f"{item['contract_error_count']} | {item['hypothesis_count']} | {item['evidence_backed_hypothesis_count']} | "
      f"{item['native_provenance_ok']} | {item['traceability_ok']} | {item['accepted_anchor_packet_consistency_ok']} | "
      f"{item['all_agent_anchor_packet_consistency_ok']} | {item['fix_set_complete']} | {item['semantic_lifecycle_ok']} | {item['production_packet_leakage_ok']} | "
      f"{item['legacy_adapter_count']} | {main_rejection} |"
    )
  report_path.write_text(existing.rstrip() + marker + "\n".join(lines[2:]) + "\n", encoding="utf-8")


def _load_json(path: Path) -> dict[str, Any]:
  if not path.exists():
    return {}
  data = json.loads(path.read_text(encoding="utf-8"))
  return data if isinstance(data, dict) else {}


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
  if not path.exists():
    return []
  items = []
  for line in path.read_text(encoding="utf-8").splitlines():
    if not line.strip():
      continue
    item = json.loads(line)
    if isinstance(item, dict):
      items.append(item)
  return items


if __name__ == "__main__":
  main()

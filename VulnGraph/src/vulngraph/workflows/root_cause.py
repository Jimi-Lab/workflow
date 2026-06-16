from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from statistics import mean
from typing import Any

from vulngraph.agent_backends import AgentResponse, RootCauseBackend
from vulngraph.agent_io import parse_root_cause_output
from vulngraph.agent_io.root_cause_contract import lint_root_cause_contract
from vulngraph.agent_io.root_cause_schema import RootCauseAgentOutputV2, root_cause_agent_output_schema
from vulngraph.services import VulnGraphClient

from .git_evidence import collect_git_evidence


class RootCauseWorkflow:
  def __init__(
    self,
    *,
    client: VulnGraphClient,
    backend: RootCauseBackend,
    repo_root: str | Path | None = None,
    timeout_s: float = 30.0,
  ) -> None:
    self.client = client
    self.backend = backend
    self.repo_root = Path(repo_root) if repo_root is not None else None
    self.timeout_s = timeout_s

  def run_root_cause_for_cve(self, cve_id: str, *, out_dir: str | Path) -> dict[str, Any]:
    started = time.monotonic()
    out_root = Path(out_dir)
    cve_dir = out_root / cve_id
    cve_dir.mkdir(parents=True, exist_ok=True)

    packet = self.client.build_root_cause_packet(cve_id, mode="production")
    evidence_trace = collect_git_evidence(cve_id, packet, repo_root=self.repo_root, timeout_s=self.timeout_s)
    prompt = render_root_cause_prompt_v2(cve_id, packet, evidence_trace)
    context = {
      "cve_id": cve_id,
      "packet": packet,
      "evidence_trace": _prompt_trace(evidence_trace),
      "system_prompt": _prompt_template(),
    }

    _write_json(cve_dir / "root_cause_packet.json", packet)
    _write_json(cve_dir / "evidence_trace.json", evidence_trace)
    (cve_dir / "prompt.txt").write_text(prompt, encoding="utf-8")

    response = self.backend.generate(prompt, context)
    (cve_dir / "raw_response.txt").write_text(response.raw_text or "", encoding="utf-8")
    raw_response_size = len((response.raw_text or "").encode("utf-8"))

    result: dict[str, Any] = {
      "cve_id": cve_id,
      "backend_name": response.backend_name,
      "backend_type": response.backend_type,
      "backend_status": response.status,
      "json_parse_status": "unknown",
      "valid_json": False,
      "malformed_json": False,
      "empty_message": False,
      "status": response.status,
      "run_dir": str(cve_dir),
      "packet_size_bytes": len(json.dumps(packet, ensure_ascii=False).encode("utf-8")),
      "evidence_trace_size_bytes": len(json.dumps(evidence_trace, ensure_ascii=False).encode("utf-8")),
      "raw_response_size_bytes": raw_response_size,
      "duration_s": 0.0,
      "evidence_observation_count": len(evidence_trace.get("git_observations") or []),
      "hypothesis_count": 0,
      "evidence_backed_hypothesis_count": 0,
      "missing_git_observation_refs": [],
      "missing_git_observation_ref_count": 0,
      "contract_error_count": 0,
      "contract_taxonomy": {},
      "contract_ok": False,
      "binding_complete_rate": 0.0,
      "agent_command_invocations_used": False,
      "multi_fix_anchor_mapping_ok": None,
      "multi_fix_commit": _fix_commit_count(packet) > 1,
      "fix_commit_count": _fix_commit_count(packet),
      "errors": [],
    }

    if response.status == "failed":
      ingestion = self.client.record_root_cause_failure(
        cve_id,
        reason=response.error or "backend failure",
        backend_name=response.backend_name,
        raw_text=response.raw_text,
        trace=evidence_trace,
      )
      result.update({"status": "failed", "json_parse_status": "backend_failed", "ingestion_result": _ingestion_dict(ingestion), "errors": [response.error or "backend failure"]})
      result["duration_s"] = round(time.monotonic() - started, 3)
      _write_json(cve_dir / "ingestion_result.json", result["ingestion_result"])
      return result

    parsed = parse_root_cause_output(response.raw_text)
    if not parsed.ok or parsed.output is None or parsed.data is None:
      reason = "empty assistant message" if parsed.empty else "malformed JSON"
      ingestion = self.client.record_root_cause_failure(
        cve_id,
        reason=reason,
        backend_name=response.backend_name,
        raw_text=response.raw_text,
        trace=evidence_trace,
      )
      result.update(
        {
          "status": "empty" if parsed.empty else "parse_error",
          "json_parse_status": "empty" if parsed.empty else "malformed",
          "empty_message": parsed.empty,
          "malformed_json": not parsed.empty,
          "parse_error": parsed.error,
          "ingestion_result": _ingestion_dict(ingestion),
          "errors": [parsed.error or reason],
        }
      )
      result["duration_s"] = round(time.monotonic() - started, 3)
      _write_json(cve_dir / "parse_error.json", {"error": parsed.error, "empty": parsed.empty})
      _write_json(cve_dir / "ingestion_result.json", result["ingestion_result"])
      return result

    output = parsed.output
    parsed_data = _normalize_for_ingestion(output)
    contract_lint = lint_root_cause_contract(parsed_data, packet, evidence_trace)
    ingestion = self.client.ingest_root_cause_output(cve_id, parsed_data, trace=evidence_trace, packet=packet)
    ingestion_payload = _ingestion_dict(ingestion)
    ingestion_payload.setdefault("details", {})["contract_lint"] = contract_lint.to_dict()
    structural_validation = (ingestion_payload.get("details") or {}).get("structural_validation") or {}
    missing_refs = _missing_git_observation_refs(output, evidence_trace)

    result.update(
      {
        "status": ingestion.status,
        "json_parse_status": parsed.format,
        "valid_json": True,
        "hypothesis_count": len(output.root_cause_hypotheses),
        "evidence_backed_hypothesis_count": ingestion.raw_hypothesis_count,
        "missing_git_observation_refs": missing_refs,
        "missing_git_observation_ref_count": len(missing_refs),
        "contract_error_count": len(contract_lint.errors),
        "contract_taxonomy": contract_lint.taxonomy,
        "contract_ok": contract_lint.ok,
        "binding_complete_rate": contract_lint.binding_complete_rate,
        "structural_error_count": len(structural_validation.get("errors") or []),
        "invented_ids": list(structural_validation.get("invented_ids") or []),
        "lint_ingestion_parity": contract_lint.ok == (ingestion.rejected_hypothesis_count == 0),
        "agent_command_invocations_used": bool(parsed_data.get("command_invocations")),
        "multi_fix_anchor_mapping_ok": _multi_fix_anchor_mapping_ok(packet, ingestion_payload),
        "ingestion_result": ingestion_payload,
        "errors": list(ingestion.errors),
      }
    )
    result["duration_s"] = round(time.monotonic() - started, 3)
    _write_json(cve_dir / "parsed_output.json", parsed_data)
    _write_json(cve_dir / "contract_lint.json", contract_lint.to_dict())
    _write_json(cve_dir / "structural_validation.json", structural_validation)
    _write_json(cve_dir / "ingestion_result.json", result["ingestion_result"])
    return result

  def run_root_cause_batch(self, cve_ids: list[str], *, out_dir: str | Path) -> dict[str, Any]:
    return run_root_cause_batch(cve_ids, client=self.client, backend=self.backend, repo_root=self.repo_root, out_dir=out_dir, timeout_s=self.timeout_s)


def run_root_cause_for_cve(
  cve_id: str,
  backend: RootCauseBackend,
  repo_root: str | Path | None,
  out_dir: str | Path,
  *,
  client: VulnGraphClient,
) -> dict[str, Any]:
  return RootCauseWorkflow(client=client, backend=backend, repo_root=repo_root).run_root_cause_for_cve(cve_id, out_dir=out_dir)


def run_root_cause_batch(
  cve_ids: list[str],
  backend: RootCauseBackend,
  out_dir: str | Path,
  *,
  client: VulnGraphClient,
  repo_root: str | Path | None = None,
  timeout_s: float = 30.0,
) -> dict[str, Any]:
  workflow = RootCauseWorkflow(client=client, backend=backend, repo_root=repo_root, timeout_s=timeout_s)
  out_root = Path(out_dir)
  out_root.mkdir(parents=True, exist_ok=True)
  results = []
  for cve_id in cve_ids:
    try:
      results.append(workflow.run_root_cause_for_cve(cve_id, out_dir=out_root))
    except Exception as error:
      results.append(
        {
          "cve_id": cve_id,
          "backend_name": getattr(backend, "backend_name", "unknown"),
          "backend_type": getattr(backend, "backend_type", "unknown"),
          "status": "failed",
          "json_parse_status": "backend_failed",
          "valid_json": False,
          "malformed_json": False,
          "empty_message": False,
          "errors": [str(error)],
          "run_dir": str(out_root / cve_id),
          "packet_size_bytes": 0,
          "evidence_trace_size_bytes": 0,
          "raw_response_size_bytes": 0,
          "duration_s": 0.0,
          "evidence_observation_count": 0,
          "hypothesis_count": 0,
          "evidence_backed_hypothesis_count": 0,
          "missing_git_observation_refs": [],
          "missing_git_observation_ref_count": 0,
          "agent_command_invocations_used": False,
          "multi_fix_anchor_mapping_ok": None,
          "multi_fix_commit": False,
          "fix_commit_count": 0,
        }
      )
  summary = _batch_summary(results)
  _write_json(out_root / "summary.json", summary)
  (out_root / "report.md").write_text(_render_batch_report(summary), encoding="utf-8")
  return summary


def render_root_cause_prompt_v2(cve_id: str, packet: dict[str, Any], evidence_trace: dict[str, Any]) -> str:
  prompt = _prompt_template()
  prompt += "\n\nCVE_ID:\n" + cve_id
  prompt += "\n\nROOT_CAUSE_PACKET:\n" + json.dumps(packet, ensure_ascii=False, indent=2)
  prompt += "\n\nWRAPPER_GIT_EVIDENCE_TRACE:\n" + json.dumps(_prompt_trace(evidence_trace), ensure_ascii=False, indent=2)
  prompt += "\n\nOUTPUT_JSON_SCHEMA:\n" + json.dumps(root_cause_agent_output_schema(), ensure_ascii=False, indent=2)
  return prompt


def _prompt_template() -> str:
  path = Path(__file__).resolve().parents[1] / "prompts" / "root_cause_v2.md"
  return path.read_text(encoding="utf-8")


def _prompt_trace(evidence_trace: dict[str, Any]) -> dict[str, Any]:
  return {
    "backend_trusted": evidence_trace.get("backend_trusted"),
    "repo": evidence_trace.get("repo"),
    "repo_path": evidence_trace.get("repo_path"),
    "evidence_inventory": [
      {
        "id": observation.get("id"),
        "source": observation.get("source"),
        "valid_evidence": observation.get("valid_evidence"),
        "observation_kind": observation.get("observation_kind"),
        "fix_commit_ids": observation.get("fix_commit_ids", []),
        "patch_hunk_ids": observation.get("patch_hunk_ids", []),
        "file_ids": observation.get("file_ids", []),
        "function_ids": observation.get("function_ids", []),
        "path": observation.get("path"),
        "claim": observation.get("claim"),
        "snippet_excerpt": str(observation.get("snippet") or "")[:2000],
      }
      for observation in evidence_trace.get("git_observations", [])
    ],
    "git_observations": evidence_trace.get("git_observations", []),
    "tool_call_summaries": [
      {
        "id": call.get("id"),
        "command": call.get("command"),
        "cwd": call.get("cwd"),
        "exit_code": call.get("exit_code"),
        "stdout_sha256": call.get("stdout_sha256"),
        "stdout_excerpt": str(call.get("stdout_excerpt") or "")[:2000],
        "stderr_excerpt": call.get("stderr_excerpt"),
      }
      for call in evidence_trace.get("tool_calls", [])
    ],
    "errors": evidence_trace.get("errors", []),
  }


def _normalize_for_ingestion(output: RootCauseAgentOutputV2) -> dict[str, Any]:
  data = output.model_dump(mode="json")
  data["negative_applicability_conditions"] = data.pop("negative_conditions", [])
  return data


def _missing_git_observation_refs(output: RootCauseAgentOutputV2, evidence_trace: dict[str, Any]) -> list[str]:
  known = {str(obs.get("id") or obs.get("observation_id") or "") for obs in evidence_trace.get("git_observations", [])}
  refs: set[str] = set(output.git_observation_refs)
  for hypothesis in output.root_cause_hypotheses:
    refs.update(hypothesis.git_observation_refs)
  for item in (
    *output.vulnerable_predicates,
    *output.fix_predicates,
    *output.guard_conditions,
    *output.negative_conditions,
    *output.code_anchors,
    *output.uncertainty_reasons,
    *output.risk_flags,
  ):
    refs.update(getattr(item, "git_observation_refs", []))
  return sorted(ref for ref in refs if ref and ref not in known)


def _multi_fix_anchor_mapping_ok(packet: dict[str, Any], ingestion_payload: dict[str, Any]) -> bool | None:
  fix_ids = {str(node.get("id") or "") for node in packet.get("patch_evidence", []) if node.get("type") == "FixCommit" and node.get("id")}
  if len(fix_ids) <= 1:
    return None
  validation = ((ingestion_payload.get("details") or {}).get("structural_validation") or {})
  accepted_hypotheses = set(validation.get("accepted_hypothesis_ids") or [])
  hypothesis_results = validation.get("hypothesis_results") or {}
  accepted_anchor_ids = {
    str(anchor_id)
    for hypothesis_id in accepted_hypotheses
    for anchor_id in ((hypothesis_results.get(hypothesis_id) or {}).get("payload") or {}).get("anchor_ids", [])
  }
  anchor_results = validation.get("anchor_results") or {}
  mapped_fix_ids = {
    str((anchor_results.get(anchor_id) or {}).get("payload", {}).get("fix_commit_id") or "")
    for anchor_id in accepted_anchor_ids
    if (anchor_results.get(anchor_id) or {}).get("gate_valid")
  }
  mapped_fix_ids.discard("")
  return fix_ids.issubset(mapped_fix_ids)


def _fix_commit_count(packet: dict[str, Any]) -> int:
  return sum(1 for node in packet.get("patch_evidence", []) if node.get("type") == "FixCommit")


def _batch_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
  backend_types = Counter(str(item.get("backend_type") or "unknown") for item in results)
  statuses = Counter(str(item.get("status") or "unknown") for item in results)
  json_parse_statuses = Counter(str(item.get("json_parse_status") or "unknown") for item in results)
  rejected_reasons = Counter(
    str((item.get("ingestion_result") or {}).get("errors", [""])[0] if (item.get("ingestion_result") or {}).get("errors") else (item.get("errors") or [""])[0])
    for item in results
    if item.get("status") in {"rejected", "parse_error", "empty", "failed"}
  )
  packet_sizes = [int(item.get("packet_size_bytes") or 0) for item in results if item.get("packet_size_bytes")]
  trace_sizes = [int(item.get("evidence_trace_size_bytes") or 0) for item in results if item.get("evidence_trace_size_bytes")]
  raw_sizes = [int(item.get("raw_response_size_bytes") or 0) for item in results if item.get("raw_response_size_bytes")]
  durations = [float(item.get("duration_s") or 0.0) for item in results]
  contract_taxonomy = Counter()
  for item in results:
    contract_taxonomy.update(dict(item.get("contract_taxonomy") or {}))
  binding_rates = [float(item.get("binding_complete_rate") or 0.0) for item in results if item.get("valid_json")]
  return {
    "total": len(results),
    "results": results,
    "status_counts": dict(statuses),
    "json_parse_status_counts": dict(json_parse_statuses),
    "backend_type_counts": dict(backend_types),
    "real_opencode_invocation_count": sum(1 for item in results if item.get("backend_type") == "opencode"),
    "ingested_raw_count": sum(1 for item in results if item.get("status") == "ingested_raw"),
    "structurally_rejected_count": sum(1 for item in results if item.get("status") == "rejected"),
    "parse_error_count": sum(1 for item in results if item.get("status") == "parse_error"),
    "backend_failed_count": sum(1 for item in results if item.get("status") == "failed" or item.get("json_parse_status") == "backend_failed"),
    "fixture_invocation_count": sum(1 for item in results if item.get("backend_type") == "fixture"),
    "opencode_real_results": sum(1 for item in results if item.get("backend_type") == "opencode" and item.get("status") == "ingested_raw"),
    "fixture_results": sum(1 for item in results if item.get("backend_type") == "fixture"),
    "valid_json_count": sum(1 for item in results if item.get("valid_json")),
    "malformed_json_count": sum(1 for item in results if item.get("malformed_json")),
    "empty_message_count": sum(1 for item in results if item.get("empty_message")),
    "evidence_backed_hypothesis_count": sum(int(item.get("evidence_backed_hypothesis_count") or 0) for item in results),
    "rejected_count": sum(1 for item in results if item.get("status") == "rejected"),
    "failure_case_count": sum(1 for item in results if (item.get("ingestion_result") or {}).get("failure_case_id")),
    "contract_error_count": sum(int(item.get("contract_error_count") or 0) for item in results),
    "contract_taxonomy": dict(contract_taxonomy),
    "contract_ok_count": sum(1 for item in results if item.get("contract_ok")),
    "structural_error_count": sum(int(item.get("structural_error_count") or 0) for item in results),
    "invented_id_cases": [
      {"cve_id": item.get("cve_id"), "invented_ids": item.get("invented_ids", [])}
      for item in results if item.get("invented_ids")
    ],
    "lint_ingestion_parity_count": sum(1 for item in results if item.get("lint_ingestion_parity")),
    "avg_binding_complete_rate": mean(binding_rates) if binding_rates else 0,
    "missing_git_observation_ref_cases": [
      {"cve_id": item.get("cve_id"), "missing_refs": item.get("missing_git_observation_refs", [])}
      for item in results
      if item.get("missing_git_observation_refs")
    ],
    "agent_command_invocation_cases": [
      item.get("cve_id")
      for item in results
      if item.get("agent_command_invocations_used")
    ],
    "rejected_reasons": dict(rejected_reasons),
    "avg_packet_size_bytes": mean(packet_sizes) if packet_sizes else 0,
    "avg_evidence_trace_size_bytes": mean(trace_sizes) if trace_sizes else 0,
    "avg_raw_response_size_bytes": mean(raw_sizes) if raw_sizes else 0,
    "total_duration_s": round(sum(durations), 3),
    "multi_fix_commit_cases": [item["cve_id"] for item in results if item.get("multi_fix_commit")],
  }


def _render_batch_report(summary: dict[str, Any]) -> str:
  lines = [
    "# Root Cause Agent v2 Batch Report",
    "",
    "## Boundary",
    "",
    "This run exercises the Root Cause Agent v2 workflow only. It does not run Judge Agent, BIC ranking, or affected-version conversion.",
    "",
    "## Backend",
    "",
    f"- Backend type counts: `{summary['backend_type_counts']}`",
    f"- Real OpenCode invocation count: {summary['real_opencode_invocation_count']}",
    f"- Ingested raw count: {summary['ingested_raw_count']}",
    f"- Structurally rejected count: {summary['structurally_rejected_count']}",
    f"- Parse error count: {summary['parse_error_count']}",
    f"- Backend failed count: {summary['backend_failed_count']}",
    f"- Fixture invocation count: {summary['fixture_invocation_count']}",
    f"- Legacy compatibility field `opencode_real_results` (real OpenCode and ingested_raw only): {summary['opencode_real_results']}",
    f"- OpenCode real results: {summary['opencode_real_results']} (legacy compatibility: ingested real OpenCode results, not invocation count)",
    f"- Fixture results: {summary['fixture_results']}",
    "",
    "## Aggregate",
    "",
    f"- Total CVEs: {summary['total']}",
    f"- Status counts: `{summary['status_counts']}`",
    f"- JSON parse status counts: `{summary['json_parse_status_counts']}`",
    f"- Valid JSON: {summary['valid_json_count']}",
    f"- Malformed JSON: {summary['malformed_json_count']}",
    f"- Empty message: {summary['empty_message_count']}",
    f"- Evidence-backed RootCauseHypothesis count: {summary['evidence_backed_hypothesis_count']}",
    f"- Rejected count: {summary['rejected_count']}",
    f"- FailureCase count: {summary['failure_case_count']}",
    f"- Contract OK count: {summary['contract_ok_count']}",
    f"- Contract error count: {summary['contract_error_count']}",
    f"- Shared structural error count: {summary['structural_error_count']}",
    f"- Invented ID cases: `{summary['invented_id_cases']}`",
    f"- Lint/ingestion parity count: {summary['lint_ingestion_parity_count']}/{summary['total']}",
    f"- Contract taxonomy: `{summary['contract_taxonomy']}`",
    f"- Average binding complete rate: {summary['avg_binding_complete_rate']:.3f}",
    f"- Missing GitObservation ref cases: `{summary['missing_git_observation_ref_cases']}`",
    f"- Agent command invocation cases: `{summary['agent_command_invocation_cases']}`",
    f"- Average packet size bytes: {summary['avg_packet_size_bytes']:.1f}",
    f"- Average evidence trace size bytes: {summary['avg_evidence_trace_size_bytes']:.1f}",
    f"- Average raw response size bytes: {summary['avg_raw_response_size_bytes']:.1f}",
    f"- Total duration seconds: {summary['total_duration_s']:.3f}",
    f"- Multi-fix commit cases: `{summary['multi_fix_commit_cases']}`",
    "",
    "## CVE Table",
    "",
    "| CVE | Backend | Status | JSON Parse | Valid JSON | Contract OK | Contract Errors | Evidence Obs | Hypotheses | Evidence-backed Hypotheses | Fix Commits | Multi-fix | Multi-fix Mapping | Missing Obs Refs | Raw Bytes | Duration(s) | Errors |",
    "| --- | --- | --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: | ---: | ---: | --- |",
  ]
  for item in summary["results"]:
    errors = "; ".join(str(error) for error in item.get("errors", []) if error)
    lines.append(
      f"| {item.get('cve_id')} | {item.get('backend_type')} | {item.get('status')} | {item.get('json_parse_status')} | "
      f"{item.get('valid_json')} | "
      f"{item.get('contract_ok')} | {item.get('contract_error_count', 0)} | "
      f"{item.get('evidence_observation_count', 0)} | {item.get('hypothesis_count', 0)} | "
      f"{item.get('evidence_backed_hypothesis_count', 0)} | {item.get('fix_commit_count', 0)} | "
      f"{item.get('multi_fix_commit')} | {item.get('multi_fix_anchor_mapping_ok')} | "
      f"{item.get('missing_git_observation_ref_count', 0)} | {item.get('raw_response_size_bytes', 0)} | "
      f"{float(item.get('duration_s') or 0.0):.3f} | {errors} |"
    )
  lines.extend(
    [
      "",
      "## Multi-Fix Representation",
      "",
      "Multi-fix cases are detected by `fix_commit_count > 1`. The packet and evidence trace preserve every `FixCommit`; valid agent outputs are checked for `fix_commit_id`, `patch_hunk_id`, and `anchor_id` mappings. This confirms representational support, not semantic correctness.",
      "",
      "## Failure Attribution",
      "",
      f"`{summary['rejected_reasons']}`",
      "",
      "## Next Prompt/Schema Optimization",
      "",
      "- When OpenCode server is reachable, run the same workflow with real OpenCode backend and compare valid JSON / empty-message rates against the fixture smoke baseline.",
      "- Keep wrapper trace as the authoritative command/evidence source; agent JSON should only reference `git_observation_refs`.",
      "- Add stricter per-hypothesis evidence checks for specific patch hunks and changed functions after real OpenCode output is available.",
      "- Add deterministic normalization only for syntactic fenced JSON, not for missing evidence or invented fields.",
    ]
  )
  return "\n".join(lines) + "\n"


def _ingestion_dict(ingestion) -> dict[str, Any]:
  return {
    "status": ingestion.status,
    "lifecycle": ingestion.lifecycle,
    "appended_events": ingestion.appended_events,
    "errors": list(ingestion.errors),
    "warnings": list(ingestion.warnings),
    "failure_case_id": ingestion.failure_case_id,
    "raw_hypothesis_count": ingestion.raw_hypothesis_count,
    "rejected_hypothesis_count": ingestion.rejected_hypothesis_count,
    "details": ingestion.details,
  }


def _write_json(path: Path, data: Any) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

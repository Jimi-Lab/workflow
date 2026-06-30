from __future__ import annotations

import csv
import json
import shutil
import time
from pathlib import Path
from typing import Any

from vulngraph.agent_backends.base import AgentResponse
from vulngraph.agent_io.judge_boundary_v1_2_contract import (
  derive_boundary_views_v1_2,
  lint_judge_boundary_output_v1_2,
)
from vulngraph.agent_io.judge_boundary_v1_2_schema import parse_judge_boundary_output_v1_2
from vulngraph.workflows.branch_context_v1_2 import SubprocessGitGraph, build_branch_scoped_groups
from vulngraph.workflows.history_event_candidates import (
  materialize_history_event_candidates,
  recover_history_events_from_inventory,
)
from vulngraph.workflows.judge_boundary_v1 import build_judge_boundary_input_v1


PROMPT_PATH_V12 = Path(__file__).resolve().parents[1] / "prompts" / "judge_boundary_v1_2.md"


class FixtureJudgeBoundaryBackendV12:
  backend_name = "fixture-judge-boundary-v1-2"
  backend_type = "fixture"

  def generate(self, prompt: str, context: dict[str, Any]) -> AgentResponse:
    boundary_input = context["boundary_input"]
    judgments = []
    first_by_context: set[str] = set()
    for event in boundary_input.get("history_event_candidates", []):
      context_id = (event.get("branch_context_ids") or [""])[0]
      if context_id not in first_by_context:
        first_by_context.add(context_id)
        decision, role = "selected", "primary_boundary"
      else:
        decision, role = "uncertain", "supporting_evidence_only"
      judgments.append({
        "event_candidate_id": event["event_candidate_id"],
        "event_commit_sha": event["event_commit_sha"],
        "boundary_role": role,
        "decision": decision,
        "confidence": "medium" if decision == "selected" else "low",
        "evidence_refs": list(event.get("evidence_refs") or [])[:2],
        "reasoning_short": "fixture uses wrapper-owned branch and SZZ evidence",
      })
    payload = {"schema_version": "judge_boundary_output_v1_2", "cve_id": boundary_input["cve_id"], "candidate_judgments": judgments}
    return AgentResponse(raw_text=json.dumps(payload, indent=2), status="ok", backend_name=self.backend_name, backend_type=self.backend_type, usage={"session_id": f"fixture-v12-{boundary_input['cve_id']}"})


def build_judge_boundary_input_v1_2(
  *, cve_id: str, judge_packet_root: str | Path, detailed_evidence_root: str | Path,
  slimming_root: str | Path, judge_v0_run: str | Path, dataset: str | Path,
  repo_root: str | Path,
) -> dict[str, Any]:
  base = build_judge_boundary_input_v1(
    cve_id=cve_id, judge_packet_root=judge_packet_root,
    detailed_evidence_root=detailed_evidence_root, slimming_root=slimming_root,
    judge_v0_run=judge_v0_run, dataset=dataset,
  )
  evidence_path = Path(detailed_evidence_root) / cve_id / "per_candidate_szz_evidence.json"
  evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
  events = materialize_history_event_candidates(base.get("candidate_set", []), evidence)
  repo = str(base.get("cve_context", {}).get("repo") or "")
  represented_fixes = {str(item.get("fix_commit_sha") or "") for item in events}
  missing_fallbacks = [
    item for item in base.get("candidate_set", [])
    if item.get("candidate_source") == "fallback"
    and str(item.get("fix_commit_id") or "").rsplit(":", 1)[-1] not in represented_fixes
  ]
  if missing_fallbacks:
    inventory = _load_frozen_inventory(Path(judge_packet_root), cve_id)
    events.extend(recover_history_events_from_inventory(
      inventory=inventory, fallback_templates=missing_fallbacks,
      root_cause_context=base.get("root_cause_context", {}),
      repo_path=Path(repo_root) / repo,
    ))
  events = list({item["event_candidate_id"]: item for item in events}.values())
  grouped = build_branch_scoped_groups(cve_id, repo, events, SubprocessGitGraph(Path(repo_root) / repo))
  sanitized_cards = [_sanitize_szz_card(card) for card in base.get("szz_evidence_cards", []) or []]
  return {
    "schema_version": "judge_boundary_input_v1_2",
    "cve_id": cve_id,
    "cve_context": base.get("cve_context", {}),
    "root_cause_context": base.get("root_cause_context", {}),
    **grouped,
    "szz_evidence_cards": sanitized_cards,
    "judge_v0_rankings": base.get("judge_v0_rankings", []),
    "attacker_context": {"available": False, "reason": "module_not_implemented"},
    "forbidden": ["ground_truth", "correct_bic", "validated_bic", "bic", "affected_versions"],
    "lifecycle": "branch_scoped_boundary_input_v1_2",
  }


def render_judge_boundary_prompt_v1_2(boundary_input: dict[str, Any]) -> str:
  return PROMPT_PATH_V12.read_text(encoding="utf-8") + "\n" + json.dumps(boundary_input, ensure_ascii=False, indent=2)


def run_judge_boundary_v1_2_for_cve(
  *, cve_id: str, judge_packet_root: str | Path, detailed_evidence_root: str | Path,
  slimming_root: str | Path, judge_v0_run: str | Path, dataset: str | Path,
  repo_root: str | Path, out_dir: str | Path, backend: Any, repair_retries: int = 1,
) -> dict[str, Any]:
  out = Path(out_dir)
  out.mkdir(parents=True, exist_ok=True)
  boundary_input = build_judge_boundary_input_v1_2(
    cve_id=cve_id, judge_packet_root=judge_packet_root,
    detailed_evidence_root=detailed_evidence_root, slimming_root=slimming_root,
    judge_v0_run=judge_v0_run, dataset=dataset, repo_root=repo_root,
  )
  prompt = render_judge_boundary_prompt_v1_2(boundary_input)
  _write_json(out / "judge_boundary_input_v1_2.json", boundary_input)
  (out / "judge_boundary_prompt_v1_2.txt").write_text(prompt, encoding="utf-8")
  response = backend.generate(prompt, {"cve_id": cve_id, "boundary_input": boundary_input, "system_prompt": "VulnGraph Judge Boundary v1.2. Strict JSON only."})
  parsed = parse_judge_boundary_output_v1_2(response.raw_text) if response.status == "ok" else None
  contract = lint_judge_boundary_output_v1_2(parsed.data, boundary_input) if parsed and parsed.ok and parsed.data else None
  retry_used = False
  repair_prompt_bytes = 0
  if repair_retries and response.status == "ok" and (not contract or not contract.ok):
    retry_used = True
    (out / "raw_response.initial.txt").write_text(response.raw_text, encoding="utf-8")
    repair = _repair_prompt(boundary_input, response.raw_text, parsed.error if parsed else response.error, contract.to_dict() if contract else {})
    repair_prompt_bytes = len(repair.encode("utf-8"))
    (out / "repair_prompt_v1_2.txt").write_text(repair, encoding="utf-8")
    response = backend.generate(repair, {"cve_id": cve_id, "boundary_input": boundary_input, "system_prompt": "Re-evaluate with the complete original v1.2 evidence. Strict JSON only."})
    parsed = parse_judge_boundary_output_v1_2(response.raw_text) if response.status == "ok" else None
    contract = lint_judge_boundary_output_v1_2(parsed.data, boundary_input) if parsed and parsed.ok and parsed.data else None
  (out / "raw_response.txt").write_text(response.raw_text, encoding="utf-8")
  if parsed and parsed.ok and parsed.data:
    _write_json(out / "parsed_boundary_output_v1_2.json", parsed.data)
  else:
    _write_json(out / "parse_error_v1_2.json", {"error": parsed.error if parsed else response.error or "backend_failed"})
  contract_dict = contract.to_dict() if contract else {"ok": False, "errors": [parsed.error if parsed else response.error or "parse_failed"], "taxonomy": {"parse_failed": 1}, "invented_candidate_ids": []}
  _write_json(out / "judge_boundary_contract_lint_v1_2.json", contract_dict)
  views = derive_boundary_views_v1_2(parsed.data, boundary_input) if contract_dict["ok"] and parsed and parsed.data else {"selected_events": [], "activation_events": [], "conjunctive_prerequisites": [], "supporting_evidence": [], "rejected_candidates": [], "uncertain_candidates": []}
  _write_json(out / "derived_boundary_views_v1_2.json", views)
  result = {
    "cve_id": cve_id, "status": response.status,
    "backend_name": response.backend_name, "backend_type": response.backend_type,
    "parse_status": parsed.format if parsed and parsed.ok else "parse_error",
    "contract_ok": bool(contract_dict["ok"]),
    "event_candidate_count": len(boundary_input["history_event_candidates"]),
    "candidate_accounted_count": len(parsed.data.get("candidate_judgments", [])) if parsed and parsed.data else 0,
    "selected_primary_count": len(views["activation_events"]),
    "uncertain_count": len(views["uncertain_candidates"]),
    "prompt_bytes": len(prompt.encode("utf-8")),
    "repair_prompt_bytes": repair_prompt_bytes,
    "model_prompt_bytes": len(prompt.encode("utf-8")) + repair_prompt_bytes,
    "model_invocation_count": 1 + int(retry_used),
    "retry_used": retry_used, "session_id": (response.usage or {}).get("session_id", ""),
    "taxonomy": contract_dict.get("taxonomy", {}),
    "lifecycle": "raw_branch_boundary_accepted" if contract_dict["ok"] else "raw_branch_boundary_rejected",
  }
  _write_json(out / "judge_boundary_result_v1_2.json", result)
  return result


def run_judge_boundary_v1_2_batch(
  *, cve_ids: list[str], judge_packet_root: str | Path, detailed_evidence_root: str | Path,
  slimming_root: str | Path, judge_v0_run: str | Path, dataset: str | Path,
  repo_root: str | Path, out_dir: str | Path, backend: Any, reset: bool = False,
  repair_retries: int = 1,
) -> dict[str, Any]:
  root = Path(out_dir)
  if reset and root.exists():
    shutil.rmtree(root)
  root.mkdir(parents=True, exist_ok=True)
  started = time.monotonic()
  results = [run_judge_boundary_v1_2_for_cve(
    cve_id=cve_id, judge_packet_root=judge_packet_root,
    detailed_evidence_root=detailed_evidence_root, slimming_root=slimming_root,
    judge_v0_run=judge_v0_run, dataset=dataset, repo_root=repo_root,
    out_dir=root / cve_id, backend=backend, repair_retries=repair_retries,
  ) for cve_id in cve_ids]
  summary = {
    "cases_total": len(results), "parse_ok_count": sum(item["parse_status"] in {"json", "fenced_json"} for item in results),
    "contract_ok_count": sum(bool(item["contract_ok"]) for item in results),
    "candidate_count": sum(item["event_candidate_count"] for item in results),
    "candidate_accounted_count": sum(item["candidate_accounted_count"] for item in results),
    "model_invocation_count": sum(item["model_invocation_count"] for item in results),
    "prompt_bytes_total": sum(item["prompt_bytes"] for item in results),
    "model_prompt_bytes_total": sum(item["model_prompt_bytes"] for item in results),
    "duration_s": round(time.monotonic() - started, 6), "results": results,
    "lifecycle": "raw_branch_boundary_v1_2",
  }
  _write_json(root / "summary.json", summary)
  _write_csv(root / "judge_boundary_v1_2_summary.csv", results)
  return summary


def _sanitize_szz_card(card: dict[str, Any]) -> dict[str, Any]:
  value = dict(card)
  value.pop("release_reachability_summary", None)
  value["risk_flags"] = [flag for flag in value.get("risk_flags", []) or [] if flag not in {"release_reachability_too_broad", "release_line_overreach", "non_release_tag_noise"}]
  return value


def _load_frozen_inventory(judge_packet_root: Path, cve_id: str) -> dict[str, Any]:
  manifest_path = judge_packet_root / "provenance_manifest.json"
  if not manifest_path.exists():
    return {}
  manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
  value = Path(str(manifest.get("anchor_artifact") or ""))
  if not value.is_absolute():
    project_root = Path(__file__).resolve().parents[3]
    value = project_root / value
  path = value / cve_id / "candidate_inventory.json"
  return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _repair_prompt(boundary_input: dict[str, Any], raw: str, parse_error: Any, contract: dict[str, Any]) -> str:
  return PROMPT_PATH_V12.read_text(encoding="utf-8") + "\n\nCONTRACT_ERRORS:\n" + json.dumps({"parse_error": parse_error, "contract": contract}, ensure_ascii=False, indent=2) + "\n\nPREVIOUS_OUTPUT:\n" + raw + "\n\nCOMPLETE_ORIGINAL_INPUT:\n" + json.dumps(boundary_input, ensure_ascii=False, indent=2)


def _write_json(path: Path, value: Any) -> None:
  path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
  columns = sorted({key for row in rows for key in row})
  with path.open("w", encoding="utf-8", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=columns)
    writer.writeheader()
    for row in rows:
      writer.writerow({key: json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value for key, value in row.items()})

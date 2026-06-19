from __future__ import annotations

import csv
import json
import shutil
import time
from pathlib import Path
from typing import Any

from vulngraph.agent_backends.base import AgentResponse
from vulngraph.agent_io.judge_boundary_contract import lint_judge_boundary_output_v1, scan_forbidden_boundary_fields
from vulngraph.agent_io.judge_boundary_schema import parse_judge_boundary_output_v1
from vulngraph.workflows.judge_v0 import build_judge_input_v0


PROMPT_PATH = Path(__file__).resolve().parents[1] / "prompts" / "judge_boundary_v1.md"
SUMMARY_COLUMNS = [
  "cve_id",
  "backend_type",
  "parse_status",
  "contract_ok",
  "candidate_count",
  "selected_event_count",
  "rejected_count",
  "uncertain_count",
  "prompt_bytes",
  "raw_response_bytes",
  "retry_used",
  "session_id",
  "taxonomy",
]


class FixtureJudgeBoundaryBackend:
  backend_name = "fixture-judge-boundary-v1"
  backend_type = "fixture"

  def generate(self, prompt: str, context: dict[str, Any]) -> AgentResponse:
    boundary_input = context.get("boundary_input") if isinstance(context.get("boundary_input"), dict) else {}
    judgments = []
    selected = []
    rejected = []
    uncertainty = []
    for index, candidate in enumerate(boundary_input.get("candidate_set", []) or []):
      candidate_id = str(candidate.get("candidate_id") or "")
      sha = str(candidate.get("candidate_commit_sha") or "")
      conflict = bool(set(candidate.get("risk_flags") or []) & {"move_copy_sensitive_blame", "whitespace_sensitive_blame", "boundary_candidate_commit"})
      if index == 0 and not conflict:
        decision = "selected"
        role = "introduction"
        selected.append({"candidate_id": candidate_id, "candidate_commit_sha": sha, "boundary_role": role, "evidence_refs": list(candidate.get("evidence_refs") or [])[:2]})
      elif conflict:
        decision = "uncertain"
        role = "uncertain_boundary"
        uncertainty.append({"candidate_id": candidate_id, "reason": "conflicting SZZ risk remains unresolved"})
      else:
        decision = "rejected"
        role = "refactor_noise"
        rejected.append({"candidate_id": candidate_id, "reason": "lower ranked duplicate boundary candidate"})
      judgments.append(
        {
          "candidate_id": candidate_id,
          "candidate_commit_sha": sha,
          "boundary_role": role,
          "decision": decision,
          "confidence": "medium" if decision == "selected" else "low",
          "evidence_refs": list(candidate.get("evidence_refs") or [])[:2],
          "reasoning_short": "fixture boundary decision uses wrapper-owned evidence refs",
        }
      )
    payload = {
      "schema_version": "judge_boundary_output_v1",
      "cve_id": str(boundary_input.get("cve_id") or context.get("cve_id") or ""),
      "candidate_judgments": judgments,
      "selected_boundary_events": selected,
      "uncertainty": uncertainty,
      "rejected_candidates": rejected,
    }
    return AgentResponse(
      raw_text=json.dumps(payload, ensure_ascii=False, indent=2),
      status="ok",
      backend_name=self.backend_name,
      backend_type=self.backend_type,
      usage={"session_id": f"fixture-boundary-{payload['cve_id']}", "prompt_chars": len(prompt)},
    )


def build_judge_boundary_input_v1(
  *,
  cve_id: str,
  judge_packet_root: str | Path,
  detailed_evidence_root: str | Path,
  slimming_root: str | Path,
  judge_v0_run: str | Path,
  dataset: str | Path,
) -> dict[str, Any]:
  base = build_judge_input_v0(
    cve_id=cve_id,
    judge_packet_root=judge_packet_root,
    detailed_evidence_root=detailed_evidence_root,
    slimming_root=slimming_root,
    dataset=dataset,
  )
  v0_parsed = _find_v0_json(Path(judge_v0_run), cve_id, "parsed_judge_output.json")
  v0_result = _find_v0_json(Path(judge_v0_run), cve_id, "judge_result.json")
  rankings = []
  for item in v0_parsed.get("candidate_judgments", []) or []:
    rankings.append(
      {
        "candidate_id": item.get("candidate_id", ""),
        "candidate_commit_sha": item.get("candidate_commit_sha", ""),
        "rank": item.get("rank", 0),
        "judgment": item.get("judgment", ""),
        "confidence": item.get("confidence", ""),
        "evidence_refs_used": item.get("evidence_refs_used", []),
      }
    )
  boundary_input = {
    "schema_version": "judge_boundary_input_v1",
    "cve_id": cve_id,
    "cve_context": base.get("cve_context", {}),
    "root_cause_context": base.get("root_cause_context", {}),
    "candidate_set": base.get("candidate_set", []),
    "szz_evidence_cards": base.get("szz_evidence_cards", []),
    "judge_v0_rankings": rankings,
    "judge_v0_contract_ok": bool(v0_result.get("contract_ok", False)),
    "release_reachability_summary": {
      item.get("candidate_id", ""): (card.get("release_reachability_summary") or {})
      for item, card in zip(base.get("candidate_set", []) or [], base.get("szz_evidence_cards", []) or [])
      if item.get("candidate_id")
    },
    "forbidden": base.get("forbidden", []),
    "lifecycle": "boundary_validation_input_v1",
  }
  scan = scan_forbidden_boundary_fields(boundary_input)
  if not scan["ok"]:
    raise ValueError(f"judge boundary input contains forbidden keys: {scan['violations']}")
  return boundary_input


def render_judge_boundary_prompt(boundary_input: dict[str, Any]) -> str:
  template = PROMPT_PATH.read_text(encoding="utf-8")
  return template + "\n" + json.dumps(boundary_input, ensure_ascii=False, indent=2)


def run_judge_boundary_v1_batch(
  *,
  cve_ids: list[str],
  judge_packet_root: str | Path,
  detailed_evidence_root: str | Path,
  slimming_root: str | Path,
  judge_v0_run: str | Path,
  dataset: str | Path,
  out_dir: str | Path,
  backend: Any,
  reset: bool = False,
  repair_retries: int = 1,
) -> dict[str, Any]:
  output_root = Path(out_dir)
  if reset and output_root.exists():
    shutil.rmtree(output_root)
  output_root.mkdir(parents=True, exist_ok=True)
  started = time.monotonic()
  results = [
    run_judge_boundary_v1_for_cve(
      cve_id=cve_id,
      judge_packet_root=judge_packet_root,
      detailed_evidence_root=detailed_evidence_root,
      slimming_root=slimming_root,
      judge_v0_run=judge_v0_run,
      dataset=dataset,
      out_dir=output_root / cve_id,
      backend=backend,
      repair_retries=repair_retries,
    )
    for cve_id in cve_ids
  ]
  summary = _summary(results, duration_s=time.monotonic() - started)
  _write_json(output_root / "summary.json", summary)
  _write_csv(output_root / "judge_boundary_summary.csv", [_summary_row(item) for item in results], SUMMARY_COLUMNS)
  (output_root / "judge_boundary_v1_report.md").write_text(_render_report(summary, results), encoding="utf-8")
  return summary


def run_judge_boundary_v1_for_cve(
  *,
  cve_id: str,
  judge_packet_root: str | Path,
  detailed_evidence_root: str | Path,
  slimming_root: str | Path,
  judge_v0_run: str | Path,
  dataset: str | Path,
  out_dir: str | Path,
  backend: Any,
  repair_retries: int = 1,
) -> dict[str, Any]:
  out_path = Path(out_dir)
  out_path.mkdir(parents=True, exist_ok=True)
  boundary_input = build_judge_boundary_input_v1(
    cve_id=cve_id,
    judge_packet_root=judge_packet_root,
    detailed_evidence_root=detailed_evidence_root,
    slimming_root=slimming_root,
    judge_v0_run=judge_v0_run,
    dataset=dataset,
  )
  prompt = render_judge_boundary_prompt(boundary_input)
  _write_json(out_path / "judge_boundary_input_v1.json", boundary_input)
  (out_path / "judge_boundary_prompt.txt").write_text(prompt, encoding="utf-8")
  response = backend.generate(
    prompt,
    {
      "cve_id": cve_id,
      "boundary_input": boundary_input,
      "system_prompt": "You are VulnGraph Judge Boundary Agent v1. Return strict JSON only.",
    },
  )
  parse_result, contract, contract_dict = _parse_and_lint(response, boundary_input)
  retry_used = False
  if repair_retries > 0 and response.status == "ok" and not contract_dict.get("ok"):
    retry_used = True
    (out_path / "raw_response.initial.txt").write_text(response.raw_text, encoding="utf-8")
    repair_prompt = _repair_prompt(
      cve_id=cve_id,
      boundary_input=boundary_input,
      raw_response=response.raw_text,
      parse_result=parse_result,
      contract_dict=contract_dict,
    )
    (out_path / "repair_prompt.txt").write_text(repair_prompt, encoding="utf-8")
    response = backend.generate(
      repair_prompt,
      {
        "cve_id": cve_id,
        "boundary_input": _repair_context(boundary_input),
        "system_prompt": "Repair the previous VulnGraph Judge Boundary v1 JSON only. Return strict JSON only.",
      },
    )
    (out_path / "raw_response.repair.txt").write_text(response.raw_text, encoding="utf-8")
    parse_result, contract, contract_dict = _parse_and_lint(response, boundary_input)

  (out_path / "raw_response.txt").write_text(response.raw_text, encoding="utf-8")
  if parse_result and parse_result.ok and parse_result.data:
    _write_json(out_path / "parsed_boundary_output.json", parse_result.data)
  else:
    _write_json(out_path / "parse_error.json", {"status": response.status, "error": response.error or (parse_result.error if parse_result else "backend_failed")})
  contract_dict = contract.to_dict() if contract else {"ok": False, "errors": [response.error or "parse_failed"], "taxonomy": {"parse_failed": 1}}
  _write_json(out_path / "judge_boundary_contract_lint.json", contract_dict)
  result = _result(cve_id, boundary_input, response, parse_result, contract_dict, retry_used=retry_used)
  _write_json(out_path / "judge_boundary_result.json", result)
  return result


def _parse_and_lint(response: AgentResponse, boundary_input: dict[str, Any]) -> tuple[Any, Any, dict[str, Any]]:
  parse_result = parse_judge_boundary_output_v1(response.raw_text) if response.status == "ok" else None
  if parse_result and parse_result.ok and parse_result.data:
    contract = lint_judge_boundary_output_v1(parse_result.data, boundary_input)
    return parse_result, contract, contract.to_dict()
  return parse_result, None, {"ok": False, "errors": [response.error or (parse_result.error if parse_result else "backend_failed")], "taxonomy": {"parse_failed": 1}}


def _result(
  cve_id: str,
  boundary_input: dict[str, Any],
  response: AgentResponse,
  parse_result: Any,
  contract: dict[str, Any],
  *,
  retry_used: bool,
) -> dict[str, Any]:
  parsed = parse_result.data if parse_result and parse_result.ok else {}
  return {
    "cve_id": cve_id,
    "backend_name": response.backend_name,
    "backend_type": response.backend_type,
    "status": response.status,
    "parse_status": parse_result.format if parse_result and parse_result.ok else ("empty" if parse_result and parse_result.empty else "parse_error" if response.status == "ok" else response.status),
    "contract_ok": bool(contract.get("ok")),
    "candidate_count": len(boundary_input.get("candidate_set", []) or []),
    "selected_boundary_event_count": len(parsed.get("selected_boundary_events", []) or []) if isinstance(parsed, dict) else 0,
    "rejected_count": len(parsed.get("rejected_candidates", []) or []) if isinstance(parsed, dict) else 0,
    "uncertain_count": sum(1 for item in parsed.get("candidate_judgments", []) or [] if item.get("decision") == "uncertain") if isinstance(parsed, dict) else 0,
    "prompt_bytes": len(json.dumps(boundary_input, ensure_ascii=False).encode("utf-8")),
    "raw_response_bytes": len(response.raw_text.encode("utf-8")),
    "retry_used": retry_used,
    "session_id": (response.usage or {}).get("session_id", ""),
    "contract_taxonomy": contract.get("taxonomy", {}),
    "lifecycle": "raw_boundary_event_accepted" if contract.get("ok") else "raw_boundary_event_rejected",
  }


def _summary(results: list[dict[str, Any]], *, duration_s: float) -> dict[str, Any]:
  return {
    "cases_total": len(results),
    "parse_ok_count": sum(1 for item in results if item.get("parse_status") in {"json", "fenced_json"}),
    "contract_ok_count": sum(1 for item in results if item.get("contract_ok")),
    "backend_failed_count": sum(1 for item in results if item.get("status") == "failed"),
    "repair_retry_count": sum(1 for item in results if item.get("retry_used")),
    "selected_boundary_event_count": sum(int(item.get("selected_boundary_event_count") or 0) for item in results),
    "rejected_count": sum(int(item.get("rejected_count") or 0) for item in results),
    "uncertain_count": sum(int(item.get("uncertain_count") or 0) for item in results),
    "lifecycle": "raw_boundary_event_accepted",
    "duration_s": round(duration_s, 6),
    "results": results,
  }


def _find_v0_json(root: Path, cve_id: str, filename: str) -> dict[str, Any]:
  candidates = [
    root / "cases" / "30" / cve_id / filename,
    root / "cases" / "10" / cve_id / filename,
    root / cve_id / filename,
  ]
  for path in candidates:
    if path.exists():
      return _read_json(path)
  return {}


def _summary_row(result: dict[str, Any]) -> dict[str, Any]:
  return {
    "cve_id": result.get("cve_id", ""),
    "backend_type": result.get("backend_type", ""),
    "parse_status": result.get("parse_status", ""),
    "contract_ok": result.get("contract_ok", False),
    "candidate_count": result.get("candidate_count", 0),
    "selected_event_count": result.get("selected_boundary_event_count", 0),
    "rejected_count": result.get("rejected_count", 0),
    "uncertain_count": result.get("uncertain_count", 0),
    "prompt_bytes": result.get("prompt_bytes", 0),
    "raw_response_bytes": result.get("raw_response_bytes", 0),
    "retry_used": result.get("retry_used", False),
    "session_id": result.get("session_id", ""),
    "taxonomy": json.dumps(result.get("contract_taxonomy", {}), ensure_ascii=False, sort_keys=True),
  }


def _render_report(summary: dict[str, Any], results: list[dict[str, Any]]) -> str:
  lines = [
    "# VulnGraph Judge Boundary v1",
    "",
    "Boundary v1 validates raw candidate boundary events for deterministic conversion. It does not output BIC or affected versions.",
    "",
    f"- cases_total: {summary['cases_total']}",
    f"- parse_ok_count: {summary['parse_ok_count']}",
    f"- contract_ok_count: {summary['contract_ok_count']}",
    f"- repair_retry_count: {summary['repair_retry_count']}",
    f"- selected_boundary_event_count: {summary['selected_boundary_event_count']}",
    f"- lifecycle: {summary['lifecycle']}",
    "",
    "| CVE | parse | contract | selected | uncertain |",
    "|---|---|---:|---:|---:|",
  ]
  for item in results:
    lines.append(f"| {item['cve_id']} | {item['parse_status']} | {item['contract_ok']} | {item['selected_boundary_event_count']} | {item['uncertain_count']} |")
  return "\n".join(lines) + "\n"


def _repair_prompt(
  *,
  cve_id: str,
  boundary_input: dict[str, Any],
  raw_response: str,
  parse_result: Any,
  contract_dict: dict[str, Any],
) -> str:
  allowed_candidates = _repair_context(boundary_input)["candidate_set"]
  repair_request = {
    "task": "repair_judge_boundary_output_v1_json",
    "cve_id": cve_id,
    "rules": [
      "Return one strict JSON object only.",
      "Use only candidate_id and candidate_commit_sha from allowed_candidates.",
      "Use only evidence refs listed for that candidate.",
      "Account for every allowed candidate exactly once in candidate_judgments.",
      "Do not output correct_bic, ground_truth, affected_versions, bic, paths, lines, or new SHAs.",
      "For conflict-risk candidates, either mark decision uncertain with boundary_role uncertain_boundary, or provide evidence-backed reasoning_short explaining the conflict.",
    ],
    "parse_error": parse_result.error if parse_result and not parse_result.ok else "",
    "contract_errors": contract_dict.get("errors", []),
    "contract_taxonomy": contract_dict.get("taxonomy", {}),
    "allowed_candidates": allowed_candidates,
    "previous_response_excerpt": raw_response[:4000],
    "required_schema": {
      "schema_version": "judge_boundary_output_v1",
      "cve_id": cve_id,
      "candidate_judgments": [
        {
          "candidate_id": "from allowed_candidates",
          "candidate_commit_sha": "matching SHA from allowed_candidates",
          "boundary_role": "introduction|activation|prerequisite|fix_series_noise|refactor_noise|equivalent_fix_noise|uncertain_boundary",
          "decision": "selected|rejected|uncertain",
          "confidence": "low|medium|high",
          "evidence_refs": ["from candidate evidence_refs"],
          "reasoning_short": "brief evidence-backed reason",
        }
      ],
      "selected_boundary_events": [],
      "uncertainty": [],
      "rejected_candidates": [],
    },
  }
  return json.dumps(repair_request, ensure_ascii=False, indent=2)


def _repair_context(boundary_input: dict[str, Any]) -> dict[str, Any]:
  candidate_set = []
  for candidate in boundary_input.get("candidate_set", []) or []:
    candidate_set.append(
      {
        "candidate_id": candidate.get("candidate_id", ""),
        "candidate_commit_sha": candidate.get("candidate_commit_sha", ""),
        "evidence_refs": candidate.get("evidence_refs", []),
        "risk_flags": candidate.get("risk_flags", []),
        "candidate_source": candidate.get("candidate_source", ""),
        "evidence_level": candidate.get("evidence_level", ""),
      }
    )
  return {"cve_id": boundary_input.get("cve_id", ""), "candidate_set": candidate_set}


def _read_json(path: Path) -> dict[str, Any]:
  data = json.loads(path.read_text(encoding="utf-8"))
  if not isinstance(data, dict):
    raise ValueError(f"expected JSON object: {path}")
  return data


def _write_json(path: Path, data: Any) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]], columns: list[str]) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  with path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=columns)
    writer.writeheader()
    for row in rows:
      writer.writerow(row)

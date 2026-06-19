from __future__ import annotations

import csv
import json
import re
import shutil
import time
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median
from typing import Any

from vulngraph.agent_io.judge_contract import FORBIDDEN_JUDGE_KEYS, scan_forbidden_judge_fields
from vulngraph.workflows.judge_v0 import run_judge_v0_for_cve


DEFAULT_JUDGE_STRESS_10_CVES = [
  "CVE-2020-14212",
  "CVE-2020-19667",
  "CVE-2020-8231",
  "CVE-2020-11984",
  "CVE-2022-0171",
  "CVE-2022-0286",
  "CVE-2020-15389",
  "CVE-2020-1967",
  "CVE-2020-11869",
  "CVE-2020-13164",
]

JUDGE_RANKING_COLUMNS = [
  "run_group",
  "cve_id",
  "candidate_id",
  "candidate_commit_sha",
  "rank",
  "decision",
  "confidence",
  "candidate_source",
  "candidate_anchor_role",
  "risk_flags",
  "evidence_refs_used",
  "top1_raw_candidate_judgment",
  "lifecycle",
]

CONTRACT_COLUMNS = [
  "run_group",
  "cve_id",
  "backend_type",
  "status",
  "parse_status",
  "contract_ok",
  "case_disposition",
  "candidate_count",
  "ranked_count",
  "excluded_count",
  "uncertain_count",
  "all_candidates_accounted",
  "retry_used",
  "session_id",
  "prompt_bytes",
  "raw_response_bytes",
  "taxonomy",
]

CANDIDATE_TYPE_COLUMNS = [
  "candidate_source",
  "candidate_count",
  "ranked_count",
  "excluded_count",
  "uncertain_count",
  "plausible_count",
  "unlikely_count",
  "unaccounted_count",
]

PROMPT_SIZE_COLUMNS = [
  "run_group",
  "cve_id",
  "candidate_count",
  "prompt_bytes",
  "raw_response_bytes",
]

MANUAL_REVIEW_COLUMNS = [
  "run_group",
  "cve_id",
  "reason",
  "candidate_count",
  "fallback_candidate_count",
  "contract_ok",
  "parse_status",
  "taxonomy",
]


def discover_cve_dirs(root: str | Path) -> list[str]:
  path = Path(root)
  if not path.exists():
    return []
  return sorted(
    child.name
    for child in path.iterdir()
    if child.is_dir() and (child / "judge_blind_input_packet.json").exists()
  )


def run_judge_v0_full_stress(
  *,
  cve_ids_10: list[str],
  cve_ids_30: list[str],
  judge_packet_root: str | Path,
  detailed_evidence_root: str | Path,
  slimming_root: str | Path,
  dataset: str | Path,
  out_dir: str | Path,
  backend: Any,
  provider_id: str = "",
  model_id: str = "",
  base_url: str = "",
  repair_retries: int = 1,
  reset: bool = False,
) -> dict[str, Any]:
  output_root = Path(out_dir)
  if reset and output_root.exists():
    shutil.rmtree(output_root)
  output_root.mkdir(parents=True, exist_ok=True)
  started = time.monotonic()

  cases = [("10", cve_id) for cve_id in cve_ids_10] + [("30", cve_id) for cve_id in cve_ids_30]
  results: list[dict[str, Any]] = []
  for run_group, cve_id in cases:
    case_out = output_root / "cases" / run_group / cve_id
    result = _run_case(
      run_group=run_group,
      cve_id=cve_id,
      judge_packet_root=judge_packet_root,
      detailed_evidence_root=detailed_evidence_root,
      slimming_root=slimming_root,
      dataset=dataset,
      out_dir=case_out,
      backend=backend,
      repair_retries=repair_retries,
    )
    results.append(result)

  forbidden_scan = scan_forbidden_full_stress_outputs(output_root)
  summary = _build_summary(
    results,
    forbidden_scan,
    cve_ids_10=cve_ids_10,
    cve_ids_30=cve_ids_30,
    duration_s=time.monotonic() - started,
    provider_id=provider_id,
    model_id=model_id,
    base_url=base_url,
  )
  _write_outputs(output_root, results, summary, forbidden_scan)
  return summary


def scan_forbidden_full_stress_outputs(root: str | Path) -> dict[str, Any]:
  root_path = Path(root)
  violations: list[dict[str, str]] = []
  for path in sorted(root_path.rglob("*")):
    if not path.is_file() or _is_prompt_file(path):
      continue
    if path.suffix.lower() == ".json":
      try:
        data = json.loads(path.read_text(encoding="utf-8"))
      except json.JSONDecodeError as error:
        violations.append({"path": str(path), "key": "<invalid_json>", "location": str(error)})
        continue
      scan = scan_forbidden_judge_fields(data)
      for item in scan["violations"]:
        violations.append({"path": str(path), **item})
      continue
    if path.suffix.lower() not in {".csv", ".md", ".txt"}:
      continue
    text = path.read_text(encoding="utf-8", errors="ignore")
    for key in sorted(FORBIDDEN_JUDGE_KEYS):
      if re.search(rf'"{re.escape(key)}"\s*:', text):
        violations.append({"path": str(path), "key": key, "location": "text_json_key_pattern"})
  return {
    "ok": not violations,
    "forbidden_keys": sorted(FORBIDDEN_JUDGE_KEYS),
    "violation_count": len(violations),
    "violations": violations,
  }


def _run_case(
  *,
  run_group: str,
  cve_id: str,
  judge_packet_root: str | Path,
  detailed_evidence_root: str | Path,
  slimming_root: str | Path,
  dataset: str | Path,
  out_dir: Path,
  backend: Any,
  repair_retries: int,
) -> dict[str, Any]:
  try:
    result = run_judge_v0_for_cve(
      cve_id=cve_id,
      judge_packet_root=judge_packet_root,
      detailed_evidence_root=detailed_evidence_root,
      slimming_root=slimming_root,
      dataset=dataset,
      out_dir=out_dir,
      backend=backend,
      repair_retries=repair_retries,
    )
  except Exception as error:
    out_dir.mkdir(parents=True, exist_ok=True)
    result = {
      "cve_id": cve_id,
      "backend_name": getattr(backend, "backend_name", ""),
      "backend_type": getattr(backend, "backend_type", ""),
      "status": "input_failed",
      "parse_status": "input_failed",
      "contract_ok": False,
      "case_disposition": "",
      "candidate_count": 0,
      "candidate_rankings": [],
      "excluded_count": 0,
      "attacker_context_available": False,
      "attacker_context_unavailable_reason": "input_failed",
      "attack_perspective_used": False,
      "prompt_bytes": 0,
      "raw_response_bytes": 0,
      "session_id": "",
      "initial_session_id": "",
      "retry_used": False,
      "contract_taxonomy": {"input_failed": 1},
      "lifecycle": "raw_candidate_judge_rejected",
      "forbidden_keys_present": False,
      "error": str(error),
    }
    _write_json(out_dir / "judge_result.json", result)
    _write_json(out_dir / "judge_contract_lint.json", {"ok": False, "errors": [str(error)], "taxonomy": {"input_failed": 1}})
    _write_json(out_dir / "parsed_judge_output.json", {})
    (out_dir / "raw_response.txt").write_text("", encoding="utf-8")

  _ensure_required_case_files(out_dir, result)
  judge_input = _read_json_default(out_dir / "judge_input_v0.json", {})
  parsed = _read_json_default(out_dir / "parsed_judge_output.json", {})
  contract = _read_json_default(out_dir / "judge_contract_lint.json", {})
  result = {
    **result,
    "run_group": run_group,
    "case_key": f"{run_group}:{cve_id}",
    "candidate_sources": _candidate_source_counts(judge_input),
    "fallback_candidate_count": _candidate_source_counts(judge_input).get("fallback", 0),
    "strong_candidate_count": _candidate_source_counts(judge_input).get("strong", 0),
    "ranked_count": len(parsed.get("candidate_judgments", []) or []) if isinstance(parsed, dict) else 0,
    "uncertain_count": _uncertain_count(parsed),
    "excluded_count": len(parsed.get("excluded_candidates", []) or []) if isinstance(parsed, dict) else int(result.get("excluded_count") or 0),
    "all_candidates_accounted": _all_candidates_accounted(judge_input, parsed),
    "judge_input_path": str(out_dir / "judge_input_v0.json"),
    "case_output_dir": str(out_dir),
    "contract_errors": contract.get("errors", []) if isinstance(contract, dict) else [],
  }
  _write_json(out_dir / "judge_result.json", result)
  return result


def _ensure_required_case_files(out_dir: Path, result: dict[str, Any]) -> None:
  if not (out_dir / "parsed_judge_output.json").exists():
    _write_json(out_dir / "parsed_judge_output.json", {})
  if not (out_dir / "judge_contract_lint.json").exists():
    _write_json(out_dir / "judge_contract_lint.json", {"ok": False, "errors": ["missing_contract"], "taxonomy": {"missing_contract": 1}})
  if not (out_dir / "raw_response.txt").exists():
    (out_dir / "raw_response.txt").write_text("", encoding="utf-8")
  if not (out_dir / "judge_prompt.txt").exists():
    (out_dir / "judge_prompt.txt").write_text("", encoding="utf-8")
  if not (out_dir / "judge_input_v0.json").exists():
    _write_json(out_dir / "judge_input_v0.json", {"cve_id": result.get("cve_id", ""), "candidate_set": []})


def _build_summary(
  results: list[dict[str, Any]],
  forbidden_scan: dict[str, Any],
  *,
  cve_ids_10: list[str],
  cve_ids_30: list[str],
  duration_s: float,
  provider_id: str,
  model_id: str,
  base_url: str,
) -> dict[str, Any]:
  duplicates = sorted(set(cve_ids_10) & set(cve_ids_30))
  prompt_sizes = [int(item.get("prompt_bytes") or 0) for item in results]
  candidate_count = sum(int(item.get("candidate_count") or 0) for item in results)
  accounted_count = sum(_accounted_count_for_result(item) for item in results)
  repair_retry_count = sum(1 for item in results if item.get("retry_used"))
  non_fixture_results = [item for item in results if item.get("backend_type") != "fixture"]
  summary = {
    "input_case_count_10": len(cve_ids_10),
    "input_case_count_30": len(cve_ids_30),
    "total_input_cases": len(results),
    "cases_total": len(results),
    "unique_cve_count": len(set(cve_ids_10) | set(cve_ids_30)),
    "duplicate_cve_count": len(duplicates),
    "duplicate_cves": duplicates,
    "provider_id": provider_id,
    "model_id": model_id,
    "base_url": base_url,
    "execution_mode": "full_stress",
    "model_invocation_count": len(non_fixture_results) + repair_retry_count,
    "parse_ok_count": sum(1 for item in results if item.get("parse_status") in {"json", "fenced_json"}),
    "contract_ok_count": sum(1 for item in results if item.get("contract_ok")),
    "backend_failed_count": sum(1 for item in results if item.get("status") in {"failed", "input_failed"}),
    "empty_response_count": sum(1 for item in results if item.get("parse_status") == "empty" or item.get("status") == "empty"),
    "empty_message_count": sum(1 for item in results if item.get("parse_status") == "empty" or item.get("status") == "empty"),
    "repair_retry_count": repair_retry_count,
    "forbidden_field_scan_ok": bool(forbidden_scan.get("ok")),
    "forbidden_violation_count": int(forbidden_scan.get("violation_count") or 0),
    "attacker_context_available_count": sum(1 for item in results if item.get("attacker_context_available")),
    "attacker_context_unavailable_count": sum(1 for item in results if not item.get("attacker_context_available")),
    "attacker_unavailable_but_used_count": sum(1 for item in results if not item.get("attacker_context_available") and item.get("attack_perspective_used")),
    "strong_candidate_count": sum(int(item.get("strong_candidate_count") or 0) for item in results),
    "fallback_candidate_count": sum(int(item.get("fallback_candidate_count") or 0) for item in results),
    "ranked_count": sum(int(item.get("ranked_count") or 0) for item in results),
    "excluded_count": sum(int(item.get("excluded_count") or 0) for item in results),
    "uncertain_count": sum(int(item.get("uncertain_count") or 0) for item in results),
    "all_candidates_accounted_rate": round(accounted_count / candidate_count, 6) if candidate_count else 1.0,
    "prompt_byte_statistics": _size_stats(prompt_sizes),
    "prompt_byte_total": sum(prompt_sizes),
    "per_cve_session_id_mapping": [
      {
        "run_group": item.get("run_group"),
        "cve_id": item.get("cve_id"),
        "session_id": item.get("session_id", ""),
        "initial_session_id": item.get("initial_session_id", ""),
        "retry_used": bool(item.get("retry_used")),
      }
      for item in results
    ],
    "top1_raw_candidate_judgments": _top1_judgments(results),
    "lifecycle": "raw_candidate_judged",
    "duration_s": round(duration_s, 6),
    "results": results,
  }
  return summary


def _write_outputs(output_root: Path, results: list[dict[str, Any]], summary: dict[str, Any], forbidden_scan: dict[str, Any]) -> None:
  _write_json(output_root / "summary.json", summary)
  _write_json(output_root / "forbidden_field_scan.json", forbidden_scan)
  _write_json(output_root / "session_manifest.json", _session_manifest(summary))
  _write_csv(output_root / "judge_rankings.csv", _ranking_rows(results), JUDGE_RANKING_COLUMNS)
  _write_csv(output_root / "judge_contract_summary.csv", _contract_rows(results), CONTRACT_COLUMNS)
  _write_csv(output_root / "candidate_type_metrics.csv", _candidate_type_rows(results), CANDIDATE_TYPE_COLUMNS)
  _write_csv(output_root / "prompt_size_summary.csv", _prompt_size_rows(results), PROMPT_SIZE_COLUMNS)
  _write_csv(output_root / "manual_review_queue.csv", _manual_review_rows(results), MANUAL_REVIEW_COLUMNS)
  (output_root / "judge_full_stress_report.md").write_text(_render_report(summary), encoding="utf-8")


def _ranking_rows(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
  rows: list[dict[str, Any]] = []
  for result in results:
    case_dir = Path(str(result.get("case_output_dir") or ""))
    judge_input = _read_json_default(case_dir / "judge_input_v0.json", {})
    parsed = _read_json_default(case_dir / "parsed_judge_output.json", {})
    candidates = {str(item.get("candidate_id") or ""): item for item in judge_input.get("candidate_set", []) or []}
    for item in parsed.get("candidate_judgments", []) or []:
      candidate = candidates.get(str(item.get("candidate_id") or ""), {})
      rows.append(
        {
          "run_group": result.get("run_group", ""),
          "cve_id": result.get("cve_id", ""),
          "candidate_id": item.get("candidate_id", ""),
          "candidate_commit_sha": item.get("candidate_commit_sha", ""),
          "rank": item.get("rank", ""),
          "decision": item.get("judgment", ""),
          "confidence": item.get("confidence", ""),
          "candidate_source": candidate.get("candidate_source", ""),
          "candidate_anchor_role": candidate.get("candidate_anchor_role", ""),
          "risk_flags": candidate.get("risk_flags", []),
          "evidence_refs_used": item.get("evidence_refs_used", []),
          "top1_raw_candidate_judgment": item.get("rank") == 1,
          "lifecycle": "raw_candidate_judged",
        }
      )
  return rows


def _contract_rows(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
  rows: list[dict[str, Any]] = []
  for item in results:
    rows.append(
      {
        "run_group": item.get("run_group", ""),
        "cve_id": item.get("cve_id", ""),
        "backend_type": item.get("backend_type", ""),
        "status": item.get("status", ""),
        "parse_status": item.get("parse_status", ""),
        "contract_ok": bool(item.get("contract_ok")),
        "case_disposition": item.get("case_disposition", ""),
        "candidate_count": int(item.get("candidate_count") or 0),
        "ranked_count": int(item.get("ranked_count") or 0),
        "excluded_count": int(item.get("excluded_count") or 0),
        "uncertain_count": int(item.get("uncertain_count") or 0),
        "all_candidates_accounted": bool(item.get("all_candidates_accounted")),
        "retry_used": bool(item.get("retry_used")),
        "session_id": item.get("session_id", ""),
        "prompt_bytes": int(item.get("prompt_bytes") or 0),
        "raw_response_bytes": int(item.get("raw_response_bytes") or 0),
        "taxonomy": item.get("contract_taxonomy", {}),
      }
    )
  return rows


def _candidate_type_rows(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
  counts: dict[str, Counter[str]] = defaultdict(Counter)
  for result in results:
    case_dir = Path(str(result.get("case_output_dir") or ""))
    judge_input = _read_json_default(case_dir / "judge_input_v0.json", {})
    parsed = _read_json_default(case_dir / "parsed_judge_output.json", {})
    candidates = {str(item.get("candidate_id") or ""): item for item in judge_input.get("candidate_set", []) or []}
    accounted: set[str] = set()
    for item in parsed.get("candidate_judgments", []) or []:
      candidate_id = str(item.get("candidate_id") or "")
      source = str(candidates.get(candidate_id, {}).get("candidate_source") or "unknown")
      counts[source]["candidate_count"] += 1
      counts[source]["ranked_count"] += 1
      if item.get("judgment") == "uncertain_boundary":
        counts[source]["uncertain_count"] += 1
      elif item.get("judgment") == "plausible_introduction_boundary":
        counts[source]["plausible_count"] += 1
      elif item.get("judgment") == "unlikely_boundary":
        counts[source]["unlikely_count"] += 1
      accounted.add(candidate_id)
    for item in parsed.get("excluded_candidates", []) or []:
      candidate_id = str(item.get("candidate_id") or "")
      source = str(candidates.get(candidate_id, {}).get("candidate_source") or "unknown")
      counts[source]["candidate_count"] += 1
      counts[source]["excluded_count"] += 1
      accounted.add(candidate_id)
    for candidate_id, candidate in candidates.items():
      if candidate_id not in accounted:
        source = str(candidate.get("candidate_source") or "unknown")
        counts[source]["candidate_count"] += 1
        counts[source]["unaccounted_count"] += 1
  return [
    {
      "candidate_source": source,
      "candidate_count": counter["candidate_count"],
      "ranked_count": counter["ranked_count"],
      "excluded_count": counter["excluded_count"],
      "uncertain_count": counter["uncertain_count"],
      "plausible_count": counter["plausible_count"],
      "unlikely_count": counter["unlikely_count"],
      "unaccounted_count": counter["unaccounted_count"],
    }
    for source, counter in sorted(counts.items())
  ]


def _prompt_size_rows(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
  return [
    {
      "run_group": item.get("run_group", ""),
      "cve_id": item.get("cve_id", ""),
      "candidate_count": int(item.get("candidate_count") or 0),
      "prompt_bytes": int(item.get("prompt_bytes") or 0),
      "raw_response_bytes": int(item.get("raw_response_bytes") or 0),
    }
    for item in results
  ]


def _manual_review_rows(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
  rows: list[dict[str, Any]] = []
  for item in results:
    reasons: list[str] = []
    if not item.get("contract_ok"):
      reasons.append("contract_or_parse_failure")
    if item.get("status") in {"failed", "input_failed", "empty"}:
      reasons.append("backend_or_input_failure")
    if int(item.get("fallback_candidate_count") or 0):
      reasons.append("fallback_candidate_present")
    if not item.get("all_candidates_accounted"):
      reasons.append("candidate_accounting_incomplete")
    if not reasons:
      continue
    rows.append(
      {
        "run_group": item.get("run_group", ""),
        "cve_id": item.get("cve_id", ""),
        "reason": ";".join(reasons),
        "candidate_count": int(item.get("candidate_count") or 0),
        "fallback_candidate_count": int(item.get("fallback_candidate_count") or 0),
        "contract_ok": bool(item.get("contract_ok")),
        "parse_status": item.get("parse_status", ""),
        "taxonomy": item.get("contract_taxonomy", {}),
      }
    )
  return rows


def _session_manifest(summary: dict[str, Any]) -> dict[str, Any]:
  return {
    "provider_id": summary.get("provider_id", ""),
    "model_id": summary.get("model_id", ""),
    "base_url": summary.get("base_url", ""),
    "execution_mode": summary.get("execution_mode", ""),
    "sessions": summary.get("per_cve_session_id_mapping", []),
  }


def _render_report(summary: dict[str, Any]) -> str:
  lines = [
    "# VulnGraph Judge Agent v0 Full Stress Evaluation",
    "",
    "This is an engineering stress run for evidence-backed raw candidate boundary ranking. It does not validate BICs and does not perform affected-version conversion.",
    "",
    f"- input_case_count_10: {summary['input_case_count_10']}",
    f"- input_case_count_30: {summary['input_case_count_30']}",
    f"- total_input_cases: {summary['total_input_cases']}",
    f"- unique_cve_count: {summary['unique_cve_count']}",
    f"- duplicate_cve_count: {summary['duplicate_cve_count']}",
    f"- duplicate_cves: {summary['duplicate_cves']}",
    f"- provider/model: {summary.get('provider_id', '')}/{summary.get('model_id', '')}",
    f"- model_invocation_count: {summary['model_invocation_count']}",
    f"- parse_ok_count: {summary['parse_ok_count']}",
    f"- contract_ok_count: {summary['contract_ok_count']}",
    f"- backend_failed_count: {summary['backend_failed_count']}",
    f"- empty_response_count: {summary['empty_response_count']}",
    f"- repair_retry_count: {summary['repair_retry_count']}",
    f"- forbidden_violation_count: {summary['forbidden_violation_count']}",
    f"- attacker_context_available_count: {summary['attacker_context_available_count']}",
    f"- attacker_context_unavailable_count: {summary['attacker_context_unavailable_count']}",
    f"- attacker_unavailable_but_used_count: {summary['attacker_unavailable_but_used_count']}",
    f"- strong_candidate_count: {summary['strong_candidate_count']}",
    f"- fallback_candidate_count: {summary['fallback_candidate_count']}",
    f"- ranked_count: {summary['ranked_count']}",
    f"- excluded_count: {summary['excluded_count']}",
    f"- uncertain_count: {summary['uncertain_count']}",
    f"- all_candidates_accounted_rate: {summary['all_candidates_accounted_rate']}",
    f"- prompt_byte_statistics: {summary['prompt_byte_statistics']}",
    f"- lifecycle: {summary['lifecycle']}",
    "",
    "Per-CVE top candidate is reported only as `top1_raw_candidate_judgment`; it is not a final introduction commit.",
  ]
  return "\n".join(lines) + "\n"


def _all_candidates_accounted(judge_input: dict[str, Any], parsed: dict[str, Any]) -> bool:
  candidates = {str(item.get("candidate_id") or "") for item in judge_input.get("candidate_set", []) or [] if item.get("candidate_id")}
  if not candidates:
    return True
  accounted = {
    str(item.get("candidate_id") or "")
    for item in (parsed.get("candidate_judgments", []) or []) + (parsed.get("excluded_candidates", []) or [])
    if item.get("candidate_id")
  }
  return candidates == accounted


def _accounted_count_for_result(result: dict[str, Any]) -> int:
  return int(result.get("ranked_count") or 0) + int(result.get("excluded_count") or 0)


def _uncertain_count(parsed: dict[str, Any]) -> int:
  if not isinstance(parsed, dict):
    return 0
  return sum(1 for item in parsed.get("candidate_judgments", []) or [] if item.get("judgment") == "uncertain_boundary")


def _candidate_source_counts(judge_input: dict[str, Any]) -> dict[str, int]:
  counter: Counter[str] = Counter()
  for item in judge_input.get("candidate_set", []) or []:
    counter[str(item.get("candidate_source") or "unknown")] += 1
  return dict(counter)


def _top1_judgments(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
  output: list[dict[str, Any]] = []
  for result in results:
    case_dir = Path(str(result.get("case_output_dir") or ""))
    parsed = _read_json_default(case_dir / "parsed_judge_output.json", {})
    for item in parsed.get("candidate_judgments", []) or []:
      if item.get("rank") != 1:
        continue
      output.append(
        {
          "run_group": result.get("run_group", ""),
          "cve_id": result.get("cve_id", ""),
          "top1_raw_candidate_judgment": {
            "candidate_id": item.get("candidate_id", ""),
            "candidate_commit_sha": item.get("candidate_commit_sha", ""),
            "decision": item.get("judgment", ""),
            "confidence": item.get("confidence", ""),
          },
        }
      )
  return output


def _size_stats(values: list[int]) -> dict[str, int | float]:
  if not values:
    return {"min": 0, "median": 0, "max": 0, "total": 0}
  return {
    "min": min(values),
    "median": median(values),
    "max": max(values),
    "total": sum(values),
  }


def _is_prompt_file(path: Path) -> bool:
  return "prompt" in path.name.lower()


def _read_json_default(path: Path, default: dict[str, Any]) -> dict[str, Any]:
  if not path.exists():
    return default
  data = json.loads(path.read_text(encoding="utf-8"))
  return data if isinstance(data, dict) else default


def _write_json(path: Path, data: Any) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]], columns: list[str]) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  with path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=columns)
    writer.writeheader()
    for row in rows:
      writer.writerow({column: _csv_value(row.get(column, "")) for column in columns})


def _csv_value(value: Any) -> Any:
  if isinstance(value, (list, dict)):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
  return value

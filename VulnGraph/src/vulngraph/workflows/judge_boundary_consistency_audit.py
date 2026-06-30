from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def audit_boundary_run(run_root: str | Path) -> dict[str, Any]:
  root = Path(run_root)
  cases = []
  for case_dir in sorted(
    item for item in root.iterdir() if item.is_dir() and item.name.startswith("CVE-")
  ):
    parsed = _read_json_default(case_dir / "parsed_boundary_output.json", {})
    result = _read_json_default(case_dir / "judge_boundary_result.json", {})
    judgments = [
      item for item in parsed.get("candidate_judgments", []) or []
      if isinstance(item, dict)
    ]
    selected = [item for item in judgments if item.get("decision") == "selected"]
    rejected = [item for item in judgments if item.get("decision") == "rejected"]
    uncertain = [item for item in judgments if item.get("decision") == "uncertain"]
    events = [
      item for item in parsed.get("selected_boundary_events", []) or []
      if isinstance(item, dict)
    ]
    rejected_view = [
      item for item in parsed.get("rejected_candidates", []) or []
      if isinstance(item, dict)
    ]
    uncertainty_view = parsed.get("uncertainty", []) or []
    event_ids = {str(item.get("candidate_id") or "") for item in events}
    selected_missing = [
      str(item.get("candidate_id") or "")
      for item in selected
      if str(item.get("candidate_id") or "") not in event_ids
    ]
    conflicts = [
      {
        "candidate_id": str(item.get("candidate_id") or ""),
        "decision": str(item.get("decision") or ""),
        "boundary_role": str(item.get("boundary_role") or ""),
      }
      for item in judgments
      if not _legacy_decision_role_consistent(
        str(item.get("decision") or ""),
        str(item.get("boundary_role") or ""),
      )
    ]
    cases.append(
      {
        "cve_id": case_dir.name,
        "contract_ok": bool(result.get("contract_ok")),
        "judgment_count": len(judgments),
        "selected_judgment_count": len(selected),
        "selected_event_count": len(events),
        "selected_judgment_missing_event_ids": selected_missing,
        "decision_role_conflicts": conflicts,
        "rejected_judgment_count": len(rejected),
        "rejected_view_count": len(rejected_view),
        "reported_rejected_count": int(result.get("rejected_count") or 0),
        "uncertain_judgment_count": len(uncertain),
        "uncertainty_view_count": len(uncertainty_view),
        "reported_uncertain_count": int(result.get("uncertain_count") or 0),
      }
    )

  return {
    "schema_version": "judge_boundary_consistency_audit_v1_1",
    "source_run": str(root),
    "summary": {
      "case_count": len(cases),
      "selected_judgment_missing_event_case_count": sum(
        1 for item in cases if item["selected_judgment_missing_event_ids"]
      ),
      "selected_judgment_missing_event_count": sum(
        len(item["selected_judgment_missing_event_ids"]) for item in cases
      ),
      "decision_role_conflict_case_count": sum(
        1 for item in cases if item["decision_role_conflicts"]
      ),
      "decision_role_conflict_count": sum(
        len(item["decision_role_conflicts"]) for item in cases
      ),
      "rejected_stat_mismatch_case_count": sum(
        1
        for item in cases
        if item["rejected_judgment_count"] != item["rejected_view_count"]
        or item["rejected_judgment_count"] != item["reported_rejected_count"]
      ),
      "uncertain_stat_mismatch_case_count": sum(
        1
        for item in cases
        if item["uncertain_judgment_count"] != item["reported_uncertain_count"]
      ),
    },
    "cases": cases,
    "notes": [
      "This is a no-model replay of the frozen Judge Boundary v1 artifacts.",
      "It audits duplicated model-owned views and does not alter old artifacts.",
    ],
  }


def write_boundary_consistency_audit(
  run_root: str | Path,
  output_path: str | Path,
) -> dict[str, Any]:
  audit = audit_boundary_run(run_root)
  path = Path(output_path)
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(audit, ensure_ascii=False, indent=2), encoding="utf-8")
  return audit


def _legacy_decision_role_consistent(decision: str, role: str) -> bool:
  if decision == "selected":
    return role in {"introduction", "activation", "prerequisite"}
  if decision == "rejected":
    return role in {"fix_series_noise", "refactor_noise", "equivalent_fix_noise"}
  return decision == "uncertain" and role in {
    "uncertain_boundary",
    "introduction",
    "activation",
    "prerequisite",
    "fix_series_noise",
    "refactor_noise",
    "equivalent_fix_noise",
  }


def _read_json_default(path: Path, default: dict[str, Any]) -> dict[str, Any]:
  if not path.exists():
    return default
  data = json.loads(path.read_text(encoding="utf-8"))
  return data if isinstance(data, dict) else default

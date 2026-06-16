from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnversion.self_evolve.leakage_gate import apply_leakage_gate, load_jsonl


def apply_promotion_gates(
  *,
  memory_candidates_path: str | Path,
  case_pack_dir: str | Path,
  out_dir: str | Path,
) -> dict[str, Any]:
  candidates = load_jsonl(memory_candidates_path)
  case_pack = Path(case_pack_dir)
  out = Path(out_dir)
  out.mkdir(parents=True, exist_ok=True)
  gated: list[dict[str, Any]] = []
  for candidate in candidates:
    gated_candidate = apply_promotion_gate(candidate, case_pack_dir=case_pack)
    gated.append(gated_candidate)
  _write_jsonl(out / "gated_memory_candidates.jsonl", gated)
  summary = {
    "status": "complete",
    "total_candidates": len(gated),
    "status_counts": _count(str(c.get("status") or "unknown") for c in gated),
    "blocked_reason_counts": _count(str(c.get("blocked_reason") or "none") for c in gated),
    "injection_allowed_count": sum(1 for c in gated if c.get("injection_allowed") is True),
    "case_pack_dir": str(case_pack.resolve()),
    "output_dir": str(out.resolve()),
  }
  _write_json(out / "gate_summary.json", summary)
  return summary


def apply_promotion_gate(candidate: dict[str, Any], *, case_pack_dir: str | Path) -> dict[str, Any]:
  gated = apply_leakage_gate(candidate)
  if gated.get("leakage_findings"):
    return gated

  case_pack = Path(case_pack_dir)
  reasons: list[str] = []
  if not (case_pack / "case_index.jsonl").exists():
    reasons.append("case_pack_missing")
  if _summary_status(case_pack / "replay_summary.json") == "not_run":
    reasons.append("replay_summary_missing_or_not_run")
  if _summary_status(case_pack / "small_sample_summary.json") == "not_run":
    reasons.append("small_sample_summary_missing_or_not_run")
  for name in ("improved_cases.jsonl", "regression_cases.jsonl", "unchanged_failure_cases.jsonl"):
    if not (case_pack / name).exists():
      reasons.append(f"{name}_missing")
  if gated.get("memory_type") == "SkillMemory" and len(gated.get("source_case_ids") or []) < 2:
    reasons.append("single_case_skillmemory_blocked")

  if reasons:
    gated["status"] = "blocked"
    gated["blocked_reason"] = reasons[0]
    gated["blocked_reasons"] = reasons
    gated["injection_allowed"] = False
    return gated

  gated["status"] = "verified"
  gated["blocked_reason"] = None
  gated["blocked_reasons"] = []
  gated["injection_allowed"] = True
  return gated


def _summary_status(path: Path) -> str:
  if not path.exists():
    return "not_run"
  try:
    value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
  except json.JSONDecodeError:
    return "not_run"
  status = str(value.get("status") or "not_run")
  return status


def _write_json(path: Path, value: Any) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  with path.open("w", encoding="utf-8") as f:
    for row in rows:
      f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _count(values: Any) -> dict[str, int]:
  out: dict[str, int] = {}
  for value in values:
    out[value] = out.get(value, 0) + 1
  return dict(sorted(out.items()))

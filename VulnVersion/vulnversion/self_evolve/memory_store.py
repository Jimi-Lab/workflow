from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnversion.self_evolve.memory_candidates import MemoryCandidate, build_memory_candidates_from_case_pack


def build_memory_store(
  *,
  case_pack_root: str | Path,
  out_root: str | Path,
  enhancement_id: str,
) -> dict[str, Any]:
  case_pack_dir = Path(case_pack_root) / enhancement_id
  out_dir = Path(out_root) / enhancement_id
  out_dir.mkdir(parents=True, exist_ok=True)
  candidates = build_memory_candidates_from_case_pack(case_pack_dir)
  _write_jsonl(out_dir / "memory_candidates.jsonl", [c.model_dump() for c in candidates])
  summary = memory_summary(candidates, enhancement_id=enhancement_id, case_pack_dir=case_pack_dir, out_dir=out_dir)
  _write_json(out_dir / "memory_summary.json", summary)
  return summary


def memory_summary(
  candidates: list[MemoryCandidate],
  *,
  enhancement_id: str,
  case_pack_dir: Path,
  out_dir: Path,
) -> dict[str, Any]:
  return {
    "enhancement_id": enhancement_id,
    "status": "candidate",
    "case_pack_dir": str(case_pack_dir.resolve()),
    "output_dir": str(out_dir.resolve()),
    "total_candidates": len(candidates),
    "candidate_counts_by_type": _count(c.memory_type for c in candidates),
    "candidate_counts_by_stage": _count(c.stage for c in candidates),
    "leakage_risk_counts": _count(c.leakage_risk for c in candidates),
    "promotion_blocked_reasons": {
      "replay_summary_missing_or_not_run": len(candidates),
      "small_sample_summary_missing_or_not_run": len(candidates),
      "leakage_gate_not_run": len(candidates),
    },
    "injection_allowed": False,
  }


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
    key = str(value)
    out[key] = out.get(key, 0) + 1
  return dict(sorted(out.items()))

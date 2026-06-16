from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
  sys.path.insert(0, str(PROJECT_ROOT))

from vulnversion.self_evolve.memory_store import build_memory_store
from vulnversion.self_evolve.promotion_gate import apply_promotion_gate, apply_promotion_gates


def _write_json(path: Path, value: Any) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  with path.open("w", encoding="utf-8") as f:
    for row in rows:
      f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _case(case_id: str, *, failure_type: str = "FP", repo: str = "demo", cve: str = "CVE-TEST-0001") -> dict[str, Any]:
  return {
    "case_id": case_id,
    "enhancement_id": "fixture",
    "repo": repo,
    "cve_id": cve,
    "stage": "stage3",
    "task_type": "tag_verdict",
    "failure_type": failure_type,
    "attribution": {
      "category": "stage3_legacy_agent_judge",
      "stage": "stage3",
      "agent_judge_relevant": True,
      "reason": "fixture",
      "blocked_from_injection": True,
      "suggested_next_step": "inspect",
    },
    "source_paths": {"result_dir": str(PROJECT_ROOT / "Result" / repo / cve)},
    "run_status": "OK",
    "verdict_source": None,
    "evidence_summary": {
      "matched_predicates": ["vp1"],
      "failed_predicates": ["fp1"],
      "triggered_guards": [],
      "evidence_snippet_count": 1,
      "has_reasoning_summary": True,
    },
    "offline_oracle": {"offline_only": True},
    "leakage_policy": {"may_enter_prompt": False},
  }


def _prepare_case_pack(root: Path, *, case_count: int = 2, replay: str = "not_run", sample: str = "not_run") -> Path:
  pack = root / "Result_agent_enhance_cases" / "fixture"
  cases = [_case(f"case_{i}", failure_type="FP" if i % 2 == 0 else "FN") for i in range(case_count)]
  _write_jsonl(pack / "case_index.jsonl", cases)
  _write_json(pack / "replay_summary.json", {"status": replay})
  _write_json(pack / "small_sample_summary.json", {"status": sample})
  for name in ("improved_cases.jsonl", "regression_cases.jsonl", "unchanged_failure_cases.jsonl"):
    (pack / name).write_text("", encoding="utf-8")
  return pack


def main() -> int:
  checks: list[dict[str, Any]] = []
  with tempfile.TemporaryDirectory() as tmp:
    tmp_dir = Path(tmp)
    pack = _prepare_case_pack(tmp_dir)
    summary = build_memory_store(
      case_pack_root=tmp_dir / "Result_agent_enhance_cases",
      out_root=tmp_dir / "Result_agent_enhance_memory",
      enhancement_id="fixture",
    )
    memory_path = tmp_dir / "Result_agent_enhance_memory" / "fixture" / "memory_candidates.jsonl"
    gate_summary = apply_promotion_gates(
      memory_candidates_path=memory_path,
      case_pack_dir=pack,
      out_dir=tmp_dir / "Result_agent_enhance_memory" / "fixture",
    )
    checks.append({
      "id": "clean_candidate_blocked_by_missing_replay",
      "pass": summary["total_candidates"] > 0 and gate_summary["status_counts"].get("blocked", 0) > 0,
    })

  with tempfile.TemporaryDirectory() as tmp:
    tmp_dir = Path(tmp)
    pack = _prepare_case_pack(tmp_dir)
    leaking = {
      "memory_id": "leak",
      "memory_type": "FailureMemory",
      "source_case_ids": ["case_0"],
      "content": {"bad": "GT affected tags and affected range must block"},
      "status": "candidate",
      "injection_allowed": False,
    }
    gated = apply_promotion_gate(leaking, case_pack_dir=pack)
    checks.append({
      "id": "leakage_candidate_blocked",
      "pass": gated.get("status") == "blocked" and gated.get("blocked_reason") == "leakage_gate_failed",
    })

  with tempfile.TemporaryDirectory() as tmp:
    tmp_dir = Path(tmp)
    pack = _prepare_case_pack(tmp_dir, case_count=1, replay="passed", sample="passed")
    skill = {
      "memory_id": "single_skill",
      "memory_type": "SkillMemory",
      "source_case_ids": ["case_0"],
      "content": {"candidate_rule": "single case rule"},
      "status": "candidate",
      "injection_allowed": False,
    }
    gated = apply_promotion_gate(skill, case_pack_dir=pack)
    checks.append({
      "id": "single_case_skillmemory_blocked",
      "pass": "single_case_skillmemory_blocked" in gated.get("blocked_reasons", []),
    })

  with tempfile.TemporaryDirectory() as tmp:
    tmp_dir = Path(tmp)
    pack = _prepare_case_pack(tmp_dir, case_count=2)
    skill = {
      "memory_id": "repeat_skill",
      "memory_type": "SkillMemory",
      "source_case_ids": ["case_0", "case_1"],
      "content": {"candidate_rule": "repeated clean rule"},
      "status": "candidate",
      "injection_allowed": False,
    }
    gated = apply_promotion_gate(skill, case_pack_dir=pack)
    checks.append({
      "id": "repeated_skillmemory_blocked_without_replay_sample",
      "pass": gated.get("status") == "blocked" and "replay_summary_missing_or_not_run" in gated.get("blocked_reasons", []),
    })

  with tempfile.TemporaryDirectory() as tmp:
    tmp_dir = Path(tmp)
    pack = _prepare_case_pack(tmp_dir, case_count=2, replay="passed", sample="passed")
    clean = {
      "memory_id": "clean",
      "memory_type": "FailureMemory",
      "source_case_ids": ["case_0"],
      "content": {"note": "clean candidate"},
      "status": "candidate",
      "injection_allowed": False,
    }
    gated = apply_promotion_gate(clean, case_pack_dir=pack)
    checks.append({
      "id": "fixture_all_required_summaries_can_pass",
      "pass": gated.get("status") == "verified" and gated.get("injection_allowed") is True,
    })

  failed = [c for c in checks if not c["pass"]]
  print(json.dumps({"passed": len(checks) - len(failed), "failed": len(failed), "checks": checks}, ensure_ascii=False, indent=2))
  return 0 if not failed else 1


if __name__ == "__main__":
  raise SystemExit(main())

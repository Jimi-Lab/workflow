from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class MemoryCandidate:
  memory_id: str
  memory_type: str
  source_case_ids: list[str]
  repo: str | None
  cve_id: str | None
  cwe_id: str | None
  stage: str
  task_type: str
  content: dict[str, Any]
  evidence_paths: list[str]
  scope: dict[str, Any]
  reliability: dict[str, Any]
  status: str = "candidate"
  injection_allowed: bool = False
  leakage_risk: str = "unchecked"
  promotion_requirements: list[str] = field(
    default_factory=lambda: [
      "case_pack_exists",
      "replay_summary_passed",
      "small_sample_summary_passed",
      "leakage_gate_passed",
      "improved_regression_unchanged_reports_present",
    ]
  )

  def model_dump(self) -> dict[str, Any]:
    return asdict(self)


def load_cases(case_index_path: str | Path) -> list[dict[str, Any]]:
  cases: list[dict[str, Any]] = []
  with Path(case_index_path).open("r", encoding="utf-8", errors="replace") as f:
    for line in f:
      text = line.strip()
      if not text:
        continue
      value = json.loads(text)
      if isinstance(value, dict):
        cases.append(value)
  return cases


def build_memory_candidates_from_case_pack(case_pack_dir: str | Path) -> list[MemoryCandidate]:
  case_pack = Path(case_pack_dir)
  cases = load_cases(case_pack / "case_index.jsonl")
  candidates: list[MemoryCandidate] = []
  candidates.extend(_failure_memory(cases))
  candidates.extend(_repo_memory(cases))
  candidates.extend(_rci_memory(cases))
  candidates.extend(_skill_memory(cases))
  return candidates


def _failure_memory(cases: list[dict[str, Any]]) -> list[MemoryCandidate]:
  out: list[MemoryCandidate] = []
  for case in cases:
    case_id = str(case.get("case_id") or "")
    source_paths = _source_paths(case)
    attribution = case.get("attribution") if isinstance(case.get("attribution"), dict) else {}
    content = {
      "failure_type": case.get("failure_type"),
      "attribution_category": attribution.get("category"),
      "agent_judge_relevant": bool(attribution.get("agent_judge_relevant")),
      "stage": case.get("stage"),
      "task_type": case.get("task_type"),
      "run_status": case.get("run_status"),
      "verdict_source": case.get("verdict_source"),
      "evidence_summary": case.get("evidence_summary") if isinstance(case.get("evidence_summary"), dict) else {},
      "promotion_note": "candidate only; not verdict evidence",
    }
    out.append(
      MemoryCandidate(
        memory_id=_memory_id("FailureMemory", [case_id], content),
        memory_type="FailureMemory",
        source_case_ids=[case_id],
        repo=_optional_str(case.get("repo")),
        cve_id=_optional_str(case.get("cve_id")),
        cwe_id=_case_cwe_id(case),
        stage=str(case.get("stage") or "unknown"),
        task_type=str(case.get("task_type") or "unknown"),
        content=content,
        evidence_paths=source_paths,
        scope={"type": "case", "repo": case.get("repo"), "stage": case.get("stage")},
        reliability={"level": "low", "reason": "single offline case; replay and sample validation not run"},
      )
    )
  return out


def _repo_memory(cases: list[dict[str, Any]]) -> list[MemoryCandidate]:
  out: list[MemoryCandidate] = []
  by_repo: dict[str, list[dict[str, Any]]] = {}
  for case in cases:
    repo = str(case.get("repo") or "")
    if repo:
      by_repo.setdefault(repo, []).append(case)
  for repo, repo_cases in sorted(by_repo.items()):
    if len(repo_cases) < 2:
      continue
    source_ids = [str(c.get("case_id") or "") for c in repo_cases]
    content = {
      "repo": repo,
      "observed_failure_count": len(repo_cases),
      "stage_counts": _count(str(c.get("stage") or "unknown") for c in repo_cases),
      "failure_type_counts": _count(str(c.get("failure_type") or "unknown") for c in repo_cases),
      "candidate_use": "repo-specific navigation and evidence review; no version answer stored",
    }
    out.append(
      MemoryCandidate(
        memory_id=_memory_id("RepoMemory", source_ids, content),
        memory_type="RepoMemory",
        source_case_ids=source_ids,
        repo=repo,
        cve_id=None,
        cwe_id=None,
        stage="multi",
        task_type="repo_context",
        content=content,
        evidence_paths=_unique_paths(repo_cases),
        scope={"type": "repo", "repo": repo},
        reliability={"level": "low", "reason": "aggregated offline cases; replay and sample validation not run"},
      )
    )
  return out


def _rci_memory(cases: list[dict[str, Any]]) -> list[MemoryCandidate]:
  out: list[MemoryCandidate] = []
  for case in cases:
    evidence = case.get("evidence_summary") if isinstance(case.get("evidence_summary"), dict) else {}
    matched = evidence.get("matched_predicates")
    failed = evidence.get("failed_predicates")
    guards = evidence.get("triggered_guards")
    if not any(isinstance(v, list) and v for v in (matched, failed, guards)):
      continue
    case_id = str(case.get("case_id") or "")
    content = {
      "predicate_signal": {
        "matched_predicate_count": len(matched) if isinstance(matched, list) else 0,
        "failed_predicate_count": len(failed) if isinstance(failed, list) else 0,
        "triggered_guard_count": len(guards) if isinstance(guards, list) else 0,
      },
      "failure_type": case.get("failure_type"),
      "risk": "predicate or guard alignment needs review before prompt use",
    }
    out.append(
      MemoryCandidate(
        memory_id=_memory_id("RCIMemory", [case_id], content),
        memory_type="RCIMemory",
        source_case_ids=[case_id],
        repo=_optional_str(case.get("repo")),
        cve_id=_optional_str(case.get("cve_id")),
        cwe_id=_case_cwe_id(case),
        stage=str(case.get("stage") or "unknown"),
        task_type=str(case.get("task_type") or "unknown"),
        content=content,
        evidence_paths=_source_paths(case),
        scope={"type": "case_rci", "repo": case.get("repo"), "stage": case.get("stage")},
        reliability={"level": "low", "reason": "predicate signal from offline verdict row only"},
      )
    )
  return out


def _skill_memory(cases: list[dict[str, Any]]) -> list[MemoryCandidate]:
  out: list[MemoryCandidate] = []
  groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
  for case in cases:
    attribution = case.get("attribution") if isinstance(case.get("attribution"), dict) else {}
    key = (
      str(case.get("stage") or "unknown"),
      str(case.get("failure_type") or "unknown"),
      str(attribution.get("category") or "unknown"),
    )
    groups.setdefault(key, []).append(case)
  for (stage, failure_type, category), group in sorted(groups.items()):
    if len(group) < 2:
      continue
    source_ids = [str(c.get("case_id") or "") for c in group]
    content = {
      "candidate_rule": f"When {stage} has repeated {failure_type} cases attributed to {category}, require evidence-localization review before promotion.",
      "repeat_count": len(group),
      "failure_type": failure_type,
      "attribution_category": category,
      "candidate_only": True,
    }
    out.append(
      MemoryCandidate(
        memory_id=_memory_id("SkillMemory", source_ids, content),
        memory_type="SkillMemory",
        source_case_ids=source_ids,
        repo=None,
        cve_id=None,
        cwe_id=None,
        stage=stage,
        task_type="candidate_rule",
        content=content,
        evidence_paths=_unique_paths(group),
        scope={"type": "stage_pattern", "stage": stage, "failure_type": failure_type},
        reliability={"level": "low", "reason": "repeated pattern only; replay and sample validation not run"},
      )
    )
  return out


def _source_paths(case: dict[str, Any]) -> list[str]:
  source = case.get("source_paths") if isinstance(case.get("source_paths"), dict) else {}
  out: list[str] = []
  for key in ("result_dir", "eval_path", "per_tag_verdict_path", "rci_path", "rci_self_check_path", "agent_trace_path", "calls_index_path"):
    value = source.get(key)
    if isinstance(value, str) and value:
      out.append(value)
  return out


def _unique_paths(cases: Iterable[dict[str, Any]]) -> list[str]:
  seen: set[str] = set()
  out: list[str] = []
  for case in cases:
    for path in _source_paths(case):
      if path not in seen:
        seen.add(path)
        out.append(path)
  return out


def _case_cwe_id(case: dict[str, Any]) -> str | None:
  source = case.get("source_paths") if isinstance(case.get("source_paths"), dict) else {}
  result_dir = source.get("result_dir")
  if isinstance(result_dir, str) and result_dir:
    root = Path(result_dir)
    for name in ("dataset_record.json", "cve_source.json", "cve_desc.txt", "rci.json"):
      path = root / name
      if path.exists():
        match = re.search(r"CWE-\d+", path.read_text(encoding="utf-8", errors="replace"))
        if match:
          return match.group(0)
  return None


def _memory_id(memory_type: str, source_case_ids: list[str], content: dict[str, Any]) -> str:
  raw = json.dumps(
    {"type": memory_type, "cases": sorted(source_case_ids), "content": content},
    sort_keys=True,
    ensure_ascii=False,
  )
  return f"{memory_type.lower()}_{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]}"


def _count(values: Iterable[str]) -> dict[str, int]:
  out: dict[str, int] = {}
  for value in values:
    out[value] = out.get(value, 0) + 1
  return dict(sorted(out.items()))


def _optional_str(value: Any) -> str | None:
  if value is None:
    return None
  text = str(value)
  return text if text else None

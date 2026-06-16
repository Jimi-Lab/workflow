from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vulnversion.stage1_semantic_aggregation.schema import (
  FixFamilySemantics,
  PatchSemantics,
  Step1Mode,
  Step1QualityReport,
)
from vulnversion.utils.jsonschema import dump_json


def _jsonl_write(path: Path, rows: list[dict[str, Any]]) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  text = "".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in rows)
  path.write_text(text, encoding="utf-8")


def _append_trace(path: Path, event: str, payload: dict[str, Any]) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  row = {
    "ts": datetime.now(timezone.utc).isoformat(),
    "event": event,
    **payload,
  }
  with path.open("a", encoding="utf-8") as f:
    f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def step1_paths(*, result_root: str | Path, repo: str, cve_id: str) -> dict[str, Path]:
  step1_dir = Path(result_root) / repo / cve_id / "step1"
  output_dir = step1_dir / "output"
  agent_calls_dir = step1_dir / "agent_calls"
  fix_evidence_dir = step1_dir / "fix_evidence"
  return {
    "step1_dir": step1_dir,
    "output_dir": output_dir,
    "agent_calls_dir": agent_calls_dir,
    "fix_evidence_dir": fix_evidence_dir,
    "trace": step1_dir / "trace.jsonl",
    "fix_family": output_dir / "fix_family_semantics.json",
    "commit_semantics": output_dir / "commit_semantics.jsonl",
    "chunk_semantics": output_dir / "chunk_semantics.jsonl",
    "semantic_regions": output_dir / "semantic_regions.jsonl",
    "region_refinements": output_dir / "region_refinements.jsonl",
    "quality_report": output_dir / "step1_quality_report.json",
    "patch_semantics": output_dir / "patch_semantics.json",
    "fix_evidence_manifest": fix_evidence_dir / "manifest.json",
  }


def write_step1_p0_artifacts(
  *,
  result_root: str | Path,
  repo: str,
  cve_id: str,
  repo_path: str,
  primary_fix_commit: str,
  fix_commits: list[str] | None = None,
  dataset_record: dict[str, Any] | None = None,
  mode: Step1Mode = "agent_refined",
) -> dict[str, str]:
  """Create the Step1 P0 artifact layout and minimal reloadable artifacts.

  This function intentionally performs no semantic extraction and no agent call.
  It establishes the stable Step1 artifact contract used by later P1+ stages.
  """

  commits = list(fix_commits or [primary_fix_commit])
  if primary_fix_commit not in commits:
    commits.insert(0, primary_fix_commit)

  paths = step1_paths(result_root=result_root, repo=repo, cve_id=cve_id)
  paths["output_dir"].mkdir(parents=True, exist_ok=True)
  paths["agent_calls_dir"].mkdir(parents=True, exist_ok=True)
  paths["fix_evidence_dir"].mkdir(parents=True, exist_ok=True)

  family = FixFamilySemantics(
    cve_id=cve_id,
    repo=repo,
    primary_fix_commit=primary_fix_commit,
    fix_commits=commits,
    family_semantics="single_fix" if len(commits) == 1 else "or_backport_bundle",
  )
  patch = PatchSemantics(
    cve_id=cve_id,
    repo_path=repo_path,
    fix_commit=primary_fix_commit,
    fix_commits=commits,
    all_chunks=[],
    chunk_roles=[],
    rci_relevant_chunks=[],
    excluded_chunks=[],
    aggregation_confidence=0.0,
    dataset_record=dataset_record,
  )
  report = Step1QualityReport(
    cve_id=cve_id,
    repo=repo,
    mode=mode,
    deterministic_complete=True,
    schema_reload_passed=True,
    hard_deletion_count=0,
    agent_failure_to_noise_count=0,
    artifact_paths={
      "fix_family_semantics": str(paths["fix_family"]),
      "commit_semantics": str(paths["commit_semantics"]),
      "chunk_semantics": str(paths["chunk_semantics"]),
      "semantic_regions": str(paths["semantic_regions"]),
      "step1_quality_report": str(paths["quality_report"]),
      "patch_semantics": str(paths["patch_semantics"]),
    },
  )

  dump_json(paths["fix_family"], family.model_dump())
  _jsonl_write(paths["commit_semantics"], [])
  _jsonl_write(paths["chunk_semantics"], [])
  _jsonl_write(paths["semantic_regions"], [])
  dump_json(paths["quality_report"], report.model_dump())
  dump_json(paths["patch_semantics"], patch.model_dump())

  _append_trace(
    paths["trace"],
    "step1_p0_artifacts_written",
    {
      "repo": repo,
      "cve_id": cve_id,
      "mode": mode,
      "output_dir": str(paths["output_dir"]),
    },
  )

  return {name: str(path) for name, path in paths.items()}

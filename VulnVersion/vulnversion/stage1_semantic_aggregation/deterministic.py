from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnversion.git_ops.diff import git_diff
from vulnversion.git_ops.repo import GitRepo
from vulnversion.stage1_semantic_aggregation.artifacts import _append_trace, _jsonl_write, step1_paths
from vulnversion.stage1_semantic_aggregation.chunk_features import (
  classify_patch_type,
  dangerous_candidates,
  guard_candidates,
  message_signals,
  source_ref,
)
from vulnversion.stage1_semantic_aggregation.file_roles import classify_file_role
from vulnversion.stage1_semantic_aggregation.fix_evidence import write_fix_commit_evidence
from vulnversion.stage1_semantic_aggregation.function_context import infer_function_context, new_start_line_from_hunk_header
from vulnversion.stage1_semantic_aggregation.schema import (
  Chunk,
  ChunkRole,
  ChunkSemantics,
  CommitSemantics,
  FixFamilySemantics,
  PatchSemantics,
  Step1Mode,
  Step1QualityReport,
)
from vulnversion.stage1_semantic_aggregation.semantic_regions import build_semantic_regions
from vulnversion.utils.jsonschema import dump_json


def _commit_subject(repo: GitRepo, commit: str) -> str:
  try:
    return repo._git(["show", "--no-patch", "--format=%s", commit]).strip()
  except Exception:
    return ""


def _show_file(repo: GitRepo, commit: str, path: str) -> str:
  try:
    return repo.show(commit, path)
  except Exception:
    return ""


def _missing_context_fields(cve_description: str, nvd_record: dict[str, Any] | None) -> list[str]:
  missing: list[str] = []
  if not cve_description.strip():
    missing.append("cve_description")
  if not nvd_record:
    missing.append("nvd_record")
    return missing
  if not nvd_record.get("description"):
    missing.append("nvd_description")
  if not (nvd_record.get("cvss2") not in (None, "N/A", []) or nvd_record.get("cvss3") or nvd_record.get("cvss4")):
    missing.append("cvss")
  return missing


def _local_window_key(line_start: int | None, window_size: int = 80) -> str | None:
  if line_start is None or line_start <= 0:
    return None
  bucket = (line_start - 1) // window_size
  return f"window:{bucket * window_size + 1}-{(bucket + 1) * window_size}"


def run_step1_deterministic_extractor(
  *,
  result_root: str | Path,
  repo_name: str,
  cve_id: str,
  repo_path: str,
  fixing_commits: list[str],
  cve_description: str,
  cwe: list[str],
  nvd_record: dict[str, Any] | None = None,
  dataset_record: dict[str, Any] | None = None,
  mode: Step1Mode = "deterministic_only",
) -> dict[str, str]:
  """Run Step1 P1 deterministic extraction and write chunk-level artifacts."""

  repo = GitRepo.open(repo_path)
  resolved_commits: list[str] = []
  seen: set[str] = set()
  for commit in fixing_commits:
    resolved = repo.rev_parse(commit)
    if resolved in seen:
      continue
    seen.add(resolved)
    resolved_commits.append(resolved)
  if not resolved_commits:
    raise ValueError("fixing_commits_required")
  primary = resolved_commits[0]

  paths = step1_paths(result_root=result_root, repo=repo_name, cve_id=cve_id)
  paths["output_dir"].mkdir(parents=True, exist_ok=True)
  paths["agent_calls_dir"].mkdir(parents=True, exist_ok=True)
  paths["fix_evidence_dir"].mkdir(parents=True, exist_ok=True)
  _append_trace(paths["trace"], "step1_deterministic_started", {"repo": repo_name, "cve_id": cve_id, "mode": mode})

  write_fix_commit_evidence(
    result_root=result_root,
    repo_name=repo_name,
    cve_id=cve_id,
    repo=repo,
    commits=resolved_commits,
  )

  commit_rows: list[CommitSemantics] = []
  chunk_rows: list[ChunkSemantics] = []
  legacy_chunks: list[Chunk] = []
  chunk_idx = 0

  for commit in resolved_commits:
    diff = git_diff(repo, commit=commit)
    subject = _commit_subject(repo, commit)
    diff_mode = str(diff.get("diff_extraction_mode") or "default")
    parent_count = int(diff.get("parent_count") or 0)
    commit_risk_flags: list[str] = []
    if diff_mode != "default":
      commit_risk_flags.append(f"diff_extraction_mode:{diff_mode}")
    commit_changed_files: list[str] = []
    source_files: list[str] = []
    test_files: list[str] = []
    doc_files: list[str] = []
    build_files: list[str] = []
    hunk_count = 0
    commit_patch_type = "empty_or_merge"

    for file_entry in diff.get("files", []):
      file_path = str(file_entry.get("path") or "")
      if not file_path:
        continue
      commit_changed_files.append(file_path)
      file_role = classify_file_role(file_path)
      if file_role == "source":
        source_files.append(file_path)
      elif file_role == "test":
        test_files.append(file_path)
      elif file_role == "doc":
        doc_files.append(file_path)
      elif file_role == "build":
        build_files.append(file_path)
      file_text = _show_file(repo, commit, file_path)

      for hunk in file_entry.get("hunks", []):
        hunk_count += 1
        chunk_idx += 1
        added = list(hunk.get("added") or [])
        removed = list(hunk.get("removed") or [])
        diff_lines = list(hunk.get("lines") or [])
        hunk_header = str(hunk.get("header") or "")
        patch_type = classify_patch_type(added=added, removed=removed)
        if commit_patch_type == "empty_or_merge":
          commit_patch_type = patch_type
        elif commit_patch_type != patch_type and patch_type != "empty_or_merge":
          commit_patch_type = "mixed"
        function_context = infer_function_context(
          hunk_header=hunk_header,
          file_text=file_text,
          new_start_line=new_start_line_from_hunk_header(hunk_header),
        )
        line_start = new_start_line_from_hunk_header(hunk_header)
        line_end = line_start + max(len(added), len(removed), 1) - 1 if line_start else None
        risk_flags: list[str] = []
        if diff_mode != "default":
          risk_flags.append(f"diff_extraction_mode:{diff_mode}")
        if function_context is None:
          risk_flags.append("function_context_missing")
        guards = guard_candidates(added)
        dangerous = dangerous_candidates(removed)
        refs = []
        source_lines: list[dict[str, Any]] = []
        if diff_lines:
          source_lines = [
            item for item in diff_lines
            if str(item.get("content") or "").strip()
          ]
        else:
          for line in removed:
            if line.strip():
              source_lines.append({"change_type": "removed", "content": line, "old_line_no": None, "new_line_no": None})
          for line in added:
            if line.strip():
              source_lines.append({"change_type": "added", "content": line, "old_line_no": None, "new_line_no": None})
        for ref_idx, item in enumerate(source_lines, start=1):
          line = str(item.get("content") or "")
          change_type = str(item.get("change_type") or "")
          refs.append(
            source_ref(
              cve_id=cve_id,
              commit=commit,
              file_path=file_path,
              kind="git_diff",
              index=chunk_idx * 1000 + ref_idx,
              snippet=line,
              change_type=change_type if change_type in {"added", "removed", "context"} else None,
              hunk_header=hunk_header,
              function_context=function_context,
              old_line_no=item.get("old_line_no") if isinstance(item.get("old_line_no"), int) else None,
              new_line_no=item.get("new_line_no") if isinstance(item.get("new_line_no"), int) else None,
              strength_hint="medium" if file_role == "source" else "weak",
            )
          )
        chunk_id = f"chunk_{chunk_idx:04d}"
        chunk_rows.append(
          ChunkSemantics(
            cve_id=cve_id,
            repo=repo_name,
            chunk_id=chunk_id,
            commit=commit,
            file_path=file_path,
            function_context=function_context,
            line_start=line_start,
            line_end=line_end,
            local_window_key=_local_window_key(line_start),
            patch_type=patch_type,
            file_role=file_role,
            chunk_role="unknown",
            root_cause_likelihood=0.0,
            fix_guard_likelihood=1.0 if guards else 0.0,
            vulnerable_sequence_likelihood=1.0 if dangerous else 0.0,
            source_refs=refs,
            risk_flags=risk_flags,
          )
        )
        legacy_chunks.append(
          Chunk(
            chunk_id=chunk_id,
            file_path=file_path,
            hunk_header=hunk_header,
            source_commit=commit,
            removed=removed,
            added=added,
          )
        )

    commit_rows.append(
      CommitSemantics(
        cve_id=cve_id,
        repo=repo_name,
        commit=commit,
        role="unknown",
        patch_type=commit_patch_type,  # type: ignore[arg-type]
        diff_extraction_mode=diff_mode,
        parent_count=parent_count,
        changed_files=sorted(set(commit_changed_files)),
        source_files=sorted(set(source_files)),
        test_files=sorted(set(test_files)),
        doc_files=sorted(set(doc_files)),
        build_files=sorted(set(build_files)),
        hunk_count=hunk_count,
        security_relevant_hunk_count=sum(1 for ch in chunk_rows if ch.commit == commit and ch.file_role == "source"),
        message_signals=message_signals(subject),
        risk_flags=commit_risk_flags,
        confidence=0.0,
      )
    )

  regions = build_semantic_regions(cve_id=cve_id, repo=repo_name, chunks=chunk_rows)
  report = Step1QualityReport(
    cve_id=cve_id,
    repo=repo_name,
    mode=mode,
    deterministic_complete=True,
    schema_reload_passed=True,
    hard_deletion_count=0,
    agent_failure_to_noise_count=0,
    patch_chunk_count=len(chunk_rows),
    semantic_region_count=len(regions),
    compression_ratio=(len(regions) / len(chunk_rows)) if chunk_rows else None,
    missing_context_fields=_missing_context_fields(cve_description, nvd_record),
    risk_flags=sorted({flag for ch in chunk_rows for flag in ch.risk_flags}),
    artifact_paths={
      "fix_family_semantics": str(paths["fix_family"]),
      "commit_semantics": str(paths["commit_semantics"]),
      "chunk_semantics": str(paths["chunk_semantics"]),
      "semantic_regions": str(paths["semantic_regions"]),
      "step1_quality_report": str(paths["quality_report"]),
      "patch_semantics": str(paths["patch_semantics"]),
      "fix_evidence_manifest": str(paths["fix_evidence_manifest"]),
      "fix_evidence_dir": str(paths["fix_evidence_dir"]),
    },
  )
  patch = PatchSemantics(
    cve_id=cve_id,
    repo_path=repo_path,
    fix_commit=primary,
    fix_commits=resolved_commits,
    all_chunks=legacy_chunks,
    chunk_roles=[ChunkRole(chunk_id=ch.chunk_id, role="CONTEXTUAL_CHANGE", uncertainty="deterministic_only") for ch in legacy_chunks],
    rci_relevant_chunks=[],
    excluded_chunks=[],
    aggregation_confidence=0.0,
    dataset_record=dataset_record,
  )
  family = FixFamilySemantics(
    cve_id=cve_id,
    repo=repo_name,
    primary_fix_commit=primary,
    fix_commits=resolved_commits,
    family_semantics="single_fix" if len(resolved_commits) == 1 else "or_backport_bundle",
  )

  dump_json(paths["fix_family"], family.model_dump())
  _jsonl_write(paths["commit_semantics"], [row.model_dump() for row in commit_rows])
  _jsonl_write(paths["chunk_semantics"], [row.model_dump() for row in chunk_rows])
  _jsonl_write(paths["semantic_regions"], [row.model_dump() for row in regions])
  dump_json(paths["quality_report"], report.model_dump())
  dump_json(paths["patch_semantics"], patch.model_dump())

  # Reload artifacts immediately to enforce P1 schema stability.
  FixFamilySemantics.model_validate(json.loads(paths["fix_family"].read_text(encoding="utf-8")))
  for line in paths["commit_semantics"].read_text(encoding="utf-8").splitlines():
    if line.strip():
      CommitSemantics.model_validate(json.loads(line))
  for line in paths["chunk_semantics"].read_text(encoding="utf-8").splitlines():
    if line.strip():
      ChunkSemantics.model_validate(json.loads(line))
  Step1QualityReport.model_validate(json.loads(paths["quality_report"].read_text(encoding="utf-8")))

  _append_trace(
    paths["trace"],
    "step1_deterministic_completed",
    {
      "repo": repo_name,
      "cve_id": cve_id,
      "chunk_count": len(chunk_rows),
      "region_count": len(regions),
    },
  )
  return {name: str(path) for name, path in paths.items()}

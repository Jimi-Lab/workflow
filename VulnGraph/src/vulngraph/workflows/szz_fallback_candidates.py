from __future__ import annotations

import json
import shutil
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from vulngraph.agent_io.szz_handoff_schema import (
  PreFixCandidateInventoryV1,
  ResolvedPreFixAnchorV1,
)
from vulngraph.services.blame_runner import CommandRunner, run_blame_for_anchors
from vulngraph.services.pre_fix_candidates import (
  GitPreFixSourceReader,
  build_pre_fix_candidate_inventory,
)


def select_fallback_inventory_candidates(
  candidates: list[dict[str, Any]],
  *,
  top_k_per_fix_commit: int = 5,
  mandatory_candidate_ids: set[str] | None = None,
) -> dict[str, Any]:
  mandatory = mandatory_candidate_ids or set()
  valid_candidates = [item for item in candidates if str(item.get("patch_family_id") or "").strip()]
  without_family = len(candidates) - len(valid_candidates)
  selected: dict[str, dict[str, Any]] = {}

  by_fix_commit: dict[str, list[dict[str, Any]]] = defaultdict(list)
  by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
  for item in valid_candidates:
    by_fix_commit[str(item.get("fix_commit_id") or "")].append(item)
    by_family[str(item.get("patch_family_id") or "")].append(item)

  for fix_commit_id, group in by_fix_commit.items():
    if not fix_commit_id:
      continue
    for item in sorted(group, key=lambda candidate: _fallback_candidate_rank_key(candidate))[:top_k_per_fix_commit]:
      selected[str(item["candidate_id"])] = item

  for family, group in by_family.items():
    if not family:
      continue
    if not any(str(item.get("candidate_id") or "") in selected for item in group):
      item = sorted(group, key=lambda candidate: _fallback_candidate_rank_key(candidate))[0]
      selected[str(item["candidate_id"])] = item

  for item in valid_candidates:
    if str(item.get("candidate_id") or "") in mandatory:
      selected[str(item["candidate_id"])] = item

  selected_values = sorted(selected.values(), key=lambda candidate: _fallback_candidate_rank_key(candidate))
  selected_by_fix_commit = Counter(str(item.get("fix_commit_id") or "") for item in selected_values)
  selected_by_family = Counter(str(item.get("patch_family_id") or "") for item in selected_values)
  return {
    "candidates": selected_values,
    "candidate_without_patch_family": without_family,
    "selected_by_fix_commit": dict(selected_by_fix_commit),
    "selected_by_patch_family": dict(selected_by_family),
    "top_k_per_fix_commit": top_k_per_fix_commit,
  }


def build_fallback_enhanced_artifact(
  *,
  anchor_run: str | Path,
  root_cause_run: str | Path,
  repo_root: str | Path,
  out_dir: str | Path,
  dataset: str | Path | None = None,
  top_k_per_fix_commit: int = 5,
  command_runner: CommandRunner | None = None,
) -> dict[str, Any]:
  started = time.monotonic()
  anchor_root = Path(anchor_run)
  root_cause_root = Path(root_cause_run)
  output_root = Path(out_dir)
  output_root.mkdir(parents=True, exist_ok=True)
  repo_root_path = Path(repo_root)
  dataset_records = _read_json_default(Path(dataset), {}) if dataset else {}
  summary = _read_json(anchor_root / "summary.json")
  results = [item for item in summary.get("results", []) if item.get("cve_id")]

  enhanced_results: list[dict[str, Any]] = []
  blocked_results: list[dict[str, Any]] = []
  for item in results:
    cve_id = str(item.get("cve_id") or "")
    source_case_dir = anchor_root / cve_id
    out_case_dir = output_root / cve_id
    if source_case_dir.exists():
      shutil.copytree(source_case_dir, out_case_dir, dirs_exist_ok=True)
    else:
      out_case_dir.mkdir(parents=True, exist_ok=True)
    raw_candidates = [
      candidate
      for candidate in _read_list(out_case_dir / "candidate_commits.json")
      if candidate.get("lifecycle") == "raw_candidate"
    ]
    if raw_candidates:
      annotated = [
        _annotate_candidate_commit(
          candidate,
          mode="strong_model_anchor",
          evidence_level="strong",
          fallback_reason="",
          anchor_source="model_selected_anchor",
        )
        for candidate in raw_candidates
      ]
      _write_json(out_case_dir / "candidate_commits.json", annotated)
      result = dict(item)
      result.update(
        {
          "status": "ingested_raw_candidate",
          "candidate_generation_mode": "strong_model_anchor",
          "evidence_level": "strong",
          "candidate_commit_count": len(annotated),
        }
      )
      ingestion = _read_json_default(out_case_dir / "ingestion_result.json", {})
      ingestion.update(
        {
          "candidate_generation_mode": "strong_model_anchor",
          "evidence_level": "strong",
          "candidate_commit_count": len(annotated),
          "lifecycle": "raw_candidate",
        }
      )
      _write_json(out_case_dir / "ingestion_result.json", ingestion)
      enhanced_results.append(result)
      continue

    fallback = _run_fallback_case(
      cve_id=cve_id,
      source_case_dir=source_case_dir,
      root_cause_case_dir=root_cause_root / cve_id,
      out_case_dir=out_case_dir,
      repo_root=repo_root_path,
      dataset_record=dataset_records.get(cve_id, {}) if isinstance(dataset_records, dict) else {},
      top_k_per_fix_commit=top_k_per_fix_commit,
      command_runner=command_runner,
    )
    result = dict(item)
    result.update(fallback["result"])
    enhanced_results.append(result)
    blocked_results.append(result)

  fallback_summary = _fallback_summary(
    enhanced_results,
    blocked_results,
    anchor_root=anchor_root,
    root_cause_root=root_cause_root,
    repo_root=repo_root_path,
    duration_s=time.monotonic() - started,
  )
  _write_json(output_root / "summary.json", fallback_summary)
  _write_json(output_root / "provenance_manifest.json", _provenance(anchor_root, root_cause_root, repo_root_path))
  (output_root / "report.md").write_text(_render_report(fallback_summary), encoding="utf-8")
  return fallback_summary


def _run_fallback_case(
  *,
  cve_id: str,
  source_case_dir: Path,
  root_cause_case_dir: Path,
  out_case_dir: Path,
  repo_root: Path,
  dataset_record: dict[str, Any],
  top_k_per_fix_commit: int,
  command_runner: CommandRunner | None,
) -> dict[str, Any]:
  inventory_data = _load_or_build_inventory(
    cve_id=cve_id,
    source_case_dir=source_case_dir,
    root_cause_case_dir=root_cause_case_dir,
    repo_root=repo_root,
    dataset_record=dataset_record,
  )
  if not inventory_data:
    result = _fallback_failure(cve_id, "missing_candidate_inventory")
    _write_case_failure(out_case_dir, result)
    return {"result": result}

  inventory = PreFixCandidateInventoryV1.model_validate(inventory_data)
  compact = _read_json_default(source_case_dir / "compact_candidate_inventory.json", {})
  mandatory_ids = set(compact.get("mandatory_candidate_ids") or [])
  selected = select_fallback_inventory_candidates(
    [item.model_dump(mode="json") for item in inventory.candidates],
    top_k_per_fix_commit=top_k_per_fix_commit,
    mandatory_candidate_ids={str(item) for item in mandatory_ids},
  )
  if not selected["candidates"]:
    result = _fallback_failure(cve_id, "no_blameable_old_side")
    result.update(
      {
        "candidate_without_patch_family": selected["candidate_without_patch_family"],
        "original_candidate_count": len(inventory.candidates),
      }
    )
    _write_json(out_case_dir / "candidate_inventory.json", inventory.model_dump(mode="json"))
    _write_case_failure(out_case_dir, result)
    return {"result": result}

  anchors = [
    _candidate_to_anchor(candidate, index=index)
    for index, candidate in enumerate(selected["candidates"], start=1)
  ]
  resolved_data = [anchor.model_dump(mode="json") for anchor in anchors]
  for name in ("resolved_anchors.json", "resolved_pre_fix_anchors.json", "fallback_resolved_pre_fix_anchors.json"):
    _write_json(out_case_dir / name, resolved_data)
  _write_json(out_case_dir / "candidate_inventory.json", inventory.model_dump(mode="json"))
  repo_path = _repo_path_for_case(inventory, repo_root, dataset_record)
  blame = run_blame_for_anchors(repo_path, anchors, command_runner=command_runner)
  blame_data = blame.to_dict()
  marked = _mark_candidates(blame.candidate_commits, inventory, repo_path)
  annotated_candidates = [
    _annotate_candidate_commit(
      candidate,
      mode="fallback_inventory_anchor",
      evidence_level="fallback",
      fallback_reason="model_szz_handoff_blocked",
      anchor_source="candidate_inventory",
      anchor_lookup={anchor.candidate_id: anchor for anchor in anchors},
    )
    for candidate in marked
  ]
  blame_data["candidate_commits"] = annotated_candidates
  _write_json(out_case_dir / "blame_trace.json", blame_data)
  _write_json(out_case_dir / "candidate_commits.json", annotated_candidates)
  _write_json(out_case_dir / "contract_lint.json", {"ok": True, "source": "deterministic_fallback_inventory"})

  status = "ingested_raw_candidate" if annotated_candidates else "raw_candidate_censored"
  no_reason = "" if annotated_candidates else _fallback_no_candidate_reason(blame.errors, blame.status)
  result = {
    "cve_id": cve_id,
    "status": status,
    "lifecycle": "raw_candidate",
    "candidate_generation_mode": "fallback_inventory_anchor",
    "evidence_level": "fallback",
    "fallback_reason": "model_szz_handoff_blocked",
    "no_fallback_candidate_reason": no_reason,
    "original_candidate_count": len(inventory.candidates),
    "fallback_selected_anchor_count": len(anchors),
    "candidate_commit_count": len(annotated_candidates),
    "candidate_without_patch_family": selected["candidate_without_patch_family"],
    "selected_by_fix_commit": selected["selected_by_fix_commit"],
    "selected_by_patch_family": selected["selected_by_patch_family"],
    "blame_status": blame.status,
    "errors": blame.errors,
  }
  _write_json(out_case_dir / "ingestion_result.json", result)
  (out_case_dir / "report.md").write_text(_render_case_report(result), encoding="utf-8")
  return {"result": result}


def _fallback_candidate_rank_key(candidate: dict[str, Any]) -> tuple[Any, ...]:
  return (
    _source_priority(candidate),
    0 if candidate.get("source_file", True) else 1,
    _noise_rank(candidate),
    str(candidate.get("fix_commit_id") or ""),
    str(candidate.get("patch_family_id") or ""),
    str(candidate.get("candidate_id") or ""),
  )


def _source_priority(candidate: dict[str, Any]) -> int:
  source = str(candidate.get("candidate_source") or "")
  modes = {str(item) for item in candidate.get("selection_mode_eligibility") or []}
  if source == "deleted_line" or modes & {"modified_old_side", "direct_deleted_line"}:
    return 0
  if candidate.get("mandatory_candidate") is True:
    return 1
  if source == "pre_fix_function_body":
    return 3
  if source == "hunk_context":
    return 4
  return 9


def _noise_rank(candidate: dict[str, Any]) -> int:
  noise_keys = ("comment_only", "blank_line", "test_file", "documentation_file", "generated_file", "changelog_file")
  return sum(1 for key in noise_keys if candidate.get(key) is True)


def _candidate_to_anchor(candidate: dict[str, Any], *, index: int) -> ResolvedPreFixAnchorV1:
  selection_mode = _selection_mode(candidate)
  return ResolvedPreFixAnchorV1(
    anchor_id=f"fallback-anchor:{candidate['candidate_id']}:{index}",
    candidate_id=str(candidate["candidate_id"]),
    cve_id=str(candidate["cve_id"]),
    fix_set_id=str(candidate["fix_set_id"]),
    patch_family_id=str(candidate["patch_family_id"]),
    fix_commit_id=str(candidate["fix_commit_id"]),
    fix_commit_sha=str(candidate["fix_commit_sha"]),
    parent_sha=str(candidate["parent_sha"]),
    patch_hunk_id=str(candidate["patch_hunk_id"]),
    path_before=str(candidate["path_before"]),
    path_after=candidate.get("path_after"),
    old_line_start=int(candidate["old_line_start"]),
    old_line_end=int(candidate["old_line_end"]),
    line_text=str(candidate["line_text"]),
    line_text_sha256=str(candidate["line_text_sha256"]),
    function_id=candidate.get("function_id"),
    function_name=candidate.get("function_name"),
    candidate_source=candidate["candidate_source"],
    role=_role_for_selection(selection_mode),
    selection_mode=selection_mode,
    root_cause_hypothesis_ids=["fallback:root-cause-hypothesis"],
    predicate_ids=[f"fallback:predicate:{candidate['patch_hunk_id']}"],
    git_observation_refs=list(candidate.get("git_observation_refs") or []),
    rationale="Deterministic wrapper fallback selected this parent-side candidate after model SZZ handoff was blocked.",
    confidence=0.35,
    lifecycle="raw_candidate",
    uncertainty_reasons=["fallback_inventory_anchor_not_formally_judged"],
    exclusion_reasons=list(candidate.get("exclusion_reasons") or []),
  )


def _selection_mode(candidate: dict[str, Any]) -> str:
  modes = [str(item) for item in candidate.get("selection_mode_eligibility") or []]
  for preferred in ("modified_old_side", "direct_deleted_line", "add_only_semantic_target", "context_fallback"):
    if preferred in modes:
      return preferred
  source = str(candidate.get("candidate_source") or "")
  if source == "pre_fix_function_body":
    return "add_only_semantic_target"
  if source == "hunk_context":
    return "context_fallback"
  return "modified_old_side"


def _role_for_selection(selection_mode: str) -> str:
  if selection_mode in {"modified_old_side", "direct_deleted_line"}:
    return "dangerous_use"
  if selection_mode == "add_only_semantic_target":
    return "missing_guard_target"
  return "control_predecessor"


def _annotate_candidate_commit(
  candidate: dict[str, Any],
  *,
  mode: str,
  evidence_level: str,
  fallback_reason: str,
  anchor_source: str,
  anchor_lookup: dict[str, ResolvedPreFixAnchorV1] | None = None,
) -> dict[str, Any]:
  item = dict(candidate)
  item["candidate_generation_mode"] = mode
  item["evidence_level"] = evidence_level
  item["fallback_reason"] = fallback_reason
  item["anchor_source"] = anchor_source
  item["lifecycle"] = "raw_candidate"
  line_provenance = []
  for record in item.get("line_provenance") or []:
    enriched = dict(record)
    enriched["candidate_generation_mode"] = mode
    enriched["evidence_level"] = evidence_level
    enriched["fallback_reason"] = fallback_reason
    anchor = (anchor_lookup or {}).get(str(record.get("candidate_id") or ""))
    if anchor is not None:
      enriched.update(_anchor_public_fields(anchor))
    line_provenance.append(enriched)
  item["line_provenance"] = line_provenance
  anchors = [
    (anchor_lookup or {}).get(str(candidate_id or ""))
    for candidate_id in item.get("candidate_ids", [])
    if (anchor_lookup or {}).get(str(candidate_id or "")) is not None
  ]
  if anchors:
    item["fix_commit_ids"] = sorted({anchor.fix_commit_id for anchor in anchors})
    item["patch_family_ids"] = sorted({anchor.patch_family_id for anchor in anchors})
    item["old_paths"] = sorted({anchor.path_before for anchor in anchors})
    item["old_lines"] = sorted({anchor.old_line_start for anchor in anchors})
    item["old_texts"] = sorted({anchor.line_text for anchor in anchors})
    first = anchors[0]
    item.update(
      {
        "fix_commit_id": first.fix_commit_id,
        "patch_family_id": first.patch_family_id,
        "old_path": first.path_before,
        "old_line": first.old_line_start,
        "old_text": first.line_text,
      }
    )
  item.setdefault("uncertainty_reasons", [])
  if fallback_reason:
    item["uncertainty_reasons"] = sorted(set(item["uncertainty_reasons"] + [fallback_reason]))
  return item


def _anchor_public_fields(anchor: ResolvedPreFixAnchorV1) -> dict[str, Any]:
  return {
    "fix_commit_id": anchor.fix_commit_id,
    "patch_family_id": anchor.patch_family_id,
    "old_path": anchor.path_before,
    "old_line": anchor.old_line_start,
    "old_text": anchor.line_text,
  }


def _mark_candidates(
  commits: list[dict[str, Any]],
  inventory: PreFixCandidateInventoryV1,
  repo_path: Path,
) -> list[dict[str, Any]]:
  fix_shas = {item.fix_commit_sha for item in inventory.candidates}
  output = []
  for commit in commits:
    item = dict(commit)
    reasons = list(item.get("exclusion_reasons") or [])
    if str(item.get("commit_sha") or "") in fix_shas:
      reasons.append("is_fix_commit")
    item["excluded"] = bool(reasons)
    item["exclusion_reasons"] = sorted(set(reasons))
    item["lifecycle"] = "raw_candidate"
    if not repo_path.exists():
      item.setdefault("uncertainty", []).append("repo_path_missing_for_patch_family_check")
    output.append(item)
  return output


def _load_or_build_inventory(
  *,
  cve_id: str,
  source_case_dir: Path,
  root_cause_case_dir: Path,
  repo_root: Path,
  dataset_record: dict[str, Any],
) -> dict[str, Any] | None:
  for name in ("candidate_inventory.json", "pre_fix_candidate_inventory.json"):
    path = source_case_dir / name
    if path.exists():
      return _read_json(path)
  packet_path = root_cause_case_dir / "root_cause_packet.json"
  if not packet_path.exists():
    return None
  packet = _read_json(packet_path)
  repo_path = repo_root / str(dataset_record.get("repo") or _repo_name_from_packet(packet))
  if not repo_path.exists():
    return None
  inventory = build_pre_fix_candidate_inventory(
    packet=packet,
    repo_path=repo_path,
    source_reader=GitPreFixSourceReader(repo_path),
  )
  return inventory.model_dump(mode="json")


def _repo_name_from_packet(packet: dict[str, Any]) -> str:
  repo_navigation = packet.get("repo_navigation")
  if isinstance(repo_navigation, dict):
    repo = repo_navigation.get("repo") or {}
    if isinstance(repo, dict):
      value = repo.get("name") or repo.get("repo") or repo.get("id")
      if value:
        return str(value)
  for item in packet.get("patch_evidence", []):
    content = item.get("content") or {}
    value = content.get("repo") or content.get("repo_name")
    if value:
      return str(value)
  return ""


def _repo_path_for_case(
  inventory: PreFixCandidateInventoryV1,
  repo_root: Path,
  dataset_record: dict[str, Any],
) -> Path:
  repo_name = str(dataset_record.get("repo") or inventory.repo_id or "")
  candidate_path = repo_root / repo_name
  if candidate_path.exists() or repo_name:
    return candidate_path
  return Path(inventory.repo_path)


def _fallback_failure(cve_id: str, reason: str) -> dict[str, Any]:
  return {
    "cve_id": cve_id,
    "status": "raw_candidate_censored",
    "lifecycle": "raw_candidate",
    "candidate_generation_mode": "fallback_inventory_anchor",
    "evidence_level": "fallback",
    "fallback_reason": "model_szz_handoff_blocked",
    "no_fallback_candidate_reason": reason,
    "candidate_commit_count": 0,
    "fallback_selected_anchor_count": 0,
    "blame_status": "not_run",
    "errors": [reason],
  }


def _write_case_failure(out_case_dir: Path, result: dict[str, Any]) -> None:
  _write_json(out_case_dir / "resolved_anchors.json", [])
  _write_json(out_case_dir / "resolved_pre_fix_anchors.json", [])
  _write_json(out_case_dir / "blame_trace.json", {"status": "not_run", "errors": result.get("errors", [])})
  _write_json(out_case_dir / "candidate_commits.json", [])
  _write_json(out_case_dir / "ingestion_result.json", result)
  (out_case_dir / "report.md").write_text(_render_case_report(result), encoding="utf-8")


def _fallback_no_candidate_reason(errors: list[str], blame_status: str) -> str:
  joined = " ".join(errors)
  for reason in ("parent_missing", "parent_path_missing", "parent_line_mismatch", "blame_failed", "shallow_history"):
    if reason in joined or blame_status == reason:
      return reason
  if blame_status == "failed":
    return "blame_failed"
  return "no_blameable_old_side"


def _fallback_summary(
  results: list[dict[str, Any]],
  blocked_results: list[dict[str, Any]],
  *,
  anchor_root: Path,
  root_cause_root: Path,
  repo_root: Path,
  duration_s: float,
) -> dict[str, Any]:
  mode_counts = Counter(str(item.get("candidate_generation_mode") or "none") for item in results)
  evidence_counts = Counter(str(item.get("evidence_level") or "none") for item in results)
  strong = [item for item in results if item.get("candidate_generation_mode") == "strong_model_anchor"]
  fallback_ready = [
    item
    for item in results
    if item.get("candidate_generation_mode") in {"fallback_inventory_anchor", "fallback_patch_only"}
    and int(item.get("candidate_commit_count") or 0) > 0
  ]
  no_candidate = [item for item in results if int(item.get("candidate_commit_count") or 0) == 0]
  return {
    "cases_total": len(results),
    "results": results,
    "strong_candidate_ready_count": len(strong),
    "fallback_candidate_ready_count": len(fallback_ready),
    "judge_input_ready_count": sum(1 for item in results if int(item.get("candidate_commit_count") or 0) > 0),
    "no_candidate_count": len(no_candidate),
    "no_candidate_cases": [
      {
        "cve_id": item.get("cve_id"),
        "no_fallback_candidate_reason": item.get("no_fallback_candidate_reason") or "candidate_missing",
      }
      for item in no_candidate
    ],
    "strong_raw_candidate_commit_count": sum(int(item.get("candidate_commit_count") or 0) for item in strong),
    "fallback_raw_candidate_commit_count": sum(int(item.get("candidate_commit_count") or 0) for item in fallback_ready),
    "candidate_generation_mode_distribution": dict(sorted(mode_counts.items())),
    "evidence_level_distribution": dict(sorted(evidence_counts.items())),
    "per_blocked_case_fallback_results": blocked_results,
    "anchor_run": str(anchor_root),
    "root_cause_run": str(root_cause_root),
    "repo_root": str(repo_root),
    "duration_s": round(duration_s, 6),
    "model_invocation_count": 0,
    "lifecycle": "raw_candidate",
  }


def _render_report(summary: dict[str, Any]) -> str:
  lines = [
    "# SZZ Anchor Audit Fallback Artifact",
    "",
    "This engineering artifact does not call a model and does not validate BICs or infer affected versions.",
    "Strong cases preserve model-selected anchors; blocked cases use deterministic wrapper-owned fallback candidates.",
    "",
    f"- cases_total: {summary['cases_total']}",
    f"- strong_candidate_ready_count: {summary['strong_candidate_ready_count']}",
    f"- fallback_candidate_ready_count: {summary['fallback_candidate_ready_count']}",
    f"- judge_input_ready_count: {summary['judge_input_ready_count']}",
    f"- no_candidate_count: {summary['no_candidate_count']}",
    f"- strong_raw_candidate_commit_count: {summary['strong_raw_candidate_commit_count']}",
    f"- fallback_raw_candidate_commit_count: {summary['fallback_raw_candidate_commit_count']}",
    f"- candidate_generation_mode_distribution: `{summary['candidate_generation_mode_distribution']}`",
    f"- evidence_level_distribution: `{summary['evidence_level_distribution']}`",
    "",
    "## Blocked Case Fallback Results",
    "",
  ]
  for item in summary["per_blocked_case_fallback_results"]:
    lines.append(
      f"- {item.get('cve_id')}: status={item.get('status')}; "
      f"candidates={item.get('candidate_commit_count')}; reason={item.get('no_fallback_candidate_reason', '')}"
    )
  return "\n".join(lines) + "\n"


def _render_case_report(result: dict[str, Any]) -> str:
  return "\n".join(
    [
      f"# {result.get('cve_id')} Fallback Candidate Case",
      "",
      f"- status: {result.get('status')}",
      f"- lifecycle: {result.get('lifecycle')}",
      f"- candidate_generation_mode: {result.get('candidate_generation_mode')}",
      f"- evidence_level: {result.get('evidence_level')}",
      f"- candidate_commit_count: {result.get('candidate_commit_count')}",
      f"- no_fallback_candidate_reason: {result.get('no_fallback_candidate_reason', '')}",
      f"- blame_status: {result.get('blame_status')}",
    ]
  ) + "\n"


def _provenance(anchor_root: Path, root_cause_root: Path, repo_root: Path) -> dict[str, Any]:
  return {
    "anchor_run": str(anchor_root),
    "root_cause_run": str(root_cause_root),
    "repo_root": str(repo_root),
    "model_invocation_count": 0,
    "judge_agent_invocation_count": 0,
    "lifecycle": "raw_candidate",
    "notes": [
      "strong_model_anchor cases preserve existing model-selected anchor provenance",
      "fallback_inventory_anchor cases use wrapper-owned candidate inventory and local blame only",
    ],
  }


def _read_json(path: Path) -> dict[str, Any]:
  data = json.loads(path.read_text(encoding="utf-8"))
  if not isinstance(data, dict):
    raise ValueError(f"expected JSON object: {path}")
  return data


def _read_json_default(path: Path | None, default: dict[str, Any]) -> dict[str, Any]:
  if path is None or not path.exists():
    return default
  return _read_json(path)


def _read_list(path: Path) -> list[dict[str, Any]]:
  if not path.exists():
    return []
  data = json.loads(path.read_text(encoding="utf-8"))
  return data if isinstance(data, list) else []


def _write_json(path: Path, data: Any) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

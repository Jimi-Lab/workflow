from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any

from vulngraph.services.blame_runner import CommandResult, CommandRunner, parse_blame_porcelain


FORBIDDEN_EVIDENCE_KEYS = {
  "validated_bic",
  "correct_bic",
  "affected_versions",
  "bic",
  "ground_truth",
  "gt_release_tags",
  "overlap_release_tags",
  "release_metrics",
  "precision",
  "recall",
  "f1",
  "exact_match",
}

BLAME_VARIANTS: tuple[tuple[str, list[str]], ...] = (
  ("normal", []),
  ("w", ["-w"]),
  ("M", ["-M"]),
  ("C", ["-C"]),
  ("w_M_C", ["-w", "-M", "-C"]),
)

SUMMARY_COLUMNS = [
  "cve_id",
  "repo",
  "candidate_commit_sha",
  "candidate_source",
  "evidence_level",
  "lifecycle",
  "variant_agreement",
  "canonical_blame_commit_sha",
  "line_survival_status",
  "candidate_is_ancestor_of_fix",
  "risk_flags",
  "confidence_features",
]

RISK_COLUMNS = [
  "cve_id",
  "candidate_commit_sha",
  "risk_flags",
  "confidence_features",
  "suitable_for_judge_v0",
]

RELEASE_COLUMNS = [
  "cve_id",
  "candidate_commit_sha",
  "reachable_release_tag_count",
  "first_reachable_release_tag_by_time",
  "last_reachable_release_tag_by_time",
  "release_line_count_estimate",
  "release_reachability_too_broad",
  "release_reachability_artifact_ref",
]


def build_detailed_szz_evidence_v0(
  *,
  slimming_root: str | Path,
  judge_packet_root: str | Path,
  dataset: str | Path,
  repo_root: str | Path,
  out_dir: str | Path,
  command_runner: CommandRunner | None = None,
) -> dict[str, Any]:
  started = time.monotonic()
  slimming_path = Path(slimming_root)
  judge_root = Path(judge_packet_root)
  dataset_records = _read_json_default(Path(dataset), {})
  repo_root_path = Path(repo_root)
  output_root = Path(out_dir)
  output_root.mkdir(parents=True, exist_ok=True)

  candidate_rows: list[dict[str, Any]] = []
  risk_rows: list[dict[str, Any]] = []
  release_rows: list[dict[str, Any]] = []
  case_results: list[dict[str, Any]] = []
  all_evidence: list[dict[str, Any]] = []

  for case_dir in _case_dirs(judge_root):
    cve_id = case_dir.name
    blind_packet = _read_json(case_dir / "judge_blind_input_packet.json")
    audit_packet = _read_json_default(case_dir / "judge_audit_packet.json", {})
    record = _dataset_record(dataset_records, cve_id)
    repo = str(blind_packet.get("repo") or record.get("repo") or "")
    repo_path = repo_root_path / repo
    audit_candidates = _audit_candidates_by_identity(audit_packet)
    case_out = output_root / cve_id
    case_out.mkdir(parents=True, exist_ok=True)
    case_evidence: list[dict[str, Any]] = []
    release_full: list[dict[str, Any]] = []

    for candidate in blind_packet.get("candidates", []) or []:
      if candidate.get("lifecycle") != "raw_candidate":
        continue
      full_candidate = audit_candidates.get(_candidate_identity(candidate), candidate)
      release_tags = _release_tags_for_candidate(candidate, full_candidate)
      evidence = build_szz_evidence_for_candidate(
        candidate=candidate,
        dataset_record=record,
        repo_path=repo_path,
        release_tags=release_tags,
        command_runner=command_runner,
      )
      case_evidence.append(evidence)
      all_evidence.append(evidence)
      release_full.append(
        {
          "candidate_commit_sha": evidence["candidate_identity"]["candidate_commit_sha"],
          "reachable_release_tags": release_tags,
          "source": "audit_candidate_or_blind_candidate_predicted_release_tags",
        }
      )
      candidate_rows.append(_summary_row(evidence))
      risk_rows.append(_risk_row(evidence))
      release_rows.append(_release_row(evidence))

    judge_packet = _judge_packet(cve_id, repo, case_evidence)
    audit_packet_out = _audit_packet(cve_id, repo, case_evidence)
    _write_json(case_out / "judge_szz_evidence_packet.json", judge_packet)
    _write_json(case_out / "szz_evidence_packet.json", judge_packet)
    _write_json(case_out / "szz_evidence_audit_packet.json", audit_packet_out)
    _write_json(case_out / "per_candidate_szz_evidence.json", case_evidence)
    _write_json(case_out / "release_reachability_full.json", release_full)
    (case_out / "szz_evidence_report.md").write_text(_render_case_report(cve_id, repo, case_evidence), encoding="utf-8")
    case_results.append(
      {
        "cve_id": cve_id,
        "repo": repo,
        "candidate_count": len(case_evidence),
        "evidence_packet_generated": bool(case_evidence),
      }
    )

  _write_csv(output_root / "szz_evidence_summary.csv", candidate_rows, SUMMARY_COLUMNS)
  _write_csv(output_root / "risk_feature_summary.csv", risk_rows, RISK_COLUMNS)
  _write_csv(output_root / "release_reachability_summary.csv", release_rows, RELEASE_COLUMNS)
  disagreement_report = _render_disagreement_report(all_evidence)
  (output_root / "blame_variant_disagreement_report.md").write_text(disagreement_report, encoding="utf-8")
  scan = scan_forbidden_output_dir(output_root)
  _write_json(output_root / "forbidden_field_scan.json", scan)
  summary = _summary(case_results, all_evidence, duration_s=time.monotonic() - started)
  _write_json(output_root / "summary.json", summary)
  _write_json(
    output_root / "provenance_manifest.json",
    {
      "slimming_root": str(slimming_path),
      "judge_packet_root": str(judge_root),
      "dataset": str(dataset),
      "repo_root": str(repo_root),
      "model_invocation_count": 0,
      "judge_invocation_count": 0,
      "root_cause_regeneration_count": 0,
      "szz_anchor_regeneration_count": 0,
      "lifecycle": "raw_candidate",
      "notes": [
        "deterministic local SZZ evidence expansion",
        "candidate commits are not validated vulnerability-introducing commits",
        "release reachability is a summary feature, not formal version inference",
      ],
    },
  )
  (output_root / "detailed_szz_evidence_report.md").write_text(_render_batch_report(summary, all_evidence), encoding="utf-8")
  return summary


def build_szz_evidence_for_candidate(
  *,
  candidate: dict[str, Any],
  dataset_record: dict[str, Any],
  repo_path: str | Path,
  release_tags: list[str],
  command_runner: CommandRunner | None = None,
  distance_limit: int = 10000,
) -> dict[str, Any]:
  repo = Path(repo_path)
  runner = command_runner or _subprocess_runner
  provenance = _first_provenance(candidate)
  fix_sha = str(provenance.get("fix_commit_sha") or _sha_from_fix_commit_id(candidate.get("fix_commit_id")) or "")
  parent_sha = str(provenance.get("parent_sha") or "")
  path_before = str(candidate.get("path_before") or provenance.get("path_before") or "")
  old_line = _int(candidate.get("old_line_start") or provenance.get("old_line"))
  line_text = str(provenance.get("old_text") or candidate.get("old_line_text") or "")
  line_hash = str(candidate.get("old_line_text_hash") or provenance.get("line_text_sha256") or _sha256(line_text))
  candidate_sha = str(candidate.get("candidate_commit_sha") or provenance.get("blamed_commit_sha") or "")
  fix_commits = _flatten_fix_commits(dataset_record.get("fixing_commits")) or ([fix_sha] if fix_sha else [])

  identity = {
    "cve_id": str(candidate.get("cve_id") or ""),
    "repo": str(candidate.get("repo") or dataset_record.get("repo") or ""),
    "candidate_commit_sha": candidate_sha,
    "candidate_source": str(candidate.get("candidate_source") or ""),
    "evidence_level": str(candidate.get("evidence_level") or ""),
    "lifecycle": "raw_candidate",
    "fix_commit_id": str(candidate.get("fix_commit_id") or provenance.get("fix_commit_id") or ""),
    "fix_commit_sha": fix_sha,
    "patch_family_id": str(candidate.get("patch_family_id") or provenance.get("patch_family_id") or ""),
    "selected_anchor_id": str(candidate.get("selected_anchor_id") or ""),
    "fallback_anchor_id": str(candidate.get("fallback_anchor_id") or ""),
    "anchor_id": str(candidate.get("selected_anchor_id") or candidate.get("fallback_anchor_id") or provenance.get("anchor_id") or ""),
    "candidate_id": str((candidate.get("candidate_ids") or [provenance.get("candidate_id") or ""])[0] or ""),
    "path_before": path_before,
    "old_line_start": old_line,
    "old_line_end": _int(candidate.get("old_line_end") or old_line),
    "old_line_text_hash": line_hash,
  }

  blame_variants = _run_blame_variants(repo, runner, parent_sha, path_before, old_line)
  line_survival = _line_survival(
    repo=repo,
    runner=runner,
    candidate_sha=candidate_sha,
    fix_sha=fix_sha,
    parent_sha=parent_sha,
    path=path_before,
    line_text=line_text,
    line_hash=line_hash,
  )
  commit_relation = _commit_relation(
    repo=repo,
    runner=runner,
    candidate_sha=candidate_sha,
    fix_sha=fix_sha,
    fix_commits=fix_commits,
    path=path_before,
    distance_limit=distance_limit,
  )
  rename_evidence = _rename_evidence(
    repo=repo,
    runner=runner,
    path=path_before,
    blame_variants=blame_variants,
  )
  fix_context = _fix_context_hints(
    candidate=candidate,
    commit_relation=commit_relation,
    fix_sha=fix_sha,
  )
  release_summary, release_too_broad = _release_summary(release_tags)
  risk_flags = _risk_flags(candidate, blame_variants, line_survival, commit_relation, rename_evidence, release_too_broad)
  confidence_features = _confidence_features(candidate, blame_variants, line_survival, commit_relation)

  return {
    "candidate_identity": identity,
    "blame_variants": blame_variants,
    "line_survival_evidence": line_survival,
    "commit_relation_evidence": commit_relation,
    "rename_move_copy_evidence": rename_evidence,
    "fix_series_equivalent_backport_hints": fix_context,
    "release_reachability_summary": {
      **release_summary,
      "release_reachability_artifact_ref": "release_reachability_full.json",
    },
    "risk_flags": risk_flags,
    "confidence_features": confidence_features,
    "audit_trace": {
      "source": "deterministic_local_git",
      "blame_variant_count": len(blame_variants["variants"]),
      "line_survival_note": line_survival.get("line_survival_status"),
    },
    "lifecycle": "raw_candidate",
  }


def scan_forbidden_evidence_fields(data: Any) -> dict[str, Any]:
  violations: list[dict[str, str]] = []
  for key in sorted(FORBIDDEN_EVIDENCE_KEYS):
    for location in _find_exact_key(data, key):
      violations.append({"key": key, "location": location})
  return {
    "ok": not violations,
    "forbidden_keys": sorted(FORBIDDEN_EVIDENCE_KEYS),
    "violation_count": len(violations),
    "violations": violations,
  }


def scan_forbidden_output_dir(root: str | Path) -> dict[str, Any]:
  violations: list[dict[str, str]] = []
  for path in sorted(Path(root).rglob("*.json")):
    data = _read_json_any(path)
    scan = scan_forbidden_evidence_fields(data)
    for item in scan["violations"]:
      violations.append({"path": str(path), **item})
  return {
    "ok": not violations,
    "forbidden_keys": sorted(FORBIDDEN_EVIDENCE_KEYS),
    "violation_count": len(violations),
    "violations": violations,
  }


def _run_blame_variants(
  repo: Path,
  runner: CommandRunner,
  parent_sha: str,
  path: str,
  line: int,
) -> dict[str, Any]:
  variants: list[dict[str, Any]] = []
  for name, flags in BLAME_VARIANTS:
    command = _git(repo, ["blame", *flags, "--line-porcelain", "-L", f"{line},{line}", parent_sha, "--", path])
    result = runner(command, repo)
    parsed = parse_blame_porcelain(result.stdout) if result.exit_code == 0 else []
    first = parsed[0] if parsed else {}
    variants.append(
      {
        "variant": name,
        "command": _safe_command(command),
        "exit_code": result.exit_code,
        "blamed_commit_sha": first.get("blamed_commit_sha"),
        "blamed_original_path": first.get("blamed_original_path", path) if first else None,
        "blamed_original_line": first.get("blamed_original_line"),
        "author_time": first.get("author_time"),
        "committer_time": first.get("committer_time"),
        "boundary_marker": bool(first.get("boundary_marker")),
        "stderr": result.stderr[-1000:],
        "failure_reason": "" if first else ("blame_failed" if result.exit_code else "empty_blame_output"),
      }
    )
  successful = [item for item in variants if item.get("blamed_commit_sha")]
  commits = {str(item.get("blamed_commit_sha")) for item in successful}
  normal = next((item for item in variants if item["variant"] == "normal" and item.get("blamed_commit_sha")), None)
  canonical = (normal or (successful[0] if successful else {})).get("blamed_commit_sha") or ""
  agreement = _variant_agreement(variants)
  return {
    "variants": variants,
    "variant_agreement": agreement,
    "canonical_blame_commit_sha": canonical,
    "success_count": len(successful),
    "failure_count": len(variants) - len(successful),
    "disagreement_taxonomy": [] if len(commits) <= 1 else ["blame_variant_commit_disagreement"],
  }


def _line_survival(
  *,
  repo: Path,
  runner: CommandRunner,
  candidate_sha: str,
  fix_sha: str,
  parent_sha: str,
  path: str,
  line_text: str,
  line_hash: str,
) -> dict[str, Any]:
  candidate_parent = _first_parent(repo, runner, candidate_sha)
  exists_candidate = _line_exists(repo, runner, candidate_sha, path, line_text, line_hash)
  exists_candidate_parent = _line_exists(repo, runner, candidate_parent, path, line_text, line_hash) if candidate_parent else False
  exists_fix_parent = _line_exists(repo, runner, parent_sha, path, line_text, line_hash)
  exists_fix = _line_exists(repo, runner, fix_sha, path, line_text, line_hash)
  changed = exists_fix_parent and not exists_fix
  if exists_fix_parent:
    status = "survives_to_fix_parent"
  elif exists_candidate:
    status = "modified_before_fix"
  else:
    status = "not_traceable"
  return {
    "line_exists_in_candidate": exists_candidate,
    "line_exists_in_candidate_parent": exists_candidate_parent,
    "line_survives_to_fix_parent": exists_fix_parent,
    "line_removed_or_modified_by_fix": changed,
    "line_text_changed_between_candidate_and_fix_parent": exists_candidate and not exists_fix_parent,
    "line_survival_status": status,
  }


def _commit_relation(
  *,
  repo: Path,
  runner: CommandRunner,
  candidate_sha: str,
  fix_sha: str,
  fix_commits: list[str],
  path: str,
  distance_limit: int,
) -> dict[str, Any]:
  candidate_times = _commit_times(repo, runner, candidate_sha)
  fix_times = _commit_times(repo, runner, fix_sha)
  ancestor = _is_ancestor(repo, runner, candidate_sha, fix_sha)
  distance, censored = _distance(repo, runner, candidate_sha, fix_sha, distance_limit)
  parents = _parents(repo, runner, candidate_sha)
  touched_files = _changed_files(repo, runner, candidate_sha)
  same_file = path in touched_files
  message = _commit_subject(repo, runner, candidate_sha)
  message_lower = message.lower()
  mentions_fix = any(token in message_lower for token in ("fix", "security", "cve", "overflow", "vulnerab"))
  mentions_refactor = any(token in message_lower for token in ("refactor", "move", "rename", "format", "cleanup"))
  after_fix = bool(candidate_times.get("committer_time") and fix_times.get("committer_time") and candidate_times["committer_time"] > fix_times["committer_time"])
  return {
    "candidate_is_ancestor_of_fix": ancestor,
    "distance_candidate_to_fix": distance,
    "distance_censored_by_limit": censored,
    "candidate_is_merge_commit": len(parents) > 1,
    "candidate_is_root_commit": len(parents) == 0,
    "candidate_is_boundary_commit": False,
    "candidate_touches_same_file": same_file,
    "candidate_touches_same_function": None,
    "candidate_in_fix_series_hint": mentions_fix or after_fix,
    "candidate_after_fix_time_anomaly": after_fix,
    "candidate_author_time": candidate_times.get("author_time"),
    "candidate_committer_time": candidate_times.get("committer_time"),
    "fix_author_time": fix_times.get("author_time"),
    "fix_committer_time": fix_times.get("committer_time"),
    "candidate_message_mentions_fix_security_cve": mentions_fix,
    "candidate_message_mentions_refactor_move_rename_format": mentions_refactor,
    "fix_commit_count": len(fix_commits),
  }


def _rename_evidence(
  *,
  repo: Path,
  runner: CommandRunner,
  path: str,
  blame_variants: dict[str, Any],
) -> dict[str, Any]:
  variants = blame_variants.get("variants", [])
  by_name = {item["variant"]: item for item in variants}
  normal_sha = str((by_name.get("normal") or {}).get("blamed_commit_sha") or "")
  m_sha = str((by_name.get("M") or {}).get("blamed_commit_sha") or "")
  c_sha = str((by_name.get("C") or {}).get("blamed_commit_sha") or "")
  paths = {str(item.get("blamed_original_path") or "") for item in variants if item.get("blamed_original_path")}
  history = _path_history(repo, runner, path)
  path_changed = bool(paths - {path})
  move_sensitive = bool(normal_sha and m_sha and normal_sha != m_sha)
  copy_sensitive = bool(normal_sha and c_sha and normal_sha != c_sha)
  if copy_sensitive:
    risk = "possible_copy"
  elif move_sensitive or path_changed:
    risk = "possible_move"
  elif history.get("uncertain"):
    risk = "path_history_uncertain"
  else:
    risk = "none"
  return {
    "path_changed_between_candidate_and_fix": path_changed,
    "renamed_path_chain": history.get("paths", []),
    "move_copy_sensitive": move_sensitive or copy_sensitive,
    "blame_M_changes_commit": move_sensitive,
    "blame_C_changes_commit": copy_sensitive,
    "rename_or_copy_risk": risk,
  }


def _fix_context_hints(candidate: dict[str, Any], commit_relation: dict[str, Any], fix_sha: str) -> dict[str, Any]:
  mode = str(candidate.get("candidate_generation_mode") or "")
  uncertainty = [str(item) for item in candidate.get("uncertainty_flags") or []]
  return {
    "fix_commit_is_merge": False,
    "equivalent_fix_commit_sha": fix_sha if mode == "fallback_equivalent_fix_anchor" else "",
    "candidate_in_same_fix_series_window": bool(commit_relation.get("candidate_in_fix_series_hint")),
    "candidate_message_mentions_fix_security_cve": bool(commit_relation.get("candidate_message_mentions_fix_security_cve")),
    "candidate_message_mentions_refactor_move_rename_format": bool(commit_relation.get("candidate_message_mentions_refactor_move_rename_format")),
    "possible_backport_context": "backport" in " ".join(uncertainty).lower(),
    "possible_equivalent_introduction_context": mode == "fallback_equivalent_fix_anchor",
  }


def _release_summary(tags: list[str]) -> tuple[dict[str, Any], bool]:
  unique = sorted(set(tags), key=_release_sort_key)
  too_broad = len(unique) >= 25
  return (
    {
      "reachable_release_tag_count": len(unique),
      "first_reachable_release_tag_by_time": unique[0] if unique else "",
      "last_reachable_release_tag_by_time": unique[-1] if unique else "",
      "release_line_count_estimate": len({_release_line_key(tag) for tag in unique if _release_line_key(tag)}),
      "release_reachability_too_broad": too_broad,
    },
    too_broad,
  )


def _risk_flags(
  candidate: dict[str, Any],
  blame_variants: dict[str, Any],
  line_survival: dict[str, Any],
  commit_relation: dict[str, Any],
  rename_evidence: dict[str, Any],
  release_too_broad: bool,
) -> list[str]:
  flags = set(str(item) for item in candidate.get("risk_flags") or [])
  if candidate.get("candidate_source") == "fallback":
    flags.add("fallback_candidate")
  if any(item.get("selection_mode") == "add_only_semantic_target" for item in _provenance_list(candidate)):
    flags.add("add_only_semantic_anchor")
  if blame_variants.get("variant_agreement") == "whitespace_differs":
    flags.add("whitespace_sensitive_blame")
  if blame_variants.get("variant_agreement") == "move_copy_differs" or rename_evidence.get("move_copy_sensitive"):
    flags.add("move_copy_sensitive_blame")
  if commit_relation.get("candidate_is_merge_commit"):
    flags.add("merge_candidate_commit")
  if commit_relation.get("candidate_is_boundary_commit") or any(item.get("boundary_marker") for item in blame_variants.get("variants", [])):
    flags.add("boundary_candidate_commit")
  if commit_relation.get("candidate_is_ancestor_of_fix") is False:
    flags.add("candidate_not_ancestor_of_fix")
  if not line_survival.get("line_survives_to_fix_parent"):
    flags.add("line_not_surviving_to_fix_parent")
  if commit_relation.get("candidate_in_fix_series_hint"):
    flags.add("candidate_in_fix_series_hint")
  if release_too_broad:
    flags.add("release_reachability_too_broad")
  if rename_evidence.get("rename_or_copy_risk") == "path_history_uncertain":
    flags.add("path_history_uncertain")
  return sorted(flags)


def _confidence_features(
  candidate: dict[str, Any],
  blame_variants: dict[str, Any],
  line_survival: dict[str, Any],
  commit_relation: dict[str, Any],
) -> list[str]:
  features: set[str] = set()
  modes = {str(item.get("selection_mode") or "") for item in _provenance_list(candidate)}
  roles = {str(item.get("role") or "") for item in _provenance_list(candidate)}
  if "direct_deleted_line" in modes:
    features.add("direct_old_side_anchor")
  if "modified_old_side" in modes:
    features.add("modified_old_side_anchor")
  if "dangerous_use" in roles:
    features.add("dangerous_use_role")
  if candidate.get("root_cause_hypothesis_bindings") and candidate.get("vulnerable_predicate_bindings"):
    features.add("root_cause_predicate_bound")
  if blame_variants.get("variant_agreement") == "all_same":
    features.add("stable_blame_variants")
  if line_survival.get("line_survives_to_fix_parent"):
    features.add("line_survives_to_fix_parent")
  if commit_relation.get("candidate_is_ancestor_of_fix"):
    features.add("candidate_ancestor_of_fix")
  if commit_relation.get("candidate_touches_same_file"):
    features.add("same_file_touch")
  if commit_relation.get("candidate_touches_same_function"):
    features.add("same_function_touch")
  return sorted(features)


def _judge_packet(cve_id: str, repo: str, evidence: list[dict[str, Any]]) -> dict[str, Any]:
  return {
    "schema_version": "judge_szz_evidence_packet_v0",
    "cve_id": cve_id,
    "repo": repo,
    "candidate_count": len(evidence),
    "lifecycle": "raw_candidate",
    "candidates": [
      {
        "candidate_identity": item["candidate_identity"],
        "blame_variants": {
          "variant_agreement": item["blame_variants"]["variant_agreement"],
          "canonical_blame_commit_sha": item["blame_variants"]["canonical_blame_commit_sha"],
          "success_count": item["blame_variants"]["success_count"],
          "failure_count": item["blame_variants"]["failure_count"],
          "disagreement_taxonomy": item["blame_variants"]["disagreement_taxonomy"],
        },
        "line_survival_evidence": item["line_survival_evidence"],
        "commit_relation_evidence": item["commit_relation_evidence"],
        "rename_move_copy_evidence": item["rename_move_copy_evidence"],
        "fix_series_equivalent_backport_hints": item["fix_series_equivalent_backport_hints"],
        "release_reachability_summary": item["release_reachability_summary"],
        "risk_flags": item["risk_flags"],
        "confidence_features": item["confidence_features"],
        "audit_artifact_ref": "szz_evidence_audit_packet.json",
        "lifecycle": "raw_candidate",
      }
      for item in evidence
    ],
  }


def _audit_packet(cve_id: str, repo: str, evidence: list[dict[str, Any]]) -> dict[str, Any]:
  return {
    "schema_version": "szz_evidence_audit_packet_v0",
    "cve_id": cve_id,
    "repo": repo,
    "candidate_count": len(evidence),
    "lifecycle": "raw_candidate",
    "candidates": evidence,
  }


def _summary(case_results: list[dict[str, Any]], evidence: list[dict[str, Any]], *, duration_s: float) -> dict[str, Any]:
  blame_variants = [item["blame_variants"] for item in evidence]
  variant_successes = sum(variant.get("success_count", 0) for variant in blame_variants)
  variant_total = sum(len(variant.get("variants", [])) for variant in blame_variants)
  return {
    "cases_total": len(case_results),
    "candidates_total": len(evidence),
    "strong_candidate_count": sum(1 for item in evidence if item["candidate_identity"].get("candidate_source") == "strong"),
    "fallback_candidate_count": sum(1 for item in evidence if item["candidate_identity"].get("candidate_source") == "fallback"),
    "evidence_packet_generated_count": sum(1 for item in case_results if item.get("evidence_packet_generated")),
    "blame_variant_success_rate": variant_successes / variant_total if variant_total else 0.0,
    "blame_variant_disagreement_count": sum(1 for item in blame_variants if item.get("variant_agreement") not in {"all_same", "failed"}),
    "line_survives_to_fix_parent_count": sum(1 for item in evidence if item["line_survival_evidence"].get("line_survives_to_fix_parent")),
    "candidate_ancestor_of_fix_count": sum(1 for item in evidence if item["commit_relation_evidence"].get("candidate_is_ancestor_of_fix")),
    "move_copy_sensitive_count": sum(1 for item in evidence if "move_copy_sensitive_blame" in item["risk_flags"]),
    "whitespace_sensitive_count": sum(1 for item in evidence if "whitespace_sensitive_blame" in item["risk_flags"]),
    "merge_candidate_count": sum(1 for item in evidence if "merge_candidate_commit" in item["risk_flags"]),
    "boundary_candidate_count": sum(1 for item in evidence if "boundary_candidate_commit" in item["risk_flags"]),
    "release_reachability_too_broad_count": sum(1 for item in evidence if "release_reachability_too_broad" in item["risk_flags"]),
    "model_invocation_count": 0,
    "judge_invocation_count": 0,
    "lifecycle": "raw_candidate",
    "duration_s": round(duration_s, 6),
  }


def _summary_row(evidence: dict[str, Any]) -> dict[str, Any]:
  identity = evidence["candidate_identity"]
  return {
    "cve_id": identity["cve_id"],
    "repo": identity["repo"],
    "candidate_commit_sha": identity["candidate_commit_sha"],
    "candidate_source": identity["candidate_source"],
    "evidence_level": identity["evidence_level"],
    "lifecycle": identity["lifecycle"],
    "variant_agreement": evidence["blame_variants"]["variant_agreement"],
    "canonical_blame_commit_sha": evidence["blame_variants"]["canonical_blame_commit_sha"],
    "line_survival_status": evidence["line_survival_evidence"]["line_survival_status"],
    "candidate_is_ancestor_of_fix": evidence["commit_relation_evidence"]["candidate_is_ancestor_of_fix"],
    "risk_flags": ";".join(evidence["risk_flags"]),
    "confidence_features": ";".join(evidence["confidence_features"]),
  }


def _risk_row(evidence: dict[str, Any]) -> dict[str, Any]:
  identity = evidence["candidate_identity"]
  risky = {"fallback_candidate", "line_not_surviving_to_fix_parent", "move_copy_sensitive_blame", "candidate_not_ancestor_of_fix", "release_reachability_too_broad"}
  flags = set(evidence["risk_flags"])
  return {
    "cve_id": identity["cve_id"],
    "candidate_commit_sha": identity["candidate_commit_sha"],
    "risk_flags": ";".join(evidence["risk_flags"]),
    "confidence_features": ";".join(evidence["confidence_features"]),
    "suitable_for_judge_v0": not bool(flags & risky),
  }


def _release_row(evidence: dict[str, Any]) -> dict[str, Any]:
  identity = evidence["candidate_identity"]
  row = {"cve_id": identity["cve_id"], "candidate_commit_sha": identity["candidate_commit_sha"]}
  row.update(evidence["release_reachability_summary"])
  return row


def _variant_agreement(variants: list[dict[str, Any]]) -> str:
  successes = [item for item in variants if item.get("blamed_commit_sha")]
  if not successes:
    return "failed"
  commits = {str(item.get("blamed_commit_sha") or "") for item in successes}
  if len(commits) == 1:
    return "all_same"
  normal = next((item for item in successes if item["variant"] == "normal"), {})
  w = next((item for item in successes if item["variant"] == "w"), {})
  if normal.get("blamed_commit_sha") != w.get("blamed_commit_sha"):
    return "whitespace_differs"
  return "move_copy_differs"


def _line_exists(repo: Path, runner: CommandRunner, revision: str, path: str, line_text: str, line_hash: str) -> bool:
  if not revision or not path:
    return False
  result = runner(_git(repo, ["show", f"{revision}:{path}"]), repo)
  if result.exit_code != 0:
    return False
  for line in _lf_lines(result.stdout):
    if line == line_text or _sha256(line) == line_hash:
      return True
  return False


def _is_ancestor(repo: Path, runner: CommandRunner, ancestor: str, descendant: str) -> bool | None:
  if not ancestor or not descendant:
    return None
  result = runner(_git(repo, ["merge-base", "--is-ancestor", ancestor, descendant]), repo)
  if result.exit_code == 0:
    return True
  if result.exit_code == 1:
    return False
  return None


def _distance(repo: Path, runner: CommandRunner, ancestor: str, descendant: str, limit: int) -> tuple[int | None, bool]:
  if not ancestor or not descendant:
    return None, False
  result = runner(_git(repo, ["rev-list", "--count", "--ancestry-path", f"{ancestor}..{descendant}"]), repo)
  if result.exit_code != 0:
    return None, False
  text = result.stdout.strip()
  if not text.isdigit():
    return None, False
  value = int(text)
  return min(value, limit), value > limit


def _parents(repo: Path, runner: CommandRunner, commit_sha: str) -> list[str]:
  if not commit_sha:
    return []
  result = runner(_git(repo, ["rev-list", "--parents", "-n", "1", commit_sha]), repo)
  if result.exit_code != 0:
    return []
  parts = result.stdout.strip().split()
  return parts[1:]


def _first_parent(repo: Path, runner: CommandRunner, commit_sha: str) -> str:
  parents = _parents(repo, runner, commit_sha)
  return parents[0] if parents else ""


def _changed_files(repo: Path, runner: CommandRunner, commit_sha: str) -> set[str]:
  if not commit_sha:
    return set()
  result = runner(_git(repo, ["diff-tree", "--no-commit-id", "--name-only", "-r", commit_sha]), repo)
  if result.exit_code != 0:
    return set()
  return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def _commit_times(repo: Path, runner: CommandRunner, commit_sha: str) -> dict[str, int | None]:
  if not commit_sha:
    return {"author_time": None, "committer_time": None}
  result = runner(_git(repo, ["show", "-s", "--format=%at:%ct:%s", commit_sha]), repo)
  if result.exit_code != 0:
    return {"author_time": None, "committer_time": None}
  parts = result.stdout.strip().split(":", 2)
  return {
    "author_time": int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else None,
    "committer_time": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None,
  }


def _commit_subject(repo: Path, runner: CommandRunner, commit_sha: str) -> str:
  result = runner(_git(repo, ["show", "-s", "--format=%s", commit_sha]), repo)
  return result.stdout.strip() if result.exit_code == 0 else ""


def _path_history(repo: Path, runner: CommandRunner, path: str) -> dict[str, Any]:
  if not path:
    return {"paths": [], "uncertain": True}
  result = runner(_git(repo, ["log", "--follow", "--name-only", "--format=", "--", path]), repo)
  if result.exit_code != 0:
    return {"paths": [], "uncertain": True}
  paths = sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})
  return {"paths": paths[:20], "uncertain": False}


def _render_case_report(cve_id: str, repo: str, evidence: list[dict[str, Any]]) -> str:
  lines = [
    f"# SZZ Evidence {cve_id}",
    "",
    f"- repo: {repo}",
    f"- candidate_count: {len(evidence)}",
    "- lifecycle: raw_candidate",
    "",
    "| candidate | source | agreement | survival | risks |",
    "|---|---|---|---|---|",
  ]
  for item in evidence:
    identity = item["candidate_identity"]
    lines.append(
      f"| `{identity['candidate_commit_sha']}` | {identity['candidate_source']} | {item['blame_variants']['variant_agreement']} | "
      f"{item['line_survival_evidence']['line_survival_status']} | `{item['risk_flags']}` |"
    )
  return "\n".join(lines) + "\n"


def _render_batch_report(summary: dict[str, Any], evidence: list[dict[str, Any]]) -> str:
  high_risk = [
    item["candidate_identity"]["cve_id"]
    for item in evidence
    if set(item["risk_flags"]) & {"fallback_candidate", "line_not_surviving_to_fix_parent", "move_copy_sensitive_blame", "release_reachability_too_broad"}
  ]
  return "\n".join(
    [
      "# Detailed SZZ Evidence Expansion v0",
      "",
      "This is deterministic local evidence expansion for raw candidate commits. It does not call OpenCode/DeepSeek, does not validate vulnerability-introducing commits, and does not infer formal affected versions.",
      "",
      "## Summary",
      "",
      f"- cases_total: {summary['cases_total']}",
      f"- candidates_total: {summary['candidates_total']}",
      f"- evidence_packet_generated_count: {summary['evidence_packet_generated_count']}",
      f"- blame_variant_success_rate: {summary['blame_variant_success_rate']:.4f}",
      f"- blame_variant_disagreement_count: {summary['blame_variant_disagreement_count']}",
      f"- line_survives_to_fix_parent_count: {summary['line_survives_to_fix_parent_count']}",
      f"- candidate_ancestor_of_fix_count: {summary['candidate_ancestor_of_fix_count']}",
      f"- release_reachability_too_broad_count: {summary['release_reachability_too_broad_count']}",
      f"- high_risk_case_ids: `{sorted(set(high_risk))}`",
      "",
      "All candidate commits remain `raw_candidate`.",
    ]
  ) + "\n"


def _render_disagreement_report(evidence: list[dict[str, Any]]) -> str:
  lines = ["# Blame Variant Disagreement", ""]
  rows = [item for item in evidence if item["blame_variants"]["variant_agreement"] not in {"all_same", "failed"}]
  if not rows:
    lines.append("No blame variant disagreements were observed.")
  for item in rows:
    identity = item["candidate_identity"]
    lines.append(f"- {identity['cve_id']} `{identity['candidate_commit_sha']}`: {item['blame_variants']['variant_agreement']}")
  return "\n".join(lines) + "\n"


def _case_dirs(root: Path) -> list[Path]:
  return sorted(path for path in root.iterdir() if path.is_dir() and path.name.startswith("CVE-")) if root.exists() else []


def _audit_candidates_by_identity(packet: dict[str, Any]) -> dict[str, dict[str, Any]]:
  output: dict[str, dict[str, Any]] = {}
  for candidate in packet.get("candidates", []) or []:
    output[_candidate_identity(candidate)] = candidate
  return output


def _candidate_identity(candidate: dict[str, Any]) -> str:
  return "\0".join(
    [
      str(candidate.get("candidate_commit_sha") or ""),
      "|".join(str(item) for item in candidate.get("candidate_ids", []) or []),
      str(candidate.get("selected_anchor_id") or candidate.get("fallback_anchor_id") or ""),
    ]
  )


def _release_tags_for_candidate(blind: dict[str, Any], audit: dict[str, Any]) -> list[str]:
  for source in (audit, blind):
    tags = source.get("predicted_release_tags_from_version_probe")
    if isinstance(tags, list):
      return [str(tag) for tag in tags]
    summary = source.get("release_tag_summary")
    if isinstance(summary, dict):
      tags = summary.get("tags")
      if isinstance(tags, list):
        return [str(tag) for tag in tags]
  return []


def _first_provenance(candidate: dict[str, Any]) -> dict[str, Any]:
  provenance = _provenance_list(candidate)
  return provenance[0] if provenance else {}


def _provenance_list(candidate: dict[str, Any]) -> list[dict[str, Any]]:
  trace = candidate.get("blame_trace") if isinstance(candidate.get("blame_trace"), dict) else {}
  return [item for item in trace.get("line_provenance", []) or [] if isinstance(item, dict)]


def _flatten_fix_commits(value: Any) -> list[str]:
  output: list[str] = []
  stack = list(value if isinstance(value, list) else [value] if value else [])
  while stack:
    item = stack.pop(0)
    if isinstance(item, list):
      stack = list(item) + stack
    elif item:
      output.append(str(item))
  return list(dict.fromkeys(output))


def _sha_from_fix_commit_id(value: Any) -> str:
  text = str(value or "")
  tail = text.rsplit(":", 1)[-1]
  return tail if len(tail) == 40 else ""


def _release_sort_key(tag: str) -> tuple[Any, ...]:
  numbers = [int(item) for item in __import__("re").findall(r"\d+", tag)]
  return (numbers, tag)


def _release_line_key(tag: str) -> str:
  numbers = __import__("re").findall(r"\d+", tag)
  return ".".join(numbers[:2]) if len(numbers) >= 2 else (numbers[0] if numbers else "")


def _safe_command(command: list[str]) -> list[str]:
  return list(command)


def _git(repo: Path, args: list[str]) -> list[str]:
  return ["git", "-c", f"safe.directory={repo}", "-C", str(repo), *args]


def _subprocess_runner(command: list[str], cwd: Path) -> CommandResult:
  result = subprocess.run(
    command,
    cwd=cwd,
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="ignore",
    check=False,
  )
  return CommandResult(command=command, exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)


def _find_exact_key(data: Any, key: str, path: str = "$") -> list[str]:
  matches: list[str] = []
  if isinstance(data, dict):
    for child_key, value in data.items():
      child_path = f"{path}.{child_key}"
      if child_key == key:
        matches.append(child_path)
      matches.extend(_find_exact_key(value, key, child_path))
  elif isinstance(data, list):
    for index, value in enumerate(data):
      matches.extend(_find_exact_key(value, key, f"{path}[{index}]"))
  return matches


def _dataset_record(records: dict[str, Any], cve_id: str) -> dict[str, Any]:
  record = records.get(cve_id, {}) if isinstance(records, dict) else {}
  return record if isinstance(record, dict) else {}


def _read_json(path: Path) -> dict[str, Any]:
  data = json.loads(path.read_text(encoding="utf-8"))
  if not isinstance(data, dict):
    raise ValueError(f"expected JSON object: {path}")
  return data


def _read_json_any(path: Path) -> Any:
  return json.loads(path.read_text(encoding="utf-8"))


def _read_json_default(path: Path, default: dict[str, Any]) -> dict[str, Any]:
  if not path.exists():
    return default
  return _read_json(path)


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


def _int(value: Any) -> int:
  try:
    return int(value)
  except (TypeError, ValueError):
    return 0


def _sha256(value: str) -> str:
  return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _lf_lines(value: str) -> list[str]:
  return [line[:-1] if line.endswith("\r") else line for line in value.split("\n")]

from __future__ import annotations

import csv
import json
import re
import statistics
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


NON_RELEASE_TAG_RE = re.compile(
  r"("
  r"(^|[-_/\.])(candidate|dev|snapshot|backup|bak|test|internal|nightly|experimental|staging|trivial|merge|branch)([-_/\.0-9]|$)"
  r"|"
  r"(rc|pre|preview|alpha|beta)[0-9]*($|[-_/\.])"
  r")",
  re.IGNORECASE,
)
VERSIONISH_TAG_RE = re.compile(
  r"^(?:(?:[a-z][a-z0-9]*|release|version)[-_.])?(?:v|n)?\d+(?:[._-]\d+){1,5}[a-z]?$",
  re.IGNORECASE,
)


@dataclass(frozen=True)
class CandidateVersionResult:
  commit_sha: str
  universe_name: str
  predicted_tags: set[str]
  metrics: dict[str, Any]
  unknown_tags: list[str]
  false_positive_taxonomy: dict[str, list[str]]

  def to_dict(self) -> dict[str, Any]:
    return {
      "commit_sha": self.commit_sha,
      "universe_name": self.universe_name,
      "predicted_tags": sorted(self.predicted_tags),
      "reachable_release_tags": sorted(self.predicted_tags) if self.universe_name == "release_tag_universe" else [],
      "diagnostic_all_tags": sorted(self.predicted_tags) if self.universe_name == "diagnostic_all_tags" else [],
      "metrics": self.metrics,
      "unknown_tags": self.unknown_tags,
      "false_positive_taxonomy": self.false_positive_taxonomy,
    }


@dataclass
class DirectReachabilityRunner:
  tags_by_repo: dict[Path, list[str]] = field(default_factory=dict)
  current_repo: Path | None = None
  cache: dict[tuple[str, str, str], str] = field(default_factory=dict)
  contains_cache: dict[tuple[str, str], set[str] | None] = field(default_factory=dict)
  commit_time_cache: dict[tuple[str, str], int | None] = field(default_factory=dict)
  trace: list[dict[str, Any]] = field(default_factory=list)

  def set_repo(self, repo_path: Path) -> None:
    self.current_repo = Path(repo_path)

  def list_tags(self, repo_path: Path) -> list[str]:
    repo = Path(repo_path)
    self.set_repo(repo)
    for key, value in self.tags_by_repo.items():
      if Path(key) == repo:
        return list(value)
    result = subprocess.run(
      ["git", "-c", f"safe.directory={repo}", "-C", str(repo), "tag", "--list"],
      capture_output=True,
      text=True,
      encoding="utf-8",
      errors="ignore",
      check=False,
    )
    self.trace.append(
      {
        "operation": "list_tags",
        "command": ["git", "-c", f"safe.directory={repo}", "-C", str(repo), "tag", "--list"],
        "cwd": str(repo),
        "exit_code": result.returncode,
        "stderr": result.stderr[-1000:],
      }
    )
    if result.returncode != 0:
      return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]

  def commit_time(self, repo_path: Path, commit_sha: str) -> int | None:
    repo = Path(repo_path)
    key = (str(repo), commit_sha)
    if key in self.commit_time_cache:
      return self.commit_time_cache[key]
    command = ["git", "-c", f"safe.directory={repo}", "-C", str(repo), "show", "-s", "--format=%ct", commit_sha]
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="ignore", check=False)
    self.trace.append(
      {
        "operation": "fix_commit_time",
        "command": command,
        "cwd": str(repo),
        "exit_code": result.returncode,
        "stderr": result.stderr[-1000:],
      }
    )
    value: int | None = None
    if result.returncode == 0:
      text = result.stdout.strip()
      if text.isdigit():
        value = int(text)
    self.commit_time_cache[key] = value
    return value

  def is_ancestor(self, ancestor: str, descendant: str) -> str:
    if self.current_repo is None:
      return "unknown"
    repo = self.current_repo
    key = (str(repo), ancestor, descendant)
    if key in self.cache:
      return self.cache[key]
    command = [
      "git",
      "-c",
      f"safe.directory={repo}",
      "-C",
      str(repo),
      "merge-base",
      "--is-ancestor",
      ancestor,
      descendant,
    ]
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="ignore", check=False)
    self.trace.append(
      {
        "operation": "merge_base_is_ancestor",
        "command": command,
        "cwd": str(repo),
        "exit_code": result.returncode,
        "stderr": result.stderr[-1000:],
      }
    )
    if result.returncode == 0:
      value = "yes"
    elif result.returncode == 1:
      value = "no"
    else:
      value = "unknown"
    self.cache[key] = value
    return value

  def tags_containing(self, commit_sha: str) -> set[str] | None:
    if self.current_repo is None:
      return None
    repo = self.current_repo
    key = (str(repo), commit_sha)
    if key in self.contains_cache:
      return self.contains_cache[key]
    command = ["git", "-c", f"safe.directory={repo}", "-C", str(repo), "tag", "--contains", commit_sha]
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="ignore", check=False)
    self.trace.append(
      {
        "operation": "tag_contains",
        "command": command,
        "cwd": str(repo),
        "exit_code": result.returncode,
        "stderr": result.stderr[-1000:],
      }
    )
    if result.returncode != 0:
      self.contains_cache[key] = None
      return None
    tags = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    self.contains_cache[key] = tags
    return tags


def set_metrics(predicted: set[str], ground_truth: set[str]) -> dict[str, Any]:
  tp = len(predicted & ground_truth)
  fp = len(predicted - ground_truth)
  fn = len(ground_truth - predicted)
  precision = tp / (tp + fp) if tp + fp else (1.0 if not ground_truth else 0.0)
  recall = tp / (tp + fn) if tp + fn else 1.0
  f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
  return {
    "precision": precision,
    "recall": recall,
    "f1": f1,
    "exact_match": predicted == ground_truth,
    "true_positive_count": tp,
    "false_positive_count": fp,
    "false_negative_count": fn,
  }


def build_tag_universe(repo: str, all_tags: list[str]) -> dict[str, Any]:
  release_tags = sorted(tag for tag in all_tags if is_release_tag(tag))
  filtered = sorted(tag for tag in all_tags if tag not in set(release_tags))
  return {
    "repo": repo,
    "all_tag_count": len(all_tags),
    "release_tag_count": len(release_tags),
    "filtered_non_release_tag_count": len(filtered),
    "all_tags": sorted(all_tags),
    "release_tag_universe": release_tags,
    "filtered_non_release_tags": filtered,
    "examples_filtered_tags": filtered[:20],
    "release_filter_source": "generic_numeric_release_tag_filter_excluding_rc_beta_alpha_pre_dev_snapshot_candidate_backup_test_internal",
    "universe_used_for_primary_metrics": "release_tag_universe",
  }


def is_release_tag(tag: str) -> bool:
  cleaned = tag.strip()
  if not cleaned:
    return False
  lower = cleaned.lower()
  if NON_RELEASE_TAG_RE.search(lower):
    return False
  if "backup" in lower or "snapshot" in lower or "internal" in lower:
    return False
  if not re.search(r"\d", cleaned):
    return False
  return bool(VERSIONISH_TAG_RE.fullmatch(cleaned.replace("/", "-")))


def classify_false_positive_tags(
  *,
  predicted_tags: set[str],
  ground_truth_tags: set[str],
  all_tags: set[str],
  release_tags: set[str],
) -> dict[str, list[str]]:
  del all_tags
  false_positive = predicted_tags - ground_truth_tags
  non_release = sorted(tag for tag in false_positive if tag not in release_tags)
  formal_release = sorted(tag for tag in false_positive if tag in release_tags)
  release_line_overreach = sorted(tag for tag in formal_release if _shares_release_line(tag, ground_truth_tags))
  conversion = sorted(tag for tag in formal_release if tag not in set(release_line_overreach))
  return {
    "false_positive_predicted_tags": sorted(false_positive),
    "non_release_tag_noise": non_release,
    "release_line_overreach": release_line_overreach,
    "branch_or_backport_limit": [],
    "conversion_likely_problem": conversion,
  }


def rank_candidate_commits(
  candidates: list[dict[str, Any]],
  *,
  fix_times: list[int] | None = None,
  fix_times_by_commit: dict[str, int] | None = None,
  ground_truth_affected_versions: set[str] | None = None,
) -> list[dict[str, Any]]:
  del ground_truth_affected_versions
  return sorted(
    candidates,
    key=lambda item: _candidate_rank_key(item, fix_times or [], fix_times_by_commit or {}),
  )


def choose_oracle_candidate(results: list[CandidateVersionResult]) -> dict[str, Any]:
  if not results:
    return {
      "oracle_best_candidate_commit": "",
      "diagnostic_only": True,
      "predicted_tags": [],
      "metrics": set_metrics(set(), set()),
    }
  best = max(
    results,
    key=lambda item: (
      float(item.metrics.get("f1") or 0.0),
      bool(item.metrics.get("exact_match")),
      float(item.metrics.get("precision") or 0.0),
      float(item.metrics.get("recall") or 0.0),
    ),
  )
  return {
    "oracle_best_candidate_commit": best.commit_sha,
    "diagnostic_only": True,
    "oracle_interpretation": "raw_candidate_pool_upper_bound_not_system_result",
    "predicted_tags": sorted(best.predicted_tags),
    "metrics": best.metrics,
  }


def direct_reachability_prediction(
  *,
  repo_path: Path,
  candidate_commit: str,
  fixing_commits: list[str],
  tags: list[str],
  runner: DirectReachabilityRunner,
  ground_truth_affected_versions: set[str] | None = None,
  all_tags: set[str] | None = None,
  release_tags: set[str] | None = None,
  universe_name: str = "release_tag_universe",
) -> CandidateVersionResult:
  runner.set_repo(Path(repo_path))
  gt = ground_truth_affected_versions or set()
  all_tag_set = all_tags or set(tags)
  release_tag_set = release_tags or set(tags)
  fast = _direct_reachability_prediction_from_contains(
    candidate_commit=candidate_commit,
    fixing_commits=fixing_commits,
    tags=tags,
    runner=runner,
    ground_truth_affected_versions=gt,
    all_tags=all_tag_set,
    release_tags=release_tag_set,
    universe_name=universe_name,
  )
  if fast is not None:
    return fast
  predicted: set[str] = set()
  unknown: list[str] = []
  for tag in tags:
    candidate_reachable = runner.is_ancestor(candidate_commit, tag)
    if candidate_reachable == "unknown":
      unknown.append(tag)
      continue
    if candidate_reachable != "yes":
      continue
    fix_states = [runner.is_ancestor(fix, tag) for fix in fixing_commits]
    if any(state == "unknown" for state in fix_states):
      unknown.append(tag)
      continue
    if any(state == "yes" for state in fix_states):
      continue
    predicted.add(tag)
  return CandidateVersionResult(
    commit_sha=candidate_commit,
    universe_name=universe_name,
    predicted_tags=predicted,
    metrics=set_metrics(predicted, gt),
    unknown_tags=sorted(set(unknown)),
    false_positive_taxonomy=classify_false_positive_tags(
      predicted_tags=predicted,
      ground_truth_tags=gt,
      all_tags=all_tag_set,
      release_tags=release_tag_set,
    ),
  )


def _direct_reachability_prediction_from_contains(
  *,
  candidate_commit: str,
  fixing_commits: list[str],
  tags: list[str],
  runner: DirectReachabilityRunner,
  ground_truth_affected_versions: set[str],
  all_tags: set[str],
  release_tags: set[str],
  universe_name: str,
) -> CandidateVersionResult | None:
  candidate_tags = runner.tags_containing(candidate_commit)
  if candidate_tags is None:
    return None
  tag_set = set(tags)
  candidate_tags &= tag_set
  fixed_tags: set[str] = set()
  unknown: list[str] = []
  for fix in fixing_commits:
    containing = runner.tags_containing(fix)
    if containing is None:
      unknown.extend(sorted(candidate_tags))
      continue
    fixed_tags |= containing & tag_set
  predicted = candidate_tags - fixed_tags
  return CandidateVersionResult(
    commit_sha=candidate_commit,
    universe_name=universe_name,
    predicted_tags=set(predicted),
    metrics=set_metrics(set(predicted), ground_truth_affected_versions),
    unknown_tags=sorted(set(unknown)),
    false_positive_taxonomy=classify_false_positive_tags(
      predicted_tags=set(predicted),
      ground_truth_tags=ground_truth_affected_versions,
      all_tags=all_tags,
      release_tags=release_tags,
    ),
  )


def inspect_dataset_schema(
  dataset: str | Path,
  cve_ids: list[str],
  *,
  repo_root: str | Path,
  git_runner: DirectReachabilityRunner | None = None,
) -> dict[str, Any]:
  records = _read_json(Path(dataset))
  runner = git_runner or DirectReachabilityRunner()
  cases: dict[str, Any] = {}
  for cve_id in cve_ids:
    record = records.get(cve_id)
    problems: list[str] = []
    repo_name = ""
    tags: list[str] = []
    release_tags: list[str] = []
    gt_values: list[str] = []
    fix_commits: list[str] = []
    affected_field = ""
    if not isinstance(record, dict):
      problems.append("record_missing")
    else:
      repo_name = str(record.get("repo") or "")
      if not repo_name:
        problems.append("missing_repo")
      fix_commits = _flatten_fix_commits(record.get("fixing_commits"))
      if not fix_commits:
        problems.append("missing_fixing_commits")
      affected_field = _affected_field(record)
      if not affected_field:
        problems.append("missing_affected_version_field")
      else:
        raw_gt = record.get(affected_field)
        if not isinstance(raw_gt, list) or not all(isinstance(item, str) for item in raw_gt):
          problems.append("invalid_affected_version_format")
        else:
          gt_values = list(raw_gt)
      if repo_name:
        repo_path = Path(repo_root) / repo_name
        if not repo_path.exists():
          problems.append("repo_path_missing")
        else:
          tags = runner.list_tags(repo_path)
          if not tags:
            problems.append("tag_list_empty")
          release_tags = build_tag_universe(repo_name, tags)["release_tag_universe"]
          missing_tags = sorted(set(gt_values) - set(tags))
          if missing_tags:
            problems.append("ground_truth_tags_not_in_repo")
    cases[cve_id] = {
      "ok": not problems,
      "problems": problems,
      "repo": repo_name,
      "affected_version_field": affected_field or None,
      "ground_truth_affected_versions": sorted(gt_values),
      "fixing_commits": fix_commits,
      "tag_count": len(tags),
      "release_tag_count": len(release_tags),
      "tag_name_samples": tags[:10],
      "release_tag_samples": release_tags[:10],
      "all_tags": tags,
      "release_tag_universe": release_tags,
      "missing_ground_truth_tags": sorted(set(gt_values) - set(tags)),
    }
  return {
    "ok": all(item["ok"] for item in cases.values()),
    "cases": cases,
    "dataset_or_tag_mapping_problem_cases": [cve_id for cve_id, item in cases.items() if not item["ok"]],
  }


def run_szz_anchor_version_probe(
  *,
  anchor_run: str | Path,
  dataset: str | Path,
  repo_root: str | Path,
  out_dir: str | Path,
  git_runner: DirectReachabilityRunner | None = None,
) -> dict[str, Any]:
  started = time.monotonic()
  anchor_root = Path(anchor_run)
  output_root = Path(out_dir)
  output_root.mkdir(parents=True, exist_ok=True)
  records = _read_json(Path(dataset))
  summary = _read_json(anchor_root / "summary.json")
  cve_ids = [str(item.get("cve_id")) for item in summary.get("results", []) if item.get("cve_id")]
  runner = git_runner or DirectReachabilityRunner()
  schema = inspect_dataset_schema(dataset, cve_ids, repo_root=repo_root, git_runner=runner)
  _write_json(output_root / "schema_diagnostics.json", schema)

  per_candidate: dict[str, Any] = {}
  ranking: dict[str, Any] = {}
  tag_diagnostics = {"repos": {}, "universe_used_for_primary_metrics": "release_tag_universe"}
  rows: list[dict[str, Any]] = []
  attribution = _empty_attribution()
  structured_attribution: list[dict[str, Any]] = []

  for cve_id in cve_ids:
    record = records.get(cve_id, {})
    case_schema = schema["cases"].get(cve_id, {})
    case_dir = anchor_root / cve_id
    repo_name = str(record.get("repo") or "")
    repo_path = Path(repo_root) / repo_name
    gt = set(case_schema.get("ground_truth_affected_versions") or [])
    fix_commits = list(case_schema.get("fixing_commits") or [])
    raw_candidates = [
      item for item in _read_list(case_dir / "candidate_commits.json") if item.get("lifecycle") == "raw_candidate"
    ]
    resolved = _read_list(case_dir / "resolved_pre_fix_anchors.json")
    ingestion = _read_json_default(case_dir / "ingestion_result.json", {})
    all_tags = list(case_schema.get("all_tags") or [])
    if not all_tags and repo_path.exists():
      all_tags = runner.list_tags(repo_path)
    universe = build_tag_universe(repo_name, all_tags)
    tag_diagnostics["repos"][repo_name] = {
      key: value
      for key, value in universe.items()
      if key
      in {
        "repo",
        "all_tag_count",
        "release_tag_count",
        "filtered_non_release_tag_count",
        "examples_filtered_tags",
        "release_filter_source",
        "universe_used_for_primary_metrics",
      }
    }
    release_tags = list(universe["release_tag_universe"])
    fix_times_by_commit = _fix_commit_times(repo_path, fix_commits, runner) if repo_path.exists() else {}
    fallback_fix_times = [value for value in fix_times_by_commit.values() if value is not None]
    ranked = rank_candidate_commits(
      raw_candidates,
      fix_times=fallback_fix_times,
      fix_times_by_commit={key: value for key, value in fix_times_by_commit.items() if value is not None},
    )

    all_results = _candidate_results_for_universe(
      raw_candidates=raw_candidates,
      repo_path=repo_path,
      fix_commits=fix_commits,
      tags=all_tags,
      runner=runner,
      gt=gt,
      all_tags=set(all_tags),
      release_tags=set(release_tags),
      universe_name="diagnostic_all_tags",
    )
    release_results = _candidate_results_for_universe(
      raw_candidates=raw_candidates,
      repo_path=repo_path,
      fix_commits=fix_commits,
      tags=release_tags,
      runner=runner,
      gt=gt,
      all_tags=set(all_tags),
      release_tags=set(release_tags),
      universe_name="release_tag_universe",
    )
    all_rank = _ranking_payload(all_results, ranked, gt)
    release_rank = _ranking_payload(release_results, ranked, gt)
    top1_release = release_rank["top1"]
    topk_release = release_rank["topk"]
    oracle_release = release_rank["oracle"]
    top1_all = all_rank["top1"]
    oracle_all = all_rank["oracle"]
    top1_fp_release = classify_false_positive_tags(
      predicted_tags=set(top1_release.get("predicted_tags") or []),
      ground_truth_tags=gt,
      all_tags=set(all_tags),
      release_tags=set(release_tags),
    )
    top1_fp_all = classify_false_positive_tags(
      predicted_tags=set(top1_all.get("predicted_tags") or []),
      ground_truth_tags=gt,
      all_tags=set(all_tags),
      release_tags=set(release_tags),
    )
    top1_fp = _merge_fp_taxonomy(top1_fp_release, top1_fp_all)
    oracle_fp_release = classify_false_positive_tags(
      predicted_tags=set(oracle_release.get("predicted_tags") or []),
      ground_truth_tags=gt,
      all_tags=set(all_tags),
      release_tags=set(release_tags),
    )
    oracle_fp_all = classify_false_positive_tags(
      predicted_tags=set(oracle_all.get("predicted_tags") or []),
      ground_truth_tags=gt,
      all_tags=set(all_tags),
      release_tags=set(release_tags),
    )
    oracle_fp = _merge_fp_taxonomy(oracle_fp_release, oracle_fp_all)
    any_fp_release = _any_candidate_fp(release_results, gt, set(all_tags), set(release_tags))
    any_fp_all = _any_candidate_fp(all_results, gt, set(all_tags), set(release_tags))
    any_fp = _merge_fp_taxonomy(any_fp_release, any_fp_all)
    bucket = _attribute_case(
      schema_ok=bool(case_schema.get("ok")),
      candidate_count=len(raw_candidates),
      top1_metrics=top1_release["metrics"],
      topk_metrics=topk_release["metrics"],
      oracle_metrics=oracle_release["metrics"],
      fp_taxonomy=oracle_fp,
    )
    attribution[bucket].append(cve_id)
    structured = _structured_case_attribution(
      cve_id=cve_id,
      schema_ok=bool(case_schema.get("ok")),
      candidate_count=len(raw_candidates),
      top1_metrics=top1_release["metrics"],
      oracle_metrics=oracle_release["metrics"],
      fp_taxonomy=oracle_fp,
      bucket=bucket,
    )
    structured_attribution.append(structured)
    per_candidate[cve_id] = {
      "ground_truth_affected_versions": sorted(gt),
      "repo": repo_name,
      "tag_universe": {
        "all_tag_count": len(all_tags),
        "release_tag_count": len(release_tags),
      },
      "diagnostic_all_tags": [
        {
          **item.to_dict(),
          "candidate_metadata": _candidate_public_metadata(raw_candidates, item.commit_sha),
        }
        for item in all_results
      ],
      "release_tag_universe": [
        {
          **item.to_dict(),
          "candidate_metadata": _candidate_public_metadata(raw_candidates, item.commit_sha),
        }
        for item in release_results
      ],
    }
    ranking[cve_id] = {
      "tie_breaker_strategy": "per_fix_commit_time_if_available_else_min_fix_commit_time",
      "fix_commit_times": fix_times_by_commit,
      "top1_candidate_commit": ranked[0].get("commit_sha") if ranked else "",
      "candidate_order": [str(item.get("commit_sha") or "") for item in ranked],
      "diagnostic_all_tags": all_rank,
      "release_tag_universe": release_rank,
    }
    rows.append(
      {
        "cve_id": cve_id,
        "repo": repo_name,
        "schema_ok": bool(case_schema.get("ok")),
        "anchor_count": len(resolved),
        "candidate_commit_count": len(raw_candidates),
        "parse_status": ingestion.get("parse_status", ""),
        "contract_ok": ingestion.get("contract_ok", ""),
        "blame_status": ingestion.get("blame_status", ""),
        "top1_candidate_commit": ranked[0].get("commit_sha") if ranked else "",
        "release_top1_precision": top1_release["metrics"]["precision"],
        "release_top1_recall": top1_release["metrics"]["recall"],
        "release_top1_f1": top1_release["metrics"]["f1"],
        "release_top1_exact_match": top1_release["metrics"]["exact_match"],
        "release_topk_precision": topk_release["metrics"]["precision"],
        "release_topk_recall": topk_release["metrics"]["recall"],
        "release_topk_f1": topk_release["metrics"]["f1"],
        "release_topk_exact_match": topk_release["metrics"]["exact_match"],
        "release_oracle_precision": oracle_release["metrics"]["precision"],
        "release_oracle_recall": oracle_release["metrics"]["recall"],
        "release_oracle_f1": oracle_release["metrics"]["f1"],
        "release_oracle_exact_match": oracle_release["metrics"]["exact_match"],
        "diagnostic_all_top1_precision": top1_all["metrics"]["precision"],
        "diagnostic_all_top1_recall": top1_all["metrics"]["recall"],
        "diagnostic_all_top1_f1": top1_all["metrics"]["f1"],
        "diagnostic_all_top1_exact_match": top1_all["metrics"]["exact_match"],
        "diagnostic_all_oracle_precision": oracle_all["metrics"]["precision"],
        "diagnostic_all_oracle_recall": oracle_all["metrics"]["recall"],
        "diagnostic_all_oracle_f1": oracle_all["metrics"]["f1"],
        "diagnostic_all_oracle_exact_match": oracle_all["metrics"]["exact_match"],
        "oracle_best_candidate_commit": oracle_release.get("oracle_best_candidate_commit", ""),
        "error_bucket": bucket,
        "top1_false_positive_tag_count": len(top1_fp["false_positive_predicted_tags"]),
        "oracle_false_positive_tag_count": len(oracle_fp["false_positive_predicted_tags"]),
        "any_candidate_false_positive_tag_count": len(any_fp["false_positive_predicted_tags"]),
        "non_release_tag_noise_count": len(any_fp["non_release_tag_noise"]),
        "release_line_overreach_count": len(any_fp["release_line_overreach"]),
        "branch_or_backport_limit_tag_count": len(any_fp["branch_or_backport_limit"]),
        "ground_truth_affected_versions": ";".join(sorted(gt)),
        "top1_predicted_tags": ";".join(top1_release.get("predicted_tags", [])),
        "topk_predicted_tags": ";".join(topk_release.get("predicted_tags", [])),
        "oracle_predicted_tags": ";".join(oracle_release.get("predicted_tags", [])),
      }
    )

  _write_json(output_root / "per_candidate_probe.json", per_candidate)
  _write_json(output_root / "ranking_diagnostics.json", ranking)
  _write_json(output_root / "tag_universe_diagnostics.json", tag_diagnostics)
  _write_csv(output_root / "per_cve_version_probe.csv", rows)
  _write_error_attribution(output_root / "error_attribution.md", attribution, structured_attribution)
  probe_summary = _summary_from_rows(
    rows,
    attribution,
    structured_attribution,
    per_candidate,
    anchor_root,
    dataset,
    repo_root,
    time.monotonic() - started,
  )
  _write_json(output_root / "summary.json", probe_summary)
  _write_json(output_root / "provenance_manifest.json", _provenance(anchor_root, dataset, repo_root))
  (output_root / "report.md").write_text(_render_report(probe_summary, rows, attribution), encoding="utf-8")
  return probe_summary


def _candidate_results_for_universe(
  *,
  raw_candidates: list[dict[str, Any]],
  repo_path: Path,
  fix_commits: list[str],
  tags: list[str],
  runner: DirectReachabilityRunner,
  gt: set[str],
  all_tags: set[str],
  release_tags: set[str],
  universe_name: str,
) -> list[CandidateVersionResult]:
  results: list[CandidateVersionResult] = []
  for candidate in raw_candidates:
    commit = str(candidate.get("commit_sha") or "")
    if not commit:
      continue
    results.append(
      direct_reachability_prediction(
        repo_path=repo_path,
        candidate_commit=commit,
        fixing_commits=fix_commits,
        tags=tags,
        runner=runner,
        ground_truth_affected_versions=gt,
        all_tags=all_tags,
        release_tags=release_tags,
        universe_name=universe_name,
      )
    )
  return results


def _ranking_payload(
  results: list[CandidateVersionResult],
  ranked_candidates: list[dict[str, Any]],
  gt: set[str],
) -> dict[str, Any]:
  top1_candidate = ranked_candidates[0] if ranked_candidates else None
  top1_result = _result_for_candidate(results, top1_candidate)
  topk_candidates = ranked_candidates[:3]
  topk_prediction = _union_predictions(results, topk_candidates)
  topk_metrics = set_metrics(topk_prediction, gt)
  oracle = choose_oracle_candidate(results)
  return {
    "top1_candidate_commit": top1_candidate.get("commit_sha") if top1_candidate else "",
    "top1": top1_result.to_dict() if top1_result else _empty_candidate_result().to_dict(),
    "topk_k": 3,
    "topk_candidate_commits": [str(item.get("commit_sha") or "") for item in topk_candidates],
    "topk": {
      "predicted_tags": sorted(topk_prediction),
      "metrics": topk_metrics,
    },
    "oracle": oracle,
  }


def _summary_from_rows(
  rows: list[dict[str, Any]],
  attribution: dict[str, list[str]],
  structured_attribution: list[dict[str, Any]],
  per_candidate: dict[str, Any],
  anchor_run: Path,
  dataset: str | Path,
  repo_root: str | Path,
  duration_s: float,
) -> dict[str, Any]:
  release_top1 = _macro(rows, "release_top1")
  release_topk = _macro(rows, "release_topk")
  release_oracle = _macro(rows, "release_oracle")
  all_top1 = _macro(rows, "diagnostic_all_top1")
  all_oracle = _macro(rows, "diagnostic_all_oracle")
  return {
    "cases_total": len(rows),
    "anchors_total": sum(int(row["anchor_count"]) for row in rows),
    "candidates_total": sum(int(row["candidate_commit_count"]) for row in rows),
    "cases_with_candidate_commits": sum(1 for row in rows if int(row["candidate_commit_count"]) > 0),
    "primary_universe": "release_tag_universe",
    "release_evaluation_universe_metrics": {
      "top1": release_top1,
      "topk": release_topk,
      "oracle": release_oracle,
      "top1_exact_match_count": sum(1 for row in rows if row["release_top1_exact_match"] is True),
      "topk_exact_match_count": sum(1 for row in rows if row["release_topk_exact_match"] is True),
      "oracle_exact_match_count": sum(1 for row in rows if row["release_oracle_exact_match"] is True),
    },
    "diagnostic_all_tags_metrics": {
      "top1": all_top1,
      "oracle": all_oracle,
      "top1_exact_match_count": sum(1 for row in rows if row["diagnostic_all_top1_exact_match"] is True),
      "oracle_exact_match_count": sum(1 for row in rows if row["diagnostic_all_oracle_exact_match"] is True),
    },
    "top1_macro_precision": release_top1["precision"],
    "top1_macro_recall": release_top1["recall"],
    "top1_macro_f1": release_top1["f1"],
    "topk_macro_precision": release_topk["precision"],
    "topk_macro_recall": release_topk["recall"],
    "topk_macro_f1": release_topk["f1"],
    "oracle_macro_precision": release_oracle["precision"],
    "oracle_macro_recall": release_oracle["recall"],
    "oracle_macro_f1": release_oracle["f1"],
    "oracle_upper_bound_interpretation": "current_raw_candidate_pool_upper_bound_not_system_result_or_bic",
    "oracle_improvement_over_top1_f1": release_oracle["f1"] - release_top1["f1"],
    "top1_false_positive_tag_cases": [
      row["cve_id"] for row in rows if int(row["top1_false_positive_tag_count"]) > 0
    ],
    "oracle_false_positive_tag_cases": [
      row["cve_id"] for row in rows if int(row["oracle_false_positive_tag_count"]) > 0
    ],
    "any_candidate_false_positive_tag_cases": [
      row["cve_id"] for row in rows if int(row["any_candidate_false_positive_tag_count"]) > 0
    ],
    "any_candidate_non_release_tag_noise_cases": [
      row["cve_id"] for row in rows if int(row["non_release_tag_noise_count"]) > 0
    ],
    "dominant_non_release_tag_noise_cases": attribution["non_release_tag_noise"],
    "manual_anchor_review_required_cases": [
      item["cve_id"]
      for item in structured_attribution
      if item.get("anchor_or_blame_status") == "requires_manual_anchor_review"
    ],
    "dominant_requires_manual_review_cases": attribution["requires_manual_review"],
    "release_line_overreach_cases": [
      row["cve_id"] for row in rows if int(row["release_line_overreach_count"]) > 0
    ],
    "branch_or_backport_limit_case_ids": [
      row["cve_id"] for row in rows if int(row["branch_or_backport_limit_tag_count"]) > 0
    ],
    "dataset_or_tag_mapping_problem_cases": attribution["dataset_or_tag_mapping_problem"],
    "structured_error_attribution": structured_attribution,
    "per_error_bucket_counts": {key: len(value) for key, value in attribution.items()},
    "per_error_bucket_cases": attribution,
    "anchor_run": str(anchor_run),
    "dataset": str(dataset),
    "repo_root": str(repo_root),
    "duration_s": round(duration_s, 6),
    "per_cve_candidate_commit_counts": {
      cve_id: len(payload.get("release_tag_universe", [])) for cve_id, payload in per_candidate.items()
    },
  }


def _macro(rows: list[dict[str, Any]], prefix: str) -> dict[str, float]:
  if not rows:
    return {"precision": 0.0, "recall": 0.0, "f1": 0.0}
  return {
    "precision": statistics.mean(float(row[f"{prefix}_precision"]) for row in rows),
    "recall": statistics.mean(float(row[f"{prefix}_recall"]) for row in rows),
    "f1": statistics.mean(float(row[f"{prefix}_f1"]) for row in rows),
  }


def _candidate_rank_key(
  candidate: dict[str, Any],
  fallback_fix_times: list[int],
  fix_times_by_commit: dict[str, int],
) -> tuple[Any, ...]:
  provenance = list(candidate.get("line_provenance") or [])
  boundary = any(item.get("boundary_marker") is True for item in provenance)
  role_rank = min((_role_priority(str(role)) for role in candidate.get("roles", []) or [""]), default=9)
  mode_rank = min((_mode_priority(str(mode)) for mode in candidate.get("selection_modes", []) or [""]), default=9)
  vote_count = int(candidate.get("vote_count") or 0)
  candidate_times = [
    int(item.get("committer_time") or item.get("author_time") or 0)
    for item in provenance
    if item.get("committer_time") or item.get("author_time")
  ]
  bound_fix_times = [
    fix_times_by_commit[str(item.get("fix_commit_sha"))]
    for item in provenance
    if str(item.get("fix_commit_sha")) in fix_times_by_commit
  ]
  target_fix_times = bound_fix_times or fallback_fix_times
  closeness = _time_closeness(candidate_times, target_fix_times)
  return (
    1 if candidate.get("excluded") is True else 0,
    1 if boundary else 0,
    role_rank,
    mode_rank,
    -vote_count,
    closeness,
    str(candidate.get("commit_sha") or ""),
  )


def _role_priority(role: str) -> int:
  if role in {"dangerous_use", "sink", "missing_guard_target"}:
    return 0
  if role in {"state_declaration", "control_predecessor", "data_source", "propagation"}:
    return 1
  if role == "context_fallback":
    return 2
  return 9


def _mode_priority(mode: str) -> int:
  if mode in {"modified_old_side", "direct_deleted_line"}:
    return 0
  if mode == "add_only_semantic_target":
    return 1
  if mode == "context_fallback":
    return 2
  return 9


def _time_closeness(candidate_times: list[int], fix_times: list[int]) -> int:
  if not candidate_times or not fix_times:
    return 10**18
  return min(abs(candidate_time - fix_time) for candidate_time in candidate_times for fix_time in fix_times)


def _affected_field(record: dict[str, Any]) -> str:
  for key in ("affected_version", "affected_versions", "ground_truth_affected_versions"):
    if key in record:
      return key
  return ""


def _flatten_fix_commits(value: Any) -> list[str]:
  output: list[str] = []
  for item in value or []:
    if isinstance(item, list):
      output.extend(str(inner) for inner in item if str(inner).strip())
    elif str(item).strip():
      output.append(str(item))
  return output


def _fix_commit_times(repo_path: Path, fix_commits: list[str], runner: DirectReachabilityRunner) -> dict[str, int | None]:
  return {fix: runner.commit_time(repo_path, fix) for fix in fix_commits}


def _result_for_candidate(
  results: list[CandidateVersionResult],
  candidate: dict[str, Any] | None,
) -> CandidateVersionResult | None:
  if not candidate:
    return None
  commit = str(candidate.get("commit_sha") or "")
  for result in results:
    if result.commit_sha == commit:
      return result
  return None


def _union_predictions(
  results: list[CandidateVersionResult],
  candidates: list[dict[str, Any]],
) -> set[str]:
  commit_ids = {str(item.get("commit_sha") or "") for item in candidates}
  output: set[str] = set()
  for result in results:
    if result.commit_sha in commit_ids:
      output |= result.predicted_tags
  return output


def _empty_candidate_result() -> CandidateVersionResult:
  return CandidateVersionResult(
    commit_sha="",
    universe_name="release_tag_universe",
    predicted_tags=set(),
    metrics=set_metrics(set(), set()),
    unknown_tags=[],
    false_positive_taxonomy={},
  )


def _candidate_public_metadata(candidates: list[dict[str, Any]], commit_sha: str) -> dict[str, Any]:
  for candidate in candidates:
    if str(candidate.get("commit_sha") or "") == commit_sha:
      return {
        "roles": candidate.get("roles", []),
        "selection_modes": candidate.get("selection_modes", []),
        "vote_count": candidate.get("vote_count", 0),
        "excluded": candidate.get("excluded", False),
        "exclusion_reasons": candidate.get("exclusion_reasons", []),
        "boundary_marker": any(item.get("boundary_marker") is True for item in candidate.get("line_provenance") or []),
        "lifecycle": candidate.get("lifecycle", ""),
      }
  return {}


def _attribute_case(
  *,
  schema_ok: bool,
  candidate_count: int,
  top1_metrics: dict[str, Any],
  topk_metrics: dict[str, Any],
  oracle_metrics: dict[str, Any],
  fp_taxonomy: dict[str, list[str]],
) -> str:
  if not schema_ok:
    return "dataset_or_tag_mapping_problem"
  if candidate_count == 0:
    return "anchor_or_blame_likely_problem"
  oracle_f1 = float(oracle_metrics.get("f1") or 0.0)
  top1_f1 = float(top1_metrics.get("f1") or 0.0)
  topk_f1 = float(topk_metrics.get("f1") or 0.0)
  if oracle_f1 < 0.2:
    return "anchor_or_blame_likely_problem"
  if fp_taxonomy.get("non_release_tag_noise") and not (
    fp_taxonomy.get("release_line_overreach") or fp_taxonomy.get("conversion_likely_problem")
  ):
    return "non_release_tag_noise"
  if fp_taxonomy.get("release_line_overreach"):
    return "release_line_overreach"
  if fp_taxonomy.get("conversion_likely_problem"):
    return "conversion_likely_problem"
  if oracle_f1 - max(top1_f1, topk_f1) >= 0.25:
    return "candidate_pool_has_signal"
  return "requires_manual_review"


def _structured_case_attribution(
  *,
  cve_id: str,
  schema_ok: bool,
  candidate_count: int,
  top1_metrics: dict[str, Any],
  oracle_metrics: dict[str, Any],
  fp_taxonomy: dict[str, list[str]],
  bucket: str,
) -> dict[str, Any]:
  if not schema_ok:
    anchor_status = "dataset_or_tag_mapping_problem"
  elif candidate_count == 0:
    anchor_status = "no_raw_candidate_commits"
  else:
    anchor_status = "requires_manual_anchor_review"
  if candidate_count == 0:
    candidate_pool_status = "empty"
  elif float(oracle_metrics.get("f1") or 0.0) > float(top1_metrics.get("f1") or 0.0):
    candidate_pool_status = "candidate_pool_has_signal"
  else:
    candidate_pool_status = "candidate_pool_signal_close_to_top1"
  if fp_taxonomy.get("non_release_tag_noise"):
    conversion_status = "non_release_tag_noise"
  elif fp_taxonomy.get("release_line_overreach"):
    conversion_status = "release_line_overreach"
  elif fp_taxonomy.get("conversion_likely_problem"):
    conversion_status = "conversion_likely_problem"
  elif bool(oracle_metrics.get("exact_match")):
    conversion_status = "direct_reachability_matches_gt"
  else:
    conversion_status = "requires_manual_review"
  return {
    "cve_id": cve_id,
    "anchor_or_blame_status": anchor_status,
    "candidate_pool_status": candidate_pool_status,
    "conversion_status": conversion_status,
    "dominant_error_source": bucket,
    "manual_review_required": anchor_status == "requires_manual_anchor_review" or conversion_status == "requires_manual_review",
  }


def _empty_attribution() -> dict[str, list[str]]:
  return {
    "candidate_pool_has_signal": [],
    "anchor_or_blame_likely_problem": [],
    "conversion_likely_problem": [],
    "dataset_or_tag_mapping_problem": [],
    "non_release_tag_noise": [],
    "release_line_overreach": [],
    "requires_manual_review": [],
  }


def _any_candidate_fp(
  results: list[CandidateVersionResult],
  gt: set[str],
  all_tags: set[str],
  release_tags: set[str],
) -> dict[str, list[str]]:
  predicted: set[str] = set()
  for result in results:
    predicted |= result.predicted_tags
  return classify_false_positive_tags(
    predicted_tags=predicted,
    ground_truth_tags=gt,
    all_tags=all_tags,
    release_tags=release_tags,
  )


def _merge_fp_taxonomy(primary_release: dict[str, list[str]], diagnostic_all: dict[str, list[str]]) -> dict[str, list[str]]:
  keys = {
    "false_positive_predicted_tags",
    "non_release_tag_noise",
    "release_line_overreach",
    "branch_or_backport_limit",
    "conversion_likely_problem",
  }
  output: dict[str, list[str]] = {}
  for key in keys:
    values = set(primary_release.get(key, []))
    if key in {"false_positive_predicted_tags", "non_release_tag_noise"}:
      values |= set(diagnostic_all.get(key, []))
    output[key] = sorted(values)
  return output


def _shares_release_line(tag: str, ground_truth_tags: set[str]) -> bool:
  tag_prefix = _release_line_key(tag)
  return bool(tag_prefix and any(tag_prefix == _release_line_key(gt) for gt in ground_truth_tags))


def _release_line_key(tag: str) -> str:
  numbers = re.findall(r"\d+", tag)
  if not numbers:
    return ""
  if len(numbers) == 1:
    return numbers[0]
  return ".".join(numbers[:2])


def _write_error_attribution(
  path: Path,
  attribution: dict[str, list[str]],
  structured_attribution: list[dict[str, Any]],
) -> None:
  lines = ["# Error Attribution", ""]
  lines.append("## Structured Per-CVE Attribution")
  lines.append("")
  for item in structured_attribution:
    lines.append(
      "- "
      f"{item['cve_id']}: anchor_or_blame={item['anchor_or_blame_status']}; "
      f"candidate_pool={item['candidate_pool_status']}; conversion={item['conversion_status']}; "
      f"dominant={item['dominant_error_source']}; manual_review={item['manual_review_required']}"
    )
  lines.append("")
  for key, values in attribution.items():
    lines.extend([f"## {key}", "", *(f"- {value}" for value in values), ""])
  path.write_text("\n".join(lines), encoding="utf-8")


def _render_report(summary: dict[str, Any], rows: list[dict[str, Any]], attribution: dict[str, list[str]]) -> str:
  release = summary["release_evaluation_universe_metrics"]
  diagnostic = summary["diagnostic_all_tags_metrics"]
  lines = [
    "# SZZ Anchor to Version Probe v2",
    "",
    "This is an engineering diagnostic over the current SZZ anchor raw candidate pool. It does not validate BICs and does not implement a formal affected-version system.",
    "",
    "Primary metrics use `release_tag_universe`. `diagnostic_all_tags` is retained only to measure non-release tag noise.",
    "",
    "Oracle metrics are a raw candidate-pool upper bound, not a system result. All candidate commits remain `raw_candidate`.",
    "",
    "## Summary",
    "",
    f"- cases_total: {summary['cases_total']}",
    f"- anchors_total: {summary['anchors_total']}",
    f"- candidates_total: {summary['candidates_total']}",
    f"- release top1 macro P/R/F1: {release['top1']['precision']:.4f} / {release['top1']['recall']:.4f} / {release['top1']['f1']:.4f}",
    f"- release topk macro P/R/F1: {release['topk']['precision']:.4f} / {release['topk']['recall']:.4f} / {release['topk']['f1']:.4f}",
    f"- release oracle macro P/R/F1: {release['oracle']['precision']:.4f} / {release['oracle']['recall']:.4f} / {release['oracle']['f1']:.4f}",
    f"- diagnostic all-tags top1 F1: {diagnostic['top1']['f1']:.4f}",
    f"- diagnostic all-tags oracle F1: {diagnostic['oracle']['f1']:.4f}",
    f"- oracle improvement over top1 F1: {summary['oracle_improvement_over_top1_f1']:.4f}",
    f"- top1 false-positive cases: `{summary['top1_false_positive_tag_cases']}`",
    f"- oracle false-positive cases: `{summary['oracle_false_positive_tag_cases']}`",
    f"- any-candidate false-positive cases: `{summary['any_candidate_false_positive_tag_cases']}`",
    f"- any-candidate non-release tag noise cases: `{summary['any_candidate_non_release_tag_noise_cases']}`",
    f"- dominant non-release tag noise cases: `{summary['dominant_non_release_tag_noise_cases']}`",
    f"- manual anchor review required cases: `{summary['manual_anchor_review_required_cases']}`",
    f"- dominant requires-manual-review cases: `{summary['dominant_requires_manual_review_cases']}`",
    "",
    "## Per-CVE",
    "",
    "| CVE | Release Top1 F1 | Release TopK F1 | Release Oracle F1 | Oracle candidate | Error bucket |",
    "|---|---:|---:|---:|---|---|",
  ]
  for row in rows:
    lines.append(
      f"| {row['cve_id']} | {float(row['release_top1_f1']):.4f} | {float(row['release_topk_f1']):.4f} | "
      f"{float(row['release_oracle_f1']):.4f} | `{row['oracle_best_candidate_commit']}` | {row['error_bucket']} |"
    )
  lines.extend(["", "## Error Buckets", ""])
  for key, values in attribution.items():
    lines.append(f"- {key}: {len(values)} cases `{values}`")
  return "\n".join(lines) + "\n"


def _provenance(anchor_run: Path, dataset: str | Path, repo_root: str | Path) -> dict[str, Any]:
  return {
    "anchor_run": str(anchor_run),
    "dataset": str(dataset),
    "repo_root": str(repo_root),
    "model_invocation_count": 0,
    "judge_agent_invocation_count": 0,
    "lifecycle": "diagnostic_probe_raw_candidate_pool",
    "prediction_field_names": ["predicted_tags", "reachable_release_tags", "diagnostic_all_tags"],
    "ground_truth_field_name": "ground_truth_affected_versions",
  }


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
  if not rows:
    path.write_text("", encoding="utf-8")
    return
  columns = list(rows[0].keys())
  with path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=columns)
    writer.writeheader()
    writer.writerows(rows)


def _read_json(path: Path) -> dict[str, Any]:
  data = json.loads(path.read_text(encoding="utf-8"))
  if not isinstance(data, dict):
    raise ValueError(f"expected JSON object: {path}")
  return data


def _read_json_default(path: Path, default: dict[str, Any]) -> dict[str, Any]:
  if not path.exists():
    return default
  return _read_json(path)


def _read_list(path: Path) -> list[dict[str, Any]]:
  if not path.exists():
    return []
  data = json.loads(path.read_text(encoding="utf-8"))
  return data if isinstance(data, list) else []


def _write_json(path: Path, data: Any) -> None:
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

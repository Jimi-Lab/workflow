from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnversion.stage1_semantic_aggregation.deterministic import run_step1_deterministic_extractor
from vulnversion.stage2_rci_navigation.step1_adapter import (
  build_root_cause_vet_from_step1,
  load_step1_vet_seed,
)


DEFAULT_DATASET = Path("DataSet/BaseDataOrder.json")
DEFAULT_NVD = Path("DataSet/BaseData_nvd.json")
DEFAULT_REPO_ROOT = Path("repo")
DEFAULT_OUT = Path("tests/step1_step2_joint_validation")


def _load_json(path: Path) -> Any:
  return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, obj: Any) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  with path.open("w", encoding="utf-8") as f:
    for row in rows:
      f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def _flatten_commits(record: dict[str, Any]) -> list[str]:
  out: list[str] = []
  for family in record.get("fixing_commits") or []:
    if isinstance(family, list):
      out.extend(str(x) for x in family)
    elif family:
      out.append(str(family))
  return out


def _percent(n: int, d: int) -> float:
  return round(n / d, 6) if d else 0.0


def _report_md(summary: dict[str, Any], per_repo: dict[str, Any]) -> str:
  lines = [
    "# Step1 -> Step2 Joint Validation",
    "",
    "This simulator validates the Step1 artifact adapter used by Step2.",
    "It does not claim Step3 probe reduction until the Step3 scheduler consumes RootCauseVet.",
    "",
    "## Summary",
    "",
    f"- total_cves: {summary['total_cves']}",
    f"- completed_cves: {summary['completed_cves']}",
    f"- failed_cves: {summary['failed_cves']}",
    f"- cves_with_priority_patterns: {summary['cves_with_priority_patterns']}",
    f"- total_priority_patterns: {summary['total_priority_patterns']}",
    f"- total_certificate_candidates: {summary['total_certificate_candidates']}",
    f"- wrong_certificate_risk_from_adapter: {summary['wrong_certificate_risk_from_adapter']}",
    f"- stage3_probe_reduction_measured: {summary['stage3_probe_reduction_measured']}",
    "",
    "## Per Repo",
    "",
    "| repo | cves | failures | avg priority patterns | certificate candidates |",
    "| --- | ---: | ---: | ---: | ---: |",
  ]
  for repo, row in sorted(per_repo.items()):
    lines.append(
      f"| {repo} | {row['cves']} | {row['failures']} | {row['avg_priority_patterns']} | {row['certificate_candidates']} |"
    )
  lines.append("")
  return "\n".join(lines)


def run_joint_validation(
  *,
  dataset_path: str | Path = DEFAULT_DATASET,
  nvd_path: str | Path = DEFAULT_NVD,
  repo_root: str | Path = DEFAULT_REPO_ROOT,
  out_dir: str | Path = DEFAULT_OUT,
  sample_size: int | None = None,
) -> dict[str, Any]:
  dataset_path = Path(dataset_path)
  nvd_path = Path(nvd_path)
  repo_root = Path(repo_root)
  out_dir = Path(out_dir)
  dataset = _load_json(dataset_path)
  nvd = _load_json(nvd_path) if nvd_path.exists() else {}
  items = list(dataset.items())
  if sample_size is not None and sample_size > 0:
    items = items[:sample_size]

  work_root = out_dir / "work"
  rows: list[dict[str, Any]] = []
  failures: list[dict[str, Any]] = []
  per_repo_acc: dict[str, dict[str, Any]] = defaultdict(lambda: {
    "cves": 0,
    "failures": 0,
    "priority_patterns": 0,
    "certificate_candidates": 0,
  })
  pattern_counts: Counter[str] = Counter()
  total_priority = 0
  total_certificates = 0
  cves_with_priority = 0

  for cve_id, record in items:
    repo = str(record.get("repo") or "")
    per_repo_acc[repo]["cves"] += 1
    row: dict[str, Any] = {
      "cve_id": cve_id,
      "repo": repo,
      "status": "unknown",
      "priority_patterns": 0,
      "certificate_candidates": 0,
      "pattern_counts": {},
    }
    try:
      commits = _flatten_commits(record)
      if not commits:
        raise ValueError("missing_fixing_commits")
      repo_path = repo_root / repo
      if not repo_path.exists():
        raise FileNotFoundError(f"repo_not_found:{repo_path}")
      nvd_record = nvd.get(cve_id) if isinstance(nvd, dict) else None
      result = run_step1_deterministic_extractor(
        result_root=work_root,
        repo_name=repo,
        cve_id=cve_id,
        repo_path=str(repo_path),
        fixing_commits=commits,
        cve_description=str((nvd_record or {}).get("description") or ""),
        cwe=list(record.get("CWE") or []),
        nvd_record=nvd_record,
        dataset_record=record,
        mode="deterministic_only",
      )
      seed = load_step1_vet_seed(Path(result["output_dir"]).parent)
      vet = build_root_cause_vet_from_step1(seed)
      counts = {
        "root_cause_files": len(vet.root_cause_files),
        "root_cause_functions": len(vet.root_cause_functions),
        "vulnerable_sequences": len(vet.vulnerable_sequences),
        "fix_guards": len(vet.fix_guards),
      }
      priority = len(vet.priority_patterns())
      certificates = len(vet.certificate_candidates())
      row.update({
        "status": "completed",
        "priority_patterns": priority,
        "certificate_candidates": certificates,
        "pattern_counts": counts,
      })
      total_priority += priority
      total_certificates += certificates
      if priority:
        cves_with_priority += 1
      for kind, count in counts.items():
        pattern_counts[kind] += count
      per_repo_acc[repo]["priority_patterns"] += priority
      per_repo_acc[repo]["certificate_candidates"] += certificates
    except Exception as exc:
      row.update({"status": "failed", "error": f"{type(exc).__name__}: {exc}"})
      failures.append(row.copy())
      per_repo_acc[repo]["failures"] += 1
    rows.append(row)

  per_repo: dict[str, Any] = {}
  for repo, acc in per_repo_acc.items():
    completed = acc["cves"] - acc["failures"]
    per_repo[repo] = {
      **acc,
      "avg_priority_patterns": round(acc["priority_patterns"] / completed, 3) if completed else 0.0,
    }

  completed_total = len(items) - len(failures)
  summary: dict[str, Any] = {
    "dataset": str(dataset_path),
    "nvd": str(nvd_path),
    "repo_root": str(repo_root),
    "total_cves": len(items),
    "completed_cves": completed_total,
    "failed_cves": len(failures),
    "cves_with_priority_patterns": cves_with_priority,
    "priority_pattern_coverage": _percent(cves_with_priority, completed_total),
    "total_priority_patterns": total_priority,
    "avg_priority_patterns_per_cve": round(total_priority / completed_total, 3) if completed_total else 0.0,
    "pattern_counts": dict(sorted(pattern_counts.items())),
    "total_certificate_candidates": total_certificates,
    "wrong_certificate_risk_from_adapter": total_certificates,
    "stage3_probe_reduction_measured": False,
    "stage3_probe_reduction_status": "not_measured_until_step3_scheduler_consumes_root_cause_vet",
  }

  _write_json(out_dir / "summary.json", summary)
  _write_json(out_dir / "per_repo.json", per_repo)
  _write_jsonl(out_dir / "per_cve.jsonl", rows)
  _write_json(out_dir / "failure_cases.json", failures)
  (out_dir / "report.md").write_text(_report_md(summary, per_repo), encoding="utf-8")
  return summary


def main() -> None:
  parser = argparse.ArgumentParser()
  parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
  parser.add_argument("--nvd", default=str(DEFAULT_NVD))
  parser.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
  parser.add_argument("--out", default=str(DEFAULT_OUT))
  parser.add_argument("--sample-size", type=int, default=None)
  args = parser.parse_args()
  summary = run_joint_validation(
    dataset_path=args.dataset,
    nvd_path=args.nvd,
    repo_root=args.repo_root,
    out_dir=args.out,
    sample_size=args.sample_size,
  )
  print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
  main()

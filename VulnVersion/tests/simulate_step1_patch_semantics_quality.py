from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnversion.stage1_semantic_aggregation.deterministic import run_step1_deterministic_extractor
from vulnversion.stage1_semantic_aggregation.schema import Step1QualityReport


DEFAULT_DATASET = Path("DataSet/BaseDataOrder.json")
DEFAULT_NVD = Path("DataSet/BaseData_nvd.json")
DEFAULT_REPO_ROOT = Path("repo")
DEFAULT_OUT = Path("tests/step1_patch_semantics_quality")
LARGE_PATCH_CHUNK_THRESHOLD = 20


def _load_json(path: Path) -> Any:
  return json.loads(path.read_text(encoding="utf-8"))


def _flatten_commits(record: dict[str, Any]) -> list[str]:
  out: list[str] = []
  for family in record.get("fixing_commits") or []:
    if isinstance(family, list):
      out.extend(str(x) for x in family)
    elif family:
      out.append(str(family))
  return out


def _write_json(path: Path, obj: Any) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  with path.open("w", encoding="utf-8") as f:
    for row in rows:
      f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def _percent(n: int, d: int) -> float:
  return round((n / d) if d else 0.0, 6)


def _report_md(summary: dict[str, Any], per_repo: dict[str, Any]) -> str:
  lines = [
    "# Step1 Patch Semantics Quality Simulator",
    "",
    "## Summary",
    "",
    f"- total_cves: {summary['total_cves']}",
    f"- completed_cves: {summary['completed_cves']}",
    f"- failed_cves: {summary['failed_cves']}",
    f"- total_chunks: {summary['total_chunks']}",
    f"- total_regions: {summary['total_regions']}",
    f"- global_compression_ratio: {summary['global_compression_ratio']}",
    f"- function_context_missing_chunks: {summary['function_context_missing_chunks']}",
    f"- large_patch_cves: {summary['large_patch_cves']}",
    "",
    "## Per Repo",
    "",
    "| repo | cves | chunks | regions | compression | failures |",
    "| --- | ---: | ---: | ---: | ---: | ---: |",
  ]
  for repo, row in sorted(per_repo.items()):
    lines.append(
      f"| {repo} | {row['cves']} | {row['chunks']} | {row['regions']} | {row['compression_ratio']} | {row['failures']} |"
    )
  lines.append("")
  return "\n".join(lines)


def run_simulation(
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
  per_cve_rows: list[dict[str, Any]] = []
  failure_cases: list[dict[str, Any]] = []
  large_patch_cases: list[dict[str, Any]] = []
  function_missing_cases: list[dict[str, Any]] = []
  patch_type_counts: Counter[str] = Counter()
  per_repo_acc: dict[str, dict[str, Any]] = defaultdict(lambda: {
    "cves": 0,
    "completed": 0,
    "failures": 0,
    "chunks": 0,
    "regions": 0,
    "function_context_missing_chunks": 0,
  })

  total_chunks = 0
  total_regions = 0
  function_missing = 0
  hard_deletion_count = 0

  for cve_id, record in items:
    repo = str(record.get("repo") or "")
    per_repo_acc[repo]["cves"] += 1
    commits = _flatten_commits(record)
    repo_path = repo_root / repo
    nvd_record = nvd.get(cve_id) if isinstance(nvd, dict) else None
    cve_desc = str((nvd_record or {}).get("description") or "")
    row: dict[str, Any] = {
      "cve_id": cve_id,
      "repo": repo,
      "status": "unknown",
      "chunks": 0,
      "regions": 0,
      "compression_ratio": None,
      "function_context_missing_chunks": 0,
      "risk_flags": [],
    }
    try:
      if not commits:
        raise ValueError("missing_fixing_commits")
      if not repo_path.exists():
        raise FileNotFoundError(f"repo_not_found:{repo_path}")
      result = run_step1_deterministic_extractor(
        result_root=work_root,
        repo_name=repo,
        cve_id=cve_id,
        repo_path=str(repo_path),
        fixing_commits=commits,
        cve_description=cve_desc,
        cwe=list(record.get("CWE") or []),
        nvd_record=nvd_record,
        dataset_record=record,
        mode="deterministic_only",
      )
      report_path = Path(result["quality_report"])
      report = Step1QualityReport.model_validate(_load_json(report_path))
      chunk_rows = [
        json.loads(line)
        for line in Path(result["chunk_semantics"]).read_text(encoding="utf-8").splitlines()
        if line.strip()
      ]
      for chunk in chunk_rows:
        patch_type_counts.update([str(chunk.get("patch_type") or "unknown")])
      missing_count = sum(1 for chunk in chunk_rows if "function_context_missing" in (chunk.get("risk_flags") or []))
      row.update({
        "status": "completed",
        "chunks": report.patch_chunk_count,
        "regions": report.semantic_region_count,
        "compression_ratio": report.compression_ratio,
        "function_context_missing_chunks": missing_count,
        "risk_flags": report.risk_flags,
      })
      total_chunks += report.patch_chunk_count
      total_regions += report.semantic_region_count
      function_missing += missing_count
      hard_deletion_count += report.hard_deletion_count
      per_repo_acc[repo]["completed"] += 1
      per_repo_acc[repo]["chunks"] += report.patch_chunk_count
      per_repo_acc[repo]["regions"] += report.semantic_region_count
      per_repo_acc[repo]["function_context_missing_chunks"] += missing_count
      if report.patch_chunk_count >= LARGE_PATCH_CHUNK_THRESHOLD:
        large_patch_cases.append(row.copy())
      if missing_count:
        function_missing_cases.append(row.copy())
    except Exception as exc:
      row.update({"status": "failed", "error": f"{type(exc).__name__}: {exc}"})
      failure_cases.append(row.copy())
      per_repo_acc[repo]["failures"] += 1
    per_cve_rows.append(row)

  per_repo: dict[str, Any] = {}
  for repo, acc in per_repo_acc.items():
    per_repo[repo] = {
      **acc,
      "compression_ratio": _percent(acc["regions"], acc["chunks"]),
      "function_context_missing_ratio": _percent(acc["function_context_missing_chunks"], acc["chunks"]),
    }

  completed = sum(1 for row in per_cve_rows if row["status"] == "completed")
  summary: dict[str, Any] = {
    "dataset": str(dataset_path),
    "nvd": str(nvd_path),
    "repo_root": str(repo_root),
    "total_cves": len(items),
    "completed_cves": completed,
    "failed_cves": len(failure_cases),
    "total_chunks": total_chunks,
    "total_regions": total_regions,
    "global_compression_ratio": _percent(total_regions, total_chunks),
    "function_context_missing_chunks": function_missing,
    "function_context_missing_ratio": _percent(function_missing, total_chunks),
    "hard_deletion_count": hard_deletion_count,
    "large_patch_threshold_chunks": LARGE_PATCH_CHUNK_THRESHOLD,
    "large_patch_cves": len(large_patch_cases),
    "patch_type_counts": dict(sorted(patch_type_counts.items())),
  }

  _write_json(out_dir / "summary.json", summary)
  _write_json(out_dir / "per_repo.json", per_repo)
  _write_jsonl(out_dir / "per_cve.jsonl", per_cve_rows)
  _write_json(out_dir / "failure_cases.json", failure_cases)
  _write_json(out_dir / "large_patch_cases.json", large_patch_cases)
  _write_json(out_dir / "function_context_missing_cases.json", function_missing_cases)
  (out_dir / "report.md").write_text(_report_md(summary, per_repo), encoding="utf-8")
  return summary


def main() -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
  parser.add_argument("--nvd", default=str(DEFAULT_NVD))
  parser.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
  parser.add_argument("--out", default=str(DEFAULT_OUT))
  parser.add_argument("--sample-size", type=int, default=None)
  args = parser.parse_args()
  summary = run_simulation(
    dataset_path=args.dataset,
    nvd_path=args.nvd,
    repo_root=args.repo_root,
    out_dir=args.out,
    sample_size=args.sample_size,
  )
  print(json.dumps(summary, ensure_ascii=False, indent=2))
  return 0 if summary["failed_cves"] == 0 else 1


if __name__ == "__main__":
  raise SystemExit(main())

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnversion.agent_harness.runtimes.opencode_runtime import OpenCodeRuntime
from vulnversion.config import Config
from vulnversion.stage1_semantic_aggregation.agent_refine_regions import refine_regions_with_agent
from vulnversion.stage1_semantic_aggregation.deterministic import run_step1_deterministic_extractor


DEFAULT_DATASET = Path("DataSet/BaseDataOrder.json")
DEFAULT_NVD = Path("DataSet/BaseData_nvd.json")
DEFAULT_REPO_ROOT = Path("repo")
DEFAULT_OUT = Path("tests/step1_p4_opencode_validation")
DEFAULT_CVES = [
  "CVE-2022-3965",   # FFmpeg, known small deterministic smoke case
  "CVE-2020-8169",   # curl
  "CVE-2020-15389",  # openjpeg
]


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


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
  if not path.exists():
    return []
  text = path.read_text(encoding="utf-8").strip()
  if not text:
    return []
  return [json.loads(line) for line in text.splitlines() if line.strip()]


def _flatten_commits(record: dict[str, Any]) -> list[str]:
  out: list[str] = []
  for family in record.get("fixing_commits") or []:
    if isinstance(family, list):
      out.extend(str(x) for x in family)
    elif family:
      out.append(str(family))
  return out


def _select_cases(dataset: dict[str, Any], cves: list[str] | None, max_cves: int | None) -> list[str]:
  if cves:
    return [cve for cve in cves if cve in dataset]
  selected = [cve for cve in DEFAULT_CVES if cve in dataset]
  if max_cves is not None and max_cves > 0:
    return selected[:max_cves]
  return selected


def _report_md(summary: dict[str, Any], rows: list[dict[str, Any]]) -> str:
  lines = [
    "# Step1 P4 OpenCode Real Validation",
    "",
    "This validates Step1 region refinement against the real OpenCode backend.",
    "It does not evaluate affected-version accuracy or Step3 probe reduction.",
    "",
    "## Summary",
    "",
    f"- total_cves: {summary['total_cves']}",
    f"- completed_cves: {summary['completed_cves']}",
    f"- failed_cves: {summary['failed_cves']}",
    f"- agent_success_cves: {summary['agent_success_cves']}",
    f"- agent_failed_cves: {summary['agent_failed_cves']}",
    f"- avg_latency_s: {summary['avg_latency_s']}",
    f"- avg_regions: {summary['avg_regions']}",
    "",
    "## Per CVE",
    "",
    "| repo | cve | status | regions | latency_s | unknown_agent_failed | roles |",
    "| --- | --- | --- | ---: | ---: | ---: | --- |",
  ]
  for row in rows:
    lines.append(
      f"| {row.get('repo')} | {row.get('cve_id')} | {row.get('status')} | "
      f"{row.get('regions', 0)} | {row.get('latency_s', 0)} | "
      f"{row.get('unknown_agent_failed_count', 0)} | {row.get('region_role_counts', {})} |"
    )
  lines.append("")
  return "\n".join(lines)


def run_validation(
  *,
  dataset_path: str | Path = DEFAULT_DATASET,
  nvd_path: str | Path = DEFAULT_NVD,
  repo_root: str | Path = DEFAULT_REPO_ROOT,
  out_dir: str | Path = DEFAULT_OUT,
  cves: list[str] | None = None,
  max_cves: int | None = None,
  timeout_s: float = 900.0,
  resume: bool = True,
  enable_git_tools: bool = False,
) -> dict[str, Any]:
  dataset_path = Path(dataset_path)
  nvd_path = Path(nvd_path)
  repo_root = Path(repo_root)
  out_dir = Path(out_dir)
  dataset = _load_json(dataset_path)
  nvd = _load_json(nvd_path) if nvd_path.exists() else {}
  selected_cves = _select_cases(dataset, cves, max_cves)

  cfg = Config()
  agent = OpenCodeRuntime.from_config(cfg, timeout_s=timeout_s, health_check=True, project_root=Path.cwd())
  diagnostics = agent.diagnostics()
  _write_json(out_dir / "opencode_diagnostics.json", diagnostics)

  work_root = out_dir / "work"
  rows: list[dict[str, Any]] = []
  failures: list[dict[str, Any]] = []
  role_total: Counter[str] = Counter()
  repo_acc: dict[str, dict[str, Any]] = defaultdict(lambda: {
    "cves": 0,
    "completed": 0,
    "failed": 0,
    "agent_failed": 0,
    "latency_s": 0.0,
    "regions": 0,
  })

  for cve_id in selected_cves:
    record = dataset[cve_id]
    repo = str(record.get("repo") or "")
    repo_acc[repo]["cves"] += 1
    row: dict[str, Any] = {"cve_id": cve_id, "repo": repo, "status": "unknown"}
    started = time.monotonic()
    try:
      commits = _flatten_commits(record)
      if not commits:
        raise ValueError("missing_fixing_commits")
      repo_path = repo_root / repo
      if not repo_path.exists():
        raise FileNotFoundError(f"repo_not_found:{repo_path}")
      nvd_record = nvd.get(cve_id) if isinstance(nvd, dict) else None
      cve_context = {
        "description": str((nvd_record or {}).get("description") or ""),
        "cwe": list(record.get("CWE") or []),
        "cvss2": (nvd_record or {}).get("cvss2") if isinstance(nvd_record, dict) else None,
        "cvss3": (nvd_record or {}).get("cvss3") if isinstance(nvd_record, dict) else None,
        "cvss4": (nvd_record or {}).get("cvss4") if isinstance(nvd_record, dict) else None,
      }
      det = run_step1_deterministic_extractor(
        result_root=work_root,
        repo_name=repo,
        cve_id=cve_id,
        repo_path=str(repo_path),
        fixing_commits=commits,
        cve_description=cve_context["description"],
        cwe=cve_context["cwe"],
        nvd_record=nvd_record,
        dataset_record=record,
        mode="agent_refined",
      )
      refine_regions_with_agent(
        result_root=work_root,
        repo=repo,
        cve_id=cve_id,
        cve_context=cve_context,
        agent=agent,
        resume=resume,
        timeout_s=timeout_s,
        enable_git_tools=enable_git_tools,
      )
      refinements_path = Path(det["output_dir"]) / "region_refinements.jsonl"
      refinements = _read_jsonl(refinements_path)
      roles = Counter(str(row.get("region_role") or "unknown_region") for row in refinements)
      unknown_failed = int(roles.get("unknown_agent_failed", 0))
      latency = round(time.monotonic() - started, 3)
      row.update({
        "status": "completed",
        "regions": len(refinements),
        "latency_s": latency,
        "unknown_agent_failed_count": unknown_failed,
        "agent_success": unknown_failed == 0 and bool(refinements),
        "region_role_counts": dict(sorted(roles.items())),
        "output_dir": str(Path(det["output_dir"])),
      })
      role_total.update(roles)
      repo_acc[repo]["completed"] += 1
      repo_acc[repo]["latency_s"] += latency
      repo_acc[repo]["regions"] += len(refinements)
      if unknown_failed:
        repo_acc[repo]["agent_failed"] += 1
    except Exception as exc:
      latency = round(time.monotonic() - started, 3)
      row.update({
        "status": "failed",
        "latency_s": latency,
        "error": f"{type(exc).__name__}: {exc}",
      })
      failures.append(row.copy())
      repo_acc[repo]["failed"] += 1
    rows.append(row)

  completed = [row for row in rows if row.get("status") == "completed"]
  success = [row for row in completed if row.get("agent_success")]
  agent_failed = [row for row in completed if row.get("unknown_agent_failed_count", 0)]
  summary: dict[str, Any] = {
    "dataset": str(dataset_path),
    "nvd": str(nvd_path),
    "repo_root": str(repo_root),
    "out_dir": str(out_dir),
    "selected_cves": selected_cves,
    "total_cves": len(selected_cves),
    "completed_cves": len(completed),
    "failed_cves": len(failures),
    "agent_success_cves": len(success),
    "agent_failed_cves": len(agent_failed),
    "avg_latency_s": round(sum(float(row.get("latency_s") or 0.0) for row in rows) / len(rows), 3) if rows else 0.0,
    "avg_regions": round(sum(int(row.get("regions") or 0) for row in completed) / len(completed), 3) if completed else 0.0,
    "region_role_counts": dict(sorted(role_total.items())),
    "timeout_s": timeout_s,
    "resume": resume,
    "enable_git_tools": enable_git_tools,
    "opencode": {
      "health": diagnostics.get("health"),
      "provider_id": diagnostics.get("provider_id"),
      "model_id": diagnostics.get("model_id"),
      "agent_name": diagnostics.get("agent_name"),
    },
  }
  per_repo: dict[str, Any] = {}
  for repo, acc in repo_acc.items():
    completed_n = int(acc["completed"])
    per_repo[repo] = {
      **acc,
      "avg_latency_s": round(acc["latency_s"] / completed_n, 3) if completed_n else 0.0,
      "avg_regions": round(acc["regions"] / completed_n, 3) if completed_n else 0.0,
    }

  _write_json(out_dir / "summary.json", summary)
  _write_json(out_dir / "per_repo.json", per_repo)
  _write_jsonl(out_dir / "per_cve.jsonl", rows)
  _write_json(out_dir / "failure_cases.json", failures)
  (out_dir / "report.md").write_text(_report_md(summary, rows), encoding="utf-8")
  return summary


def main() -> None:
  parser = argparse.ArgumentParser()
  parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
  parser.add_argument("--nvd", default=str(DEFAULT_NVD))
  parser.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
  parser.add_argument("--out", default=str(DEFAULT_OUT))
  parser.add_argument("--cves", default="", help="Comma-separated CVE IDs. Defaults to a fixed 3-CVE smoke sample.")
  parser.add_argument("--max-cves", type=int, default=None)
  parser.add_argument("--timeout-s", type=float, default=900.0)
  parser.add_argument("--no-resume", action="store_true")
  parser.add_argument("--enable-git-tools", action="store_true")
  args = parser.parse_args()
  cves = [x.strip() for x in args.cves.split(",") if x.strip()] if args.cves.strip() else None
  summary = run_validation(
    dataset_path=args.dataset,
    nvd_path=args.nvd,
    repo_root=args.repo_root,
    out_dir=args.out,
    cves=cves,
    max_cves=args.max_cves,
    timeout_s=args.timeout_s,
    resume=not args.no_resume,
    enable_git_tools=args.enable_git_tools,
  )
  print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
  main()

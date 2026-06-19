from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulngraph.workflows.affected_version_converter_v1 import discover_boundary_cves, run_affected_version_converter_v1


DEFAULT_BOUNDARY_RUN = Path("runs/batches/vulngraph-judge-boundary-v1-dev30")
DEFAULT_DATASET = Path(r"E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json")
DEFAULT_REPO_ROOT = Path(r"E:\AI\Agent\workflow\VulnVersion\repo")


def main() -> None:
  parser = argparse.ArgumentParser(description="Run deterministic affected-version converter v1.")
  parser.add_argument("--boundary-run", type=Path, default=DEFAULT_BOUNDARY_RUN)
  parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
  parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
  parser.add_argument("--out-dir", type=Path, required=True)
  parser.add_argument("--cves", nargs="+")
  parser.add_argument("--reset", action="store_true")
  args = parser.parse_args()
  cves = _parse_cves(args.cves) if args.cves else discover_boundary_cves(args.boundary_run)
  summary = run_affected_version_converter_v1(
    cve_ids=cves,
    boundary_run=args.boundary_run,
    dataset=args.dataset,
    repo_root=args.repo_root,
    out_dir=args.out_dir,
    reset=args.reset,
  )
  print(json.dumps(summary, ensure_ascii=False, indent=2))


def _parse_cves(values: list[str] | None) -> list[str]:
  output: list[str] = []
  for value in values or []:
    output.extend(item.strip() for item in value.split(",") if item.strip())
  return output


if __name__ == "__main__":
  main()

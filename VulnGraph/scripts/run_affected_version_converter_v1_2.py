from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulngraph.workflows.affected_version_converter_v1_2 import run_affected_version_converter_v1_2


def main() -> None:
  parser = argparse.ArgumentParser(description="Run branch-scoped deterministic affected-version converter v1.2.")
  parser.add_argument("--boundary-run", type=Path, required=True)
  parser.add_argument("--dataset", type=Path, default=Path(r"E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json"))
  parser.add_argument("--repo-root", type=Path, default=Path(r"E:\AI\Agent\workflow\VulnVersion\repo"))
  parser.add_argument("--out-dir", type=Path, required=True)
  parser.add_argument("--cves", nargs="+")
  parser.add_argument("--reset", action="store_true")
  args = parser.parse_args()
  cves = args.cves or sorted(path.name for path in args.boundary_run.glob("CVE-*") if (path / "judge_boundary_result_v1_2.json").exists())
  summary = run_affected_version_converter_v1_2(
    cve_ids=cves, boundary_run=args.boundary_run, dataset=args.dataset,
    repo_root=args.repo_root, out_dir=args.out_dir, reset=args.reset,
  )
  print(json.dumps(summary, indent=2))


if __name__ == "__main__":
  main()

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from vulngraph.workflows.szz_anchor_version_probe import run_szz_anchor_version_probe


DEFAULT_ANCHOR_RUN = Path("runs/batches/root-cause-v2-szz-anchor-audit-engineering-deepseek-10-final")
DEFAULT_DATASET = Path(r"E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json")
DEFAULT_REPO_ROOT = Path(r"E:\AI\Agent\workflow\VulnVersion\repo")


def main() -> None:
  parser = argparse.ArgumentParser(
    description="Run a diagnostic upper-bound affected-version probe over SZZ anchor raw candidates."
  )
  parser.add_argument("--anchor-run", "--anchor-audit-run", dest="anchor_run", type=Path, default=DEFAULT_ANCHOR_RUN)
  parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
  parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
  parser.add_argument("--out-dir", type=Path, required=True)
  parser.add_argument("--reset", action="store_true")
  args = parser.parse_args()

  if args.reset and args.out_dir.exists():
    shutil.rmtree(args.out_dir)
  args.out_dir.mkdir(parents=True, exist_ok=True)

  summary = run_szz_anchor_version_probe(
    anchor_run=args.anchor_run,
    dataset=args.dataset,
    repo_root=args.repo_root,
    out_dir=args.out_dir,
  )
  summary["command"] = " ".join(["run_szz_anchor_version_probe.py", *args_to_strings()])
  (args.out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
  print(json.dumps(summary, ensure_ascii=False, indent=2))


def args_to_strings() -> list[str]:
  import sys

  return sys.argv[1:]


if __name__ == "__main__":
  main()

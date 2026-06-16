from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from vulngraph.workflows.szz_release_line_conversion_probe import run_release_line_conversion_probe


DEFAULT_ANCHOR_RUN = Path("runs/batches/root-cause-v2-szz-anchor-audit-engineering-deepseek-10-final")
DEFAULT_VERSION_RUN = Path("runs/batches/root-cause-v2-szz-anchor-version-probe-v2-release-filter-fix-10")
DEFAULT_DATASET = Path(r"E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json")
DEFAULT_REPO_ROOT = Path(r"E:\AI\Agent\workflow\VulnVersion\repo")
DEFAULT_CVES = ["CVE-2022-0171", "CVE-2020-11869", "CVE-2020-13164"]


def main() -> None:
  parser = argparse.ArgumentParser(description="Run deterministic release-line conversion diagnostics over raw candidates.")
  parser.add_argument("--anchor-audit-run", type=Path, default=DEFAULT_ANCHOR_RUN)
  parser.add_argument("--version-probe-run", type=Path, default=DEFAULT_VERSION_RUN)
  parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
  parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
  parser.add_argument("--out-dir", type=Path, required=True)
  parser.add_argument("--cves", nargs="+", default=DEFAULT_CVES)
  parser.add_argument("--reset", action="store_true")
  args = parser.parse_args()

  if args.reset and args.out_dir.exists():
    shutil.rmtree(args.out_dir)
  args.out_dir.mkdir(parents=True, exist_ok=True)

  summary = run_release_line_conversion_probe(
    anchor_audit_run=args.anchor_audit_run,
    version_probe_run=args.version_probe_run,
    dataset=args.dataset,
    repo_root=args.repo_root,
    out_dir=args.out_dir,
    cve_ids=list(args.cves),
  )
  summary["command"] = " ".join(["run_szz_release_line_conversion_probe.py", *args_to_strings()])
  (args.out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
  print(json.dumps(summary, ensure_ascii=False, indent=2))


def args_to_strings() -> list[str]:
  import sys

  return sys.argv[1:]


if __name__ == "__main__":
  main()

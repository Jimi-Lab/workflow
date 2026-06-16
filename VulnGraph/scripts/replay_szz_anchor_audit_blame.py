from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from vulngraph.workflows.szz_anchor_audit import replay_szz_anchor_audit


DEFAULT_PREVIOUS_RUN = Path("runs/batches/root-cause-v2-szz-anchor-audit-engineering-deepseek-10")
DEFAULT_ROOT_CAUSE_RUN = Path("runs/batches/root-cause-v2-optimized-contract-10")
DEFAULT_DATASET = Path(r"E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json")
DEFAULT_REPO_ROOT = Path(r"E:\AI\Agent\workflow\VulnVersion\repo")


def main() -> None:
  parser = argparse.ArgumentParser(
    description="Replay existing SZZ handoff artifacts through local contract/resolve/blame only."
  )
  parser.add_argument("--previous-run", type=Path, default=DEFAULT_PREVIOUS_RUN)
  parser.add_argument("--root-cause-run", type=Path, default=DEFAULT_ROOT_CAUSE_RUN)
  parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
  parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
  parser.add_argument("--out-dir", type=Path, required=True)
  parser.add_argument("--cves", nargs="+", required=True)
  parser.add_argument("--top-k-per-patch-family", type=int, default=40)
  parser.add_argument("--reset", action="store_true")
  args = parser.parse_args()

  cve_ids = _parse_cves(args.cves)
  if args.reset and args.out_dir.exists():
    shutil.rmtree(args.out_dir)
  args.out_dir.mkdir(parents=True, exist_ok=True)

  summary = replay_szz_anchor_audit(
    cve_ids,
    root_cause_run=args.root_cause_run,
    previous_run=args.previous_run,
    dataset=args.dataset,
    repo_root=args.repo_root,
    out_dir=args.out_dir,
    top_k_per_patch_family=args.top_k_per_patch_family,
  )
  summary["command"] = " ".join(["replay_szz_anchor_audit_blame.py", *args_to_strings()])
  (args.out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
  print(json.dumps(summary, ensure_ascii=False, indent=2))


def _parse_cves(values: list[str]) -> list[str]:
  output: list[str] = []
  for value in values:
    output.extend(item.strip() for item in value.split(",") if item.strip())
  return output


def args_to_strings() -> list[str]:
  import sys

  return sys.argv[1:]


if __name__ == "__main__":
  main()

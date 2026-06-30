from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulngraph.workflows.affected_version_converter_v1_2_1 import ranked_raw_top1_metrics
from vulngraph.workflows.affected_version_converter_v1_2_2 import (
  run_affected_version_converter_v1_2_2,
)


EXPECTED_RAW_TOP1_EXACT = 15
EXPECTED_RAW_TOP1_F1 = 0.7048723897911834


def main() -> None:
  parser = argparse.ArgumentParser(description="Run deterministic function-scope semantic-state reconstruction v1.2.2")
  parser.add_argument("--boundary-run", required=True)
  parser.add_argument("--dataset", required=True)
  parser.add_argument("--repo-root", required=True)
  parser.add_argument("--raw-top1-run", required=True)
  parser.add_argument("--out-dir", required=True)
  parser.add_argument("--cves", nargs="*")
  parser.add_argument("--reset", action="store_true")
  args = parser.parse_args()

  dataset = _read(Path(args.dataset))
  cve_ids = args.cves or list(dataset)
  raw_root = Path(args.raw_top1_run)
  raw_metrics = ranked_raw_top1_metrics(
    dataset,
    _read(raw_root / "ranking_diagnostics.json"),
    _read(raw_root / "per_candidate_probe.json"),
  )
  full_dev30 = len(cve_ids) == len(dataset) == 30 and set(cve_ids) == set(dataset)
  if full_dev30 and (
    raw_metrics["exact_match_count"] != EXPECTED_RAW_TOP1_EXACT
    or abs(raw_metrics["micro_f1"] - EXPECTED_RAW_TOP1_F1) > 1e-12
  ):
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    blocked = {
      "replay_started": False,
      "blocked_reason": "raw_top1_reproduction_gate_failed",
      "raw_top1_metrics": raw_metrics,
      "model_invocation_count": 0,
    }
    _write(out / "summary.json", blocked)
    _write(out / "raw_top1_reproduction.json", raw_metrics)
    print(json.dumps(blocked, indent=2))
    raise SystemExit(2)

  result = run_affected_version_converter_v1_2_2(
    cve_ids=cve_ids,
    boundary_run=args.boundary_run,
    dataset=args.dataset,
    repo_root=args.repo_root,
    out_dir=args.out_dir,
    reset=args.reset,
  )
  _write(Path(args.out_dir) / "raw_top1_reproduction.json", raw_metrics)
  print(json.dumps({**result, "raw_top1_metrics": raw_metrics}, indent=2))


def _read(path: Path) -> dict:
  return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, value: object) -> None:
  path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
  main()

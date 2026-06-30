from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulngraph.workflows.affected_version_converter_v1_2_1 import (
  audit_fix_universe_v1_2_1,
  ranked_raw_top1_metrics,
)


def main() -> None:
  parser = argparse.ArgumentParser(description="Audit v1.2.1 deterministic reconstruction stop gates")
  parser.add_argument("--boundary-run", required=True)
  parser.add_argument("--dataset", required=True)
  parser.add_argument("--repo-root", required=True)
  parser.add_argument("--raw-top1-run", required=True)
  parser.add_argument("--out-dir", required=True)
  parser.add_argument("--cves", nargs="*")
  args = parser.parse_args()

  dataset = _read(Path(args.dataset))
  cves = args.cves or list(dataset)
  fix_audit = audit_fix_universe_v1_2_1(cves, args.boundary_run, dataset, args.repo_root)
  raw_root = Path(args.raw_top1_run)
  raw_metrics = ranked_raw_top1_metrics(
    dataset, _read(raw_root / "ranking_diagnostics.json"), _read(raw_root / "per_candidate_probe.json"),
  )
  output = {
    "fix_universe_gate_ok": fix_audit["coverage"] == 1.0 and fix_audit["unresolved_declared_fix_count"] == 0,
    "raw_top1_gate_ok": raw_metrics["exact_match_count"] == 15 and abs(raw_metrics["micro_f1"] - 0.7048723897911834) <= 1e-12,
    "fix_universe_audit": fix_audit,
    "raw_top1_metrics": raw_metrics,
    "model_invocation_count": 0,
  }
  out = Path(args.out_dir)
  out.mkdir(parents=True, exist_ok=True)
  _write(out / "preflight_stop_gate_audit.json", output)
  print(json.dumps(output, indent=2))


def _read(path: Path) -> dict:
  return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, value: object) -> None:
  path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
  main()

from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulngraph.workflows.judge_boundary_consistency_audit import (
  write_boundary_consistency_audit,
)


def main() -> None:
  parser = argparse.ArgumentParser(description="Audit frozen Judge Boundary v1 duplicated views.")
  parser.add_argument("--run-root", type=Path, required=True)
  parser.add_argument("--output", type=Path, required=True)
  args = parser.parse_args()
  audit = write_boundary_consistency_audit(args.run_root, args.output)
  print(json.dumps(audit["summary"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
  main()

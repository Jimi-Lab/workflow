from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
  sys.path.insert(0, str(PROJECT_ROOT))

from vulnversion.self_evolve.memory_store import build_memory_store
from vulnversion.self_evolve.promotion_gate import apply_promotion_gates


def main() -> int:
  parser = argparse.ArgumentParser(description="Build offline memory candidates from an agent enhancement case pack.")
  parser.add_argument("--enhancement-id", required=True)
  parser.add_argument("--case-pack-root", default="Result_agent_enhance_cases")
  parser.add_argument("--out-root", default="Result_agent_enhance_memory")
  parser.add_argument("--apply-gates", action="store_true")
  args = parser.parse_args()

  summary = build_memory_store(
    case_pack_root=PROJECT_ROOT / args.case_pack_root,
    out_root=PROJECT_ROOT / args.out_root,
    enhancement_id=args.enhancement_id,
  )
  if args.apply_gates:
    gate_summary = apply_promotion_gates(
      memory_candidates_path=PROJECT_ROOT / args.out_root / args.enhancement_id / "memory_candidates.jsonl",
      case_pack_dir=PROJECT_ROOT / args.case_pack_root / args.enhancement_id,
      out_dir=PROJECT_ROOT / args.out_root / args.enhancement_id,
    )
    summary = {**summary, "gate_summary": gate_summary}
  print(json.dumps(summary, ensure_ascii=False, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

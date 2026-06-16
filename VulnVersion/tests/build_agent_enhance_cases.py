from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
  sys.path.insert(0, str(PROJECT_ROOT))

from vulnversion.self_evolve import build_case_pack


def main() -> int:
  parser = argparse.ArgumentParser(
    description="Build an offline agent enhancement case pack from existing VulnVersion results."
  )
  parser.add_argument("--result-root", default="Result", help="Existing VulnVersion result root.")
  parser.add_argument("--out-root", default="Result_agent_enhance_cases", help="Case-pack output root.")
  parser.add_argument("--enhancement-id", default="stage3_failure_attribution_v0")
  parser.add_argument("--limit", type=int, default=None, help="Optional max number of cases.")
  parser.add_argument(
    "--agent-only",
    action="store_true",
    help="Emit only cases attributable to direct agent judgement/runtime.",
  )
  args = parser.parse_args()

  manifest = build_case_pack(
    result_root=PROJECT_ROOT / args.result_root,
    out_root=PROJECT_ROOT / args.out_root,
    enhancement_id=args.enhancement_id,
    limit=args.limit,
    include_non_agent=not args.agent_only,
  )
  print(json.dumps(manifest.model_dump(), ensure_ascii=False, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

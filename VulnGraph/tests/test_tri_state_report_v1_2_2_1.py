from __future__ import annotations

import runpy
from pathlib import Path


def test_raw_top1_report_uses_count_field_names() -> None:
  script = Path(__file__).resolve().parents[1] / "scripts" / "run_tri_state_policy_audit_v1_2_2_1.py"
  module = runpy.run_path(str(script))
  report = module["_comparison_report"]({
    "raw_top1_diagnostic": {
      "case_count": 30,
      "exact_match_count": 15,
      "true_positive_count": 1519,
      "false_positive_count": 774,
      "false_negative_count": 498,
      "micro_precision": 0.6624509376362844,
      "micro_recall": 0.7530986613782846,
      "micro_f1": 0.7048723897911834,
    }
  })

  assert "| raw_top1_diagnostic | 0.500000 | n/a |" in report
  assert "| 1519 | 774 | 498 |" in report

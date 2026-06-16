"""Regression gate for the module-backed Step3 GT simulator output.

The expensive 1128-CVE run is produced by:
    python tests/simulate_module_backed_step3.py \
      --dataset DataSet/BaseDataOrder.json \
      --repo-root repo \
      --out-dir tests/module_backed_step3_simulator \
      --policies staged_nofix_stride3_file

This test verifies the committed/output artifact still matches the selected
cost-aware staged_nofix_stride3_file profile before verify_tags.py integration.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "tests" / "module_backed_step3_simulator"
SUMMARY_PATH = OUT_DIR / "summary.json"
MISMATCH_PATH = OUT_DIR / "mismatch_cases.json"


class TestModuleBackedStep3SimulatorArtifacts(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(
            SUMMARY_PATH.exists(),
            f"missing module-backed simulator summary: {SUMMARY_PATH}",
        )
        self.assertTrue(
            MISMATCH_PATH.exists(),
            f"missing module-backed simulator mismatch dump: {MISMATCH_PATH}",
        )
        self.summary = json.loads(SUMMARY_PATH.read_text(encoding="utf-8"))
        self.mismatches = json.loads(MISMATCH_PATH.read_text(encoding="utf-8"))

    def test_reference_diff_is_reported_not_hidden(self):
        self.assertEqual(self.summary["metadata"]["mismatch_count"], len(self.mismatches))
        self.assertEqual(self.summary["metadata"]["mismatch_count"], 244)
        self.assertFalse(self.summary["metadata"]["strict_reference_parity"])

    def test_staged_nofix_stride3_file_core_metrics(self):
        metadata = self.summary["metadata"]
        self.assertEqual(metadata["policies"], ["staged_nofix_stride3_file"])
        self.assertEqual(metadata["nn_sentinel_count"], 3)
        self.assertEqual(metadata["aa_sentinel_count"], 1)
        self.assertEqual(metadata["fixed_segment_sentinel"], 1)
        self.assertEqual(metadata["expansion_radius"], 1)

        metrics = self.summary["overall"]["staged_nofix_stride3_file"]
        self.assertEqual(metrics["cves"], 1128)
        self.assertEqual(metrics["exact_match_cves"], 1112)
        self.assertEqual(metrics["has_fn_cves"], 8)
        self.assertEqual(metrics["has_fp_cves"], 4)
        self.assertEqual(metrics["micro_f1"], 0.999822)
        self.assertEqual(metrics["probe_avg"], 68.34)


if __name__ == "__main__":
    unittest.main()

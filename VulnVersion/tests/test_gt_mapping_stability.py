"""Official BaseDataOrder GT mapping stability tests.

Current policy: all formal tests and runs use DataSet/BaseDataOrder.json.
This gate validates the official dataset itself and checks that its sorted
affected_version values map stably to actual release tags.
"""
from __future__ import annotations

from collections import Counter
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT / "repo"
OUT_DIR = ROOT / "tests" / "gt_mapping_stability"
OFFICIAL_DATASET = "BaseDataOrder.json"


def _load_official_dataset() -> dict:
    p = ROOT / "DataSet" / OFFICIAL_DATASET
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def _repos_available() -> bool:
    return REPO_ROOT.exists() and any(REPO_ROOT.iterdir())


class TestOfficialDatasetStructure(unittest.TestCase):
    def test_official_dataset_has_expected_size(self):
        ds = _load_official_dataset()
        if not ds:
            self.skipTest(f"{OFFICIAL_DATASET} not found")
        self.assertEqual(len(ds), 1128)

    def test_all_cves_have_repo_field(self):
        ds = _load_official_dataset()
        if not ds:
            self.skipTest(f"{OFFICIAL_DATASET} not found")
        missing = [cve for cve, rec in ds.items()
                   if not isinstance(rec, dict) or not rec.get("repo")]
        self.assertEqual(missing, [], f"CVEs missing repo: {missing[:5]}")

    def test_empty_affected_version_count_bounded(self):
        ds = _load_official_dataset()
        if not ds:
            self.skipTest(f"{OFFICIAL_DATASET} not found")
        empty = [cve for cve, rec in ds.items()
                 if isinstance(rec, dict) and not rec.get("affected_version")]
        self.assertLess(len(empty), 40, f"{len(empty)} CVEs have empty affected_version")

    def test_nine_target_repos_present(self):
        ds = _load_official_dataset()
        if not ds:
            self.skipTest(f"{OFFICIAL_DATASET} not found")
        by_repo = Counter(rec.get("repo") for rec in ds.values() if isinstance(rec, dict))
        expected = {"FFmpeg", "ImageMagick", "curl", "httpd", "linux",
                    "openjpeg", "openssl", "qemu", "wireshark"}
        self.assertEqual(set(by_repo.keys()), expected)
        self.assertEqual(sum(by_repo.values()), 1128)

    def test_sorted_affected_version_mapping_is_idempotent(self):
        try:
            from vulnversion.git_ops.repo import map_gt_tags_to_repo_tags
        except ImportError:
            self.skipTest("vulnversion not importable")
        ds = _load_official_dataset()
        if not ds:
            self.skipTest(f"{OFFICIAL_DATASET} not found")
        cve_id = "CVE-2021-4190"
        if cve_id not in ds:
            self.skipTest(f"{cve_id} not in dataset")
        mock_scanned = [
            "wireshark-3.4.6", "wireshark-3.4.9", "wireshark-3.4.11",
            "v3.4.6", "v3.4.9", "v3.4.11",
            "wireshark-3.2.16", "wireshark-3.2.17",
            "v3.2.16", "v3.2.17",
        ]
        affected = [str(t) for t in (ds[cve_id].get("affected_version") or [])]
        m_unsorted, _ = map_gt_tags_to_repo_tags(affected, mock_scanned, mode="loose")
        m_sorted, _ = map_gt_tags_to_repo_tags(sorted(affected), mock_scanned, mode="loose")
        self.assertEqual(sorted(m_unsorted), sorted(m_sorted))


class TestOfficialGTMappingStability(unittest.TestCase):
    """Use actual repo release tags to verify official GT mapping is stable."""

    @classmethod
    def setUpClass(cls):
        if not _repos_available():
            return
        try:
            from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
            from vulnversion.stage3_verify.version_registry import filter_release_tags
        except ImportError:
            return
        ds = _load_official_dataset()
        if not ds:
            return

        OUT_DIR.mkdir(parents=True, exist_ok=True)
        mismatch_cases = []
        total = 0
        match_count = 0
        empty_affected = 0

        for cve_id, rec in ds.items():
            repo_name = str(rec.get("repo") or "")
            repo_path = REPO_ROOT / repo_name
            if not repo_path.exists():
                continue
            affected = [str(t) for t in (rec.get("affected_version") or [])]
            if not affected:
                empty_affected += 1
                continue
            try:
                repo = GitRepo.open(str(repo_path))
                raw_tags = repo.list_tags(max_tags=None)
                release_tags = filter_release_tags(repo_name, raw_tags)
                m_unsorted, _ = map_gt_tags_to_repo_tags(affected, release_tags, mode="loose")
                m_sorted, _ = map_gt_tags_to_repo_tags(sorted(affected), release_tags, mode="loose")
                total += 1
                if sorted(m_unsorted) == sorted(m_sorted):
                    match_count += 1
                else:
                    mismatch_cases.append({
                        "cve_id": cve_id,
                        "repo": repo_name,
                        "mapped_unsorted": sorted(m_unsorted),
                        "mapped_sorted": sorted(m_sorted),
                        "diff_unsorted_extra": sorted(set(m_unsorted) - set(m_sorted)),
                        "diff_sorted_extra": sorted(set(m_sorted) - set(m_unsorted)),
                    })
            except Exception as e:
                mismatch_cases.append({
                    "cve_id": cve_id,
                    "repo": repo_name,
                    "error": str(e),
                })

        (OUT_DIR / "mismatch_cases.json").write_text(
            json.dumps(mismatch_cases, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (OUT_DIR / "summary.json").write_text(
            json.dumps({
                "dataset": f"DataSet/{OFFICIAL_DATASET}",
                "total_cves_checked": total,
                "empty_affected_version_cves": empty_affected,
                "match_count": match_count,
                "mismatch_count": len(mismatch_cases),
                "pass_rate": match_count / total if total else 0.0,
            }, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def setUp(self):
        if not _repos_available():
            self.skipTest("repo/ directory not available")
        if not _load_official_dataset():
            self.skipTest(f"{OFFICIAL_DATASET} not found")

    def test_mismatch_cases_json_written(self):
        p = OUT_DIR / "mismatch_cases.json"
        self.assertTrue(p.exists(), "mismatch_cases.json must always be written")
        cases = json.loads(p.read_text(encoding="utf-8"))
        self.assertIsInstance(cases, list)

    def test_pass_rate_above_99_percent(self):
        p = OUT_DIR / "summary.json"
        if not p.exists():
            self.skipTest("summary.json not generated (repos unavailable?)")
        s = json.loads(p.read_text(encoding="utf-8"))
        total = s.get("total_cves_checked", 0)
        if total == 0:
            self.skipTest("no CVEs could be checked")
        pass_rate = s.get("pass_rate", 0.0)
        self.assertGreaterEqual(
            pass_rate, 0.99,
            f"official GT mapping pass_rate={pass_rate:.4f} < 0.99 "
            f"({s.get('mismatch_count')} mismatches in {total} CVEs). "
            f"See {OUT_DIR / 'mismatch_cases.json'}"
        )

    def test_zero_mismatches_after_official_ordering(self):
        p = OUT_DIR / "mismatch_cases.json"
        if not p.exists():
            self.skipTest("mismatch_cases.json not generated")
        cases = [c for c in json.loads(p.read_text(encoding="utf-8")) if "error" not in c]
        self.assertEqual(cases, [], f"{len(cases)} CVEs mismatch. First 3: {cases[:3]}")

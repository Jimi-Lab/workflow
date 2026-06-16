import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from simulate_step1_step2_joint_validation import run_joint_validation


def test_step1_step2_joint_validation_writes_expected_reports(tmp_path: Path):
  project = Path(__file__).resolve().parents[1]
  out = tmp_path / "joint"
  summary = run_joint_validation(
    dataset_path=project / "DataSet" / "BaseDataOrder.json",
    nvd_path=project / "DataSet" / "BaseData_nvd.json",
    repo_root=project / "repo",
    out_dir=out,
    sample_size=3,
  )

  assert summary["total_cves"] == 3
  assert summary["completed_cves"] == 3
  assert summary["failed_cves"] == 0
  assert summary["cves_with_priority_patterns"] >= 1
  assert summary["total_certificate_candidates"] == 0
  assert summary["stage3_probe_reduction_measured"] is False
  assert (out / "summary.json").is_file()
  assert (out / "per_repo.json").is_file()
  assert (out / "per_cve.jsonl").is_file()
  assert (out / "failure_cases.json").is_file()
  assert (out / "report.md").is_file()
  rows = [json.loads(line) for line in (out / "per_cve.jsonl").read_text(encoding="utf-8").splitlines()]
  assert all(row["status"] == "completed" for row in rows)

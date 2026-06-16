import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from simulate_step1_patch_semantics_quality import run_simulation


def _git(repo: Path, *args: str) -> str:
  return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def _make_repo(tmp_path: Path) -> tuple[Path, str]:
  repo = tmp_path / "repo" / "demo"
  repo.mkdir(parents=True)
  _git(repo, "init")
  _git(repo, "config", "user.email", "test@example.com")
  _git(repo, "config", "user.name", "Test User")
  (repo / "file.c").write_text("int f(int x) {\n    return x + 1;\n}\n", encoding="utf-8")
  _git(repo, "add", "file.c")
  _git(repo, "commit", "-m", "initial")
  (repo / "file.c").write_text(
    "int f(int x) {\n    if (x < 0) return -1;\n    return x + 1;\n}\n",
    encoding="utf-8",
  )
  _git(repo, "add", "file.c")
  _git(repo, "commit", "-m", "CVE-SMOKE fix bounds")
  return repo.parent, _git(repo, "rev-parse", "HEAD")


def test_step1_quality_simulator_writes_summary_and_cases(tmp_path: Path):
  repo_root, commit = _make_repo(tmp_path)
  dataset_path = tmp_path / "BaseDataOrder.json"
  nvd_path = tmp_path / "BaseData_nvd.json"
  out_dir = tmp_path / "out"
  dataset_path.write_text(
    json.dumps(
      {
        "CVE-SMOKE": {
          "repo": "demo",
          "fixing_commits": [[commit]],
          "affected_version": [],
          "CWE": ["CWE-125"],
        }
      },
      ensure_ascii=False,
    ),
    encoding="utf-8",
  )
  nvd_path.write_text(
    json.dumps({"CVE-SMOKE": {"description": "bounds check", "cvss3": [{"score": "7.5 HIGH"}]}}, ensure_ascii=False),
    encoding="utf-8",
  )

  summary = run_simulation(
    dataset_path=dataset_path,
    nvd_path=nvd_path,
    repo_root=repo_root,
    out_dir=out_dir,
    sample_size=None,
  )

  assert summary["total_cves"] == 1
  assert summary["completed_cves"] == 1
  assert summary["failed_cves"] == 0
  assert summary["total_chunks"] == 1
  assert summary["total_regions"] == 1
  assert summary["hard_deletion_count"] == 0
  assert (out_dir / "summary.json").is_file()
  assert (out_dir / "per_repo.json").is_file()
  assert (out_dir / "per_cve.jsonl").is_file()
  assert (out_dir / "failure_cases.json").is_file()
  assert (out_dir / "large_patch_cases.json").is_file()
  assert (out_dir / "function_context_missing_cases.json").is_file()
  assert (out_dir / "report.md").is_file()

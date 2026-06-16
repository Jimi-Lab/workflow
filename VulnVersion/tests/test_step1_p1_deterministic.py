import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnversion.stage1_semantic_aggregation.deterministic import run_step1_deterministic_extractor
from vulnversion.stage1_semantic_aggregation.schema import ChunkSemantics, CommitSemantics, SemanticRegion, Step1QualityReport


def _git(repo: Path, *args: str) -> str:
  return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def _jsonl(path: Path) -> list[dict]:
  text = path.read_text(encoding="utf-8").strip()
  if not text:
    return []
  return [json.loads(line) for line in text.splitlines()]


def _make_repo(tmp_path: Path) -> tuple[Path, str]:
  repo = tmp_path / "repo"
  repo.mkdir()
  _git(repo, "init")
  _git(repo, "config", "user.email", "test@example.com")
  _git(repo, "config", "user.name", "Test User")
  (repo / "file.c").write_text(
    "\n".join(
      [
        "int parse_len(int len) {",
        "    int size = len + 1;",
        "    return size;",
        "}",
        "",
      ]
    ),
    encoding="utf-8",
  )
  _git(repo, "add", "file.c")
  _git(repo, "commit", "-m", "initial")
  (repo / "file.c").write_text(
    "\n".join(
      [
        "int parse_len(int len) {",
        "    if (len < 0) {",
        "        return -1;",
        "    }",
        "    int size = len + 1;",
        "    return size;",
        "}",
        "",
      ]
    ),
    encoding="utf-8",
  )
  _git(repo, "add", "file.c")
  _git(repo, "commit", "-m", "CVE-TEST add bounds check")
  return repo, _git(repo, "rev-parse", "HEAD")


def _make_mixed_repo(tmp_path: Path) -> tuple[Path, str]:
  repo = tmp_path / "repo_mixed"
  repo.mkdir()
  _git(repo, "init")
  _git(repo, "config", "user.email", "test@example.com")
  _git(repo, "config", "user.name", "Test User")
  (repo / "copy.c").write_text(
    "\n".join(
      [
        "#include <string.h>",
        "int copy_data(char *dst, int dst_len, char *src, int len) {",
        "    memcpy(dst, src, len);",
        "    return 0;",
        "}",
        "",
      ]
    ),
    encoding="utf-8",
  )
  _git(repo, "add", "copy.c")
  _git(repo, "commit", "-m", "initial")
  (repo / "copy.c").write_text(
    "\n".join(
      [
        "#include <string.h>",
        "int copy_data(char *dst, int dst_len, char *src, int len) {",
        "    if (len > dst_len) {",
        "        return -1;",
        "    }",
        "    memcpy(dst, src, dst_len);",
        "    return 0;",
        "}",
        "",
      ]
    ),
    encoding="utf-8",
  )
  _git(repo, "add", "copy.c")
  _git(repo, "commit", "-m", "CVE-TEST fix copy bounds")
  return repo, _git(repo, "rev-parse", "HEAD")


def test_deterministic_extractor_writes_chunk_level_artifacts(tmp_path: Path):
  repo, commit = _make_repo(tmp_path)
  result = run_step1_deterministic_extractor(
    result_root=tmp_path / "Result",
    repo_name="demo",
    cve_id="CVE-TEST",
    repo_path=str(repo),
    fixing_commits=[commit],
    cve_description="Out-of-bounds read in parse_len due to missing length check.",
    cwe=["CWE-125"],
    nvd_record={"description": "Out-of-bounds read", "cvss3": [{"score": "7.5 HIGH"}]},
    dataset_record={"repo": "demo", "fixing_commits": [[commit]]},
    mode="deterministic_only",
  )

  output = Path(result["output_dir"])
  commits = [CommitSemantics.model_validate(row) for row in _jsonl(output / "commit_semantics.jsonl")]
  chunks = [ChunkSemantics.model_validate(row) for row in _jsonl(output / "chunk_semantics.jsonl")]
  regions = [SemanticRegion.model_validate(row) for row in _jsonl(output / "semantic_regions.jsonl")]
  report = Step1QualityReport.model_validate(json.loads((output / "step1_quality_report.json").read_text(encoding="utf-8")))

  assert len(commits) == 1
  assert commits[0].commit == commit
  assert commits[0].patch_type == "add_only"
  assert commits[0].source_files == ["file.c"]
  assert commits[0].hunk_count == 1
  assert "security_keyword_in_message" in commits[0].message_signals

  assert len(chunks) == 1
  chunk = chunks[0]
  assert chunk.file_role == "source"
  assert chunk.patch_type == "add_only"
  assert chunk.function_context and "parse_len" in chunk.function_context
  assert chunk.source_refs
  assert any("if (len < 0)" in ref.snippet and ref.change_type == "added" for ref in chunk.source_refs)
  assert all(ref.change_type in {"added", "removed", "context"} for ref in chunk.source_refs)

  assert len(regions) == 1
  region = regions[0]
  assert region.file_path == "file.c"
  assert region.chunk_ids == [chunk.chunk_id]
  assert region.added_guard_sequence
  assert any("if (len < 0)" in x for x in region.added_guard_sequence)
  assert "added_guard_check" in region.score_reasons
  assert region.root_cause_score > 0

  assert report.deterministic_complete is True
  assert report.patch_chunk_count == 1
  assert report.semantic_region_count == 1
  assert report.hard_deletion_count == 0
  assert report.missing_context_fields == []
  assert "fix_evidence_manifest" in report.artifact_paths
  manifest_path = Path(report.artifact_paths["fix_evidence_manifest"])
  assert manifest_path.is_file()
  manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
  assert manifest["schema_version"] == "step1_fix_commit_evidence.v1"
  assert manifest["commits"][0]["commit"] == commit
  patch_path = Path(manifest["commits"][0]["files"]["show_full_patch"]["path"])
  assert patch_path.is_file()
  assert "if (len < 0)" in patch_path.read_text(encoding="utf-8")


def test_deterministic_extractor_records_missing_nvd_context(tmp_path: Path):
  repo, commit = _make_repo(tmp_path)
  result = run_step1_deterministic_extractor(
    result_root=tmp_path / "Result",
    repo_name="demo",
    cve_id="CVE-MISSING",
    repo_path=str(repo),
    fixing_commits=[commit],
    cve_description="",
    cwe=[],
    nvd_record=None,
    dataset_record={},
    mode="deterministic_only",
  )
  output = Path(result["output_dir"])
  report = Step1QualityReport.model_validate(json.loads((output / "step1_quality_report.json").read_text(encoding="utf-8")))
  assert "nvd_record" in report.missing_context_fields
  assert "cve_description" in report.missing_context_fields


def test_deterministic_extractor_runs_on_real_dataset_cve(tmp_path: Path):
  project = Path(__file__).resolve().parents[1]
  dataset_path = project / "DataSet" / "BaseDataOrder.json"
  nvd_path = project / "DataSet" / "BaseData_nvd.json"
  repo_root = project / "repo" / "FFmpeg"
  if not repo_root.exists():
    pytest.skip("FFmpeg repo is not available")

  dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
  nvd = json.loads(nvd_path.read_text(encoding="utf-8"))
  cve_id = "CVE-2022-3965"
  record = dataset[cve_id]
  commits = [c for family in record["fixing_commits"] for c in family]
  result = run_step1_deterministic_extractor(
    result_root=tmp_path / "Result",
    repo_name=record["repo"],
    cve_id=cve_id,
    repo_path=str(repo_root),
    fixing_commits=commits,
    cve_description=nvd[cve_id]["description"],
    cwe=record.get("CWE") or [],
    nvd_record=nvd[cve_id],
    dataset_record=record,
    mode="deterministic_only",
  )
  output = Path(result["output_dir"])
  chunks = [ChunkSemantics.model_validate(row) for row in _jsonl(output / "chunk_semantics.jsonl")]
  regions = [SemanticRegion.model_validate(row) for row in _jsonl(output / "semantic_regions.jsonl")]
  report = Step1QualityReport.model_validate(json.loads((output / "step1_quality_report.json").read_text(encoding="utf-8")))

  assert chunks
  assert regions
  assert report.patch_chunk_count == len(chunks)
  assert report.semantic_region_count == len(regions)
  assert report.hard_deletion_count == 0
  assert "nvd_record" not in report.missing_context_fields


@pytest.mark.parametrize(
  ("repo_name", "cve_id", "commit", "expected_snippet"),
  [
    ("openjpeg", "CVE-2020-27814", "43dd9ee17894a22fa3df88b1e561274632d9ab43", "l_data_size = 74"),
    ("linux", "CVE-2022-20568", "5695e51619745d4fe3ec2506a2f0cd982c5e27a4", "PF_IO_WORKER"),
  ],
)
def test_deterministic_extractor_expands_merge_commit_patch(
  tmp_path: Path,
  repo_name: str,
  cve_id: str,
  commit: str,
  expected_snippet: str,
):
  project = Path(__file__).resolve().parents[1]
  repo_root = project / "repo" / repo_name
  if not repo_root.exists():
    pytest.skip(f"{repo_name} repo is not available")

  result = run_step1_deterministic_extractor(
    result_root=tmp_path / "Result",
    repo_name=repo_name,
    cve_id=cve_id,
    repo_path=str(repo_root),
    fixing_commits=[commit],
    cve_description="Merge commit patch extraction regression.",
    cwe=[],
    nvd_record={"description": "Merge commit patch extraction regression.", "cvss3": [{"score": "7.5 HIGH"}]},
    dataset_record={"repo": repo_name, "fixing_commits": [[commit]]},
    mode="deterministic_only",
  )

  output = Path(result["output_dir"])
  commits = [CommitSemantics.model_validate(row) for row in _jsonl(output / "commit_semantics.jsonl")]
  chunks = [ChunkSemantics.model_validate(row) for row in _jsonl(output / "chunk_semantics.jsonl")]
  report = Step1QualityReport.model_validate(json.loads((output / "step1_quality_report.json").read_text(encoding="utf-8")))

  assert commits[0].parent_count > 1
  assert commits[0].diff_extraction_mode == "merge_first_parent"
  assert report.patch_chunk_count > 0
  assert chunks
  assert any(expected_snippet in ref.snippet for chunk in chunks for ref in chunk.source_refs)


def test_deterministic_extractor_preserves_diff_line_polarity(tmp_path: Path):
  repo, commit = _make_mixed_repo(tmp_path)
  result = run_step1_deterministic_extractor(
    result_root=tmp_path / "Result",
    repo_name="demo",
    cve_id="CVE-MIXED",
    repo_path=str(repo),
    fixing_commits=[commit],
    cve_description="Out-of-bounds write due to unchecked copy length.",
    cwe=["CWE-787"],
    nvd_record={"description": "Out-of-bounds write", "cvss3": [{"score": "7.5 HIGH"}]},
    dataset_record={"repo": "demo", "fixing_commits": [[commit]]},
    mode="deterministic_only",
  )

  output = Path(result["output_dir"])
  chunks = [ChunkSemantics.model_validate(row) for row in _jsonl(output / "chunk_semantics.jsonl")]
  regions = [SemanticRegion.model_validate(row) for row in _jsonl(output / "semantic_regions.jsonl")]
  chunk = chunks[0]
  change_types = {ref.change_type for ref in chunk.source_refs}

  assert {"added", "removed", "context"}.issubset(change_types)
  assert any(ref.change_type == "removed" and "memcpy(dst, src, len)" in ref.snippet for ref in chunk.source_refs)
  assert any(ref.change_type == "added" and "if (len > dst_len)" in ref.snippet for ref in chunk.source_refs)
  assert any(ref.change_type == "context" and "int copy_data" in ref.snippet for ref in chunk.source_refs)
  assert any(ref.old_line_no is not None for ref in chunk.source_refs if ref.change_type in {"removed", "context"})
  assert any(ref.new_line_no is not None for ref in chunk.source_refs if ref.change_type in {"added", "context"})

  region = regions[0]
  assert any("if (len > dst_len)" in line for line in region.added_guard_sequence)
  assert not any("memcpy(dst, src, len)" in line for line in region.added_guard_sequence)
  assert any("memcpy(dst, src, len)" in line for line in region.removed_critical_sequence)
  assert not any("if (len > dst_len)" in line for line in region.removed_critical_sequence)

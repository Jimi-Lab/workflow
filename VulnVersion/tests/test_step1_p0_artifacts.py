import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnversion.stage1_semantic_aggregation.artifacts import write_step1_p0_artifacts
from vulnversion.stage1_semantic_aggregation.schema import (
  ChunkSemantics,
  CommitSemantics,
  EvidenceRef,
  FixFamilySemantics,
  SemanticRegion,
  Step1QualityReport,
)


def _jsonl(path: Path) -> list[dict]:
  if not path.read_text(encoding="utf-8").strip():
    return []
  return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_step1_p0_schema_round_trip():
  ref = EvidenceRef(
    ref_id="src:CVE-1:abc:file.c:git_diff:1",
    kind="git_diff",
    commit="abc",
    file_path="file.c",
    snippet="if (x) return;",
    snippet_hash="sha256:demo",
    strength_hint="medium",
  )
  commit = CommitSemantics(
    cve_id="CVE-1",
    repo="demo",
    commit="abc",
    role="primary_fix",
    patch_type="mixed",
    changed_files=["file.c"],
    source_files=["file.c"],
    hunk_count=1,
  )
  chunk = ChunkSemantics(
    cve_id="CVE-1",
    repo="demo",
    chunk_id="chunk_0001",
    commit="abc",
    file_path="file.c",
    patch_type="mixed",
    file_role="source",
    chunk_role="unknown",
    source_refs=[ref],
  )
  region = SemanticRegion(
    cve_id="CVE-1",
    repo="demo",
    region_id="region_0001",
    commits=["abc"],
    file_path="file.c",
    chunk_ids=["chunk_0001"],
    patch_type="mixed",
    file_role="source",
    source_refs=[ref],
  )
  family = FixFamilySemantics(
    cve_id="CVE-1",
    repo="demo",
    primary_fix_commit="abc",
    fix_commits=["abc"],
  )
  report = Step1QualityReport(
    cve_id="CVE-1",
    repo="demo",
    mode="deterministic_only",
    deterministic_complete=True,
  )

  assert EvidenceRef.model_validate(ref.model_dump()) == ref
  assert CommitSemantics.model_validate(commit.model_dump()) == commit
  assert ChunkSemantics.model_validate(chunk.model_dump()) == chunk
  assert SemanticRegion.model_validate(region.model_dump()) == region
  assert FixFamilySemantics.model_validate(family.model_dump()) == family
  assert Step1QualityReport.model_validate(report.model_dump()) == report


def test_write_step1_p0_artifacts_creates_required_layout(tmp_path: Path):
  result = write_step1_p0_artifacts(
    result_root=tmp_path,
    repo="demo",
    cve_id="CVE-1",
    repo_path="repo/demo",
    primary_fix_commit="abc",
    fix_commits=["abc"],
    dataset_record={"cve": "CVE-1"},
    mode="deterministic_only",
  )

  step1_dir = tmp_path / "demo" / "CVE-1" / "step1"
  output = step1_dir / "output"
  assert result["step1_dir"] == str(step1_dir)
  assert (step1_dir / "agent_calls").is_dir()
  assert (step1_dir / "trace.jsonl").is_file()

  required = [
    "fix_family_semantics.json",
    "commit_semantics.jsonl",
    "chunk_semantics.jsonl",
    "semantic_regions.jsonl",
    "step1_quality_report.json",
    "patch_semantics.json",
  ]
  for name in required:
    assert (output / name).is_file()

  family = FixFamilySemantics.model_validate(json.loads((output / "fix_family_semantics.json").read_text(encoding="utf-8")))
  report = Step1QualityReport.model_validate(json.loads((output / "step1_quality_report.json").read_text(encoding="utf-8")))
  patch = json.loads((output / "patch_semantics.json").read_text(encoding="utf-8"))

  assert family.schema_version == "fix_family_semantics.v1"
  assert family.fix_commits == ["abc"]
  assert report.schema_version == "step1_quality_report.v1"
  assert report.deterministic_complete is True
  assert patch["cve_id"] == "CVE-1"
  assert patch["fix_commit"] == "abc"
  assert _jsonl(output / "commit_semantics.jsonl") == []
  assert _jsonl(output / "chunk_semantics.jsonl") == []
  assert _jsonl(output / "semantic_regions.jsonl") == []

  trace_rows = _jsonl(step1_dir / "trace.jsonl")
  assert trace_rows[-1]["event"] == "step1_p0_artifacts_written"
  assert trace_rows[-1]["cve_id"] == "CVE-1"

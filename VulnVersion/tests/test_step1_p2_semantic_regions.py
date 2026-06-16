import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnversion.stage1_semantic_aggregation.schema import ChunkSemantics, EvidenceRef
from vulnversion.stage1_semantic_aggregation.semantic_regions import build_semantic_regions


def _ref(cve_id: str, commit: str, file_path: str, idx: int, snippet: str, *, line_start: int | None = None) -> EvidenceRef:
  return EvidenceRef(
    ref_id=f"src:{cve_id}:{commit}:{file_path}:git_diff:{idx}",
    kind="git_diff",
    commit=commit,
    file_path=file_path,
    line_start=line_start,
    snippet=snippet,
    snippet_hash=f"sha256:{idx}",
    strength_hint="medium",
  )


def _chunk(
  chunk_id: str,
  *,
  file_path: str = "file.c",
  function_context: str | None = "parse_len",
  file_role: str = "source",
  patch_type: str = "mixed",
  line_start: int | None = 10,
  fix_guard: float = 0.0,
  vuln_seq: float = 0.0,
  snippet: str = "if (len < 0) return -1;",
) -> ChunkSemantics:
  ref = _ref("CVE-X", "abc", file_path, int(chunk_id.split("_")[-1]), snippet, line_start=line_start)
  return ChunkSemantics(
    cve_id="CVE-X",
    repo="demo",
    chunk_id=chunk_id,
    commit="abc",
    file_path=file_path,
    function_context=function_context,
    patch_type=patch_type,  # type: ignore[arg-type]
    file_role=file_role,  # type: ignore[arg-type]
    line_start=line_start,
    chunk_role="unknown",
    fix_guard_likelihood=fix_guard,
    vulnerable_sequence_likelihood=vuln_seq,
    source_refs=[ref],
  )


def test_regions_compress_chunks_by_file_and_function():
  chunks = [
    _chunk("chunk_0001", fix_guard=1.0),
    _chunk("chunk_0002", vuln_seq=1.0, snippet="memcpy(dst, src, len);"),
  ]
  regions = build_semantic_regions(cve_id="CVE-X", repo="demo", chunks=chunks)

  assert len(regions) == 1
  region = regions[0]
  assert region.chunk_ids == ["chunk_0001", "chunk_0002"]
  assert region.compression_input_chunks == 2
  assert region.compression_ratio == 0.5
  assert "added_guard_check" in region.score_reasons
  assert "dangerous_or_vulnerable_sequence" in region.score_reasons
  assert region.root_cause_score > 0


def test_regions_use_local_window_when_function_context_missing():
  chunks = [
    _chunk("chunk_0001", function_context=None, line_start=10),
    _chunk("chunk_0002", function_context=None, line_start=25),
    _chunk("chunk_0003", function_context=None, line_start=220),
  ]
  regions = build_semantic_regions(cve_id="CVE-X", repo="demo", chunks=chunks, local_window_size=80)

  assert len(regions) == 2
  assert sorted(len(r.chunk_ids) for r in regions) == [1, 2]
  assert all(r.local_window_key for r in regions)
  assert all("function_context_missing" in r.risk_flags for r in regions)


def test_low_score_region_is_retained_and_downgraded_not_deleted():
  chunks = [
    _chunk(
      "chunk_0001",
      file_path="docs/security.md",
      function_context=None,
      file_role="doc",
      patch_type="add_only",
      line_start=1,
      snippet="Update advisory text",
    )
  ]
  regions = build_semantic_regions(cve_id="CVE-X", repo="demo", chunks=chunks)

  assert len(regions) == 1
  region = regions[0]
  assert region.root_cause_score < 0
  assert "low_score_region" in region.risk_flags
  assert "non_source_region" in region.risk_flags
  assert region.allowed_downstream_use == ["prompt_context"]

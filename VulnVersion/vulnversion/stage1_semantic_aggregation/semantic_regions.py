from __future__ import annotations

from collections import defaultdict

from vulnversion.stage1_semantic_aggregation.chunk_features import dangerous_candidates, guard_candidates
from vulnversion.stage1_semantic_aggregation.schema import ChunkSemantics, SemanticRegion


def _score_region(chunks: list[ChunkSemantics]) -> tuple[float, list[str]]:
  score = 0.0
  reasons: list[str] = []
  if any(ch.file_role == "source" for ch in chunks):
    score += 3
    reasons.append("source_file")
  if any(ch.file_role in {"test", "doc", "build", "generated"} for ch in chunks):
    score -= 5
    reasons.append("non_source_file")
  if any(ch.fix_guard_likelihood > 0 for ch in chunks):
    score += 3
    reasons.append("added_guard_check")
  if any(ch.vulnerable_sequence_likelihood > 0 for ch in chunks):
    score += 3
    reasons.append("dangerous_or_vulnerable_sequence")
  if any(ch.patch_type == "mixed" for ch in chunks):
    score += 2
    reasons.append("mixed_patch")
  return score, reasons


def _window_key(ch: ChunkSemantics, local_window_size: int) -> str:
  if ch.function_context:
    return f"func:{ch.function_context}"
  if ch.local_window_key:
    return ch.local_window_key
  if ch.line_start and ch.line_start > 0:
    bucket = (ch.line_start - 1) // max(1, local_window_size)
    return f"window:{bucket * local_window_size + 1}-{(bucket + 1) * local_window_size}"
  return "window:unknown"


def _region_risk_flags(group: list[ChunkSemantics], score: float) -> list[str]:
  flags = {flag for ch in group for flag in ch.risk_flags}
  if any(ch.function_context is None for ch in group):
    flags.add("function_context_missing")
  if any(ch.file_role != "source" for ch in group):
    flags.add("non_source_region")
  if score <= 0:
    flags.add("low_score_region")
  return sorted(flags)


def _downstream_use(score: float) -> list[str]:
  if score <= 0:
    return ["prompt_context"]
  return ["prompt_context", "priority_signal"]


def build_semantic_regions(
  *,
  cve_id: str,
  repo: str,
  chunks: list[ChunkSemantics],
  local_window_size: int = 80,
) -> list[SemanticRegion]:
  grouped: dict[tuple[str, str], list[ChunkSemantics]] = defaultdict(list)
  for ch in chunks:
    grouped[(ch.file_path, _window_key(ch, local_window_size))].append(ch)

  regions: list[SemanticRegion] = []
  for idx, ((file_path, function_context), group) in enumerate(sorted(grouped.items()), start=1):
    score, reasons = _score_region(group)
    added_guard_sequence: list[str] = []
    removed_critical_sequence: list[str] = []
    nearby_dangerous_operation: list[str] = []
    source_refs = []
    for ch in group:
      source_refs.extend(ch.source_refs)
      added_lines = [ref.snippet for ref in ch.source_refs if ref.change_type == "added" and ref.snippet.strip()]
      removed_lines = [ref.snippet for ref in ch.source_refs if ref.change_type == "removed" and ref.snippet.strip()]
      context_lines = [ref.snippet for ref in ch.source_refs if ref.change_type == "context" and ref.snippet.strip()]
      if ch.fix_guard_likelihood > 0:
        added_guard_sequence.extend(guard_candidates(added_lines))
      if ch.vulnerable_sequence_likelihood > 0:
        removed_critical_sequence.extend(dangerous_candidates(removed_lines))
      nearby_dangerous_operation.extend(dangerous_candidates(context_lines))
    line_starts = [ch.line_start for ch in group if ch.line_start is not None]
    line_ends = [ch.line_end for ch in group if ch.line_end is not None]
    function_context = group[0].function_context
    local_window_key = None if function_context else _window_key(group[0], local_window_size)
    regions.append(
      SemanticRegion(
        cve_id=cve_id,
        repo=repo,
        region_id=f"region_{idx:04d}",
        commits=sorted({ch.commit for ch in group}),
        file_path=file_path,
        function_context=function_context,
        line_start=min(line_starts) if line_starts else None,
        line_end=max(line_ends) if line_ends else None,
        local_window_key=local_window_key,
        chunk_ids=[ch.chunk_id for ch in group],
        compression_input_chunks=len(group),
        compression_ratio=1 / len(group) if group else None,
        patch_type=group[0].patch_type,
        file_role=group[0].file_role,
        removed_critical_sequence=removed_critical_sequence[:20],
        added_guard_sequence=added_guard_sequence[:20],
        nearby_dangerous_operation=nearby_dangerous_operation[:20],
        root_cause_score=score,
        score_reasons=reasons,
        evidence_strength="medium" if score > 0 else "weak",
        allowed_downstream_use=_downstream_use(score),
        risk_flags=_region_risk_flags(group, score),
        source_refs=source_refs[:50],
      )
    )
  return regions

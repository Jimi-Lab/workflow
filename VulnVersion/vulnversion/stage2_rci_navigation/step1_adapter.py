from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from vulnversion.stage1_semantic_aggregation.schema import (
  EvidenceRef,
  FixFamilySemantics,
  RegionRefinementResult,
  SemanticRegion,
)
from vulnversion.stage2_rci_navigation.vet_schema import RootCauseVet, VetEvidenceRef, VetPattern


@dataclass(frozen=True)
class Step1VetSeed:
  """Step1 artifacts normalized for Step2 VET induction.

  This adapter is intentionally conservative: Step1 evidence is admitted as
  scheduling priority and prompt context by default.  Certificate candidates are
  only emitted when explicitly requested and backed by strong Step1 evidence.
  """

  fix_family: FixFamilySemantics
  regions: list[SemanticRegion]
  refinements: list[RegionRefinementResult]


def _read_jsonl(path: Path) -> list[dict]:
  if not path.exists():
    return []
  text = path.read_text(encoding="utf-8").strip()
  if not text:
    return []
  return [json.loads(line) for line in text.splitlines() if line.strip()]


def _required(path: Path) -> Path:
  if not path.exists():
    raise FileNotFoundError(str(path))
  return path


def _output_dir(step1_dir_or_cve_dir: str | Path) -> Path:
  root = Path(step1_dir_or_cve_dir)
  if root.name == "output":
    return root
  if (root / "output").is_dir():
    return root / "output"
  if (root / "step1" / "output").is_dir():
    return root / "step1" / "output"
  return root / "output"


def load_step1_vet_seed(step1_dir_or_cve_dir: str | Path) -> Step1VetSeed:
  """Load Step1 artifacts needed by Step2.

  Accepted roots are the Step1 directory, the Step1 output directory, or the CVE
  result directory containing ``step1/output``.
  """

  out_dir = _output_dir(step1_dir_or_cve_dir)
  fix_family = FixFamilySemantics.model_validate(
    json.loads(_required(out_dir / "fix_family_semantics.json").read_text(encoding="utf-8"))
  )
  regions = [
    SemanticRegion.model_validate(row)
    for row in _read_jsonl(_required(out_dir / "semantic_regions.jsonl"))
  ]
  refinements = [
    RegionRefinementResult.model_validate(row)
    for row in _read_jsonl(out_dir / "region_refinements.jsonl")
  ]
  return Step1VetSeed(fix_family=fix_family, regions=regions, refinements=refinements)


def _vet_evidence(refs: Iterable[EvidenceRef], *, fallback_ref: str, snippet: str = "") -> list[VetEvidenceRef]:
  out: list[VetEvidenceRef] = []
  for ref in refs:
    out.append(VetEvidenceRef(source=ref.kind, ref=ref.ref_id, snippet=ref.snippet[:500]))
  if not out:
    out.append(VetEvidenceRef(source="step1", ref=fallback_ref, snippet=snippet[:500]))
  return out


def _allowed_uses(*, step1_uses: list[str], strength: str, allow_certificates: bool) -> list[str]:
  uses: set[str] = {"priority", "prompt_context"}
  if allow_certificates and strength == "strong" and "certificate_candidate" in step1_uses:
    uses.add("certificate_candidate")
  return sorted(uses)


def _add_pattern(
  target: list[VetPattern],
  seen: set[tuple[str, str, tuple[str, ...]]],
  *,
  pattern_id: str,
  kind: str,
  value: str | None,
  scope_files: list[str],
  strength: str,
  allowed_uses: list[str],
  evidence: list[VetEvidenceRef],
  notes: str = "",
) -> None:
  normalized = (value or "").strip()
  if not normalized:
    return
  key = (kind, normalized, tuple(scope_files))
  if key in seen:
    return
  seen.add(key)
  target.append(
    VetPattern(
      pattern_id=pattern_id,
      kind=kind,  # type: ignore[arg-type]
      value=normalized,
      scope_files=scope_files,
      strength=strength,  # type: ignore[arg-type]
      allowed_uses=allowed_uses,  # type: ignore[arg-type]
      evidence=evidence,
      notes=notes,
    )
  )


def build_root_cause_vet_from_step1(
  seed: Step1VetSeed,
  *,
  allow_step1_certificates: bool = False,
) -> RootCauseVet:
  """Convert Step1 semantic regions into a conservative Step2 RootCauseVet seed."""

  cve_id = seed.fix_family.cve_id
  repo = seed.fix_family.repo
  refinement_by_region = {row.region_id: row for row in seed.refinements}
  vet = RootCauseVet(
    cve_id=cve_id,
    repo=repo,
    root_cause_summary=(
      f"Step1 supplied {len(seed.regions)} semantic regions"
      + (f" and {len(seed.refinements)} agent refinements." if seed.refinements else ".")
    ),
    confidence={
      "source": "step1_artifacts",
      "step1_regions": len(seed.regions),
      "step1_refinement_regions": len(seed.refinements),
      "fix_family_semantics": seed.fix_family.family_semantics,
      "step1_certificates_enabled": allow_step1_certificates,
    },
  )

  seen: set[tuple[str, str, tuple[str, ...]]] = set()
  for idx, region in enumerate(seed.regions, start=1):
    refinement = refinement_by_region.get(region.region_id)
    strength = (refinement.evidence_strength if refinement else region.evidence_strength) or "weak"
    step1_uses = list(refinement.allowed_downstream_use if refinement else region.allowed_downstream_use)
    allowed = _allowed_uses(
      step1_uses=step1_uses,
      strength=strength,
      allow_certificates=allow_step1_certificates,
    )
    evidence = _vet_evidence(
      region.source_refs,
      fallback_ref=region.region_id,
      snippet="; ".join(region.score_reasons),
    )
    scope = [region.file_path] if region.file_path else []
    prefix = f"step1_region_{idx:04d}"
    notes = (
      f"region_role={refinement.region_role}; relation={refinement.root_cause_relation}; "
      f"{refinement.reasoning_summary}"
      if refinement
      else f"score={region.root_cause_score}; reasons={','.join(region.score_reasons)}"
    )

    _add_pattern(
      vet.root_cause_files,
      seen,
      pattern_id=f"{prefix}_file",
      kind="file",
      value=region.file_path,
      scope_files=[],
      strength=strength,
      allowed_uses=allowed,
      evidence=evidence,
      notes=notes,
    )
    _add_pattern(
      vet.root_cause_functions,
      seen,
      pattern_id=f"{prefix}_function",
      kind="function",
      value=region.function_context,
      scope_files=scope,
      strength=strength,
      allowed_uses=allowed,
      evidence=evidence,
      notes=notes,
    )

    vulnerable_sequences = list(region.removed_critical_sequence)
    fix_guards = list(region.added_guard_sequence)
    if refinement:
      vulnerable_sequences = list(refinement.vulnerable_sequence or vulnerable_sequences)
      fix_guards = list(refinement.fix_guard_sequence or fix_guards)

    for seq_idx, sequence in enumerate(vulnerable_sequences[:5], start=1):
      _add_pattern(
        vet.vulnerable_sequences,
        seen,
        pattern_id=f"{prefix}_vulnseq_{seq_idx}",
        kind="vulnerable_sequence",
        value=sequence,
        scope_files=scope,
        strength=strength,
        allowed_uses=allowed,
        evidence=evidence,
        notes=notes,
      )
    for guard_idx, guard in enumerate(fix_guards[:5], start=1):
      _add_pattern(
        vet.fix_guards,
        seen,
        pattern_id=f"{prefix}_fixguard_{guard_idx}",
        kind="fix_guard",
        value=guard,
        scope_files=scope,
        strength=strength,
        allowed_uses=allowed,
        evidence=evidence,
        notes=notes,
      )

  return vet

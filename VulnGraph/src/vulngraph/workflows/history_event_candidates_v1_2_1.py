from __future__ import annotations

import hashlib
import re
from typing import Any


_DECLARATION_RE = re.compile(
  r"^(?:(?:static|const|volatile|unsigned|signed|struct|enum|union|long|short)\s+)*"
  r"[A-Za-z_][\w\s\*]+\s+[A-Za-z_]\w*(?:\s*=\s*[^();]+)?;$"
)
_FUNCTION_DECLARATION_RE = re.compile(
  r"^(?:(?:static|inline|extern|const|volatile|unsigned|signed|long|short)\s+)*"
  r"(?:struct\s+\w+|[A-Za-z_]\w*)\s*\**\s+[A-Za-z_]\w*\s*\([^{}]*\)\s*;?$"
)
_SEMANTIC_DECLARATION_ROLES = {
  "callback_activation",
  "type_truncation",
  "state_layout",
  "interface_constraint",
}
_CONVERTER_ONLY_RISK_FLAGS = {
  "release_reachability_too_broad",
  "release_line_overreach",
  "non_release_tag_noise",
}


def materialize_semantic_history_events(
  candidates: list[dict[str, Any]],
  evidence_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
  """Materialize blame alternatives while retaining only bound semantic declarations."""
  evidence_by_id = {
    str(item.get("candidate_identity", {}).get("candidate_id") or ""): item
    for item in evidence_records
  }
  output: list[dict[str, Any]] = []
  for candidate in candidates:
    source_anchor_id = str(candidate.get("candidate_id") or "")
    line_text = str(candidate.get("old_line_text") or "")
    taxonomy = _fallback_taxonomy(candidate)
    if str(candidate.get("candidate_source") or "") == "fallback" and taxonomy.startswith("noise_"):
      continue
    evidence = evidence_by_id.get(source_anchor_id, {})
    identity = evidence.get("candidate_identity", {})
    by_sha: dict[str, list[str]] = {}
    for variant in evidence.get("blame_variants", {}).get("variants", []) or []:
      if variant.get("exit_code") not in (0, None):
        continue
      sha = str(variant.get("blamed_commit_sha") or "").strip()
      if sha:
        by_sha.setdefault(sha, []).append(str(variant.get("variant") or ""))
    canonical = str(candidate.get("candidate_commit_sha") or "").strip()
    if canonical:
      by_sha.setdefault(canonical, []).append("canonical")
    for event_sha, modes in sorted(by_sha.items()):
      event_id = _event_id(source_anchor_id, event_sha)
      fix_sha = str(identity.get("fix_commit_sha") or _fix_sha(candidate.get("fix_commit_id")))
      output.append({
        "event_candidate_id": event_id,
        "source_anchor_id": source_anchor_id,
        "event_commit_sha": event_sha,
        "derivation_modes": sorted(set(modes)),
        "path_before": str(candidate.get("path_before") or identity.get("path_before") or ""),
        "old_line_start": candidate.get("old_line_start") or identity.get("old_line_start"),
        "old_line_end": candidate.get("old_line_end") or identity.get("old_line_end"),
        "old_line_text": line_text,
        "old_line_text_hash": str(candidate.get("line_text_hash") or candidate.get("old_line_text_hash") or identity.get("old_line_text_hash") or ""),
        "fix_commit_id": str(candidate.get("fix_commit_id") or identity.get("fix_commit_id") or ""),
        "fix_commit_sha": fix_sha,
        "patch_family_id": str(candidate.get("patch_family_id") or identity.get("patch_family_id") or ""),
        "patch_hunk_id": str(candidate.get("patch_hunk_id") or identity.get("patch_hunk_id") or ""),
        "root_cause_binding_refs": list(candidate.get("root_cause_binding_refs") or []),
        "vulnerable_predicate_refs": list(candidate.get("vulnerable_predicate_refs") or []),
        "fix_predicate_refs": list(candidate.get("fix_predicate_refs") or []),
        "evidence_refs": sorted(set(candidate.get("evidence_refs") or []) | {f"history_event:{event_id}"}),
        "candidate_source": str(candidate.get("candidate_source") or ""),
        "candidate_selection_mode": str(candidate.get("candidate_selection_mode") or ""),
        "fallback_semantic_taxonomy": taxonomy,
        "risk_flags": sorted((set(candidate.get("risk_flags") or []) | set(evidence.get("risk_flags") or [])) - _CONVERTER_ONLY_RISK_FLAGS),
        "confidence_features": list(evidence.get("confidence_features") or []),
        "line_survival_evidence": dict(evidence.get("line_survival_evidence") or {}),
        "branch_context_ids": [],
        "lifecycle": "raw_candidate",
      })
  return output


def _fallback_taxonomy(candidate: dict[str, Any]) -> str:
  value = str(candidate.get("old_line_text") or "").strip()
  if not value or value in {"{", "}", "};"}:
    return "noise_blank_or_brace"
  if value.startswith(("//", "/*", "*", "#")):
    return "noise_comment_only"
  is_declaration = bool(_DECLARATION_RE.fullmatch(value) or _FUNCTION_DECLARATION_RE.fullmatch(value))
  if not is_declaration:
    return "executable_or_predicate_statement"
  role = str(candidate.get("semantic_role") or "")
  bound = bool(candidate.get("root_cause_binding_refs") and candidate.get("vulnerable_predicate_refs"))
  root_hunk = bool(candidate.get("root_cause_hunk_match"))
  if bound and root_hunk and role in _SEMANTIC_DECLARATION_ROLES:
    return f"{role}_declaration"
  return "noise_unbound_declaration"


def _event_id(anchor_id: str, sha: str) -> str:
  return f"history-event:{hashlib.sha256(f'{anchor_id}|{sha}'.encode()).hexdigest()}"


def _fix_sha(value: Any) -> str:
  text = str(value or "")
  return text.rsplit(":", 1)[-1] if ":" in text else text

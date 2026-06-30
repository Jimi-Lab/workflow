from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any

from vulngraph.services.blame_runner import parse_blame_porcelain


_DECLARATION_RE = re.compile(
  r"^(?:(?:static|const|volatile|unsigned|signed|struct|enum|union|long|short)\s+)*"
  r"[A-Za-z_][\w\s\*]+\s+[A-Za-z_]\w*(?:\s*=\s*[^();]+)?;$"
)
_FUNCTION_DECLARATION_RE = re.compile(
  r"^(?:(?:static|inline|extern|const|volatile|unsigned|signed|long|short)\s+)*"
  r"(?:struct\s+\w+|[A-Za-z_]\w*)\s*\**\s+[A-Za-z_]\w*\s*\([^{}]*\)\s*;?$"
)
_STRUCTURAL_CONTROL_RE = re.compile(r"^[{}]\s*(?:else(?:\s+if\s*\([^)]*\))?\s*)?[{}]$")
_CONVERTER_ONLY_RISK_FLAGS = {
  "release_reachability_too_broad",
  "release_line_overreach",
  "non_release_tag_noise",
}


def materialize_history_event_candidates(
  candidates: list[dict[str, Any]],
  evidence_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
  """Materialize distinct wrapper-observed blame SHAs as alternative history events."""
  evidence_by_id = {
    str(item.get("candidate_identity", {}).get("candidate_id") or ""): item
    for item in evidence_records
  }
  output: list[dict[str, Any]] = []
  for candidate in candidates:
    source_anchor_id = str(candidate.get("candidate_id") or "")
    line_text = str(candidate.get("old_line_text") or "")
    if str(candidate.get("candidate_source") or "") == "fallback" and _is_noise_line(line_text):
      continue
    evidence = evidence_by_id.get(source_anchor_id, {})
    identity = evidence.get("candidate_identity", {})
    by_sha: dict[str, list[str]] = {}
    for variant in evidence.get("blame_variants", {}).get("variants", []) or []:
      if variant.get("exit_code") not in (0, None):
        continue
      sha = str(variant.get("blamed_commit_sha") or "").strip()
      mode = str(variant.get("variant") or "").strip()
      if sha:
        by_sha.setdefault(sha, []).append(mode)
    canonical = str(candidate.get("candidate_commit_sha") or "").strip()
    if canonical:
      by_sha.setdefault(canonical, []).append("canonical")
    for event_sha, modes in sorted(by_sha.items()):
      event_id = _event_id(source_anchor_id, event_sha)
      fix_sha = str(identity.get("fix_commit_sha") or _fix_sha(candidate.get("fix_commit_id")))
      output.append(
        {
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
          "root_cause_binding_refs": list(candidate.get("root_cause_binding_refs") or []),
          "vulnerable_predicate_refs": list(candidate.get("vulnerable_predicate_refs") or []),
          "fix_predicate_refs": list(candidate.get("fix_predicate_refs") or []),
          "evidence_refs": sorted(set(candidate.get("evidence_refs") or []) | {f"history_event:{event_id}"}),
          "candidate_source": str(candidate.get("candidate_source") or ""),
          "candidate_selection_mode": str(candidate.get("candidate_selection_mode") or ""),
          "risk_flags": sorted((set(candidate.get("risk_flags") or []) | set(evidence.get("risk_flags") or [])) - _CONVERTER_ONLY_RISK_FLAGS),
          "confidence_features": list(evidence.get("confidence_features") or []),
          "line_survival_evidence": dict(evidence.get("line_survival_evidence") or {}),
          "branch_context_ids": [],
          "lifecycle": "raw_candidate",
        }
      )
  return output


def recover_history_events_from_inventory(
  *, inventory: dict[str, Any], fallback_templates: list[dict[str, Any]],
  root_cause_context: dict[str, Any], repo_path: str | Path,
  max_per_fix: int = 3,
) -> list[dict[str, Any]]:
  """Recover verified, non-noise events from an existing frozen candidate inventory."""
  repo = Path(repo_path)
  root_hunks = _root_cause_hunk_ids(root_cause_context)
  templates_by_fix = {
    _fix_sha(item.get("fix_commit_id")): item for item in fallback_templates
    if str(item.get("candidate_source") or "") == "fallback"
  }
  templates_by_family = {
    str(item.get("patch_family_id") or ""): item for item in fallback_templates
    if str(item.get("candidate_source") or "") == "fallback" and item.get("patch_family_id")
  }
  template_for_fix: dict[str, dict[str, Any]] = dict(templates_by_fix)
  rows_by_fix: dict[str, list[dict[str, Any]]] = {}
  for row in inventory.get("candidates", []) or []:
    fix_sha = str(row.get("fix_commit_sha") or _fix_sha(row.get("fix_commit_id")))
    template = templates_by_fix.get(fix_sha) or templates_by_family.get(str(row.get("patch_family_id") or ""))
    if not template:
      continue
    template_for_fix.setdefault(fix_sha, template)
    line_text = str(row.get("line_text") or "")
    if _is_noise_line(line_text) or row.get("generated_file") or row.get("test_file") or row.get("documentation_file"):
      continue
    rows_by_fix.setdefault(fix_sha, []).append(row)
  recovered: list[dict[str, Any]] = []
  for fix_sha, rows in rows_by_fix.items():
    relevant = [row for row in rows if str(row.get("patch_hunk_id") or "") in root_hunks]
    pool = relevant or rows
    pool.sort(key=lambda row: _inventory_rank(row, root_hunks), reverse=True)
    template = template_for_fix[fix_sha]
    for row in pool[:max_per_fix]:
      verified = _verify_inventory_line(repo, row)
      if not verified:
        continue
      variants = _blame_inventory_line(repo, row)
      if not variants:
        continue
      candidate = {
        "candidate_id": str(row.get("candidate_id") or ""),
        "candidate_commit_sha": "",
        "candidate_source": "fallback",
        "candidate_selection_mode": (row.get("selection_mode_eligibility") or ["inventory_parent_side"])[0],
        "path_before": str(row.get("path_before") or ""),
        "old_line_start": row.get("old_line_start"),
        "old_line_end": row.get("old_line_end"),
        "old_line_text": str(row.get("line_text") or ""),
        "line_text_hash": str(row.get("line_text_sha256") or ""),
        "fix_commit_id": str(row.get("fix_commit_id") or ""),
        "patch_family_id": str(row.get("patch_family_id") or ""),
        "root_cause_binding_refs": list(template.get("root_cause_binding_refs") or []),
        "vulnerable_predicate_refs": list(template.get("vulnerable_predicate_refs") or []),
        "fix_predicate_refs": list(template.get("fix_predicate_refs") or []),
        "evidence_refs": sorted(set(template.get("evidence_refs") or []) | {f"inventory:{row.get('candidate_id')}", f"patch:{row.get('patch_hunk_id')}"}),
        "risk_flags": sorted((set(template.get("risk_flags") or []) | {"fallback_candidate", "no_model_anchor"}) - _CONVERTER_ONLY_RISK_FLAGS),
      }
      evidence = {
        "candidate_identity": {
          "candidate_id": candidate["candidate_id"],
          "fix_commit_sha": fix_sha,
          "fix_commit_id": candidate["fix_commit_id"],
          "patch_family_id": candidate["patch_family_id"],
          "path_before": candidate["path_before"],
          "old_line_start": candidate["old_line_start"],
          "old_line_end": candidate["old_line_end"],
          "old_line_text_hash": candidate["line_text_hash"],
        },
        "blame_variants": {"variants": variants},
        "risk_flags": candidate["risk_flags"],
        "confidence_features": ["frozen_inventory", "parent_line_hash_verified", "root_cause_hunk_bound" if relevant else "inventory_fallback"],
        "line_survival_evidence": {"line_survival_status": "verified_in_fix_parent"},
      }
      recovered.extend(materialize_history_event_candidates([candidate], [evidence]))
  return recovered


def _is_noise_line(line: str) -> bool:
  value = line.strip()
  if not value or value in {"{", "}", "};"}:
    return True
  if _STRUCTURAL_CONTROL_RE.fullmatch(value):
    return True
  if value.startswith(("//", "/*", "*", "#")):
    return True
  return bool(_DECLARATION_RE.fullmatch(value) or _FUNCTION_DECLARATION_RE.fullmatch(value))


def _root_cause_hunk_ids(context: dict[str, Any]) -> set[str]:
  output: set[str] = set()
  for value in context.get("code_anchor_summaries", []) or []:
    match = re.search(r"(patch-hunk:[^\s]+)", str(value))
    if match:
      output.add(match.group(1))
  return output


def _inventory_rank(row: dict[str, Any], root_hunks: set[str]) -> tuple[int, int, int, int]:
  text = str(row.get("line_text") or "").strip()
  semantic = 0
  if re.search(r"\b(?:if|while|for|switch|return)\b", text):
    semantic += 4
  if "=" in text:
    semantic += 3
  if re.search(r"\w+\s*\([^;{}]*\)\s*;", text):
    semantic += 4
  source = 1 if row.get("source_file") else 0
  direct = 2 if str(row.get("candidate_source") or "") == "deleted_line" else 1 if str(row.get("change_type") or "") == "modify" else 0
  hunk = 1 if str(row.get("patch_hunk_id") or "") in root_hunks else 0
  return hunk, direct, source, semantic


def _verify_inventory_line(repo: Path, row: dict[str, Any]) -> bool:
  parent = str(row.get("parent_sha") or "")
  path = str(row.get("path_before") or "")
  line_number = int(row.get("old_line_start") or 0)
  text = str(row.get("line_text") or "")
  expected_hash = str(row.get("line_text_sha256") or "")
  if not parent or not path or line_number <= 0 or not text:
    return False
  result = subprocess.run(["git", "-C", str(repo), "show", f"{parent}:{path}"], text=True, encoding="utf-8", errors="replace", capture_output=True, check=False)
  lines = result.stdout.splitlines() if result.returncode == 0 else []
  if line_number > len(lines) or lines[line_number - 1] != text:
    return False
  return not expected_hash or hashlib.sha256(text.encode()).hexdigest() == expected_hash


def _blame_inventory_line(repo: Path, row: dict[str, Any]) -> list[dict[str, Any]]:
  variants = (("normal", []), ("w", ["-w"]), ("M", ["-M"]), ("C", ["-C"]), ("w_M_C", ["-w", "-M", "-C"]))
  output = []
  for name, flags in variants:
    command = ["git", "-C", str(repo), "blame", *flags, "--line-porcelain", "-L", f"{row['old_line_start']},{row['old_line_end']}", str(row["parent_sha"]), "--", str(row["path_before"])]
    result = subprocess.run(command, text=True, encoding="utf-8", errors="replace", capture_output=True, check=False)
    records = parse_blame_porcelain(result.stdout) if result.returncode == 0 else []
    parsed = records[0] if records else {}
    output.append({
      "variant": name, "exit_code": result.returncode,
      "blamed_commit_sha": parsed.get("blamed_commit_sha", ""),
      "boundary_marker": bool(parsed.get("boundary_marker")),
      "failure_reason": "" if result.returncode == 0 else result.stderr[-500:],
      "command": command,
    })
  return [item for item in output if item["exit_code"] == 0 and item["blamed_commit_sha"]]


def _event_id(anchor_id: str, sha: str) -> str:
  digest = hashlib.sha256(f"{anchor_id}|{sha}".encode()).hexdigest()
  return f"history-event:{digest}"


def _fix_sha(value: Any) -> str:
  text = str(value or "")
  return text.rsplit(":", 1)[-1] if ":" in text else text

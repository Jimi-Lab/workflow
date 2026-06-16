from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from vulnversion.agent_harness.base import AgentRuntime
from vulnversion.opencode.agent import OpenCodeJSONParseError
from vulnversion.stage1_semantic_aggregation.schema import PatchSemantics
from vulnversion.stage2_rci_navigation.induce_rci import induce_rci
from vulnversion.stage2_rci_navigation.navigator import build_navigation_hints
from vulnversion.stage2_rci_navigation.schema import RCIModel
from vulnversion.stage2_rci_navigation.step1_adapter import build_root_cause_vet_from_step1, load_step1_vet_seed
from vulnversion.utils.jsonschema import dump_json
from vulnversion.utils.paths import Paths


def _load_patch_semantics(path: str | Path) -> PatchSemantics:
  data = json.loads(Path(path).read_text(encoding="utf-8"))
  return PatchSemantics.model_validate(data)


def _load_step1_vet_seed_for_stage2(out_dir: Path) -> dict[str, Any] | None:
  """Load Step1 root-cause VET seed if the new Step1 artifacts are present."""

  step1_dir = out_dir / "step1"
  if not step1_dir.exists():
    return None
  try:
    seed = load_step1_vet_seed(step1_dir)
    vet = build_root_cause_vet_from_step1(seed)
  except FileNotFoundError:
    return None
  return vet.model_dump()


def _as_dict(value: Any, *, list_key: str) -> dict[str, Any]:
  if isinstance(value, dict):
    return value
  if isinstance(value, list):
    return {list_key: value}
  return {}


def _as_list(value: Any) -> list[Any]:
  if isinstance(value, list):
    return value
  if isinstance(value, dict):
    return [value]
  return []


def _normalize_rci_payload(raw: dict[str, Any]) -> dict[str, Any]:
  out = dict(raw)

  if "RCI" in out and isinstance(out.get("RCI"), dict):
    has_top_fields = all(k in out for k in ("cve_id", "fix_commit", "vuln_commit"))
    if not has_top_fields:
      out = dict(out["RCI"])

  anchor = out.get("anchor")
  if not isinstance(anchor, dict):
    anchor = {}
  context_window = anchor.get("context_window")
  if not isinstance(context_window, int):
    try:
      context_window = int(context_window)
    except Exception:
      context_window = 50
  anchor["context_window"] = context_window
  anchor["fuzzy_rules"] = _as_dict(anchor.get("fuzzy_rules"), list_key="rules")
  out["anchor"] = anchor

  out["trigger_conditions"] = _as_dict(out.get("trigger_conditions"), list_key="conditions")
  out["patch_logic"] = _as_dict(out.get("patch_logic"), list_key="steps")
  out["self_checks"] = _as_dict(out.get("self_checks"), list_key="checks")
  out["metadata"] = _as_dict(out.get("metadata"), list_key="items")
  out["root_cause"] = _as_dict(out.get("root_cause"), list_key="mechanism_steps")

  out["related_chunks"] = [str(x) for x in _as_list(out.get("related_chunks")) if str(x).strip()]
  out["evidence_pack"] = [x for x in _as_list(out.get("evidence_pack")) if isinstance(x, dict)]
  out["vuln_predicates"] = [x for x in _as_list(out.get("vuln_predicates")) if isinstance(x, dict)]
  out["fix_predicates"] = [x for x in _as_list(out.get("fix_predicates")) if isinstance(x, dict)]
  out["guards"] = [x for x in _as_list(out.get("guards")) if isinstance(x, dict)]

  confidence = out.get("confidence")
  if not isinstance(confidence, dict):
    confidence = {}
  comps = confidence.get("components")
  if not isinstance(comps, dict):
    comps = {}
  confidence["components"] = comps
  out["confidence"] = confidence

  return out


def _self_check_rci(
  rci: dict[str, Any],
  repo_path: str,
  fix_commit: str,
  vuln_commit: str,
) -> dict[str, Any]:
  """Validate RCI predicates against vuln_commit and fix_commit using native git.

  Also validates anchor_at_vuln when present: its file_paths should exist at
  vuln_commit, which is the primary use case of this anchor.

  Returns a dict with check results.  Failures here indicate the RCI may be
  unreliable and should be refined.
  """
  from vulnversion.git_ops.repo import GitRepo

  repo = GitRepo.open(repo_path)
  anchor = rci.get("anchor", {})
  file_paths = anchor.get("file_paths", [])[:4]
  anchor_at_vuln = rci.get("anchor_at_vuln", {})
  vuln_file_paths = anchor_at_vuln.get("file_paths", [])[:4]

  checks: dict[str, Any] = {
      "anchor_exists_at_vuln": False,
      "anchor_exists_at_fix": False,
      "anchor_at_vuln_validated": False,
      "anchor_at_vuln_present": bool(anchor_at_vuln and vuln_file_paths),
      "vuln_tokens_at_vuln": {},
      "fix_tokens_at_fix": {},
      "vuln_predicate_tokens_present": 0,
      "vuln_predicate_tokens_total": 0,
      "fix_predicate_tokens_present": 0,
      "fix_predicate_tokens_total": 0,
      "pass": False,
  }

  # Check anchor files (fix-commit paths) exist at vuln_commit
  for fp in file_paths:
    try:
      repo.show(vuln_commit, fp)
      checks["anchor_exists_at_vuln"] = True
      break
    except Exception:
      continue

  for fp in file_paths:
    try:
      repo.show(fix_commit, fp)
      checks["anchor_exists_at_fix"] = True
      break
    except Exception:
      continue

  # Validate anchor_at_vuln: its file_paths should exist at vuln_commit
  # (when files were renamed, anchor_at_vuln uses old names that exist at vuln_commit)
  if vuln_file_paths:
    for fp in vuln_file_paths:
      try:
        repo.show(vuln_commit, fp)
        checks["anchor_at_vuln_validated"] = True
        # If fix anchor was not found at vuln_commit but anchor_at_vuln is,
        # update anchor_exists_at_vuln (indicates a rename happened)
        if not checks["anchor_exists_at_vuln"]:
          checks["anchor_exists_at_vuln"] = True
          checks["anchor_found_via_anchor_at_vuln"] = True
        break
      except Exception:
        continue
  else:
    # No anchor_at_vuln provided — treat as trivially valid
    checks["anchor_at_vuln_validated"] = checks["anchor_exists_at_vuln"]

  def _extract_tokens_from_pred(pred: dict) -> list[str]:
    """Extract one or more checkable token strings from a predicate, regardless of kind.

    Handles all predicate kinds used in practice:
      token_all / token_any  → args.tokens  (list of strings)
      ordered_tokens         → args.pattern (list of strings; pick the first identifier-like)
      proximity              → args.tokens  (list of strings)
      regex                  → args.pattern (string; extract leading identifier word)
    """
    import re as _re
    args = pred.get("args", {})
    kind = pred.get("kind", "")

    # Primary: args.tokens (token_all, token_any, proximity)
    raw = args.get("tokens") or args.get("token")
    if raw:
      if isinstance(raw, str):
        return [raw]
      return [t for t in raw if isinstance(t, str) and t.strip()]

    # ordered_tokens / structured: args.pattern is a list of token fragments
    pattern = args.get("pattern") or args.get("patterns")
    if pattern is None:
      return []

    if isinstance(pattern, list):
      # ordered_tokens: list of token strings; pick the longest identifier-like ones (skip operators)
      idents = [t for t in pattern if isinstance(t, str) and _re.match(r'^[A-Za-z_]\w*$', t.strip())]
      return idents[:3] if idents else []

    if isinstance(pattern, str):
      # regex: extract the first identifier-like literal from the pattern
      # Remove anchors, quantifiers, lookaheads; keep alphabetic runs
      literals = _re.findall(r'[A-Za-z_]\w{3,}', pattern)
      # Prefer longer, non-generic tokens
      return [max(literals, key=len)][:1] if literals else []

    return []

  def _check_tokens(ref: str, tokens: list[str], present_dict: dict, total_key: str, present_key: str) -> None:
    for token in tokens[:3]:  # check at most 3 tokens per predicate
      if not token.strip():
        continue
      checks[total_key] += 1
      try:
        matches = repo.grep(ref, token)
        if matches:
          checks[present_key] += 1
          present_dict[token] = True
        else:
          present_dict[token] = False
      except Exception:
        present_dict[token] = False

  # Check vuln_predicate tokens at vuln_commit (should be present)
  for pred in rci.get("vuln_predicates", []):
    tokens = _extract_tokens_from_pred(pred)
    _check_tokens(
      vuln_commit, tokens,
      checks["vuln_tokens_at_vuln"],
      "vuln_predicate_tokens_total",
      "vuln_predicate_tokens_present",
    )

  # Check fix_predicate tokens at fix_commit (should be present)
  for pred in rci.get("fix_predicates", []):
    tokens = _extract_tokens_from_pred(pred)
    _check_tokens(
      fix_commit, tokens,
      checks["fix_tokens_at_fix"],
      "fix_predicate_tokens_total",
      "fix_predicate_tokens_present",
    )
  # Determine pass/fail
  vuln_ratio = (
      checks["vuln_predicate_tokens_present"] / checks["vuln_predicate_tokens_total"]
      if checks["vuln_predicate_tokens_total"] > 0
      else 0.0
  )
  fix_ratio = (
      checks["fix_predicate_tokens_present"] / checks["fix_predicate_tokens_total"]
      if checks["fix_predicate_tokens_total"] > 0
      else 0.0
  )
  checks["vuln_token_ratio"] = vuln_ratio
  checks["fix_token_ratio"] = fix_ratio
  # Pass when:
  # - anchor found at vuln_commit (via either anchor or anchor_at_vuln), AND
  # - vuln/fix predicate token ratios are acceptable (≥0.5)
  # Special case: if no tokens were extractable for a set (total=0), treat that
  # set as unverified (neutral, not fail) — the predicates may use formats
  # (regex/ordered_tokens) that don't expose simple tokens.
  vuln_ok = vuln_ratio >= 0.5 if checks["vuln_predicate_tokens_total"] > 0 else True
  fix_ok  = fix_ratio  >= 0.5 if checks["fix_predicate_tokens_total"]  > 0 else True
  checks["pass"] = (
      checks["anchor_exists_at_vuln"]
      and vuln_ok
      and fix_ok
  )

  return checks


def run_stage2(
  *,
  cve_id: str,
  repo_path: str,
  fix_commit: str,
  vuln_commit: str | None,
  cve_desc: str,
  cwe: list[str],
  artifacts_dir: str,
  patch_semantics_path: str | Path,
  repomaster_root: str | None = None,
  agent: AgentRuntime | None = None,
  session_id: str | None = None,
) -> dict[str, Any]:
  patch_semantics = _load_patch_semantics(patch_semantics_path)
  vuln = vuln_commit or f"{fix_commit}^"
  hints = build_navigation_hints(repo_path=repo_path, repomaster_root=repomaster_root)
  fix_commits = list(getattr(patch_semantics, "fix_commits", None) or []) or [fix_commit]

  if hints is not None:
    paths = Paths.from_root(Path.cwd(), artifacts_dir)
    out_dir = paths.ensure_dir(paths.cve_dir(cve_id))
    dump_json(out_dir / "repomaster_index.json", hints)

  paths = Paths.from_root(Path.cwd(), artifacts_dir)
  out_dir = paths.ensure_dir(paths.cve_dir(cve_id))
  step1_vet_seed = _load_step1_vet_seed_for_stage2(out_dir)
  if step1_vet_seed is not None:
    dump_json(out_dir / "step1_vet_seed.json", step1_vet_seed)
  try:
    rci_raw = induce_rci(
      agent=agent,
      session_id=session_id,
      cve_id=cve_id,
      repo_path=repo_path,
      fix_commit=fix_commit,
      fix_commits=fix_commits,
      vuln_commit=vuln,
      cve_desc=cve_desc,
      cwe=cwe,
      patch_semantics=patch_semantics,
      step1_vet_seed=step1_vet_seed,
      repomaster_hints=hints,
    )
  except OpenCodeJSONParseError as e:
    raw = (e.raw_text or "").strip()
    dump_json(
      out_dir / "rci_parse_invalid.json",
      {
        "cve_id": cve_id,
        "error": str(e),
        "error_type": type(e).__name__,
        "raw_preview": raw[:4000],
      },
    )
    (out_dir / "rci_parse_invalid.txt").write_text(raw or "(empty model text)", encoding="utf-8")
    raise RuntimeError(f"stage2_rci_parse_error: {e}") from e
  try:
    rci = RCIModel.model_validate(rci_raw).model_dump()
  except ValidationError:
    normalized = _normalize_rci_payload(rci_raw)
    try:
      rci = RCIModel.model_validate(normalized).model_dump()
    except ValidationError as e2:
      # Retry once with stricter output constraints.
      try:
        rci_retry_raw = induce_rci(
          agent=agent,
          session_id=session_id,
          cve_id=cve_id,
          repo_path=repo_path,
          fix_commit=fix_commit,
          fix_commits=fix_commits,
          vuln_commit=vuln,
          cve_desc=cve_desc,
          cwe=cwe,
          patch_semantics=patch_semantics,
          step1_vet_seed=step1_vet_seed,
          repomaster_hints=hints,
          strict_json_retry=True,
        )
      except OpenCodeJSONParseError as e3:
        raw = (e3.raw_text or "").strip()
        dump_json(
          out_dir / "rci_parse_invalid.json",
          {
            "cve_id": cve_id,
            "error": str(e3),
            "error_type": type(e3).__name__,
            "raw_preview": raw[:4000],
            "after": "schema_retry",
          },
        )
        (out_dir / "rci_parse_invalid.txt").write_text(raw or "(empty model text)", encoding="utf-8")
        dump_json(out_dir / "rci_raw_invalid.json", rci_raw)
        dump_json(out_dir / "rci_normalized_invalid.json", normalized)
        raise RuntimeError(f"stage2_rci_parse_error_after_schema_retry: {e3}") from e3

      retry_normalized = _normalize_rci_payload(rci_retry_raw)
      try:
        rci = RCIModel.model_validate(rci_retry_raw).model_dump()
      except ValidationError:
        try:
          rci = RCIModel.model_validate(retry_normalized).model_dump()
        except ValidationError as e4:
          dump_json(out_dir / "rci_raw_invalid.json", rci_retry_raw)
          dump_json(out_dir / "rci_normalized_invalid.json", retry_normalized)
          raise RuntimeError(f"stage2_rci_schema_error: {e4}") from e4

  out_path = out_dir / "rci.json"
  dump_json(out_path, rci)

  # ── Self-evaluation: validate RCI predicates against vuln/fix commits ──
  vuln = vuln_commit or f"{fix_commit}^"
  try:
    self_checks = _self_check_rci(rci, repo_path, fix_commit, vuln)
    rci["self_checks"] = self_checks
    dump_json(out_dir / "rci_self_check.json", self_checks)
    dump_json(out_path, rci)  # re-save with self_checks
  except Exception:
    pass  # self-check is best-effort; don't fail the pipeline

  return rci

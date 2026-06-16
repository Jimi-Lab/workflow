from __future__ import annotations

import json
from typing import Any

from vulnversion.agent_harness.base import AgentRuntime
from vulnversion.agent_harness.prompts import STAGE2_RCI_V0
from vulnversion.agent_harness.task import AgentTask
from vulnversion.stage1_semantic_aggregation.schema import PatchSemantics


def _prompt_for_rci(
  *,
  cve_id: str,
  repo_path: str,
  fix_commit: str,
  fix_commits: list[str],
  vuln_commit: str,
  cve_desc: str,
  cwe: list[str],
  patch_semantics: dict[str, Any],
  step1_vet_seed: dict[str, Any] | None,
  repomaster_hints: dict[str, Any] | None,
  strict_json_retry: bool = False,
) -> str:
  hints = repomaster_hints if repomaster_hints is not None else {}
  patch_semantics_text = json.dumps(patch_semantics, ensure_ascii=False, indent=2)[:120000]
  step1_vet_seed_text = json.dumps(step1_vet_seed or {}, ensure_ascii=False, indent=2)[:60000]
  hints_text = json.dumps(hints, ensure_ascii=False, indent=2)[:60000]
  lines = [
      "You are a navigation-based vulnerability theorem induction agent (RCI/VET).",
      "You must operate under strict read-only evidence rules and cite evidence snippets.",
      "Your output will be used for cross-version verification over many historical tags.",
      "Optimize for cross-version discriminative power, not just vuln_commit/fix_commit self-consistency.",
      "",
      f"cve_id: {cve_id}",
      f"repo_path: {repo_path}",
      f"fix_commit: {fix_commit}",
      f"fix_commits: {fix_commits}",
      f"vuln_commit: {vuln_commit}",
      f"cwe: {cwe}",
      "",
      "CVE description (evidence):",
      cve_desc.strip(),
      "",
      "Stage1 patch semantics JSON (evidence):",
      patch_semantics_text,
      "",
      "Step1 root-cause VET seed JSON (evidence; priority/prompt-context by default, not a hard certificate):",
      step1_vet_seed_text,
      "",
      "Optional navigation hints (NOT evidence):",
      hints_text,
      "",
      "Required behavior:",
      "- Navigate code at BOTH fix_commit AND vuln_commit using git_show/git_grep.",
      "- Define anchors suitable for cross-version matching at BOTH commit points.",
      "- Record any file renames between vuln_commit and fix_commit in known_renames.",
      "- Prefer predicates tied to the same file/function/block as the patch; avoid repo-wide generic tokens.",
      "- Produce executable vulnerability predicates and fix predicates using a simple DSL.",
      "- A NOT_AFFECTED decision in Stage3 must require strong evidence: explicit fix structure in the anchor region, or verified absence of the vulnerable feature after rename-aware search.",
      "- If a signal is generic, branch-local, weakly localized, or likely to appear in unaffected code, do NOT encode it as a fix_predicate; place it under metadata.weak_signals instead.",
      "- Include guards to avoid false positives and false negatives caused by refactors, file moves, alternative implementations, or feature gating.",
      "- Add self-checks: predicates should hold on vuln_commit and not hold on fix_commit, but do not confuse this with cross-version proof.",
      "- Think about branch-local backports and non-monotone release lines. If same-label interval inference is unsafe, record that explicitly in metadata.",
      "- Keep predicate count minimal. Prefer a few strong predicates over many weak ones.",
      "",
      "Output strictly as a single JSON object named RCI with keys:",
      "- cve_id, fix_commit, vuln_commit, related_chunks",
      "- anchor { file_paths[], function_names[], stable_tokens[], alternative_tokens[], context_window, fuzzy_rules }",
      "  anchor is based on fix_commit paths (current/latest paths).",
      "  anchor.context_window MUST be integer and anchor.fuzzy_rules MUST be object.",
      "  anchor.alternative_tokens: tokens that identify the vulnerable code across ALL versions",
      "  (including old versions before file renames — use generic identifiers).",
      "- anchor_at_vuln { file_paths[], function_names[], stable_tokens[], context_window, fuzzy_rules }",
      "  anchor_at_vuln is based on vuln_commit paths (may differ if file was renamed/split).",
      "  MUST reflect the actual file/function names at vuln_commit (use git_show to verify).",
      "  If paths are identical to anchor (no rename), copy anchor values.",
      "- known_renames[] — list of { old_path, new_path, rename_type, approximate_version }",
      "  for each file that was renamed/moved between vuln_commit and the current tree.",
      "  Use 'git log --follow --diff-filter=R' to detect renames if needed.",
      "- root_cause { summary, mechanism_steps[], vulnerability_type }",
      "- root_cause_vet MUST be an object for Step3 line relevance scheduling, not a hard verdict:",
      '  { "root_cause_summary": "...",',
      '    "root_cause_files": [{"pattern_id":"...","kind":"file","value":"...","scope_files":[],"strength":"weak|medium|strong","allowed_uses":["priority","prompt_context"],"evidence":[...],"notes":"..."}],',
      '    "root_cause_functions": [...],',
      '    "vulnerable_sequences": [...],',
      '    "fix_guards": [...],',
      '    "feature_introduction_clues": [...],',
      '    "component_scope": [...],',
      '    "negative_applicability_conditions": [...],',
      '    "grep_patterns": [...],',
      '    "git_log_sg_queries": [...],',
      '    "certificate_policy": {"default_use":"priority_only","cert_absent_requires":[...],"cert_fixed_requires":[...]},',
      '    "confidence": {...} }',
      "- For root_cause_vet, ordinary touched files and generic tokens MUST be strength=weak and allowed_uses must NOT include certificate_candidate.",
      "- Only localized root-cause files/functions/sequences verified by git_show/git_grep may be strength=strong.",
      "- Step3 may use root_cause_vet first for priority/risk only; do not claim a CERT_ABSENT or CERT_FIXED rule unless the evidence is explicit and localized.",
      "- vuln_predicates[] / fix_predicates[] / guards[] where each item is:",
      '  { "id": "...", "kind": "token_all|token_any|regex|ordered_tokens|proximity", "args": {...}, "scope": {...}, "evidence": [{"ref":"...","source":"git_show|git_grep|git_diff|cve_desc","snippet":"..."}] }',
      "  Do not emit a predicate unless its evidence is localized to the vulnerable mechanism.",
      "- trigger_conditions MUST be object",
      '  Prefer structure like { "requires": [...], "sufficient": [...], "notes": "..." } when relevant.',
      "- patch_logic MUST be object",
      "- evidence_pack MUST be array of objects",
      "- self_checks MUST be object",
      '- metadata MUST be object and SHOULD include { "negative_prefilter_safe": bool, "same_label_bisect_safe": bool,',
      '  "line_local_fix_required": bool, "preferred_stage3_mode": "direct_probe|prefilter_then_probe|bisect_allowed|full_scan",',
      '  "risk_flags": [str], "weak_signals": [object], "sentinel_probe_plan": [object] }',
      "- confidence { total, components } where components is object",
      "  confidence.components.discriminative_power MUST reflect historical tag separation difficulty, not just commit-local fit.",
  ]

  if strict_json_retry:
    lines.extend(
      [
        "",
        "STRICT JSON RETRY MODE (must follow exactly):",
        "- Return ONE JSON object only. No markdown, no code fences, no prose.",
        "- Do NOT output tool-call pseudo tags like <bash>, <tool_call>, or XML.",
        "- Do NOT include trailing commas.",
        "- Ensure required top-level keys exist: cve_id, fix_commit, vuln_commit.",
      ]
    )

  return "\n".join(lines)


def induce_rci(
  *,
  agent: AgentRuntime | None,
  session_id: str | None,
  cve_id: str,
  repo_path: str,
  fix_commit: str,
  fix_commits: list[str] | None,
  vuln_commit: str,
  cve_desc: str,
  cwe: list[str],
  patch_semantics: PatchSemantics,
  step1_vet_seed: dict[str, Any] | None = None,
  repomaster_hints: dict[str, Any] | None,
  strict_json_retry: bool = False,
) -> dict[str, Any]:
  seed = step1_vet_seed if isinstance(step1_vet_seed, dict) else None
  if agent is None or session_id is None:
    return {
      "cve_id": cve_id,
      "fix_commit": fix_commit,
      "vuln_commit": vuln_commit,
      "related_chunks": [c.chunk_id for c in patch_semantics.all_chunks],
      "anchor": {"file_paths": [], "function_names": [], "stable_tokens": [], "context_window": 50, "fuzzy_rules": {}},
      "root_cause": {"summary": "", "mechanism_steps": [], "vulnerability_type": ""},
      "root_cause_vet": seed or {
        "cve_id": cve_id,
        "repo": "",
        "root_cause_summary": "",
        "root_cause_files": [],
        "root_cause_functions": [],
        "vulnerable_sequences": [],
        "fix_guards": [],
        "feature_introduction_clues": [],
        "component_scope": [],
        "negative_applicability_conditions": [],
        "grep_patterns": [],
        "git_log_sg_queries": [],
        "certificate_policy": {
          "default_use": "priority_only",
          "cert_absent_requires": [
            "strong root_cause_file/function evidence",
            "strong feature absence evidence",
          ],
          "cert_fixed_requires": [
            "strong fix_guard evidence",
            "strong vulnerable_sequence absence evidence",
          ],
        },
        "confidence": {},
      },
      "vuln_predicates": [],
      "fix_predicates": [],
      "guards": [],
      "trigger_conditions": {},
      "patch_logic": {},
      "evidence_pack": [],
      "confidence": {"total": 0.0, "components": {}},
      "self_checks": {"error": "no_opencode_agent"},
      "metadata": {"step1_vet_seed_consumed": bool(seed)},
    }

  resolved_fix_commits = fix_commits or list(getattr(patch_semantics, "fix_commits", None) or []) or [fix_commit]
  prompt = _prompt_for_rci(
    cve_id=cve_id,
    repo_path=repo_path,
    fix_commit=fix_commit,
    fix_commits=resolved_fix_commits,
    vuln_commit=vuln_commit,
    cve_desc=cve_desc,
    cwe=cwe,
    patch_semantics=patch_semantics.model_dump(),
    step1_vet_seed=seed,
    repomaster_hints=repomaster_hints,
    strict_json_retry=strict_json_retry,
  )
  task = AgentTask(
    stage="stage2",
    task_type="rci_induction",
    cve_id=cve_id,
    repo_path=repo_path,
    prompt=prompt,
    session_id=session_id,
    prompt_name=STAGE2_RCI_V0.name,
    prompt_version=STAGE2_RCI_V0.version,
    schema_name=STAGE2_RCI_V0.schema_name,
    prompt_builder=STAGE2_RCI_V0.builder,
    judgement_only=True,
    forbidden_context=["tag_plan", "early_stop", "gt_affected_tags", "affected_range"],
    metadata={
      "fix_commit": fix_commit,
      "vuln_commit": vuln_commit,
      "strict_json_retry": strict_json_retry,
    },
  )
  run_task = getattr(agent, "run_task", None)
  if callable(run_task):
    return run_task(task).parsed
  return agent.run_json(
    session_id=session_id,
    prompt=prompt,
    metadata={
      "stage": "stage2",
      "task_type": "rci_induction",
      **STAGE2_RCI_V0.trace_metadata(),
      "cve_id": cve_id,
      "repo_path": repo_path,
      "fix_commit": fix_commit,
      "vuln_commit": vuln_commit,
      "strict_json_retry": strict_json_retry,
      "judgement_only": True,
      "forbidden_context": ["tag_plan", "early_stop", "gt_affected_tags", "affected_range"],
    },
  )

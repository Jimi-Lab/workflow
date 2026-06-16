from __future__ import annotations

import csv
import json
from pathlib import Path
import re
import subprocess
from typing import Any, cast

from vulnversion.agent_harness.base import AgentRuntime
from vulnversion.agent_harness.prompts import STAGE3_VERDICT_V0, STAGE3_VERDICT_V1
from vulnversion.agent_harness.task import AgentTask
from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.artifact_eval import evaluate_step3_output
from vulnversion.stage3_verify.asbs_line import (
  FIXED_SEG_SENTINEL,
  NN_SENTINEL_COUNT,
  AA_SENTINEL_COUNT,
  ASBSResult,
  run_asbs_segment,
  run_fixed_segment_sentinel,
)
from vulnversion.stage3_verify.git_reachability import batch_tags_containing
from vulnversion.stage3_verify.line_scheduler import (
  LineRunResult,
  compute_seed_lines,
  run_staged_scheduler,
  _ordered_by_family,
)
from vulnversion.stage3_verify.plan_tags import build_tag_plan, write_tag_plan
from vulnversion.stage3_verify.schema import TagVerdict


# ---------------------------------------------------------------------------
# System prompt — sets the Agent's role as a git + security expert
# ---------------------------------------------------------------------------

GIT_EXPERT_SYSTEM_PROMPT = """\
You are a senior security researcher **and** git power-user.
Your sole job is to examine source code at a specific git tag and determine
whether a known vulnerability exists in that version.

Core competencies you MUST demonstrate:
• Fluent use of `git show <ref>:<path>`, `git grep`, `git ls-tree`,
  `git log`, `git diff`, and `git cat-file` to navigate repository history.
• Deep understanding of C / C++ / Python / Java vulnerability patterns
  (buffer overflow, use-after-free, integer overflow, injection, etc.).
• Strict evidence-based reasoning: every claim must cite actual code read
  via git commands. Never speculate based on version numbers or dates.
• Conservative negative reasoning: `NOT_AFFECTED` requires stronger evidence
  than `AFFECTED`.

Behavioural rules:
1. You operate in **read-only** mode — no editing or building code. You MUST use the `bash` tool to execute all your `git` commands.
2. You are deciding **one tag only**. Do NOT rely on neighboring tags,
   monotonicity assumptions, release chronology, or advisory version ranges.
3. You quote the exact code lines that support your verdict.
4. You respond with a single JSON object — no extra commentary outside it.
"""


def _load_rci(path: str | Path | None) -> dict[str, Any]:
  if path is None:
    return {}
  return json.loads(Path(path).read_text(encoding="utf-8"))

def _is_tool_crash_error(e: BaseException) -> bool:
  """Detect OpenCode JS tool-layer crash (e.g. 'text9.split is not a function')."""
  msg = str(e).lower()
  return "text9.split" in msg or "is not a function" in msg


def _error_verdict(*, tag: str, line: str | None, source: str, error: BaseException) -> TagVerdict:
  msg = f"{type(error).__name__}: {error}"
  # Give a named summary so callers can detect tool-layer crashes in reports
  if _is_tool_crash_error(error):
    summary = "opencode_tool_crash: git tool returned non-string output (text9.split). Upgrade OpenCode."
  else:
    summary = f"tag_error: {type(error).__name__}"
  return TagVerdict(
    tag=tag,
    line=line,
    verdict=None,
    run_status="AGENT_ERROR",
    confidence=0.0,
    matched_predicates=[],
    failed_predicates=[],
    triggered_guards=[],
    evidence_snippets=[{"ref": tag, "source": source, "snippet": msg[:2000]}],
    reasoning_summary=summary,
    verdict_source="agent_error",
  )


def _timeout_verdict(*, tag: str, line: str | None, timeout_s: float) -> TagVerdict:
  return TagVerdict(
    tag=tag,
    line=line,
    verdict=None,
    run_status="TIMEOUT",
    confidence=0.0,
    matched_predicates=[],
    failed_predicates=[],
    triggered_guards=[],
    evidence_snippets=[{"ref": tag, "source": "tag_timeout", "snippet": f"tag_timeout_s={timeout_s}"}],
    reasoning_summary="tag_timeout",
    verdict_source="agent_error",
  )


def _update_line_discoveries(
  line_discoveries: dict[str, Any],
  verdict: "TagVerdict",
  rci: dict[str, Any],
) -> None:
  """Extract file-path discoveries from a verdict and update the line cache."""
  del rci
  for ev in (verdict.evidence_snippets or []):
    ref = str(ev.get("ref") or "")
    snippet = str(ev.get("snippet") or "").lower()
    if ":" not in ref:
      continue
    parts = ref.split(":", 2)
    if len(parts) < 2:
      continue
    path = parts[1].strip()
    if not path or "/" not in path:
      continue
    # Negative cache: evidence explicitly says file not found
    if any(kw in snippet for kw in ("not found", "does not exist", "missing", "no such")):
      absent = line_discoveries.setdefault("absent_paths", [])
      if path not in absent:
        absent.append(path)
    else:
      confirmed = line_discoveries.setdefault("confirmed_paths", {})
      if path not in confirmed:
        confirmed[path] = {"found_at": verdict.tag, "confidence": 0.9}

  if verdict.verdict in ("AFFECTED", "NOT_AFFECTED"):
    line_discoveries["last_verdict"] = verdict.verdict
    line_discoveries["last_verdict_tag"] = verdict.tag


def _normalize_predicate_ids(value: Any) -> list[str]:
  if value is None:
    return []
  items = value if isinstance(value, list) else [value]
  out: list[str] = []
  for item in items:
    if isinstance(item, str):
      s = item.strip()
      if s:
        out.append(s)
      continue
    if isinstance(item, dict):
      s = str(item.get("id") or item.get("predicate_id") or item.get("reason") or "").strip()
      if s:
        out.append(s)
  return out


def _normalize_tag_verdict_raw(raw: dict[str, Any], *, fallback_tag: str) -> dict[str, Any]:
  v = dict(raw)
  v["tag"] = str(v.get("tag") or fallback_tag)
  verdict = v.get("verdict")
  if isinstance(verdict, str):
    verdict = verdict.strip().upper()
  if verdict not in {"AFFECTED", "NOT_AFFECTED"}:
    verdict = None
  v["verdict"] = verdict
  v["run_status"] = str(v.get("run_status") or ("OK" if verdict else "PARSE_ERROR")).upper()
  try:
    v["confidence"] = float(v.get("confidence") or 0.0)
  except Exception:
    v["confidence"] = 0.0
  v["matched_predicates"] = _normalize_predicate_ids(v.get("matched_predicates"))
  v["failed_predicates"] = _normalize_predicate_ids(v.get("failed_predicates"))
  v["triggered_guards"] = _normalize_predicate_ids(v.get("triggered_guards"))
  ev = v.get("evidence_snippets")
  if isinstance(ev, list):
    v["evidence_snippets"] = [x for x in ev if isinstance(x, dict)]
  elif isinstance(ev, dict):
    v["evidence_snippets"] = [ev]
  else:
    v["evidence_snippets"] = []
  v["reasoning_summary"] = str(v.get("reasoning_summary") or "")
  return v


def _build_navigation_prompt(
  *,
  cve_id: str,
  tag: str,
  line: str,
  rci: dict[str, Any],
  line_context: dict[str, Any] | None = None,
) -> str:
  """Build the tag-level agent prompt for the current Step3 pipeline.

  Step3 planning is handled deterministically by VulnTree, git reachability,
  line scheduling, and ASBS. This prompt is deliberately limited to one task:
  inspect code at the requested tag and return AFFECTED or NOT_AFFECTED.
  Evidence files are optional context only; they must not act as planning inputs
  or as automatic fix predicates.
  """
  lines = [
    f"# Task: Verify whether tag `{tag}` is affected by {cve_id}",
    "",
    f"Release line: `{line}`",
    f"Target tag: `{tag}`",
    "",
    "You are judging this tag only. The scheduler may have selected this tag",
    "because it is an endpoint, sentinel, or binary-search probe, but that",
    "selection reason is not evidence of vulnerability by itself.",
    "",
  ]

  context_items: list[str] = []
  for key in (
    "cve_description",
    "description",
    "summary",
    "patch_semantics_summary",
    "patch_summary",
    "vulnerability_summary",
  ):
    value = rci.get(key)
    if value:
      context_items.append(f"{key}: {str(value)[:2000]}")
  patch_semantics = rci.get("patch_semantics")
  if isinstance(patch_semantics, dict):
    context_items.append("patch_semantics: " + json.dumps(patch_semantics, ensure_ascii=False)[:4000])
  if context_items:
    lines.extend(["## Optional Evidence Context", ""])
    lines.extend(context_items)
    lines.append("")

  if line_context:
    scheduler_fields = {
      "scheduler_strategy": line_context.get("scheduler_strategy"),
      "frontier_source": line_context.get("frontier_source"),
      "task_mode": line_context.get("task_mode"),
      "probe_role": line_context.get("probe_role"),
      "line_candidate_count": line_context.get("line_candidate_count"),
    }
    visible_fields = {k: v for k, v in scheduler_fields.items() if v is not None and v != ""}
    if visible_fields:
      lines.extend([
        "## Scheduler Context (not verdict evidence)",
        "",
        json.dumps(visible_fields, ensure_ascii=False, indent=2),
        "",
      ])
    discovered_paths = line_context.get("discovered_paths")
    if discovered_paths:
      lines.extend([
        "## Previously Confirmed Paths On This Line",
        "",
        "These paths were observed in earlier probes on the same release line.",
        "Use them as search hints only; still judge the current tag from code.",
      ])
      for dp in discovered_paths[:5]:
        lines.append(f"- `{dp}`")
      lines.append("")

  lines.extend([
    "## How To Inspect This Tag",
    "",
    "Use git commands against the target tag. Do not inspect working-tree files.",
    "",
    "```bash",
    f"git show {tag}:<filepath>",
    f"git grep -n '<symbol-or-token>' {tag}",
    f"git grep -n -C 3 '<symbol-or-token>' {tag}",
    f"git ls-tree -r --name-only {tag}",
    f"git log --oneline {tag} -- <filepath>",
    "```",
    "",
    "## Decision Policy",
    "",
    "- Return AFFECTED only when the vulnerable behavior is present in code at this tag.",
    "- Return NOT_AFFECTED only when code evidence shows the vulnerable behavior is absent or mitigated at this tag.",
    "- Do not use release order, neighboring tag verdicts, advisory ranges, or scheduler decisions as verdict evidence.",
    "- Do not treat the mere presence of a fix commit, a generic token, or a missing token as automatic proof.",
    "- If evidence is weak or conflicting, choose the verdict best supported by code and lower confidence.",
    "",
    "## Output Format",
    "",
    "Output exactly one JSON object:",
    "",
    "{",
    f'  "tag": "{tag}",',
    f'  "line": "{line}",',
    '  "verdict": "AFFECTED | NOT_AFFECTED",',
    '  "run_status": "OK",',
    '  "confidence": 0.0,',
    '  "matched_predicates": [],',
    '  "failed_predicates": [],',
    '  "triggered_guards": [],',
    '  "evidence_snippets": [{"ref": "<tag>:<file>:<line>", "source": "git_show|git_grep", "snippet": "<actual code>"}],',
    '  "reasoning_summary": "Brief code-grounded explanation"',
    "}",
  ])
  return "\n".join(lines)


def _json_excerpt(value: Any, *, limit: int) -> str:
  if value is None:
    return "null"
  text = json.dumps(value, ensure_ascii=False, indent=2)
  if len(text) <= limit:
    return text
  return text[:limit] + "\n...<truncated>"


def _rci_section(rci: dict[str, Any], key: str, *, limit: int) -> list[str]:
  value = rci.get(key)
  if value in (None, "", [], {}):
    return []
  return [f"### {key}", "", _json_excerpt(value, limit=limit), ""]


def _compact_root_cause(root_cause: Any) -> dict[str, Any] | str:
  if not isinstance(root_cause, dict):
    return str(root_cause)[:1200]
  out: dict[str, Any] = {}
  for key in ("summary", "vulnerability_type"):
    if root_cause.get(key):
      out[key] = root_cause.get(key)
  steps = root_cause.get("mechanism_steps")
  if isinstance(steps, list) and steps:
    out["mechanism_steps"] = steps[:3]
  return out


def _compact_anchor(rci: dict[str, Any]) -> dict[str, Any]:
  anchor = rci.get("anchor") if isinstance(rci.get("anchor"), dict) else {}
  anchor_at_vuln = rci.get("anchor_at_vuln") if isinstance(rci.get("anchor_at_vuln"), dict) else {}

  def _merged_list(key: str, limit: int) -> list[Any]:
    values: list[Any] = []
    for src in (anchor, anchor_at_vuln):
      raw = src.get(key)
      if isinstance(raw, list):
        for item in raw:
          if item not in values:
            values.append(item)
    return values[:limit]

  out: dict[str, Any] = {
    "candidate_paths": _merged_list("file_paths", 6),
    "functions": _merged_list("function_names", 8),
    "stable_tokens": _merged_list("stable_tokens", 10),
    "alternative_tokens": _merged_list("alternative_tokens", 6),
  }
  known_renames = rci.get("known_renames")
  if known_renames:
    out["known_renames"] = known_renames
  return {k: v for k, v in out.items() if v not in (None, "", [], {})}


def _compact_predicate(pred: dict[str, Any]) -> dict[str, Any]:
  args = pred.get("args") if isinstance(pred.get("args"), dict) else {}
  compact_args: dict[str, Any] = {}
  for key in ("tokens", "pattern", "max_gap_lines", "order_strict", "same_block"):
    if args.get(key) not in (None, "", [], {}):
      compact_args[key] = args.get(key)
  out: dict[str, Any] = {
    "id": pred.get("id"),
    "kind": pred.get("kind"),
    "args": compact_args,
    "scope": pred.get("scope"),
  }
  return {k: v for k, v in out.items() if v not in (None, "", [], {})}


def _compact_predicates(rci: dict[str, Any], key: str, *, limit: int = 8) -> list[dict[str, Any]]:
  raw = rci.get(key)
  if not isinstance(raw, list):
    return []
  return [_compact_predicate(p) for p in raw[:limit] if isinstance(p, dict)]


def _build_target_tag_theorem_prompt(
  *,
  cve_id: str,
  tag: str,
  line: str,
  repo_path: str,
  rci: dict[str, Any],
  line_context: dict[str, Any] | None = None,
) -> str:
  """Build the Stage3 v1 target-tag theorem checking prompt.

  The agent still has git access and must inspect the target tag by itself.
  The prompt narrows the task from broad repository navigation to checking
  whether the Step2 vulnerability theorem holds in this one tag.
  """

  repo_path_for_git = repo_path.replace("\\", "/")
  theorem = {
    "root_cause": _compact_root_cause(rci.get("root_cause") or rci.get("summary") or ""),
    "anchor": _compact_anchor(rci),
    "vuln_predicates": _compact_predicates(rci, "vuln_predicates"),
    "fix_predicates": _compact_predicates(rci, "fix_predicates"),
    "guards": _compact_predicates(rci, "guards", limit=6),
  }
  if rci.get("patch_logic"):
    patch_logic = rci.get("patch_logic")
    if isinstance(patch_logic, dict):
      theorem["patch_logic"] = {
        k: patch_logic.get(k)
        for k in ("before", "after", "invariant")
        if patch_logic.get(k) not in (None, "", [], {})
      }
    else:
      theorem["patch_logic"] = str(patch_logic)[:1200]

  lines = [
    f"# Task: Target-tag theorem judge for {cve_id}",
    "",
    f"Repository path: `{repo_path_for_git}`",
    f"Target tag: `{tag}`",
    f"Release line label: `{line}`",
    "",
    "You judge only whether the target tag satisfies the Step2 vulnerability existence theorem.",
    "You may use git tools, but every command must serve this target-tag theorem check.",
    "",
    "## Non-negotiable Boundary",
    "",
    "- Do not plan tags, scan order, early stop, or affected ranges.",
    "- Do not infer the verdict from neighboring tags, advisory ranges, release chronology, or scheduler state.",
    "- Do not use GT affected tags or affected ranges as evidence.",
    "- The final verdict must be based on source evidence from the current target tag.",
    f"- Every git command MUST target the repository path with `git -C \"{repo_path_for_git}\" ...`.",
    "- Do not run git in the VulnVersion project root unless that root is the target repository.",
    "- `git grep` may locate candidates, but it is not final evidence until you read local context with `git show` or equivalent.",
    "",
    "## Step2 Vulnerability Existence Theorem",
    "",
    "Use this compact RCI theorem to check the target tag. It is context, not proof that this tag is affected.",
    "",
    _json_excerpt(theorem, limit=4200),
    "",
  ]

  metadata = rci.get("metadata")
  if isinstance(metadata, dict):
    focused_metadata = {
      "risk_flags": metadata.get("risk_flags"),
      "preferred_stage3_mode": metadata.get("preferred_stage3_mode"),
    }
    focused_metadata = {k: v for k, v in focused_metadata.items() if v not in (None, "", [], {})}
    if focused_metadata:
      lines.extend(["### metadata_for_judging", "", _json_excerpt(focused_metadata, limit=700), ""])

  if line_context:
    hint_fields = {
      "discovered_paths": line_context.get("discovered_paths"),
      "anchor_relocated": line_context.get("anchor_relocated"),
    }
    hint_fields = {k: v for k, v in hint_fields.items() if v not in (None, "", [], {})}
    if hint_fields:
      lines.extend([
        "## Line-local Search Hints (not verdict evidence)",
        "",
        _json_excerpt(hint_fields, limit=1000),
        "",
      ])

  lines.extend([
    "## Required Target-tag Workflow",
    "",
    "1. Start from the RCI anchor file/function/tokens.",
    f"2. Read the target tag snapshot with `git -C \"{repo_path_for_git}\" show {tag}:<path>` whenever a candidate path is known.",
    "3. If the path is missing, do at most one bounded relocation with anchor tokens; do not inspect the VulnVersion root repo.",
    "4. Check vuln_predicates in the same local scope as the root cause.",
    "5. Check fix_predicates and guards in that same local scope.",
    "6. Decide whether the theorem holds in this target tag.",
    "",
    "## Git Search Policy",
    "",
    "Preferred commands:",
    "",
    "```bash",
    f"git -C \"{repo_path_for_git}\" show {tag}:<known_path>",
    f"git -C \"{repo_path_for_git}\" grep -F -n '<specific-anchor-or-predicate-token>' {tag} -- <likely_path_or_dir>",
    f"git -C \"{repo_path_for_git}\" grep -n -C 5 '<specific-pattern>' {tag} -- <likely_path_or_dir>",
    f"git -C \"{repo_path_for_git}\" ls-tree --name-only {tag} <likely_dir>",
    "```",
    "",
    "Allowed fallback when path/anchor is missing:",
    "",
    "```bash",
    f"git -C \"{repo_path_for_git}\" grep -F -n '<anchor-function-or-rare-token>' {tag}",
    f"git -C \"{repo_path_for_git}\" log --follow --name-status -- <path>",
    "```",
    "",
    "Avoid broad repo-wide searches with generic tokens. If you must do one fallback search, explain why it was necessary.",
    "",
    "## Verdict Rule",
    "",
    "- AFFECTED: the target tag contains the vulnerable mechanism described by root_cause and the required vuln_predicates hold in the local source context, with no effective fix/guard blocking the mechanism.",
    "- NOT_AFFECTED: the vulnerable mechanism is absent after bounded target-tag search, or an effective fix/guard is present in the local source context and blocks the root cause.",
    "- If evidence is incomplete or conflicting, choose the lower-confidence verdict supported by current-tag source evidence; do not invent an affected-range inference.",
    "",
    "## Output Format",
    "",
    "Output exactly one JSON object:",
    "",
    "{",
    f'  "tag": "{tag}",',
    f'  "line": "{line}",',
    '  "verdict": "AFFECTED | NOT_AFFECTED",',
    '  "run_status": "OK",',
    '  "confidence": 0.0,',
    '  "matched_predicates": [],',
    '  "failed_predicates": [],',
    '  "triggered_guards": [],',
    '  "evidence_snippets": [{"ref": "<tag>:<file>:<line>", "source": "git_show|git_grep|git_ls_tree|git_log", "snippet": "<actual evidence>"}],',
    '  "reasoning_summary": "Brief theorem-check explanation grounded in target-tag source evidence"',
    "}",
  ])
  return "\n".join(lines)


def _stage3_prompt_spec(prompt_version: str):
  normalized = (prompt_version or "v1").strip().lower()
  if normalized == "v0":
    return STAGE3_VERDICT_V0
  if normalized == "v1":
    return STAGE3_VERDICT_V1
  raise ValueError(f"unsupported_stage3_prompt_version: {prompt_version}")


def _build_stage3_prompt(
  *,
  cve_id: str,
  tag: str,
  line: str,
  repo_path: str,
  rci: dict[str, Any],
  line_context: dict[str, Any] | None,
  prompt_version: str,
) -> tuple[str, Any]:
  spec = _stage3_prompt_spec(prompt_version)
  if spec.version == "v1":
    return (
      _build_target_tag_theorem_prompt(
        cve_id=cve_id,
        tag=tag,
        line=line,
        repo_path=repo_path,
        rci=rci,
        line_context=line_context,
      ),
      spec,
    )
  return (
    _build_navigation_prompt(
      cve_id=cve_id,
      tag=tag,
      line=line,
      rci=rci,
      line_context=line_context,
    ),
    spec,
  )


# ---------------------------------------------------------------------------
# Single-tag LLM verification (extracted for reuse by binary search)
# ---------------------------------------------------------------------------

def _verify_single_tag_llm(
  *,
  repo: GitRepo,
  agent: AgentRuntime,
  cve_id: str,
  tag: str,
  line: str,
  rci: dict[str, Any],
  line_discoveries: dict[str, Any],
  line_context: dict[str, Any],
  per_tag_session: bool,
  session_id: str | None,
  tag_timeout_s: float,
  log_progress: bool,
  stage3_prompt_version: str = "v1",
) -> TagVerdict:
  """Run LLM verification for a single tag.  Returns a TagVerdict.

  This is the Step3 tag-verdict path. Planning is deterministic; the agent
  only reads code at this tag and returns AFFECTED or NOT_AFFECTED.
  """
  if per_tag_session:
    try:
      tag_session_id = agent.create_readonly_session(
        title=f"VulnVersion-stage3-{cve_id}-{tag}",
      )
    except Exception as e:
      return _error_verdict(tag=tag, line=line, source="session_create_error", error=e)
  else:
    tag_session_id = cast(str, session_id)

  try:
    prompt, prompt_spec = _build_stage3_prompt(
      cve_id=cve_id, tag=tag, line=line, rci=rci,
      repo_path=str(repo.repo_path),
      line_context=line_context,
      prompt_version=stage3_prompt_version,
    )
    agent_mode = "target_tag_theorem_judge" if prompt_spec.version == "v1" else "legacy_navigation"
    search_policy = "target_tag_scoped_git" if prompt_spec.version == "v1" else "legacy_navigation_git"
    prompt_lifecycle = "candidate" if prompt_spec.version == "v1" else "deprecated_baseline"
    task = AgentTask(
      stage="stage3",
      task_type="tag_verdict",
      cve_id=cve_id,
      repo_path=str(repo.repo_path),
      prompt=prompt,
      session_id=tag_session_id,
      system=GIT_EXPERT_SYSTEM_PROMPT,
      timeout_s=float(tag_timeout_s),
      prompt_name=prompt_spec.name,
      prompt_version=prompt_spec.version,
      schema_name=prompt_spec.schema_name,
      prompt_builder=prompt_spec.builder,
      judgement_only=True,
      forbidden_context=[
        "tag_plan",
        "scan_order",
        "early_stop",
        "gt_affected_tags",
        "affected_range",
        "neighbor_tag_verdicts",
      ],
      metadata={
        "tag": tag,
        "line": line,
        "per_tag_session": per_tag_session,
        "anchor_relocated": bool(line_context.get("anchor_relocated")) if isinstance(line_context, dict) else False,
        "agent_mode": agent_mode,
        "search_policy": search_policy,
        "prompt_lifecycle": prompt_lifecycle,
      },
    )
    run_task = getattr(agent, "run_task", None)
    if callable(run_task):
      raw = run_task(task).parsed
    else:
      raw = agent.run_json(
        session_id=tag_session_id,
        prompt=prompt,
        system=GIT_EXPERT_SYSTEM_PROMPT,
        timeout_s=float(tag_timeout_s),
        metadata={
          "stage": "stage3",
          "task_type": "tag_verdict",
          **prompt_spec.trace_metadata(),
          "cve_id": cve_id,
          "repo_path": str(repo.repo_path),
          "tag": tag,
          "line": line,
          "per_tag_session": per_tag_session,
          "anchor_relocated": bool(line_context.get("anchor_relocated")) if isinstance(line_context, dict) else False,
          "agent_mode": agent_mode,
          "search_policy": search_policy,
          "prompt_lifecycle": prompt_lifecycle,
          "judgement_only": True,
          "forbidden_context": [
            "tag_plan",
            "scan_order",
            "early_stop",
            "gt_affected_tags",
            "affected_range",
            "neighbor_tag_verdicts",
          ],
        },
      )
    normalized = _normalize_tag_verdict_raw(raw, fallback_tag=tag)
    normalized["line"] = line
    return TagVerdict.model_validate(normalized)
  except TimeoutError:
    return _timeout_verdict(tag=tag, line=line, timeout_s=float(tag_timeout_s))
  except BaseException as e:
    return _error_verdict(tag=tag, line=line, source="agent_error", error=e)


def _write_verdict(out_jsonl: Path, verdict: TagVerdict) -> None:
  with out_jsonl.open("a", encoding="utf-8") as f:
    f.write(json.dumps(verdict.model_dump(), ensure_ascii=False) + "\n")


def _read_existing_verdicts(out_jsonl: Path) -> dict[str, TagVerdict]:
  existing: dict[str, TagVerdict] = {}
  if not out_jsonl.exists():
    return existing
  for line in out_jsonl.read_text(encoding="utf-8").splitlines():
    if not line.strip():
      continue
    try:
      verdict = TagVerdict.model_validate(json.loads(line))
      existing[verdict.tag] = verdict
    except Exception:
      continue
  return existing


def _probe_tag_agent_only(
  *,
  repo: GitRepo,
  agent: AgentRuntime,
  cve_id: str,
  tag: str,
  line: str,
  evidence: dict[str, Any],
  line_discoveries: dict[str, Any],
  line_context: dict[str, Any],
  per_tag_session: bool,
  session_id: str | None,
  tag_timeout_s: float,
  log_progress: bool,
  out_jsonl: Path,
  probe_cache: dict[str, TagVerdict],
  stage3_prompt_version: str = "v1",
) -> TagVerdict:
  """Probe one tag through the agent-only verifier path.

  This is the default Step3 path used by the new scheduler. It intentionally
  skips legacy RCI token prefilter and path-relocation planning logic.
  The optional evidence object is passed only as prompt context.
  """
  if tag in probe_cache:
    return probe_cache[tag]
  try:
    repo.rev_parse(tag)
  except Exception as e:
    verdict = _error_verdict(tag=tag, line=line, source="invalid_tag", error=e)
    probe_cache[tag] = verdict
    _write_verdict(out_jsonl, verdict)
    return verdict

  verdict = _verify_single_tag_llm(
    repo=repo,
    agent=agent,
    cve_id=cve_id,
    tag=tag,
    line=line,
    rci=evidence,
    line_discoveries=line_discoveries,
    line_context=line_context,
    per_tag_session=per_tag_session,
    session_id=session_id,
    tag_timeout_s=tag_timeout_s,
    log_progress=log_progress,
    stage3_prompt_version=stage3_prompt_version,
  )
  if verdict.verdict_source is None:
    verdict.verdict_source = "agent" if verdict.run_status in ("OK", "PARTIAL_PARSE") else "agent_error"
  if verdict.run_status in ("OK", "PARTIAL_PARSE"):
    _update_line_discoveries(line_discoveries, verdict, evidence)
    if line_discoveries.get("confirmed_paths"):
      line_context["discovered_paths"] = sorted(line_discoveries["confirmed_paths"].keys())
  probe_cache[tag] = verdict
  _write_verdict(out_jsonl, verdict)
  return verdict


def _flatten_fix_commits(value: Any) -> list[str]:
  commits: list[str] = []
  if isinstance(value, list):
    for item in value:
      if isinstance(item, list):
        commits.extend(str(x) for x in item if x)
      elif item:
        commits.append(str(item))
  elif value:
    commits.append(str(value))
  seen: set[str] = set()
  out: list[str] = []
  for commit in commits:
    if commit in seen:
      continue
    seen.add(commit)
    out.append(commit)
  return out


def _fix_commits_from_plan(tag_plan: dict[str, Any]) -> list[str]:
  commits: list[str] = []
  for family in tag_plan.get("fix_families") or []:
    for commit_rec in family.get("commits") or []:
      sha = commit_rec.get("sha") if isinstance(commit_rec, dict) else commit_rec
      if sha:
        commits.append(str(sha))
  if commits:
    return _flatten_fix_commits(commits)
  cluster_commits: list[str] = []
  for cluster in tag_plan.get("fix_clusters") or []:
    cluster_commits.extend(str(c) for c in (cluster.get("commits") or []) if c)
  return _flatten_fix_commits(cluster_commits)


def _release_lines_from_plan(tag_plan: dict[str, Any]) -> dict[str, list[str]]:
  out: dict[str, list[str]] = {}
  for line, entry in (tag_plan.get("release_lines") or {}).items():
    if isinstance(entry, dict):
      out[str(line)] = list(entry.get("tags") or [])
    elif isinstance(entry, list):
      out[str(line)] = list(entry)
  return out


def _runs_by_fix_containment(tags: list[str], fix_containing_tags: set[str]) -> list[dict[str, Any]]:
  if not tags:
    return []
  runs: list[dict[str, Any]] = []
  start = 0
  current = tags[0] in fix_containing_tags
  for idx, tag in enumerate(tags[1:], start=1):
    value = tag in fix_containing_tags
    if value == current:
      continue
    runs.append({"is_fix_containing": current, "tags": tags[start:idx]})
    start = idx
    current = value
  runs.append({"is_fix_containing": current, "tags": tags[start:]})
  return runs


def _git_base_cmd(repo: GitRepo) -> list[str]:
  repo_str = str(repo.repo_path.resolve())
  return ["git", "-c", f"safe.directory={repo_str}", "-C", repo_str]


def _batch_path_exists(repo: GitRepo, queries: set[tuple[str, str]]) -> dict[tuple[str, str], bool]:
  if not queries:
    return {}
  ordered = sorted(queries)
  payload = "".join(f"{tag}:{path}\n" for tag, path in ordered)
  proc = subprocess.Popen(
    [*_git_base_cmd(repo), "cat-file", "--batch-check"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    encoding="utf-8",
    errors="replace",
  )
  stdout, _stderr = proc.communicate(payload)
  out: dict[tuple[str, str], bool] = {}
  for query, raw_line in zip(ordered, stdout.splitlines()):
    out[query] = not raw_line.strip().endswith(" missing")
  for query in ordered[len(out):]:
    out[query] = False
  return out


def _changed_files_for_fix_commits(repo: GitRepo, commits: list[str]) -> list[str]:
  out: list[str] = []
  seen: set[str] = set()
  for commit in commits:
    try:
      files = repo.changed_files(commit)
    except Exception:
      files = []
    for path in files:
      if path and path not in seen:
        seen.add(path)
        out.append(path)
  return out


def _file_endpoint_lines(
  *,
  repo: GitRepo,
  release_lines: dict[str, list[str]],
  fix_touched_files: list[str],
) -> set[str]:
  if not fix_touched_files:
    return set()
  queries: set[tuple[str, str]] = set()
  for tags in release_lines.values():
    if not tags:
      continue
    for tag in {tags[0], tags[-1]}:
      for path in fix_touched_files:
        queries.add((tag, path))
  exists = _batch_path_exists(repo, queries)
  out: set[str] = set()
  for line, tags in release_lines.items():
    if not tags:
      continue
    for tag in {tags[0], tags[-1]}:
      if any(exists.get((tag, path), False) for path in fix_touched_files):
        out.add(line)
        break
  return out


def _verdict_for_source(source: str, predicted_affected: set[str], tag: str) -> str:
  if source in {"inferred_no_affected", "fixed_segment_clear"}:
    return "NOT_AFFECTED"
  if source in {"inferred_interval", "inferred_full_line_affected"}:
    return "AFFECTED"
  return "AFFECTED" if tag in predicted_affected else "NOT_AFFECTED"


def _run_status_for_source(source: str) -> str:
  if source == "fixed_segment_clear":
    return "FIXED_SEGMENT_CLEAR"
  if source.startswith("inferred_"):
    return "INFERRED"
  if source == "probe_error":
    return "AGENT_ERROR"
  return "OK"


def _emit_inferred_rows(
  *,
  result: ASBSResult,
  line: str,
  out_jsonl: Path,
  probe_cache: dict[str, TagVerdict],
) -> None:
  predicted = set(result.predicted_affected)
  inferred_from = list(result.probe_tags)
  certificate_id = f"asbs:{line}:{result.status}:v1"
  for tag, source in result.verdict_sources.items():
    if tag in result.probe_tags or tag in probe_cache or source in {"agent", "probe_error"}:
      continue
    verdict = TagVerdict(
      tag=tag,
      line=line,
      verdict=_verdict_for_source(source, predicted, tag),
      run_status=_run_status_for_source(source),
      confidence=0.85,
      matched_predicates=[],
      failed_predicates=[],
      triggered_guards=[],
      evidence_snippets=[],
      reasoning_summary=f"Step3 scheduler inference from {result.status}; source={source}.",
      verdict_source=source,
      inferred_from=inferred_from,
      certificate_id=certificate_id,
    )
    probe_cache[tag] = verdict
    _write_verdict(out_jsonl, verdict)


def _eval_with_legacy_aliases(
  *,
  tag_rows: list[dict[str, Any]],
  all_release_tags: list[str],
  gt_affected_tags: list[str] | None,
  gt_match_mode: str,
  predicted_affected_tags: list[str],
  affected_intervals: list[dict[str, Any]],
  run_status_counts: dict[str, int],
) -> dict[str, Any] | None:
  if gt_affected_tags is None:
    return None
  result = evaluate_step3_output(
    tag_rows=tag_rows,
    all_release_tags=all_release_tags,
    gt_affected_tags=sorted(str(t) for t in gt_affected_tags),
    gt_match_mode=gt_match_mode,
  )
  out = result.to_dict()
  official = out.get("official_metrics") or {}
  out["confusion_matrix"] = (official.get("confusion_matrix") or {})
  out["metrics"] = (official.get("metrics") or {})
  out["metrics_resolved_only"] = (official.get("metrics_resolved_only") or {})
  out["probed_tags"] = list(out.get("agent_tags") or [])
  out["prefiltered_tags"] = []
  out["inferred_tags"] = list(out.get("inferred_tags") or [])
  out["predicted_affected_tags"] = predicted_affected_tags
  out["affected_intervals"] = affected_intervals
  out["probe_count"] = len(tag_rows)
  out["predicted_affected_count"] = len(predicted_affected_tags)
  out["run_status_counts"] = run_status_counts
  gt_total = len(gt_affected_tags)
  out["gt_coverage"] = len(out.get("mapped_gt_tags") or []) / gt_total if gt_total else 0.0
  return out


def _verdict_label(verdict: TagVerdict | None) -> str | None:
  if verdict is None:
    return None
  if verdict.verdict in ("AFFECTED", "NOT_AFFECTED"):
    return verdict.verdict
  return None


def _task_line_context(tag_plan: dict[str, Any], line: str, task: dict[str, Any]) -> dict[str, Any]:
  boundary = ((tag_plan.get("line_boundaries") or {}).get(line) or {})
  return {
    "preferred_fix_commit": None,
    "preferred_fix_tag": task.get("fic_tag") or boundary.get("fic_tag"),
    "frontier_status": boundary.get("status"),
    "frontier_source": "vuln_tree",
    "line_candidate_count": len(task.get("candidate_tags") or []),
    "line_local_vic_tag": task.get("vic_tag") or boundary.get("vic_tag"),
  }


def _all_release_tags_from_plan(tag_plan: dict[str, Any]) -> list[str]:
  tags: list[str] = []
  for line in tag_plan.get("ordered_lines") or []:
    entry = (tag_plan.get("release_lines") or {}).get(line) or {}
    tags.extend(entry.get("tags") or [])
  if tags:
    return tags
  for entry in (tag_plan.get("release_lines") or {}).values():
    tags.extend(entry.get("tags") or [])
  return tags


def _runtime_role_for_source(verdict_source: str | None) -> str:
  if verdict_source == "fixed_segment_clear":
    return "fixed_segment_clear_tag"
  if verdict_source in ("inferred_interval", "inferred_no_affected", "inferred_full_line_affected"):
    return "inferred_tag"
  if verdict_source == "agent_error":
    return "agent_error_tag"
  return "agent_probed_tag"


def _append_role(runtime: dict[str, Any], role: str) -> None:
  roles = list(runtime.get("plan_roles") or [])
  if role not in roles:
    roles.append(role)
  runtime["plan_roles"] = roles


def _find_tag_runtime(
  tag_plan: dict[str, Any],
  *,
  line: str | None,
  tag: str,
) -> dict[str, Any] | None:
  lines = tag_plan.get("lines") or {}
  candidate_lines: list[str] = []
  if line and line in lines:
    candidate_lines.append(line)
  candidate_lines.extend([str(k) for k in lines.keys() if str(k) not in candidate_lines])

  for line_key in candidate_lines:
    line_dict = lines.get(line_key) or {}
    for tag_node in line_dict.get("tag_nodes") or []:
      if tag_node.get("tag") == tag:
        runtime = tag_node.get("runtime")
        if not isinstance(runtime, dict):
          runtime = {}
          tag_node["runtime"] = runtime
        return runtime
  return None


def _sync_boundaries_to_runtime(
  tag_plan: dict[str, Any],
  line_boundaries: dict[str, Any],
) -> None:
  """Make final boundary statuses visible in line/boundary runtime state."""

  lines = tag_plan.get("lines") or {}
  for line, boundary in line_boundaries.items():
    line_key = str(line)
    status = str(boundary.get("status") or "unknown")
    no_fic_reason = ((boundary.get("runtime") or {}).get("no_fic_reason"))
    if status == "verified_no_affected_on_line":
      no_fic_reason = "line_not_vulnerable_in_released_tags"

    boundary_runtime = boundary.get("runtime")
    if not isinstance(boundary_runtime, dict):
      boundary_runtime = {}
      boundary["runtime"] = boundary_runtime
    boundary_runtime["boundary_status"] = status
    boundary_runtime["certificate_id"] = f"boundary:{line_key}:{status}:v1"
    if no_fic_reason is not None:
      boundary_runtime["no_fic_reason"] = no_fic_reason

    line_dict = lines.get(line_key)
    if not isinstance(line_dict, dict):
      continue
    line_runtime = line_dict.get("runtime")
    if not isinstance(line_runtime, dict):
      line_runtime = {}
      line_dict["runtime"] = line_runtime
    line_runtime["boundary_status"] = status
    line_runtime["certificate_id"] = f"line:{line_key}:{status}:v1"
    if no_fic_reason is not None:
      line_runtime["no_fic_reason"] = no_fic_reason


def _sync_verdicts_to_tag_runtime(
  tag_plan: dict[str, Any],
  results: list[TagVerdict],
) -> None:
  """Back-propagate final per-tag verdict rows into VulnTree tag runtime.

  `per_tag_verdict.jsonl` remains the event log.  `vuln_tree_runtime.json`
  should be the final graph-state snapshot after verification, so each verdict
  row that maps to a real tag node must also be reflected on that node.
  """

  unmapped: list[dict[str, Any]] = []
  for ordinal, verdict in enumerate(results, start=1):
    runtime = _find_tag_runtime(tag_plan, line=verdict.line, tag=verdict.tag)
    if runtime is None:
      unmapped.append({
        "tag": verdict.tag,
        "line": verdict.line,
        "verdict_source": verdict.verdict_source,
        "run_status": verdict.run_status,
      })
      continue

    source = verdict.verdict_source or ("agent_error" if verdict.verdict is None else "agent")
    runtime["verdict"] = verdict.verdict
    runtime["verdict_source"] = source
    runtime["confidence"] = verdict.confidence
    runtime["inferred_from"] = list(verdict.inferred_from or [])
    if verdict.certificate_id is not None:
      runtime["certificate_id"] = verdict.certificate_id
    if source in ("agent", "agent_error"):
      runtime["probe_round"] = ordinal
      runtime["plan_status"] = "verification_error" if source == "agent_error" else "verified"
    elif source in ("inferred_interval", "inferred_no_affected", "inferred_full_line_affected"):
      runtime["probe_round"] = None
      runtime["plan_status"] = "inferred"
    elif source == "fixed_segment_clear":
      runtime["probe_round"] = None
      runtime["plan_status"] = "fixed_segment_clear"
    else:
      runtime["probe_round"] = ordinal
      runtime["plan_status"] = "verified"
    _append_role(runtime, _runtime_role_for_source(source))

  if unmapped:
    tag_plan["runtime_unmapped_verdicts"] = unmapped
  else:
    tag_plan.pop("runtime_unmapped_verdicts", None)


def _verify_vuln_tree_plan(
  *,
  repo: GitRepo,
  agent: AgentRuntime,
  cve_id: str,
  rci: dict[str, Any],
  out_dir_p: Path,
  out_jsonl: Path,
  out_csv: Path,
  tag_plan: dict[str, Any],
  resume: bool,
  gt_affected_tags: list[str] | None,
  gt_match_mode: str,
  per_tag_session: bool,
  session_id: str | None,
  tag_timeout_s: float,
  log_progress: bool,
  stage3_prompt_version: str = "v1",
) -> dict[str, Any]:
  probe_cache = _read_existing_verdicts(out_jsonl) if resume else {}
  release_lines = _release_lines_from_plan(tag_plan)
  release_tags = _all_release_tags_from_plan(tag_plan)
  repo_name = str(tag_plan.get("repo") or "")
  fix_commits = _fix_commits_from_plan(tag_plan)
  fix_containing_tags: set[str] = set()
  if fix_commits:
    contains_by_commit = batch_tags_containing(
      repo=repo,
      release_tags=release_tags,
      target_commits=fix_commits,
    )
    for result in contains_by_commit.values():
      if result.get("ok"):
        fix_containing_tags.update(result.get("tags") or [])
  else:
    contains_by_commit = {}

  fix_touched_files = _changed_files_for_fix_commits(repo, fix_commits)
  file_endpoint_lines = _file_endpoint_lines(
    repo=repo,
    release_lines=release_lines,
    fix_touched_files=fix_touched_files,
  )
  ordered_by_family = _ordered_by_family(repo_name, release_lines)
  seed_lines = compute_seed_lines(
    repo_name=repo_name,
    release_lines=release_lines,
    ordered_by_family=ordered_by_family,
    fix_containing_tags=fix_containing_tags,
    file_endpoint_lines=file_endpoint_lines,
    stride=3,
    file_neighbor_radius=1,
  )
  line_boundaries: dict[str, Any] = dict(tag_plan.get("line_boundaries") or {})
  line_states: dict[str, dict[str, Any]] = {}

  def run_line(line: str, tags_asc: list[str]) -> LineRunResult:
    predicted: set[str] = set()
    probes: set[str] = set()
    verdict_sources: dict[str, str] = {}
    statuses: dict[str, int] = {}
    state = line_states.setdefault(line, {
      "discoveries": {},
      "context": {
        "frontier_status": "staged_scheduler",
        "frontier_source": "git_guided_soft",
        "line_candidate_count": len(tags_asc),
        "fix_containing_count": sum(1 for t in tags_asc if t in fix_containing_tags),
      },
    })

    def verdict_fn(tag: str) -> str | None:
      verdict = _probe_tag_agent_only(
        repo=repo,
        agent=agent,
        cve_id=cve_id,
        tag=tag,
        line=line,
        evidence=rci,
        line_discoveries=state["discoveries"],
        line_context=state["context"],
        per_tag_session=per_tag_session,
        session_id=session_id,
        tag_timeout_s=tag_timeout_s,
        log_progress=log_progress,
        out_jsonl=out_jsonl,
        probe_cache=probe_cache,
        stage3_prompt_version=stage3_prompt_version,
      )
      return _verdict_label(verdict)

    def merge(result: ASBSResult, *, status_prefix: str | None = None) -> None:
      predicted.update(result.predicted_affected)
      probes.update(result.probe_tags)
      verdict_sources.update(result.verdict_sources)
      status = f"{status_prefix}_{result.status}" if status_prefix else result.status
      statuses[status] = statuses.get(status, 0) + 1
      _emit_inferred_rows(result=result, line=line, out_jsonl=out_jsonl, probe_cache=probe_cache)

    for segment in _runs_by_fix_containment(tags_asc, fix_containing_tags):
      seg_tags = list(segment.get("tags") or [])
      if not seg_tags:
        continue
      if segment.get("is_fix_containing"):
        sentinel = run_fixed_segment_sentinel(
          seg_tags,
          verdict_fn,
          fixed_seg_sentinel=FIXED_SEG_SENTINEL,
        )
        merge(sentinel)
        if sentinel.status == "fixed_segment_probe_hit":
          fallback = run_asbs_segment(
            seg_tags,
            verdict_fn,
            nn_sentinel_count=NN_SENTINEL_COUNT,
            aa_sentinel_count=AA_SENTINEL_COUNT,
          )
          merge(fallback, status_prefix="fallback")
      else:
        result = run_asbs_segment(
          seg_tags,
          verdict_fn,
          nn_sentinel_count=NN_SENTINEL_COUNT,
          aa_sentinel_count=AA_SENTINEL_COUNT,
        )
        merge(result)

    is_positive = bool(predicted)
    for tag in probes:
      verdict = probe_cache.get(tag)
      if verdict and verdict.verdict == "AFFECTED":
        is_positive = True
        break
    return LineRunResult(
      line=line,
      is_positive=is_positive,
      predicted_affected=[t for t in tags_asc if t in predicted],
      probe_tags=[t for t in tags_asc if t in probes],
      verdict_sources=verdict_sources,
      statuses=statuses,
      fix_containing_count=sum(1 for t in tags_asc if t in fix_containing_tags),
    )

  scheduler_state = run_staged_scheduler(
    seed_lines=seed_lines,
    release_lines=release_lines,
    ordered_by_family=ordered_by_family,
    fix_containing_tags=fix_containing_tags,
    run_line_fn=run_line,
    expansion_radius=1,
    fallback_mode="none",
  )

  results = list(probe_cache.values())
  run_status_counts: dict[str, int] = {}
  for verdict in results:
    run_status_counts[verdict.run_status] = run_status_counts.get(verdict.run_status, 0) + 1

  affected_intervals: list[dict[str, Any]] = []
  predicted_affected_tags: list[str] = []
  predicted_seen: set[str] = set()
  for line in tag_plan.get("ordered_lines") or release_lines.keys():
    line_result = scheduler_state.line_results.get(str(line))
    if not line_result:
      continue
    line_pred = [tag for tag in release_lines.get(str(line), []) if tag in set(line_result.predicted_affected)]
    if line_pred:
      affected_intervals.append({
        "line": str(line),
        "tags": line_pred,
        "status": "scheduler_predicted_affected",
        "source": "line_scheduler_asbs",
      })
      for tag in line_pred:
        if tag not in predicted_seen:
          predicted_seen.add(tag)
          predicted_affected_tags.append(tag)
    boundary = dict(line_boundaries.get(str(line)) or {"line": str(line)})
    boundary["status"] = "scheduler_predicted_affected" if line_pred else "verified_no_affected_on_line"
    boundary["affected_interval"] = {"tags": line_pred} if line_pred else None
    boundary["monotonicity_certificate"] = {
      "rule": "staged_nofix_stride3_file",
      "probe_tags": line_result.probe_tags,
      "statuses": line_result.statuses,
      "fix_containing_count": line_result.fix_containing_count,
    }
    line_boundaries[str(line)] = boundary
  tag_plan["line_boundaries"] = line_boundaries
  tag_plan["affected_intervals"] = affected_intervals
  tag_plan["line_intervals"] = affected_intervals
  tag_plan["scheduler"] = {
    "name": "staged_nofix_stride3_file",
    "nn_sentinel_count": NN_SENTINEL_COUNT,
    "aa_sentinel_count": AA_SENTINEL_COUNT,
    "fixed_segment_sentinel": FIXED_SEG_SENTINEL,
    "expansion_radius": 1,
    "seed_lines": sorted(seed_lines),
    "visited_lines": sorted(scheduler_state.visited),
    "positive_lines": sorted(scheduler_state.positive_lines),
    "fix_commits": fix_commits,
    "fix_containing_tags_count": len(fix_containing_tags),
    "fix_touched_files": fix_touched_files,
    "file_endpoint_lines": sorted(file_endpoint_lines),
    "status_counts": scheduler_state.status_counts,
    "contains_by_commit": contains_by_commit,
  }
  _sync_boundaries_to_runtime(tag_plan, line_boundaries)
  _sync_verdicts_to_tag_runtime(tag_plan, results)
  write_tag_plan(out_dir_p, tag_plan)
  (out_dir_p / "affected_intervals.json").write_text(
    json.dumps(affected_intervals, ensure_ascii=False, indent=2),
    encoding="utf-8",
  )
  (out_dir_p / "line_intervals.json").write_text(
    json.dumps(affected_intervals, ensure_ascii=False, indent=2),
    encoding="utf-8",
  )
  (out_dir_p / "scheduler_plan.json").write_text(
    json.dumps(tag_plan["scheduler"], ensure_ascii=False, indent=2),
    encoding="utf-8",
  )

  _write_results_csv(results, out_csv)

  eval_out = _eval_with_legacy_aliases(
    tag_rows=[r.model_dump() for r in results],
    all_release_tags=release_tags,
    gt_affected_tags=gt_affected_tags,
    gt_match_mode=gt_match_mode,
    predicted_affected_tags=predicted_affected_tags,
    affected_intervals=affected_intervals,
    run_status_counts=run_status_counts,
  )
  if eval_out is not None:
    (out_dir_p / "eval.json").write_text(json.dumps(eval_out, ensure_ascii=False, indent=2), encoding="utf-8")

  return {
    "tags": [r.tag for r in results],
    "tag_plan": tag_plan,
    "fix_tag": None,
    "tag_scope": "vuln_tree",
    "verification_mode": "vuln_tree_git_guided_scheduler",
    "tags_verified": len(results),
    "results": [r.model_dump() for r in results],
    "eval": eval_out,
  }


def _write_results_csv(results: list[TagVerdict], out_csv: Path) -> None:
  with out_csv.open("w", encoding="utf-8", newline="") as f:
    w = csv.DictWriter(
      f,
      fieldnames=[
        "tag",
        "line",
        "run_status",
        "verdict",
        "verdict_source",
        "confidence",
        "matched_predicates",
        "failed_predicates",
        "triggered_guards",
        "inferred_from",
        "certificate_id",
        "reasoning_summary",
      ],
    )
    w.writeheader()
    for r in results:
      w.writerow(
        {
          "tag": r.tag,
          "line": r.line,
          "run_status": r.run_status,
          "verdict": r.verdict,
          "verdict_source": r.verdict_source or "",
          "confidence": r.confidence,
          "matched_predicates": json.dumps(r.matched_predicates, ensure_ascii=False),
          "failed_predicates": json.dumps(r.failed_predicates, ensure_ascii=False),
          "triggered_guards": json.dumps(r.triggered_guards, ensure_ascii=False),
          "inferred_from": json.dumps(r.inferred_from, ensure_ascii=False),
          "certificate_id": r.certificate_id or "",
          "reasoning_summary": r.reasoning_summary,
        }
      )


def _compute_probe_only_eval(
  *,
  results: list[TagVerdict],
  scanned_tags: list[str],
  gt_affected_tags: list[str] | None,
  gt_match_mode: str,
) -> dict[str, Any] | None:
  if gt_affected_tags is None:
    return None

  mapped, unmapped = map_gt_tags_to_repo_tags(gt_affected_tags, scanned_tags, mode=gt_match_mode)
  tag_to_row = {r.tag: r for r in results}
  tp = fp = fn = fn_execution = tn = unk = 0
  run_status_counts: dict[str, int] = {}
  mapped_set = set(mapped)

  # P0-2: explicit verdict_source buckets
  bucket_probed: list[str] = []
  bucket_prefiltered: list[str] = []
  bucket_inferred: list[str] = []
  bucket_errored: list[str] = []

  for tag in scanned_tags:
    row = tag_to_row.get(tag)
    pred = row.verdict if row is not None else None
    run_status = row.run_status if row is not None else "PARSE_ERROR"
    run_status_counts[run_status] = run_status_counts.get(run_status, 0) + 1
    gt = tag in mapped_set
    src = (row.verdict_source if row is not None else None) or (
      "prefilter" if run_status == "PREFILTER"
      else "inferred_interval" if run_status == "INFERRED"
      else "agent" if pred in ("AFFECTED", "NOT_AFFECTED")
      else "agent_error"
    )
    if src == "agent":
      bucket_probed.append(tag)
    elif src == "prefilter":
      bucket_prefiltered.append(tag)
    elif src == "inferred_interval":
      bucket_inferred.append(tag)
    else:
      bucket_errored.append(tag)

    if src == "agent_error" or pred is None:
      if gt:
        fn_execution += 1
      unk += 1
      continue
    if gt and pred == "AFFECTED":
      tp += 1
    elif gt and pred == "NOT_AFFECTED":
      fn += 1
    elif (not gt) and pred == "AFFECTED":
      fp += 1
    elif (not gt) and pred == "NOT_AFFECTED":
      tn += 1

  fn_unmapped = len(unmapped)
  total_fn = fn + fn_execution + fn_unmapped
  precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
  recall = tp / (tp + total_fn) if (tp + total_fn) > 0 else 0.0
  f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
  recall_scanned = tp / (tp + fn + fn_execution) if (tp + fn + fn_execution) > 0 else 0.0
  f1_scanned = 2 * precision * recall_scanned / (precision + recall_scanned) if (precision + recall_scanned) > 0 else 0.0
  gt_coverage = len(mapped) / len(gt_affected_tags) if gt_affected_tags else 0.0
  resolved_rate = (tp + fp + fn + tn) / len(scanned_tags) if scanned_tags else 0.0
  return {
    "gt_affected_tags": gt_affected_tags,
    "mapped_gt_tags": mapped,
    "unmapped_gt_tags": unmapped,
    "scanned_tags": scanned_tags,
    "probed_tags": bucket_probed,
    "prefiltered_tags": bucket_prefiltered,
    "inferred_tags": bucket_inferred,
    "agent_error_tags": bucket_errored,
    "agent_error_count": len(bucket_errored),
    "confusion_matrix": {
      "TP": tp,
      "FP": fp,
      "FN": fn,
      "FN_execution": fn_execution,
      "FN_unmapped": fn_unmapped,
      "TN": tn,
      "UNK": unk,
    },
    "metrics": {"precision": precision, "recall": recall, "f1": f1},
    "metrics_scanned_only": {"precision": precision, "recall": recall_scanned, "f1": f1_scanned},
    "gt_coverage": gt_coverage,
    "resolved_rate": resolved_rate,
    "run_status_counts": run_status_counts,
  }


def _build_explicit_tag_plan(
  *,
  repo_name: str,
  cve_id: str,
  tags: list[str],
  tags_glob: str | None,
) -> dict[str, Any]:
  from vulnversion.stage3_verify.version_registry import line_key, sort_tags_for_line

  verification_order = list(dict.fromkeys(tags))
  grouped_explicit: dict[str, list[str]] = {}
  for tag in verification_order:
    grouped_explicit.setdefault(line_key(repo_name, tag), []).append(tag)

  ordered_lines = list(grouped_explicit.keys())
  release_lines: dict[str, dict[str, Any]] = {}
  line_plans: dict[str, dict[str, Any]] = {}
  frontiers: dict[str, dict[str, Any]] = {}
  for line in ordered_lines:
    explicit_tags = grouped_explicit[line]
    tags_asc = sort_tags_for_line(repo_name, explicit_tags, reverse=False)
    release_lines[line] = {"tags": tags_asc}
    line_plans[line] = {
      "candidate_tags": tags_asc,
      "verification_order": explicit_tags,
      "frontier_status": "explicit",
      "fic_tag": None,
      "fic_index": None,
      "vic_tag": None,
      "vic_index": None,
      "task_mode": "explicit",
    }
    frontiers[line] = {
      "status": "explicit",
      "source": "explicit",
      "first_fully_fixed_tag": None,
      "first_fully_fixed_index": None,
      "line_local_vic_tag": None,
      "line_local_vic_index": None,
      "family_frontiers": {},
    }

  return {
    "plan_kind": "explicit",
    "repo": repo_name,
    "cve_id": cve_id,
    "mode": "explicit",
    "branch_model": "explicit",
    "ordered_lines": ordered_lines,
    "release_lines": release_lines,
    "fix_families": [],
    "frontiers": frontiers,
    "line_plans": line_plans,
    "verification_order": verification_order,
    "tags_glob": tags_glob,
  }


def _verify_explicit_tags(
  *,
  repo: GitRepo,
  repo_name: str,
  agent: AgentRuntime,
  cve_id: str,
  rci: dict[str, Any],
  out_dir_p: Path,
  out_jsonl: Path,
  out_csv: Path,
  tag_plan: dict[str, Any],
  resume: bool,
  gt_affected_tags: list[str] | None,
  gt_match_mode: str,
  per_tag_session: bool,
  session_id: str | None,
  tag_timeout_s: float,
  log_progress: bool,
  stage3_prompt_version: str = "v1",
) -> dict[str, Any]:
  from vulnversion.stage3_verify.version_registry import line_key

  probe_cache = _read_existing_verdicts(out_jsonl) if resume else {}
  line_states: dict[str, dict[str, Any]] = {}
  scanned_tags = list(tag_plan.get("verification_order") or [])

  for tag in scanned_tags:
    line = line_key(repo_name, tag)
    if line not in line_states:
      line_states[line] = {
        "discoveries": {},
        "context": {
          "preferred_fix_commit": None,
          "preferred_fix_tag": None,
          "frontier_status": "explicit",
          "frontier_source": "explicit",
          "line_candidate_count": len(((tag_plan.get("release_lines") or {}).get(line) or {}).get("tags") or []),
        },
      }
    state = line_states[line]
    _probe_tag_agent_only(
      repo=repo,
      agent=agent,
      cve_id=cve_id,
      tag=tag,
      line=line,
      evidence=rci,
      line_discoveries=state["discoveries"],
      line_context=state["context"],
      per_tag_session=per_tag_session,
      session_id=session_id,
      tag_timeout_s=tag_timeout_s,
      log_progress=log_progress,
      out_jsonl=out_jsonl,
      probe_cache=probe_cache,
      stage3_prompt_version=stage3_prompt_version,
    )

  results = [probe_cache[tag] for tag in scanned_tags if tag in probe_cache]
  _write_results_csv(results, out_csv)
  eval_out = _compute_probe_only_eval(
    results=results,
    scanned_tags=scanned_tags,
    gt_affected_tags=gt_affected_tags,
    gt_match_mode=gt_match_mode,
  )
  if eval_out is not None:
    (out_dir_p / "eval.json").write_text(json.dumps(eval_out, ensure_ascii=False, indent=2), encoding="utf-8")

  return {
    "tags": scanned_tags,
    "tag_plan": tag_plan,
    "fix_tag": None,
    "tag_scope": "explicit",
    "verification_mode": "explicit_agent",
    "tags_verified": len(results),
    "results": [r.model_dump() for r in results],
    "eval": eval_out,
  }


def verify_tags(
  *,
  repo_path: str,
  cve_id: str,
  out_dir: str | Path,
  rci_path: str | Path | None = None,
  evidence_path: str | Path | None = None,
  fix_commit: str | None = None,
  fixing_commits: list[list[str]] | None = None,
  tags: list[str] | None = None,
  tags_glob: str | None = None,
  resume: bool = False,
  gt_affected_tags: list[str] | None = None,
  gt_match_mode: str = "strict",
  agent: AgentRuntime | None = None,
  session_id: str | None = None,
  per_tag_session: bool = True,
  log_progress: bool = False,
  tag_timeout_s: float = 300.0,
  stage3_prompt_version: str = "v1",
) -> dict[str, Any]:
  """Verify tags against a CVE.

  Step3 now supports only two execution modes:
  - VulnTree planning with deterministic line-local ASBS
  - explicit tag verification for caller-supplied tag lists
  """
  repo = GitRepo.open(repo_path)
  from vulnversion.stage3_verify.version_registry import infer_repo_name
  repo_name = infer_repo_name(repo_path)
  if agent is None:
    raise RuntimeError("stage3_requires_agent: agent is required")
  if not per_tag_session and session_id is None:
    raise RuntimeError("stage3_requires_session_id: provide session_id or set per_tag_session=True")
  evidence_path = evidence_path or rci_path
  rci = _load_rci(evidence_path)
  out_dir_p = Path(out_dir)
  out_dir_p.mkdir(parents=True, exist_ok=True)
  out_jsonl = out_dir_p / "per_tag_verdict.jsonl"
  out_csv = out_dir_p / "per_tag_verdict.csv"

  if tags is None:
    tag_plan = build_tag_plan(
      repo_path=repo_path,
      cve_id=cve_id,
      fixing_commits=fixing_commits or ([[fix_commit]] if fix_commit else None),
      rci_path=None,
      tags_glob=tags_glob,
      mode="eval",
    )
  else:
    tag_plan = _build_explicit_tag_plan(
      repo_name=repo_name,
      cve_id=cve_id,
      tags=tags,
      tags_glob=tags_glob,
    )

  write_tag_plan(out_dir_p, tag_plan)
  if tag_plan.get("plan_kind") == "vuln_tree":
    return _verify_vuln_tree_plan(
      repo=repo,
      agent=agent,
      cve_id=cve_id,
      rci=rci,
      out_dir_p=out_dir_p,
      out_jsonl=out_jsonl,
      out_csv=out_csv,
      tag_plan=tag_plan,
      resume=resume,
      gt_affected_tags=gt_affected_tags,
      gt_match_mode=gt_match_mode,
      per_tag_session=per_tag_session,
      session_id=session_id,
      tag_timeout_s=tag_timeout_s,
      log_progress=log_progress,
      stage3_prompt_version=stage3_prompt_version,
    )
  return _verify_explicit_tags(
    repo=repo,
    repo_name=repo_name,
    agent=agent,
    cve_id=cve_id,
    rci=rci,
    out_dir_p=out_dir_p,
    out_jsonl=out_jsonl,
    out_csv=out_csv,
    tag_plan=tag_plan,
    resume=resume,
    gt_affected_tags=gt_affected_tags,
    gt_match_mode=gt_match_mode,
    per_tag_session=per_tag_session,
    session_id=session_id,
    tag_timeout_s=tag_timeout_s,
    log_progress=log_progress,
    stage3_prompt_version=stage3_prompt_version,
  )

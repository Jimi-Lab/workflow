from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


def collect_git_evidence(
  cve_id: str,
  packet: dict[str, Any],
  *,
  repo_root: str | Path | None,
  timeout_s: float = 30.0,
  max_stdout_chars: int = 12000,
) -> dict[str, Any]:
  repo = _repo_name(packet)
  repo_path = Path(repo_root) / repo if repo_root and repo else None
  trace_run_id = f"wrapper-trace-{cve_id}-{uuid4().hex[:12]}"
  trace: dict[str, Any] = {
    "cve_id": cve_id,
    "trace_run_id": trace_run_id,
    "source": "wrapper_git_trace",
    "repo": repo,
    "repo_path": str(repo_path) if repo_path else "",
    "backend_trusted": "wrapper",
    "tool_calls": [],
    "tool_outputs": [],
    "git_observations": [],
    "errors": [],
  }
  if not repo_path or not repo_path.exists():
    trace["errors"].append(f"repo path not found: {repo_path}")
    return trace

  fix_commits = _fix_commit_nodes(packet)
  for fix_commit in fix_commits:
    fix_commit_id = str(fix_commit.get("id") or "")
    commit_sha = str((fix_commit.get("content") or {}).get("commit_sha") or "")
    if not commit_sha:
      continue
    commit_scope = _packet_scope(packet, fix_commit_id)
    _record_git_command(
      trace,
      repo_path,
      ["git", "show", "--stat", "--no-color", commit_sha],
      command_id=f"git-show-stat-{commit_sha[:12]}",
      observation_kind="patch_stat",
      observation_claim=f"git show --stat for fix commit {commit_sha}",
      packet_scope=commit_scope,
      expected_commit_sha=commit_sha,
      path="",
      timeout_s=timeout_s,
      max_stdout_chars=max_stdout_chars,
    )
    _record_git_command(
      trace,
      repo_path,
      ["git", "show", "--unified=80", "--no-color", commit_sha],
      command_id=f"git-show-unified-{commit_sha[:12]}",
      observation_kind="patch_diff",
      observation_claim=f"git show --unified=80 for fix commit {commit_sha}",
      packet_scope=commit_scope,
      expected_commit_sha=commit_sha,
      path="",
      timeout_s=timeout_s,
      max_stdout_chars=max_stdout_chars,
    )
    for path in commit_scope["paths"][:8]:
      path_scope = _packet_scope(packet, fix_commit_id, path=path)
      _record_git_command(
        trace,
        repo_path,
        ["git", "log", "--follow", "--oneline", "-n", "5", commit_sha, "--", path],
        command_id=f"git-log-follow-{commit_sha[:12]}-{_path_token(path)}",
        observation_kind="file_history",
        observation_claim=f"git log --follow around changed path {path}",
        packet_scope=path_scope,
        expected_commit_sha=commit_sha,
        path=path,
        timeout_s=timeout_s,
        max_stdout_chars=max_stdout_chars,
      )
  return trace


def adapt_legacy_evidence_trace(cve_id: str, packet: dict[str, Any], legacy_trace: dict[str, Any]) -> dict[str, Any]:
  """Reconstruct wrapper provenance from legacy collector ToolCalls without trusting legacy observations."""
  call_ids = "|".join(str(call.get("id") or "") for call in legacy_trace.get("tool_calls") or [])
  trace_run_id = f"legacy-trace-{hashlib.sha256((cve_id + call_ids).encode('utf-8')).hexdigest()[:12]}"
  adapted: dict[str, Any] = {
    "source": "wrapper_git_trace",
    "created_from": "legacy_replay_adapter",
    "legacy_reconstructed": True,
    "cve_id": cve_id,
    "trace_run_id": trace_run_id,
    "repo": legacy_trace.get("repo", ""),
    "repo_path": legacy_trace.get("repo_path", ""),
    "backend_trusted": "wrapper",
    "tool_calls": [],
    "tool_outputs": [],
    "git_observations": [],
    "errors": list(legacy_trace.get("errors") or []),
  }
  legacy_observations = {
    str(observation.get("command_ref") or ""): observation
    for observation in legacy_trace.get("git_observations") or []
    if observation.get("command_ref")
  }
  fix_nodes = _fix_commit_nodes(packet)
  for legacy_call in legacy_trace.get("tool_calls") or []:
    command_id = str(legacy_call.get("id") or legacy_call.get("invocation_id") or "")
    command = str(legacy_call.get("command") or "")
    fix_node = next(
      (
        node for node in fix_nodes
        if str((node.get("content") or {}).get("commit_sha") or "")
        and str((node.get("content") or {}).get("commit_sha")) in command
      ),
      None,
    )
    if not command_id or not fix_node:
      adapted["errors"].append(f"legacy ToolCall cannot be associated with packet scope: {command_id}")
      continue
    fix_id = str(fix_node.get("id") or "")
    commit_sha = str((fix_node.get("content") or {}).get("commit_sha") or "")
    observation_kind = _legacy_observation_kind(command)
    path = command.rsplit(" -- ", 1)[1].strip() if " -- " in command else ""
    scope = _packet_scope(packet, fix_id, path=path or None)
    output_text = str(legacy_call.get("output") or legacy_call.get("stdout_excerpt") or "")
    output_id = f"tool-output-{command_id}"
    common = {"source": "wrapper_git_trace", "created_from": "legacy_replay_adapter", "cve_id": cve_id, "trace_run_id": trace_run_id}
    adapted["tool_calls"].append({**legacy_call, **common, "id": command_id})
    adapted["tool_outputs"].append(
      {
        **common,
        "id": output_id,
        "command_ref": command_id,
        "text": output_text,
        "stdout_sha256": str(legacy_call.get("stdout_sha256") or hashlib.sha256(output_text.encode("utf-8", errors="ignore")).hexdigest()),
        "stderr_excerpt": str(legacy_call.get("stderr_excerpt") or ""),
        "exit_code": int(legacy_call.get("exit_code", -1)),
      }
    )
    valid, invalid_reason = _evaluate_evidence(
      observation_kind,
      exit_code=int(legacy_call.get("exit_code", -1)),
      stdout=output_text,
      expected_commit_sha=commit_sha,
      packet_scope=scope,
    )
    old_observation = legacy_observations.get(command_id, {})
    adapted["git_observations"].append(
      {
        **common,
        "id": str(old_observation.get("id") or old_observation.get("observation_id") or f"obs-{command_id}"),
        "valid_evidence": valid,
        "invalid_reason": invalid_reason,
        "observation_kind": observation_kind,
        "command_ref": command_id,
        "tool_output_ref": output_id,
        "fix_commit_ids": scope["fix_commit_ids"],
        "fix_commit_id": scope["fix_commit_ids"][0] if scope["fix_commit_ids"] else "",
        "patch_hunk_ids": scope["patch_hunk_ids"],
        "file_ids": scope["file_ids"],
        "function_ids": scope["function_ids"],
        "path": path,
        "claim": str(old_observation.get("claim") or f"legacy reconstructed {observation_kind}"),
        "snippet": output_text[:2000],
      }
    )
  return adapted


def enrich_legacy_packet_fix_sets(cve_id: str, packet: dict[str, Any], fixing_commits: Any) -> dict[str, Any]:
  enriched = json.loads(json.dumps(packet, ensure_ascii=False))
  metadata: dict[str, dict[str, Any]] = {}
  if isinstance(fixing_commits, list):
    for group_index, group in enumerate(fixing_commits, start=1):
      commits = group if isinstance(group, list) else [group]
      for order, commit in enumerate(commits, start=1):
        sha = str(commit).strip()
        if sha:
          metadata[sha] = {"fix_set_id": f"{cve_id}:fix-set:{group_index}", "group_index": group_index, "order": order}
  for node in enriched.get("patch_evidence", []) or []:
    if node.get("type") != "FixCommit":
      continue
    content = node.setdefault("content", {})
    commit_sha = str(content.get("commit_sha") or "")
    if commit_sha in metadata:
      content.update(metadata[commit_sha])
  return enriched


def _legacy_observation_kind(command: str) -> str:
  if "git show --stat" in command:
    return "patch_stat"
  if "git show --unified" in command or "git show --patch" in command:
    return "patch_diff"
  if "git log --follow" in command:
    return "file_history"
  if "git grep" in command:
    return "negative_search"
  return "unknown"


def _record_git_command(
  trace: dict[str, Any],
  cwd: Path,
  args: list[str],
  *,
  command_id: str,
  observation_kind: str,
  observation_claim: str,
  packet_scope: dict[str, list[str]],
  expected_commit_sha: str,
  path: str,
  timeout_s: float,
  max_stdout_chars: int,
) -> None:
  safe_args = _with_safe_directory(args, cwd)
  started_at = _now()
  try:
    result = subprocess.run(safe_args, cwd=str(cwd), capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=timeout_s)
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    exit_code = result.returncode
  except Exception as error:
    stdout = ""
    stderr = str(error)
    exit_code = -1
  finished_at = _now()
  stdout_excerpt = stdout[:max_stdout_chars]
  stderr_excerpt = stderr[:2000]
  trace["tool_calls"].append(
    {
      "id": command_id,
      "source": "wrapper_git_trace",
      "cve_id": trace["cve_id"],
      "trace_run_id": trace["trace_run_id"],
      "command": _format_command(args),
      "args": safe_args,
      "cwd": str(cwd),
      "exit_code": exit_code,
      "stdout_excerpt": stdout_excerpt,
      "stdout_sha256": hashlib.sha256(stdout.encode("utf-8", errors="ignore")).hexdigest(),
      "stderr_excerpt": stderr_excerpt,
      "started_at": started_at,
      "finished_at": finished_at,
    }
  )
  output_id = f"tool-output-{command_id}"
  trace["tool_outputs"].append(
    {
      "id": output_id,
      "source": "wrapper_git_trace",
      "cve_id": trace["cve_id"],
      "trace_run_id": trace["trace_run_id"],
      "command_ref": command_id,
      "text": stdout_excerpt,
      "stdout_sha256": hashlib.sha256(stdout.encode("utf-8", errors="ignore")).hexdigest(),
      "stderr_excerpt": stderr_excerpt,
      "exit_code": exit_code,
    }
  )
  valid_evidence, invalid_reason = _evaluate_evidence(
    observation_kind,
    exit_code=exit_code,
    stdout=stdout_excerpt,
    expected_commit_sha=expected_commit_sha,
    packet_scope=packet_scope,
  )
  trace["git_observations"].append(
    {
      "id": f"obs-{command_id}",
      "source": "wrapper_git_trace",
      "valid_evidence": valid_evidence,
      "invalid_reason": invalid_reason,
      "observation_kind": observation_kind,
      "cve_id": trace["cve_id"],
      "trace_run_id": trace["trace_run_id"],
      "command_ref": command_id,
      "tool_output_ref": output_id,
      "fix_commit_ids": packet_scope["fix_commit_ids"],
      "fix_commit_id": packet_scope["fix_commit_ids"][0] if packet_scope["fix_commit_ids"] else "",
      "patch_hunk_ids": packet_scope["patch_hunk_ids"],
      "file_ids": packet_scope["file_ids"],
      "function_ids": packet_scope["function_ids"],
      "path": path,
      "claim": observation_claim,
      "snippet": stdout_excerpt[:2000],
    }
  )


def _repo_name(packet: dict[str, Any]) -> str:
  for section in ("context", "repo_navigation", "patch_evidence"):
    for node in packet.get(section, []) or []:
      content = node.get("content") or {}
      if node.get("type") == "Repo" and content.get("repo"):
        return str(content["repo"])
      if content.get("repo"):
        return str(content["repo"])
  return ""


def _fix_commit_nodes(packet: dict[str, Any]) -> list[dict[str, Any]]:
  return [node for node in packet.get("patch_evidence", []) or [] if node.get("type") == "FixCommit"]


def _packet_scope(packet: dict[str, Any], fix_commit_id: str, *, path: str | None = None) -> dict[str, list[str]]:
  patch_nodes = list(packet.get("patch_evidence") or [])
  nav_nodes = list(packet.get("repo_navigation") or [])
  fix_node = next((node for node in patch_nodes if node.get("id") == fix_commit_id), {})
  commit_sha = str((fix_node.get("content") or {}).get("commit_sha") or "")
  hunks = [
    node for node in patch_nodes
    if node.get("type") == "PatchHunk"
    and str((node.get("content") or {}).get("commit_sha") or "") == commit_sha
    and (path is None or str((node.get("content") or {}).get("path") or "") == path)
  ]
  paths = sorted({str((node.get("content") or {}).get("path") or "") for node in hunks if (node.get("content") or {}).get("path")})
  files = [node for node in nav_nodes + patch_nodes if node.get("type") in {"File", "ChangedFile", "FilePath"} and str((node.get("content") or {}).get("path") or "") in paths]
  functions = [
    node for node in patch_nodes + nav_nodes
    if node.get("type") in {"ChangedFunction", "Function", "FunctionSymbol"}
    and str((node.get("content") or {}).get("commit_sha") or "") == commit_sha
    and str((node.get("content") or {}).get("path") or "") in paths
  ]
  return {
    "fix_commit_ids": [fix_commit_id] if fix_node else [],
    "patch_hunk_ids": [str(node.get("id")) for node in hunks if node.get("id")],
    "file_ids": [str(node.get("id")) for node in files if node.get("id")],
    "function_ids": [str(node.get("id")) for node in functions if node.get("id")],
    "paths": paths,
  }


def _evaluate_evidence(
  observation_kind: str,
  *,
  exit_code: int,
  stdout: str,
  expected_commit_sha: str,
  packet_scope: dict[str, list[str]],
) -> tuple[bool, str]:
  if not packet_scope["fix_commit_ids"]:
    return False, "command output cannot be associated with packet FixCommit scope"
  if exit_code != 0:
    return False, f"command failed with exit_code={exit_code}"
  if observation_kind == "patch_stat":
    valid = bool(stdout.strip() and expected_commit_sha in stdout)
  elif observation_kind == "patch_diff":
    valid = bool(stdout.strip() and expected_commit_sha in stdout and "diff --git" in stdout)
  elif observation_kind == "file_history":
    valid = bool(stdout.strip() and expected_commit_sha[:7] in stdout)
  elif observation_kind == "negative_search":
    valid = not stdout.strip()
  else:
    valid = False
  return (True, "") if valid else (False, f"{observation_kind} output failed semantic validity checks")


def _format_command(args: list[str]) -> str:
  return " ".join(args)


def _with_safe_directory(args: list[str], cwd: Path) -> list[str]:
  if not args or args[0] != "git":
    return args
  return ["git", "-c", f"safe.directory={cwd}", *args[1:]]


def _now() -> str:
  return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe(value: str) -> str:
  return "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in value)


def _path_token(path: str) -> str:
  digest = hashlib.sha256(path.encode("utf-8", errors="ignore")).hexdigest()[:10]
  return f"{_safe(path)[:24]}-{digest}"

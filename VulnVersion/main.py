from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import queue
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
  sys.path.insert(0, str(_ROOT))

from vulnversion.agent_harness.base import AgentRuntime
from vulnversion.agent_harness.runtimes.opencode_runtime import OpenCodeRuntime
from vulnversion.agent_harness.service import AgentService
from vulnversion.agent_harness.trace import JsonlTraceWriter
from vulnversion.config import Config, LLM_PROFILES, resolve_model_config
from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
from vulnversion.opencode.hints import opencode_restart_hint
from vulnversion.stage1_semantic_aggregation.run import run_stage1
from vulnversion.stage2_rci_navigation.run import run_stage2
from vulnversion.stage3_verify.run import run_stage3
from vulnversion.utils.cve_desc import ensure_cve_desc_from_nvd_cache_or_crawler
from vulnversion.utils.dataset import list_fix_commits, load_dataset, pick_default_fix_commit
from vulnversion.utils.paths import Paths
from vulnversion.utils.result_layout import materialize_result_layout


# Example:
# python main.py --dataset DataSet/BaseDataOrder.json


def _project_root() -> Path:
  return Path(__file__).resolve().parent


def _ts() -> str:
  return datetime.now(timezone.utc).isoformat()


def _log(message: str) -> None:
  print(f"[{_ts()}] {message}", flush=True)


def _load_json(path: str | Path) -> Any:
  return json.loads(Path(path).read_text(encoding="utf-8"))


def _maybe_agent(cfg: Config, *, timeout_s: float, project_root: Path | None = None) -> tuple[AgentRuntime | None, str | None]:
  backend = (cfg.agent_backend or "opencode").strip().lower()
  if backend != "opencode":
    raise RuntimeError(
      f"agent_backend_not_implemented: {backend}. "
      "Current source phase only wires OpenCodeRuntime; Codex/Claude are reserved adapters."
    )
  if not cfg.opencode_base_url:
    return None, None
  agent = OpenCodeRuntime.from_config(cfg, timeout_s=timeout_s, health_check=True, project_root=project_root)
  session_id = agent.create_readonly_session(title="VulnVersion-test-all")
  return agent, session_id


def _ensure_cve_desc(cve_id: str, out_dir: Path, *, allow_fetch: bool, project_root: Path, cfg: Config) -> str:
  nvd_cache = (project_root / Path(cfg.nvd_cache_path)).resolve() if not Path(cfg.nvd_cache_path).is_absolute() else Path(cfg.nvd_cache_path).resolve()
  crawler = (project_root / Path(cfg.nvd_crawler_path)).resolve() if not Path(cfg.nvd_crawler_path).is_absolute() else Path(cfg.nvd_crawler_path).resolve()
  dataset = (project_root / Path(cfg.dataset_path)).resolve() if not Path(cfg.dataset_path).is_absolute() else Path(cfg.dataset_path).resolve()
  return ensure_cve_desc_from_nvd_cache_or_crawler(
    cve_id=cve_id,
    out_dir=out_dir,
    nvd_cache_path=nvd_cache,
    crawler_script_path=crawler,
    dataset_path=dataset,
    allow_crawl=allow_fetch,
  )


def _repo_ready(repo_dir: Path) -> bool:
  return repo_dir.exists() and (repo_dir / ".git").exists()


def _group_dataset_by_repo(ds: dict[str, Any]) -> dict[str, list[str]]:
  out: dict[str, list[str]] = {}
  for cve_id, rec in ds.items():
    if not isinstance(rec, dict):
      continue
    repo = rec.get("repo")
    if not isinstance(repo, str) or not repo.strip():
      continue
    out.setdefault(repo.strip(), []).append(str(cve_id))
  for k in list(out.keys()):
    out[k] = sorted(set(out[k]))
  return out


def _wait_for_opencode(
  base_url: str,
  *,
  max_wait_s: float = 120.0,
  poll_interval_s: float = 5.0,
) -> bool:
  """Wait up to max_wait_s for OpenCode to become healthy. Returns True if recovered."""
  import httpx as _httpx
  deadline = time.time() + max_wait_s
  while time.time() < deadline:
    try:
      r = _httpx.get(f"{base_url.rstrip('/')}/global/health", timeout=5.0)
      if r.status_code == 200:
        return True
    except Exception:
      pass
    time.sleep(poll_interval_s)
  return False


def _should_skip_cve(cve_dir: Path, *, resume: bool) -> bool:
  if not resume:
    return False

  # Prefer an explicit completion marker.
  if (cve_dir / "run_ok.json").exists() or (cve_dir / "final" / "run_ok.json").exists():
    return True

  # Backward-compatible: treat eval.json as completion for older runs.
  if (cve_dir / "eval.json").exists() or (cve_dir / "final" / "eval.json").exists():
    return True

  # IMPORTANT:
  # A CVE run may be interrupted (e.g., cve_timeout_s). In that case
  # per_tag_verdict.jsonl may exist but is only a *partial* progress log.
  # When resume=True we should continue from that file instead of skipping.
  if (cve_dir / "run_error.json").exists():
    return False

  return False

def _eval_against_gt(*, gt_tags: list[str], scanned_tags: list[str], results: list[dict[str, Any]], mode: str) -> dict[str, Any]:
  """P0-2: bucket scanned tags into 4 disjoint groups before computing CM.

  - probed_tags        : verdict_source=agent
  - prefiltered_tags   : verdict_source=prefilter
  - inferred_tags      : verdict_source=inferred_interval
  - agent_error_tags   : verdict_source=agent_error  (excluded from CM)
  - unmapped_gt_tags   : GT tags that could not map to any scanned tag

  Resolved-only confusion matrix counts only probed + prefiltered + inferred
  rows. agent_error tags contribute only to FN_execution in the recall metric.
  """
  mapped, unmapped = map_gt_tags_to_repo_tags(gt_tags, scanned_tags, mode=mode)
  mapped_set = set(mapped)

  by_tag: dict[str, dict[str, Any]] = {str(r.get("tag") or ""): r for r in results}

  bucket_probed: list[str] = []
  bucket_prefiltered: list[str] = []
  bucket_inferred: list[str] = []
  bucket_errored: list[str] = []
  for t in scanned_tags:
    row = by_tag.get(t)
    if row is None:
      bucket_errored.append(t)
      continue
    src = row.get("verdict_source")
    verdict = row.get("verdict")
    if src is None:
      # Backward compat: derive source from verdict / run_status.
      run_status = str(row.get("run_status") or "")
      if run_status == "PREFILTER":
        src = "prefilter"
      elif run_status == "INFERRED":
        src = "inferred_interval"
      elif verdict in ("AFFECTED", "NOT_AFFECTED"):
        src = "agent"
      else:
        src = "agent_error"
    if src == "agent":
      bucket_probed.append(t)
    elif src == "prefilter":
      bucket_prefiltered.append(t)
    elif src == "inferred_interval":
      bucket_inferred.append(t)
    else:
      bucket_errored.append(t)

  resolved_set = set(bucket_probed) | set(bucket_prefiltered) | set(bucket_inferred)

  tp = fp = fn = tn = 0
  for t in resolved_set:
    row = by_tag.get(t) or {}
    pred = str(row.get("verdict") or "")
    gt = t in mapped_set
    if gt and pred == "AFFECTED":
      tp += 1
    elif gt and pred == "NOT_AFFECTED":
      fn += 1
    elif (not gt) and pred == "AFFECTED":
      fp += 1
    elif (not gt) and pred == "NOT_AFFECTED":
      tn += 1

  fn_execution = sum(1 for t in bucket_errored if t in mapped_set)
  fn_unmapped = len(unmapped)
  total_fn_for_recall = fn + fn_execution + fn_unmapped

  precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
  recall = tp / (tp + total_fn_for_recall) if (tp + total_fn_for_recall) > 0 else 0.0
  f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
  recall_resolved = tp / (tp + fn) if (tp + fn) > 0 else 0.0
  f1_resolved = (
    2 * precision * recall_resolved / (precision + recall_resolved)
    if (precision + recall_resolved) > 0 else 0.0
  )

  return {
    "gt_affected_tags": gt_tags,
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
      "UNK": len(bucket_errored),
    },
    "metrics": {"precision": precision, "recall": recall, "f1": f1},
    "metrics_resolved_only": {
      "precision": precision,
      "recall": recall_resolved,
      "f1": f1_resolved,
    },
  }


def _dump_opencode_messages(
  *,
  out_dir: Path,
  repo_name: str,
  cve_id: str,
  agent: AgentRuntime | None,
  session_id: str | None,
) -> None:
  if agent is None or not session_id:
    return
  bundle_export = getattr(agent, "export_known_session_messages", None)
  if callable(bundle_export):
    try:
      bundles = list(bundle_export())
      if bundles:
        sessions = [
          {
            "session": b.get("session"),
            "messages_count": b.get("messages_count"),
          }
          for b in bundles
          if isinstance(b, dict)
        ]
        (out_dir / "agent_sessions.json").write_text(
          json.dumps(
            {
              "repo": repo_name,
              "cve_id": cve_id,
              "backend": getattr(agent, "backend", "unknown"),
              "primary_session_id": session_id,
              "sessions_count": len(sessions),
              "sessions": sessions,
            },
            ensure_ascii=False,
            indent=2,
          ),
          encoding="utf-8",
        )
        with (out_dir / "opencode_messages_all.jsonl").open("w", encoding="utf-8") as f:
          for b in bundles:
            if not isinstance(b, dict):
              continue
            session = b.get("session") if isinstance(b.get("session"), dict) else {}
            sid = session.get("session_id") if isinstance(session, dict) else None
            for item in list(b.get("messages") or []):
              f.write(
                json.dumps(
                  {
                    "session_id": sid,
                    "session": session,
                    "message": item,
                  },
                  ensure_ascii=False,
                )
                + "\n"
              )
    except Exception:
      pass
  try:
    export = getattr(agent, "export_session_messages", None)
    if callable(export):
      messages = export(session_id=session_id)
    else:
      client = getattr(agent, "_client", None)
      if client is None or not hasattr(client, "list_messages"):
        return
      messages = client.list_messages(session_id=session_id)
  except Exception as e:
    meta = {
      "repo": repo_name,
      "cve_id": cve_id,
      "session_id": session_id,
      "backend": getattr(agent, "backend", "unknown"),
      "export_error": f"{type(e).__name__}: {e}",
      "messages_count": 0,
    }
    (out_dir / "opencode_session.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return

  meta = {
    "repo": repo_name,
    "cve_id": cve_id,
    "session_id": session_id,
    "backend": getattr(agent, "backend", "unknown"),
    "messages_count": len(messages),
  }
  (out_dir / "opencode_session.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
  (out_dir / "opencode_messages.json").write_text(json.dumps(messages, ensure_ascii=False, indent=2), encoding="utf-8")

  with (out_dir / "opencode_messages.jsonl").open("w", encoding="utf-8") as f:
    for item in messages:
      f.write(json.dumps(item, ensure_ascii=False) + "\n")


def _run_cve_worker(
  q: "mp.Queue[dict[str, Any]]",
  *,
  cfg_data: dict[str, Any],
  project_root: str,
  repo_name: str,
  repo_dir: str,
  repo_artifacts_root: str,
  dataset_path: str,
  cve_id: str,
  fix_commit: str,
  fix_commits: list[str],
  cve_desc: str,
  cwe: list[str],
  dataset_record: dict[str, Any],
  gt_tags: list[str],
  tags_glob: str | None,
  tag_timeout_s: float,
  stage3_prompt_version: str,
) -> None:
  agent: AgentRuntime | None = None
  session_id: str | None = None
  out_dir: Path | None = None
  try:
    cfg = Config.model_validate(cfg_data)
    project_root_path = Path(project_root)
    agent, session_id = _maybe_agent(
      cfg,
      timeout_s=float(cfg_data.get("opencode_timeout_s") or 1200.0),
      project_root=project_root_path,
    )
    paths = Paths.from_root(Path(project_root), repo_artifacts_root)
    out_dir = paths.ensure_dir(paths.cve_dir(cve_id))
    if agent is not None:
      agent = AgentService(
        runtime=agent,
        trace_writer=JsonlTraceWriter(out_dir / "agent_trace.jsonl"),
        default_metadata={
          "repo": repo_name,
          "cve_id": cve_id,
          "repo_path": repo_dir,
          "agent_backend": getattr(agent, "backend", "unknown"),
        },
      )
      if isinstance(agent, AgentService):
        agent.register_session(
          session_id=session_id,
          title="VulnVersion-test-all",
          role="initial",
          metadata={"repo": repo_name, "cve_id": cve_id},
        )
        agent.write_runtime_manifest(out_dir / "agent_runtime.json")

    # ── Stage 1+2 Session Isolation (E3) ──────────────────────────────────
    # For large patches (many chunks), Stage 1's exploration context can exceed
    # the context window before Stage 2 even starts. When chunk count exceeds
    # STAGE_SESSION_SPLIT_THRESHOLD, use separate sessions for Stage 1 and Stage 2.
    # For small patches, shared session is preferred (Stage 2 benefits from Stage 1 history).
    STAGE_SESSION_SPLIT_THRESHOLD = 30  # chunks
    from vulnversion.git_ops.repo import GitRepo as _GitRepo
    from vulnversion.git_ops.diff import git_diff as _git_diff
    try:
      _repo_tmp = _GitRepo.open(repo_dir)
      _chunks_count = sum(
        len(f.get("hunks", []))
        for c in (fix_commits or [fix_commit])
        for f in (_git_diff(_repo_tmp, commit=c).get("files") or [])
      )
    except Exception:
      _chunks_count = 0
    _large_patch = _chunks_count > STAGE_SESSION_SPLIT_THRESHOLD

    if _large_patch:
      _log(f"stage1_session_split chunks={_chunks_count} (>{STAGE_SESSION_SPLIT_THRESHOLD}) repo={repo_name} cve={cve_id}")
      stage1_session_id = agent.create_readonly_session(title=f"VulnVersion-stage1-{cve_id}")
      stage2_session_id = agent.create_readonly_session(title=f"VulnVersion-stage2-{cve_id}")
    else:
      stage1_session_id = session_id
      stage2_session_id = session_id

    _log(f"stage1_start repo={repo_name} cve={cve_id} chunks={_chunks_count} split={_large_patch}")
    run_stage1(
      cve_id=cve_id,
      repo_path=repo_dir,
      fix_commit=fix_commit,
      fix_commits=fix_commits,
      cve_desc=cve_desc,
      cwe=cwe,
      artifacts_dir=repo_artifacts_root,
      dataset_record=dataset_record,
      agent=agent,
      session_id=stage1_session_id,
    )
    _log(f"stage1_done repo={repo_name} cve={cve_id}")

    _log(f"stage2_start repo={repo_name} cve={cve_id}")
    run_stage2(
      cve_id=cve_id,
      repo_path=repo_dir,
      fix_commit=fix_commit,
      vuln_commit=None,
      cve_desc=cve_desc,
      cwe=cwe,
      artifacts_dir=repo_artifacts_root,
      patch_semantics_path=str(out_dir / "patch_semantics.json"),
      repomaster_root=cfg.repomaster_root,
      agent=agent,
      session_id=stage2_session_id,
    )
    _log(f"stage2_done repo={repo_name} cve={cve_id}")

    resolved_tags_glob = str(tags_glob).strip() if isinstance(tags_glob, str) and tags_glob.strip() else None
    active_glob = resolved_tags_glob
    # Don't pre-select tags here; let verify_tags handle smart selection
    # using list_tags() (all tags) so release-branch tags aren't missed.
    tags = None
    sample = "(deferred to verify_tags)"
    _log(f"stage3_start repo={repo_name} cve={cve_id} "
         f"tags_glob={active_glob or ''} prompt_version={stage3_prompt_version} sample={sample}")
    stage3_out = run_stage3(
      cve_id=cve_id,
      repo_path=repo_dir,
      artifacts_dir=repo_artifacts_root,
      rci_path=str(out_dir / "rci.json"),
      fix_commit=fix_commit,
      fixing_commits=dataset_record.get("fixing_commits"),
      tags=None,
      tags_glob=active_glob,
      tag_timeout_s=float(tag_timeout_s),
      resume=True,
      gt_affected_tags=gt_tags if gt_tags else None,
      gt_match_mode=cfg.gt_tag_match_mode,
      agent=agent,
      session_id=None,       # per_tag_session=True creates fresh session per tag
      per_tag_session=True,  # KEY FIX: isolate each tag in its own session
      log_progress=True,
      stage3_prompt_version=stage3_prompt_version,
    )
    if gt_tags:
      eval_out = stage3_out.get("eval")
      if not eval_out:
        eval_out = _eval_against_gt(
          gt_tags=gt_tags,
          scanned_tags=list(stage3_out.get("tags") or []),
          results=list(stage3_out.get("results") or []),
          mode=cfg.gt_tag_match_mode,
        )
      (out_dir / "eval.json").write_text(json.dumps(eval_out, ensure_ascii=False, indent=2), encoding="utf-8")
    _log(f"stage3_done repo={repo_name} cve={cve_id}")

    # Mark completion so resume-skip logic is safe.
    try:
      (out_dir / "run_ok.json").write_text(
        json.dumps({"cve_id": cve_id, "status": "ok"}, ensure_ascii=False, indent=2),
        encoding="utf-8",
      )
    except Exception:
      pass

    q.put({"ok": True})
  except BaseException as e:
    q.put({"ok": False, "error": str(e), "type": type(e).__name__})
  finally:
    if out_dir is not None:
      try:
        _dump_opencode_messages(
          out_dir=out_dir,
          repo_name=repo_name,
          cve_id=cve_id,
          agent=agent,
          session_id=session_id,
        )
      except Exception as e:
        _log(f"opencode_export_error repo={repo_name} cve={cve_id} error={type(e).__name__}: {e}")
      try:
        materialize_result_layout(
          out_dir,
          repo=repo_name,
          cve_id=cve_id,
          dataset_path=dataset_path,
        )
      except Exception as e:
        _log(f"result_layout_error repo={repo_name} cve={cve_id} error={type(e).__name__}: {e}")


def _terminate_process(p: mp.Process, *, grace_s: float) -> None:
  if not p.is_alive():
    return
  p.terminate()
  p.join(timeout=grace_s)
  if not p.is_alive():
    return
  if hasattr(p, "kill"):
    p.kill()  # type: ignore[attr-defined]
    p.join(timeout=grace_s)


def main(argv: list[str] | None = None) -> int:
  ap = argparse.ArgumentParser()
  ap.add_argument("--dataset", default=None)
  ap.add_argument("--config", default="vuln_config.json")
  ap.add_argument("--allow-fetch-cve-desc", action="store_true")
  ap.add_argument("--no-allow-fetch-cve-desc", dest="allow_fetch_cve_desc", action="store_false")
  ap.set_defaults(allow_fetch_cve_desc=True)
  ap.add_argument("--tags-glob", default=None)
  ap.add_argument("--watch", action="store_true")
  ap.add_argument("--no-watch", dest="watch", action="store_false")
  ap.set_defaults(watch=True)
  ap.add_argument("--watch-interval-s", type=float, default=300.0)
  ap.add_argument("--agent-backend", default=None, choices=["opencode", "codex", "claude", "replay"],
                  help="Agent runtime backend. Only opencode is wired in the current refactor phase.")
  ap.add_argument("--opencode-timeout", type=float, default=3600.0)
  ap.add_argument("--model", default=None,
                  help=f"LLM profile: {', '.join(LLM_PROFILES)}. Overrides config provider/model and sets profile default timeout.")
  ap.add_argument("--tag-timeout-s", type=float, default=None,
                  help="Max seconds per tag in stage3 (overrides --model profile default). Default: 900s, or profile value when --model is set.")
  ap.add_argument("--stage3-prompt-version", default="v1", choices=["v0", "v1"],
                  help="Stage3 tag-verdict prompt. v0=legacy navigation, v1=target-tag theorem judge.")
  ap.add_argument("--cve-timeout-s", type=float, default=21600.0)
  ap.add_argument("--kill-grace-s", type=float, default=10.0)
  ap.add_argument("--resume", action="store_true")
  ap.add_argument("--no-resume", dest="resume", action="store_false")
  ap.set_defaults(resume=True)
  args = ap.parse_args(argv)

  project_root = _project_root()
  cfg = Config()
  cfg_path = Path(args.config)
  if not cfg_path.is_absolute():
    cfg_path = (project_root / cfg_path).resolve()
  if cfg_path.exists():
    cfg = Config.model_validate(_load_json(cfg_path))
  if args.agent_backend:
    cfg.agent_backend = args.agent_backend

  # Apply --model profile: resolves provider_id, model_id, per-tag timeout.
  if args.model:
    cfg.model_profile = args.model
  provider_id, model_id, profile_tag_timeout = resolve_model_config(cfg)
  if provider_id:
    cfg.opencode_provider_id = provider_id
  if model_id:
    cfg.opencode_model_id = model_id
  # --tag-timeout-s explicitly wins; otherwise use profile default (or cfg default).
  effective_tag_timeout_s: float = args.tag_timeout_s if args.tag_timeout_s is not None else profile_tag_timeout
  if args.model:
    _log(f"model_profile={args.model} provider={provider_id} model={model_id} tag_timeout_s={effective_tag_timeout_s}")

  artifacts_root = (project_root / cfg.artifacts_dir).resolve() if not Path(cfg.artifacts_dir).is_absolute() else Path(cfg.artifacts_dir).resolve()
  if not artifacts_root.is_relative_to(project_root):
    raise SystemExit(f"artifacts_dir must be under {project_root}, got: {artifacts_root}")

  repo_root = project_root / "repo"
  dataset_path = Path(args.dataset) if args.dataset else Path(cfg.dataset_path)
  if not dataset_path.is_absolute():
    dataset_path = (project_root / dataset_path).resolve()
  if not dataset_path.exists():
    raise SystemExit(f"dataset not found: {dataset_path}")
  ds = load_dataset(dataset_path)
  by_repo = _group_dataset_by_repo(ds)
  total_cves = sum(len(v) for v in by_repo.values())
  _log(f"dataset_loaded repos={len(by_repo)} cves={total_cves} dataset={dataset_path}")

  agent, session_id = _maybe_agent(cfg, timeout_s=float(args.opencode_timeout), project_root=project_root)
  if agent is None:
    _log("opencode_disabled")
  else:
    _log(f"agent_enabled backend={agent.backend} timeout_s={float(args.opencode_timeout)} base_url={cfg.opencode_base_url}")
  if agent is None or session_id is None:
    raise SystemExit("opencode is required for this experiment, but it is not available")

  remaining: dict[str, set[str]] = {r: set(cves) for r, cves in by_repo.items()}
  repo_state: dict[str, str] = {}
  loop = 0

  while True:
    loop += 1
    progressed = False
    waiting_count = 0
    ready_count = 0
    for repo_name in remaining.keys():
      repo_dir = repo_root / repo_name
      if _repo_ready(repo_dir):
        ready_count += 1
      else:
        waiting_count += 1
    _log(f"scan_loop={loop} remaining_repos={len(remaining)} ready_repos={ready_count} waiting_repos={waiting_count}")

    for repo_name in sorted(list(remaining.keys())):
      repo_dir = repo_root / repo_name
      if not _repo_ready(repo_dir):
        prev = repo_state.get(repo_name)
        if prev != "waiting":
          _log(f"repo_waiting repo={repo_name} path={repo_dir}")
          repo_state[repo_name] = "waiting"
        continue

      prev = repo_state.get(repo_name)
      if prev != "ready":
        _log(f"repo_ready repo={repo_name} path={repo_dir}")
        repo_state[repo_name] = "ready"

      repo_artifacts_root = artifacts_root / repo_name
      paths = Paths.from_root(project_root, str(repo_artifacts_root))
      cve_ids = sorted(list(remaining[repo_name]))
      _log(f"repo_begin repo={repo_name} remaining_cves={len(cve_ids)} out_root={repo_artifacts_root}")
      for cve_id in cve_ids:
        out_dir = paths.ensure_dir(paths.cve_dir(cve_id))
        rec = ds.get(cve_id) or {}
        (out_dir / "dataset_record.json").write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")

        if _should_skip_cve(out_dir, resume=bool(args.resume)):
          try:
            materialize_result_layout(
              out_dir,
              repo=repo_name,
              cve_id=cve_id,
              dataset_path=dataset_path,
            )
          except Exception as e:
            _log(f"result_layout_error repo={repo_name} cve={cve_id} error={type(e).__name__}: {e}")
          _log(f"cve_skip repo={repo_name} cve={cve_id} reason=resume_outputs_present out_dir={out_dir}")
          remaining[repo_name].discard(cve_id)
          progressed = True
          continue

        try:
          fix_commits = list_fix_commits(rec)
          fix_commit = pick_default_fix_commit(rec)
          cwe = list(rec.get("CWE") or [])
          gt = [str(t) for t in list(rec.get("affected_version") or []) if str(t).strip()]
          cve_desc = _ensure_cve_desc(
            cve_id,
            out_dir,
            allow_fetch=bool(args.allow_fetch_cve_desc),
            project_root=project_root,
            cfg=cfg,
          )

          _log(f"cve_begin repo={repo_name} cve={cve_id} fix_commit={fix_commit} gt_tags={len(gt)} cwe={len(cwe)} out_dir={out_dir}")

          # ── Health check: if OpenCode crashed during a previous CVE, wait for recovery ──
          import httpx as _httpx
          _oc_url = cfg.opencode_base_url or ""
          if _oc_url:
            try:
              _httpx.get(f"{_oc_url.rstrip('/')}/global/health", timeout=5.0).raise_for_status()
            except Exception:
              _log(f"opencode_down_before_cve repo={repo_name} cve={cve_id} — waiting up to 120s for recovery")
              _recovered = _wait_for_opencode(_oc_url, max_wait_s=120.0)
              if _recovered:
                _log(f"opencode_recovered repo={repo_name} cve={cve_id}")
              else:
                _log(f"opencode_still_down repo={repo_name} cve={cve_id} — skipping CVE, {opencode_restart_hint(_oc_url)}")
                err = {"cve_id": cve_id, "status": "error", "error": "opencode_server_down_not_recovered", "error_type": "OpenCodeServerDownError"}
                (out_dir / "run_error.json").write_text(json.dumps(err, ensure_ascii=False, indent=2), encoding="utf-8")
                try:
                  materialize_result_layout(
                    out_dir,
                    repo=repo_name,
                    cve_id=cve_id,
                    dataset_path=dataset_path,
                    status="error",
                  )
                except Exception as e:
                  _log(f"result_layout_error repo={repo_name} cve={cve_id} error={type(e).__name__}: {e}")
                remaining[repo_name].discard(cve_id)
                progressed = True
                continue

          cfg_data = cfg.model_dump()
          cfg_data["opencode_timeout_s"] = float(args.opencode_timeout)
          q: "mp.Queue[dict[str, Any]]" = mp.Queue()
          p = mp.Process(
            target=_run_cve_worker,
            kwargs={
              "q": q,
              "cfg_data": cfg_data,
              "project_root": str(project_root),
              "repo_name": repo_name,
              "repo_dir": str(repo_dir),
              "repo_artifacts_root": str(repo_artifacts_root),
              "dataset_path": str(dataset_path),
              "cve_id": cve_id,
              "fix_commit": fix_commit,
              "fix_commits": fix_commits,
              "cve_desc": cve_desc,
              "cwe": cwe,
              "dataset_record": rec,
              "gt_tags": gt,
              "tags_glob": args.tags_glob,
              "tag_timeout_s": effective_tag_timeout_s,
              "stage3_prompt_version": args.stage3_prompt_version,
            },
            daemon=True,
          )
          p.start()
          p.join(timeout=float(args.cve_timeout_s))
          if p.is_alive():
            _log(f"cve_timeout repo={repo_name} cve={cve_id} timeout_s={float(args.cve_timeout_s)}")
            _terminate_process(p, grace_s=float(args.kill_grace_s))
            raise TimeoutError(f"cve_timeout_s={float(args.cve_timeout_s)}")
          try:
            result = q.get_nowait()
          except queue.Empty:
            result = {"ok": (p.exitcode == 0), "error": "no_worker_result", "type": "NoWorkerResult"}
          if not bool(result.get("ok")):
            err_type = str(result.get("type") or "WorkerError")
            err_msg = str(result.get("error") or "worker_failed")
            raise RuntimeError(f"{err_type}: {err_msg}")

          remaining[repo_name].discard(cve_id)
          progressed = True
          _log(f"cve_done repo={repo_name} cve={cve_id} status=ok")
        except BaseException as e:
          if isinstance(e, KeyboardInterrupt):
            raise
          err = {"cve_id": cve_id, "status": "error", "error": str(e), "error_type": type(e).__name__}
          (out_dir / "run_error.json").write_text(json.dumps(err, ensure_ascii=False, indent=2), encoding="utf-8")
          try:
            materialize_result_layout(
              out_dir,
              repo=repo_name,
              cve_id=cve_id,
              dataset_path=dataset_path,
              status="error",
            )
          except Exception as layout_e:
            _log(f"result_layout_error repo={repo_name} cve={cve_id} error={type(layout_e).__name__}: {layout_e}")
          remaining[repo_name].discard(cve_id)
          progressed = True
          _log(f"cve_done repo={repo_name} cve={cve_id} status=error error={str(e)}")

      if not remaining[repo_name]:
        _log(f"repo_done repo={repo_name}")
        del remaining[repo_name]

    if not remaining:
      _log("all_done")
      return 0

    if not args.watch:
      _log("stopped_no_watch")
      return 0

    if not progressed:
      _log(f"sleep seconds={float(args.watch_interval_s)}")
      time.sleep(float(args.watch_interval_s))


if __name__ == "__main__":
  raise SystemExit(main())

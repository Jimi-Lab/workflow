from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from vulnversion.config import Config, resolve_model_config
from vulnversion.opencode.agent import OpenCodeAgent
from vulnversion.opencode.client import OpenCodeAuth, OpenCodeClient
from vulnversion.opencode.hints import opencode_start_hint
from vulnversion.stage1_semantic_aggregation.run import run_stage1
from vulnversion.stage2_rci_navigation.run import run_stage2
from vulnversion.stage3_verify.run import run_stage3
from vulnversion.utils.cve_desc import ensure_cve_desc, ensure_cve_desc_from_nvd_cache_or_crawler
from vulnversion.utils.dataset import get_dataset_record, list_fix_commits, load_dataset, pick_default_fix_commit
from vulnversion.utils.paths import Paths


def _maybe_agent(cfg: Config) -> tuple[OpenCodeAgent | None, str | None]:
  if not cfg.opencode_base_url:
    return None, None
  auth = None
  if cfg.opencode_username and cfg.opencode_password:
    auth = OpenCodeAuth(username=cfg.opencode_username, password=cfg.opencode_password)
  client = OpenCodeClient(base_url=cfg.opencode_base_url, auth=auth)
  try:
    client.health()
  except Exception as e:
    raise RuntimeError(f"opencode_unreachable: {opencode_start_hint(cfg.opencode_base_url)}") from e
  agent = OpenCodeAgent(client=client, provider_id=cfg.opencode_provider_id, model_id=cfg.opencode_model_id, agent=cfg.opencode_agent)
  session_id = agent.create_readonly_session(title="VulnVersion")
  return agent, session_id


def _read_json(path: str | Path) -> Any:
  return json.loads(Path(path).read_text(encoding="utf-8"))

def _project_root() -> Path:
  return Path(__file__).resolve().parents[1]


def _resolve_artifacts_root(project_root: Path, artifacts_dir: str) -> Path:
  p = Path(artifacts_dir)
  root = p.resolve() if p.is_absolute() else (project_root / p).resolve()
  if not root.is_relative_to(project_root):
    raise ValueError(f"artifacts_dir must be under {project_root}, got: {root}")
  return root


def _resolve_repo_path(project_root: Path, repo_path: str) -> str:
  p = Path(repo_path)
  if p.is_absolute():
    return str(p.resolve())

  candidate = (project_root / p).resolve()
  if candidate.is_relative_to(project_root / "repo") and candidate.exists():
    return str(candidate)

  candidate2 = (project_root / "repo" / p).resolve()
  if candidate2.is_relative_to(project_root / "repo") and candidate2.exists():
    return str(candidate2)

  raise FileNotFoundError(f"repo_path must exist under {project_root / 'repo'}, got: {repo_path}")


def _resolve_dataset_path(project_root: Path, dataset_path: str) -> str:
  p = Path(dataset_path)
  if p.is_absolute():
    return str(p.resolve())
  return str((project_root / p).resolve())


def _write_run_inputs(out_dir: Path, data: dict[str, Any]) -> None:
  out_dir.mkdir(parents=True, exist_ok=True)
  (out_dir / "run_inputs.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _resolve_cfg_path(project_root: Path, path_str: str) -> Path:
  p = Path(path_str)
  if p.is_absolute():
    return p.resolve()
  return (project_root / p).resolve()


def _ensure_cve_desc_from_args_or_cache(
  *,
  cve_id: str,
  out_dir: Path,
  args: argparse.Namespace,
  cfg: Config,
  project_root: Path,
  allow_crawl: bool,
) -> str:
  cve_source = _read_json(args.cve_source_json) if getattr(args, "cve_source_json", None) else None
  if args.cve_desc or args.cve_desc_file or cve_source is not None:
    return ensure_cve_desc(
      out_dir=out_dir,
      cve_desc=args.cve_desc,
      cve_desc_file=args.cve_desc_file,
      cve_source_json=cve_source,
    )

  return ensure_cve_desc_from_nvd_cache_or_crawler(
    cve_id=cve_id,
    out_dir=out_dir,
    nvd_cache_path=_resolve_cfg_path(project_root, cfg.nvd_cache_path),
    crawler_script_path=_resolve_cfg_path(project_root, cfg.nvd_crawler_path),
    dataset_path=_resolve_cfg_path(project_root, cfg.dataset_path),
    allow_crawl=allow_crawl,
  )


def main(argv: list[str] | None = None) -> int:
  p = argparse.ArgumentParser(prog="vulnversion")
  p.add_argument("--config", default=None)
  p.add_argument("--model", default=None, help="LLM profile name (e.g. deepseek-v3, gpt-4o, claude-sonnet)")
  sub = p.add_subparsers(dest="cmd", required=True)

  p1 = sub.add_parser("semantic-aggregate")
  p1.add_argument("--cve-id", required=True)
  p1.add_argument("--repo-path", required=True)
  p1.add_argument("--fix-commit", default=None)
  p1.add_argument("--dataset", default=None)
  p1.add_argument("--cve-desc", default=None)
  p1.add_argument("--cve-desc-file", default=None)
  p1.add_argument("--cve-source-json", default=None)
  p1.add_argument("--allow-crawl-cve-desc", action="store_true")
  p1.add_argument("--no-allow-crawl-cve-desc", dest="allow_crawl_cve_desc", action="store_false")
  p1.set_defaults(allow_crawl_cve_desc=True)

  p2 = sub.add_parser("rci-extract")
  p2.add_argument("--cve-id", required=True)
  p2.add_argument("--repo-path", required=True)
  p2.add_argument("--fix-commit", required=True)
  p2.add_argument("--vuln-commit", default=None)
  p2.add_argument("--patch-semantics", default=None)
  p2.add_argument("--cve-desc", default=None)
  p2.add_argument("--cve-desc-file", default=None)
  p2.add_argument("--cve-source-json", default=None)
  p2.add_argument("--allow-crawl-cve-desc", action="store_true")
  p2.add_argument("--no-allow-crawl-cve-desc", dest="allow_crawl_cve_desc", action="store_false")
  p2.set_defaults(allow_crawl_cve_desc=True)

  p3 = sub.add_parser("verify-tags")
  p3.add_argument("--cve-id", required=True)
  p3.add_argument("--repo-path", required=True)
  p3.add_argument("--rci", required=True)
  p3.add_argument("--fix-commit", default=None)
  p3.add_argument("--tags-glob", default=None)
  p3.add_argument("--max-tags", type=int, default=None)
  p3.add_argument("--resume", action="store_true")
  p3.add_argument("--gt-affected-tags", default=None)
  p3.add_argument("--gt-match-mode", default=None)
  # Stage3 is agent-only by design; no local matcher fallback.

  args = p.parse_args(argv)

  cfg = Config()
  if args.config:
    cfg = Config.model_validate(_read_json(args.config))
  if args.model:
    cfg.model_profile = args.model

  # Resolve model profile into provider/model/timeout overrides
  provider_id, model_id, per_tag_timeout = resolve_model_config(cfg)
  if provider_id:
    cfg.opencode_provider_id = provider_id
  if model_id:
    cfg.opencode_model_id = model_id

  project_root = _project_root()
  artifacts_root = _resolve_artifacts_root(project_root, cfg.artifacts_dir)
  paths = Paths.from_root(project_root, str(artifacts_root))

  if args.cmd == "semantic-aggregate":
    dataset_record: dict[str, Any] | None = None
    cwe: list[str] = []
    fix_commit = args.fix_commit
    fix_commits: list[str] | None = None
    repo_path = _resolve_repo_path(project_root, args.repo_path)
    dataset_candidate = args.dataset
    if dataset_candidate is None and fix_commit is None:
      dataset_candidate = cfg.dataset_path
    if dataset_candidate:
      ds = load_dataset(_resolve_dataset_path(project_root, dataset_candidate))
      dataset_record = get_dataset_record(ds, args.cve_id)
      fix_commits = list_fix_commits(dataset_record)
      if fix_commit is None:
        fix_commit = pick_default_fix_commit(dataset_record)
      cwe = list(dataset_record.get("CWE") or [])

    out_dir = paths.ensure_dir(paths.cve_dir(args.cve_id))
    _write_run_inputs(
      out_dir,
      {
        "cmd": "semantic-aggregate",
        "cve_id": args.cve_id,
        "repo_path": repo_path,
        "fix_commit": fix_commit,
        "fix_commits": fix_commits,
        "dataset": args.dataset,
        "cve_desc": args.cve_desc,
        "cve_desc_file": args.cve_desc_file,
        "cve_source_json": args.cve_source_json,
      },
    )

    cve_desc = _ensure_cve_desc_from_args_or_cache(
      cve_id=args.cve_id,
      out_dir=out_dir,
      args=args,
      cfg=cfg,
      project_root=project_root,
      allow_crawl=bool(args.allow_crawl_cve_desc),
    )

    if fix_commit is None:
      raise SystemExit("--fix-commit is required (or provide --dataset)")

    agent, session_id = _maybe_agent(cfg)
    run_stage1(
      cve_id=args.cve_id,
      repo_path=repo_path,
      fix_commit=fix_commit,
      fix_commits=fix_commits,
      cve_desc=cve_desc,
      cwe=cwe,
      artifacts_dir=str(artifacts_root),
      dataset_record=dataset_record,
      agent=agent,
      session_id=session_id,
    )
    return 0

  if args.cmd == "rci-extract":
    repo_path = _resolve_repo_path(project_root, args.repo_path)
    out_dir = paths.ensure_dir(paths.cve_dir(args.cve_id))
    _write_run_inputs(
      out_dir,
      {
        "cmd": "rci-extract",
        "cve_id": args.cve_id,
        "repo_path": repo_path,
        "fix_commit": args.fix_commit,
        "vuln_commit": args.vuln_commit,
        "patch_semantics": args.patch_semantics,
        "cve_desc": args.cve_desc,
        "cve_desc_file": args.cve_desc_file,
        "cve_source_json": args.cve_source_json,
      },
    )
    cve_desc = _ensure_cve_desc_from_args_or_cache(
      cve_id=args.cve_id,
      out_dir=out_dir,
      args=args,
      cfg=cfg,
      project_root=project_root,
      allow_crawl=bool(args.allow_crawl_cve_desc),
    )

    patch_path = args.patch_semantics or str(paths.cve_dir(args.cve_id) / "patch_semantics.json")
    agent, session_id = _maybe_agent(cfg)
    run_stage2(
      cve_id=args.cve_id,
      repo_path=repo_path,
      fix_commit=args.fix_commit,
      vuln_commit=args.vuln_commit,
      cve_desc=cve_desc,
      cwe=[],
      artifacts_dir=str(artifacts_root),
      patch_semantics_path=patch_path,
      repomaster_root=cfg.repomaster_root,
      agent=agent,
      session_id=session_id,
    )
    return 0

  if args.cmd == "verify-tags":
    repo_path = _resolve_repo_path(project_root, args.repo_path)
    out_dir = paths.ensure_dir(paths.cve_dir(args.cve_id))
    _write_run_inputs(
      out_dir,
      {
        "cmd": "verify-tags",
        "cve_id": args.cve_id,
        "repo_path": repo_path,
        "rci": args.rci,
        "tags_glob": args.tags_glob,
        "resume": bool(args.resume),
        "gt_affected_tags": args.gt_affected_tags,
        "gt_match_mode": args.gt_match_mode,

      },
    )
    gt_tags = None
    if args.gt_affected_tags:
      gt_tags = [t for t in args.gt_affected_tags.split(",") if t.strip()]
    gt_mode = args.gt_match_mode or cfg.gt_tag_match_mode
    agent, session_id = _maybe_agent(cfg)
    run_stage3(
      cve_id=args.cve_id,
      repo_path=repo_path,
      artifacts_dir=str(artifacts_root),
      rci_path=args.rci,
      fix_commit=getattr(args, 'fix_commit', None),
      tags_glob=args.tags_glob,
      tag_timeout_s=per_tag_timeout,
      resume=args.resume,
      gt_affected_tags=gt_tags,
      gt_match_mode=gt_mode,
      agent=agent,
      session_id=session_id,
      log_progress=True,
    )
    return 0

  raise SystemExit(f"unknown command: {args.cmd}")


if __name__ == "__main__":
  raise SystemExit(main())

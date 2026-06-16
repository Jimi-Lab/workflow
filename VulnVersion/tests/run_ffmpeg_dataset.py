from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
  sys.path.insert(0, str(_ROOT))

from vulnversion.config import Config
from vulnversion.opencode.agent import OpenCodeAgent
from vulnversion.opencode.client import OpenCodeAuth, OpenCodeClient
from vulnversion.opencode.hints import opencode_start_hint
from vulnversion.stage1_semantic_aggregation.run import run_stage1
from vulnversion.stage2_rci_navigation.run import run_stage2
from vulnversion.stage3_verify.run import run_stage3
from vulnversion.utils.cve_desc import ensure_cve_desc, fetch_cve_desc_from_nvd
from vulnversion.utils.dataset import list_fix_commits, load_dataset, pick_default_fix_commit
from vulnversion.utils.paths import Paths


def _project_root() -> Path:
  return Path(__file__).resolve().parents[1]


def _load_json(path: str | Path) -> Any:
  return json.loads(Path(path).read_text(encoding="utf-8"))


def _maybe_agent(cfg: Config, *, timeout_s: float) -> tuple[OpenCodeAgent | None, str | None]:
  if not cfg.opencode_base_url:
    return None, None
  auth = None
  if cfg.opencode_username and cfg.opencode_password:
    auth = OpenCodeAuth(username=cfg.opencode_username, password=cfg.opencode_password)
  client = OpenCodeClient(base_url=cfg.opencode_base_url, auth=auth, timeout_s=timeout_s)
  try:
    client.health()
  except Exception as e:
    raise RuntimeError(f"opencode_unreachable: {opencode_start_hint(cfg.opencode_base_url)}") from e
  agent = OpenCodeAgent(client=client, provider_id=cfg.opencode_provider_id, model_id=cfg.opencode_model_id, agent=cfg.opencode_agent)
  session_id = agent.create_readonly_session(title="VulnVersion-FFmpeg-Batch")
  return agent, session_id


def _read_cached_cve_desc(out_dir: Path) -> str | None:
  p = out_dir / "cve_desc.txt"
  if p.exists():
    t = p.read_text(encoding="utf-8").strip()
    return t or None
  return None


def _fetch_cve_desc_from_nvd(cve_id: str, *, timeout_s: float = 30.0) -> tuple[str, dict[str, Any]]:
  return fetch_cve_desc_from_nvd(cve_id, timeout_s=timeout_s)


def _ensure_cve_desc(cve_id: str, out_dir: Path, *, allow_fetch: bool) -> str:
  cached = _read_cached_cve_desc(out_dir)
  if cached is not None:
    return cached
  if not allow_fetch:
    raise RuntimeError(f"missing cve_desc.txt for {cve_id} and fetch disabled")
  desc, raw = _fetch_cve_desc_from_nvd(cve_id)
  return ensure_cve_desc(out_dir=out_dir, cve_desc=desc, cve_desc_file=None, cve_source_json=raw)


def _repo_dir(project_root: Path) -> Path:
  return project_root / "repo" / "FFmpeg"


def main(argv: list[str] | None = None) -> int:
  ap = argparse.ArgumentParser()
  ap.add_argument("--dataset", default=None)
  ap.add_argument("--config", default="vuln_config.json")
  ap.add_argument("--max-cves", type=int, default=5)
  ap.add_argument("--start", type=int, default=0)
  ap.add_argument("--skip-stage3", action="store_true")
  ap.add_argument("--max-tags", type=int, default=20)
  ap.add_argument("--tags-glob", default=None)
  ap.add_argument("--gt-match-mode", default="loose")
  ap.add_argument("--allow-fetch-cve-desc", action="store_true")
  ap.add_argument("--no-allow-fetch-cve-desc", dest="allow_fetch_cve_desc", action="store_false")
  ap.set_defaults(allow_fetch_cve_desc=True)
  ap.add_argument("--opencode-timeout", type=float, default=300.0)
  args = ap.parse_args(argv)

  project_root = _project_root()
  cfg = Config()
  cfg_path = Path(args.config)
  if not cfg_path.is_absolute():
    cfg_path = (project_root / cfg_path).resolve()
  if cfg_path.exists():
    cfg = Config.model_validate(_load_json(cfg_path))

  artifacts_root = (project_root / cfg.artifacts_dir).resolve() if not Path(cfg.artifacts_dir).is_absolute() else Path(cfg.artifacts_dir).resolve()
  if not artifacts_root.is_relative_to(project_root):
    raise SystemExit(f"artifacts_dir must be under {project_root}, got: {artifacts_root}")
  paths = Paths.from_root(project_root, str(artifacts_root))

  repo_path = _repo_dir(project_root)
  if not (repo_path / ".git").exists():
    raise SystemExit(f"FFmpeg repo not found: {repo_path}")

  dataset_path = Path(args.dataset) if args.dataset else Path(cfg.dataset_path)
  if not dataset_path.is_absolute():
    dataset_path = (project_root / dataset_path).resolve()
  if not dataset_path.exists():
    raise SystemExit(f"dataset not found: {dataset_path}")
  ds = load_dataset(dataset_path)
  ffmpeg_cves = [cve_id for cve_id, rec in ds.items() if isinstance(rec, dict) and rec.get("repo") == "FFmpeg"]
  ffmpeg_cves = sorted(ffmpeg_cves)

  start = max(0, int(args.start))
  max_cves = int(args.max_cves) if args.max_cves and int(args.max_cves) > 0 else len(ffmpeg_cves)
  targets = ffmpeg_cves[start : start + max_cves]

  print(f"[VulnVersion] FFmpeg CVEs total={len(ffmpeg_cves)}, running start={start}, count={len(targets)}")
  agent, session_id = _maybe_agent(cfg, timeout_s=float(args.opencode_timeout))
  print(f"[VulnVersion] OpenCode agent enabled, timeout_s={float(args.opencode_timeout)}")
  summary: list[dict[str, Any]] = []

  for cve_id in targets:
    rec = ds.get(cve_id) or {}
    out_dir = paths.ensure_dir(paths.cve_dir(cve_id))
    (out_dir / "dataset_record.json").write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")

    try:
      print(f"[VulnVersion] ==== {cve_id} ====")
      fix_commits = list_fix_commits(rec)
      fix_commit = pick_default_fix_commit(rec)
      cwe = list(rec.get("CWE") or [])
      gt = list(rec.get("affected_version") or [])
      print(f"[VulnVersion] Preparing CVE description (allow_fetch={bool(args.allow_fetch_cve_desc)})")
      cve_desc = _ensure_cve_desc(cve_id, out_dir, allow_fetch=args.allow_fetch_cve_desc)

      print(f"[VulnVersion] Stage1: semantic aggregation start (commit={fix_commit})")
      run_stage1(
        cve_id=cve_id,
        repo_path=str(repo_path),
        fix_commit=fix_commit,
        fix_commits=fix_commits,
        cve_desc=cve_desc,
        cwe=cwe,
        artifacts_dir=str(artifacts_root),
        dataset_record=rec,
        agent=agent,
        session_id=session_id,
      )
      print(f"[VulnVersion] Stage1: semantic aggregation done")

      print(f"[VulnVersion] Stage2: RCI induction start")
      run_stage2(
        cve_id=cve_id,
        repo_path=str(repo_path),
        fix_commit=fix_commit,
        vuln_commit=None,
        cve_desc=cve_desc,
        cwe=cwe,
        artifacts_dir=str(artifacts_root),
        patch_semantics_path=str(out_dir / "patch_semantics.json"),
        repomaster_root=cfg.repomaster_root,
        agent=agent,
        session_id=session_id,
      )
      print(f"[VulnVersion] Stage2: RCI induction done")

      if not args.skip_stage3:
        print(f"[VulnVersion] Stage3: tag verification start (glob={args.tags_glob})")
        run_stage3(
          cve_id=cve_id,
          repo_path=str(repo_path),
          artifacts_dir=str(artifacts_root),
          rci_path=str(out_dir / "rci.json"),
          fix_commit=fix_commit,
          fixing_commits=rec.get("fixing_commits"),
          tags_glob=args.tags_glob,
          resume=True,
          gt_affected_tags=gt,
          gt_match_mode=args.gt_match_mode,
          agent=agent,
          session_id=session_id,
        )
        print(f"[VulnVersion] Stage3: tag verification done")
      else:
        print(f"[VulnVersion] Stage3: skipped")

      summary.append({"cve_id": cve_id, "status": "ok"})
    except Exception as e:
      err = {"cve_id": cve_id, "status": "error", "error": str(e)}
      (out_dir / "run_error.json").write_text(json.dumps(err, ensure_ascii=False, indent=2), encoding="utf-8")
      summary.append(err)

  (paths.artifacts_dir / "ffmpeg_batch_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

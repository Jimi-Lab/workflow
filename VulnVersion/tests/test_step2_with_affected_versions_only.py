from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
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
from vulnversion.utils.cve_desc import ensure_cve_desc_from_nvd_cache_or_crawler
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
  session_id = agent.create_readonly_session(title="VulnVersion-step2-affected-only")
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


def _extract_verdict_summary(stage3_out: dict[str, Any]) -> dict[str, Any]:
  counts = {"AFFECTED": 0, "NOT_AFFECTED": 0, "INCONCLUSIVE": 0}
  for item in stage3_out.get("results") or []:
    verdict = str((item or {}).get("verdict") or "INCONCLUSIVE")
    counts[verdict] = counts.get(verdict, 0) + 1
  total = sum(counts.values())
  return {
    "total_verdicts": total,
    "counts": counts,
  }


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


def main(argv: list[str] | None = None) -> int:
  ap = argparse.ArgumentParser()
  ap.add_argument("--config", default="vuln_config.json")
  ap.add_argument("--dataset", default="DataSet/BaseDataSet_30.json")
  ap.add_argument("--artifacts-dir", default="Result_step12")
  ap.add_argument("--allow-fetch-cve-desc", action="store_true")
  ap.add_argument("--no-allow-fetch-cve-desc", dest="allow_fetch_cve_desc", action="store_false")
  ap.set_defaults(allow_fetch_cve_desc=True)
  ap.add_argument("--opencode-timeout", type=float, default=1200.0)
  ap.add_argument("--tag-timeout-s", type=float, default=300.0)
  ap.add_argument("--resume-stage3", action="store_true", help="Resume per_tag_verdict.jsonl in stage3")
  ap.add_argument("--resume-cve", action="store_true", help="Skip CVE if run_ok.json exists")
  args = ap.parse_args(argv)

  project_root = _project_root()

  cfg = Config()
  cfg_path = Path(args.config)
  if not cfg_path.is_absolute():
    cfg_path = (project_root / cfg_path).resolve()
  if cfg_path.exists():
    cfg = Config.model_validate(_load_json(cfg_path))

  dataset_path = Path(args.dataset)
  if not dataset_path.is_absolute():
    dataset_path = (project_root / dataset_path).resolve()
  if not dataset_path.exists():
    raise SystemExit(f"dataset not found: {dataset_path}")

  artifacts_root = (project_root / args.artifacts_dir).resolve() if not Path(args.artifacts_dir).is_absolute() else Path(args.artifacts_dir).resolve()
  if not artifacts_root.is_relative_to(project_root):
    raise SystemExit(f"artifacts_dir must be under {project_root}, got: {artifacts_root}")

  ds = load_dataset(dataset_path)
  by_repo = _group_dataset_by_repo(ds)
  if not by_repo:
    raise SystemExit(f"no valid records found in dataset: {dataset_path}")

  agent, session_id = _maybe_agent(cfg, timeout_s=float(args.opencode_timeout))
  if agent is None or session_id is None:
    raise SystemExit("opencode is required for this test")

  print(f"[VulnVersion] dataset={dataset_path}")
  print(f"[VulnVersion] artifacts_root={artifacts_root}")

  global_summary: list[dict[str, Any]] = []
  for repo_name in sorted(by_repo.keys()):
    repo_path = (project_root / "repo" / repo_name).resolve()
    if not (repo_path / ".git").exists():
      print(f"[VulnVersion] skip repo={repo_name} reason=repo_not_found path={repo_path}")
      for cve_id in by_repo[repo_name]:
        global_summary.append({"repo": repo_name, "cve_id": cve_id, "status": "skip", "reason": "repo_not_found"})
      continue

    paths = Paths.from_root(project_root, str(artifacts_root / repo_name))
    print(f"[VulnVersion] repo={repo_name} cves={len(by_repo[repo_name])}")

    for cve_id in by_repo[repo_name]:
      rec = ds.get(cve_id) or {}
      out_dir = paths.ensure_dir(paths.cve_dir(cve_id))
      (out_dir / "dataset_record.json").write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")

      if args.resume_cve and (out_dir / "run_ok.json").exists():
        print(f"[VulnVersion] skip repo={repo_name} cve={cve_id} reason=run_ok_exists")
        global_summary.append({"repo": repo_name, "cve_id": cve_id, "status": "skip", "reason": "run_ok_exists"})
        continue

      try:
        fix_commits = list_fix_commits(rec)
        fix_commit = pick_default_fix_commit(rec)
        cwe = list(rec.get("CWE") or [])
        affected_versions = [str(t).strip() for t in (rec.get("affected_version") or []) if str(t).strip()]
        if not affected_versions:
          raise RuntimeError("dataset_record has no affected_version")

        cve_desc = _ensure_cve_desc(
          cve_id,
          out_dir,
          allow_fetch=bool(args.allow_fetch_cve_desc),
          project_root=project_root,
          cfg=cfg,
        )

        print(f"[VulnVersion] repo={repo_name} cve={cve_id} Stage1 start")
        run_stage1(
          cve_id=cve_id,
          repo_path=str(repo_path),
          fix_commit=fix_commit,
          fix_commits=fix_commits,
          cve_desc=cve_desc,
          cwe=cwe,
          artifacts_dir=str(artifacts_root / repo_name),
          dataset_record=rec,
          agent=agent,
          session_id=session_id,
        )
        print(f"[VulnVersion] repo={repo_name} cve={cve_id} Stage1 done")

        print(f"[VulnVersion] repo={repo_name} cve={cve_id} Stage2 start")
        run_stage2(
          cve_id=cve_id,
          repo_path=str(repo_path),
          fix_commit=fix_commit,
          vuln_commit=None,
          cve_desc=cve_desc,
          cwe=cwe,
          artifacts_dir=str(artifacts_root / repo_name),
          patch_semantics_path=str(out_dir / "patch_semantics.json"),
          repomaster_root=cfg.repomaster_root,
          agent=agent,
          session_id=session_id,
        )
        print(f"[VulnVersion] repo={repo_name} cve={cve_id} Stage2 done")

        print(f"[VulnVersion] repo={repo_name} cve={cve_id} Stage3 start (affected_version only)")
        stage3_out = run_stage3(
          cve_id=cve_id,
          repo_path=str(repo_path),
          artifacts_dir=str(artifacts_root / repo_name),
          rci_path=str(out_dir / "rci.json"),
          fix_commit=fix_commit,
          tags=affected_versions,
          tags_glob=None,
          tag_timeout_s=float(args.tag_timeout_s),
          resume=bool(args.resume_stage3),
          gt_affected_tags=affected_versions,
          gt_match_mode=cfg.gt_tag_match_mode,
          agent=agent,
          session_id=None,
          per_tag_session=True,
          log_progress=True,
        )
        print(f"[VulnVersion] repo={repo_name} cve={cve_id} Stage3 done")

        summary = {
          "repo": repo_name,
          "cve_id": cve_id,
          "fix_commit": fix_commit,
          "affected_versions_input": affected_versions,
          "stage3_summary": _extract_verdict_summary(stage3_out),
          "stage3_tags_scanned": stage3_out.get("tags") or [],
          "status": "ok",
        }
        (out_dir / "step2_affected_only_summary.json").write_text(
          json.dumps(summary, ensure_ascii=False, indent=2),
          encoding="utf-8",
        )
        (out_dir / "run_ok.json").write_text(
          json.dumps({"repo": repo_name, "cve_id": cve_id, "status": "ok"}, ensure_ascii=False, indent=2),
          encoding="utf-8",
        )
        global_summary.append(summary)
      except Exception as e:
        err = {
          "repo": repo_name,
          "cve_id": cve_id,
          "status": "error",
          "error": str(e),
          "error_type": type(e).__name__,
        }
        (out_dir / "run_error.json").write_text(json.dumps(err, ensure_ascii=False, indent=2), encoding="utf-8")
        global_summary.append(err)
        print(f"[VulnVersion] repo={repo_name} cve={cve_id} error={type(e).__name__}: {e}")

  (artifacts_root / "step2_affected_only_global_summary.json").write_text(
    json.dumps(global_summary, ensure_ascii=False, indent=2),
    encoding="utf-8",
  )
  print(f"[VulnVersion] global summary saved: {artifacts_root / 'step2_affected_only_global_summary.json'}")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

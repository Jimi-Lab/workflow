from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path

from vulnversion.agent_harness.runtimes.opencode_runtime import OpenCodeRuntime
from vulnversion.agent_harness.service import AgentService
from vulnversion.agent_harness.trace import JsonlTraceWriter
from vulnversion.config import Config
from vulnversion.stage3_verify.run import run_stage3


def _read_tags(path: Path) -> list[str]:
  tags: list[str] = []
  for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    if not line.strip():
      continue
    row = json.loads(line)
    tag = str(row.get("tag") or "")
    if tag and tag not in tags:
      tags.append(tag)
  return tags


def main() -> int:
  ap = argparse.ArgumentParser()
  ap.add_argument("--version", choices=["v0", "v1"], required=True)
  ap.add_argument("--repo", default="FFmpeg")
  ap.add_argument("--cve", default="CVE-2020-13904")
  ap.add_argument("--resume", action="store_true")
  ap.add_argument("--limit", type=int, default=0)
  ap.add_argument("--tag", action="append", default=[])
  ap.add_argument("--tag-source", default="")
  ap.add_argument("--experiment-root", default="Result_stage3_ab")
  ap.add_argument("--tag-timeout-s", type=float, default=300.0)
  args = ap.parse_args()

  project = Path(__file__).resolve().parents[1]
  source = project / "Result" / args.repo / args.cve
  repo = project / "repo" / args.repo
  record = json.loads((source / "dataset_record.json").read_text(encoding="utf-8"))
  tag_source = Path(args.tag_source) if args.tag_source else source / "per_tag_verdict.jsonl"
  if not tag_source.is_absolute():
    tag_source = (project / tag_source).resolve()
  tags = _read_tags(tag_source)
  if args.tag:
    requested = set(args.tag)
    tags = [tag for tag in tags if tag in requested]
    for tag in args.tag:
      if tag not in tags:
        tags.append(tag)
  if args.limit > 0:
    tags = tags[: args.limit]

  out_root = project / args.experiment_root / args.version / args.repo
  out_dir = out_root / args.cve
  if out_dir.exists() and not args.resume:
    shutil.rmtree(out_dir)
  out_dir.mkdir(parents=True, exist_ok=True)
  shutil.copy2(source / "dataset_record.json", out_dir / "dataset_record.json")
  shutil.copy2(source / "rci.json", out_dir / "rci.json")

  cfg = Config(opencode_base_url="http://127.0.0.1:4096")
  runtime = OpenCodeRuntime.from_config(cfg, timeout_s=600.0, health_check=True, project_root=project)
  session_id = runtime.create_readonly_session(title=f"VulnVersion-stage3-ab-{args.version}-{args.cve}")
  agent = AgentService(
    runtime=runtime,
    trace_writer=JsonlTraceWriter(out_dir / "agent_trace.jsonl"),
    default_metadata={
      "repo": args.repo,
      "cve_id": args.cve,
      "repo_path": str(repo),
      "agent_backend": getattr(runtime, "backend", "unknown"),
    },
  )
  agent.register_session(
    session_id=session_id,
    title=f"VulnVersion-stage3-ab-{args.version}",
    role="initial",
    metadata={"repo": args.repo, "cve_id": args.cve, "prompt_version": args.version},
  )
  agent.write_runtime_manifest(out_dir / "agent_runtime.json")
  print(f"RUN {args.version} start tags={len(tags)} resume={args.resume}", flush=True)
  t0 = time.time()
  result = run_stage3(
    cve_id=args.cve,
    repo_path=str(repo),
    artifacts_dir=str(out_root),
    rci_path=str(source / "rci.json"),
    fixing_commits=record.get("fixing_commits"),
    tags=tags,
    tag_timeout_s=float(args.tag_timeout_s),
    resume=args.resume,
    gt_affected_tags=record.get("affected_version"),
    gt_match_mode="loose",
    agent=agent,
    session_id=session_id,
    per_tag_session=True,
    log_progress=True,
    stage3_prompt_version=args.version,
  )
  agent.write_runtime_manifest(out_dir / "agent_runtime.json")
  messages = agent.export_known_session_messages()
  with (out_dir / "opencode_messages_all.jsonl").open("w", encoding="utf-8") as f:
    for item in messages:
      f.write(json.dumps(item, ensure_ascii=False) + "\n")
  print(
    "RUN %s done seconds=%.1f tags_verified=%s"
    % (args.version, time.time() - t0, result.get("tags_verified")),
    flush=True,
  )
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

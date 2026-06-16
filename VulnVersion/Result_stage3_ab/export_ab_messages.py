from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulnversion.agent_harness.runtimes.opencode_runtime import OpenCodeRuntime
from vulnversion.config import Config


def main() -> int:
  ap = argparse.ArgumentParser()
  ap.add_argument("--version", choices=["v0", "v1"], required=True)
  ap.add_argument("--experiment-root", default="Result_stage3_ab")
  ap.add_argument("--repo", default="")
  ap.add_argument("--cve", default="")
  args = ap.parse_args()

  project = Path(__file__).resolve().parents[1]
  root = project / args.experiment_root / args.version
  if args.repo and args.cve:
    out_dirs = [root / args.repo / args.cve]
  else:
    out_dirs = [p for p in root.glob("*/*") if (p / "agent_runtime.json").exists()]
  runtime = OpenCodeRuntime.from_config(
    Config(opencode_base_url="http://127.0.0.1:4096"),
    timeout_s=120.0,
    health_check=True,
    project_root=project,
  )
  total_sessions = 0
  for out_dir in out_dirs:
    manifest = json.loads((out_dir / "agent_runtime.json").read_text(encoding="utf-8"))
    sessions = manifest.get("known_sessions") or []
    index_path = out_dir / "agent_calls" / "index.jsonl"
    if index_path.exists():
      seen = {str(s.get("session_id") or "") for s in sessions}
      for line in index_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
          continue
        row = json.loads(line)
        session_id = str(row.get("session_id") or "")
        if session_id and session_id not in seen:
          sessions.append({
            "session_id": session_id,
            "backend": row.get("backend") or "opencode",
            "title": f"agent_calls:{row.get('stage')}:{row.get('task_type')}:{row.get('trace_id')}",
            "role": f"{row.get('stage')}:{row.get('task_type')}",
            "last_trace_id": row.get("trace_id"),
          })
          seen.add(session_id)
    with (out_dir / "opencode_messages_all.jsonl").open("w", encoding="utf-8") as f:
      for session in sessions:
        session_id = str(session.get("session_id") or "")
        if not session_id:
          continue
        messages = runtime.export_session_messages(session_id=session_id)
        f.write(json.dumps({
          "session": session,
          "messages_count": len(messages),
          "messages": messages,
        }, ensure_ascii=False) + "\n")
    total_sessions += len(sessions)
    print(f"exported {len(sessions)} sessions for {args.version} {out_dir.parent.name}/{out_dir.name}")
  print(f"exported total {total_sessions} sessions for {args.version}")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

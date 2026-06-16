from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from vulngraph.agent_backend import OpenCodeBackend, OpenCodeBackendConfig, add_opencode_model_arguments
from vulngraph.agent_backends import FixtureSzzAnchorBackend, OpenCodeGenerateBackend
from vulngraph.workflows.szz_anchor_audit import (
  DEFAULT_SZZ_AUDIT_CVES,
  run_szz_anchor_audit,
  verify_szz_audit_preconditions,
)


DEFAULT_ROOT_CAUSE_RUN = Path("runs/batches/root-cause-v2-optimized-contract-10")
DEFAULT_DATASET = Path(r"E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json")
DEFAULT_REPO_ROOT = Path(r"E:\AI\Agent\workflow\VulnVersion\repo")


def main() -> None:
  parser = argparse.ArgumentParser(description="Audit Root Cause outputs as wrapper-owned pre-fix SZZ anchors.")
  parser.add_argument("--root-cause-run", type=Path, default=DEFAULT_ROOT_CAUSE_RUN)
  parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
  parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
  parser.add_argument("--out-dir", type=Path, required=True)
  parser.add_argument("--cves", nargs="+", default=DEFAULT_SZZ_AUDIT_CVES)
  parser.add_argument("--base-url", default="http://127.0.0.1:4096")
  add_opencode_model_arguments(parser)
  parser.add_argument("--agent")
  parser.add_argument("--timeout", type=float, default=300.0)
  parser.add_argument("--reset", action="store_true")
  parser.add_argument("--fixture", action="store_true", help="Engineering-only deterministic fixture; not a real agent audit.")
  parser.add_argument("--engineering-smoke", action="store_true", help="Run a real-agent engineering smoke without requiring completed semantic labels.")
  parser.add_argument("--allow-shallow-diagnostic", action="store_true", help="Allow shallow-history cases only as censored diagnostic outputs.")
  parser.add_argument("--top-k-per-patch-family", type=int, default=40)
  args = parser.parse_args()

  cve_ids = _parse_cves(args.cves)
  if args.reset and args.out_dir.exists():
    shutil.rmtree(args.out_dir)
  args.out_dir.mkdir(parents=True, exist_ok=True)

  if args.fixture:
    backend = FixtureSzzAnchorBackend()
    preconditions = {
      "ready": True,
      "mode": "fixture",
      "warning": "Fixture mode bypasses formal OpenCode/manual-label preconditions and is not a real agent result.",
      "provider_id": "fixture",
      "model_id": "fixture",
    }
  else:
    config = OpenCodeBackendConfig(
      base_url=args.base_url,
      provider_id=args.provider_id,
      model_id=args.model_id,
      agent=args.agent,
      timeout_s=args.timeout,
      max_retries=0,
    )
    low_level = OpenCodeBackend(config)
    try:
      health = low_level.health()
    except Exception as error:
      health = {"healthy": False, "error": str(error)}
    preconditions = verify_szz_audit_preconditions(
      cve_ids,
      root_cause_run=args.root_cause_run,
      dataset=args.dataset,
      repo_root=args.repo_root,
      opencode_health=health,
      provider_id=args.provider_id,
      model_id=args.model_id,
      require_semantic_labels=not args.engineering_smoke,
      mode="engineering_smoke" if args.engineering_smoke else "formal",
      allow_shallow_diagnostic=args.allow_shallow_diagnostic,
    )
    _write_json(args.out_dir / "preconditions.json", preconditions)
    if not preconditions["ready"]:
      (args.out_dir / "report.md").write_text(_render_blocked_report(preconditions), encoding="utf-8")
      print(json.dumps(preconditions, ensure_ascii=False, indent=2))
      raise SystemExit(2)
    backend = OpenCodeGenerateBackend(config, timeout_s=args.timeout)

  _write_json(args.out_dir / "preconditions.json", preconditions)
  summary = run_szz_anchor_audit(
    cve_ids,
    root_cause_run=args.root_cause_run,
    dataset=args.dataset,
    repo_root=args.repo_root,
    out_dir=args.out_dir,
    backend=backend,
    top_k_per_patch_family=args.top_k_per_patch_family,
  )
  summary.update(
    {
      "execution_mode": "fixture" if args.fixture else ("engineering_smoke" if args.engineering_smoke else "real_opencode"),
      "provider_id": "fixture" if args.fixture else args.provider_id,
      "model_id": "fixture" if args.fixture else args.model_id,
      "base_url": "" if args.fixture else args.base_url,
      "command": " ".join([Path(sys.argv[0]).name, *sys.argv[1:]]),
    }
  )
  _write_json(args.out_dir / "summary.json", summary)
  print(json.dumps(summary, ensure_ascii=False, indent=2))


def _parse_cves(values: list[str]) -> list[str]:
  output: list[str] = []
  for value in values:
    output.extend(item.strip() for item in value.split(",") if item.strip())
  return output


def _write_json(path: Path, data: object) -> None:
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _render_blocked_report(preconditions: dict) -> str:
  return "\n".join(
    [
      "# Root Cause to SZZ Anchor Audit Blocked",
      "",
      "The formal audit did not start because required independent preconditions were not satisfied.",
      "",
      f"- Blocking reasons: `{preconditions.get('blocking_reasons', [])}`",
      f"- Structurally accepted: {preconditions.get('structurally_accepted', 0)}",
      f"- Semantic labels complete: {preconditions.get('semantic_labels_complete', False)}",
      f"- Fix commits with parents: {preconditions.get('fix_commits_with_parents', 0)}",
      f"- Shallow history cases: `{preconditions.get('shallow_history_cases', [])}`",
      f"- Allow shallow diagnostic: {preconditions.get('allow_shallow_diagnostic', False)}",
      "",
      "No OpenCode anchor selection was invoked and no formal before/after result was produced.",
    ]
  ) + "\n"


if __name__ == "__main__":
  main()

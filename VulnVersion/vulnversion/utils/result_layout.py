from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import shutil
from typing import Any


LAYOUT_SCHEMA_VERSION = "v1"


@dataclass(frozen=True)
class ResultLayout:
  """Canonical per-CVE result layout.

  The current pipeline still writes legacy flat files for compatibility.  This
  layout provides the stable structured view used by humans, papers, and future
  analysis scripts.
  """

  root: Path

  @property
  def cve_info(self) -> Path:
    return self.root / "cve_info"

  @property
  def step1(self) -> Path:
    return self.root / "step1"

  @property
  def step2(self) -> Path:
    return self.root / "step2"

  @property
  def step3(self) -> Path:
    return self.root / "step3"

  @property
  def final(self) -> Path:
    return self.root / "final"

  @property
  def run_logs(self) -> Path:
    return self.root / "run_logs"

  @property
  def manifest(self) -> Path:
    return self.root / "manifest.json"

  def ensure(self) -> "ResultLayout":
    for path in [
      self.cve_info,
      self.step1 / "output",
      self.step1 / "agent_calls",
      self.step2 / "output",
      self.step2 / "agent_calls",
      self.step3 / "planning",
      self.step3 / "verification",
      self.step3 / "intervals",
      self.step3 / "evaluation",
      self.step3 / "agent_calls",
      self.final,
      self.run_logs,
    ]:
      path.mkdir(parents=True, exist_ok=True)
    return self


def get_result_layout(cve_dir: str | Path) -> ResultLayout:
  return ResultLayout(root=Path(cve_dir)).ensure()


def materialize_result_layout(
  cve_dir: str | Path,
  *,
  repo: str | None = None,
  cve_id: str | None = None,
  dataset_path: str | Path | None = None,
  status: str | None = None,
) -> dict[str, Any]:
  """Populate the structured result layout from the legacy flat artifacts.

  This is intentionally non-destructive: legacy flat files remain in place.
  Existing structured files are overwritten with the latest flat artifacts so a
  resumed run always leaves a coherent structured snapshot.
  """

  layout = get_result_layout(cve_dir)
  root = layout.root

  copied: dict[str, str] = {}

  def copy_if_exists(src_name: str, dst: Path) -> None:
    src = root / src_name
    if not src.exists() or not src.is_file():
      return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    copied[src_name] = _rel(root, dst)

  # CVE source inputs.
  for name in ["dataset_record.json", "cve_source.json", "cve_desc.txt", "fix_commits.json", "patch_metadata.json"]:
    copy_if_exists(name, layout.cve_info / name)

  # Step outputs.
  copy_if_exists("patch_semantics.json", layout.step1 / "output" / "patch_semantics.json")

  for name in [
    "rci.json",
    "rci_self_check.json",
    "vet.json",
    "repomaster_index.json",
    "rci_parse_invalid.json",
    "rci_parse_invalid.txt",
    "rci_raw_invalid.json",
    "rci_normalized_invalid.json",
  ]:
    copy_if_exists(name, layout.step2 / "output" / name)

  for name in ["tag_plan.json", "vuln_tree.json", "vuln_tree_runtime.json", "scheduler_plan.json"]:
    copy_if_exists(name, layout.step3 / "planning" / name)
  for name in ["per_tag_verdict.jsonl", "per_tag_verdict.csv"]:
    copy_if_exists(name, layout.step3 / "verification" / name)
  for name in ["line_boundaries.json", "line_intervals.json", "affected_intervals.json"]:
    copy_if_exists(name, layout.step3 / "intervals" / name)
  copy_if_exists("eval.json", layout.step3 / "evaluation" / "step3_eval.json")

  # Final outputs.  Keep final/eval.json as the public evaluation entrypoint.
  copy_if_exists("eval.json", layout.final / "eval.json")
  copy_if_exists("run_ok.json", layout.final / "run_ok.json")
  copy_if_exists("run_error.json", layout.final / "run_error.json")
  copy_if_exists("affected_intervals.json", layout.final / "affected_intervals.json")
  _write_final_affected_versions(layout)

  # Run-level backend logs.
  for name in [
    "agent_runtime.json",
    "agent_sessions.json",
    "agent_trace.jsonl",
    "opencode_session.json",
    "opencode_messages.json",
    "opencode_messages.jsonl",
    "opencode_messages_all.jsonl",
    "cost_summary.json",
    "environment.json",
    "pipeline_events.jsonl",
  ]:
    copy_if_exists(name, layout.run_logs / name)

  _split_agent_trace_and_calls(layout)

  manifest = _build_manifest(
    layout,
    repo=repo,
    cve_id=cve_id,
    dataset_path=dataset_path,
    status=status,
    copied=copied,
  )
  layout.manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
  return manifest


def _split_agent_trace_and_calls(layout: ResultLayout) -> None:
  trace_path = layout.root / "agent_trace.jsonl"
  if not trace_path.exists():
    return

  stage_to_dir = {
    "stage1": layout.step1,
    "step1": layout.step1,
    "stage2": layout.step2,
    "step2": layout.step2,
    "stage3": layout.step3,
    "step3": layout.step3,
  }
  stage_events: dict[Path, list[dict[str, Any]]] = {
    layout.step1: [],
    layout.step2: [],
    layout.step3: [],
  }

  for raw in trace_path.read_text(encoding="utf-8", errors="ignore").splitlines():
    if not raw.strip():
      continue
    try:
      event = json.loads(raw)
    except Exception:
      continue
    stage = str(event.get("stage") or "").lower()
    dst_stage_dir = stage_to_dir.get(stage)
    if dst_stage_dir is None:
      continue
    event = dict(event)
    _copy_event_agent_artifact(layout.root, event, "prompt_path", dst_stage_dir / "agent_calls")
    _copy_event_agent_artifact(layout.root, event, "system_path", dst_stage_dir / "agent_calls")
    _copy_event_agent_artifact(layout.root, event, "parsed_output_path", dst_stage_dir / "agent_calls")
    stage_events[dst_stage_dir].append(event)

  for stage_dir, events in stage_events.items():
    if not events:
      continue
    trace_out = stage_dir / "trace.jsonl"
    trace_out.parent.mkdir(parents=True, exist_ok=True)
    with trace_out.open("w", encoding="utf-8") as f:
      for event in events:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def _copy_event_agent_artifact(root: Path, event: dict[str, Any], field: str, dst_dir: Path) -> None:
  value = event.get(field)
  if not value:
    return
  src = Path(str(value))
  if not src.exists() or not src.is_file():
    return
  dst_dir.mkdir(parents=True, exist_ok=True)
  dst = dst_dir / src.name
  shutil.copy2(src, dst)
  event[field] = str(dst.resolve())
  # Keep paths relative-readable for new consumers without breaking the legacy
  # absolute path fields expected by old analysis scripts.
  event[f"{field}_rel"] = _rel(root, dst)


def _write_final_affected_versions(layout: ResultLayout) -> None:
  intervals_path = layout.root / "affected_intervals.json"
  eval_path = layout.root / "eval.json"
  tags: list[str] = []
  source = None

  if eval_path.exists():
    try:
      obj = json.loads(eval_path.read_text(encoding="utf-8"))
      predicted = obj.get("predicted_affected_tags")
      if isinstance(predicted, list):
        tags = [str(t) for t in predicted if str(t)]
        source = "eval.predicted_affected_tags"
    except Exception:
      pass

  if not tags and intervals_path.exists():
    try:
      intervals = json.loads(intervals_path.read_text(encoding="utf-8"))
      seen: set[str] = set()
      for item in intervals if isinstance(intervals, list) else []:
        for tag in list((item or {}).get("tags") or []):
          text = str(tag)
          if text and text not in seen:
            seen.add(text)
            tags.append(text)
      source = "affected_intervals"
    except Exception:
      pass

  if not tags:
    return
  out = {
    "affected_versions": tags,
    "affected_count": len(tags),
    "source": source,
    "source_artifacts": [
      "step3/verification/per_tag_verdict.jsonl",
      "step3/intervals/affected_intervals.json",
      "final/eval.json",
    ],
  }
  (layout.final / "affected_versions.json").write_text(
    json.dumps(out, ensure_ascii=False, indent=2),
    encoding="utf-8",
  )


def _build_manifest(
  layout: ResultLayout,
  *,
  repo: str | None,
  cve_id: str | None,
  dataset_path: str | Path | None,
  status: str | None,
  copied: dict[str, str],
) -> dict[str, Any]:
  inferred_status = status or _infer_status(layout)
  return {
    "schema_version": LAYOUT_SCHEMA_VERSION,
    "repo": repo,
    "cve_id": cve_id,
    "dataset": str(dataset_path) if dataset_path is not None else None,
    "status": inferred_status,
    "layout": {
      "cve_info": "cve_info/",
      "step1": "step1/",
      "step2": "step2/",
      "step3": "step3/",
      "final": "final/",
      "run_logs": "run_logs/",
    },
    "stages": {
      "step1": {
        "status": "ok" if (layout.step1 / "output" / "patch_semantics.json").exists() else "missing",
        "output": _rel_if_exists(layout.root, layout.step1 / "output" / "patch_semantics.json"),
        "trace": _rel_if_exists(layout.root, layout.step1 / "trace.jsonl"),
      },
      "step2": {
        "status": "ok" if (layout.step2 / "output" / "rci.json").exists() else "missing",
        "output": _rel_if_exists(layout.root, layout.step2 / "output" / "rci.json"),
        "self_check": _rel_if_exists(layout.root, layout.step2 / "output" / "rci_self_check.json"),
        "trace": _rel_if_exists(layout.root, layout.step2 / "trace.jsonl"),
      },
      "step3": {
        "status": "ok" if (layout.step3 / "verification" / "per_tag_verdict.jsonl").exists() else "missing",
        "plan": _rel_if_exists(layout.root, layout.step3 / "planning" / "tag_plan.json"),
        "scheduler": _rel_if_exists(layout.root, layout.step3 / "planning" / "scheduler_plan.json"),
        "verdicts": _rel_if_exists(layout.root, layout.step3 / "verification" / "per_tag_verdict.jsonl"),
        "eval": _rel_if_exists(layout.root, layout.step3 / "evaluation" / "step3_eval.json"),
        "trace": _rel_if_exists(layout.root, layout.step3 / "trace.jsonl"),
      },
    },
    "final": {
      "affected_versions": _rel_if_exists(layout.root, layout.final / "affected_versions.json"),
      "affected_intervals": _rel_if_exists(layout.root, layout.final / "affected_intervals.json"),
      "eval": _rel_if_exists(layout.root, layout.final / "eval.json"),
      "run_ok": _rel_if_exists(layout.root, layout.final / "run_ok.json"),
      "run_error": _rel_if_exists(layout.root, layout.final / "run_error.json"),
    },
    "run_logs": {
      "agent_runtime": _rel_if_exists(layout.root, layout.run_logs / "agent_runtime.json"),
      "agent_sessions": _rel_if_exists(layout.root, layout.run_logs / "agent_sessions.json"),
      "agent_trace": _rel_if_exists(layout.root, layout.run_logs / "agent_trace.jsonl"),
      "opencode_messages_all": _rel_if_exists(layout.root, layout.run_logs / "opencode_messages_all.jsonl"),
    },
    "legacy_flat_files_mirrored": copied,
  }


def _infer_status(layout: ResultLayout) -> str:
  if (layout.root / "run_ok.json").exists() or (layout.final / "run_ok.json").exists():
    return "ok"
  if (layout.root / "run_error.json").exists() or (layout.final / "run_error.json").exists():
    return "error"
  return "unknown"


def _rel_if_exists(root: Path, path: Path) -> str | None:
  if not path.exists():
    return None
  return _rel(root, path)


def _rel(root: Path, path: Path) -> str:
  try:
    return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
  except Exception:
    return str(path)

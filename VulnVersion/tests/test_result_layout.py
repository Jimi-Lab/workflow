from __future__ import annotations

import json
from pathlib import Path

from vulnversion.utils.result_layout import materialize_result_layout


def _write_json(path: Path, obj: object) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def test_result_layout_materializes_stage_outputs(tmp_path: Path) -> None:
  cve_dir = tmp_path / "Result" / "linux" / "CVE-X"
  cve_dir.mkdir(parents=True)
  _write_json(cve_dir / "dataset_record.json", {"repo": "linux"})
  (cve_dir / "cve_desc.txt").write_text("desc", encoding="utf-8")
  _write_json(cve_dir / "patch_semantics.json", {"stage": 1})
  _write_json(cve_dir / "rci.json", {"stage": 2})
  _write_json(cve_dir / "rci_self_check.json", {"pass": True})
  _write_json(cve_dir / "tag_plan.json", {"plan_kind": "vuln_tree"})
  _write_json(cve_dir / "vuln_tree.json", {"lines": {}})
  _write_json(cve_dir / "scheduler_plan.json", {"name": "staged"})
  (cve_dir / "per_tag_verdict.jsonl").write_text('{"tag":"v1","verdict":"AFFECTED"}\n', encoding="utf-8")
  _write_json(cve_dir / "affected_intervals.json", [{"line": "1.0", "tags": ["v1"]}])
  _write_json(cve_dir / "eval.json", {"predicted_affected_tags": ["v1"]})
  _write_json(cve_dir / "run_ok.json", {"status": "ok"})

  manifest = materialize_result_layout(
    cve_dir,
    repo="linux",
    cve_id="CVE-X",
    dataset_path="DataSet/BaseDataOrder.json",
  )

  assert (cve_dir / "cve_info" / "dataset_record.json").exists()
  assert (cve_dir / "step1" / "output" / "patch_semantics.json").exists()
  assert (cve_dir / "step2" / "output" / "rci.json").exists()
  assert (cve_dir / "step3" / "planning" / "tag_plan.json").exists()
  assert (cve_dir / "step3" / "verification" / "per_tag_verdict.jsonl").exists()
  assert (cve_dir / "step3" / "intervals" / "affected_intervals.json").exists()
  assert (cve_dir / "step3" / "evaluation" / "step3_eval.json").exists()
  assert (cve_dir / "final" / "eval.json").exists()
  assert (cve_dir / "final" / "run_ok.json").exists()
  affected = json.loads((cve_dir / "final" / "affected_versions.json").read_text(encoding="utf-8"))
  assert affected["affected_versions"] == ["v1"]
  assert manifest["status"] == "ok"
  assert manifest["stages"]["step3"]["verdicts"] == "step3/verification/per_tag_verdict.jsonl"


def test_result_layout_splits_agent_trace_by_stage(tmp_path: Path) -> None:
  cve_dir = tmp_path / "Result" / "qemu" / "CVE-Y"
  calls = cve_dir / "agent_calls"
  calls.mkdir(parents=True)
  for trace_id in ["s1", "s2", "s3"]:
    (calls / f"{trace_id}.prompt.txt").write_text(f"prompt {trace_id}", encoding="utf-8")
    _write_json(calls / f"{trace_id}.parsed.json", {"trace_id": trace_id})
  events = [
    {
      "trace_id": "s1",
      "stage": "stage1",
      "prompt_path": str((calls / "s1.prompt.txt").resolve()),
      "parsed_output_path": str((calls / "s1.parsed.json").resolve()),
    },
    {
      "trace_id": "s2",
      "stage": "stage2",
      "prompt_path": str((calls / "s2.prompt.txt").resolve()),
      "parsed_output_path": str((calls / "s2.parsed.json").resolve()),
    },
    {
      "trace_id": "s3",
      "stage": "stage3",
      "prompt_path": str((calls / "s3.prompt.txt").resolve()),
      "parsed_output_path": str((calls / "s3.parsed.json").resolve()),
    },
  ]
  with (cve_dir / "agent_trace.jsonl").open("w", encoding="utf-8") as f:
    for event in events:
      f.write(json.dumps(event, ensure_ascii=False) + "\n")

  materialize_result_layout(cve_dir, repo="qemu", cve_id="CVE-Y")

  assert (cve_dir / "step1" / "trace.jsonl").exists()
  assert (cve_dir / "step2" / "trace.jsonl").exists()
  assert (cve_dir / "step3" / "trace.jsonl").exists()
  assert (cve_dir / "step1" / "agent_calls" / "s1.prompt.txt").exists()
  assert (cve_dir / "step2" / "agent_calls" / "s2.prompt.txt").exists()
  assert (cve_dir / "step3" / "agent_calls" / "s3.prompt.txt").exists()
  step3_event = json.loads((cve_dir / "step3" / "trace.jsonl").read_text(encoding="utf-8").strip())
  assert step3_event["prompt_path_rel"] == "step3/agent_calls/s3.prompt.txt"

from __future__ import annotations

import inspect
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = PROJECT_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
  sys.path.insert(0, str(PROJECT_ROOT))


def _read(path: Path) -> str:
  return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def _check(id_: str, ok: bool, evidence: str, *, level: str = "static") -> dict[str, Any]:
  return {"id": id_, "status": "pass" if ok else "fail", "level": level, "evidence": evidence}


def main() -> int:
  required_files = [
    PROJECT_ROOT / "vulnversion/agent_harness/base.py",
    PROJECT_ROOT / "vulnversion/agent_harness/task.py",
    PROJECT_ROOT / "vulnversion/agent_harness/result.py",
    PROJECT_ROOT / "vulnversion/agent_harness/service.py",
    PROJECT_ROOT / "vulnversion/agent_harness/trace.py",
    PROJECT_ROOT / "vulnversion/agent_harness/json_utils.py",
    PROJECT_ROOT / "vulnversion/agent_harness/config.py",
    PROJECT_ROOT / "vulnversion/agent_harness/runtimes/opencode_runtime.py",
    PROJECT_ROOT / "vulnversion/agent_harness/runtimes/codex_runtime.py",
    PROJECT_ROOT / "vulnversion/agent_harness/runtimes/claude_runtime.py",
    PROJECT_ROOT / "vulnversion/agent_harness/runtimes/replay_runtime.py",
    PROJECT_ROOT / "vulnversion/agent_harness/prompts/provenance.py",
    PROJECT_ROOT / "vulnversion/agent_harness/prompts/renderer.py",
    PROJECT_ROOT / "vulnversion/agent_harness/memory/schema.py",
    PROJECT_ROOT / "vulnversion/agent_harness/skills/schema.py",
    PROJECT_ROOT / "vulnversion/self_evolve/__init__.py",
    PROJECT_ROOT / "vulnversion/self_evolve/schema.py",
    PROJECT_ROOT / "vulnversion/self_evolve/trace_loader.py",
    PROJECT_ROOT / "vulnversion/self_evolve/failure_attributor.py",
    PROJECT_ROOT / "vulnversion/self_evolve/hard_cases.py",
    PROJECT_ROOT / "vulnversion/self_evolve/case_pack.py",
    PROJECT_ROOT / "vulnversion/self_evolve/memory_candidates.py",
    PROJECT_ROOT / "vulnversion/self_evolve/memory_store.py",
    PROJECT_ROOT / "vulnversion/self_evolve/leakage_gate.py",
    PROJECT_ROOT / "vulnversion/self_evolve/promotion_gate.py",
    PROJECT_ROOT / "tests/build_agent_enhance_cases.py",
    PROJECT_ROOT / "tests/build_memory_candidates.py",
    PROJECT_ROOT / "tests/check_memory_candidates.py",
    PROJECT_ROOT / "tests/check_opencode_skills.py",
    PROJECT_ROOT / "tests/evaluate_agent_enhancement.py",
  ]
  stage_files = [
    PROJECT_ROOT / "main.py",
    PROJECT_ROOT / "vulnversion/stage1_semantic_aggregation/annotate_chunks.py",
    PROJECT_ROOT / "vulnversion/stage1_semantic_aggregation/run.py",
    PROJECT_ROOT / "vulnversion/stage2_rci_navigation/induce_rci.py",
    PROJECT_ROOT / "vulnversion/stage2_rci_navigation/run.py",
    PROJECT_ROOT / "vulnversion/stage3_verify/run.py",
    PROJECT_ROOT / "vulnversion/stage3_verify/verify_tags.py",
  ]
  direct_opencode_agent_hits = [
    str(p.relative_to(PROJECT_ROOT))
    for p in stage_files
    if "OpenCodeAgent" in _read(p)
  ]

  checks: list[dict[str, Any]] = []
  missing = [str(p.relative_to(PROJECT_ROOT)) for p in required_files if not p.exists()]
  checks.append(_check("agent_harness_required_files", not missing, f"missing={missing}"))
  checks.append(_check("stage_direct_opencodeagent_removed", not direct_opencode_agent_hits, f"hits={direct_opencode_agent_hits}"))

  try:
    from vulnversion.agent_harness.runtimes.opencode_runtime import OpenCodeRuntime
    from vulnversion.agent_harness.runtimes.replay_runtime import ReplayMissError, ReplayRuntime
    from vulnversion.agent_harness.trace import stable_text_hash
    from vulnversion.config import Config
    from vulnversion.self_evolve import build_case_pack
    from vulnversion.self_evolve.memory_store import build_memory_store
    from vulnversion.self_evolve.promotion_gate import apply_promotion_gates
    from vulnversion.stage1_semantic_aggregation.run import run_stage1
    from vulnversion.stage2_rci_navigation.run import run_stage2
    from vulnversion.stage3_verify.run import run_stage3

    import_ok = all([OpenCodeRuntime, Config, run_stage1, run_stage2, run_stage3])
    checks.append(_check("imports_core_agent_harness", bool(import_ok), "core imports completed"))
    sig = inspect.signature(run_stage3)
    deprecated_stage3_args = {"max_tags", "early_stop_n", "bisect_enabled"}
    checks.append(_check(
      "stage3_deprecated_runtime_args_removed",
      not any(name in sig.parameters for name in deprecated_stage3_args),
      str(sig),
    ))
    with tempfile.TemporaryDirectory() as tmp:
      tmp_dir = Path(tmp)
      parsed_path = tmp_dir / "trace-demo.parsed.json"
      parsed_path.write_text(json.dumps({"ok": True}), encoding="utf-8")
      prompt = "return json"
      index_path = tmp_dir / "index.jsonl"
      index_path.write_text(
        json.dumps(
          {
            "trace_id": "trace-demo",
            "stage": "status",
            "task_type": "replay_probe",
            "prompt_name": "status_prompt",
            "prompt_version": "v1",
            "schema_name": "status_schema",
            "prompt_hash": stable_text_hash(prompt),
            "parsed_output_path": str(parsed_path),
          }
        )
        + "\n",
        encoding="utf-8",
      )
      replay = ReplayRuntime(calls_index_path=index_path)
      replayed = replay.run_json(
        session_id="status-replay",
        prompt=prompt,
        metadata={
          "stage": "status",
          "task_type": "replay_probe",
          "prompt_name": "status_prompt",
          "prompt_version": "v1",
          "schema_name": "status_schema",
        },
      )
      missed = False
      try:
        replay.run_json(session_id="status-replay", prompt="miss", metadata={"stage": "status", "task_type": "replay_probe"})
      except ReplayMissError:
        missed = True
      checks.append(_check("replay_runtime_v1_loads_index", replayed == {"ok": True} and missed, str(index_path), level="local"))
    with tempfile.TemporaryDirectory() as tmp:
      tmp_dir = Path(tmp)
      result_dir = tmp_dir / "Result" / "demo_repo" / "CVE-TEST-0001"
      result_dir.mkdir(parents=True)
      (result_dir / "eval.json").write_text(
        json.dumps(
          {
            "gt_affected_tags": ["v2"],
            "mapped_gt_tags": ["v2"],
            "confusion_matrix": {"TP": 0, "FP": 1, "FN": 1, "TN": 0},
          }
        ),
        encoding="utf-8",
      )
      (result_dir / "per_tag_verdict.jsonl").write_text(
        "\n".join(
          [
            json.dumps({"tag": "v1", "line": "main", "verdict": "AFFECTED", "run_status": "OK", "verdict_source": "agent"}),
            json.dumps({"tag": "v2", "line": "main", "verdict": "NOT_AFFECTED", "run_status": "OK", "verdict_source": "agent"}),
          ]
        )
        + "\n",
        encoding="utf-8",
      )
      (result_dir / "rci.json").write_text("{}", encoding="utf-8")
      manifest = build_case_pack(
        result_root=tmp_dir / "Result",
        out_root=tmp_dir / "Result_agent_enhance_cases",
        enhancement_id="checker_stage3_failure_v0",
      )
      case_index = tmp_dir / "Result_agent_enhance_cases" / "checker_stage3_failure_v0" / "case_index.jsonl"
      replay_summary = tmp_dir / "Result_agent_enhance_cases" / "checker_stage3_failure_v0" / "replay_summary.json"
      checks.append(_check(
        "self_evolve_case_pack_builder_local",
        manifest.total_cases == 2
        and manifest.agent_judge_relevant_cases == 2
        and case_index.exists()
        and replay_summary.exists()
        and "read_only_memory_injection_allowed" in _read(replay_summary),
        str(case_index),
        level="local",
      ))
    with tempfile.TemporaryDirectory() as tmp:
      tmp_dir = Path(tmp)
      case_pack_dir = tmp_dir / "Result_agent_enhance_cases" / "checker_memory_candidates_v0"
      case_pack_dir.mkdir(parents=True)
      case_rows = [
        {
          "case_id": "case_fp",
          "enhancement_id": "checker_memory_candidates_v0",
          "repo": "demo_repo",
          "cve_id": "CVE-TEST-0002",
          "stage": "stage3",
          "task_type": "tag_verdict",
          "failure_type": "FP",
          "attribution": {"category": "stage3_legacy_agent_judge", "agent_judge_relevant": True},
          "source_paths": {"result_dir": str(tmp_dir / "Result" / "demo_repo" / "CVE-TEST-0002")},
          "evidence_summary": {"matched_predicates": ["p1"], "failed_predicates": [], "triggered_guards": []},
          "leakage_policy": {"may_enter_prompt": False},
        },
        {
          "case_id": "case_fn",
          "enhancement_id": "checker_memory_candidates_v0",
          "repo": "demo_repo",
          "cve_id": "CVE-TEST-0002",
          "stage": "stage3",
          "task_type": "tag_verdict",
          "failure_type": "FN",
          "attribution": {"category": "stage3_legacy_agent_judge", "agent_judge_relevant": True},
          "source_paths": {"result_dir": str(tmp_dir / "Result" / "demo_repo" / "CVE-TEST-0002")},
          "evidence_summary": {"matched_predicates": [], "failed_predicates": ["p2"], "triggered_guards": ["g1"]},
          "leakage_policy": {"may_enter_prompt": False},
        },
      ]
      (case_pack_dir / "case_index.jsonl").write_text(
        "\n".join(json.dumps(row) for row in case_rows) + "\n",
        encoding="utf-8",
      )
      (case_pack_dir / "replay_summary.json").write_text(json.dumps({"status": "not_run"}), encoding="utf-8")
      (case_pack_dir / "small_sample_summary.json").write_text(json.dumps({"status": "not_run"}), encoding="utf-8")
      for name in ("improved_cases.jsonl", "regression_cases.jsonl", "unchanged_failure_cases.jsonl"):
        (case_pack_dir / name).write_text("", encoding="utf-8")
      memory_summary = build_memory_store(
        case_pack_root=tmp_dir / "Result_agent_enhance_cases",
        out_root=tmp_dir / "Result_agent_enhance_memory",
        enhancement_id="checker_memory_candidates_v0",
      )
      gate_summary = apply_promotion_gates(
        memory_candidates_path=tmp_dir / "Result_agent_enhance_memory" / "checker_memory_candidates_v0" / "memory_candidates.jsonl",
        case_pack_dir=case_pack_dir,
        out_dir=tmp_dir / "Result_agent_enhance_memory" / "checker_memory_candidates_v0",
      )
      checks.append(_check(
        "memory_candidate_store_and_gates_local",
        memory_summary["total_candidates"] >= 2
        and (tmp_dir / "Result_agent_enhance_memory" / "checker_memory_candidates_v0" / "memory_candidates.jsonl").exists()
        and (tmp_dir / "Result_agent_enhance_memory" / "checker_memory_candidates_v0" / "gated_memory_candidates.jsonl").exists()
        and gate_summary["status_counts"].get("blocked", 0) == memory_summary["total_candidates"]
        and gate_summary["injection_allowed_count"] == 0,
        str(tmp_dir / "Result_agent_enhance_memory" / "checker_memory_candidates_v0"),
        level="local",
      ))
  except Exception as e:
    checks.append(_check("imports_core_agent_harness", False, f"{type(e).__name__}: {e}"))
    checks.append(_check("stage3_deprecated_runtime_args_removed", False, "import failed"))
    checks.append(_check("replay_runtime_v1_loads_index", False, "import failed", level="local"))
    checks.append(_check("self_evolve_case_pack_builder_local", False, "import failed", level="local"))
    checks.append(_check("memory_candidate_store_and_gates_local", False, "import failed", level="local"))

  main_text = _read(PROJECT_ROOT / "main.py")
  service_text = _read(PROJECT_ROOT / "vulnversion/agent_harness/service.py")
  trace_text = _read(PROJECT_ROOT / "vulnversion/agent_harness/trace.py")
  config_text = _read(PROJECT_ROOT / "vulnversion/agent_harness/config.py")
  prompt_provenance_text = _read(PROJECT_ROOT / "vulnversion/agent_harness/prompts/provenance.py")
  opencode_runtime_text = _read(PROJECT_ROOT / "vulnversion/agent_harness/runtimes/opencode_runtime.py")
  replay_runtime_text = _read(PROJECT_ROOT / "vulnversion/agent_harness/runtimes/replay_runtime.py")
  self_evolve_schema_text = _read(PROJECT_ROOT / "vulnversion/self_evolve/schema.py")
  self_evolve_case_pack_text = _read(PROJECT_ROOT / "vulnversion/self_evolve/case_pack.py")
  self_evolve_attributor_text = _read(PROJECT_ROOT / "vulnversion/self_evolve/failure_attributor.py")
  memory_candidates_text = _read(PROJECT_ROOT / "vulnversion/self_evolve/memory_candidates.py")
  memory_store_text = _read(PROJECT_ROOT / "vulnversion/self_evolve/memory_store.py")
  leakage_gate_text = _read(PROJECT_ROOT / "vulnversion/self_evolve/leakage_gate.py")
  promotion_gate_text = _read(PROJECT_ROOT / "vulnversion/self_evolve/promotion_gate.py")
  self_evolve_builder_text = _read(PROJECT_ROOT / "tests/build_agent_enhance_cases.py")
  memory_builder_text = _read(PROJECT_ROOT / "tests/build_memory_candidates.py")
  memory_checker_text = _read(PROJECT_ROOT / "tests/check_memory_candidates.py")
  opencode_skills_checker_text = _read(PROJECT_ROOT / "tests/check_opencode_skills.py")
  agent_eval_text = _read(PROJECT_ROOT / "tests/evaluate_agent_enhancement.py")
  git_skill_text = _read(PROJECT_ROOT / ".opencode/skills/git-navigation/SKILL.md")
  git_stage3_ref_text = _read(PROJECT_ROOT / ".opencode/skills/git-navigation/references/stage3.md")
  git_evidence_ref_text = _read(PROJECT_ROOT / ".opencode/skills/git-navigation/references/evidence-discipline.md")
  cwe_skill_text = _read(PROJECT_ROOT / ".opencode/skills/cwe-skills/SKILL.md")
  cwe_learned_readme_text = _read(PROJECT_ROOT / ".opencode/skills/cwe-skills/references/learned/README.md")
  stage1_text = _read(PROJECT_ROOT / "vulnversion/stage1_semantic_aggregation/annotate_chunks.py")
  stage2_text = _read(PROJECT_ROOT / "vulnversion/stage2_rci_navigation/induce_rci.py")
  stage3_text = _read(PROJECT_ROOT / "vulnversion/stage3_verify/verify_tags.py")
  stage3_run_text = _read(PROJECT_ROOT / "vulnversion/stage3_verify/run.py")
  checks.append(_check("main_has_agent_backend_arg", "--agent-backend" in main_text, "main.py argparse"))
  checks.append(_check("main_has_stage3_prompt_version_arg", "--stage3-prompt-version" in main_text, "main.py argparse"))
  checks.append(_check(
    "main_stage3_prompt_default_is_v1",
    '--stage3-prompt-version", default="v1"' in main_text or "--stage3-prompt-version', default='v1'" in main_text,
    "main.py argparse",
  ))
  checks.append(_check(
    "main_deprecated_stage3_cli_args_removed",
    all(k not in main_text for k in ["--all-tags", "--max-tags", "--early-stop-n", "all_tags", "early_stop_n"]),
    "main.py argparse/worker",
  ))
  checks.append(_check("main_uses_opencode_runtime", "OpenCodeRuntime.from_config" in main_text, "main.py _maybe_agent"))
  checks.append(_check("main_wraps_runtime_with_agentservice", "AgentService(" in main_text and "agent_trace.jsonl" in main_text, "main.py worker"))
  checks.append(_check("agentservice_has_run_json_trace", "def run_json(" in service_text and "AgentTraceEvent(" in service_text, "agent_harness/service.py"))
  checks.append(_check("agentservice_tracks_sessions", "def register_session(" in service_text and "export_known_session_messages" in service_text, "agent_harness/service.py"))
  checks.append(_check("main_writes_runtime_manifest", "agent_runtime.json" in main_text and "write_runtime_manifest" in main_text, "main.py worker"))
  checks.append(_check("opencode_runtime_diagnostics", "def diagnostics(" in opencode_runtime_text and "native_skill_inventory" in opencode_runtime_text and "native_tool_inventory" in opencode_runtime_text, "agent_harness/runtimes/opencode_runtime.py"))
  checks.append(_check("trace_event_has_prompt_hash_and_latency", "prompt_hash" in trace_text and "latency_s" in trace_text and "trace_id" in trace_text, "agent_harness/trace.py"))
  checks.append(_check(
    "trace_event_has_call_artifact_paths",
    all(k in trace_text for k in ["parsed_output_path", "prompt_path", "system_path"]),
    "agent_harness/trace.py",
  ))
  checks.append(_check(
    "agentservice_supports_agent_calls_artifacts",
    all(k in service_text for k in ["agent_calls", ".parsed.json", ".prompt.txt", ".system.txt", "index.jsonl", "artifact_write_error"]),
    "agent_harness/service.py",
  ))
  checks.append(_check(
    "prompt_provenance_schema_present",
    all([
      "class PromptSpec" in prompt_provenance_text,
      "class PromptProvenance" in prompt_provenance_text,
      "STAGE1_CHUNK_V0" in prompt_provenance_text,
      "STAGE2_RCI_V0" in prompt_provenance_text,
      "STAGE3_VERDICT_V0" in prompt_provenance_text,
      "STAGE3_VERDICT_V1" in prompt_provenance_text,
      "target_tag_theorem_judge" in prompt_provenance_text,
    ]),
    "agent_harness/prompts/provenance.py",
  ))
  checks.append(_check(
    "trace_event_has_prompt_provenance",
    all(k in trace_text for k in ["prompt_name", "prompt_version", "prompt_builder", "schema_name"]),
    "agent_harness/trace.py",
  ))
  checks.append(_check(
    "agentservice_accepts_prompt_provenance",
    all(k in service_text for k in ["prompt_name: str | None", "prompt_version: str | None", "schema_name: str | None", "prompt_builder: str | None"]),
    "agent_harness/service.py",
  ))
  checks.append(_check(
    "stage_run_json_metadata_present",
    all([
      '"stage": "stage1"' in stage1_text or 'stage="stage1"' in stage1_text,
      '"stage": "stage2"' in stage2_text,
      '"stage": "stage3"' in stage3_text,
    ]),
    "stage1/stage2/stage3 run_json metadata",
  ))
  checks.append(_check(
    "stage_prompt_v0_metadata_present",
    all([
      "STAGE1_CHUNK_V0" in stage1_text,
      "STAGE2_RCI_V0" in stage2_text,
      "STAGE3_VERDICT_V0" in stage3_text,
      "STAGE3_VERDICT_V1" in stage3_text,
    ]),
    "stage1/stage2/stage3 prompt metadata",
  ))
  checks.append(_check(
    "stage1_uses_agenttask",
    all([
      "AgentTask(" in stage1_text,
      "run_task" in stage1_text,
      "judgement_only=True" in stage1_text,
      '"tag_plan"' in stage1_text,
      '"early_stop"' in stage1_text,
      '"gt_affected_tags"' in stage1_text,
    ]),
    "stage1 annotate_chunks.py",
  ))
  checks.append(_check(
    "stage2_uses_agenttask",
    all([
      "AgentTask(" in stage2_text,
      "run_task" in stage2_text,
      "judgement_only=True" in stage2_text,
      '"tag_plan"' in stage2_text,
      '"early_stop"' in stage2_text,
      '"gt_affected_tags"' in stage2_text,
      '"affected_range"' in stage2_text,
    ]),
    "stage2 induce_rci.py",
  ))
  checks.append(_check(
    "stage3_uses_agenttask",
    all([
      "AgentTask(" in stage3_text,
      "run_task" in stage3_text,
      "judgement_only=True" in stage3_text,
      '"scan_order"' in stage3_text,
      '"neighbor_tag_verdicts"' in stage3_text,
      '"affected_range"' in stage3_text,
    ]),
    "stage3 verify_tags.py",
  ))
  checks.append(_check(
    "stage3_target_tag_theorem_prompt_v1_exists",
    all(k in stage3_text + stage3_run_text + main_text for k in [
      "_build_target_tag_theorem_prompt",
      "stage3_prompt_version",
      "target_tag_theorem_judge",
      "target_tag_scoped_git",
      "Step2 Vulnerability Existence Theorem",
      "Repository path",
      "git -C",
      "deprecated_baseline",
    ]),
    "stage3 prompt v1",
  ))
  checks.append(_check(
    "stage3_verify_deprecated_compat_args_removed",
    all(k not in (stage3_text + stage3_run_text) for k in [
      "early_stop_n",
      "bisect_enabled",
      "deprecated_step3_args",
      "early_stopped",
    ]),
    "stage3 run.py/verify_tags.py",
  ))
  checks.append(_check(
    "replay_runtime_v1_local_replay_contract",
    all([
      "class ReplayRuntimePlan" in replay_runtime_text,
      "class ReplayMissError" in replay_runtime_text,
      "calls_index_path" in replay_runtime_text,
      "MATCH_FIELDS" in replay_runtime_text,
      "json_reliability=\"recorded\"" in replay_runtime_text or 'json_reliability="recorded"' in replay_runtime_text,
    ]),
    "agent_harness/runtimes/replay_runtime.py",
  ))
  checks.append(_check(
    "harness_mode_config_exists",
    all([
      "VV_MEMORY_MODE" in config_text,
      "VV_SKILL_MODE" in config_text,
      "VV_REPLAY_MODE" in config_text,
      "read_only" in config_text,
      "canonical_verified" in config_text,
      "permissive" in config_text,
      "def normalize_mode" in config_text,
      "def model_dump" in config_text,
    ]),
    "agent_harness/config.py",
  ))
  checks.append(_check(
    "runtime_manifest_records_harness_mode",
    "harness_config" in service_text and "runtime_manifest" in service_text,
    "agent_harness/service.py",
  ))
  checks.append(_check(
    "injection_audit_fields_exist",
    all(k in service_text for k in [
      "memory_mode",
      "skill_mode",
      "replay_mode",
      "retrieved_memory_ids",
      "selected_skills",
      "suppressed_skills",
      "injection_policy",
    ]),
    "agent_harness/service.py",
  ))
  checks.append(_check(
    "self_evolve_case_schema_exists",
    all(k in self_evolve_schema_text for k in [
      "class AgentEnhanceCase",
      "class CasePackManifest",
      "class FailureAttribution",
      "blocked_from_injection",
      "offline_oracle",
      "leakage_policy",
    ]),
    "self_evolve/schema.py",
  ))
  checks.append(_check(
    "self_evolve_case_pack_contract_exists",
    all(k in self_evolve_case_pack_text for k in [
      "case_index.jsonl",
      "hypothesis.md",
      "replay_summary.json",
      "small_sample_summary.json",
      "improved_cases.jsonl",
      "regression_cases.jsonl",
      "unchanged_failure_cases.jsonl",
      "read_only_memory_injection_allowed",
    ]),
    "self_evolve/case_pack.py",
  ))
  checks.append(_check(
    "self_evolve_failure_attribution_boundary",
    all(k in self_evolve_attributor_text for k in [
      "stage3_agent_judge",
      "stage3_agent_runtime_or_schema",
      "deterministic_stage3_non_agent",
      "agent_judge_relevant=False",
    ]),
    "self_evolve/failure_attributor.py",
  ))
  checks.append(_check(
    "self_evolve_builder_cli_exists",
    all(k in self_evolve_builder_text for k in [
      "--result-root",
      "--out-root",
      "--enhancement-id",
      "--agent-only",
      "build_case_pack",
    ]),
    "tests/build_agent_enhance_cases.py",
  ))
  checks.append(_check(
    "opencode_skills_audit_exists",
    all(k in opencode_skills_checker_text for k in [
      "GIT_REQUIRED_REFERENCES",
      "Dataset.json",
      "BaseDataSet.json",
      "BaseDataTest.json",
      "BaseDataOrder.json",
      "missing_cwe_files",
      "dataset_cwe_coverage",
    ]),
    "tests/check_opencode_skills.py",
  ))
  checks.append(_check(
    "git_navigation_v2_judge_only_skill",
    all(k.lower() in (git_skill_text + git_stage3_ref_text + git_evidence_ref_text).lower() for k in [
      "opencode-native",
      "judge-only",
      "tag:path",
      "git grep",
      "git show",
      "failure-triggered",
      "affected range",
      "tag plan",
    ]),
    ".opencode/skills/git-navigation",
  ))
  checks.append(_check(
    "cwe_static_base_learned_overlay_exists",
    all([
      (PROJECT_ROOT / ".opencode/skills/cwe-skills/references/learned/README.md").exists(),
      (PROJECT_ROOT / ".opencode/skills/cwe-skills/references/learned/by-id/.gitkeep").exists(),
      (PROJECT_ROOT / ".opencode/skills/cwe-skills/references/learned/candidates/.gitkeep").exists(),
      all(k in (cwe_skill_text + cwe_learned_readme_text) for k in [
        "static base knowledge",
        "learned overlay",
        "case pack",
        "ReplayRuntime",
        "leakage gate",
        "verified overlay",
        "ArtifactMemory",
      ]),
    ]),
    ".opencode/skills/cwe-skills/references/learned",
  ))
  checks.append(_check(
    "memory_candidate_store_contract_exists",
    all(k in memory_candidates_text + memory_store_text + memory_builder_text for k in [
      "FailureMemory",
      "RepoMemory",
      "RCIMemory",
      "SkillMemory",
      "memory_candidates.jsonl",
      "memory_summary.json",
      "injection_allowed",
      "promotion_requirements",
      "source_case_ids",
    ]),
    "vulnversion/self_evolve/memory_candidates.py",
  ))
  checks.append(_check(
    "leakage_gate_contract_exists",
    all(k in leakage_gate_text for k in [
      "gt_affected_tags",
      "affected\\s*range",
      "neighbor\\s*verdict",
      "scan\\s*order",
      "early\\s*stop",
      "tag\\s*plan",
      "planner\\s*state",
      "leakage_gate_failed",
    ]),
    "vulnversion/self_evolve/leakage_gate.py",
  ))
  checks.append(_check(
    "promotion_gate_contract_exists",
    all(k in promotion_gate_text for k in [
      "replay_summary.json",
      "small_sample_summary.json",
      "improved_cases.jsonl",
      "regression_cases.jsonl",
      "unchanged_failure_cases.jsonl",
      "gated_memory_candidates.jsonl",
      "gate_summary.json",
      "single_case_skillmemory_blocked",
    ]),
    "vulnversion/self_evolve/promotion_gate.py",
  ))
  checks.append(_check(
    "memory_candidate_local_test_exists",
    all(k in memory_checker_text for k in [
      "clean_candidate_blocked_by_missing_replay",
      "leakage_candidate_blocked",
      "single_case_skillmemory_blocked",
      "repeated_skillmemory_blocked_without_replay_sample",
      "fixture_all_required_summaries_can_pass",
    ]),
    "tests/check_memory_candidates.py",
  ))
  checks.append(_check(
    "agent_enhancement_ab_eval_script_exists",
    all(k in agent_eval_text for k in [
      "agent_enhance_eval_summary.json",
      "improved_cases.jsonl",
      "regression_cases.jsonl",
      "unchanged_cases.jsonl",
      "cost_report.json",
      "avg_latency_s_per_tag",
      "avg_tool_calls_per_tag",
      "stage3_probed_tag_accuracy",
      "json_parse_failure_count",
      "--self-test",
      "messages",
      "b_correct is not True",
      "message_json_chars",
    ]),
    "tests/evaluate_agent_enhancement.py",
  ))

  agent_doc = WORKFLOW_ROOT / "SystemDesign/Architecture/Develop/Agent-Enhance.md"
  step3_doc = WORKFLOW_ROOT / "SystemDesign/Architecture/Develop/step3.md"
  checks.append(_check("agent_enhance_skill_boundary_documented", "Backend-specific Skills Boundary" in _read(agent_doc), str(agent_doc)))
  checks.append(_check("step3_agent_runtime_boundary_documented", "Agent backend" in _read(step3_doc), str(step3_doc)))

  passed = sum(1 for c in checks if c["status"] == "pass")
  failed = len(checks) - passed
  progress = {
    "harness_scaffold": {"score": 3, "max_score": 5, "status": "static_integrated"},
    "opencode_runtime": {"score": 3, "max_score": 5, "status": "wired_with_native_inventory_static"},
    "codex_runtime": {"score": 1, "max_score": 5, "status": "reserved_only"},
    "claude_runtime": {"score": 1, "max_score": 5, "status": "reserved_only"},
    "replay_runtime": {"score": 3, "max_score": 5, "status": "local_replay_capable_not_batch_validated"},
    "trace": {"score": 3, "max_score": 5, "status": "call_artifacts_static_integrated"},
    "prompt_provenance": {"score": 3, "max_score": 5, "status": "static_integrated_v0_v1"},
    "agenttask": {"score": 3, "max_score": 5, "status": "stage1_stage2_stage3_static_integrated"},
    "harness_mode_config": {"score": 3, "max_score": 5, "status": "env_config_manifest_ready"},
    "injection_audit": {"score": 3, "max_score": 5, "status": "trace_metadata_stub_only"},
    "memory": {"score": 2, "max_score": 5, "status": "candidate_store_local_no_injection"},
    "skills": {"score": 2, "max_score": 5, "status": "opencode_native_v2_canonical_off"},
    "backend_specific_skill_boundary": {"score": 3, "max_score": 5, "status": "opencode_native_inventory_and_audit_wired"},
    "prompt_templates": {"score": 4, "max_score": 5, "status": "stage3_prompt_v1_default_after_8cve_cost_gate"},
    "stage3_prompt_ab": {"score": 4, "max_score": 5, "status": "eight_cve_stage3_only_cost_gate_validated"},
    "self_evolution_case_pack": {"score": 2, "max_score": 5, "status": "offline_case_pack_builder_local"},
    "opencode_skills_audit": {"score": 2, "max_score": 5, "status": "static_audit_local_dataset_coverage_warn_allowed"},
    "memory_candidate_store": {"score": 2, "max_score": 5, "status": "offline_candidate_generation_local"},
    "self_evolution_gates": {"score": 2, "max_score": 5, "status": "blocking_gates_local_no_injection"},
  }
  out = {
    "project_root": str(PROJECT_ROOT),
    "summary": {"passed": passed, "failed": failed, "total": len(checks)},
    "checks": checks,
    "progress": progress,
  }
  print(json.dumps(out, ensure_ascii=False, indent=2))
  return 0 if failed == 0 else 1


if __name__ == "__main__":
  raise SystemExit(main())

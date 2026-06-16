from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from vulngraph.agent_io.root_cause_contract import lint_root_cause_contract
from vulngraph.agent_io.root_cause_schema import parse_root_cause_output, root_cause_agent_output_schema
from vulngraph.builder.patch import build_patch_graph_from_text
from vulngraph.schema import GraphEdge, GraphNode, SourceRef
from vulngraph.services import VulnGraphClient
from vulngraph.workflows.root_cause import _batch_summary, _multi_fix_anchor_mapping_ok


CVE_ID = "CVE-STRUCT"
REPO = "demo"
SHA = "abc123"
FIX_ID = f"fix-commit:{REPO}:{SHA}"
HUNK_ID = f"patch-hunk:{REPO}:{SHA}:src/parser.c:1"
FILE_ID = f"file:{REPO}:src/parser.c"
FUNCTION_ID = f"changed-function:{REPO}:{SHA}:src/parser.c:parse_record"
FIX_SET_ID = f"{CVE_ID}:fix-set:1"


def _patch_text() -> str:
  return """diff --git a/src/parser.c b/src/parser.c
--- a/src/parser.c
+++ b/src/parser.c
@@ -10,5 +10,6 @@ static int previous_function(void)
 int parse_record(int len)
 {
-    return copy_record(len);
+    if (len < 0)
+        return -1;
+    return copy_record(len);
 }
"""


def _client_packet_trace_output(tmp_path: Path) -> tuple[VulnGraphClient, dict, dict, dict]:
  graph = build_patch_graph_from_text(
    cve_id=CVE_ID,
    repo=REPO,
    commit_sha=SHA,
    patch_text=_patch_text(),
    fix_commit_content={"fix_set_id": FIX_SET_ID, "order": 1},
  )
  graph.nodes.append(
    GraphNode(
      id=f"cve:{CVE_ID}",
      type="CVE",
      scope="cve",
      source_refs=[SourceRef(kind="test", ref="tests://structural-integrity")],
      allowed_use="context_only",
      confidence=1.0,
      lifecycle="raw",
      created_from="test",
      content={"cve_id": CVE_ID},
    )
  )
  graph.edges.append(
    GraphEdge(
      id=f"edge:cve:{CVE_ID}:fixed_by:{FIX_ID}",
      type="fixed_by",
      source=f"cve:{CVE_ID}",
      target=FIX_ID,
      scope="cve",
      source_refs=[SourceRef(kind="test", ref="tests://structural-integrity")],
      allowed_use="root_cause_evidence",
      confidence=1.0,
      lifecycle="raw",
      created_from="test",
    )
  )
  client = VulnGraphClient(tmp_path / "graph")
  client.append_graph(graph, created_from="test")
  packet = client.build_root_cause_packet(CVE_ID)
  trace = {
    "source": "wrapper_git_trace",
    "cve_id": CVE_ID,
    "trace_run_id": "trace-1",
    "tool_calls": [
      {
        "id": "cmd-1",
        "source": "wrapper_git_trace",
        "cve_id": CVE_ID,
        "trace_run_id": "trace-1",
        "command": "git show abc123",
        "exit_code": 0,
      }
    ],
    "tool_outputs": [
      {
        "id": "out-1",
        "source": "wrapper_git_trace",
        "cve_id": CVE_ID,
        "trace_run_id": "trace-1",
        "command_ref": "cmd-1",
        "text": "diff",
      }
    ],
    "git_observations": [
      {
        "id": "obs-1",
        "source": "wrapper_git_trace",
        "valid_evidence": True,
        "observation_kind": "patch_diff",
        "cve_id": CVE_ID,
        "trace_run_id": "trace-1",
        "command_ref": "cmd-1",
        "tool_output_ref": "out-1",
        "fix_commit_ids": [FIX_ID],
        "patch_hunk_ids": [HUNK_ID],
        "file_ids": [FILE_ID],
        "function_ids": [FUNCTION_ID],
        "path": "src/parser.c",
        "claim": "parse_record adds a length guard",
        "snippet": "if (len < 0) return -1",
      }
    ],
  }
  output = {
    "agent_run": {"run_id": "run-1", "cve_id": CVE_ID, "backend": "test"},
    "root_cause_hypotheses": [
      {
        "hypothesis_id": "hyp-1",
        "summary": "negative length reaches copy_record",
        "fix_commit_ids": [FIX_ID],
        "fix_set_ids": [FIX_SET_ID],
        "vulnerable_predicate_ids": ["vp-1"],
        "fix_predicate_ids": ["fp-1"],
        "guard_condition_ids": [],
        "negative_condition_ids": [],
        "anchor_ids": ["anchor-1"],
        "git_observation_refs": ["obs-1"],
      }
    ],
    "code_anchors": [
      {
        "anchor_id": "anchor-1",
        "fix_commit_id": FIX_ID,
        "patch_hunk_id": HUNK_ID,
        "file_id": FILE_ID,
        "path": "src/parser.c",
        "function_id": FUNCTION_ID,
        "function": "parse_record",
        "git_observation_refs": ["obs-1"],
      }
    ],
    "vulnerable_predicates": [
      {
        "predicate_id": "vp-1",
        "description": "negative length reaches copy_record",
        "anchor_ids": ["anchor-1"],
        "git_observation_refs": ["obs-1"],
      }
    ],
    "fix_predicates": [
      {
        "predicate_id": "fp-1",
        "description": "negative length is rejected",
        "anchor_ids": ["anchor-1"],
        "git_observation_refs": ["obs-1"],
      }
    ],
    "guard_conditions": [],
    "negative_conditions": [],
    "git_observation_refs": ["obs-1"],
    "uncertainty_reasons": [],
    "learned_candidates": [],
    "risk_flags": [],
  }
  return client, packet, trace, output


def test_production_packet_contains_all_scope_entities_and_mappings(tmp_path: Path):
  _, packet, _, _ = _client_packet_trace_output(tmp_path)
  nodes = {node["id"]: node for section in ("patch_evidence", "repo_navigation") for node in packet[section]}

  assert {FIX_ID, HUNK_ID, FILE_ID, FUNCTION_ID} <= set(nodes)
  assert nodes[HUNK_ID]["content"]["commit_sha"] == SHA
  assert nodes[HUNK_ID]["content"]["path"] == "src/parser.c"
  assert nodes[HUNK_ID]["content"]["function_id"] == FUNCTION_ID


def test_cve_2020_24020_hunk_maps_to_actual_changed_function_not_header_context():
  patch_text = """diff --git a/libavfilter/dnn/dnn_backend_native.c b/libavfilter/dnn/dnn_backend_native.c
--- a/libavfilter/dnn/dnn_backend_native.c
+++ b/libavfilter/dnn/dnn_backend_native.c
@@ -295,7 +297,13 @@ int32_t calculate_operand_dims_count(const DnnOperand *oprd)
 int32_t calculate_operand_data_length(const DnnOperand* oprd)
 {
     // currently, we just support DNN_FLOAT
-    return oprd->dims[0] * oprd->dims[1] * oprd->dims[2] * oprd->dims[3] * sizeof(float);
+    uint64_t len = sizeof(float);
+    for (int i = 0; i < 4; i++) {
+        len *= oprd->dims[i];
+        if (len > INT32_MAX)
+            return 0;
+    }
+    return len;
 }
"""

  graph = build_patch_graph_from_text(cve_id="CVE-2020-24020", repo="FFmpeg", commit_sha="584f", patch_text=patch_text)
  functions = [node for node in graph.nodes if node.type == "ChangedFunction"]
  hunk = next(node for node in graph.nodes if node.type == "PatchHunk")

  assert [node.content["symbol"] for node in functions] == ["calculate_operand_data_length"]
  assert hunk.content["function_id"].endswith(":calculate_operand_data_length")
  assert not any(node.content["symbol"] == "calculate_operand_dims_count" for node in functions)


def test_unreliable_hunk_header_without_body_declaration_does_not_create_changed_function():
  patch_text = """diff --git a/src/parser.c b/src/parser.c
--- a/src/parser.c
+++ b/src/parser.c
@@ -50,2 +50,2 @@ misleading_header_function(void)
-value = old_value;
+value = checked_value;
"""

  graph = build_patch_graph_from_text(cve_id=CVE_ID, repo=REPO, commit_sha=SHA, patch_text=patch_text)

  assert not any(node.type == "ChangedFunction" for node in graph.nodes)
  assert not any(edge.type == "touches_function" for edge in graph.edges)


def test_multiline_c_function_signature_is_resolved_from_source_range():
  source = """static int helper(void)
{
    return 0;
}

static int vp3_decode_frame(AVCodecContext *avctx,
                            AVFrame *frame,
                            int *got_frame,
                            AVPacket *avpkt)
{
    int ret = 0;
    if (!frame)
        return -1;
    return ret;
}
"""
  patch_text = """diff --git a/libavcodec/vp3.c b/libavcodec/vp3.c
--- a/libavcodec/vp3.c
+++ b/libavcodec/vp3.c
@@ -11,4 +11,5 @@ static int misleading_header(void)
     int ret = 0;
-    if (!frame)
+    if (!frame) {
         return -1;
+    }
"""

  graph = build_patch_graph_from_text(
    cve_id="CVE-2022-3109",
    repo="FFmpeg",
    commit_sha="656c",
    patch_text=patch_text,
    new_sources={"libavcodec/vp3.c": source},
    old_sources={"libavcodec/vp3.c": source},
  )
  function = next(node for node in graph.nodes if node.type == "ChangedFunction")
  hunk = next(node for node in graph.nodes if node.type == "PatchHunk")

  assert function.content["symbol"] == "vp3_decode_frame"
  assert hunk.content["function_resolution"] == "source_range"


def test_wrong_function_id_is_rejected_by_lint_and_ingestion(tmp_path: Path):
  client, packet, trace, output = _client_packet_trace_output(tmp_path)
  output["code_anchors"][0]["function_id"] = "changed-function:demo:abc123:src/parser.c:wrong"

  lint = lint_root_cause_contract(output, packet, trace)
  ingestion = client.ingest_root_cause_output(CVE_ID, output, trace=trace, packet=packet)

  assert not lint.ok
  assert "function_id" in " ".join(lint.errors)
  assert ingestion.status == "rejected"


def test_function_id_and_function_name_conflict_is_rejected(tmp_path: Path):
  client, packet, trace, output = _client_packet_trace_output(tmp_path)
  output["code_anchors"][0]["function"] = "other_function"

  lint = lint_root_cause_contract(output, packet, trace)
  ingestion = client.ingest_root_cause_output(CVE_ID, output, trace=trace, packet=packet)

  assert not lint.ok
  assert ingestion.status == "rejected"


def test_function_id_that_exists_but_does_not_belong_to_hunk_is_rejected(tmp_path: Path):
  client, packet, trace, output = _client_packet_trace_output(tmp_path)
  other_function_id = "changed-function:demo:abc123:src/parser.c:other_function"
  packet["patch_evidence"].append(
    {
      "id": other_function_id,
      "type": "ChangedFunction",
      "allowed_use": "root_cause_evidence",
      "content": {"cve_id": CVE_ID, "repo": REPO, "commit_sha": SHA, "path": "src/parser.c", "symbol": "other_function"},
    }
  )
  output["code_anchors"][0].update(function_id=other_function_id, function="other_function")

  lint = lint_root_cause_contract(output, packet, trace)
  ingestion = client.ingest_root_cause_output(CVE_ID, output, trace=trace, packet=packet)

  assert not lint.ok
  assert any("does not belong to PatchHunk" in error for error in lint.errors)
  assert ingestion.status == "rejected"


@pytest.mark.parametrize(
  "mutate",
  [
    lambda payload: payload["root_cause_hypotheses"][0].update(id="other-hypothesis"),
    lambda payload: payload["root_cause_hypotheses"][0].update(code_anchor_ids=["other-anchor"]),
    lambda payload: payload["code_anchors"][0].update(id="other-anchor"),
    lambda payload: payload["code_anchors"][0].update(function_name="other_function"),
    lambda payload: payload["code_anchors"][0].update(line_start=10, line_end=12, line_range=[10, 13]),
    lambda payload: payload["vulnerable_predicates"][0].update(id="other-predicate"),
    lambda payload: payload["vulnerable_predicates"][0].update(statement="different statement"),
    lambda payload: payload["vulnerable_predicates"][0].update(code_anchor_ids=["other-anchor"]),
  ],
)
def test_conflicting_aliases_are_parse_errors(tmp_path: Path, mutate):
  _, _, _, payload = _client_packet_trace_output(tmp_path)
  mutate(payload)

  parsed = parse_root_cause_output(json.dumps(payload))

  assert not parsed.ok
  assert "conflict" in str(parsed.error).lower()


def test_agent_output_schema_exposes_only_canonical_fields():
  schema_text = json.dumps(root_cause_agent_output_schema())

  for compatibility_alias in ("id", "code_anchor_ids", "function_name", "line_range", "statement"):
    assert f'"{compatibility_alias}"' not in schema_text


@pytest.mark.parametrize("semantic_type", ["hypothesis", "anchor", "predicate"])
def test_duplicate_semantic_ids_are_parse_errors(tmp_path: Path, semantic_type: str):
  _, _, _, payload = _client_packet_trace_output(tmp_path)
  if semantic_type == "hypothesis":
    payload["root_cause_hypotheses"].append(copy.deepcopy(payload["root_cause_hypotheses"][0]))
  elif semantic_type == "anchor":
    payload["code_anchors"].append(copy.deepcopy(payload["code_anchors"][0]))
  else:
    payload["fix_predicates"][0]["predicate_id"] = payload["vulnerable_predicates"][0]["predicate_id"]

  parsed = parse_root_cause_output(json.dumps(payload))

  assert not parsed.ok
  assert "duplicate" in str(parsed.error).lower()


@pytest.mark.parametrize("condition_field,hypothesis_field", [("guard_conditions", "guard_condition_ids"), ("negative_conditions", "negative_condition_ids")])
def test_referenced_guard_or_negative_without_anchor_is_rejected(tmp_path: Path, condition_field: str, hypothesis_field: str):
  client, packet, trace, output = _client_packet_trace_output(tmp_path)
  output[condition_field] = [
    {
      "predicate_id": "cond-1",
      "description": "scope condition",
      "anchor_ids": [],
      "git_observation_refs": ["obs-1"],
    }
  ]
  output["root_cause_hypotheses"][0][hypothesis_field] = ["cond-1"]

  lint = lint_root_cause_contract(output, packet, trace)
  ingestion = client.ingest_root_cause_output(CVE_ID, output, trace=trace, packet=packet)

  assert not lint.ok
  assert ingestion.status == "rejected"


def test_lint_ok_output_is_not_structurally_rejected_by_ingestion(tmp_path: Path):
  client, packet, trace, output = _client_packet_trace_output(tmp_path)

  lint = lint_root_cause_contract(output, packet, trace)
  ingestion = client.ingest_root_cause_output(CVE_ID, output, trace=trace, packet=packet)

  assert lint.ok
  assert ingestion.status == "ingested_raw"


def test_reporting_separates_real_invocations_from_ingested_results():
  summary = _batch_summary(
    [
      {"cve_id": "CVE-A", "backend_type": "opencode", "status": "rejected", "json_parse_status": "json", "duration_s": 1.0},
      {"cve_id": "CVE-B", "backend_type": "opencode", "status": "ingested_raw", "json_parse_status": "json", "duration_s": 1.0},
      {"cve_id": "CVE-D", "backend_type": "opencode", "status": "failed", "json_parse_status": "backend_failed", "duration_s": 1.0},
      {"cve_id": "CVE-C", "backend_type": "fixture", "status": "ingested_raw", "json_parse_status": "json", "duration_s": 1.0},
    ]
  )

  assert summary["real_opencode_invocation_count"] == 3
  assert summary["ingested_raw_count"] == 2


def test_multi_fix_reporting_uses_only_gate_accepted_anchors():
  packet = {
    "patch_evidence": [
      {"id": "fix-1", "type": "FixCommit"},
      {"id": "fix-2", "type": "FixCommit"},
    ]
  }
  ingestion_payload = {
    "details": {
      "structural_validation": {
        "accepted_hypothesis_ids": ["hyp-1"],
        "hypothesis_results": {"hyp-1": {"payload": {"anchor_ids": ["a-1", "a-2"]}}},
        "anchor_results": {
          "a-1": {"gate_valid": True, "payload": {"fix_commit_id": "fix-1"}},
          "a-2": {"gate_valid": False, "payload": {"fix_commit_id": "fix-2"}},
        },
      }
    }
  }

  assert _multi_fix_anchor_mapping_ok(packet, ingestion_payload) is False

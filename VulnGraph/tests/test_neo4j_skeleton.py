from __future__ import annotations

import json
import sys
from pathlib import Path

from vulngraph.builder.dataset import build_dataset_graph
from vulngraph.builder.patch import build_patch_graph_from_text
from vulngraph.cli.main import main
from vulngraph.neo4j_store import (
  edge_to_neo4j_record,
  iter_schema_cypher,
  node_to_neo4j_record,
)
from vulngraph.ontology import target_verdict_evidence_nodes
from vulngraph.schema import GraphDocument, GraphEdge, GraphNode, SourceRef
from vulngraph.store import JsonlGraphStore


def _src() -> SourceRef:
  return SourceRef(kind="test", ref="tests://neo4j")


def _node(node_id: str, node_type: str, *, allowed_use: str, lifecycle: str = "raw") -> GraphNode:
  return GraphNode(
    id=node_id,
    type=node_type,
    scope="cve",
    source_refs=[_src()],
    allowed_use=allowed_use,
    confidence=0.8,
    lifecycle=lifecycle,
    created_from="unit-test",
    content={"nested": {"value": 1}},
  )


def test_neo4j_records_encode_core_metadata_as_flat_properties():
  node = _node("cve:CVE-TEST", "CVE", allowed_use="context_only")
  record = node_to_neo4j_record(node)

  assert record.label == "CVE"
  assert record.properties["id"] == "cve:CVE-TEST"
  assert record.properties["node_type"] == "CVE"
  assert record.properties["allowed_use"] == "context_only"
  assert json.loads(record.properties["source_refs_json"])[0]["kind"] == "test"
  assert json.loads(record.properties["content_json"]) == {"nested": {"value": 1}}

  edge = GraphEdge(
    id="edge:cve:CVE-TEST:fixed_by:fix-commit:abc123",
    type="fixed_by",
    source="cve:CVE-TEST",
    target="fix-commit:abc123",
    scope="cve",
    source_refs=[_src()],
    allowed_use="root_cause_evidence",
    confidence=0.9,
    lifecycle="raw",
    created_from="unit-test",
    content={"role": "primary"},
  )
  edge_record = edge_to_neo4j_record(edge)

  assert edge_record.type == "FIXED_BY"
  assert edge_record.source_id == "cve:CVE-TEST"
  assert edge_record.target_id == "fix-commit:abc123"
  assert edge_record.properties["edge_type"] == "fixed_by"
  assert json.loads(edge_record.properties["content_json"]) == {"role": "primary"}


def test_dataset_import_builds_core_graph_and_offline_labels(tmp_path: Path):
  dataset_path = tmp_path / "dataset.json"
  dataset_path.write_text(
    json.dumps(
      {
        "CVE-TEST-1": {
          "repo": "demo",
          "CWE": ["CWE-787", "CWE-119"],
          "fixing_commits": [["abc123"], ["def456", "fedcba"]],
          "affected_version": ["v1.0.0", "v1.0.1"],
        }
      }
    ),
    encoding="utf-8",
  )

  graph = build_dataset_graph(dataset_path, limit=1, include_offline_eval=True)
  node_by_id = {node.id: node for node in graph.nodes}
  edge_types = {edge.type for edge in graph.edges}

  assert {"CVE", "Repo", "CWE", "FixCommit", "TargetVerdict"} <= {node.type for node in graph.nodes}
  assert node_by_id["cve:CVE-TEST-1"].allowed_use == "context_only"
  assert node_by_id["repo:demo"].scope == "repo"
  assert node_by_id["fix-commit:demo:abc123"].allowed_use == "root_cause_evidence"
  assert node_by_id["offline-affected:CVE-TEST-1:v1.0.0"].allowed_use == "offline_eval_only"
  assert "fixed_by" in edge_types
  assert "has_cwe" in edge_types
  assert "has_offline_affected_version" in edge_types


def test_patch_text_import_builds_hunks_files_and_changed_functions():
  patch_text = """commit abc123
Author: Test

diff --git a/src/parser.c b/src/parser.c
index 1111111..2222222 100644
--- a/src/parser.c
+++ b/src/parser.c
@@ -10,7 +10,8 @@ static int parse_record(int len)
 int parse_record(int len) {
-  memcpy(dst, src, len);
+  if (len <= cap)
+    memcpy(dst, src, len);
   return 0;
 }
"""

  graph = build_patch_graph_from_text(
    cve_id="CVE-TEST-1",
    repo="demo",
    commit_sha="abc123",
    patch_text=patch_text,
  )
  nodes = {node.id: node for node in graph.nodes}

  assert "patch-hunk:demo:abc123:src/parser.c:1" in nodes
  assert "code-anchor:demo:abc123:src/parser.c:1" in nodes
  assert nodes["file:demo:src/parser.c"].type == "File"
  assert nodes["changed-function:demo:abc123:src/parser.c:parse_record"].type == "ChangedFunction"
  assert nodes["code-anchor:demo:abc123:src/parser.c:1"].type == "CodeAnchor"
  assert nodes["changed-function:demo:abc123:src/parser.c:parse_record"].content["cve_id"] == "CVE-TEST-1"
  hunk = nodes["patch-hunk:demo:abc123:src/parser.c:1"]
  assert hunk.content["old_start"] == 10
  assert hunk.content["new_start"] == 10
  assert hunk.content["deleted_lines"][0]["text"].strip() == "memcpy(dst, src, len);"
  assert {"has_patch_hunk", "touches_file", "touches_function", "yields_anchor"} <= {edge.type for edge in graph.edges}


def test_target_verdict_evidence_filter_excludes_context_candidates_and_offline_nodes():
  graph = GraphDocument(
    nodes=[
      _node("cve:CVE-TEST", "CVE", allowed_use="context_only"),
      _node("memory:repo", "RepoMemory", allowed_use="learning_candidate", lifecycle="candidate"),
      _node("gt:v1", "TargetVerdict", allowed_use="offline_eval_only"),
      _node("git-observation:1", "GitObservation", allowed_use="target_verdict_evidence"),
      _node("predicate-evaluation:1", "PredicateEvaluation", allowed_use="target_verdict_evidence"),
    ]
  )

  assert {node.id for node in target_verdict_evidence_nodes(graph)} == {
    "git-observation:1",
    "predicate-evaluation:1",
  }


def test_schema_cypher_contains_minimal_labels_and_relationships():
  statements = list(iter_schema_cypher())
  joined = "\n".join(statements)

  assert "FOR (n:CVE) REQUIRE n.id IS UNIQUE" in joined
  assert "FOR (n:FixCommit) REQUIRE n.id IS UNIQUE" in joined
  assert "FOR (n:PatchHunk) REQUIRE n.id IS UNIQUE" in joined
  assert "FOR ()-[r:FIXED_BY]-() REQUIRE r.id IS UNIQUE" in joined
  assert "FOR ()-[r:SUPPORTS]-() REQUIRE r.id IS UNIQUE" in joined


def test_cli_import_dataset_writes_jsonl_materialized_graph(tmp_path: Path, monkeypatch, capsys):
  dataset_path = tmp_path / "dataset.json"
  store_root = tmp_path / "store"
  dataset_path.write_text(
    json.dumps(
      {
        "CVE-TEST-1": {
          "repo": "demo",
          "CWE": ["CWE-787"],
          "fixing_commits": [["abc123"]],
          "affected_version": ["v1.0.0"],
        }
      }
    ),
    encoding="utf-8",
  )
  monkeypatch.setattr(
    sys,
    "argv",
    [
      "vulngraph",
      "import-dataset",
      "--store",
      str(store_root),
      "--dataset",
      str(dataset_path),
      "--limit",
      "1",
      "--include-offline-eval",
    ],
  )

  main()

  output = json.loads(capsys.readouterr().out)
  graph = JsonlGraphStore(store_root).materialize()
  assert output["status"] == "ok"
  assert output["nodes"] == len(graph.nodes)
  assert "fix-commit:demo:abc123" in {node.id for node in graph.nodes}

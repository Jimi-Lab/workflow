from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulngraph.agent_backend import OpenCodeBackend, OpenCodeBackendConfig, add_opencode_model_arguments
from vulngraph.agent_io import AgentOutput, agent_output_to_events
from vulngraph.builder import SeedGraphInput, build_dataset_graph, build_patch_graph_from_repo, build_seed_graph
from vulngraph.neo4j_store import Neo4jConfig, Neo4jGraphStore
from vulngraph.root_cause import (
  RootCauseAgentService,
  RootCauseContextConfig,
  load_batch_cases,
  run_root_cause_batch,
)
from vulngraph.schema import GraphEvent
from vulngraph.store import JsonlGraphStore


def main() -> None:
  parser = argparse.ArgumentParser(prog="vulngraph")
  sub = parser.add_subparsers(dest="command", required=True)

  seed = sub.add_parser("seed")
  seed.add_argument("--store", required=True)
  seed.add_argument("--input", required=True)

  ingest = sub.add_parser("ingest-agent-output")
  ingest.add_argument("--store", required=True)
  ingest.add_argument("--input", required=True)

  materialize = sub.add_parser("materialize")
  materialize.add_argument("--store", required=True)

  import_dataset = sub.add_parser("import-dataset")
  import_dataset.add_argument("--store", required=True)
  import_dataset.add_argument("--dataset", required=True)
  import_dataset.add_argument("--limit", type=int)
  import_dataset.add_argument("--include-offline-eval", action="store_true")
  import_dataset.add_argument("--include-patches", action="store_true")
  import_dataset.add_argument("--repo-root")
  import_dataset.add_argument("--patch-max-chars", type=int)

  neo4j_init = sub.add_parser("neo4j-init")
  neo4j_init.add_argument("--uri")
  neo4j_init.add_argument("--user")
  neo4j_init.add_argument("--password")

  neo4j_sync = sub.add_parser("neo4j-sync")
  neo4j_sync.add_argument("--store", required=True)
  neo4j_sync.add_argument("--init-schema", action="store_true")
  neo4j_sync.add_argument("--uri")
  neo4j_sync.add_argument("--user")
  neo4j_sync.add_argument("--password")

  root_cause = sub.add_parser("root-cause")
  root_cause.add_argument("--store", required=True)
  root_cause.add_argument("--runs", default="runs")
  root_cause.add_argument("--cve", required=True)
  root_cause.add_argument("--repo", required=True)
  root_cause.add_argument("--repo-path", required=True)
  root_cause.add_argument("--base-url", default="http://127.0.0.1:4096")
  add_opencode_model_arguments(root_cause)
  root_cause.add_argument("--agent")
  root_cause.add_argument("--timeout", type=float, default=300.0)
  root_cause.add_argument("--max-context-nodes", type=int, default=40)
  root_cause.add_argument("--max-context-chars", type=int, default=24000)
  root_cause.add_argument("--allow-bash", action="store_true")

  batch = sub.add_parser("root-cause-batch")
  batch.add_argument("--dataset", required=True)
  batch.add_argument("--nvd", required=True)
  batch.add_argument("--repo-root", required=True)
  batch.add_argument("--output-root", required=True)
  batch.add_argument("--limit", type=int, default=10)
  batch.add_argument("--base-url", default="http://127.0.0.1:4096")
  add_opencode_model_arguments(batch)
  batch.add_argument("--agent")
  batch.add_argument("--timeout", type=float, default=300.0)
  batch.add_argument("--max-context-nodes", type=int, default=40)
  batch.add_argument("--max-context-chars", type=int, default=24000)

  args = parser.parse_args()

  if args.command == "seed":
    store = JsonlGraphStore(args.store)
    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    graph = build_seed_graph(SeedGraphInput.model_validate(data))
    events = [GraphEvent.upsert_node(node, created_from="cli_seed") for node in graph.nodes]
    events.extend(GraphEvent.upsert_edge(edge, created_from="cli_seed") for edge in graph.edges)
    store.append_events(events)
    graph = store.materialize()
    store.write_snapshot(graph)
    print(json.dumps({"status": "ok", "nodes": len(graph.nodes), "edges": len(graph.edges)}, ensure_ascii=False))
    return

  if args.command == "ingest-agent-output":
    store = JsonlGraphStore(args.store)
    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    store.append_events(agent_output_to_events(AgentOutput.model_validate(data)))
    graph = store.materialize()
    store.write_snapshot(graph)
    print(json.dumps({"status": "ok", "nodes": len(graph.nodes), "edges": len(graph.edges)}, ensure_ascii=False))
    return

  if args.command == "materialize":
    store = JsonlGraphStore(args.store)
    graph = store.materialize()
    store.write_snapshot(graph)
    print(json.dumps({"status": "ok", "nodes": len(graph.nodes), "edges": len(graph.edges)}, ensure_ascii=False))
    return

  if args.command == "import-dataset":
    store = JsonlGraphStore(args.store)
    graph = build_dataset_graph(
      args.dataset,
      limit=args.limit,
      include_offline_eval=args.include_offline_eval,
    )
    store.append_graph(graph, created_from="cli_import_dataset")
    patch_nodes = 0
    patch_edges = 0
    if args.include_patches:
      if not args.repo_root:
        raise SystemExit("--repo-root is required with --include-patches")
      for node in graph.nodes:
        if node.type != "FixCommit":
          continue
        repo = str(node.content.get("repo") or "")
        commit_sha = str(node.content.get("commit_sha") or "")
        cve_id = str(node.content.get("cve_id") or "")
        repo_path = Path(args.repo_root) / repo
        if not repo or not commit_sha or not cve_id or not repo_path.exists():
          continue
        try:
          patch_graph = build_patch_graph_from_repo(
            cve_id=cve_id,
            repo=repo,
            repo_path=repo_path,
            commit_sha=commit_sha,
            max_chars=args.patch_max_chars,
            fix_commit_content=dict(node.content),
          )
        except Exception:
          continue
        patch_nodes += len(patch_graph.nodes)
        patch_edges += len(patch_graph.edges)
        store.append_graph(patch_graph, created_from="cli_import_patch")
    materialized_graph = store.materialize()
    store.write_snapshot(materialized_graph)
    print(
      json.dumps(
        {
          "status": "ok",
          "nodes": len(materialized_graph.nodes),
          "edges": len(materialized_graph.edges),
          "patch_nodes": patch_nodes,
          "patch_edges": patch_edges,
        },
        ensure_ascii=False,
      )
    )
    return

  if args.command == "neo4j-init":
    store = Neo4jGraphStore(_neo4j_config_from_args(args))
    try:
      store.create_schema()
    finally:
      store.close()
    print(json.dumps({"status": "ok"}, ensure_ascii=False))
    return

  if args.command == "neo4j-sync":
    graph = JsonlGraphStore(args.store).materialize()
    store = Neo4jGraphStore(_neo4j_config_from_args(args))
    try:
      store.upsert_graph(graph, create_schema=args.init_schema)
      counts = store.counts()
    finally:
      store.close()
    print(json.dumps({"status": "ok", **counts}, ensure_ascii=False))
    return

  if args.command == "root-cause":
    store = JsonlGraphStore(args.store)
    backend = OpenCodeBackend(
      OpenCodeBackendConfig(
        base_url=args.base_url,
        provider_id=args.provider_id,
        model_id=args.model_id,
        agent=args.agent,
        timeout_s=args.timeout,
        allow_bash=args.allow_bash,
      )
    )
    service = RootCauseAgentService(
      backend=backend,
      store=store,
      runs_root=args.runs,
      context_config=RootCauseContextConfig(
        max_nodes=args.max_context_nodes,
        max_chars=args.max_context_chars,
      ),
    )
    result = service.run(
      cve_id=args.cve,
      repo=args.repo,
      repo_path=args.repo_path,
      timeout_s=args.timeout,
    )
    print(json.dumps({"status": "ok", **result.model_dump()}, ensure_ascii=False))
    return

  if args.command == "root-cause-batch":
    backend = OpenCodeBackend(
      OpenCodeBackendConfig(
        base_url=args.base_url,
        provider_id=args.provider_id,
        model_id=args.model_id,
        agent=args.agent,
        timeout_s=args.timeout,
      )
    )
    cases = load_batch_cases(
      dataset_path=args.dataset,
      nvd_path=args.nvd,
      repo_root=args.repo_root,
      limit=args.limit,
    )
    summary = run_root_cause_batch(
      cases=cases,
      backend=backend,
      output_root=args.output_root,
      context_config=RootCauseContextConfig(
        max_nodes=args.max_context_nodes,
        max_chars=args.max_context_chars,
      ),
      timeout_s=args.timeout,
    )
    print(json.dumps(summary.model_dump(mode="json"), ensure_ascii=False))


def _neo4j_config_from_args(args) -> Neo4jConfig | None:
  if not args.uri and not args.user and not args.password:
    return None
  base = Neo4jConfig.from_env()
  return Neo4jConfig(
    uri=args.uri or base.uri,
    user=args.user or base.user,
    password=args.password if args.password is not None else base.password,
  )


if __name__ == "__main__":
  main()

# VulnGraph

VulnGraph is a lightweight, event-sourced multidimensional evidence graph for CVE-oriented agent judgement. JSONL remains the append-only audit/source log, and Neo4j is now the materialized query graph for schema constraints, graph traversal, and packet-oriented retrieval.

The current design does not depend on VulnVersion Step2 or VET. It focuses on:

- typed nodes and edges for vulnerability context, repo context, patch evidence, vulnerability semantics, agent runtime, and self-evolution;
- append-only graph events plus materialized JSONL snapshots and Neo4j query sync;
- strict agent JSON ingestion into graph events;
- packet extraction with allowed-use filtering;
- candidate-only self-evolution until a later gate validates memory or procedures.
- a minimal OpenCode-backed Root Cause Agent with bounded context, read-only Git tools, strict JSON output, and append-only graph ingestion.

## Layout

```text
src/vulngraph/
  schema/      core graph models and event materialization
  ontology/    node/edge/policy definitions
  store/       JSONL event store and snapshots
  builder/     manual seed, dataset, and patch graph construction
  packets/     root-cause and target packet extraction
  agent_io/    strict agent JSON contract and ingestion
  evolution/   failure-to-candidate-memory scaffolding
  root_cause/  context packet, prompt, output contract, event mapping, orchestration
  agent_backend/ OpenCode session and permission adapter
  cli/         small utility commands
data/
  fixtures/    small reproducible graph examples
  external/    placeholder for large external corpora
runs/          local runtime outputs
docs/          ontology and evolution notes
```

## Boundary

VulnGraph does not perform version planning, affected-range aggregation, or GT-driven runtime judgement. CVE/CWE/CAPEC text is context only. A target verdict must be supported by target-local command output represented as `GitObservation` and `PredicateEvaluation`.

See `docs/root_cause_agent.md` for the minimum Root Cause Agent run loop.

## Neo4j Skeleton

The default runtime keeps JSONL auditable and syncs the materialized graph into Neo4j when requested:

```powershell
$env:PYTHONPATH='src'
$env:NEO4J_URI='bolt://localhost:7687'
$env:NEO4J_USER='neo4j'
$env:NEO4J_PASSWORD='<password>'

python -m vulngraph.cli.main import-dataset `
  --store data\graphs\base10 `
  --dataset E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataOrder.json `
  --limit 10 `
  --include-offline-eval

python -m vulngraph.cli.main neo4j-sync --store data\graphs\base10 --init-schema
```

`affected_version` labels are imported only as `offline_eval_only` nodes and are blocked from runtime packets.

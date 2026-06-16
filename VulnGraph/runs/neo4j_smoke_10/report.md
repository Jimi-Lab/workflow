# Neo4j Smoke 10 Report

Generated: 2026-06-12

## Scope

This run only verifies the Neo4j skeleton with real Docker Neo4j, Python CLI import/sync, and scoped query smoke checks. It does not start Root Cause Agent v2 and does not implement Judge Agent.

The data path remains:

```text
BaseDataOrder.json -> JSONL append-only store -> materialized snapshot -> Neo4j query graph
```

## Environment

| Item | Result |
| --- | --- |
| Python | 3.11.3 (`D:\CodeTools\Language\Python\python.exe`) |
| `neo4j` Python driver | 6.2.0 |
| Driver import check | `from neo4j import GraphDatabase` succeeded |
| VulnGraph package | installed editable from `E:\AI\Agent\workflow\VulnGraph` |
| Docker | Docker 28.3.3, Compose v2.39.2-desktop.1 |
| Container | `VulnKG-Neo4j Up 9 hours` |
| Bolt endpoint | `bolt://localhost:7687` |
| Neo4j server | Neo4j Kernel 2026.05.0 community |
| Connectivity | `driver.verify_connectivity()` succeeded |

The local `src/neo4j/docker-compose.yml` uses `NEO4J_AUTH: neo4j/password`. Runtime commands set `NEO4J_PASSWORD` only as a process environment variable; no password was written into source code.

## Executed Commands

Driver and CLI checks:

```powershell
python -c "from neo4j import GraphDatabase; import neo4j; print('ok'); print(getattr(neo4j, '__file__', None))"
$env:PYTHONPATH='src'; python -c "import importlib.util; spec=importlib.util.find_spec('neo4j'); print(spec); from neo4j import GraphDatabase; print('ok')"
python -m vulngraph.cli.main --help
```

Docker and connectivity checks:

```powershell
docker ps -a --filter "name=VulnKG-Neo4j" --format "{{.Names}} {{.Status}} {{.Ports}}"
$env:NEO4J_URI='bolt://localhost:7687'
$env:NEO4J_USER='neo4j'
$env:NEO4J_PASSWORD='<local-compose-password>'
python -c "from neo4j import GraphDatabase; import os; driver=GraphDatabase.driver(os.environ['NEO4J_URI'], auth=(os.environ['NEO4J_USER'], os.environ['NEO4J_PASSWORD'])); driver.verify_connectivity(); print('connected'); driver.close()"
```

10-CVE import and Neo4j sync:

```powershell
python -m vulngraph.cli.main import-dataset --store 'E:\AI\Agent\workflow\VulnGraph\runs\neo4j_smoke_10\graph_store' --dataset 'E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataOrder.json' --limit 10 --include-offline-eval --include-patches --repo-root 'E:\AI\Agent\workflow\VulnVersion\repo' --patch-max-chars 80000

$env:NEO4J_URI='bolt://localhost:7687'
$env:NEO4J_USER='neo4j'
$env:NEO4J_PASSWORD='<local-compose-password>'
python -m vulngraph.cli.main neo4j-sync --store 'E:\AI\Agent\workflow\VulnGraph\runs\neo4j_smoke_10\graph_store' --init-schema

python scripts\neo4j_smoke_checks.py --store 'E:\AI\Agent\workflow\VulnGraph\runs\neo4j_smoke_10\graph_store' --output 'E:\AI\Agent\workflow\VulnGraph\runs\neo4j_smoke_10\smoke_checks.json'
```

Verification:

```powershell
python -m pytest -q
python -m compileall src tests
```

## Import Result

Final CLI import output:

```json
{"status": "ok", "nodes": 1586, "edges": 1662, "patch_nodes": 272, "patch_edges": 305}
```

Final Neo4j sync output:

```json
{"status": "ok", "nodes": 1586, "edges": 1662}
```

JSONL audit files:

| File | Size |
| --- | ---: |
| `graph_store/events.jsonl` | 6,971,809 bytes |
| `graph_store/nodes.jsonl` | 1,145,651 bytes |
| `graph_store/edges.jsonl` | 1,133,977 bytes |

## 10-CVE Import Table

| CVE | Repo | CWEs | FixCommits | PatchHunks | CodeAnchors | ChangedFunctions | OfflineAffected |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CVE-2022-3965 | FFmpeg | 2 | 1 | 8 | 8 | 1 | 6 |
| CVE-2020-24020 | FFmpeg | 1 | 1 | 9 | 9 | 1 | 1 |
| CVE-2022-3341 | FFmpeg | 1 | 1 | 2 | 2 | 2 | 350 |
| CVE-2022-3109 | FFmpeg | 1 | 1 | 1 | 1 | 0 | 328 |
| CVE-2024-7055 | FFmpeg | 1 | 1 | 1 | 1 | 0 | 32 |
| CVE-2020-14212 | FFmpeg | 1 | 2 | 46 | 46 | 14 | 1 |
| CVE-2022-48434 | FFmpeg | 1 | 2 | 14 | 14 | 7 | 224 |
| CVE-2023-47342 | FFmpeg | 1 | 2 | 2 | 2 | 0 | 351 |
| CVE-2022-3964 | FFmpeg | 2 | 1 | 6 | 6 | 0 | 17 |
| CVE-2020-12284 | FFmpeg | 2 | 3 | 3 | 3 | 0 | 9 |

## Neo4j Scoped Counts

These counts are scoped to node/edge ids from the JSONL store, not the entire database.

| Node type | Count |
| --- | ---: |
| CVE | 10 |
| CWE | 9 |
| Repo | 1 |
| FixCommit | 15 |
| PatchHunk | 92 |
| CodeAnchor | 92 |
| File | 23 |
| ChangedFunction | 25 |
| TargetVerdict | 1319 |

| Edge type | Count |
| --- | ---: |
| fixed_by | 15 |
| has_cwe | 13 |
| targets_repo | 10 |
| has_patch_hunk | 92 |
| touches_file | 92 |
| touches_function | 29 |
| yields_anchor | 92 |
| has_offline_affected_version | 1319 |

Coverage:

| Check | Result |
| --- | ---: |
| CVEs with `FIXED_BY` FixCommit | 10 |
| `FIXED_BY` edges | 15 |
| linked FixCommit nodes | 15 |
| FixCommits with `HAS_PATCH_HUNK` | 15 |
| `HAS_PATCH_HUNK` edges | 92 |
| linked PatchHunk nodes | 92 |

## Policy Checks

| Check | Result |
| --- | ---: |
| Nodes missing `scope/allowed_use/lifecycle/source_refs` metadata | 0 |
| Edges missing `scope/allowed_use/lifecycle/source_refs` metadata | 0 |
| Context nodes incorrectly marked `target_verdict_evidence` | 0 |
| Offline eval nodes incorrectly marked `target_verdict_evidence` | 0 |

`affected_version` labels are present only as `TargetVerdict` nodes with `allowed_use=offline_eval_only`. They are not target verdict evidence.

## Verification Results

| Command | Result |
| --- | --- |
| `python -m pytest -q` | `19 passed in 0.60s` |
| `python -m compileall src tests` | exit code 0 |
| Neo4j import/sync | exit code 0 |
| Neo4j smoke query | exit code 0; wrote `runs/neo4j_smoke_10/smoke_checks.json` |

## Current Blockers And Notes

- No hard blocker remains for the Neo4j skeleton smoke path.
- `src/neo4j` currently contains Docker compose data/logs/plugins. This did not break import after installing the official driver, but it is poor project hygiene because `python -m compileall src tests` traverses Neo4j database directories. Move this Docker working directory to something like `infra/neo4j` or `docker/neo4j` after stopping the container and updating paths.
- The first 10 entries of `BaseDataOrder.json` are all FFmpeg CVEs, so this is a pipeline smoke test, not repo-diversity validation.
- Changed function extraction is heuristic and depends on unified diff hunk headers. Several CVEs have anchors but zero changed-function symbols; this is expected for the current parser.
- The JSONL store is still the audit/source layer. Neo4j is the materialized query graph.

## Next Step Recommendation

Keep this report as the Neo4j skeleton baseline. After review, the next implementation step should be Root Cause Agent v2 packet extraction and tool-trace ingestion, but that was intentionally not started in this run.

## Service API Layer Update

Update time: 2026-06-12

The Agent-Graph interaction core is now exposed as Python service functions. CLI remains a debug wrapper and is not the main workflow interface.

### Implemented API Surface

Main entrypoint:

```python
from vulngraph.services import VulnGraphClient

client = VulnGraphClient(r"E:\AI\Agent\workflow\VulnGraph\runs\neo4j_smoke_10\graph_store")
```

Available service APIs:

| API | Status | Purpose |
| --- | --- | --- |
| `client.get_cve_graph(cve_id, include_debug=False)` | implemented and unit-tested | Return structured CVE subgraph context for workflow prompt construction. |
| `client.build_root_cause_packet(cve_id, mode="production")` | implemented and unit-tested | Build production/debug root-cause packet with policy filtering. |
| `client.ingest_root_cause_output(cve_id, agent_output, trace=None)` | implemented and unit-tested | Write root-cause semantic nodes and wrapper trace evidence into JSONL graph. |
| `client.build_judge_packet(cve_id, target_id, repo_ref=None, mode="production")` | implemented and unit-tested | Build target-judgement packet from existing root-cause evidence. |
| `client.ingest_judge_output(cve_id, target_id, agent_output, trace=None)` | implemented and unit-tested | Write target-local evidence, predicate evaluation, and verdict into graph. |
| `client.get_target_verdicts(cve_id, target_ids)` | implemented and unit-tested | Query multiple target verdicts without using offline eval labels. |
| `client.infer_bic_candidates(cve_id, target_ids, strategy="hybrid")` | implemented and unit-tested | Infer commit-level BIC candidates from blame/ancestry GitObservation evidence. |
| `client.sync_to_neo4j(create_schema=True)` | implemented, not unit-tested with live server | Sync current JSONL materialized graph into Neo4j. |

### API Input/Output Examples

Root-cause packet:

```python
packet = client.build_root_cause_packet("CVE-TEST", mode="production")
```

Output shape:

```json
{
  "task": "root_cause_extraction",
  "context": ["CVE/CWE/Reference/Advisory nodes"],
  "patch_evidence": ["FixCommit/PatchHunk/ChangedFunction/CodeAnchor nodes"],
  "repo_navigation": ["Repo/File/PathAlias nodes"],
  "procedure_hints": ["validated ProcedureMemory only"],
  "output_contract": {"evidence_gate": "RootCauseHypothesis must be supported by at least one GitObservation from wrapper trace."},
  "forbidden": ["affected_version/offline_eval_only", "target verdicts as root-cause evidence"]
}
```

Root-cause ingestion:

```python
result = client.ingest_root_cause_output(
    "CVE-TEST",
    agent_output={
        "agent_run": {"run_id": "rc-1", "backend": "opencode"},
        "root_cause_hypotheses": [{"hypothesis_id": "hyp-1", "summary": "..."}],
        "vulnerable_predicates": [],
        "fix_predicates": [],
        "guard_conditions": [],
        "negative_conditions": [],
        "code_anchors": []
    },
    trace={
        "tool_calls": [{"id": "cmd-1", "command": "git show ...", "output": "...", "exit_code": 0}],
        "git_observations": [{"id": "obs-1", "command_ref": "cmd-1", "claim": "...", "supports": ["hyp-1"]}]
    }
)
```

Result shape:

```json
{"status": "accepted|rejected", "lifecycle": "raw|rejected", "appended_events": 12, "errors": []}
```

Judge packet:

```python
packet = client.build_judge_packet("CVE-TEST", "v1.0.0")
```

Output includes `RootCauseHypothesis`, top-k `CodeAnchor`, predicates, recommended git operations, candidate paths/functions, and the required target-local evidence schema. It does not include final verdict evidence.

Judge ingestion:

```python
result = client.ingest_judge_output(
    "CVE-TEST",
    "v1.0.0",
    agent_output={
        "agent_run": {"run_id": "judge-v1.0.0"},
        "predicate_evaluations": [{"evaluation_id": "eval-1", "observation_ids": ["obs-1"], "result": "satisfied"}],
        "target_verdict": {"verdict_id": "verdict-1", "target_id": "v1.0.0", "verdict": "AFFECTED", "evidence_evaluation_ids": ["eval-1"]}
    },
    trace={
        "git_observations": [{"id": "obs-1", "target_id": "v1.0.0", "claim": "...", "blame_commit": "badc0de"}]
    }
)
```

### Policy Gate Test Results

Added `tests/test_services.py` with six service-level policy tests:

| Gate | Result |
| --- | --- |
| `build_root_cause_packet(..., mode="production")` excludes candidate memory | pass |
| `build_root_cause_packet(..., mode="production")` excludes offline eval affected-version labels | pass |
| `ingest_root_cause_output` rejects hypotheses without GitObservation support | pass |
| `build_judge_packet` includes root-cause hypothesis but no final verdict evidence | pass |
| `ingest_judge_output` rejects verdicts without target-local GitObservation | pass |
| `infer_bic_candidates` returns commit-level candidates, not target versions | pass |

Verification after service update:

```text
python -m pytest tests\test_services.py -q  -> 6 passed
python -m pytest -q                         -> 25 passed
python -m compileall src tests scripts      -> exit code 0
neo4j-sync --init-schema                    -> {"status": "ok", "nodes": 1586, "edges": 1662}
```

### Implemented vs Placeholder

Implemented and runnable:

- JSONL-backed service client.
- CVE graph extraction.
- Root-cause packet policy filtering.
- Root-cause output ingestion with wrapper-trace evidence gate.
- Judge packet extraction.
- Judge output ingestion with target-local evidence gate.
- Multi-target verdict query.
- BIC candidate inference from blame/ancestry GitObservation evidence.
- Minimal Neo4j schema labels/relations for `Target`, `TargetSnapshot`, `BICCandidate`, `VersionBoundary`, and `VerdictAggregation`.

Still intentionally not implemented:

- Full OpenCode Root Cause Agent v2 orchestration.
- Full Judge Agent orchestration.
- Automatic affected-version conversion.
- Version planning.
- Broad version graph / release graph.
- Automatic candidate memory promotion.

### How Root Cause Agent v2 Should Use This

The next Root Cause Agent v2 loop should call the service API directly:

```text
client.build_root_cause_packet(cve_id)
  -> render prompt for OpenCode
  -> run OpenCode with wrapper-owned read-only git tools
  -> wrapper captures tool_calls/git_observations
  -> client.ingest_root_cause_output(cve_id, agent_json, trace=wrapper_trace)
  -> optional client.sync_to_neo4j(create_schema=True)
```

The agent must not be asked to self-report command traces as the evidence source. Wrapper-captured trace is the authoritative evidence channel.

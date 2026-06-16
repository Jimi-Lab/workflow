from __future__ import annotations

import json
import time
from pathlib import Path

from pydantic import BaseModel, Field

from vulngraph.agent_backend import RootCauseAgentBackend
from vulngraph.builder import SeedGraphInput, build_seed_graph
from vulngraph.store import JsonlGraphStore

from .context import RootCauseContextConfig
from .service import RootCauseAgentService


class RootCauseBatchCase(BaseModel):
  cve_id: str
  repo: str
  repo_path: str
  cwe_ids: list[str] = Field(default_factory=list)
  description: str = ""
  fix_commits: list[str] = Field(min_length=1)
  references: list[str] = Field(default_factory=list)


class RootCauseBatchCaseResult(BaseModel):
  cve_id: str
  repo: str
  primary_fix_commit: str
  all_fix_commits: list[str]
  status: str
  duration_s: float
  run_id: str | None = None
  session_id: str | None = None
  graph_nodes: int = 0
  graph_edges: int = 0
  event_count: int = 0
  command_count: int = 0
  schema_repair_count: int = 0
  hypothesis_count: int = 0
  anchor_count: int = 0
  vulnerable_predicate_count: int = 0
  fix_predicate_count: int = 0
  guard_condition_count: int = 0
  negative_condition_count: int = 0
  risk_flag_count: int = 0
  error_type: str | None = None
  error_message: str | None = None
  run_dir: str | None = None


class RootCauseBatchSummary(BaseModel):
  total: int
  succeeded: int
  failed: int
  output_root: str
  results: list[RootCauseBatchCaseResult]


def load_batch_cases(
  *,
  dataset_path: str | Path,
  nvd_path: str | Path,
  repo_root: str | Path,
  limit: int | None = None,
) -> list[RootCauseBatchCase]:
  dataset = json.loads(Path(dataset_path).read_text(encoding="utf-8"))
  nvd = json.loads(Path(nvd_path).read_text(encoding="utf-8"))
  cases: list[RootCauseBatchCase] = []
  for cve_id, record in dataset.items():
    commits = _flatten_commits(record.get("fixing_commits", []))
    if not commits:
      continue
    repo = str(record.get("repo") or "")
    if not repo:
      continue
    nvd_record = nvd.get(cve_id, {})
    cases.append(
      RootCauseBatchCase(
        cve_id=cve_id,
        repo=repo,
        repo_path=str(Path(repo_root) / repo),
        cwe_ids=[str(value) for value in record.get("CWE", []) if value and value != "None"],
        description=str(nvd_record.get("description") or ""),
        fix_commits=commits,
        references=[f"local-dataset:{Path(dataset_path).name}", f"local-nvd:{Path(nvd_path).name}"],
      )
    )
    if limit is not None and len(cases) >= limit:
      break
  return cases


def run_root_cause_batch(
  *,
  cases: list[RootCauseBatchCase],
  backend: RootCauseAgentBackend,
  output_root: str | Path,
  context_config: RootCauseContextConfig | None = None,
  timeout_s: float | None = None,
) -> RootCauseBatchSummary:
  output_root = Path(output_root)
  output_root.mkdir(parents=True, exist_ok=True)
  (output_root / "batch_cases.json").write_text(
    json.dumps([case.model_dump(mode="json") for case in cases], ensure_ascii=False, indent=2),
    encoding="utf-8",
  )
  results: list[RootCauseBatchCaseResult] = []
  for case in cases:
    started = time.monotonic()
    graph_root = output_root / "graphs" / case.cve_id
    store = JsonlGraphStore(graph_root)
    seed = build_seed_graph(
      SeedGraphInput(
        cve_id=case.cve_id,
        repo=case.repo,
        cwe_id=case.cwe_ids[0] if case.cwe_ids else None,
        cve_description=case.description,
        fix_commit=case.fix_commits[0],
        references=case.references,
        product_hints=[f"additional_fix_commit:{commit}" for commit in case.fix_commits[1:]],
      )
    )
    store.append_graph(seed, created_from="root_cause_batch_seed")
    service = RootCauseAgentService(
      backend=backend,
      store=store,
      runs_root=output_root / "runs",
      context_config=context_config,
    )
    try:
      run = service.run(
        cve_id=case.cve_id,
        repo=case.repo,
        repo_path=case.repo_path,
        timeout_s=timeout_s,
      )
      graph = store.materialize()
      run_dir = Path(run.run_dir)
      output = json.loads((run_dir / "output.json").read_text(encoding="utf-8"))
      prompt = json.loads((run_dir / "prompt.json").read_text(encoding="utf-8"))
      result = RootCauseBatchCaseResult(
        cve_id=case.cve_id,
        repo=case.repo,
        primary_fix_commit=case.fix_commits[0],
        all_fix_commits=case.fix_commits,
        status="success",
        duration_s=round(time.monotonic() - started, 3),
        run_id=run.run_id,
        session_id=run.session_id,
        graph_nodes=len(graph.nodes),
        graph_edges=len(graph.edges),
        event_count=run.event_count,
        command_count=len(output.get("command_invocations", [])),
        schema_repair_count=int(prompt.get("schema_repair_count", 0)),
        hypothesis_count=len(output.get("root_cause_hypotheses", [])),
        anchor_count=len(output.get("code_anchors", [])),
        vulnerable_predicate_count=len(output.get("vulnerable_predicates", [])),
        fix_predicate_count=len(output.get("fix_predicates", [])),
        guard_condition_count=len(output.get("guard_conditions", [])),
        negative_condition_count=len(output.get("negative_applicability_conditions", [])),
        risk_flag_count=len(output.get("risk_flags", [])),
        run_dir=str(run_dir),
      )
    except Exception as error:
      graph = store.materialize()
      result = RootCauseBatchCaseResult(
        cve_id=case.cve_id,
        repo=case.repo,
        primary_fix_commit=case.fix_commits[0],
        all_fix_commits=case.fix_commits,
        status="failed",
        duration_s=round(time.monotonic() - started, 3),
        graph_nodes=len(graph.nodes),
        graph_edges=len(graph.edges),
        error_type=type(error).__name__,
        error_message=str(error),
      )
    results.append(result)
    _write_summary(output_root, results, total=len(cases))
  return _build_summary(output_root, results, total=len(cases))


def _flatten_commits(groups: list) -> list[str]:
  commits: list[str] = []
  for group in groups:
    values = group if isinstance(group, list) else [group]
    for value in values:
      commit = str(value).strip()
      if commit and commit not in commits:
        commits.append(commit)
  return commits


def _build_summary(output_root: Path, results: list[RootCauseBatchCaseResult], *, total: int) -> RootCauseBatchSummary:
  succeeded = sum(result.status == "success" for result in results)
  return RootCauseBatchSummary(
    total=total,
    succeeded=succeeded,
    failed=len(results) - succeeded,
    output_root=str(output_root),
    results=results,
  )


def _write_summary(output_root: Path, results: list[RootCauseBatchCaseResult], *, total: int) -> None:
  summary = _build_summary(output_root, results, total=total)
  (output_root / "summary.json").write_text(
    json.dumps(summary.model_dump(mode="json"), ensure_ascii=False, indent=2),
    encoding="utf-8",
  )

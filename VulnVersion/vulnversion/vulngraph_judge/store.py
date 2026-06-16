from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

from .schema import GraphDocument, GraphEdge, GraphNode


T = TypeVar("T", bound=BaseModel)


class JudgeGraphStore:
  def __init__(self, root: str | Path):
    self.root = Path(root)

  def graph_dir(self, repo: str, cve_id: str) -> Path:
    graph_dir = self.root / "per_cve_graph" / _safe_segment(repo) / _safe_segment(cve_id)
    graph_dir.mkdir(parents=True, exist_ok=True)
    return graph_dir

  def append_node(self, repo: str, cve_id: str, node: GraphNode) -> Path:
    path = self.graph_dir(repo, cve_id) / "nodes.jsonl"
    _append_jsonl(path, node)
    return path

  def append_edge(self, repo: str, cve_id: str, edge: GraphEdge) -> Path:
    path = self.graph_dir(repo, cve_id) / "edges.jsonl"
    _append_jsonl(path, edge)
    return path

  def append_observation(self, repo: str, cve_id: str, observation: GraphNode) -> Path:
    path = self.graph_dir(repo, cve_id) / "observations.jsonl"
    _append_jsonl(path, observation)
    return path

  def load_graph(self, repo: str, cve_id: str) -> GraphDocument:
    graph_dir = self.graph_dir(repo, cve_id)
    return GraphDocument(
      nodes=_read_jsonl(graph_dir / "nodes.jsonl", GraphNode),
      edges=_read_jsonl(graph_dir / "edges.jsonl", GraphEdge),
    )


def _safe_segment(value: str) -> str:
  return re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip() or "unknown")


def _append_jsonl(path: Path, item: BaseModel) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  with path.open("a", encoding="utf-8") as fp:
    fp.write(json.dumps(item.model_dump(mode="json", exclude_none=True), ensure_ascii=False))
    fp.write("\n")


def _read_jsonl(path: Path, model: type[T]) -> list[T]:
  if not path.exists():
    return []
  items: list[T] = []
  for line in path.read_text(encoding="utf-8").splitlines():
    if line.strip():
      items.append(model.model_validate(json.loads(line)))
  return items

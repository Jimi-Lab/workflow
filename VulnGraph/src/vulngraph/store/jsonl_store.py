from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from vulngraph.schema import GraphDocument, GraphEdge, GraphEvent, GraphNode


class JsonlGraphStore:
  def __init__(self, root: str | Path):
    self.root = Path(root)

  @property
  def events_path(self) -> Path:
    return self.root / "events.jsonl"

  @property
  def nodes_path(self) -> Path:
    return self.root / "nodes.jsonl"

  @property
  def edges_path(self) -> Path:
    return self.root / "edges.jsonl"

  def append_event(self, event: GraphEvent) -> None:
    self.root.mkdir(parents=True, exist_ok=True)
    with self.events_path.open("a", encoding="utf-8") as fp:
      fp.write(json.dumps(event.model_dump(mode="json", exclude_none=True), ensure_ascii=False))
      fp.write("\n")

  def append_events(self, events: Iterable[GraphEvent]) -> None:
    for event in events:
      self.append_event(event)

  def append_graph(self, graph: GraphDocument, *, created_from: str) -> None:
    events = [GraphEvent.upsert_node(node, created_from=created_from) for node in graph.nodes]
    events.extend(GraphEvent.upsert_edge(edge, created_from=created_from) for edge in graph.edges)
    self.append_events(events)

  def load_events(self) -> list[GraphEvent]:
    if not self.events_path.exists():
      return []
    events: list[GraphEvent] = []
    for line in self.events_path.read_text(encoding="utf-8").splitlines():
      if line.strip():
        events.append(GraphEvent.model_validate(json.loads(line)))
    return events

  def materialize(self) -> GraphDocument:
    return GraphDocument.from_events(self.load_events())

  def write_snapshot(self, graph: GraphDocument) -> None:
    self.root.mkdir(parents=True, exist_ok=True)
    _write_jsonl(self.nodes_path, graph.nodes)
    _write_jsonl(self.edges_path, graph.edges)


def _write_jsonl(path: Path, items: list[GraphNode] | list[GraphEdge]) -> None:
  with path.open("w", encoding="utf-8") as fp:
    for item in items:
      fp.write(json.dumps(item.model_dump(mode="json", exclude_none=True), ensure_ascii=False))
      fp.write("\n")

from __future__ import annotations

from pydantic import BaseModel, Field


class PredicateEval(BaseModel):
  predicate_id: str
  matched: bool
  evidence_snippets: list[dict] = Field(default_factory=list)


class TagVerdict(BaseModel):
  tag: str
  line: str | None = None
  verdict: str | None = None
  run_status: str = "OK"
  confidence: float
  matched_predicates: list[str] = Field(default_factory=list)
  failed_predicates: list[str] = Field(default_factory=list)
  triggered_guards: list[str] = Field(default_factory=list)
  evidence_snippets: list[dict] = Field(default_factory=list)
  reasoning_summary: str = ""
  # ── P0-2: artifact semantic separation ─────────────────────────────
  # Canonical verdict_source taxonomy:
  #   "agent"             — LLM agent gave a verdict (run_status OK / PARTIAL_PARSE)
  #   "prefilter"         — static prefilter resolved (run_status PREFILTER)
  #   "inferred_interval" — ASBS interval inference (run_status INFERRED)
  #   "agent_error"       — execution failure (AGENT_ERROR / TIMEOUT / etc.)
  # Downstream consumers must bucket by this field, NOT by verdict alone.
  verdict_source: str | None = None
  # For inferred_interval rows: tags whose probed verdicts justify this inference.
  inferred_from: list[str] = Field(default_factory=list)
  # Stable identifier of the monotonicity/prefilter certificate that produced this row.
  certificate_id: str | None = None

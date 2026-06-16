from __future__ import annotations

from pydantic import BaseModel, Field


class EvidenceRef(BaseModel):
  ref: str
  source: str
  snippet: str


class TraceStep(BaseModel):
  step_id: str
  thought_summary: str | None = None
  tool_name: str | None = None
  tool_args: dict | None = None
  tool_output_digest: str | None = None
  evidence_refs: list[EvidenceRef] = Field(default_factory=list)


class AgentRunOutput(BaseModel):
  result: dict
  trace: list[TraceStep] = Field(default_factory=list)
  evidence_pack: list[EvidenceRef] = Field(default_factory=list)


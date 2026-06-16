from __future__ import annotations

from vulngraph.schema import GraphNode


NODE_TYPES = {
  "CVE",
  "CWE",
  "CAPEC",
  "Advisory",
  "Reference",
  "ProductHint",
  "Repo",
  "File",
  "Function",
  "Symbol",
  "RepoComponent",
  "FilePath",
  "FunctionSymbol",
  "PathAlias",
  "BuildCondition",
  "FixCommit",
  "PatchHunk",
  "ChangedFile",
  "ChangedFunction",
  "CodeAnchor",
  "RootCauseHypothesis",
  "VulnerablePredicate",
  "FixPredicate",
  "GuardCondition",
  "NegativeCondition",
  "NegativeApplicabilityCondition",
  "RiskFlag",
  "AgentRun",
  "AgentStep",
  "ToolCall",
  "ToolOutput",
  "CommandInvocation",
  "CommandOutput",
  "GitObservation",
  "PredicateEvaluation",
  "Target",
  "TargetSnapshot",
  "TargetVerdict",
  "UncertaintyReason",
  "BICCandidate",
  "VersionBoundary",
  "VerdictAggregation",
  "FailureCase",
  "SuccessCase",
  "MemoryCandidate",
  "RepoMemory",
  "CWEMemory",
  "PredicateMemory",
  "ProcedureMemory",
  "SkillProcedure",
  "ArtifactRule",
}

EDGE_TYPES = {
  "has_cwe",
  "has_reference",
  "affects_product_hint",
  "targets_repo",
  "has_component",
  "contains_path",
  "defines_function",
  "aliases",
  "fixed_by",
  "has_patch_hunk",
  "modifies",
  "touches_file",
  "touches_function",
  "yields_anchor",
  "requires",
  "blocked_by",
  "constrained_by",
  "excluded_by",
  "anchored_by",
  "has_step",
  "invokes",
  "produces",
  "proposes",
  "derives",
  "supports",
  "contradicts",
  "supports_verdict",
  "has_snapshot",
  "evaluates_target",
  "has_uncertainty",
  "ranks_bic",
  "has_boundary",
  "has_offline_affected_version",
  "candidate_updates",
  "generates_candidate",
  "promoted_to",
  "reinforces",
  "may_promote_to",
  "supersedes",
  "deprecated_by",
}

CONTEXT_NODE_TYPES = {
  "CVE",
  "CWE",
  "CAPEC",
  "Advisory",
  "Reference",
  "ProductHint",
  "Repo",
  "File",
  "Function",
  "Symbol",
  "RepoComponent",
  "FilePath",
  "FunctionSymbol",
  "PathAlias",
  "BuildCondition",
}

AGENT_RUNTIME_TYPES = {
  "AgentRun",
  "AgentStep",
  "ToolCall",
  "ToolOutput",
  "CommandInvocation",
  "CommandOutput",
  "GitObservation",
  "PredicateEvaluation",
  "Target",
  "TargetSnapshot",
  "TargetVerdict",
  "UncertaintyReason",
  "BICCandidate",
  "VersionBoundary",
  "VerdictAggregation",
}

LEARNING_NODE_TYPES = {
  "FailureCase",
  "SuccessCase",
  "MemoryCandidate",
  "RepoMemory",
  "CWEMemory",
  "PredicateMemory",
  "ProcedureMemory",
  "SkillProcedure",
  "ArtifactRule",
}


def packet_eligible(node: GraphNode) -> bool:
  if node.lifecycle not in {"raw", "validated"}:
    return False
  if node.allowed_use in {"learning_candidate", "offline_eval_only"}:
    return False
  return True


def target_verdict_evidence_nodes(graph) -> list[GraphNode]:
  return [
    node
    for node in graph.nodes
    if node.type in {"GitObservation", "PredicateEvaluation"}
    and node.allowed_use == "target_verdict_evidence"
    and node.lifecycle in {"raw", "validated"}
  ]

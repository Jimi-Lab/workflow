from __future__ import annotations

from collections import defaultdict
from typing import Any, Literal

from vulngraph.schema import GraphDocument

from .common import node_to_dict


BicStrategy = Literal["blame", "boundary", "hybrid"]


def get_target_verdicts(graph: GraphDocument, cve_id: str, target_ids: list[str]) -> dict[str, Any]:
  targets: dict[str, list[dict[str, Any]]] = {target_id: [] for target_id in target_ids}
  for node in graph.nodes:
    if node.type != "TargetVerdict":
      continue
    if node.allowed_use == "offline_eval_only":
      continue
    if str(node.content.get("cve_id") or "") != cve_id:
      continue
    target_id = str(node.content.get("target_id") or node.content.get("target") or "")
    if target_id not in targets:
      continue
    item = node_to_dict(node)
    item["verdict"] = node.content.get("verdict")
    item["target_id"] = target_id
    targets[target_id].append(item)
  return {"cve_id": cve_id, "targets": targets}


def infer_bic_candidates(
  graph: GraphDocument,
  cve_id: str,
  target_ids: list[str],
  *,
  strategy: BicStrategy = "hybrid",
) -> dict[str, Any]:
  target_set = set(target_ids)
  evidence_by_commit: dict[str, list[dict[str, Any]]] = defaultdict(list)
  for node in graph.nodes:
    if node.type == "BICCandidate":
      commit_sha = str(node.content.get("commit_sha") or "")
      if commit_sha and commit_sha not in target_set and str(node.content.get("cve_id") or "") == cve_id:
        evidence_by_commit[commit_sha].append({"node_id": node.id, "evidence_type": node.content.get("evidence_type", "candidate")})
      continue
    if node.type != "GitObservation":
      continue
    if node.allowed_use != "target_verdict_evidence":
      continue
    if str(node.content.get("cve_id") or "") != cve_id:
      continue
    target_id = str(node.content.get("target_id") or node.content.get("target") or "")
    if target_id not in target_set:
      continue
    commit_sha = _commit_from_observation(node.content)
    if not commit_sha or commit_sha in target_set:
      continue
    evidence_type = "blame" if node.content.get("blame_commit") or "blame" in str(node.content.get("command_ref") or "").lower() else "ancestry"
    if strategy == "blame" and evidence_type != "blame":
      continue
    if strategy == "boundary" and evidence_type == "blame":
      continue
    evidence_by_commit[commit_sha].append(
      {
        "node_id": node.id,
        "target_id": target_id,
        "evidence_type": evidence_type,
        "claim": node.content.get("claim"),
        "path": node.content.get("path"),
      }
    )

  candidates = [
    {
      "commit_sha": commit_sha,
      "rank": index + 1,
      "strategy": strategy,
      "evidence_type": _dominant_evidence_type(evidence),
      "support_count": len(evidence),
      "evidence": evidence,
    }
    for index, (commit_sha, evidence) in enumerate(
      sorted(evidence_by_commit.items(), key=lambda item: (-len(item[1]), item[0]))
    )
  ]
  return {
    "cve_id": cve_id,
    "target_ids": target_ids,
    "strategy": strategy,
    "boundary": _verdict_boundary(graph, cve_id, target_ids),
    "candidates": candidates,
    "note": "BICCandidate is a commit-level hypothesis; target versions are never returned as BIC commits.",
  }


def _commit_from_observation(content: dict[str, Any]) -> str:
  for key in ("blame_commit", "bic_candidate_sha", "candidate_commit", "commit_sha"):
    value = content.get(key)
    if value:
      return str(value)
  return ""


def _dominant_evidence_type(evidence: list[dict[str, Any]]) -> str:
  if any(item.get("evidence_type") == "blame" for item in evidence):
    return "blame"
  if any(item.get("evidence_type") == "ancestry" for item in evidence):
    return "ancestry"
  return str(evidence[0].get("evidence_type") or "candidate") if evidence else "candidate"


def _verdict_boundary(graph: GraphDocument, cve_id: str, target_ids: list[str]) -> dict[str, list[str]]:
  verdicts = get_target_verdicts(graph, cve_id, target_ids)
  boundary = {"affected": [], "fixed": [], "unknown": []}
  for target_id, items in verdicts["targets"].items():
    if not items:
      boundary["unknown"].append(target_id)
      continue
    latest = items[-1]
    verdict = str(latest.get("verdict") or "").upper()
    if verdict == "AFFECTED":
      boundary["affected"].append(target_id)
    elif verdict == "NOT_AFFECTED":
      boundary["fixed"].append(target_id)
    else:
      boundary["unknown"].append(target_id)
  return boundary

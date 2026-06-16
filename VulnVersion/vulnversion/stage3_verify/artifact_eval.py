"""artifact_eval.py – official Step3 evaluation metrics with full verdict_source breakdown.

Issue 6 constraint: official_metrics MUST include fixed_segment_clear.
  fixed_segment_clear is a Git-evidence-guided NOT_AFFECTED deduction.
  When correct (tag is GT NOT_AFFECTED) → TN.
  When wrong  (tag is GT AFFECTED)     → FN.
  It must never silently disappear from the confusion matrix.

Two metric sets are always computed and reported together:
  official_metrics:
      Every resolved tag (agent + inferred + fixed_segment_clear) participates.
      This is the primary paper metric.
  ablation_metrics_without_fixed_segment_clear:
      fixed_segment_clear tags are excluded from CM to isolate the
      agent+ASBS contribution.  Used for ablation experiments.

agent_error tags:
  Do NOT participate in official TP/FP/FN/TN.
  They contribute to FN_execution (when the tag is in GT) and to UNK count.
  They are always reported in a separate bucket.

unresolved/deferred tags:
  Are distinct from agent_error. They mean Step3 did not produce a row for the
  tag, or intentionally deferred the tag. GT-affected unresolved/deferred tags
  contribute to FN_unresolved/FN_deferred in official recall.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ──────────────────────────────────────────────────────────────────────
# Verdict source taxonomy (canonical names — must match asbs_line.py)
# ──────────────────────────────────────────────────────────────────────

AGENT_SOURCES: frozenset[str] = frozenset({"agent"})
INFERRED_SOURCES: frozenset[str] = frozenset({
    "inferred_interval",
    "inferred_no_affected",
    "inferred_full_line_affected",
})
GIT_PREFILTER_SOURCES: frozenset[str] = frozenset({"fixed_segment_clear"})
ERROR_SOURCES: frozenset[str] = frozenset({"probe_error", "agent_error"})
DEFERRED_SOURCES: frozenset[str] = frozenset({"deferred", "unresolved"})


def _source_bucket(verdict_source: str | None) -> str:
    """Classify a verdict_source value into one of four eval buckets."""
    s = verdict_source or "agent_error"
    if s in AGENT_SOURCES:
        return "agent"
    if s in INFERRED_SOURCES:
        return "inferred"
    if s in GIT_PREFILTER_SOURCES:
        return "fixed_segment_clear"
    if s in DEFERRED_SOURCES:
        return "deferred"
    return "agent_error"


# ──────────────────────────────────────────────────────────────────────
# Confusion matrix helper
# ──────────────────────────────────────────────────────────────────────

@dataclass
class ConfusionMatrix:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    fn_execution: int = 0    # GT-affected tags that failed (agent_error)
    fn_unmapped: int = 0     # GT tags that could not be mapped to any release tag
    fn_unresolved: int = 0   # GT-affected tags with no output row
    fn_deferred: int = 0     # GT-affected tags explicitly deferred
    unk: int = 0             # total unresolved/deferred/error tags regardless of GT

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 1.0

    @property
    def recall(self) -> float:
        denom = (
            self.tp
            + self.fn
            + self.fn_execution
            + self.fn_unmapped
            + self.fn_unresolved
            + self.fn_deferred
        )
        return self.tp / denom if denom > 0 else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        denom = p + r
        return 2 * p * r / denom if denom > 0 else 0.0

    @property
    def recall_resolved(self) -> float:
        """Recall over resolved tags only (excludes agent_error and unmapped)."""
        denom = self.tp + self.fn
        return self.tp / denom if denom > 0 else 1.0

    @property
    def f1_resolved(self) -> float:
        p, r = self.precision, self.recall_resolved
        denom = p + r
        return 2 * p * r / denom if denom > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "TP": self.tp,
            "FP": self.fp,
            "FN": self.fn,
            "TN": self.tn,
            "FN_execution": self.fn_execution,
            "FN_unmapped": self.fn_unmapped,
            "FN_unresolved": self.fn_unresolved,
            "FN_deferred": self.fn_deferred,
            "UNK": self.unk,
        }


@dataclass
class MetricsSet:
    name: str
    cm: ConfusionMatrix = field(default_factory=ConfusionMatrix)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "confusion_matrix": self.cm.to_dict(),
            "metrics": {
                "precision": self.cm.precision,
                "recall": self.cm.recall,
                "f1": self.cm.f1,
            },
            "metrics_resolved_only": {
                "precision": self.cm.precision,
                "recall": self.cm.recall_resolved,
                "f1": self.cm.f1_resolved,
            },
        }


# ──────────────────────────────────────────────────────────────────────
# Main evaluation function
# ──────────────────────────────────────────────────────────────────────

@dataclass
class EvalResult:
    """Output of evaluate_step3_output."""

    # Per-tag verdict rows (from per_tag_verdict.jsonl or ASBSResult)
    tag_rows: list[dict[str, Any]]

    # GT information
    gt_affected_tags: list[str]              # original GT list
    mapped_gt_tags: list[str]                # GT tags mapped to release tags
    unmapped_gt_tags: list[str]              # GT tags that didn't map

    # Disjoint buckets
    agent_tags: list[str]
    inferred_tags: list[str]
    fixed_segment_clear_tags: list[str]
    agent_error_tags: list[str]
    unresolved_tags: list[str]
    deferred_tags: list[str]

    # Official metrics (includes fixed_segment_clear)
    official_metrics: MetricsSet

    # Ablation metrics (excludes fixed_segment_clear from CM)
    ablation_metrics: MetricsSet

    def to_dict(self) -> dict[str, Any]:
        return {
            "gt_affected_tags": self.gt_affected_tags,
            "mapped_gt_tags": self.mapped_gt_tags,
            "unmapped_gt_tags": self.unmapped_gt_tags,
            "agent_tags": self.agent_tags,
            "inferred_tags": self.inferred_tags,
            "fixed_segment_clear_tags": self.fixed_segment_clear_tags,
            "agent_error_tags": self.agent_error_tags,
            "unresolved_tags": self.unresolved_tags,
            "deferred_tags": self.deferred_tags,
            "agent_error_count": len(self.agent_error_tags),
            "unresolved_count": len(self.unresolved_tags),
            "deferred_count": len(self.deferred_tags),
            "official_metrics": self.official_metrics.to_dict(),
            "ablation_metrics_without_fixed_segment_clear": self.ablation_metrics.to_dict(),
        }


def evaluate_step3_output(
    *,
    tag_rows: list[dict[str, Any]],
    all_release_tags: list[str],
    gt_affected_tags: list[str],
    gt_match_mode: str = "loose",
) -> EvalResult:
    """Compute official and ablation metrics for one CVE's Step3 output.

    Args:
        tag_rows: list of per_tag_verdict.jsonl-style dicts, each with keys:
                  "tag", "verdict", "verdict_source"
        all_release_tags: all release tags for this repo/CVE (full universe)
        gt_affected_tags: ground-truth affected version list (already filtered
                          through sorted() by caller for determinism)
        gt_match_mode: "strict" or "loose" passed to map_gt_tags_to_repo_tags
    """
    from vulnversion.git_ops.repo import map_gt_tags_to_repo_tags

    release_set = set(all_release_tags)

    # Canonical GT mapping (caller should sort gt_affected_tags first)
    mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(
        gt_affected_tags, all_release_tags, mode=gt_match_mode
    )
    gt_set = set(mapped_gt)

    # Build tag-level lookup
    by_tag: dict[str, dict[str, Any]] = {
        str(r.get("tag") or ""): r for r in tag_rows if r.get("tag")
    }

    # Bucket every release tag
    agent_tags: list[str] = []
    inferred_tags: list[str] = []
    fsc_tags: list[str] = []    # fixed_segment_clear
    error_tags: list[str] = []
    unresolved_tags: list[str] = []
    deferred_tags: list[str] = []

    for tag in all_release_tags:
        row = by_tag.get(tag)
        if row is None:
            unresolved_tags.append(tag)
            continue
        bucket = _source_bucket(row.get("verdict_source"))
        if bucket == "agent":
            agent_tags.append(tag)
        elif bucket == "inferred":
            inferred_tags.append(tag)
        elif bucket == "fixed_segment_clear":
            fsc_tags.append(tag)
        elif bucket == "deferred":
            deferred_tags.append(tag)
        else:
            error_tags.append(tag)

    # ── Official CM (agent + inferred + fixed_segment_clear) ──────────
    off = ConfusionMatrix()
    off.fn_unmapped = len(unmapped_gt)
    off.unk = len(error_tags) + len(unresolved_tags) + len(deferred_tags)
    off.fn_execution = sum(1 for t in error_tags if t in gt_set)
    off.fn_unresolved = sum(1 for t in unresolved_tags if t in gt_set)
    off.fn_deferred = sum(1 for t in deferred_tags if t in gt_set)

    resolved_sources = {*agent_tags, *inferred_tags, *fsc_tags}
    for tag in resolved_sources:
        row = by_tag.get(tag, {})
        verdict = row.get("verdict")
        # fixed_segment_clear has implicit verdict NOT_AFFECTED
        if tag in fsc_tags and verdict is None:
            verdict = "NOT_AFFECTED"
        in_gt = tag in gt_set
        if verdict == "AFFECTED" and in_gt:
            off.tp += 1
        elif verdict == "AFFECTED" and not in_gt:
            off.fp += 1
        elif verdict != "AFFECTED" and in_gt:
            off.fn += 1
        elif verdict != "AFFECTED" and not in_gt:
            off.tn += 1

    # ── Ablation CM (agent + inferred only; excludes fixed_segment_clear) ─
    abl = ConfusionMatrix()
    abl.fn_unmapped = len(unmapped_gt)
    abl.unk = len(error_tags) + len(unresolved_tags) + len(deferred_tags) + len(fsc_tags)
    abl.fn_execution = off.fn_execution
    abl.fn_unresolved = off.fn_unresolved
    abl.fn_deferred = off.fn_deferred + sum(1 for t in fsc_tags if t in gt_set)

    ablation_resolved = {*agent_tags, *inferred_tags}
    for tag in ablation_resolved:
        row = by_tag.get(tag, {})
        verdict = row.get("verdict")
        in_gt = tag in gt_set
        if verdict == "AFFECTED" and in_gt:
            abl.tp += 1
        elif verdict == "AFFECTED" and not in_gt:
            abl.fp += 1
        elif verdict != "AFFECTED" and in_gt:
            abl.fn += 1
        elif verdict != "AFFECTED" and not in_gt:
            abl.tn += 1

    return EvalResult(
        tag_rows=tag_rows,
        gt_affected_tags=gt_affected_tags,
        mapped_gt_tags=mapped_gt,
        unmapped_gt_tags=unmapped_gt,
        agent_tags=agent_tags,
        inferred_tags=inferred_tags,
        fixed_segment_clear_tags=fsc_tags,
        agent_error_tags=error_tags,
        unresolved_tags=unresolved_tags,
        deferred_tags=deferred_tags,
        official_metrics=MetricsSet("official", off),
        ablation_metrics=MetricsSet("ablation_without_fixed_segment_clear", abl),
    )

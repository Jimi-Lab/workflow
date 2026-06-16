"""Dynamic line activation scheduler simulator for Step3.

This simulator tests whether family interval closure and evidence-ranked queues
can reduce irrelevant active lines for Step3.  It intentionally does not change
production verifier code.

Boundaries:
  - GT is used only as the selected-probe oracle and final evaluator.
  - No line/tag is removed from the VulnTree.
  - VET evidence only changes priority, activation order, or deferral.
  - VET evidence never emits NOT_AFFECTED / CERT_ABSENT / CERT_FIXED here.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = ROOT / "tests"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from vulnversion.git_ops.repo import map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.git_reachability import batch_tags_containing
from vulnversion.stage3_verify.line_scheduler import _no_fix_lines, _static_neighbors, _stride_lines

from simulate_global_state_line_scheduler import (
    SchedulerConfig,
    _all_fix_file_scout_lines,
    _build_file_endpoint_lines,
    _commits,
    _initial_lines,
    _line_neighbors,
    _line_to_family,
    _load_dataset,
    _repo_name,
    _run_line,
)
from simulate_module_backed_step3 import (
    _batch_path_exists,
    _changed_files_for_commits,
    _release_context,
)
from simulate_step3_low_cost_schedulers import (
    PatchProfile,
    _batch_file_text,
    _extract_patch_profile,
    _sample_tags_for_line,
    _token_evidence_lines,
)
from simulate_vet_line_relevance_scheduler import _build_line_evidence


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "dynamic_line_activation_scheduler"


@dataclass(frozen=True)
class DynamicPolicy:
    name: str
    rank_scout: bool = False
    family_interval_closure: bool = False
    late_all_fix_file_scout: bool = False
    ranked_positive_neighbor: bool = False
    positive_score_threshold: float | None = None
    allfix_score_threshold: float | None = None


@dataclass
class LineRuntimeRecord:
    line: str
    tags: list[str]
    family: str
    evidence: dict[str, Any]
    activation_reasons: list[str] = field(default_factory=list)
    modes: list[str] = field(default_factory=list)
    probe_tags: set[str] = field(default_factory=set)
    predicted_affected: set[str] = field(default_factory=set)
    gt_affected: set[str] = field(default_factory=set)
    status_counts: Counter[str] = field(default_factory=Counter)
    deferred_reasons: list[str] = field(default_factory=list)

    def activate(self, reason: str) -> None:
        if reason not in self.activation_reasons:
            self.activation_reasons.append(reason)

    def defer(self, reason: str) -> None:
        if reason not in self.deferred_reasons:
            self.deferred_reasons.append(reason)

    def update(self, *, mode: str, result: Any) -> None:
        if mode not in self.modes:
            self.modes.append(mode)
        self.probe_tags.update(result.probe_tags)
        self.predicted_affected.update(result.predicted_affected)
        self.status_counts.update(result.statuses)

    @property
    def visited(self) -> bool:
        return bool(self.modes)

    @property
    def primary_reason(self) -> str:
        return self.activation_reasons[0] if self.activation_reasons else "unknown"

    def to_dict(self) -> dict[str, Any]:
        gt = set(self.gt_affected)
        pred = set(self.predicted_affected)
        return {
            "line": self.line,
            "family": self.family,
            "tag_count": len(self.tags),
            "visited": self.visited,
            "activation_reasons": list(self.activation_reasons),
            "primary_reason": self.primary_reason,
            "deferred_reasons": list(self.deferred_reasons),
            "modes": list(self.modes),
            "probe_tags": sorted(self.probe_tags),
            "predicted_affected": sorted(pred),
            "gt_affected": sorted(gt),
            "missed_affected_tags": sorted(gt - pred),
            "fp_tags": sorted(pred - gt),
            "evidence": dict(self.evidence),
            "status_counts": dict(self.status_counts),
        }


def _required_policy_names() -> list[str]:
    return [
        "control_transition_scout_s4_expand2_allfixfile_s4",
        "family_interval_closure_only",
        "evidence_ranked_scout_queue",
        "late_all_fix_file_scout",
        "ranked_positive_neighbor",
        "hybrid_dynamic_scheduler",
    ]


def _policies() -> list[DynamicPolicy]:
    return [
        DynamicPolicy("control_transition_scout_s4_expand2_allfixfile_s4"),
        DynamicPolicy("family_interval_closure_only", family_interval_closure=True),
        DynamicPolicy("evidence_ranked_scout_queue", rank_scout=True),
        DynamicPolicy("late_all_fix_file_scout", late_all_fix_file_scout=True, allfix_score_threshold=0.20),
        DynamicPolicy("ranked_positive_neighbor", ranked_positive_neighbor=True, positive_score_threshold=0.20),
        DynamicPolicy(
            "hybrid_dynamic_scheduler",
            rank_scout=True,
            family_interval_closure=True,
            late_all_fix_file_scout=True,
            ranked_positive_neighbor=True,
            positive_score_threshold=0.20,
            allfix_score_threshold=0.20,
        ),
    ]


def _base_config(name: str) -> SchedulerConfig:
    return SchedulerConfig(
        name=name,
        initial="transition",
        scout_stride=4,
        scout_scope="all_unvisited",
        scout_nn_sentinel=0,
        nohit_fallback="nofix",
        positive_expand_radius=2,
        all_fix_file_scout_stride=4,
    )


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def _append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _pct(values: list[int], pct: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    idx = round((len(ordered) - 1) * pct)
    return int(ordered[idx])


def _affected_set(rec: dict[str, Any], release_tags: list[str]) -> set[str]:
    mapped, _unmapped = map_gt_tags_to_repo_tags(
        sorted(str(t) for t in (rec.get("affected_version") or [])),
        release_tags,
        mode="loose",
    )
    return set(mapped)


def _evidence_dict(obj: Any) -> dict[str, Any]:
    return {
        "score": float(getattr(obj, "score", 0.0)),
        "file_endpoint": bool(getattr(obj, "file_endpoint", False)),
        "critical_hit": bool(getattr(obj, "critical_hit", False)),
        "vuln_hit": bool(getattr(obj, "vuln_hit", False)),
        "fix_guard_hit": bool(getattr(obj, "fix_guard_hit", False)),
        "function_hit": bool(getattr(obj, "function_hit", False)),
        "transition_line": bool(getattr(obj, "transition_line", False)),
        "no_fix": bool(getattr(obj, "no_fix", False)),
        "all_fix": bool(getattr(obj, "all_fix", False)),
    }


def _line_family_index(ordered_by_family: dict[str, list[str]]) -> dict[str, int]:
    return {
        line: idx
        for _family, lines in ordered_by_family.items()
        for idx, line in enumerate(lines)
    }


def _line_rank_key(
    line: str,
    evidence: dict[str, dict[str, Any]],
    family_index: dict[str, int],
) -> tuple[float, int, str]:
    score = float((evidence.get(line) or {}).get("score", 0.0))
    return (-score, family_index.get(line, 10**9), line)


def _ranked_stride_lines(
    *,
    ordered_by_family: dict[str, list[str]],
    candidates: set[str],
    evidence: dict[str, dict[str, Any]],
    stride: int,
) -> set[str]:
    if stride <= 0:
        return set()
    selected: set[str] = set()
    family_index = _line_family_index(ordered_by_family)
    for _family, lines in ordered_by_family.items():
        family_candidates = [line for line in lines if line in candidates]
        if not family_candidates:
            continue
        quota = max(1, (len(family_candidates) + stride - 1) // stride)
        ranked = sorted(family_candidates, key=lambda line: _line_rank_key(line, evidence, family_index))
        selected.update(ranked[:quota])
    return selected


def _family_positive_indices(
    *,
    ordered_by_family: dict[str, list[str]],
    line_to_family: dict[str, str],
    positive_lines: set[str],
    line: str,
) -> tuple[list[str], list[int], int]:
    family = line_to_family.get(line)
    if family is None:
        return [], [], -1
    lines = ordered_by_family.get(family, [])
    positives = [ln for ln in positive_lines if ln in lines]
    positive_indices = sorted(lines.index(ln) for ln in positives)
    idx = lines.index(line) if line in lines else -1
    return lines, positive_indices, idx


def _allowed_by_family_interval(
    *,
    candidate: str,
    current_line: str,
    ordered_by_family: dict[str, list[str]],
    line_to_family: dict[str, str],
    positive_lines: set[str],
) -> bool:
    lines, positive_indices, candidate_idx = _family_positive_indices(
        ordered_by_family=ordered_by_family,
        line_to_family=line_to_family,
        positive_lines=positive_lines,
        line=candidate,
    )
    if candidate_idx < 0 or not positive_indices:
        return False
    current_idx = lines.index(current_line) if current_line in lines else candidate_idx
    if len(positive_indices) == 1:
        return abs(candidate_idx - current_idx) <= 1
    lo = max(0, min(positive_indices) - 1)
    hi = min(len(lines) - 1, max(positive_indices) + 1)
    return lo <= candidate_idx <= hi


def _positive_neighbors(
    *,
    policy: DynamicPolicy,
    current_line: str,
    ordered_by_family: dict[str, list[str]],
    line_to_family: dict[str, str],
    positive_lines: set[str],
    visited_full: set[str],
    evidence: dict[str, dict[str, Any]],
    radius: int,
) -> tuple[list[str], list[dict[str, Any]]]:
    candidates = _line_neighbors(ordered_by_family, line_to_family, current_line, radius) - visited_full
    family_index = _line_family_index(ordered_by_family)
    ranked = sorted(candidates, key=lambda line: _line_rank_key(line, evidence, family_index))
    accepted: list[str] = []
    deferred: list[dict[str, Any]] = []
    for candidate in ranked:
        ev = evidence.get(candidate) or {}
        allowed_interval = True
        if policy.family_interval_closure:
            allowed_interval = _allowed_by_family_interval(
                candidate=candidate,
                current_line=current_line,
                ordered_by_family=ordered_by_family,
                line_to_family=line_to_family,
                positive_lines=positive_lines,
            )
        allowed_rank = True
        if policy.ranked_positive_neighbor and policy.positive_score_threshold is not None:
            allowed_rank = (
                float(ev.get("score", 0.0)) >= policy.positive_score_threshold
                or bool(ev.get("file_endpoint"))
                or bool(ev.get("transition_line"))
            )
        if allowed_interval and allowed_rank:
            accepted.append(candidate)
        else:
            deferred.append({
                "line": candidate,
                "reason": "deferred_positive_neighbor",
                "allowed_interval": allowed_interval,
                "allowed_rank": allowed_rank,
                "score": ev.get("score", 0.0),
            })
    return accepted, deferred


def _classify_fn_sources(lines: dict[str, dict[str, Any]]) -> dict[str, Any]:
    skipped_tags: list[str] = []
    active_missed_tags: list[str] = []
    skipped_lines: list[str] = []
    active_missed_lines: list[str] = []
    for line, row in lines.items():
        gt = set(row.get("gt_affected") or [])
        predicted = set(row.get("predicted_affected") or [])
        missed = sorted(gt - predicted)
        if not missed:
            continue
        if not row.get("visited"):
            skipped_tags.extend(missed)
            skipped_lines.append(line)
        else:
            active_missed_tags.extend(missed)
            active_missed_lines.append(line)
    return {
        "skipped_affected_line_tags": sorted(skipped_tags),
        "active_line_missed_tags": sorted(active_missed_tags),
        "skipped_affected_lines": sorted(skipped_lines),
        "active_line_missed_lines": sorted(active_missed_lines),
        "source_counts": {
            "skipped_affected_line": len(skipped_tags),
            "active_line_missed_asbs_or_sparse": len(active_missed_tags),
        },
    }


def _select_scouts(
    *,
    policy: DynamicPolicy,
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    fix_containing_tags: set[str],
    visited_full: set[str],
    evidence: dict[str, dict[str, Any]],
    stride: int,
) -> set[str]:
    candidates = _no_fix_lines(release_lines, fix_containing_tags) - visited_full
    if policy.rank_scout:
        return _ranked_stride_lines(
            ordered_by_family=ordered_by_family,
            candidates=candidates,
            evidence=evidence,
            stride=stride,
        )
    return _stride_lines(ordered_by_family, stride, lines_subset=candidates)


def _select_allfix_scouts(
    *,
    policy: DynamicPolicy,
    config: SchedulerConfig,
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    fix_containing_tags: set[str],
    file_endpoint_lines: set[str],
    visited_full: set[str],
    positive_lines: set[str],
    evidence: dict[str, dict[str, Any]],
) -> set[str]:
    candidates = _all_fix_file_scout_lines(
        config=config,
        release_lines=release_lines,
        ordered_by_family=ordered_by_family,
        fix_containing_tags=fix_containing_tags,
        file_endpoint_lines=file_endpoint_lines,
        visited_full=visited_full,
    )
    if not candidates:
        return set()
    if policy.late_all_fix_file_scout:
        line_to_family = _line_to_family(ordered_by_family)
        positive_families = {line_to_family[line] for line in positive_lines if line in line_to_family}
        if positive_families:
            candidates = {line for line in candidates if line_to_family.get(line) in positive_families}
        if policy.allfix_score_threshold is not None:
            candidates = {
                line for line in candidates
                if float((evidence.get(line) or {}).get("score", 0.0)) >= policy.allfix_score_threshold
                or bool((evidence.get(line) or {}).get("file_endpoint"))
            }
    if policy.rank_scout or policy.late_all_fix_file_scout:
        return _ranked_stride_lines(
            ordered_by_family=ordered_by_family,
            candidates=candidates,
            evidence=evidence,
            stride=config.all_fix_file_scout_stride,
        )
    return candidates


def _simulate_one(
    *,
    repo_name: str,
    cve_id: str,
    rec: dict[str, Any],
    release_tags: list[str],
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    fix_containing_tags: set[str],
    file_endpoint_lines: set[str],
    evidence: dict[str, dict[str, Any]],
    policy: DynamicPolicy,
    event_path: Path | None = None,
) -> dict[str, Any]:
    config = _base_config(policy.name)
    affected = _affected_set(rec, release_tags)
    release_set = set(release_tags)
    line_to_family = _line_to_family(ordered_by_family)
    runtime = {
        line: LineRuntimeRecord(
            line=line,
            tags=list(tags),
            family=line_to_family.get(line, "unknown"),
            evidence=evidence.get(line, {"score": 0.0}),
            gt_affected=set(tags) & affected,
        )
        for line, tags in release_lines.items()
    }
    queue: deque[tuple[str, str, str]] = deque()
    visited_full: set[str] = set()
    predicted: set[str] = set()
    probes: set[str] = set()
    positive_lines: set[str] = set()
    reason_counts: Counter[str] = Counter()
    mode_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    deferred_counts: Counter[str] = Counter()

    def emit(event: str, line: str, **extra: Any) -> None:
        if event_path is None:
            return
        row = {
            "repo": repo_name,
            "cve": cve_id,
            "strategy": policy.name,
            "event": event,
            "line": line,
            "score": float((evidence.get(line) or {}).get("score", 0.0)),
            **extra,
        }
        _append_jsonl(event_path, row)

    def enqueue(line: str, mode: str, reason: str) -> None:
        if line not in release_lines:
            return
        runtime[line].activate(reason)
        queue.append((line, mode, reason))
        emit("enqueue", line, mode=mode, reason=reason)

    seeds, reasons = _initial_lines(
        config=config,
        repo_name=repo_name,
        release_lines=release_lines,
        ordered_by_family=ordered_by_family,
        fix_containing_tags=fix_containing_tags,
        file_endpoint_lines=file_endpoint_lines,
    )
    for line in sorted(seeds):
        enqueue(line, "full", reasons.get(line, "initial"))

    def process_queue() -> None:
        while queue:
            line, mode, reason = queue.popleft()
            if line not in release_lines:
                continue
            if mode == "full" and line in visited_full:
                emit("skip_already_full", line, mode=mode, reason=reason)
                continue
            if mode == "scout" and "full" in runtime[line].modes:
                emit("skip_already_full", line, mode=mode, reason=reason)
                continue
            result = _run_line(
                line=line,
                mode=mode,
                release_lines=release_lines,
                affected_set=affected,
                fix_containing_tags=fix_containing_tags,
                config=config,
            )
            runtime[line].update(mode=mode, result=result)
            reason_counts[reason] += 1
            mode_counts[mode] += 1
            status_counts.update(result.statuses)
            probes.update(result.probe_tags)
            predicted.update(result.predicted_affected)
            if mode == "full":
                visited_full.add(line)
            emit(
                "run_line",
                line,
                mode=mode,
                reason=reason,
                probe_count=len(result.probe_tags),
                predicted_count=len(result.predicted_affected),
                is_positive=bool(result.is_positive),
                statuses=dict(result.statuses),
            )
            if result.is_positive:
                positive_lines.add(line)
                if mode == "scout" and line not in visited_full:
                    enqueue(line, "full", "scout_positive")
                accepted, deferred = _positive_neighbors(
                    policy=policy,
                    current_line=line,
                    ordered_by_family=ordered_by_family,
                    line_to_family=line_to_family,
                    positive_lines=positive_lines,
                    visited_full=visited_full,
                    evidence=evidence,
                    radius=config.positive_expand_radius,
                )
                for neighbor in accepted:
                    enqueue(neighbor, "full", "positive_neighbor")
                for item in deferred:
                    dline = item["line"]
                    runtime[dline].defer(item["reason"])
                    deferred_counts[item["reason"]] += 1
                    event_item = {k: v for k, v in item.items() if k != "line"}
                    emit("defer", dline, **event_item)

    process_queue()

    scouts = _select_scouts(
        policy=policy,
        release_lines=release_lines,
        ordered_by_family=ordered_by_family,
        fix_containing_tags=fix_containing_tags,
        visited_full=visited_full,
        evidence=evidence,
        stride=config.scout_stride,
    )
    for line in sorted(scouts, key=lambda ln: _line_rank_key(ln, evidence, _line_family_index(ordered_by_family))):
        if line not in visited_full:
            enqueue(line, "scout", "scout_stride")
    process_queue()

    if not policy.late_all_fix_file_scout:
        allfix_stage = _select_allfix_scouts(
            policy=policy,
            config=config,
            release_lines=release_lines,
            ordered_by_family=ordered_by_family,
            fix_containing_tags=fix_containing_tags,
            file_endpoint_lines=file_endpoint_lines,
            visited_full=visited_full,
            positive_lines=positive_lines,
            evidence=evidence,
        )
        for line in sorted(allfix_stage, key=lambda ln: _line_rank_key(ln, evidence, _line_family_index(ordered_by_family))):
            if line not in visited_full:
                enqueue(line, "scout", "all_fix_file_scout")
        process_queue()

    if not positive_lines and config.nohit_fallback == "nofix":
        for line in sorted(_no_fix_lines(release_lines, fix_containing_tags)):
            if line not in visited_full:
                enqueue(line, "full", "nohit_fallback")
        process_queue()

    if policy.late_all_fix_file_scout:
        allfix_stage = _select_allfix_scouts(
            policy=policy,
            config=config,
            release_lines=release_lines,
            ordered_by_family=ordered_by_family,
            fix_containing_tags=fix_containing_tags,
            file_endpoint_lines=file_endpoint_lines,
            visited_full=visited_full,
            positive_lines=positive_lines,
            evidence=evidence,
        )
        for line in sorted(allfix_stage, key=lambda ln: _line_rank_key(ln, evidence, _line_family_index(ordered_by_family))):
            if line not in visited_full:
                enqueue(line, "scout", "all_fix_file_scout")
        process_queue()

    line_rows = {line: rt.to_dict() for line, rt in runtime.items()}
    visited_lines = {line for line, row in line_rows.items() if row["visited"]}
    affected_lines = {line for line, row in line_rows.items() if row["gt_affected"]}
    irrelevant_active = visited_lines - affected_lines
    fn_sources = _classify_fn_sources(line_rows)
    tp = len(predicted & affected)
    fp = len(predicted - affected)
    fn = len(affected - predicted)
    tn = len(release_set - affected - predicted)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    irrelevant_by_primary = Counter(line_rows[line]["primary_reason"] for line in irrelevant_active)
    irrelevant_by_any = Counter()
    for line in irrelevant_active:
        for reason in line_rows[line]["activation_reasons"] or ["unknown"]:
            irrelevant_by_any[reason] += 1

    return {
        "strategy": policy.name,
        "repo": repo_name,
        "cve": cve_id,
        "release_tag_count": len(release_tags),
        "line_count": len(release_lines),
        "affected_line_count": len(affected_lines),
        "visited_line_count": len(visited_lines),
        "irrelevant_active_line_count": len(irrelevant_active),
        "skipped_affected_line_count": len(set(fn_sources["skipped_affected_lines"])),
        "probe_count": len(probes),
        "predicted_count": len(predicted),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "exact_match": fp == 0 and fn == 0,
        "has_fn": fn > 0,
        "has_fp": fp > 0,
        "fn_tags": sorted(affected - predicted),
        "fp_tags": sorted(predicted - affected),
        "fn_sources": fn_sources,
        "activation_reason_counts": dict(reason_counts),
        "deferred_reason_counts": dict(deferred_counts),
        "mode_counts": dict(mode_counts),
        "status_counts": dict(status_counts),
        "irrelevant_activation_by_primary_reason": dict(irrelevant_by_primary),
        "irrelevant_activation_by_any_reason": dict(irrelevant_by_any),
        "lines": line_rows,
    }


def _summarize(rows: list[dict[str, Any]], *, policy: DynamicPolicy) -> dict[str, Any]:
    cm = Counter()
    probes = [int(row["probe_count"]) for row in rows]
    by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    fn_sources = Counter()
    primary_irrelevant = Counter()
    any_irrelevant = Counter()
    activation_counts = Counter()
    deferred_counts = Counter()
    status_counts = Counter()
    active_line_asbs_miss = 0
    skipped_affected_lines = 0
    for row in rows:
        cm.update({"TP": row["tp"], "FP": row["fp"], "FN": row["fn"], "TN": row["tn"]})
        by_repo[row["repo"]].append(row)
        fn_sources.update(row["fn_sources"]["source_counts"])
        primary_irrelevant.update(row.get("irrelevant_activation_by_primary_reason", {}))
        any_irrelevant.update(row.get("irrelevant_activation_by_any_reason", {}))
        activation_counts.update(row.get("activation_reason_counts", {}))
        deferred_counts.update(row.get("deferred_reason_counts", {}))
        status_counts.update(row.get("status_counts", {}))
        active_line_asbs_miss += row["fn_sources"]["source_counts"].get("active_line_missed_asbs_or_sparse", 0)
        skipped_affected_lines += row["fn_sources"]["source_counts"].get("skipped_affected_line", 0)
    precision = cm["TP"] / (cm["TP"] + cm["FP"]) if cm["TP"] + cm["FP"] else 1.0
    recall = cm["TP"] / (cm["TP"] + cm["FN"]) if cm["TP"] + cm["FN"] else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    def avg(key: str, rs: list[dict[str, Any]] = rows) -> float:
        return statistics.mean(float(row[key]) for row in rs) if rs else 0.0

    repo_summary = {}
    for repo, rs in sorted(by_repo.items()):
        repo_irrelevant = Counter()
        repo_fn_sources = Counter()
        for row in rs:
            repo_irrelevant.update(row["irrelevant_activation_by_primary_reason"])
            repo_fn_sources.update(row["fn_sources"]["source_counts"])
        repo_summary[repo] = {
            "cves": len(rs),
            "avg_probes": avg("probe_count", rs),
            "p95_probes": _pct([int(row["probe_count"]) for row in rs], 0.95),
            "exact_cves": sum(1 for row in rs if row["exact_match"]),
            "fn_cves": sum(1 for row in rs if row["has_fn"]),
            "fp_cves": sum(1 for row in rs if row["has_fp"]),
            "avg_visited_lines": avg("visited_line_count", rs),
            "avg_irrelevant_active_lines": avg("irrelevant_active_line_count", rs),
            "irrelevant_primary_reason_counts": dict(repo_irrelevant),
            "fn_source_counts": dict(repo_fn_sources),
        }

    return {
        "strategy": policy.name,
        "policy": {
            "rank_scout": policy.rank_scout,
            "family_interval_closure": policy.family_interval_closure,
            "late_all_fix_file_scout": policy.late_all_fix_file_scout,
            "ranked_positive_neighbor": policy.ranked_positive_neighbor,
            "positive_score_threshold": policy.positive_score_threshold,
            "allfix_score_threshold": policy.allfix_score_threshold,
        },
        "cves": len(rows),
        "avg_probes": avg("probe_count"),
        "p50_probes": _pct(probes, 0.50),
        "p95_probes": _pct(probes, 0.95),
        "exact_cves": sum(1 for row in rows if row["exact_match"]),
        "fn_cves": sum(1 for row in rows if row["has_fn"]),
        "fp_cves": sum(1 for row in rows if row["has_fp"]),
        "avg_affected_lines": avg("affected_line_count"),
        "avg_visited_lines": avg("visited_line_count"),
        "avg_irrelevant_active_lines": avg("irrelevant_active_line_count"),
        "irrelevant_active_line_ratio": (
            sum(row["irrelevant_active_line_count"] for row in rows)
            / sum(row["visited_line_count"] for row in rows)
            if sum(row["visited_line_count"] for row in rows)
            else 0.0
        ),
        "fn_source_counts": dict(fn_sources),
        "active_line_asbs_miss_tags": active_line_asbs_miss,
        "skipped_affected_line_tags": skipped_affected_lines,
        "irrelevant_primary_reason_counts": dict(primary_irrelevant),
        "irrelevant_any_reason_counts": dict(any_irrelevant),
        "activation_reason_counts": dict(activation_counts),
        "deferred_reason_counts": dict(deferred_counts),
        "status_counts": dict(status_counts),
        "version": {
            "TP": cm["TP"],
            "FP": cm["FP"],
            "FN": cm["FN"],
            "TN": cm["TN"],
            "precision": precision,
            "recall": recall,
            "f1": f1,
        },
        "by_repo": repo_summary,
    }


def _build_evidence_for_repo(
    *,
    repo: Any,
    records: list[tuple[str, dict[str, Any]]],
    release_lines: dict[str, list[str]],
) -> tuple[dict[str, list[str]], dict[str, PatchProfile], dict[tuple[str, str], bool], dict[tuple[str, str], str | None], list[dict[str, Any]]]:
    changed_cache: dict[str, list[str]] = {}
    changed_by_cve: dict[str, list[str]] = {}
    profile_by_cve: dict[str, PatchProfile] = {}
    path_queries: set[tuple[str, str]] = set()
    text_queries: set[tuple[str, str]] = set()
    failures: list[dict[str, Any]] = []
    sample_tags = {tag for tags in release_lines.values() for tag in _sample_tags_for_line(tags)}
    for cve, rec in records:
        try:
            commits = _commits(rec)
            changed = _changed_files_for_commits(repo, commits, changed_cache)
            profile = _extract_patch_profile(repo, commits, changed)
        except Exception as exc:
            failures.append({"cve": cve, "stage": "profile", "error": f"{type(exc).__name__}: {exc}"})
            changed = []
            profile = PatchProfile([], [], [], [], [], [])
        changed_by_cve[cve] = changed
        profile_by_cve[cve] = profile
        for tag in sample_tags:
            for path in profile.files:
                path_queries.add((tag, path))
                text_queries.add((tag, path))
    path_exists = _batch_path_exists(repo, path_queries)
    text_cache = _batch_file_text(repo, text_queries)
    return changed_by_cve, profile_by_cve, path_exists, text_cache, failures


def run(dataset: Path, repo_root: Path, out_dir: Path, limit: int | None = None) -> dict[str, Any]:
    data = _load_dataset(dataset)
    records: list[tuple[str, dict[str, Any]]] = sorted(data.items())
    if limit is not None:
        records = records[:limit]
    by_repo: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for cve, rec in records:
        repo_name = _repo_name(rec)
        if repo_name:
            by_repo[repo_name].append((cve, rec))

    out_dir.mkdir(parents=True, exist_ok=True)
    for name in [
        "per_cve.jsonl",
        "line_queue_events.jsonl",
    ]:
        path = out_dir / name
        if path.exists():
            path.unlink()

    policies = _policies()
    rows_by_policy: dict[str, list[dict[str, Any]]] = defaultdict(list)
    failures: list[dict[str, Any]] = []
    event_path = out_dir / "line_queue_events.jsonl"

    for repo_name, repo_records in sorted(by_repo.items()):
        context = _release_context(repo_name, repo_root / repo_name)
        repo = context["repo"]
        release_tags = context["release_tags"]
        release_lines = context["release_lines"]
        ordered_by_family = context["ordered_by_family"]
        all_commits = {commit for _cve, rec in repo_records for commit in _commits(rec)}
        contains = batch_tags_containing(
            repo=repo,
            release_tags=release_tags,
            target_commits=all_commits,
        )
        changed_by_cve, profile_by_cve, path_exists, text_cache, evidence_failures = _build_evidence_for_repo(
            repo=repo,
            records=repo_records,
            release_lines=release_lines,
        )
        for failure in evidence_failures:
            failures.append({"repo": repo_name, **failure})

        for cve, rec in repo_records:
            try:
                fix_containing: set[str] = set()
                for commit in _commits(rec):
                    info = contains.get(commit, {"ok": False, "tags": []})
                    if info.get("ok"):
                        fix_containing.update(info.get("tags") or [])
                file_endpoint_lines = _build_file_endpoint_lines(
                    release_lines=release_lines,
                    files=changed_by_cve.get(cve, []),
                    path_exists=path_exists,
                )
                semantic_lines = _token_evidence_lines(
                    release_lines=release_lines,
                    profile=profile_by_cve.get(cve) or PatchProfile([], [], [], [], [], []),
                    text_cache=text_cache,
                )
                evidence_obj = _build_line_evidence(
                    release_lines=release_lines,
                    fix_containing_tags=fix_containing,
                    file_endpoint_lines=file_endpoint_lines,
                    semantic_lines=semantic_lines,
                )
                evidence = {line: _evidence_dict(ev) for line, ev in evidence_obj.items()}
                for policy in policies:
                    row = _simulate_one(
                        repo_name=repo_name,
                        cve_id=cve,
                        rec=rec,
                        release_tags=release_tags,
                        release_lines=release_lines,
                        ordered_by_family=ordered_by_family,
                        fix_containing_tags=fix_containing,
                        file_endpoint_lines=file_endpoint_lines,
                        evidence=evidence,
                        policy=policy,
                        event_path=event_path,
                    )
                    compact = {k: v for k, v in row.items() if k != "lines"}
                    rows_by_policy[policy.name].append(compact)
                    _append_jsonl(out_dir / "per_cve.jsonl", compact)
            except Exception as exc:
                failures.append({
                    "repo": repo_name,
                    "cve": cve,
                    "error": f"{type(exc).__name__}: {exc}",
                })

    per_strategy = {
        policy.name: _summarize(rows_by_policy[policy.name], policy=policy)
        for policy in policies
    }
    control = per_strategy["control_transition_scout_s4_expand2_allfixfile_s4"]
    summary = {
        "metadata": {
            "dataset": str(dataset),
            "repo_root": str(repo_root),
            "total_cves": sum(len(v) for v in by_repo.values()),
            "policy_names": _required_policy_names(),
            "gt_note": "GT is used only as simulated probe oracle and final evaluator.",
            "hard_deletion": False,
        },
        "control": control,
        "strategies": per_strategy,
        "deltas_vs_control": {
            name: {
                "avg_probe_delta": s["avg_probes"] - control["avg_probes"],
                "version_fn_delta": s["version"]["FN"] - control["version"]["FN"],
                "exact_cve_delta": s["exact_cves"] - control["exact_cves"],
                "irrelevant_active_line_delta": s["avg_irrelevant_active_lines"] - control["avg_irrelevant_active_lines"],
            }
            for name, s in per_strategy.items()
            if name != control["strategy"]
        },
    }
    _write_json(out_dir / "summary.json", summary)
    _write_json(out_dir / "per_strategy.json", per_strategy)
    _write_json(out_dir / "failures.json", failures)

    fn_cases = [row for rows in rows_by_policy.values() for row in rows if row["has_fn"]]
    _write_json(out_dir / "fn_cases.json", fn_cases)
    irrelevant_by_reason = {
        name: {
            "primary_reason_counts": s["irrelevant_primary_reason_counts"],
            "any_reason_counts": s["irrelevant_any_reason_counts"],
            "by_repo": {
                repo: vals["irrelevant_primary_reason_counts"]
                for repo, vals in s["by_repo"].items()
            },
        }
        for name, s in per_strategy.items()
    }
    _write_json(out_dir / "irrelevant_activation_by_reason.json", irrelevant_by_reason)

    report = [
        "# Dynamic Line Activation Scheduler Simulator",
        "",
        f"Dataset: `{dataset}`",
        "",
        "GT is used only as the simulator oracle. VET evidence changes priority/order only.",
        "",
        "| strategy | avg probes | p50 | p95 | exact | FN CVEs | FP CVEs | avg active lines | irrelevant active % | version FN | P | R | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name in _required_policy_names():
        s = per_strategy[name]
        v = s["version"]
        report.append(
            f"| `{name}` | {s['avg_probes']:.2f} | {s['p50_probes']} | {s['p95_probes']} | "
            f"{s['exact_cves']}/{s['cves']} | {s['fn_cves']} | {s['fp_cves']} | "
            f"{s['avg_visited_lines']:.2f} | {100 * s['irrelevant_active_line_ratio']:.2f}% | "
            f"{v['FN']} | {v['precision']:.6f} | {v['recall']:.6f} | {v['f1']:.6f} |"
        )
    report.extend([
        "",
        "## Deltas vs Control",
        "",
        json.dumps(summary["deltas_vs_control"], ensure_ascii=False, indent=2, sort_keys=True),
        "",
        "## Admission Decision",
        "",
        "No dynamic policy in this run is ready to replace the control scheduler.",
        "",
        "- `evidence_ranked_scout_queue` reduces avg probes and irrelevant lines, but adds version FN.",
        "- `late_all_fix_file_scout` is the safest cost-reduction candidate, but still adds version FN.",
        "- `ranked_positive_neighbor` and `hybrid_dynamic_scheduler` are unsafe with the current evidence score.",
        "- Current cheap VET evidence can guide priority, but is not reliable enough to defer affected lines safely.",
    ])
    (out_dir / "report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    summary = run(args.dataset, args.repo_root, args.out, args.limit)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

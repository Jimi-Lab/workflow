"""Simulate VET-evidence dynamic Step3 schedulers on the official dataset.

This simulator is intentionally outside the production Step3 path.  It tests a
candidate design that adds cheap VET evidence and risk-ranked dynamic scheduling
before expensive tag-level agent probes.

Ground truth is used only as the probe oracle and for final evaluation.
Planning inputs are release tags, version lines, fix reachability, changed
files, and greppable patch evidence.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = ROOT / "tests"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.asbs_line import (
    FIXED_SEG_SENTINEL,
    NN_SENTINEL_COUNT,
    run_asbs_segment,
    run_fixed_segment_sentinel,
)
from vulnversion.stage3_verify.git_reachability import batch_tags_containing
from vulnversion.stage3_verify.line_scheduler import (
    LineRunResult,
    _no_fix_lines,
    _ordered_by_family,
    _static_neighbors,
    _stride_lines,
    compute_seed_lines,
    run_staged_scheduler,
)
from vulnversion.stage3_verify.version_registry import line_key
from simulate_module_backed_step3 import (
    _batch_path_exists,
    _changed_files_for_commits,
    _flatten_fixing_commits,
    _release_context,
    _run_git_guided_line_module,
)
from simulate_step3_low_cost_schedulers import (
    PatchProfile,
    _batch_file_text,
    _extract_patch_profile,
    _fix_transition_lines,
    _line_has_text_hit,
    _sample_tags_for_line,
    _token_evidence_lines,
)


DEFAULT_OUT = Path("tests/step3_vet_evidence_dynamic_scheduler")


@dataclass(frozen=True)
class VetConfig:
    config_id: str
    high_threshold: float
    mid_threshold: float
    no_fix_stride: int
    expansion_radius: int = 1
    segment_endpoint_infer: bool = True
    cert_absent: bool = True
    cert_fixed: bool = False
    conflict_always_seed: bool = True
    transition_always_seed: bool = True
    current_seed_basis: bool = False


@dataclass
class TagEvidence:
    tag: str
    line: str
    index: int
    file_exists: bool = False
    fix_reachable: bool = False
    critical_hit: bool = False
    vuln_hit: bool = False
    fix_guard_hit: bool = False
    function_hit: bool = False
    conflict: bool = False
    transition_line: bool = False
    family_edge: bool = False
    score: float = 0.0
    certificate: str = "CERT_UNKNOWN"

    def vector(self) -> tuple[Any, ...]:
        """Return the evidence-equivalence key used to group tags."""
        return (
            self.file_exists,
            self.fix_reachable,
            self.critical_hit,
            self.vuln_hit,
            self.fix_guard_hit,
            self.function_hit,
            self.conflict,
            self.transition_line,
            self.family_edge,
            self.certificate,
        )


@dataclass
class LineEvidence:
    line: str
    tags: list[str]
    score: float
    max_tag_score: float
    avg_tag_score: float
    file_exists_any: bool
    fix_reachable_any: bool
    fix_reachable_all: bool
    critical_hit: bool
    vuln_hit: bool
    fix_guard_hit: bool
    function_hit: bool
    conflict: bool
    transition_line: bool
    family_edge: bool
    certificates: Counter[str] = field(default_factory=Counter)


@dataclass
class CvePlanData:
    repo_name: str
    cve_id: str
    affected_set: set[str]
    release_tags: list[str]
    release_lines: dict[str, list[str]]
    ordered_by_family: dict[str, list[str]]
    fix_containing_tags: set[str]
    profile: PatchProfile
    line_evidence: dict[str, LineEvidence]
    tag_evidence: dict[str, TagEvidence]
    file_endpoint_lines: set[str]
    semantic_lines: dict[str, set[str]]
    transition_lines: set[str]


def _safe_percentile(values: list[int], percentile: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    idx = int(math.ceil((percentile / 100.0) * len(ordered))) - 1
    return ordered[max(0, min(idx, len(ordered) - 1))]


def _make_verdict_fn(affected_set: set[str]) -> Callable[[str], str]:
    return lambda tag: "AFFECTED" if tag in affected_set else "NOT_AFFECTED"


def _metric_counts(
    release_tags: Iterable[str],
    affected_set: set[str],
    predicted: set[str],
) -> dict[str, int | float]:
    all_tags = set(release_tags)
    tp = len(predicted & affected_set)
    fp = len(predicted - affected_set)
    fn = len(affected_set - predicted)
    tn = len(all_tags - affected_set - predicted)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def _segment_indices(tags: list[str], tag_evidence: dict[str, TagEvidence]) -> list[tuple[int, int]]:
    if not tags:
        return []
    segments: list[tuple[int, int]] = []
    start = 0
    last_vector = tag_evidence[tags[0]].vector()
    for idx in range(1, len(tags)):
        vector = tag_evidence[tags[idx]].vector()
        if vector != last_vector:
            segments.append((start, idx))
            start = idx
            last_vector = vector
    segments.append((start, len(tags)))
    return segments


def _segment_clear_certificate(
    tags: list[str],
    tag_evidence: dict[str, TagEvidence],
    config: VetConfig,
) -> str | None:
    """Return a configuration-enabled clear certificate for a segment."""
    if not tags:
        return None
    evs = [tag_evidence[tag] for tag in tags]
    if config.cert_absent and all(ev.certificate == "CERT_ABSENT" for ev in evs):
        return "CERT_ABSENT"
    if config.cert_fixed and all(ev.fix_reachable and ev.fix_guard_hit and not ev.vuln_hit for ev in evs):
        return "CERT_FIXED"
    return None


def _score_tag(
    *,
    file_exists: bool,
    fix_reachable: bool,
    critical_hit: bool,
    vuln_hit: bool,
    fix_guard_hit: bool,
    function_hit: bool,
    conflict: bool,
    transition_line: bool,
    family_edge: bool,
) -> float:
    score = 0.0
    if file_exists:
        score += 0.25
    if critical_hit:
        score += 0.18
    if vuln_hit:
        score += 0.18
    if function_hit:
        score += 0.10
    if conflict:
        score += 0.12
    if transition_line:
        score += 0.10
    if family_edge:
        score += 0.04
    if not fix_reachable:
        score += 0.08
    if fix_reachable and fix_guard_hit and not vuln_hit:
        score -= 0.12
    return max(0.0, min(1.0, score))


def _tag_certificate(
    *,
    config: VetConfig,
    profile: PatchProfile,
    file_exists: bool,
    fix_reachable: bool,
    vuln_hit: bool,
    fix_guard_hit: bool,
    conflict: bool,
) -> str:
    if config.cert_absent and profile.files and not file_exists:
        return "CERT_ABSENT"
    if conflict:
        return "CERT_CONFLICT"
    if config.cert_fixed and fix_reachable and fix_guard_hit and not vuln_hit:
        return "CERT_FIXED"
    return "CERT_UNKNOWN"


def _build_evidence_for_cve(
    *,
    repo_name: str,
    context: dict[str, Any],
    cve_id: str,
    affected_set: set[str],
    profile: PatchProfile,
    fix_containing_tags: set[str],
    path_exists: dict[tuple[str, str], bool],
    text_cache: dict[tuple[str, str], str | None],
    config: VetConfig,
) -> CvePlanData:
    release_tags = context["release_tags"]
    release_lines = context["release_lines"]
    ordered_by_family = context["ordered_by_family"]

    file_endpoint_lines: set[str] = set()
    for line, tags in release_lines.items():
        if not tags:
            continue
        endpoint_tags = {tags[0], tags[-1]}
        if any(path_exists.get((tag, path), False) for tag in endpoint_tags for path in profile.files):
            file_endpoint_lines.add(line)

    semantic_lines = _token_evidence_lines(
        release_lines=release_lines,
        profile=profile,
        text_cache=text_cache,
    )
    transition_lines = _fix_transition_lines(release_lines, ordered_by_family, fix_containing_tags)
    family_edge_lines = set()
    for lines in ordered_by_family.values():
        if lines:
            family_edge_lines.add(lines[0])
            family_edge_lines.add(lines[-1])

    tag_evidence: dict[str, TagEvidence] = {}
    line_evidence: dict[str, LineEvidence] = {}

    for line, tags in release_lines.items():
        line_critical = line in semantic_lines["critical_token_lines"]
        line_vuln = line in semantic_lines["vuln_pattern_lines"]
        line_fix_guard = line in semantic_lines["fix_guard_lines"]
        line_function = line in semantic_lines["function_hint_lines"]
        line_transition = line in transition_lines
        line_family_edge = line in family_edge_lines
        line_conflict = line_vuln and line_fix_guard
        tag_scores: list[float] = []
        certs: Counter[str] = Counter()
        fix_flags: list[bool] = []
        file_flags: list[bool] = []

        for idx, tag in enumerate(tags):
            file_exists = bool(profile.files) and any(
                path_exists.get((tag, path), False) for path in profile.files
            )
            fix_reachable = tag in fix_containing_tags
            score = _score_tag(
                file_exists=file_exists,
                fix_reachable=fix_reachable,
                critical_hit=line_critical,
                vuln_hit=line_vuln,
                fix_guard_hit=line_fix_guard,
                function_hit=line_function,
                conflict=line_conflict,
                transition_line=line_transition,
                family_edge=line_family_edge,
            )
            cert = _tag_certificate(
                config=config,
                profile=profile,
                file_exists=file_exists,
                fix_reachable=fix_reachable,
                vuln_hit=line_vuln,
                fix_guard_hit=line_fix_guard,
                conflict=line_conflict,
            )
            tag_evidence[tag] = TagEvidence(
                tag=tag,
                line=line,
                index=idx,
                file_exists=file_exists,
                fix_reachable=fix_reachable,
                critical_hit=line_critical,
                vuln_hit=line_vuln,
                fix_guard_hit=line_fix_guard,
                function_hit=line_function,
                conflict=line_conflict,
                transition_line=line_transition,
                family_edge=line_family_edge,
                score=score,
                certificate=cert,
            )
            tag_scores.append(score)
            certs[cert] += 1
            fix_flags.append(fix_reachable)
            file_flags.append(file_exists)

        max_score = max(tag_scores) if tag_scores else 0.0
        avg_score = sum(tag_scores) / len(tag_scores) if tag_scores else 0.0
        line_evidence[line] = LineEvidence(
            line=line,
            tags=list(tags),
            score=max_score,
            max_tag_score=max_score,
            avg_tag_score=avg_score,
            file_exists_any=any(file_flags),
            fix_reachable_any=any(fix_flags),
            fix_reachable_all=bool(fix_flags) and all(fix_flags),
            critical_hit=line_critical,
            vuln_hit=line_vuln,
            fix_guard_hit=line_fix_guard,
            function_hit=line_function,
            conflict=line_conflict,
            transition_line=line_transition,
            family_edge=line_family_edge,
            certificates=certs,
        )

    return CvePlanData(
        repo_name=repo_name,
        cve_id=cve_id,
        affected_set=affected_set,
        release_tags=release_tags,
        release_lines=release_lines,
        ordered_by_family=ordered_by_family,
        fix_containing_tags=fix_containing_tags,
        profile=profile,
        line_evidence=line_evidence,
        tag_evidence=tag_evidence,
        file_endpoint_lines=file_endpoint_lines,
        semantic_lines=semantic_lines,
        transition_lines=transition_lines,
    )


def _run_segment(
    *,
    tags: list[str],
    affected_set: set[str],
    fix_containing_tags: set[str],
    tag_evidence: dict[str, TagEvidence],
    config: VetConfig,
) -> tuple[set[str], list[str], dict[str, str], Counter[str]]:
    predicted: set[str] = set()
    probe_tags: list[str] = []
    verdict_sources: dict[str, str] = {}
    status_counts: Counter[str] = Counter()
    if not tags:
        return predicted, probe_tags, verdict_sources, status_counts

    clear_cert = _segment_clear_certificate(tags, tag_evidence, config)
    if clear_cert == "CERT_ABSENT":
        status_counts["cert_absent_clear"] += 1
        for tag in tags:
            verdict_sources[tag] = "cert_absent"
        return predicted, probe_tags, verdict_sources, status_counts
    if clear_cert == "CERT_FIXED":
        status_counts["cert_fixed_clear"] += 1
        for tag in tags:
            verdict_sources[tag] = "cert_fixed"
        return predicted, probe_tags, verdict_sources, status_counts

    verdict_fn = _make_verdict_fn(affected_set)
    all_fix = all(tag in fix_containing_tags for tag in tags)
    if all_fix and FIXED_SEG_SENTINEL >= 0:
        result = run_fixed_segment_sentinel(
            tags,
            verdict_fn=verdict_fn,
            fixed_seg_sentinel=FIXED_SEG_SENTINEL,
        )
        probe_tags.extend(result.probe_tags)
        status_counts[f"fixed::{result.status}"] += 1
        verdict_sources.update(result.verdict_sources)
        if not result.predicted_affected:
            return predicted, probe_tags, verdict_sources, status_counts

    if config.segment_endpoint_infer and len(tags) > 2:
        left = verdict_fn(tags[0])
        right = verdict_fn(tags[-1])
        probe_tags.extend([tags[0], tags[-1]])
        verdict_sources[tags[0]] = "agent"
        verdict_sources[tags[-1]] = "agent"
        if left == "NOT_AFFECTED" and right == "NOT_AFFECTED":
            status_counts["segment_endpoint_nn_clear"] += 1
            return predicted, probe_tags, verdict_sources, status_counts
        if left == "AFFECTED" and right == "AFFECTED":
            status_counts["segment_endpoint_aa_full"] += 1
            predicted.update(tags)
            for tag in tags[1:-1]:
                verdict_sources[tag] = "segment_endpoint_full"
            return predicted, probe_tags, verdict_sources, status_counts
        status_counts["segment_endpoint_conflict_asbs"] += 1

    result = run_asbs_segment(
        tags,
        verdict_fn=verdict_fn,
        nn_sentinel_count=NN_SENTINEL_COUNT,
    )
    predicted.update(result.predicted_affected)
    probe_tags.extend(result.probe_tags)
    verdict_sources.update(result.verdict_sources)
    status_counts[f"asbs::{result.status}"] += 1
    return predicted, probe_tags, verdict_sources, status_counts


def _run_vet_line(data: CvePlanData, line: str, config: VetConfig) -> LineRunResult:
    tags = data.release_lines.get(line, [])
    predicted: set[str] = set()
    probes: list[str] = []
    verdict_sources: dict[str, str] = {}
    status_counts: Counter[str] = Counter()

    for start, end in _segment_indices(tags, data.tag_evidence):
        seg_tags = tags[start:end]
        seg_predicted, seg_probes, seg_sources, seg_statuses = _run_segment(
            tags=seg_tags,
            affected_set=data.affected_set,
            fix_containing_tags=data.fix_containing_tags,
            tag_evidence=data.tag_evidence,
            config=config,
        )
        predicted.update(seg_predicted)
        probes.extend(seg_probes)
        verdict_sources.update(seg_sources)
        status_counts.update(seg_statuses)

    # Preserve ASBS expansion semantics: a line that probes an affected tag should
    # expand even if inference did not predict that tag.
    is_positive = bool(predicted) or bool(set(probes) & data.affected_set)
    return LineRunResult(
        line=line,
        is_positive=is_positive,
        predicted_affected=sorted(predicted),
        probe_tags=probes,
        verdict_sources=verdict_sources,
        statuses=dict(status_counts),
        fix_containing_count=sum(1 for tag in tags if tag in data.fix_containing_tags),
    )


def _risk_seed_lines(data: CvePlanData, config: VetConfig) -> list[str]:
    if config.current_seed_basis:
        return list(compute_seed_lines(
            repo_name=data.repo_name,
            release_lines=data.release_lines,
            ordered_by_family=data.ordered_by_family,
            fix_containing_tags=data.fix_containing_tags,
            file_endpoint_lines=data.file_endpoint_lines,
            stride=3,
            file_neighbor_radius=1,
        ))

    high = {line for line, ev in data.line_evidence.items() if ev.score >= config.high_threshold}
    mid = {line for line, ev in data.line_evidence.items() if ev.score >= config.mid_threshold}
    seeds: set[str] = set(high)
    for lines in data.ordered_by_family.values():
        seeds.update(_static_neighbors(lines, set(lines) & high, radius=1))
    seeds.update(mid)
    if config.conflict_always_seed:
        seeds.update(line for line, ev in data.line_evidence.items() if ev.conflict)
    if config.transition_always_seed:
        seeds.update(data.transition_lines)
    if config.no_fix_stride > 0:
        seeds.update(
            _stride_lines(
                data.ordered_by_family,
                config.no_fix_stride,
                lines_subset=_no_fix_lines(data.release_lines, data.fix_containing_tags),
            )
        )

    ordered: list[str] = []
    for lines in data.ordered_by_family.values():
        for line in lines:
            if line in seeds:
                ordered.append(line)
    return ordered


def _run_vet_scheduler(data: CvePlanData, config: VetConfig) -> dict[str, Any]:
    seeds = _risk_seed_lines(data, config)
    line_cache: dict[str, LineRunResult] = {}

    def run_line(line: str, _tags: list[str]) -> LineRunResult:
        if line not in line_cache:
            line_cache[line] = _run_vet_line(data, line, config)
        return line_cache[line]

    state = run_staged_scheduler(
        seed_lines=set(seeds),
        release_lines=data.release_lines,
        ordered_by_family=data.ordered_by_family,
        fix_containing_tags=data.fix_containing_tags,
        run_line_fn=run_line,
        expansion_radius=config.expansion_radius,
        fallback_mode="none",
    )

    predicted = set(state.predicted_affected)
    probes = list(state.all_probe_tags)
    visited = set(state.visited)
    verdict_sources: dict[str, str] = {}
    status_counts: Counter[str] = Counter(state.status_counts)
    certified_clear_tags: set[str] = set()
    unresolved_tags: set[str] = set()

    for result in line_cache.values():
        verdict_sources.update(result.verdict_sources)

    for line, tags in data.release_lines.items():
        if line in visited:
            continue
        clear_cert = _segment_clear_certificate(tags, data.tag_evidence, config)
        if clear_cert == "CERT_ABSENT":
            status_counts["unvisited_cert_absent_clear"] += 1
            certified_clear_tags.update(tags)
            for tag in tags:
                verdict_sources[tag] = "cert_absent"
        elif clear_cert == "CERT_FIXED":
            status_counts["unvisited_cert_fixed_clear"] += 1
            certified_clear_tags.update(tags)
            for tag in tags:
                verdict_sources[tag] = "cert_fixed"
        else:
            status_counts["unresolved_line"] += 1
            unresolved_tags.update(tags)
            for tag in tags:
                verdict_sources[tag] = "unresolved"

    counts = _metric_counts(data.release_tags, data.affected_set, predicted)
    return {
        "predicted": predicted,
        "probes": probes,
        "visited_lines": visited,
        "seed_lines": seeds,
        "status_counts": dict(status_counts),
        "verdict_sources": verdict_sources,
        "certified_clear_tags": certified_clear_tags,
        "unresolved_tags": unresolved_tags,
        "metrics": counts,
        "deferred_fn": len(unresolved_tags & data.affected_set),
        "cert_absent_fn": len(
            {tag for tag in certified_clear_tags & data.affected_set if data.tag_evidence[tag].certificate == "CERT_ABSENT"}
        ),
        "cert_fixed_fn": len(
            {tag for tag in certified_clear_tags & data.affected_set if data.tag_evidence[tag].certificate != "CERT_ABSENT"}
        ),
    }


def _run_current_control(data: CvePlanData) -> dict[str, Any]:
    line_cache: dict[str, LineRunResult] = {}

    def run_line(line: str, tags: list[str]) -> LineRunResult:
        if line not in line_cache:
            line_cache[line] = _run_git_guided_line_module(
                line=line,
                tags=tags,
                affected_set=data.affected_set,
                fix_containing_tags=data.fix_containing_tags,
                nn_sentinel_count=NN_SENTINEL_COUNT,
                aa_sentinel_count=1,
                fixed_segment_sentinel=FIXED_SEG_SENTINEL,
            )
        return line_cache[line]

    seed_lines = compute_seed_lines(
        repo_name=data.repo_name,
        release_lines=data.release_lines,
        ordered_by_family=data.ordered_by_family,
        fix_containing_tags=data.fix_containing_tags,
        file_endpoint_lines=data.file_endpoint_lines,
        stride=3,
        file_neighbor_radius=1,
    )
    state = run_staged_scheduler(
        seed_lines=seed_lines,
        release_lines=data.release_lines,
        ordered_by_family=data.ordered_by_family,
        fix_containing_tags=data.fix_containing_tags,
        run_line_fn=run_line,
        expansion_radius=1,
        fallback_mode="nohit_nofix",
    )
    predicted = set(state.predicted_affected)
    counts = _metric_counts(data.release_tags, data.affected_set, predicted)
    return {
        "predicted": predicted,
        "probes": list(state.all_probe_tags),
        "visited_lines": set(state.visited),
        "seed_lines": list(seed_lines),
        "status_counts": dict(state.status_counts),
        "verdict_sources": {},
        "certified_clear_tags": set(),
        "unresolved_tags": set(),
        "metrics": counts,
        "deferred_fn": 0,
        "cert_absent_fn": 0,
        "cert_fixed_fn": 0,
    }


def _load_dataset(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        for key in ("records", "data", "cves"):
            if isinstance(data.get(key), list):
                return data[key]
        if all(isinstance(value, dict) for value in data.values()):
            records: list[dict[str, Any]] = []
            for cve, rec in sorted(data.items()):
                row = dict(rec)
                row.setdefault("cve_id", cve)
                row.setdefault("cve", cve)
                records.append(row)
            return records
    if isinstance(data, list):
        return data
    raise ValueError(f"Unsupported dataset shape: {path}")


def _repo_name(record: dict[str, Any]) -> str:
    return str(record.get("repo") or record.get("project") or record.get("repository") or "")


def _cve_id(record: dict[str, Any]) -> str:
    return str(record.get("cve") or record.get("cve_id") or record.get("CVE") or "")


def _affected_versions(record: dict[str, Any]) -> list[str]:
    versions = record.get("affected_version") or record.get("affected_versions") or []
    return [str(v) for v in versions]


def _prepare_repo_data(
    *,
    repo_name: str,
    records: list[dict[str, Any]],
    repo_root: Path,
    config: VetConfig,
) -> tuple[dict[str, Any], dict[str, CvePlanData], list[dict[str, Any]]]:
    repo_path = repo_root / repo_name
    context = _release_context(repo_name, repo_path)
    repo: GitRepo = context["repo"]
    release_tags: list[str] = context["release_tags"]
    release_lines: dict[str, list[str]] = context["release_lines"]

    all_commits: set[str] = set()
    commits_by_cve: dict[str, list[str]] = {}
    changed_files_by_cve: dict[str, list[str]] = {}
    profiles: dict[str, PatchProfile] = {}
    path_queries: set[tuple[str, str]] = set()
    text_queries: set[tuple[str, str]] = set()
    changed_cache: dict[str, list[str]] = {}
    failures: list[dict[str, Any]] = []

    sample_tags = sorted({tag for tags in release_lines.values() for tag in _sample_tags_for_line(tags)})

    for record in records:
        cve = _cve_id(record)
        commits = _flatten_fixing_commits(
            record.get("fixing_commits")
            or record.get("fixing_commit")
            or record.get("fix_commit")
        )
        commits_by_cve[cve] = commits
        all_commits.update(commits)
        try:
            changed_files = _changed_files_for_commits(repo, commits, changed_cache)
            changed_files_by_cve[cve] = changed_files
            profile = _extract_patch_profile(repo, commits, changed_files)
            profiles[cve] = profile
        except Exception as exc:  # pragma: no cover - per-case failure dump.
            failures.append({"repo": repo_name, "cve": cve, "stage": "profile", "error": str(exc)})
            profiles[cve] = PatchProfile()
            changed_files_by_cve[cve] = []
        for tag in release_tags:
            for path in profiles[cve].files:
                path_queries.add((tag, path))
        for tag in sample_tags:
            for path in profiles[cve].files:
                text_queries.add((tag, path))

    contains = batch_tags_containing(
        repo=repo,
        release_tags=release_tags,
        target_commits=all_commits,
    )
    path_exists = _batch_path_exists(repo, path_queries)
    existing_text_queries = {query for query in text_queries if path_exists.get(query)}
    text_cache = _batch_file_text(repo, existing_text_queries)

    cve_data: dict[str, CvePlanData] = {}
    for record in records:
        cve = _cve_id(record)
        mapped_tags, _unmapped_tags = map_gt_tags_to_repo_tags(
            sorted(_affected_versions(record)),
            release_tags,
            mode="loose",
        )
        affected_set = set(mapped_tags)
        fix_tags: set[str] = set()
        for commit in commits_by_cve.get(cve, []):
            result = contains.get(commit, {"ok": False, "tags": []})
            if result.get("ok"):
                fix_tags.update(result.get("tags", []))
        cve_data[cve] = _build_evidence_for_cve(
            repo_name=repo_name,
            context=context,
            cve_id=cve,
            affected_set=affected_set,
            profile=profiles[cve],
            fix_containing_tags=fix_tags,
            path_exists=path_exists,
            text_cache=text_cache,
            config=config,
        )

    return context, cve_data, failures


def _configs() -> list[VetConfig]:
    return [
        VetConfig("control_current", 0.0, 0.0, 0, current_seed_basis=True),
        VetConfig("vet_current_seed_cert_absent", 0.0, 0.0, 0, current_seed_basis=True),
        VetConfig("vet_current_seed_no_endpoint", 0.0, 0.0, 0, current_seed_basis=True, segment_endpoint_infer=False),
        VetConfig("vet_h0.80_m0.50_s0", 0.80, 0.50, 0),
        VetConfig("vet_h0.70_m0.40_s6", 0.70, 0.40, 6),
        VetConfig("vet_h0.60_m0.30_s6", 0.60, 0.30, 6),
        VetConfig("vet_h0.50_m0.20_s3", 0.50, 0.20, 3),
        VetConfig("vet_h0.50_m0.20_s0", 0.50, 0.20, 0),
        VetConfig("vet_h0.40_m0.20_s3", 0.40, 0.20, 3),
        VetConfig("vet_h0.30_m0.10_s3", 0.30, 0.10, 3),
        VetConfig("vet_h0.20_m0.10_s3", 0.20, 0.10, 3),
        VetConfig("vet_h0.10_m0.05_s3", 0.10, 0.05, 3),
        VetConfig("vet_no_endpoint_h0.40_m0.20_s3", 0.40, 0.20, 3, segment_endpoint_infer=False),
        VetConfig("vet_no_endpoint_h0.60_m0.30_s6", 0.60, 0.30, 6, segment_endpoint_infer=False),
        VetConfig("vet_cert_fixed_h0.60_m0.30_s6", 0.60, 0.30, 6, cert_fixed=True),
    ]


def _run_config(data: CvePlanData, config: VetConfig) -> dict[str, Any]:
    if config.config_id == "control_current":
        return _run_current_control(data)
    return _run_vet_scheduler(data, config)


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    probes = [int(row["probe_count"]) for row in rows]
    cm = Counter()
    repos = defaultdict(list)
    exact = 0
    fn_cves = 0
    fp_cves = 0
    deferred_fn = 0
    cert_absent_fn = 0
    cert_fixed_fn = 0
    unresolved_tags = 0
    certified_clear_tags = 0
    for row in rows:
        metrics = row["metrics"]
        cm.update({key: int(metrics[key]) for key in ("TP", "FP", "FN", "TN")})
        if metrics["FP"] == 0 and metrics["FN"] == 0:
            exact += 1
        if metrics["FN"] > 0:
            fn_cves += 1
        if metrics["FP"] > 0:
            fp_cves += 1
        deferred_fn += int(row.get("deferred_fn", 0))
        cert_absent_fn += int(row.get("cert_absent_fn", 0))
        cert_fixed_fn += int(row.get("cert_fixed_fn", 0))
        unresolved_tags += int(row.get("unresolved_count", 0))
        certified_clear_tags += int(row.get("certified_clear_count", 0))
        repos[row["repo"]].append(row)
    precision = cm["TP"] / (cm["TP"] + cm["FP"]) if cm["TP"] + cm["FP"] else 1.0
    recall = cm["TP"] / (cm["TP"] + cm["FN"]) if cm["TP"] + cm["FN"] else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "cves": len(rows),
        "avg_probes": sum(probes) / len(probes) if probes else 0.0,
        "p50_probes": _safe_percentile(probes, 50),
        "p95_probes": _safe_percentile(probes, 95),
        "exact_cves": exact,
        "fn_cves": fn_cves,
        "fp_cves": fp_cves,
        "version": {
            "TP": cm["TP"],
            "FP": cm["FP"],
            "FN": cm["FN"],
            "TN": cm["TN"],
            "precision": precision,
            "recall": recall,
            "f1": f1,
        },
        "deferred_fn": deferred_fn,
        "cert_absent_fn": cert_absent_fn,
        "cert_fixed_fn": cert_fixed_fn,
        "unresolved_tags": unresolved_tags,
        "certified_clear_tags": certified_clear_tags,
        "by_repo": {
            repo: {
                "cves": len(repo_rows),
                "avg_probes": sum(int(r["probe_count"]) for r in repo_rows) / len(repo_rows),
                "exact_cves": sum(1 for r in repo_rows if r["metrics"]["FP"] == 0 and r["metrics"]["FN"] == 0),
                "fn_cves": sum(1 for r in repo_rows if r["metrics"]["FN"] > 0),
                "fp_cves": sum(1 for r in repo_rows if r["metrics"]["FP"] > 0),
            }
            for repo, repo_rows in sorted(repos.items())
        },
    }


def _write_report(out_dir: Path, summaries: dict[str, Any]) -> None:
    lines = [
        "# Step3 VET Evidence Dynamic Scheduler Simulator",
        "",
        "Dataset: `DataSet/BaseDataOrder.json`.",
        "",
        "GT is used only as the probe oracle and final evaluator.",
        "",
        "| strategy | avg probes | p50 | p95 | exact | FN CVEs | FP CVEs | P | R | F1 | deferred FN | cert_absent FN |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for strategy, summary in summaries.items():
        v = summary["version"]
        lines.append(
            f"| {strategy} | {summary['avg_probes']:.2f} | {summary['p50_probes']} | "
            f"{summary['p95_probes']} | {summary['exact_cves']}/{summary['cves']} | "
            f"{summary['fn_cves']} | {summary['fp_cves']} | {v['precision']:.6f} | "
            f"{v['recall']:.6f} | {v['f1']:.6f} | {summary['deferred_fn']} | "
            f"{summary['cert_absent_fn']} |"
        )
    (out_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(dataset: Path, repo_root: Path, out_dir: Path, limit: int | None = None) -> dict[str, Any]:
    records = _load_dataset(dataset)
    if limit is not None:
        records = records[:limit]
    by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        repo = _repo_name(record)
        if repo:
            by_repo[repo].append(record)

    out_dir.mkdir(parents=True, exist_ok=True)
    configs = _configs()
    all_rows: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    line_score_rows: list[dict[str, Any]] = []

    for repo_name, repo_records in sorted(by_repo.items()):
        # Evidence construction uses certificate options.  cert_absent is shared
        # by all candidate configs; cert_fixed is recomputed inside per-config
        # line execution only when the config enables it.
        evidence_config = VetConfig("evidence", 0.0, 0.0, 0, cert_absent=True, cert_fixed=False)
        _, cve_data_map, repo_failures = _prepare_repo_data(
            repo_name=repo_name,
            records=repo_records,
            repo_root=repo_root,
            config=evidence_config,
        )
        failures.extend(repo_failures)

        for record in repo_records:
            cve = _cve_id(record)
            data = cve_data_map[cve]
            for line, ev in data.line_evidence.items():
                line_score_rows.append(
                    {
                        "repo": repo_name,
                        "cve": cve,
                        "line": line,
                        "score": ev.score,
                        "avg_tag_score": ev.avg_tag_score,
                        "tags": len(ev.tags),
                        "affected_tags": len(set(ev.tags) & data.affected_set),
                        "certificates": dict(ev.certificates),
                        "file_exists_any": ev.file_exists_any,
                        "critical_hit": ev.critical_hit,
                        "vuln_hit": ev.vuln_hit,
                        "fix_guard_hit": ev.fix_guard_hit,
                        "function_hit": ev.function_hit,
                        "transition_line": ev.transition_line,
                        "conflict": ev.conflict,
                    }
                )
            for config in configs:
                result = _run_config(data, config)
                metrics = result["metrics"]
                row = {
                    "strategy": config.config_id,
                    "repo": repo_name,
                    "cve": cve,
                    "probe_count": len(set(result["probes"])),
                    "visited_lines": len(result["visited_lines"]),
                    "seed_lines": len(result["seed_lines"]),
                    "predicted_count": len(result["predicted"]),
                    "affected_count": len(data.affected_set),
                    "metrics": metrics,
                    "status_counts": result["status_counts"],
                    "deferred_fn": result["deferred_fn"],
                    "cert_absent_fn": result["cert_absent_fn"],
                    "cert_fixed_fn": result["cert_fixed_fn"],
                    "unresolved_count": len(result["unresolved_tags"]),
                    "certified_clear_count": len(result["certified_clear_tags"]),
                    "fn_tags": sorted(data.affected_set - result["predicted"]),
                    "fp_tags": sorted(result["predicted"] - data.affected_set),
                }
                all_rows.append(row)

    per_strategy: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in all_rows:
        per_strategy[row["strategy"]].append(row)
    summaries = {strategy: _summarize(rows) for strategy, rows in sorted(per_strategy.items())}
    fn_cases = [
        row
        for row in all_rows
        if row["metrics"]["FN"] > 0 or row["metrics"]["FP"] > 0 or row.get("cert_absent_fn", 0) > 0
    ]

    (out_dir / "summary.json").write_text(json.dumps(summaries, indent=2, sort_keys=True), encoding="utf-8")
    (out_dir / "per_strategy.json").write_text(json.dumps(summaries, indent=2, sort_keys=True), encoding="utf-8")
    with (out_dir / "per_cve.jsonl").open("w", encoding="utf-8") as fh:
        for row in all_rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    (out_dir / "fn_cases.json").write_text(json.dumps(fn_cases, indent=2, sort_keys=True), encoding="utf-8")
    (out_dir / "failures.json").write_text(json.dumps(failures, indent=2, sort_keys=True), encoding="utf-8")
    with (out_dir / "line_scores.jsonl").open("w", encoding="utf-8") as fh:
        for row in line_score_rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    _write_report(out_dir, summaries)
    return summaries


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="DataSet/BaseDataOrder.json")
    parser.add_argument("--repo-root", default="repo")
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    summaries = run(
        dataset=Path(args.dataset),
        repo_root=Path(args.repo_root),
        out_dir=Path(args.out),
        limit=args.limit,
    )
    print(json.dumps(summaries, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

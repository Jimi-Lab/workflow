from __future__ import annotations

import argparse
import csv
import json
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SEMANTIC_BINDING_REPAIR_SCHEMA_VERSION = "semantic_binding_lineage_repair_v1"
FORBIDDEN_KEYS = {"validated_bic", "correct_bic", "affected_versions", "ground_truth"}
PREFERRED_ROOT_CAUSE_RUNS = [
    "root-cause-v2-optimized-contract-30-deepseek",
    "root-cause-v2-optimized-contract-10",
    "root-cause-v2-semantic-baseline-10",
]


def _load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(row.get(key, "")) for key in fieldnames})


def _csv_value(value: Any) -> Any:
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return value


def _ordered_unique(values: list[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = str(value or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def _node_id(item: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = item.get(key)
        if value:
            return str(value)
    return ""


def _fix_sha_from_fix_commit_id(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("fix-commit:"):
        return text.rsplit(":", 1)[-1]
    return text


def _short_path(path: Path) -> str:
    return str(path).replace("\\", "/")


def _artifact_status(artifact_path: Path, ingestion: dict[str, Any] | None, parsed: dict[str, Any] | None) -> str:
    if not artifact_path.exists():
        return "unavailable"
    if parsed is None:
        return "malformed" if (artifact_path / "parse_error.json").exists() else "unavailable"
    if not ingestion:
        return "rejected"
    status = str(ingestion.get("status") or "")
    return "accepted" if status == "ingested_raw" else "rejected"


def _accepted_hypothesis_ids(parsed: dict[str, Any], ingestion: dict[str, Any] | None, accepted: bool) -> list[str]:
    if not accepted:
        return []
    details = (ingestion or {}).get("details") or {}
    accepted_ids: list[str] = []
    for key, value in (details.get("hypothesis_results") or {}).items():
        if isinstance(value, dict) and value.get("gate_valid") is True:
            accepted_ids.append(str(key))
    accepted_ids.extend(str(item) for item in details.get("accepted_hypothesis_ids") or [] if item)
    if accepted_ids:
        return _ordered_unique(accepted_ids)
    return _ordered_unique(
        [
            _node_id(item, "hypothesis_id", "id")
            for item in parsed.get("root_cause_hypotheses") or []
        ]
    )


def _refs(*items: dict[str, Any]) -> list[str]:
    values: list[Any] = []
    for item in items:
        values.extend(item.get("git_observation_refs") or [])
        values.extend(item.get("evidence_refs") or [])
    return _ordered_unique(values)


def extract_root_cause_artifact_inventory(
    cve_id: str,
    artifact_path: str | Path,
    source_run_name: str,
) -> dict[str, Any]:
    """Extract accepted Root Cause semantic IDs from one per-CVE artifact dir."""

    artifact = Path(artifact_path)
    parsed = _load_json(artifact / "parsed_output.json")
    ingestion = _load_json(artifact / "ingestion_result.json")
    status = _artifact_status(artifact, ingestion, parsed)
    accepted = status == "accepted"
    parsed = parsed or {}

    hypotheses = {
        _node_id(item, "hypothesis_id", "id"): item
        for item in parsed.get("root_cause_hypotheses") or []
        if _node_id(item, "hypothesis_id", "id")
    }
    vuln_predicates = {
        _node_id(item, "predicate_id", "id"): item
        for item in parsed.get("vulnerable_predicates") or []
        if _node_id(item, "predicate_id", "id")
    }
    fix_predicates = {
        _node_id(item, "predicate_id", "id"): item
        for item in parsed.get("fix_predicates") or []
        if _node_id(item, "predicate_id", "id")
    }
    anchors = {
        _node_id(item, "anchor_id", "id"): item
        for item in parsed.get("code_anchors") or []
        if _node_id(item, "anchor_id", "id")
    }
    accepted_hypotheses = _accepted_hypothesis_ids(parsed, ingestion, accepted)
    entries: list[dict[str, Any]] = []

    if accepted:
        for hyp_id in accepted_hypotheses:
            hypothesis = hypotheses.get(hyp_id) or {}
            anchor_ids = _ordered_unique((hypothesis.get("anchor_ids") or []) + (hypothesis.get("code_anchor_ids") or []))
            if not anchor_ids:
                for predicate_id in hypothesis.get("vulnerable_predicate_ids") or []:
                    anchor_ids.extend(vuln_predicates.get(predicate_id, {}).get("anchor_ids") or [])
                for predicate_id in hypothesis.get("fix_predicate_ids") or []:
                    anchor_ids.extend(fix_predicates.get(predicate_id, {}).get("anchor_ids") or [])
                anchor_ids = _ordered_unique(anchor_ids)
            if not anchor_ids:
                anchor_ids = [""]

            vuln_ids = _ordered_unique(hypothesis.get("vulnerable_predicate_ids") or [])
            fix_ids = _ordered_unique(hypothesis.get("fix_predicate_ids") or [])
            fix_commit_ids = _ordered_unique(hypothesis.get("fix_commit_ids") or [])
            fix_set_ids = _ordered_unique(hypothesis.get("fix_set_ids") or [])
            for anchor_id in anchor_ids:
                anchor = anchors.get(anchor_id) or {}
                entry_fix_commit_id = str(anchor.get("fix_commit_id") or (fix_commit_ids[0] if fix_commit_ids else ""))
                for vuln_id in vuln_ids or [""]:
                    vuln = vuln_predicates.get(vuln_id) or {}
                    for fix_id in fix_ids or [""]:
                        fix = fix_predicates.get(fix_id) or {}
                        entries.append(
                            {
                                "cve_id": cve_id,
                                "source_artifact_path": _short_path(artifact),
                                "source_run_name": source_run_name,
                                "root_cause_hypothesis_id": hyp_id,
                                "vulnerable_predicate_id": vuln_id,
                                "fix_predicate_id": fix_id,
                                "anchor_id": anchor_id,
                                "fix_commit_id": entry_fix_commit_id,
                                "fix_commit_sha": _fix_sha_from_fix_commit_id(entry_fix_commit_id),
                                "patch_hunk_id": str(anchor.get("patch_hunk_id") or ""),
                                "fix_set_id": fix_set_ids[0] if fix_set_ids else "",
                                "patch_family_id": str(anchor.get("patch_family_id") or anchor.get("patch_family") or ""),
                                "path": str(anchor.get("path") or ""),
                                "function_id": str(anchor.get("function_id") or ""),
                                "function_name": str(anchor.get("function") or anchor.get("function_name") or ""),
                                "source_predicate_id": fix_id or vuln_id,
                                "evidence_refs": _refs(hypothesis, vuln, fix, anchor),
                                "confidence": "exact_hunk_match" if anchor.get("patch_hunk_id") else "exact_fix_commit_match",
                                "source_status": "accepted",
                            }
                        )

    return {
        "schema_version": SEMANTIC_BINDING_REPAIR_SCHEMA_VERSION,
        "cve_id": cve_id,
        "source_artifact_path": _short_path(artifact),
        "source_run_name": source_run_name,
        "artifact_status": status,
        "ingestion_status": (ingestion or {}).get("status", ""),
        "root_cause_hypothesis_ids": _ordered_unique([item["root_cause_hypothesis_id"] for item in entries])
        if accepted
        else [],
        "vulnerable_predicate_ids": _ordered_unique([item["vulnerable_predicate_id"] for item in entries])
        if accepted
        else [],
        "fix_predicate_ids": _ordered_unique([item["fix_predicate_id"] for item in entries]) if accepted else [],
        "entries": entries,
        "entry_count": len(entries),
    }


def _entry_fingerprint(entry: dict[str, Any]) -> tuple[str, ...]:
    return (
        str(entry.get("fix_commit_id") or ""),
        str(entry.get("fix_commit_sha") or ""),
        str(entry.get("patch_hunk_id") or ""),
        str(entry.get("path") or ""),
        str(entry.get("root_cause_hypothesis_id") or ""),
        str(entry.get("vulnerable_predicate_id") or ""),
        str(entry.get("fix_predicate_id") or ""),
    )


def build_semantic_binding_index(inventories: list[dict[str, Any]]) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    accepted_by_cve: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for inventory in inventories:
        if inventory.get("artifact_status") != "accepted":
            continue
        cve_id = str(inventory.get("cve_id") or "")
        accepted_by_cve[cve_id].append(inventory)
        entries.extend(json.loads(json.dumps(entry)) for entry in inventory.get("entries") or [])

    conflict_cves: dict[str, dict[str, Any]] = {}
    for cve_id, cve_inventories in accepted_by_cve.items():
        fingerprints_by_source: dict[str, set[tuple[str, ...]]] = {}
        for inventory in cve_inventories:
            source = str(inventory.get("source_artifact_path") or "")
            fingerprints_by_source[source] = {_entry_fingerprint(entry) for entry in inventory.get("entries") or []}
        unique_sets = {tuple(sorted(value)) for value in fingerprints_by_source.values()}
        if len(unique_sets) > 1:
            conflict_cves[cve_id] = {
                "sources": sorted(fingerprints_by_source),
                "reason": "accepted_artifact_semantic_binding_conflict",
            }

    by_cve: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        by_cve[str(entry.get("cve_id") or "")].append(entry)
    return {
        "schema_version": SEMANTIC_BINDING_REPAIR_SCHEMA_VERSION,
        "entries": entries,
        "by_cve": dict(by_cve),
        "conflict_cves": conflict_cves,
        "entry_count": len(entries),
    }


def _binding_container(candidate: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if isinstance(candidate.get("candidate_origin"), dict):
        return candidate["candidate_origin"], "candidate_origin"
    if isinstance(candidate.get("root_cause_bindings"), dict):
        return candidate["root_cause_bindings"], "root_cause_bindings"
    if isinstance(candidate.get("root_cause_binding"), dict):
        return candidate["root_cause_binding"], "root_cause_binding"
    candidate["root_cause_binding"] = {}
    return candidate["root_cause_binding"], "root_cause_binding"


def _get_bindings(container: dict[str, Any], kind: str) -> list[str]:
    if kind == "root":
        return _ordered_unique((container.get("root_cause_hypothesis_bindings") or []) + (container.get("root_cause_hypothesis_ids") or []))
    if kind == "vuln":
        return _ordered_unique((container.get("vulnerable_predicate_bindings") or []) + (container.get("vulnerable_predicate_ids") or []))
    return _ordered_unique((container.get("fix_predicate_bindings") or []) + (container.get("fix_predicate_ids") or []))


def _set_bindings(container: dict[str, Any], location: str, *, roots: list[str], vulns: list[str], fixes: list[str]) -> None:
    if location == "candidate_origin":
        container["root_cause_hypothesis_bindings"] = roots
        container["vulnerable_predicate_bindings"] = vulns
        container["fix_predicate_bindings"] = fixes
    elif location == "root_cause_bindings":
        container["root_cause_hypothesis_ids"] = roots
        container["vulnerable_predicate_ids"] = vulns
        container["fix_predicate_ids"] = fixes
    else:
        container["root_cause_hypothesis_ids"] = roots
        container["vulnerable_predicate_ids"] = vulns
        container["fix_predicate_ids"] = fixes


def _real_bindings(values: list[str]) -> list[str]:
    return [value for value in values if not value.startswith("fallback:")]


def _candidate_fact(candidate: dict[str, Any], container: dict[str, Any], key: str) -> str:
    identity = candidate.get("candidate_event_identity") or {}
    if key == "fix_commit_sha":
        return str(container.get(key) or identity.get(key) or _fix_sha_from_fix_commit_id(container.get("fix_commit_id")) or "")
    if key == "fix_commit_id":
        return str(container.get(key) or "")
    if key == "path":
        return str(container.get("anchor_path") or container.get("path") or identity.get("path") or "")
    if key == "patch_hunk_id":
        values = []
        for field in ("patch_hunk_id", "selected_anchor_id", "anchor_id"):
            if container.get(field):
                values.append(str(container.get(field)))
        values.extend(_get_bindings(container, "vuln"))
        for value in values:
            marker = "patch-hunk:"
            if marker in value:
                return marker + value.split(marker, 1)[1]
        return ""
    return ""


def _unique_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, ...], dict[str, Any]] = {}
    for entry in entries:
        unique[_entry_fingerprint(entry)] = entry
    return list(unique.values())


def _match_entries(candidate: dict[str, Any], container: dict[str, Any], index: dict[str, Any], cve_id: str) -> tuple[list[dict[str, Any]], str, str]:
    if cve_id in (index.get("conflict_cves") or {}):
        return [], "", "source_artifact_conflict"
    entries = list((index.get("by_cve") or {}).get(cve_id) or [])
    if not entries:
        return [], "", "source_artifact_unavailable"
    if not any(entry.get("fix_predicate_id") for entry in entries):
        return [], "", "source_fix_predicate_unavailable"

    patch_hunk_id = _candidate_fact(candidate, container, "patch_hunk_id")
    if patch_hunk_id:
        matched = _unique_entries([entry for entry in entries if entry.get("patch_hunk_id") == patch_hunk_id])
        if len(matched) == 1:
            return matched, "exact_hunk_match", ""
        if len(matched) > 1:
            return [], "", "ambiguous_hunk_match"

    fix_commit_id = _candidate_fact(candidate, container, "fix_commit_id")
    fix_commit_sha = _candidate_fact(candidate, container, "fix_commit_sha")
    path = _candidate_fact(candidate, container, "path")
    if (fix_commit_id or fix_commit_sha) and path:
        matched = _unique_entries(
            [
                entry
                for entry in entries
                if (not fix_commit_id or entry.get("fix_commit_id") == fix_commit_id)
                and (not fix_commit_sha or entry.get("fix_commit_sha") == fix_commit_sha)
                and entry.get("path") == path
            ]
        )
        if len(matched) == 1:
            return matched, "exact_fix_commit_path_match", ""
        if len(matched) > 1:
            return [], "", "ambiguous_fix_commit_path_match"

    if fix_commit_id or fix_commit_sha:
        matched = _unique_entries(
            [
                entry
                for entry in entries
                if (fix_commit_id and entry.get("fix_commit_id") == fix_commit_id)
                or (fix_commit_sha and entry.get("fix_commit_sha") == fix_commit_sha)
            ]
        )
        if len(matched) == 1:
            return matched, "exact_fix_commit_match", ""
        if len(matched) > 1:
            return [], "", "ambiguous_fix_commit_match"

    return [], "", "ambiguous_cve_level_only"


def repair_candidate_semantic_bindings(
    candidate: dict[str, Any],
    index: dict[str, Any],
    cve_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    repaired = json.loads(json.dumps(candidate))
    container, location = _binding_container(repaired)

    before_roots = _get_bindings(container, "root")
    before_vulns = _get_bindings(container, "vuln")
    before_fixes = _get_bindings(container, "fix")
    real_fixes = _real_bindings(before_fixes)
    candidate_id = str(repaired.get("candidate_id") or repaired.get("event_id") or "")
    source_lane = str(repaired.get("source_lane") or ((repaired.get("evidence_features") or {}).get("source_lanes") or [""])[0] or "")

    if real_fixes:
        lineage = {
            "root_cause_binding_status": "already_present" if _real_bindings(before_roots) else "not_applicable",
            "vulnerable_predicate_binding_status": "already_present" if _real_bindings(before_vulns) else "not_applicable",
            "fix_predicate_binding_status": "already_present",
            "source_artifact_path": "",
            "source_run_name": "",
            "binding_strategy": "already_present",
            "missing_reason": "",
            "evidence_refs": [],
        }
        container["semantic_binding_lineage"] = lineage
        ledger = _ledger_row(cve_id, candidate_id, source_lane, before_roots, before_vulns, before_fixes, before_roots, before_vulns, before_fixes, lineage)
        return repaired, ledger

    matched, strategy, missing_reason = _match_entries(repaired, container, index, cve_id)
    if matched:
        roots = _ordered_unique(_real_bindings(before_roots) + [entry.get("root_cause_hypothesis_id") for entry in matched])
        vulns = _ordered_unique(_real_bindings(before_vulns) + [entry.get("vulnerable_predicate_id") for entry in matched])
        fixes = _ordered_unique(_real_bindings(before_fixes) + [entry.get("fix_predicate_id") for entry in matched])
        _set_bindings(container, location, roots=roots, vulns=vulns, fixes=fixes)
        status = "backfilled_exact" if strategy.startswith("exact_") else "backfilled_unambiguous"
        lineage = {
            "root_cause_binding_status": status if roots else "unavailable",
            "vulnerable_predicate_binding_status": status if vulns else "unavailable",
            "fix_predicate_binding_status": status if fixes else "unavailable",
            "source_artifact_path": matched[0].get("source_artifact_path", ""),
            "source_run_name": matched[0].get("source_run_name", ""),
            "binding_strategy": strategy,
            "missing_reason": "",
            "evidence_refs": _ordered_unique([ref for entry in matched for ref in entry.get("evidence_refs") or []]),
        }
    else:
        status = "conflict" if missing_reason == "source_artifact_conflict" else "unavailable"
        if missing_reason.startswith("ambiguous"):
            status = "ambiguous"
        lineage = {
            "root_cause_binding_status": "not_applicable" if before_roots else status,
            "vulnerable_predicate_binding_status": "not_applicable" if before_vulns else status,
            "fix_predicate_binding_status": status,
            "source_artifact_path": "",
            "source_run_name": "",
            "binding_strategy": "",
            "missing_reason": missing_reason,
            "evidence_refs": [],
        }
    container["semantic_binding_lineage"] = lineage
    after_roots = _get_bindings(container, "root")
    after_vulns = _get_bindings(container, "vuln")
    after_fixes = _get_bindings(container, "fix")
    ledger = _ledger_row(cve_id, candidate_id, source_lane, before_roots, before_vulns, before_fixes, after_roots, after_vulns, after_fixes, lineage)
    return repaired, ledger


def _ledger_row(
    cve_id: str,
    candidate_id: str,
    source_lane: str,
    before_roots: list[str],
    before_vulns: list[str],
    before_fixes: list[str],
    after_roots: list[str],
    after_vulns: list[str],
    after_fixes: list[str],
    lineage: dict[str, Any],
) -> dict[str, Any]:
    return {
        "cve_id": cve_id,
        "candidate_id": candidate_id,
        "source_lane": source_lane,
        "before_root_cause_binding": bool(_real_bindings(before_roots)),
        "before_vulnerable_predicate_binding": bool(_real_bindings(before_vulns)),
        "before_fix_predicate_binding": bool(_real_bindings(before_fixes)),
        "after_root_cause_binding": bool(_real_bindings(after_roots)),
        "after_vulnerable_predicate_binding": bool(_real_bindings(after_vulns)),
        "after_fix_predicate_binding": bool(_real_bindings(after_fixes)),
        "root_cause_binding_status": lineage.get("root_cause_binding_status", ""),
        "vulnerable_predicate_binding_status": lineage.get("vulnerable_predicate_binding_status", ""),
        "fix_predicate_binding_status": lineage.get("fix_predicate_binding_status", ""),
        "binding_strategy": lineage.get("binding_strategy", ""),
        "missing_reason": lineage.get("missing_reason", ""),
        "source_artifact_path": lineage.get("source_artifact_path", ""),
        "source_run_name": lineage.get("source_run_name", ""),
        "fix_predicate_ids_after": ";".join(after_fixes),
    }


def _dataset_cves(dataset_path: str | Path) -> list[str]:
    data = _load_json(Path(dataset_path), {})
    if isinstance(data, dict):
        return sorted(str(key) for key in data)
    if isinstance(data, list):
        result = []
        for item in data:
            if isinstance(item, dict):
                result.append(str(item.get("cve_id") or item.get("CVE") or item.get("cve") or ""))
        return sorted([item for item in result if item])
    return []


def _artifact_candidates(runs_root: Path, cve_id: str) -> list[Path]:
    candidates: list[Path] = []
    for run in runs_root.iterdir() if runs_root.exists() else []:
        if not run.is_dir() or "root-cause" not in run.name:
            continue
        case_dir = run / cve_id
        if (case_dir / "parsed_output.json").exists() or (case_dir / "ingestion_result.json").exists() or (case_dir / "parse_error.json").exists():
            candidates.append(case_dir)
    return candidates


def discover_root_cause_artifact_inventories(
    *,
    cve_ids: list[str],
    runs_root: str | Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    root = Path(runs_root)
    all_inventories: list[dict[str, Any]] = []
    selected_inventories: list[dict[str, Any]] = []
    manifest_rows: list[dict[str, Any]] = []

    for cve_id in cve_ids:
        case_paths = _artifact_candidates(root, cve_id)
        inventories_by_path: dict[str, dict[str, Any]] = {}
        for path in case_paths:
            inventory = extract_root_cause_artifact_inventory(cve_id, path, path.parent.name)
            inventories_by_path[str(path)] = inventory
            all_inventories.append(inventory)

        selected: list[dict[str, Any]] = []
        selected_priority = ""
        for run_name in PREFERRED_ROOT_CAUSE_RUNS:
            accepted = [
                inv
                for inv in inventories_by_path.values()
                if inv.get("source_run_name") == run_name and inv.get("artifact_status") == "accepted"
            ]
            if accepted:
                selected = accepted
                selected_priority = run_name
                break
        if not selected:
            selected = [inv for inv in inventories_by_path.values() if inv.get("artifact_status") == "accepted"][:1]
            selected_priority = "fallback_scan" if selected else ""
        selected_paths = {item["source_artifact_path"] for item in selected}
        selected_inventories.extend(selected)
        for inventory in inventories_by_path.values():
            selected_flag = inventory["source_artifact_path"] in selected_paths
            manifest_rows.append(
                {
                    "cve_id": cve_id,
                    "source_run_name": inventory.get("source_run_name", ""),
                    "source_artifact_path": inventory.get("source_artifact_path", ""),
                    "artifact_status": inventory.get("artifact_status", ""),
                    "entry_count": inventory.get("entry_count", 0),
                    "selected": selected_flag,
                    "selection_policy": selected_priority if selected_flag else "not_selected",
                    "selection_reason": "first_preferred_accepted_artifact" if selected_flag else "lower_priority_or_unaccepted",
                }
            )
        if not inventories_by_path:
            manifest_rows.append(
                {
                    "cve_id": cve_id,
                    "source_run_name": "",
                    "source_artifact_path": "",
                    "artifact_status": "unavailable",
                    "entry_count": 0,
                    "selected": False,
                    "selection_policy": "",
                    "selection_reason": "no_root_cause_artifact_found",
                }
            )
    return all_inventories, selected_inventories, manifest_rows


def _repair_list(payload: Any, index: dict[str, Any], cve_id: str, ledgers: list[dict[str, Any]]) -> Any:
    if not isinstance(payload, list):
        return payload
    repaired_items = []
    for item in payload:
        if isinstance(item, dict):
            repaired, ledger = repair_candidate_semantic_bindings(item, index, cve_id)
            ledgers.append(ledger)
            repaired_items.append(repaired)
        else:
            repaired_items.append(item)
    return repaired_items


def _repair_blind_packet(payload: Any, index: dict[str, Any], cve_id: str, ledgers: list[dict[str, Any]]) -> Any:
    if not isinstance(payload, dict):
        return payload
    repaired = json.loads(json.dumps(payload))
    candidates = []
    for item in repaired.get("candidates") or []:
        if isinstance(item, dict):
            fixed, ledger = repair_candidate_semantic_bindings(item, index, cve_id)
            ledgers.append(ledger)
            candidates.append(fixed)
        else:
            candidates.append(item)
    repaired["candidates"] = candidates
    return repaired


def _repair_v3_events(payload: Any, history_ledgers_by_candidate_id: dict[str, dict[str, Any]]) -> Any:
    if not isinstance(payload, list):
        return payload
    repaired = json.loads(json.dumps(payload))
    for event in repaired:
        if not isinstance(event, dict):
            continue
        event["semantic_binding_lineage_by_source_candidate_id"] = {
            candidate_id: history_ledgers_by_candidate_id[candidate_id]
            for candidate_id in event.get("source_candidate_ids") or []
            if candidate_id in history_ledgers_by_candidate_id
        }
    return repaired


def _copy_if_exists(src: Path, dst: Path) -> None:
    if src.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def _repair_artifact_roots(
    *,
    cve_ids: list[str],
    index: dict[str, Any],
    reconstruction_root: Path,
    readiness_root: Path,
    v3_replay_root: Path,
    topk_root: Path,
    root_boundary_root: Path,
    out_dir: Path,
) -> list[dict[str, Any]]:
    ledger_rows: list[dict[str, Any]] = []
    history_ledgers_by_cve: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)

    repaired_reconstruction = out_dir / "repaired_history_event_reconstruction"
    repaired_readiness = out_dir / "repaired_history_event_judge_readiness"
    repaired_v3 = out_dir / "repaired_v3_semantic_chain_gate_dev30_replay"
    repaired_topk = out_dir / "repaired_topk_judge_packet_v1_dev13"
    repaired_boundary = out_dir / "repaired_history_root_boundary_v1_1_1"

    for cve_id in cve_ids:
        history_ledgers: list[dict[str, Any]] = []
        src = reconstruction_root / cve_id / "history_event_packets.json"
        if src.exists():
            repaired = _repair_list(_load_json(src, []), index, cve_id, history_ledgers)
            _write_json(repaired_reconstruction / cve_id / "history_event_packets.json", repaired)
            for name in ("case_report_zh.md", "candidate_review_table.csv"):
                _copy_if_exists(reconstruction_root / cve_id / name, repaired_reconstruction / cve_id / name)
        ledger_rows.extend(history_ledgers)
        history_ledgers_by_cve[cve_id] = {row["candidate_id"]: row for row in history_ledgers}

        readiness_ledgers: list[dict[str, Any]] = []
        for filename in ("judge_blind_history_event_packets.json", "judge_audit_history_event_packets.json"):
            src = readiness_root / cve_id / filename
            if src.exists():
                repaired = _repair_list(_load_json(src, []), index, cve_id, readiness_ledgers)
                _write_json(repaired_readiness / cve_id / filename, repaired)
        ledger_rows.extend(readiness_ledgers)

        for filename in ("v3_candidates.json", "v3_gate_decisions.json", "v3_rejected_events.json"):
            src = v3_replay_root / cve_id / filename
            if src.exists():
                repaired = _repair_v3_events(_load_json(src, []), history_ledgers_by_cve[cve_id])
                _write_json(repaired_v3 / cve_id / filename, repaired)
        for filename in ("v3_case_metrics.json",):
            _copy_if_exists(v3_replay_root / cve_id / filename, repaired_v3 / cve_id / filename)

        for filename in ("judge_blind_history_event_packet.json", "judge_audit_history_event_packet.json"):
            src = topk_root / cve_id / filename
            if src.exists():
                topk_ledgers: list[dict[str, Any]] = []
                payload = _load_json(src, {})
                repaired = _repair_blind_packet(payload, index, cve_id, topk_ledgers) if "blind" not in filename else _repair_blind_packet(payload, index, cve_id, topk_ledgers)
                _write_json(repaired_topk / cve_id / filename, repaired)
                ledger_rows.extend(topk_ledgers)

        for filename in ("judge_blind_history_event_packet.json", "judge_audit_history_event_packet.json"):
            src = root_boundary_root / cve_id / filename
            if src.exists():
                boundary_ledgers: list[dict[str, Any]] = []
                payload = _load_json(src, {})
                repaired = _repair_blind_packet(payload, index, cve_id, boundary_ledgers)
                _write_json(repaired_boundary / cve_id / filename, repaired)
                ledger_rows.extend(boundary_ledgers)
    return ledger_rows


def _coverage_rows(ledger_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    candidate_rows = [row for row in ledger_rows if row.get("candidate_id")]
    by_cve: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in candidate_rows:
        by_cve[row["cve_id"]].append(row)

    def _rate(rows: list[dict[str, Any]], key: str) -> float:
        if not rows:
            return 0.0
        return sum(1 for row in rows if row.get(key) is True) / len(rows)

    per_cve: list[dict[str, Any]] = []
    for cve_id, rows in sorted(by_cve.items()):
        reasons = Counter(str(row.get("missing_reason") or "none") for row in rows if not row.get("after_fix_predicate_binding"))
        per_cve.append(
            {
                "cve_id": cve_id,
                "candidate_count": len(rows),
                "before_root_cause_binding_coverage": _rate(rows, "before_root_cause_binding"),
                "after_root_cause_binding_coverage": _rate(rows, "after_root_cause_binding"),
                "before_vulnerable_predicate_binding_coverage": _rate(rows, "before_vulnerable_predicate_binding"),
                "after_vulnerable_predicate_binding_coverage": _rate(rows, "after_vulnerable_predicate_binding"),
                "before_fix_predicate_binding_coverage": _rate(rows, "before_fix_predicate_binding"),
                "after_fix_predicate_binding_coverage": _rate(rows, "after_fix_predicate_binding"),
                "missing_reason_distribution": dict(sorted(reasons.items())),
            }
        )

    summary_by_lane = {}
    for lane in ("strong", "fallback", ""):
        rows = [row for row in candidate_rows if str(row.get("source_lane") or "") == lane] if lane else candidate_rows
        label = lane or "total"
        summary_by_lane[label] = {
            "candidate_count": len(rows),
            "before_root_cause_binding_coverage": _rate(rows, "before_root_cause_binding"),
            "after_root_cause_binding_coverage": _rate(rows, "after_root_cause_binding"),
            "before_vulnerable_predicate_binding_coverage": _rate(rows, "before_vulnerable_predicate_binding"),
            "after_vulnerable_predicate_binding_coverage": _rate(rows, "after_vulnerable_predicate_binding"),
            "before_fix_predicate_binding_coverage": _rate(rows, "before_fix_predicate_binding"),
            "after_fix_predicate_binding_coverage": _rate(rows, "after_fix_predicate_binding"),
        }

    missing = [
        row
        for row in candidate_rows
        if not row.get("after_fix_predicate_binding") or row.get("missing_reason") in {"source_artifact_conflict", "source_artifact_unavailable"}
    ]
    summary = {
        "schema_version": SEMANTIC_BINDING_REPAIR_SCHEMA_VERSION,
        "coverage": summary_by_lane,
        "total_candidates": len(candidate_rows),
        "conflict_count": sum(1 for row in candidate_rows if row.get("fix_predicate_binding_status") == "conflict"),
        "unavailable_count": sum(1 for row in candidate_rows if row.get("fix_predicate_binding_status") == "unavailable"),
        "ambiguous_count": sum(1 for row in candidate_rows if row.get("fix_predicate_binding_status") == "ambiguous"),
        "backfilled_count": sum(1 for row in candidate_rows if str(row.get("fix_predicate_binding_status") or "").startswith("backfilled")),
        "missing_or_conflict_count": len(missing),
        "model_invocation_count": 0,
        "judge_invocation_count": 0,
        "converter_invocation_count": 0,
    }
    return per_cve, missing, summary


def _inventory_rows(inventories: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for inventory in inventories:
        rows.append(
            {
                "cve_id": inventory.get("cve_id", ""),
                "source_run_name": inventory.get("source_run_name", ""),
                "source_artifact_path": inventory.get("source_artifact_path", ""),
                "artifact_status": inventory.get("artifact_status", ""),
                "root_cause_hypothesis_ids": ";".join(inventory.get("root_cause_hypothesis_ids") or []),
                "vulnerable_predicate_ids": ";".join(inventory.get("vulnerable_predicate_ids") or []),
                "fix_predicate_ids": ";".join(inventory.get("fix_predicate_ids") or []),
                "entry_count": inventory.get("entry_count", 0),
            }
        )
    return rows


def _index_rows(index: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "cve_id": entry.get("cve_id", ""),
            "fix_commit_id": entry.get("fix_commit_id", ""),
            "fix_commit_sha": entry.get("fix_commit_sha", ""),
            "patch_hunk_id": entry.get("patch_hunk_id", ""),
            "path": entry.get("path", ""),
            "root_cause_hypothesis_id": entry.get("root_cause_hypothesis_id", ""),
            "vulnerable_predicate_id": entry.get("vulnerable_predicate_id", ""),
            "fix_predicate_id": entry.get("fix_predicate_id", ""),
            "source_artifact_path": entry.get("source_artifact_path", ""),
            "source_run_name": entry.get("source_run_name", ""),
            "confidence": entry.get("confidence", ""),
        }
        for entry in index.get("entries") or []
    ]


def _scan_forbidden(output: Path) -> dict[str, Any]:
    violations: list[dict[str, Any]] = []

    def visit(value: Any, path: str, json_path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key in FORBIDDEN_KEYS:
                    violations.append({"file": path, "json_path": f"{json_path}.{key}".strip("."), "key": key})
                visit(child, path, f"{json_path}.{key}".strip("."))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, path, f"{json_path}[{index}]")

    for path in output.rglob("*.json"):
        payload = _load_json(path)
        visit(payload, str(path.relative_to(output)), "")
    return {"violation_count": len(violations), "violations": violations}


def _report_zh(summary: dict[str, Any], per_cve_rows: list[dict[str, Any]]) -> str:
    cve_19667 = next((row for row in per_cve_rows if row["cve_id"] == "CVE-2020-19667"), {})
    lines = [
        "# VulnGraph Semantic Binding Lineage Repair v1",
        "",
        "本轮只修复 wrapper/harness 层的 Root Cause semantic binding 血缘传递，不调用模型，不运行 Judge/converter，不输出版本预测。",
        "",
        "## Source Selection Policy",
        "",
        "- 优先级：`root-cause-v2-optimized-contract-30-deepseek` -> `root-cause-v2-optimized-contract-10` -> `root-cause-v2-semantic-baseline-10` -> fallback scan。",
        "- 只有 `ingestion_result.status == ingested_raw` 的 artifact 进入 semantic binding index。",
        "- 多个同优先级 accepted artifact 若语义 fingerprint 冲突，则该 CVE fail-closed，不静默选择。",
        "",
        "## Coverage",
        "",
    ]
    for lane, data in (summary.get("coverage") or {}).items():
        lines.append(
            f"- {lane}: candidates={data['candidate_count']}, "
            f"fix before/after={data['before_fix_predicate_binding_coverage']:.3f}/{data['after_fix_predicate_binding_coverage']:.3f}, "
            f"root before/after={data['before_root_cause_binding_coverage']:.3f}/{data['after_root_cause_binding_coverage']:.3f}, "
            f"vuln before/after={data['before_vulnerable_predicate_binding_coverage']:.3f}/{data['after_vulnerable_predicate_binding_coverage']:.3f}"
        )
    lines.extend(
        [
            "",
            "## CVE-2020-19667",
            "",
            f"- candidate_count: `{cve_19667.get('candidate_count', '')}`",
            f"- fix predicate coverage before/after: `{cve_19667.get('before_fix_predicate_binding_coverage', '')}` / `{cve_19667.get('after_fix_predicate_binding_coverage', '')}`",
            f"- missing reason distribution: `{cve_19667.get('missing_reason_distribution', {})}`",
            "",
            "## Stop Boundary",
            "",
            "- 输出仍是 repaired copies；旧 artifacts 未覆盖。",
            "- 回填只使用已存在的 RootCauseHypothesis / VulnerablePredicate / FixPredicate ID。",
            "- forbidden exact key scan 结果见 `forbidden_field_scan.json`。",
            "",
        ]
    )
    return "\n".join(lines)


def run_semantic_binding_lineage_repair_v1(
    *,
    dataset: str | Path,
    runs_root: str | Path,
    reconstruction_root: str | Path,
    readiness_root: str | Path,
    v3_replay_root: str | Path,
    topk_root: str | Path,
    root_boundary_root: str | Path,
    out_dir: str | Path,
    reset: bool = False,
) -> dict[str, Any]:
    output = Path(out_dir)
    if reset and output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    cve_ids = _dataset_cves(dataset)
    all_inventories, selected_inventories, source_manifest = discover_root_cause_artifact_inventories(
        cve_ids=cve_ids,
        runs_root=runs_root,
    )
    index = build_semantic_binding_index(selected_inventories)
    ledger_rows = _repair_artifact_roots(
        cve_ids=cve_ids,
        index=index,
        reconstruction_root=Path(reconstruction_root),
        readiness_root=Path(readiness_root),
        v3_replay_root=Path(v3_replay_root),
        topk_root=Path(topk_root),
        root_boundary_root=Path(root_boundary_root),
        out_dir=output,
    )
    per_cve_rows, missing_rows, summary = _coverage_rows(ledger_rows)
    summary["cve_count"] = len(cve_ids)
    summary["selected_source_artifact_count"] = len(selected_inventories)
    summary["semantic_binding_index_entry_count"] = len(index.get("entries") or [])
    summary["artifact_conflict_cves"] = sorted((index.get("conflict_cves") or {}).keys())

    _write_json(output / "semantic_binding_source_manifest.json", {"schema_version": SEMANTIC_BINDING_REPAIR_SCHEMA_VERSION, "sources": source_manifest})
    _write_csv(output / "root_cause_artifact_inventory.csv", _inventory_rows(all_inventories))
    _write_json(output / "semantic_binding_index.json", index)
    _write_csv(output / "semantic_binding_index.csv", _index_rows(index))
    _write_csv(output / "candidate_semantic_binding_ledger.csv", ledger_rows)
    _write_csv(output / "semantic_binding_before_after.csv", ledger_rows)
    _write_csv(output / "per_cve_semantic_binding_coverage.csv", per_cve_rows)
    _write_csv(output / "missing_or_conflict_binding_cases.csv", missing_rows)
    forbidden = _scan_forbidden(output)
    summary["forbidden_field_scan"] = forbidden
    summary["forbidden_field_violation_count"] = forbidden["violation_count"]
    _write_json(output / "semantic_binding_repair_summary.json", summary)
    _write_json(output / "forbidden_field_scan.json", forbidden)
    (output / "semantic_binding_repair_report_zh.md").write_text(_report_zh(summary, per_cve_rows), encoding="utf-8")
    return summary


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Repair semantic binding lineage in existing VulnGraph artifacts.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--runs-root", required=True)
    parser.add_argument("--reconstruction-root", required=True)
    parser.add_argument("--readiness-root", required=True)
    parser.add_argument("--v3-replay-root", required=True)
    parser.add_argument("--topk-root", required=True)
    parser.add_argument("--root-boundary-root", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--reset", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    summary = run_semantic_binding_lineage_repair_v1(
        dataset=args.dataset,
        runs_root=args.runs_root,
        reconstruction_root=args.reconstruction_root,
        readiness_root=args.readiness_root,
        v3_replay_root=args.v3_replay_root,
        topk_root=args.topk_root,
        root_boundary_root=args.root_boundary_root,
        out_dir=args.out_dir,
        reset=args.reset,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("forbidden_field_violation_count") == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())

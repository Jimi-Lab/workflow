from __future__ import annotations

import argparse
import json
import re
import shutil
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


NS = {
    "cwe": "http://cwe.mitre.org/cwe-7",
    "xhtml": "http://www.w3.org/1999/xhtml",
}

GENERIC_DANGEROUS_TOKENS = [
    "size",
    "len",
    "length",
    "count",
    "index",
    "idx",
    "buf",
    "data",
    "value",
    "ptr",
]


def clean_text(value: str | None) -> str:
    if not value:
        return ""
    text = re.sub(r"\s+", " ", value.replace("\xa0", " ")).strip()
    return text


def node_text(elem: ET.Element | None) -> str:
    if elem is None:
        return ""
    return clean_text(" ".join(t for t in elem.itertext()))


def unique_keep_order(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in values:
        item = clean_text(item)
        if not item:
            continue
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def short_sentence(text: str, *, limit: int = 240) -> str:
    text = clean_text(text)
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].strip()
    return cut + "..."


def significant_terms(*texts: str, limit: int = 12) -> list[str]:
    stop = {
        "the", "and", "for", "with", "that", "this", "from", "into", "when",
        "where", "which", "while", "does", "have", "uses", "using", "product",
        "software", "allow", "allows", "attacker", "attackers", "application",
        "program", "code", "data", "input", "output", "without", "improper",
        "insufficient", "incorrect", "missing", "generation", "exposure",
        "resource", "resources", "state", "access", "control", "validation",
        "check", "checks", "use", "used", "not", "can", "may", "via", "has",
        "its", "their", "there", "then", "than", "such", "should", "being",
        "more", "less", "after", "before", "during", "within", "outside",
        "pointer", "buffer", "overflow", "underflow", "weakness", "condition",
        "conditions", "object", "objects", "function", "functions", "memory",
        "example", "examples", "include", "includes", "including", "provide",
        "provides", "provided", "construct", "constructs", "extension",
        "extensions", "easier", "avoid", "occur", "language", "languages",
        "framework", "frameworks", "library", "libraries", "compiler",
        "compilers", "automatic", "detection", "offered", "certain", "many",
        "perform", "performs", "their", "own", "safe", "security", "sensitive"
    }
    raw = " ".join(texts).lower()
    tokens = re.findall(r"[a-z_][a-z0-9_+\-]{2,}", raw)
    score: dict[str, int] = defaultdict(int)
    for tok in tokens:
        if tok in stop:
            continue
        if tok.isdigit():
            continue
        score[tok] += 1
    ranked = sorted(score.items(), key=lambda x: (-x[1], -len(x[0]), x[0]))
    return [tok for tok, _ in ranked[:limit]]


def classify_archetype(name: str, description: str, extended: str) -> str:
    blob = f"{name} {description} {extended}".lower()
    checks = [
        ("oob_write", ["out-of-bounds write", "buffer write", "buffer overflow", "overwrite"]),
        ("oob_read", ["out-of-bounds read", "buffer over-read", "over-read", "read past"]),
        ("uaf", ["use after free", "use-after-free", "dangling pointer"]),
        ("double_free", ["double free", "double-free"]),
        ("null_deref", ["null pointer dereference", "null dereference"]),
        ("int_overflow", ["integer overflow", "wraparound", "signed overflow", "truncation"]),
        ("path_traversal", ["path traversal", "directory traversal", "improper limitation of a pathname"]),
        ("sql_injection", ["sql injection"]),
        ("command_injection", ["command injection", "os command injection", "shell command"]),
        ("xss", ["cross site scripting", "cross-site scripting", "xss"]),
        ("xxe", ["xml external entity", "xxe"]),
        ("deserialization", ["deserialization", "deserialize untrusted"]),
        ("auth_session", ["authentication", "session", "cookie"]),
        ("race", ["race condition", "concurrent", "time-of-check", "time of check", "toctou"]),
    ]
    for label, needles in checks:
        if any(n in blob for n in needles):
            return label
    return "generic"


def archetype_profile(archetype: str) -> dict[str, list[str]]:
    profiles: dict[str, dict[str, list[str]]] = {
        "oob_write": {
            "sources": ["external length/index value", "allocation-size mismatch"],
            "sinks": ["write/copy sink", "array/pointer write"],
            "fix": ["add bounds check", "clamp size/index", "repair allocation arithmetic"],
            "vuln_patterns": ["write sink + unchecked length/index", "capacity smaller than write amount"],
            "fix_patterns": ["if (len > cap)", "checked allocation", "safe wrapper around copy/write"],
            "guards": ["same function scope", "sink and bound variables co-occur"],
            "scope": ["function", "basic_block", "anchor_window"],
            "good_kinds": ["ordered_tokens", "proximity", "token_all"],
            "bad_kinds": ["token_any", "regex"],
        },
        "oob_read": {
            "sources": ["external length/index value", "loop bound from untrusted field"],
            "sinks": ["read/copy-out sink", "array/pointer read"],
            "fix": ["add bounds check", "limit read length", "validate header/body size relation"],
            "vuln_patterns": ["read sink + unchecked range", "loop bound exceeds container size"],
            "fix_patterns": ["if (off + len > size)", "reject truncated input", "cap loop bound"],
            "guards": ["same data structure scope", "read target and bound variables co-occur"],
            "scope": ["function", "basic_block", "anchor_window"],
            "good_kinds": ["ordered_tokens", "proximity", "token_all"],
            "bad_kinds": ["token_any", "regex"],
        },
        "uaf": {
            "sources": ["freed object reused on later path", "lifetime mismatch across branches"],
            "sinks": ["dereference after free", "method call after release"],
            "fix": ["null/reset pointer", "reorder free/use", "add ownership guard"],
            "vuln_patterns": ["free/release followed by later use", "missing lifetime guard"],
            "fix_patterns": ["ptr = NULL", "reference count guard", "move free after last use"],
            "guards": ["same object identity", "same control-flow region"],
            "scope": ["function", "control_flow_region", "anchor_window"],
            "good_kinds": ["ordered_tokens", "proximity"],
            "bad_kinds": ["token_any"],
        },
        "double_free": {
            "sources": ["duplicate cleanup path", "error path re-release"],
            "sinks": ["second free/release call"],
            "fix": ["idempotent cleanup guard", "null/reset after free", "single ownership check"],
            "vuln_patterns": ["same resource freed twice", "cleanup called on already released object"],
            "fix_patterns": ["if (ptr != NULL)", "state flag before free", "ptr = NULL after free"],
            "guards": ["same pointer/resource identity"],
            "scope": ["function", "control_flow_region"],
            "good_kinds": ["ordered_tokens", "proximity"],
            "bad_kinds": ["token_any"],
        },
        "null_deref": {
            "sources": ["unchecked return value", "optional allocation/use path"],
            "sinks": ["dereference/call through possibly-null pointer"],
            "fix": ["null check", "early return", "fallback path"],
            "vuln_patterns": ["pointer use without preceding null check"],
            "fix_patterns": ["if (!ptr)", "if (ptr == NULL)", "return error on null"],
            "guards": ["same pointer variable in check and use"],
            "scope": ["function", "basic_block", "anchor_window"],
            "good_kinds": ["ordered_tokens", "proximity", "token_all"],
            "bad_kinds": ["regex"],
        },
        "int_overflow": {
            "sources": ["unchecked arithmetic on size/count", "signed/unsigned conversion"],
            "sinks": ["allocation or copy size derived from overflowed result"],
            "fix": ["checked arithmetic", "widen type", "range guard before multiplication/addition"],
            "vuln_patterns": ["size/count arithmetic without overflow guard"],
            "fix_patterns": ["checked_mul", "safe_add", "if (a > MAX / b)"],
            "guards": ["arithmetic operands and sink must co-occur"],
            "scope": ["function", "anchor_window"],
            "good_kinds": ["ordered_tokens", "proximity"],
            "bad_kinds": ["token_any", "regex"],
        },
        "generic": {
            "sources": ["untrusted or insufficiently validated state reaches sensitive operation"],
            "sinks": ["security-relevant operation"],
            "fix": ["add explicit validation", "constrain state before sink", "fail closed on invalid condition"],
            "vuln_patterns": ["security-sensitive sink without sufficient guard"],
            "fix_patterns": ["explicit validation before sink", "reject invalid state", "safe helper/wrapper"],
            "guards": ["same logical object and same sink context"],
            "scope": ["function", "anchor_window"],
            "good_kinds": ["ordered_tokens", "proximity", "token_all"],
            "bad_kinds": ["token_any"],
        },
    }
    return profiles.get(archetype, profiles["generic"])


def build_stage_hints(archetype: str) -> dict[str, dict[str, list[str] | str]]:
    profile = archetype_profile(archetype)
    return {
        "stage1": {
            "goal": "Classify patch chunks by how directly they repair the CWE root cause.",
            "must_focus": [
                "direct change to vulnerable sink or validation site",
                "changes that alter boundary, lifecycle, policy, or authorization relation",
                "supporting helper or error-propagation logic needed by the main fix",
            ],
            "must_avoid": [
                "comment-only or naming-only changes",
                "generic logging changes without security semantics",
                "refactors unrelated to the sensitive sink/path",
            ],
            "recommended_queries": profile["vuln_patterns"][:2] + profile["fix_patterns"][:2],
        },
        "stage2": {
            "goal": "Construct discriminative root cause, anchor, predicates, and guards.",
            "must_focus": [
                "anchor at the sink or dominant validation block",
                "prefer predicates that encode relations, not lone generic tokens",
                "choose function-local or anchor-window scope whenever possible",
            ],
            "must_avoid": [
                "whole-repo unscoped token matches",
                "predicates that rely on generic names alone",
                "anchors in wrappers that lack the core vulnerability mechanism",
            ],
            "recommended_queries": profile["vuln_patterns"][:2] + profile["guards"][:2],
        },
        "stage3": {
            "goal": "Verify whether the target tag still exhibits the vulnerable relation or already contains the fix relation.",
            "must_focus": [
                "whether the sensitive sink/path still exists",
                "whether the fix relation is locally present in the same code region",
                "whether anchor relocation is required before concluding absence",
            ],
            "must_avoid": [
                "declaring NOT_AFFECTED from generic token absence alone",
                "assuming refactor/rename means vulnerability removal",
                "using broad token matches as final evidence",
            ],
            "recommended_queries": profile["fix_patterns"][:2] + profile["vuln_patterns"][:2],
        },
    }


def build_meta(
    weakness: ET.Element,
    *,
    source_xml: str,
    catalog_version: str,
    generated_at: str,
) -> dict:
    cwe_num = weakness.attrib["ID"]
    cwe_id = f"CWE-{cwe_num}"
    name = clean_text(weakness.attrib.get("Name"))
    abstraction = clean_text(weakness.attrib.get("Abstraction")) or "Unknown"
    status = clean_text(weakness.attrib.get("Status"))
    description = node_text(weakness.find("cwe:Description", NS))
    extended = node_text(weakness.find("cwe:Extended_Description", NS))
    archetype = classify_archetype(name, description, extended)
    profile = archetype_profile(archetype)

    relationships = {"parents": [], "children": [], "peers": []}
    for rel in weakness.findall("cwe:Related_Weaknesses/cwe:Related_Weakness", NS):
        item = {
            "cwe_id": f"CWE-{clean_text(rel.attrib.get('CWE_ID'))}",
            "nature": clean_text(rel.attrib.get("Nature")),
            "view_id": clean_text(rel.attrib.get("View_ID")) or None,
            "ordinal": clean_text(rel.attrib.get("Ordinal")) or None,
            "name": None,
        }
        nature = item["nature"].lower()
        if nature == "childof":
            relationships["parents"].append(item)
        elif nature == "parentof":
            relationships["children"].append(item)
        else:
            relationships["peers"].append(item)

    languages: list[str] = []
    technologies: list[str] = []
    architectures: list[str] = []
    paradigms: list[str] = []
    for lang in weakness.findall("cwe:Applicable_Platforms/cwe:Language", NS):
        languages.append(clean_text(lang.attrib.get("Name") or lang.attrib.get("Class")))
    for tech in weakness.findall("cwe:Applicable_Platforms/cwe:Technology", NS):
        technologies.append(clean_text(tech.attrib.get("Name") or tech.attrib.get("Class")))
    for arch in weakness.findall("cwe:Applicable_Platforms/cwe:Architecture", NS):
        architectures.append(clean_text(arch.attrib.get("Name") or arch.attrib.get("Class")))
    for par in weakness.findall("cwe:Applicable_Platforms/cwe:Paradigm", NS):
        paradigms.append(clean_text(par.attrib.get("Name") or par.attrib.get("Class")))

    phases = unique_keep_order([
        node_text(p)
        for p in weakness.findall("cwe:Modes_Of_Introduction/cwe:Introduction/cwe:Phase", NS)
    ])

    usage = node_text(weakness.find("cwe:Mapping_Notes/cwe:Usage", NS))
    fit = node_text(weakness.find("cwe:Mapping_Notes/cwe:Reasons/cwe:Reason", NS))
    rationale = node_text(weakness.find("cwe:Mapping_Notes/cwe:Rationale", NS))

    mitigations = unique_keep_order([
        short_sentence(node_text(m.find("cwe:Description", NS)), limit=180)
        for m in weakness.findall("cwe:Potential_Mitigations/cwe:Mitigation", NS)
        if node_text(m.find("cwe:Description", NS))
    ])[:6]

    bad_examples = []
    good_examples = []
    for ex in weakness.findall("cwe:Demonstrative_Examples/cwe:Demonstrative_Example", NS):
        intro = short_sentence(node_text(ex.find("cwe:Intro_Text", NS)), limit=160)
        for code in ex.findall("cwe:Example_Code", NS):
            nature = clean_text(code.attrib.get("Nature"))
            language = clean_text(code.attrib.get("Language")) or None
            snippet = short_sentence(node_text(code), limit=220)
            item = {
                "language": language,
                "nature": nature or None,
                "summary": intro or short_sentence(description, limit=160),
                "snippet": snippet or None,
            }
            if nature.lower() == "good":
                good_examples.append(item)
            elif nature.lower() == "bad":
                bad_examples.append(item)

    observed_examples = []
    for ex in weakness.findall("cwe:Observed_Examples/cwe:Observed_Example", NS)[:6]:
        observed_examples.append({
            "reference": node_text(ex.find("cwe:Reference", NS)),
            "description": short_sentence(node_text(ex.find("cwe:Description", NS)), limit=220),
            "link": node_text(ex.find("cwe:Link", NS)) or None,
        })

    terms = significant_terms(name, description, extended, limit=10)
    preferred_tokens = [t for t in terms if t not in GENERIC_DANGEROUS_TOKENS][:8]

    return {
        "cwe_id": cwe_id,
        "name": name,
        "abstraction": abstraction,
        "status": status,
        "description": description,
        "extended_description": extended,
        "relationships": relationships,
        "applicable_platforms": {
            "languages": unique_keep_order(languages),
            "technologies": unique_keep_order(technologies),
            "architectures": unique_keep_order(architectures),
            "paradigms": unique_keep_order(paradigms),
        },
        "introduction_phases": phases,
        "likelihood_of_exploit": node_text(weakness.find("cwe:Likelihood_Of_Exploit", NS)) or "Unknown",
        "mapping": {
            "usage": usage,
            "fit": fit,
            "rationale": rationale,
        },
        "mechanism": {
            "root_cause_summary": short_sentence(description or name, limit=220),
            "typical_preconditions": unique_keep_order(profile["sources"] + phases)[:6],
            "typical_sources": profile["sources"][:6],
            "typical_sinks": profile["sinks"][:6],
            "typical_fix_actions": profile["fix"][:6],
            "negative_nonfix_signals": [
                "comment-only change",
                "rename-only change",
                "logging-only change",
                "style refactor without changing the sensitive path",
            ],
        },
        "code_signals": {
            "vuln_search_patterns": unique_keep_order(profile["vuln_patterns"] + preferred_tokens[:4])[:8],
            "fix_search_patterns": profile["fix_patterns"][:8],
            "guard_patterns": profile["guards"][:6],
            "dangerous_generic_tokens": GENERIC_DANGEROUS_TOKENS,
            "preferred_distinctive_tokens": preferred_tokens,
        },
        "predicate_priors": {
            "preferred_scope": profile["scope"][:6],
            "good_predicate_kinds": profile["good_kinds"][:6],
            "discouraged_predicate_kinds": profile["bad_kinds"][:6],
            "recommended_guard_templates": profile["guards"][:6],
            "recommended_predicate_templates": unique_keep_order(
                profile["vuln_patterns"] + profile["fix_patterns"]
            )[:8],
        },
        "stage_hints": build_stage_hints(archetype),
        "examples": {
            "bad_examples": bad_examples[:4],
            "good_examples": good_examples[:4],
            "observed_examples": observed_examples,
        },
        "repo_notes": {},
        "evolution": {
            "usage_count": 0,
            "success_count": 0,
            "fp_lessons": [],
            "fn_lessons": [],
            "last_updated": None,
        },
        "metadata": {
            "source_xml": source_xml,
            "catalog_version": catalog_version,
            "generated_at": generated_at,
        },
    }


def format_bullets(items: list[str], fallback: str) -> str:
    items = [clean_text(x) for x in items if clean_text(x)]
    if not items:
        items = [fallback]
    return "\n".join(f"- {x}" for x in items)


def format_queries(items: list[str], fallback: str) -> str:
    items = [clean_text(x) for x in items if clean_text(x)]
    if not items:
        items = [fallback]
    return "\n".join(f"- {x}" for x in items)


def render_sections(parts: list[str]) -> str:
    return "\n".join(part.rstrip() for part in parts if part is not None).strip() + "\n"


def render_stage1(meta: dict) -> str:
    return render_sections([
        f"# {meta['cwe_id']} Stage 1 View",
        f"Name: {meta['name']}",
        "",
        "## Goal",
        "",
        "在 patch chunk 级别判断哪些改动最可能直接修复了该 CWE 的根因，哪些只是支撑性修改，哪些只是上下文或无关改动。",
        "",
        "## Mechanism Summary",
        "",
        meta["mechanism"]["root_cause_summary"],
        "",
        "## PRIMARY_FIX Signals",
        "",
        format_bullets(meta["mechanism"]["typical_fix_actions"], "Directly changes the vulnerable relation or dominant validation site."),
        "",
        "## SUPPORTING_FIX Signals",
        "",
        "- Introduces helpers, wrappers, or state propagation needed by the main fix\n"
        "- Adds error handling or early return logic that makes the main fix effective\n"
        "- Refactors data/control flow so the primary validation can dominate the sink/path",
        "",
        "## CONTEXTUAL_CHANGE Signals",
        "",
        format_bullets(meta["mechanism"]["negative_nonfix_signals"], "Context-only edits that do not change the security relation."),
        "",
        "## High-Value Clues",
        "",
        format_bullets(meta["code_signals"]["preferred_distinctive_tokens"], "Prefer tokens tied to the sensitive sink/path rather than generic variables."),
        "",
        "## Dangerous Generic Tokens",
        "",
        "以下 token 过于常见，不能单独作为 chunk 角色判断依据：",
        "",
        format_bullets(meta["code_signals"]["dangerous_generic_tokens"], "Avoid generic tokens without relation to the sink/path."),
        "",
        "## Stage 1 Focus",
        "",
        format_bullets(meta["stage_hints"]["stage1"]["must_focus"], "Focus on whether the chunk changes the core vulnerability mechanism."),
        "",
        "## Stage 1 Avoid",
        "",
        format_bullets(meta["stage_hints"]["stage1"]["must_avoid"], "Avoid over-weighting comments, formatting, or broad refactors."),
    ])


def render_stage2(meta: dict) -> str:
    return render_sections([
        f"# {meta['cwe_id']} Stage 2 View",
        f"Name: {meta['name']}",
        "",
        "## Goal",
        "",
        "为 RCI 构造提供结构化先验，重点指导 root cause、anchor、predicate、guard 和 scope 的选择。",
        "",
        "## Root Cause Template",
        "",
        "推荐围绕以下机制写 root cause：",
        "",
        format_bullets(meta["mechanism"]["typical_preconditions"], "Describe how insufficient validation reaches a sensitive sink/path."),
        "",
        "典型敏感 sink/path：",
        "",
        format_bullets(meta["mechanism"]["typical_sinks"], "Use the sink or dominant validation block as the anchor center."),
        "",
        "## Preferred Anchor",
        "",
        "- Prefer the function, block, or local region where the sensitive relation is visible\n"
        "- Prefer code where the sink/path and its guarding relation can be observed together\n"
        "- Avoid anchoring on wrappers that hide the vulnerability mechanism",
        "",
        "## Preferred Predicate Kinds",
        "",
        format_bullets(meta["predicate_priors"]["good_predicate_kinds"], "Use predicate kinds that encode relation rather than loose presence."),
        "",
        "## Discouraged Predicate Kinds",
        "",
        format_bullets(meta["predicate_priors"]["discouraged_predicate_kinds"], "Avoid predicate kinds that are too permissive for this CWE."),
        "",
        "## Preferred Scope",
        "",
        format_bullets(meta["predicate_priors"]["preferred_scope"], "Use local scope whenever possible."),
        "",
        "## Recommended Predicate Templates",
        "",
        format_bullets(meta["predicate_priors"]["recommended_predicate_templates"], "Prefer templates that tie the sensitive sink/path to its guarding relation."),
        "",
        "## Recommended Guard Templates",
        "",
        format_bullets(meta["predicate_priors"]["recommended_guard_templates"], "Use guards that constrain matches to the same code relation."),
        "",
        "## Dangerous Generic Tokens",
        "",
        "以下 token 不能单独构成 predicate：",
        "",
        format_bullets(meta["code_signals"]["dangerous_generic_tokens"], "Generic tokens require co-occurring relation evidence."),
        "",
        "## Stage 2 Focus",
        "",
        format_bullets(meta["stage_hints"]["stage2"]["must_focus"], "Make predicates discriminative and scoped."),
        "",
        "## Stage 2 Avoid",
        "",
        format_bullets(meta["stage_hints"]["stage2"]["must_avoid"], "Avoid unscoped whole-repo token matches and generic anchors."),
    ])


def render_stage3(meta: dict) -> str:
    return render_sections([
        f"# {meta['cwe_id']} Stage 3 View",
        f"Name: {meta['name']}",
        "",
        "## Goal",
        "",
        "在单个 tag 上验证该版本是否仍然表现出该 CWE 的危险关系，或是否已经包含足够强的修复关系。",
        "",
        "## Verification Strategy",
        "",
        "推荐搜索顺序：",
        "",
        format_queries(meta["stage_hints"]["stage3"]["recommended_queries"], "Search the sensitive sink/path first, then verify whether the guarding relation is present."),
        "",
        "## High-Signal Vulnerable Evidence",
        "",
        format_bullets(meta["code_signals"]["vuln_search_patterns"], "Sensitive sink/path still exists without sufficient guarding relation."),
        "",
        "## High-Signal Fixed Evidence",
        "",
        format_bullets(meta["code_signals"]["fix_search_patterns"], "Fix relation is locally present in the same code region as the sink/path."),
        "",
        "## Guard Checks",
        "",
        format_bullets(meta["code_signals"]["guard_patterns"], "Require the same logical object/path and same local region."),
        "",
        "## Dangerous Generic Tokens",
        "",
        "以下 token 不能单独支持 `NOT_AFFECTED`：",
        "",
        format_bullets(meta["code_signals"]["dangerous_generic_tokens"], "Do not conclude safety from generic token absence alone."),
        "",
        "## Stage 3 Focus",
        "",
        format_bullets(meta["stage_hints"]["stage3"]["must_focus"], "Verify local evidence around the relocated anchor."),
        "",
        "## Stage 3 Avoid",
        "",
        format_bullets(meta["stage_hints"]["stage3"]["must_avoid"], "Do not treat rename/refactor as proof of safety."),
    ])


def render_family_doc(cwe_id: str, meta: dict, children: list[dict]) -> str:
    child_lines = "\n".join(
        f"- `{child['cwe_id']}`: {child['name']} ({child['abstraction']})"
        for child in sorted(children, key=lambda x: x["cwe_id"])
    )
    return render_sections([
        f"# {cwe_id} Family View",
        f"Name: {meta['name']}",
        "",
        "## Family Summary",
        "",
        meta["mechanism"]["root_cause_summary"],
        "",
        "## Use This Family View When",
        "",
        "- only a broad CWE family is known\n"
        "- you need to choose a more specific child CWE before loading a stage file\n"
        "- the available CVE metadata is vague or only maps to a parent class",
        "",
        "## Children",
        "",
        child_lines if child_lines else "- No child weaknesses were generated for this family.",
    ])


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, payload: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def generate(xml_path: Path, output_root: Path, *, clean: bool) -> dict:
    if clean and output_root.exists():
        for child in output_root.iterdir():
            if child.name == "meta.schema.json":
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()

    output_root.mkdir(parents=True, exist_ok=True)
    by_id_root = output_root / "by-id"
    by_family_root = output_root / "by-family"

    tree = ET.parse(xml_path)
    root = tree.getroot()
    catalog_version = root.attrib.get("Version", "unknown")
    generated_at = datetime.now(timezone.utc).isoformat()

    weakness_nodes = root.findall("cwe:Weaknesses/cwe:Weakness", NS)
    entries: dict[str, dict] = {}
    for weakness in weakness_nodes:
        meta = build_meta(
            weakness,
            source_xml=xml_path.name,
            catalog_version=catalog_version,
            generated_at=generated_at,
        )
        entries[meta["cwe_id"]] = meta

    for meta in entries.values():
        for bucket in ("parents", "children", "peers"):
            for rel in meta["relationships"][bucket]:
                target = entries.get(rel["cwe_id"])
                if target:
                    rel["name"] = target["name"]

    for cwe_id, meta in sorted(entries.items()):
        base = by_id_root / cwe_id
        write_json(base / "meta.json", meta)
        write_text(base / "stage1.md", render_stage1(meta))
        write_text(base / "stage2.md", render_stage2(meta))
        write_text(base / "stage3.md", render_stage3(meta))

    child_map: dict[str, dict[str, dict]] = defaultdict(dict)
    for meta in entries.values():
        for rel in meta["relationships"]["parents"]:
            parent = entries.get(rel["cwe_id"])
            if parent:
                child_map[parent["cwe_id"]][meta["cwe_id"]] = {
                    "cwe_id": meta["cwe_id"],
                    "name": meta["name"],
                    "abstraction": meta["abstraction"],
                }

    for family_id, children in sorted(child_map.items()):
        family_meta = entries[family_id]
        write_text(by_family_root / f"{family_id}.md", render_family_doc(family_id, family_meta, list(children.values())))

    index_payload = {
        "catalog_version": catalog_version,
        "generated_at": generated_at,
        "source_xml": xml_path.name,
        "counts": {
            "weaknesses": len(entries),
            "families": len(child_map),
        },
        "skills": [
            {
                "cwe_id": meta["cwe_id"],
                "name": meta["name"],
                "abstraction": meta["abstraction"],
                "status": meta["status"],
                "paths": {
                    "meta": f"references/by-id/{meta['cwe_id']}/meta.json",
                    "stage1": f"references/by-id/{meta['cwe_id']}/stage1.md",
                    "stage2": f"references/by-id/{meta['cwe_id']}/stage2.md",
                    "stage3": f"references/by-id/{meta['cwe_id']}/stage3.md"
                }
            }
            for meta in sorted(entries.values(), key=lambda x: x["cwe_id"])
        ]
    }
    write_json(output_root / "index.json", index_payload)
    return index_payload["counts"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate structured CWE skill tree from CWE-2000 XML.")
    parser.add_argument("--xml", required=True, help="Path to CWE-2000.xml")
    parser.add_argument("--out", required=True, help="Output directory, usually CWESkills/references")
    parser.add_argument("--clean", action="store_true", help="Delete previously generated docs before writing new ones")
    args = parser.parse_args()

    xml_path = Path(args.xml).resolve()
    out_path = Path(args.out).resolve()
    counts = generate(xml_path, out_path, clean=bool(args.clean))
    print(json.dumps({"ok": True, **counts}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

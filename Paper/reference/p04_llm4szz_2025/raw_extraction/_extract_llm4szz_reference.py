from __future__ import annotations

import ast
import csv
import json
import os
import re
from datetime import datetime
from pathlib import Path

from pypdf import PdfReader


PAPER_ID = "p04_llm4szz_2025"
TITLE = "LLM4SZZ: Enhancing SZZ Algorithm with Context-Enhanced Assessment on Large Language Models"
YEAR = "2025"
AUTHORS = ["Lingxiao Tang", "Jiakun Liu", "Zhongxin Liu", "Xiaohu Yang", "Lingfeng Bao"]
ROOT = Path(r"E:\AI\Agent\workflow\Paper\reference") / PAPER_ID
RAW = ROOT / "raw_extraction"
INPUT_ROOT = Path(r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\LLM4SZZ")
SOURCE = INPUT_ROOT / "LLM4SZZ"


def long_path(path: Path) -> str:
    text = str(path)
    if os.name == "nt" and not text.startswith("\\\\?\\"):
        return "\\\\?\\" + text
    return text


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def read_text(path: Path, limit: int | None = None) -> str:
    text = Path(long_path(path)).read_text(encoding="utf-8", errors="replace")
    return text if limit is None else text[:limit]


def stable_id(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", text.strip().lower()).strip("_")[:70] or "unit"


def find_pdf() -> Path:
    pdfs = list(INPUT_ROOT.glob("*.pdf"))
    if len(pdfs) != 1:
        raise RuntimeError(f"expected one PDF, found {len(pdfs)}")
    return pdfs[0]


def extract_pdf(pdf: Path) -> dict:
    reader = PdfReader(long_path(pdf))
    pages = []
    empty = []
    page_dir = RAW / "page_text"
    page_dir.mkdir(parents=True, exist_ok=True)
    for idx, page in enumerate(reader.pages, 1):
        text = page.extract_text() or ""
        if not text.strip():
            empty.append(idx)
        pages.append(text)
        write(page_dir / f"page_{idx:03d}.txt", text)
    write(RAW / "full_text.txt", "\n\n".join(f"===== PAGE {i:03d} =====\n{text}" for i, text in enumerate(pages, 1)))
    return {
        "page_count": len(reader.pages),
        "empty_pages": empty,
        "metadata": {str(k): str(v) for k, v in (reader.metadata or {}).items()},
        "pages": pages,
    }


SECTION_RANGES = [
    ("01_abstract.txt", "Abstract", r"(?m)^LLM4SZZ:.*?Large Language Models.*?\n", r"(?m)^1\s+Introduction$"),
    ("02_introduction.txt", "1 Introduction", r"(?m)^1\s+Introduction$", r"(?m)^2\s+Background$"),
    ("03_background.txt", "2 Background", r"(?m)^2\s+Background$", r"(?m)^3\s+Approach$"),
    ("04_method.txt", "3 Approach", r"(?m)^3\s+Approach$", r"(?m)^4\s+Experiment Setup$"),
    ("05_experiments.txt", "4 Experiment Setup", r"(?m)^4\s+Experiment Setup$", r"(?m)^5\s+Experiment Results$"),
    ("06_evaluation.txt", "5 Experiment Results", r"(?m)^5\s+Experiment Results$", r"(?m)^6\s+Discussion$"),
    ("08_limitations.txt", "6 Discussion / Threats", r"(?m)^6\s+Discussion$", r"(?m)^7\s+Related Work$"),
    ("07_related_work.txt", "7 Related Work", r"(?m)^7\s+Related Work$", r"(?m)^8\s+Conclusion and Future Work$"),
    ("09_conclusion.txt", "8 Conclusion and Future Work", r"(?m)^8\s+Conclusion and Future Work$", r"(?m)^9\s+Acknowledgement$"),
    ("10_references.txt", "References", r"(?m)^References$", r"$^"),
]


def split_sections(full_text: str) -> list[dict]:
    out = []
    for filename, label, start_pat, end_pat in SECTION_RANGES:
        matches = list(re.finditer(start_pat, full_text, re.IGNORECASE | re.MULTILINE | re.DOTALL))
        start = matches[-1] if label == "References" and matches else (matches[0] if matches else None)
        if not start:
            out.append({"label": label, "file": filename, "status": "[NEEDS SECTION SPLIT]"})
            continue
        tail = full_text[start.end():]
        end = None if end_pat == r"$^" else re.search(end_pat, tail, re.IGNORECASE | re.MULTILINE)
        end_pos = start.end() + end.start() if end else len(full_text)
        body = full_text[start.start():end_pos].strip()
        write(RAW / "section_text" / filename, body)
        out.append({"label": label, "file": f"section_text/{filename}", "status": "extracted", "chars": len(body)})
    lines = ["Section Split Status: heuristic from extracted PDF headings", ""]
    for s in out:
        lines.append(f"- {s['label']}: {s['status']} -> {s.get('file', '')} chars={s.get('chars', '')}")
    write(RAW / "sections.txt", "\n".join(lines) + "\n")
    ref = RAW / "section_text" / "10_references.txt"
    write(RAW / "references.txt", ref.read_text(encoding="utf-8") if ref.exists() else "[NEEDS CITATION VERIFICATION]\n")
    return out


def extract_caption_units(pages: list[str]) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    figures, tables, algorithms, prompts = [], [], [], []
    for page_no, text in enumerate(pages, 1):
        compact = re.sub(r"\s+", " ", text)
        for m in re.finditer(r"((?:Fig\.|Figure)\s*\d+[:.]\s+.{20,320}?)(?=(?:Fig\.|Figure|Table|Algorithm|Listing|\s[A-Z][a-z]+ \d|$))", compact):
            cap = m.group(1).strip()
            fid = f"figure_{len(figures)+1:03d}"
            write(RAW / "figures" / f"{fid}_caption.txt", cap + "\n")
            write(RAW / "figures" / f"{fid}_context.txt", compact[max(0, m.start()-400):m.end()+500] + "\n")
            write(RAW / "figures" / f"{fid}_agent_summary.txt", f"Caption/context-only evidence. [NEEDS FIGURE EXTRACTION]\nCaption: {cap}\n")
            figures.append({"id": fid, "page": page_no, "caption": cap})
        for m in re.finditer(r"(Table\s+\d+[:.]\s+.{20,420}?)(?=(?:Fig\.|Figure|Table|Algorithm|Listing|\s[A-Z][a-z]+ \d|$))", compact):
            cap = m.group(1).strip()
            tid = f"table_{len(tables)+1:03d}"
            raw = compact[max(0, m.start()-600):m.end()+900]
            write(RAW / "tables" / f"{tid}_raw.txt", raw + "\n[NEEDS TABLE REPAIR]\n")
            write(RAW / "tables" / f"{tid}.md", f"| Field | Value |\n| --- | --- |\n| Page | {page_no} |\n| Caption | {cap} |\n| Status | caption/context only; [NEEDS TABLE REPAIR] |\n")
            with (RAW / "tables" / f"{tid}.csv").open("w", encoding="utf-8", newline="") as fh:
                writer = csv.writer(fh)
                writer.writerow(["field", "value"])
                writer.writerow(["page", page_no])
                writer.writerow(["caption", cap])
                writer.writerow(["status", "[NEEDS TABLE REPAIR]"])
            write(RAW / "tables" / f"{tid}_cells.json", json.dumps({"page": page_no, "caption": cap, "cells": [], "repair_needed": True}, indent=2))
            tables.append({"id": tid, "page": page_no, "caption": cap})
        for m in re.finditer(r"(Algorithm\s+\d+[:.]\s+.{20,700}?)(?=(?:Fig\.|Figure|Table|Algorithm|\s[A-Z][a-z]+ \d|$))", compact):
            aid = f"algorithm_{len(algorithms)+1:03d}"
            raw = m.group(1).strip()
            write(RAW / "algorithms" / f"{aid}.txt", f"ID: {aid}\nPage: {page_no}\nRaw Extracted Text:\n{raw}\nExtraction Confidence: partial\nRepair Needed: [NEEDS ALGORITHM REPAIR]\n")
            algorithms.append({"id": aid, "page": page_no, "anchor": raw[:140]})
        if re.search(r"\bprompt\b|LLM\b.*\banswer\b|rank\b.*buggy", compact, re.IGNORECASE):
            pid = f"prompt_{len(prompts)+1:03d}"
            snippet = compact[:1800]
            write(RAW / "prompts" / f"{pid}.txt", f"ID: {pid}\nPage: {page_no}\nRaw Extracted Text / Context:\n{snippet}\nExtraction Confidence: partial\nRepair Needed: [NEEDS PROMPT REPAIR]\n")
            prompts.append({"id": pid, "page": page_no, "anchor": snippet[:140]})
    write(RAW / "figures" / "figure_index.txt", "\n".join(f"- {f['id']}: page {f['page']}; {f['caption']} [NEEDS FIGURE EXTRACTION]" for f in figures) + "\n")
    write(RAW / "tables" / "table_index.txt", "\n".join(f"- {t['id']}: page {t['page']}; {t['caption']} [NEEDS TABLE REPAIR]" for t in tables) + "\n")
    write(RAW / "algorithms" / "algorithm_index.txt", "\n".join(f"- {a['id']}: page {a['page']}; {a['anchor']} [NEEDS ALGORITHM REPAIR]" for a in algorithms) + ("\n" if algorithms else "No algorithm blocks confidently extracted. [NEEDS ALGORITHM REPAIR]\n"))
    write(RAW / "prompts" / "prompt_index.txt", "\n".join(f"- {p['id']}: page {p['page']}; {p['anchor']} [NEEDS PROMPT REPAIR]" for p in prompts) + ("\n" if prompts else "Prompt mentions not detected. [NEEDS PROMPT REPAIR]\n"))
    return figures, tables, algorithms, prompts


def inspect_source() -> dict:
    files, dirs = [], []
    for path in SOURCE.rglob("*"):
        rel = path.relative_to(SOURCE)
        if ".git" in rel.parts or "__pycache__" in rel.parts:
            continue
        if path.is_dir():
            dirs.append(str(rel))
        else:
            files.append({"path": str(rel), "size": path.stat().st_size, "ext": path.suffix.lower()})
    py = []
    for item in files:
        if item["ext"] != ".py":
            continue
        path = SOURCE / item["path"]
        text = read_text(path)
        try:
            tree = ast.parse(text)
            funcs = [n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
            imports = []
            calls = []
            strings = []
            for n in ast.walk(tree):
                if isinstance(n, ast.Import):
                    imports.extend(a.name for a in n.names)
                elif isinstance(n, ast.ImportFrom):
                    imports.append(n.module or "")
                elif isinstance(n, ast.Call):
                    func = n.func
                    if isinstance(func, ast.Name):
                        calls.append(func.id)
                    elif isinstance(func, ast.Attribute):
                        calls.append(func.attr)
                elif isinstance(n, ast.Constant) and isinstance(n.value, str):
                    val = n.value.strip()
                    if any(k in val.lower() for k in ["prompt", "llm", "blame", "dataset", "save_logs", "candidate", "version"]):
                        strings.append(val[:220])
            py.append({
                "path": item["path"],
                "lines": text.count("\n") + 1,
                "functions": funcs[:40],
                "classes": classes[:20],
                "imports": sorted(set(i for i in imports if i))[:35],
                "calls": sorted(set(calls))[:60],
                "notable_strings": strings[:12],
            })
        except SyntaxError as exc:
            py.append({"path": item["path"], "parse_error": str(exc)})
    samples = {}
    for name in ["README.md", "requirements.txt", "constant.py", "dataset/FFmpeg_dataset_fa.json", "time.txt"]:
        path = SOURCE / name
        if path.exists():
            samples[name] = read_text(path, 6000)
    inv = {"source_path": str(SOURCE), "directories": dirs, "files": files, "python": py, "samples": samples}
    write(RAW / "source_static_inventory.json", json.dumps(inv, indent=2, ensure_ascii=False))
    lines = [
        f"Source Path: {SOURCE}",
        "Analysis Mode: static-only",
        "Runtime Behavior: [EXECUTION NOT REQUESTED]",
        "",
        "Repository / File Layout Observed:",
    ]
    for d in dirs:
        lines.append(f"- dir: {d}")
    for f in files:
        lines.append(f"- file: {f['path']} ({f['size']} bytes)")
    lines += ["", "Primary Files:"]
    for p in py:
        lines.append(f"- {p['path']}: lines={p.get('lines', '[NEEDS EVIDENCE]')}; functions={', '.join(p.get('functions', [])[:16]) or '[NEEDS EVIDENCE]'}; imports={', '.join(p.get('imports', [])[:12]) or '[NEEDS EVIDENCE]'}")
    lines += [
        "",
        "Key Static Evidence:",
        "- README.md and requirements.txt are present.",
        "- Dataset directory is present with FFmpeg_dataset_fa.json.",
        "- Script sequence names suggest input preparation, VCC extraction, vulnerable-version generation, duplicated patch detection, and result parsing.",
        "- LLM-specific scripts are visible: gen_results_for_dels_llm.py and gen_results_for_no_dels_llm.py.",
        "- Baseline and V-SZZ comparison scripts are visible: gen_baseline_results_for_* and gen_results_for_*_vszz.py.",
        "- Core SZZ support is visible under core/abstract_szz.py, core/vszz.py, and core/comment_parser.py.",
        "- version_range_evidence.py and 3_gen_vuln_version.py indicate affected-version/version-range post-processing artifacts.",
        "",
        "Static Consistency Notes:",
        "- Static layout partially supports the paper claim that LLM4SZZ combines LLM assessment with SZZ-style candidate tracing.",
        "- Runtime behavior, prompts sent to models, API outputs, and benchmark reproduction were not checked. [EXECUTION NOT REQUESTED]",
        "- Completeness of required precomputed save_logs/model outputs is not verified. [NEEDS ARTIFACT]",
        "- The artifact appears to include post-processing for affected versions, which is adjacent to but distinct from paper-level SZZ evaluation.",
        "",
        "Observed Local Output / Data Artifacts:",
    ]
    for f in files:
        if f["ext"] in [".json", ".txt", ".csv", ".md"]:
            lines.append(f"- {f['path']} ({f['size']} bytes)")
    lines += [
        "",
        "Missing Data / Missing Entrypoints:",
        "- End-to-end execution was not requested. [EXECUTION NOT REQUESTED]",
        "- External repositories, full benchmark data, model outputs, API keys, and generated save_logs are not verified in this pass. [NEEDS ARTIFACT]",
    ]
    write(RAW / "source_static_inventory.txt", "\n".join(lines) + "\n")
    return inv


def write_manifest_metadata(pdf: Path, info: dict) -> None:
    write(RAW / "00_source_manifest.txt", f"""Paper ID: {PAPER_ID}
Original PDF Path: {pdf}
Original Text Path: {RAW / 'full_text.txt'}
Source Code Path or URL: {SOURCE}
Artifact/Data Path or URL: {SOURCE}
Extraction Date: {datetime.now().isoformat(timespec='seconds')}
Extraction Tools: pypdf text extraction; Python static AST/file inventory
Artifact Type: Type A
Notes: Static analysis only; no dependency installation, code execution, script execution, model calls, or experiment reproduction.
""")
    metadata = {
        "paper_id": PAPER_ID,
        "title": TITLE,
        "authors": AUTHORS,
        "venue": "Proc. ACM Softw. Eng.",
        "year": YEAR,
        "doi": "",
        "arxiv": "",
        "pdf_path": str(pdf),
        "source_path": str(SOURCE),
        "artifact_type": "Type A",
        "page_count": info["page_count"],
        "citation_status": "unverified",
        "pdf_metadata": info["metadata"],
    }
    write(RAW / "metadata.json", json.dumps(metadata, indent=2, ensure_ascii=False))


def write_logs(info: dict, figs: list[dict], tabs: list[dict], algs: list[dict], prompts: list[dict]) -> None:
    write(RAW / "extraction_log.txt", f"""Status: partial-success
Tools Used: pypdf; Python static AST/file inventory
Successful Outputs: full_text.txt, page_text/*.txt, sections.txt, section_text/*.txt, references.txt, caption/context figure and table indexes, prompt/algorithm context snippets, source_static_inventory.txt
Failed Outputs: verified layout blocks, verified table cells, figure image crops, citation metadata verification, prompt/layout repair
Pages With Empty Text: {info['empty_pages'] or 'none'}
OCR Needed: no
Tables Extracted: {len(tabs)} caption/context records; [NEEDS TABLE REPAIR]
Figures/Captions Extracted: {len(figs)} caption/context records; [NEEDS FIGURE EXTRACTION]
References Extracted: yes, from text layer; [NEEDS CITATION VERIFICATION]
Known Losses: multi-column order may be imperfect; table cells and figure images are not citation-ready; prompts and algorithms may be incomplete.
Next Repair Step: repair tables/figures and verify official citation metadata before exact claims.
PDF Text Complete: yes
PDF Layout Partial: yes
Citation-Ready Tables: no
Figure-Ready: no
Agent Index: partial
""")
    write(RAW / "extraction_profile.txt", f"""Primary Consumer: agent
PDF Text Layer: complete
Layout Block Layer: missing/not attempted
Table Layer: caption/context-only
Figure Layer: caption-only
Formula Layer: not attempted
Algorithm Layer: partial
Prompt Layer: partial
Known Ordering Losses: pypdf text from two-column ACM layout may have imperfect reading order.
Known Layout Losses: tables, figures, prompt formatting, and algorithm-like blocks are not layout-verified.
Agent Retrieval Usability: medium
Citation Readiness: low
Next Repair Step: [NEEDS TABLE REPAIR], [NEEDS FIGURE EXTRACTION], [NEEDS LAYOUT BLOCK EXTRACTION], [NEEDS PROMPT REPAIR], [NEEDS CITATION VERIFICATION]
""")


def seed_agent_index(sections, figs, tabs, algs, prompts):
    units = []
    for s in sections:
        if s["status"] != "extracted":
            units.append({
                "id": f"{PAPER_ID}:gap:{stable_id(s['label'])}",
                "type": "gap",
                "page": None,
                "section": s["label"],
                "topic": "section split gap",
                "text_anchor": s["status"],
                "bbox": None,
                "files": ["sections.txt"],
                "confidence": "low",
                "repair_needed": True,
                "usable_for": ["repair"],
                "do_not_use_for": ["paper claim", "exact numeric claim"],
                "notes": "[NEEDS SECTION SPLIT]",
            })
            continue
        units.append({
            "id": f"{PAPER_ID}:section:{stable_id(s['label'])}",
            "type": "section",
            "page": None,
            "section": s["label"],
            "topic": s["label"],
            "text_anchor": s["label"],
            "bbox": None,
            "files": ["full_text.txt", s["file"]],
            "confidence": "medium",
            "repair_needed": False,
            "usable_for": ["abstract", "introduction", "background", "method", "evaluation", "limitations", "related_work"],
            "do_not_use_for": ["exact numeric claim without table/PDF verification"],
            "notes": "Heuristic section split from PDF text layer.",
        })
    for f in figs:
        units.append({
            "id": f"{PAPER_ID}:figure:{f['id']}",
            "type": "figure",
            "page": f["page"],
            "section": None,
            "topic": "figure caption/context",
            "text_anchor": f["caption"][:120],
            "bbox": None,
            "files": [f"figures/{f['id']}_caption.txt", f"figures/{f['id']}_context.txt"],
            "confidence": "partial",
            "repair_needed": True,
            "usable_for": ["method", "evaluation", "writing_patterns"],
            "do_not_use_for": ["figure reuse", "visual detail claim"],
            "notes": "[NEEDS FIGURE EXTRACTION]",
        })
    for t in tabs:
        units.append({
            "id": f"{PAPER_ID}:table:{t['id']}",
            "type": "table",
            "page": t["page"],
            "section": None,
            "topic": "table caption/context",
            "text_anchor": t["caption"][:120],
            "bbox": None,
            "files": [f"tables/{t['id']}_raw.txt", f"tables/{t['id']}.md", f"tables/{t['id']}.csv"],
            "confidence": "partial",
            "repair_needed": True,
            "usable_for": ["evaluation"],
            "do_not_use_for": ["citation-ready numeric claim"],
            "notes": "[NEEDS TABLE REPAIR]",
        })
    for a in algs:
        units.append({
            "id": f"{PAPER_ID}:algorithm:{a['id']}",
            "type": "algorithm",
            "page": a["page"],
            "section": None,
            "topic": "algorithm/pseudocode context",
            "text_anchor": a["anchor"],
            "bbox": None,
            "files": [f"algorithms/{a['id']}.txt"],
            "confidence": "partial",
            "repair_needed": True,
            "usable_for": ["method"],
            "do_not_use_for": ["exact algorithm reproduction"],
            "notes": "[NEEDS ALGORITHM REPAIR]",
        })
    for p in prompts:
        units.append({
            "id": f"{PAPER_ID}:prompt:{p['id']}",
            "type": "prompt",
            "page": p["page"],
            "section": None,
            "topic": "LLM prompt/context mention",
            "text_anchor": p["anchor"],
            "bbox": None,
            "files": [f"prompts/{p['id']}.txt"],
            "confidence": "partial",
            "repair_needed": True,
            "usable_for": ["method", "artifact_consistency"],
            "do_not_use_for": ["verbatim prompt reuse"],
            "notes": "[NEEDS PROMPT REPAIR]",
        })
    units.append({
        "id": f"{PAPER_ID}:artifact:source_static_inventory",
        "type": "artifact",
        "page": None,
        "section": "source artifact",
        "topic": "static source inventory",
        "text_anchor": "static-only source inventory",
        "bbox": None,
        "files": ["source_static_inventory.txt", "source_static_inventory.json"],
        "confidence": "medium",
        "repair_needed": False,
        "usable_for": ["method", "reproducibility", "artifact_consistency"],
        "do_not_use_for": ["runtime behavior", "reproduced result claim"],
        "notes": "[EXECUTION NOT REQUESTED]",
    })
    index = {
        "paper_id": PAPER_ID,
        "title": TITLE,
        "source_manifest": "00_source_manifest.txt",
        "extraction_profile": "extraction_profile.txt",
        "evidence_units": units,
        "known_gaps": [
            "[NEEDS TABLE REPAIR]",
            "[NEEDS FIGURE EXTRACTION]",
            "[NEEDS LAYOUT BLOCK EXTRACTION]",
            "[NEEDS PROMPT REPAIR]",
            "[NEEDS CITATION VERIFICATION]",
            "[NEEDS ARTIFACT]",
            "[EXECUTION NOT REQUESTED]",
        ],
    }
    write(RAW / "agent_index.json", json.dumps(index, indent=2, ensure_ascii=False))


def main():
    for sub in ["page_text", "section_text", "tables", "figures", "formulas", "algorithms", "prompts", "layout_blocks"]:
        (RAW / sub).mkdir(parents=True, exist_ok=True)
    pdf = find_pdf()
    info = extract_pdf(pdf)
    full = (RAW / "full_text.txt").read_text(encoding="utf-8")
    sections = split_sections(full)
    figs, tabs, algs, prompts = extract_caption_units(info["pages"])
    inspect_source()
    write_manifest_metadata(pdf, info)
    write_logs(info, figs, tabs, algs, prompts)
    seed_agent_index(sections, figs, tabs, algs, prompts)
    write(RAW / "appendix.txt", "[NEEDS EVIDENCE] Appendix was not separately recovered as a verified layout section.\n")
    write(RAW / "formulas" / "formula_index.txt", "[NEEDS FORMULA REPAIR] Formula extraction was not attempted as a layout-aware pass.\n")
    write(RAW / "layout_blocks" / "layout_status.txt", "[NEEDS LAYOUT BLOCK EXTRACTION] Layout blocks were not extracted in this static pass.\n")


if __name__ == "__main__":
    main()

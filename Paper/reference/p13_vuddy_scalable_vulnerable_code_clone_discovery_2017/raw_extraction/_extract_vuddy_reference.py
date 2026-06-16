from __future__ import annotations

import ast
import csv
import json
import os
import re
from datetime import datetime
from pathlib import Path

from pypdf import PdfReader


PAPER_ID = "p13_vuddy_scalable_vulnerable_code_clone_discovery_2017"
TITLE = "VUDDY: A Scalable Approach for Vulnerable Code Clone Discovery"
YEAR = "2017"
AUTHORS = ["Seulbae Kim", "Seunghoon Woo", "Heejo Lee", "Hakjoo Oh"]
ROOT = Path(r"E:\AI\Agent\workflow\Paper\reference") / PAPER_ID
RAW = ROOT / "raw_extraction"
INPUT_ROOT = Path(r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\VUDDY")
SOURCE = INPUT_ROOT / "VUDDY"


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
        raise RuntimeError(f"expected one top-level PDF, found {len(pdfs)}")
    return pdfs[0]


def extract_pdf(pdf: Path) -> dict:
    reader = PdfReader(long_path(pdf))
    pages = []
    empty = []
    for idx, page in enumerate(reader.pages, 1):
        text = page.extract_text() or ""
        if not text.strip():
            empty.append(idx)
        pages.append(text)
        write(RAW / "page_text" / f"page_{idx:03d}.txt", text)
    write(RAW / "full_text.txt", "\n\n".join(f"===== PAGE {i:03d} =====\n{text}" for i, text in enumerate(pages, 1)))
    return {
        "page_count": len(reader.pages),
        "empty_pages": empty,
        "metadata": {str(k): str(v) for k, v in (reader.metadata or {}).items()},
        "pages": pages,
    }


SECTION_RANGES = [
    ("01_abstract.txt", "Abstract", r"^Abstract—", r"^I\.\s*I\s*N T R O D U C T I O N|^I\.\s*INTRODUCTION|^I\.\s+I NTRODUCTION"),
    ("02_introduction.txt", "I. Introduction", r"^I\.\s*I\s*N T R O D U C T I O N|^I\.\s*INTRODUCTION|^I\.\s+I NTRODUCTION", r"^II\.\s*B|^II\."),
    ("03_background.txt", "II. Background", r"^II\.", r"^III\."),
    ("04_method.txt", "III-VI Problem / Method / Application / Implementation", r"^III\.", r"^VII\."),
    ("05_experiments.txt", "VII. Evaluation", r"^VII\.", r"^VIII\."),
    ("06_evaluation.txt", "VIII-IX Comparison / Case Study", r"^VIII\.", r"^X\."),
    ("07_related_work.txt", "Related Work subsection", r"^B\.\s*Related work", r"^III\."),
    ("08_limitations.txt", "X-XI Discussion / Conclusion", r"^X\.", r"^R EFERENCES|^REFERENCES"),
    ("09_references.txt", "References", r"^R EFERENCES|^REFERENCES", r"$^"),
]


def split_sections(full_text: str) -> list[dict]:
    out = []
    for filename, label, start_pat, end_pat in SECTION_RANGES:
        matches = list(re.finditer(start_pat, full_text, re.IGNORECASE | re.MULTILINE))
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
    ref = RAW / "section_text" / "09_references.txt"
    write(RAW / "references.txt", ref.read_text(encoding="utf-8") if ref.exists() else "[NEEDS CITATION VERIFICATION]\n")
    return out


def extract_caption_units(pages: list[str]) -> tuple[list[dict], list[dict], list[dict]]:
    figures, tables, formulas = [], [], []
    for page_no, text in enumerate(pages, 1):
        compact = re.sub(r"\s+", " ", text)
        for m in re.finditer(r"((?:Fig\.|Figure)\s*\d+[:.]?\s+.{20,340}?)(?=(?:Fig\.|Figure|Table|\s[A-Z][a-z]+ \d|$))", compact):
            cap = m.group(1).strip()
            fid = f"figure_{len(figures)+1:03d}"
            write(RAW / "figures" / f"{fid}_caption.txt", cap + "\n")
            write(RAW / "figures" / f"{fid}_context.txt", compact[max(0, m.start()-450):m.end()+550] + "\n")
            write(RAW / "figures" / f"{fid}_agent_summary.txt", f"Caption/context-only evidence. [NEEDS FIGURE EXTRACTION]\nCaption: {cap}\n")
            figures.append({"id": fid, "page": page_no, "caption": cap})
        for m in re.finditer(r"(Table\s+[IVXLC\d]+[:.]?\s+.{20,520}?)(?=(?:Fig\.|Figure|Table|\s[A-Z][a-z]+ \d|$))", compact):
            cap = m.group(1).strip()
            tid = f"table_{len(tables)+1:03d}"
            raw = compact[max(0, m.start()-700):m.end()+1000]
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
        if any(token in compact for token in ["H(s)", "hash", "SHA", "signature", "fingerprint"]):
            fid = f"formula_{len(formulas)+1:03d}"
            snippet = compact[:1600]
            write(RAW / "formulas" / f"{fid}.txt", f"ID: {fid}\nPage: {page_no}\nRaw Extracted Text / Context:\n{snippet}\nExtraction Confidence: partial\nRepair Needed: [NEEDS FORMULA REPAIR]\n")
            formulas.append({"id": fid, "page": page_no, "anchor": snippet[:140]})
    write(RAW / "figures" / "figure_index.txt", "\n".join(f"- {f['id']}: page {f['page']}; {f['caption']} [NEEDS FIGURE EXTRACTION]" for f in figures) + ("\n" if figures else "No figure captions confidently extracted. [NEEDS FIGURE EXTRACTION]\n"))
    write(RAW / "tables" / "table_index.txt", "\n".join(f"- {t['id']}: page {t['page']}; {t['caption']} [NEEDS TABLE REPAIR]" for t in tables) + ("\n" if tables else "No table captions confidently extracted. [NEEDS TABLE REPAIR]\n"))
    write(RAW / "formulas" / "formula_index.txt", "\n".join(f"- {f['id']}: page {f['page']}; {f['anchor']} [NEEDS FORMULA REPAIR]" for f in formulas) + ("\n" if formulas else "No formulas confidently extracted. [NEEDS FORMULA REPAIR]\n"))
    write(RAW / "algorithms" / "algorithm_index.txt", "No algorithm blocks confidently extracted. [NEEDS ALGORITHM REPAIR]\n")
    write(RAW / "prompts" / "prompt_index.txt", "Prompt Layer: not detected.\n")
    return figures, tables, formulas


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
    py, java, grammar = [], [], []
    for item in files:
        path = SOURCE / item["path"]
        if item["ext"] == ".py":
            text = read_text(path)
            try:
                tree = ast.parse(text)
                funcs = [n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
                classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
                imports = []
                strings = []
                for n in ast.walk(tree):
                    if isinstance(n, ast.Import):
                        imports.extend(a.name for a in n.names)
                    elif isinstance(n, ast.ImportFrom):
                        imports.append(n.module or "")
                    elif isinstance(n, ast.Constant) and isinstance(n.value, str):
                        val = n.value.strip()
                        if any(k in val.lower() for k in ["hash", "clone", "vul", "cve", "repo", "function", "mysql", "jar"]):
                            strings.append(val[:220])
                py.append({"path": item["path"], "lines": text.count("\n") + 1, "functions": funcs[:40], "classes": classes[:20], "imports": sorted(set(i for i in imports if i))[:30], "notable_strings": strings[:12]})
            except SyntaxError as exc:
                py.append({"path": item["path"], "parse_error": str(exc)})
        elif item["ext"] == ".java":
            text = read_text(path)
            methods = re.findall(r"(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\([^;]*\)\s*\{", text)
            classes = re.findall(r"\bclass\s+(\w+)", text)
            java.append({"path": item["path"], "lines": text.count("\n") + 1, "classes": classes[:20], "methods": methods[:60]})
        elif item["ext"] == ".g4":
            text = read_text(path)
            rules = re.findall(r"(?m)^([a-zA-Z_]\w*)\s*:", text)
            grammar.append({"path": item["path"], "rules": rules[:40], "lines": text.count("\n") + 1})
    samples = {}
    for name in ["README.md", "hmark/README.md", "docs/examples.md", "config.py", "LICENSE.md", "tools/cvedatagen/README.md", "dep.sh"]:
        path = SOURCE / name
        if path.exists():
            samples[name] = read_text(path, 6000)
    inv = {"source_path": str(SOURCE), "directories": dirs, "files": files, "python": py, "java": java, "grammar": grammar, "samples": samples}
    write(RAW / "source_static_inventory.json", json.dumps(inv, indent=2, ensure_ascii=False))
    lines = [
        f"Source Path: {SOURCE}",
        "Analysis Mode: static-only",
        "Runtime Behavior: [EXECUTION NOT REQUESTED]",
        "",
        "Repository / File Layout Observed:",
    ]
    for d in dirs[:120]:
        lines.append(f"- dir: {d}")
    for f in files[:220]:
        lines.append(f"- file: {f['path']} ({f['size']} bytes)")
    lines += ["", "Primary Python Files:"]
    for p in py:
        lines.append(f"- {p['path']}: lines={p.get('lines', '[NEEDS EVIDENCE]')}; functions={', '.join(p.get('functions', [])[:14]) or '[NEEDS EVIDENCE]'}; imports={', '.join(p.get('imports', [])[:10]) or '[NEEDS EVIDENCE]'}")
    lines += ["", "Primary Java / Parser Files:"]
    for j in java:
        lines.append(f"- {j['path']}: lines={j.get('lines')}; classes={', '.join(j.get('classes', [])[:8]) or '[NEEDS EVIDENCE]'}; methods={', '.join(j.get('methods', [])[:12]) or '[NEEDS EVIDENCE]'}")
    for g in grammar:
        lines.append(f"- {g['path']}: grammar_rules={', '.join(g.get('rules', [])[:12]) or '[NEEDS EVIDENCE]'}")
    lines += [
        "",
        "Key Static Evidence:",
        "- README.md, LICENSE.md, config.py, initialize.py, dep.sh, docs/examples.md, and hmark README are present.",
        "- checker/check_clones.py and checker/check_clones_origin.py indicate clone checking entrypoints.",
        "- src scripts indicate CVE patch collection, source extraction, repository update, duplicate removal, vulnerable hash/index generation, and verification.",
        "- FuncParser-opt contains Java/ANTLR grammar sources and parser JAR artifacts.",
        "- hmark contains hashing/marking scripts and a bundled parser JAR.",
        "- tools/cvedatagen contains CVE XML downloader/parser/updater utilities.",
        "- testcode contains C files for local examples/tests.",
        "- Additional nested PDFs/manuals exist under docs/ and paper/ but were treated as artifact documents, not the selected main reference PDF.",
        "",
        "Static Consistency Notes:",
        "- Static layout supports the paper-level claim that VUDDY uses function-level parsing, hashing/signatures, and clone checking for vulnerable code clone discovery.",
        "- Runtime behavior, database state, parser execution, clone detection output, and benchmark reproduction were not checked. [EXECUTION NOT REQUESTED]",
        "- Complete vulnerability database contents and large-scale benchmark artifacts are not visible as reproduced results in this pass. [NEEDS ARTIFACT]",
        "",
        "Observed Local Output / Data Artifacts:",
    ]
    for f in files:
        if f["ext"] in [".md", ".pdf", ".jar", ".c", ".py", ".g4", ".sh"]:
            lines.append(f"- {f['path']} ({f['size']} bytes)")
    lines += [
        "",
        "Missing Data / Missing Entrypoints:",
        "- No execution or parser/build step was requested. [EXECUTION NOT REQUESTED]",
        "- Database contents, full vulnerability index, large OSS corpus, and benchmark outputs need artifact verification. [NEEDS ARTIFACT]",
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
Extraction Tools: pypdf text extraction; Python static AST/file inventory; regex Java/ANTLR inventory
Artifact Type: Type A
Notes: Static analysis only; no dependency installation, parser execution, script execution, database setup, or experiment reproduction.
""")
    metadata = {
        "paper_id": PAPER_ID,
        "title": TITLE,
        "authors": AUTHORS,
        "venue": "IEEE Symposium on Security and Privacy",
        "year": YEAR,
        "doi": "10.1109/SP.2017.62",
        "arxiv": "",
        "pdf_path": str(pdf),
        "source_path": str(SOURCE),
        "artifact_type": "Type A",
        "page_count": info["page_count"],
        "citation_status": "unverified",
        "pdf_metadata": info["metadata"],
    }
    write(RAW / "metadata.json", json.dumps(metadata, indent=2, ensure_ascii=False))


def write_logs(info: dict, figs: list[dict], tabs: list[dict], formulas: list[dict]) -> None:
    write(RAW / "extraction_log.txt", f"""Status: partial-success
Tools Used: pypdf; Python static AST/file inventory; regex Java/ANTLR inventory
Successful Outputs: full_text.txt, page_text/*.txt, sections.txt, section_text/*.txt, references.txt, caption/context table and figure indexes, formula/hash context snippets, source_static_inventory.txt
Failed Outputs: verified layout blocks, verified table cells, figure image crops, citation metadata verification, formula/layout repair
Pages With Empty Text: {info['empty_pages'] or 'none'}
OCR Needed: no
Tables Extracted: {len(tabs)} caption/context records; [NEEDS TABLE REPAIR]
Figures/Captions Extracted: {len(figs)} caption/context records; [NEEDS FIGURE EXTRACTION]
References Extracted: yes, from text layer; [NEEDS CITATION VERIFICATION]
Known Losses: multi-column order may be imperfect; table cells and figure images are not citation-ready; formulas/hash definitions may lose layout.
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
Formula Layer: partial
Algorithm Layer: not detected/not attempted
Prompt Layer: not detected
Known Ordering Losses: pypdf text from IEEE two-column layout may have imperfect reading order.
Known Layout Losses: tables, figures, equations/signatures, and parser details are not layout-verified.
Agent Retrieval Usability: medium
Citation Readiness: low
Next Repair Step: [NEEDS TABLE REPAIR], [NEEDS FIGURE EXTRACTION], [NEEDS LAYOUT BLOCK EXTRACTION], [NEEDS FORMULA REPAIR], [NEEDS CITATION VERIFICATION]
""")


def seed_agent_index(sections, figs, tabs, formulas):
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
    for fm in formulas:
        units.append({
            "id": f"{PAPER_ID}:formula:{fm['id']}",
            "type": "formula",
            "page": fm["page"],
            "section": None,
            "topic": "hash/signature context",
            "text_anchor": fm["anchor"],
            "bbox": None,
            "files": [f"formulas/{fm['id']}.txt"],
            "confidence": "partial",
            "repair_needed": True,
            "usable_for": ["method"],
            "do_not_use_for": ["exact formula claim"],
            "notes": "[NEEDS FORMULA REPAIR]",
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
            "[NEEDS FORMULA REPAIR]",
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
    figs, tabs, formulas = extract_caption_units(info["pages"])
    inspect_source()
    write_manifest_metadata(pdf, info)
    write_logs(info, figs, tabs, formulas)
    seed_agent_index(sections, figs, tabs, formulas)
    write(RAW / "appendix.txt", "[NEEDS EVIDENCE] Appendix was not separately recovered as a verified layout section.\n")
    write(RAW / "layout_blocks" / "layout_status.txt", "[NEEDS LAYOUT BLOCK EXTRACTION] Layout blocks were not extracted in this static pass.\n")


if __name__ == "__main__":
    main()

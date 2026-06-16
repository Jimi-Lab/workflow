# Agent-Oriented Extraction Workflow

Use this workflow when extracted paper evidence will be consumed by Codex, Claude Code, or another writing/research agent. This extends `raw_extraction_workflow.md`; it does not replace the raw extraction contract.

The goal is not pixel-perfect PDF restoration. The goal is to create an evidence package that an agent can retrieve, rank, quote-check, and refuse to overuse when extraction quality is weak.

## Core Principle

Keep imperfect extraction, but label it. Do not discard partially recovered tables, captions, algorithms, prompts, or figure context. Store them as evidence units with confidence and repair flags so later writing can distinguish:

- agent-usable retrieval evidence
- citation-ready numeric evidence
- figure-ready visual evidence
- weak evidence that only supports follow-up inspection

## Output Contract

For each paper, add these files under:

```text
Paper/reference/<paper_id>/raw_extraction/
```

Preferred agent package:

```text
agent_index.json
extraction_profile.txt
layout_blocks/
  page_001_blocks.json
tables/
  table_001_raw.txt
  table_001_cells.json
  table_001.md
  table_001.csv
figures/
  figure_001.png
  figure_001_caption.txt
  figure_001_context.txt
  figure_001_agent_summary.txt
formulas/
  formula_001.txt
algorithms/
  algorithm_001.txt
prompts/
  prompt_001.txt
```

Only create files supported by actual extraction. Missing files must be recorded in `extraction_log.txt`, `extraction_profile.txt`, and the relevant evidence unit.

## Extraction Profile

`extraction_profile.txt` should summarize what an agent can trust:

```text
Primary Consumer: agent
PDF Text Layer: complete/partial/missing
Layout Block Layer: complete/partial/missing/not attempted
Table Layer: cells+csv/markdown+raw/caption-only/missing
Figure Layer: crop+caption/page-crop+caption/caption-only/missing
Formula Layer: extracted/partial/not detected/not attempted
Algorithm Layer: extracted/partial/not detected/not attempted
Prompt Layer: extracted/partial/not detected/not attempted
Known Ordering Losses:
Known Layout Losses:
Agent Retrieval Usability: high/medium/low
Citation Readiness: high/medium/low
Next Repair Step:
```

Do not mark `Citation Readiness: high` if quantitative tables, references, or claims have not been checked against the PDF.

## Agent Index Schema

`agent_index.json` is the main retrieval file. It should index every important section, table, figure, formula, algorithm, prompt, artifact note, and known extraction gap.

Use this shape:

```json
{
  "paper_id": "",
  "title": "",
  "source_manifest": "00_source_manifest.txt",
  "extraction_profile": "extraction_profile.txt",
  "evidence_units": [
    {
      "id": "p01:section:introduction",
      "type": "section",
      "page": 1,
      "section": "Introduction",
      "topic": "problem motivation",
      "text_anchor": "",
      "bbox": null,
      "files": [
        "full_text.txt",
        "section_text/02_introduction.txt"
      ],
      "confidence": "medium",
      "repair_needed": false,
      "usable_for": [
        "introduction",
        "motivation"
      ],
      "do_not_use_for": [
        "exact numeric claim"
      ],
      "notes": ""
    }
  ],
  "known_gaps": []
}
```

Rules:

- `id` must be stable and unique inside the paper directory.
- `type` should use one of: `section`, `table`, `figure`, `formula`, `algorithm`, `prompt`, `reference`, `artifact`, `gap`.
- `page` may be `null` if unknown. Do not guess.
- `bbox` may be `null` when layout coordinates are unavailable.
- `text_anchor` should be short and local, not a copied paragraph.
- `files` must point to local files inside the paper directory when possible.
- `usable_for` should name later writing uses, such as `abstract`, `introduction`, `method`, `evaluation`, `limitations`, or `related_work`.
- `do_not_use_for` must explicitly block unsafe downstream uses.

## Confidence Labels

Use these labels consistently:

```text
high:
  Text, cells, image crop, or artifact evidence is cleanly recovered and anchored.

medium:
  Evidence is usable for writing structure or qualitative claims, but layout or boundaries may be imperfect.

partial:
  Evidence is useful for retrieval and follow-up inspection, but not citation-ready.

low:
  Evidence is ambiguous, weak, or only indicates that a repair step is needed.
```

Never upgrade confidence because the claim sounds plausible. Confidence comes from extraction quality and source anchoring only.

## Layout Blocks

When possible, save per-page layout blocks:

```json
[
  {
    "page": 1,
    "block_id": "p01:block:001",
    "block_type": "paragraph",
    "text": "",
    "bbox": [0, 0, 0, 0],
    "reading_order": 1,
    "column_guess": 1,
    "confidence": "medium"
  }
]
```

If only plain text extraction is available, record:

```text
Layout Block Layer: missing/not attempted
Known Ordering Losses: multi-column reading order may be wrong
```

Plain text from pypdf-like tools can be `PDF Text Complete`, but it is usually `PDF Layout Partial`.

## Table Policy

CSV is useful but not mandatory for agent-oriented use. Acceptable table evidence layers are:

```text
table_001_raw.txt     raw extracted table area or caption-neighbor text
table_001_cells.json  structured cells if available
table_001.md          agent-readable markdown table if reliable enough
table_001.csv         optional, only when column/cell structure is trustworthy
```

If the table is only caption-neighbor text, create a table evidence unit with:

```json
{
  "type": "table",
  "confidence": "partial",
  "repair_needed": true,
  "do_not_use_for": ["citation-ready numeric claim"]
}
```

Exact numeric claims require either `table_*.csv`, `table_*_cells.json`, or manual PDF verification recorded in the notes.

## Figure Policy

For agent use, a page crop is better than caption-only evidence, and caption-only evidence is better than no figure record.

Preferred figure files:

```text
figure_001.png
figure_001_caption.txt
figure_001_context.txt
figure_001_agent_summary.txt
```

Rules:

- `figure_001_caption.txt` stores the extracted caption only.
- `figure_001_context.txt` stores nearby page text or section anchors.
- `figure_001_agent_summary.txt` explains what the figure appears to support, using only caption/context/crop evidence.
- If no image or page crop exists, mark `[NEEDS FIGURE EXTRACTION]`.
- Do not describe visual details that were not actually extracted or inspected.

## Formula, Algorithm, and Prompt Blocks

Treat equations, pseudocode, algorithms, prompts, and examples as first-class evidence units when detected.

Store them under:

```text
formulas/
algorithms/
prompts/
```

Record:

```text
ID:
Page:
Section:
Raw Extracted Text:
Nearby Context:
Extraction Confidence:
Repair Needed:
Notes:
```

If layout is damaged, keep the raw text and mark `confidence: partial` or `low`. Do not rewrite formulas, pseudocode, or prompts into cleaner versions unless the user explicitly asks for a repair pass.

## Minimal Acceptable Agent Package

When tools are limited, the minimal acceptable package is:

```text
full_text.txt
page_text/
sections.txt
section_text/
extraction_log.txt
extraction_profile.txt
agent_index.json
```

In that case:

- mark tables as `caption-only`, `partial`, or `missing`
- mark figures as `caption-only` or `missing`
- mark layout blocks as `missing/not attempted`
- mark exact numeric claims as not citation-ready

## Repair Labels

Use explicit repair labels in `agent_index.json`, `extraction_profile.txt`, and `analysis/13_completeness_audit.txt`:

```text
[NEEDS TABLE REPAIR]
[NEEDS FIGURE EXTRACTION]
[NEEDS LAYOUT BLOCK EXTRACTION]
[NEEDS FORMULA REPAIR]
[NEEDS ALGORITHM REPAIR]
[NEEDS PROMPT REPAIR]
[NEEDS CITATION VERIFICATION]
```

## Downstream Use

When drafting later paper sections, read `agent_index.json` before browsing full text. Select evidence units by `usable_for`, then verify the original local files. If an evidence unit is `partial` or `low`, use it only to guide retrieval or mark the draft with `[NEEDS EVIDENCE]`.

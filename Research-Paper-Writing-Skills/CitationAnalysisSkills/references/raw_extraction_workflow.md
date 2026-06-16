# Raw Extraction Workflow

Use this workflow before section-level paper analysis. The purpose is to preserve recoverable evidence from PDFs and paper artifacts so later writing can inspect the original text, tables, figures, captions, references, and extraction failures.

For Codex, Claude Code, or other agent consumers, also apply `agent_extraction_workflow.md`. That workflow adds `agent_index.json`, `extraction_profile.txt`, layout/table/figure evidence units, confidence labels, and repair flags. The agent package is required when the output is meant to support a multi-paper writing corpus.

## Output Contract

For each paper, create:

```text
E:\AI\Agent\workflow\Paper\reference\<paper_id>\
  raw_extraction/
    00_source_manifest.txt
    agent_index.json
    extraction_profile.txt
    metadata.json
    extraction_log.txt
    full_text.txt
    page_text/
      page_001.txt
      page_002.txt
    layout_blocks/
    sections.txt
    section_text/
      01_abstract.txt
      02_introduction.txt
      03_background.txt
      04_method.txt
      05_experiments.txt
      06_evaluation.txt
      07_related_work.txt
      08_limitations.txt
      09_references.txt
    tables/
      table_index.txt
      table_001.txt
      table_001_raw.txt
      table_001_cells.json
      table_001.md
      table_001.csv
    figures/
      figure_index.txt
      figure_001.png
      figure_001_caption.txt
      figure_001_page.txt
      figure_001_context.txt
      figure_001_agent_summary.txt
    formulas/
    algorithms/
    prompts/
    references.txt
    appendix.txt
  analysis/
```

Only create files that are supported by actual extraction. If something cannot be extracted, record it in `raw_extraction/extraction_log.txt` and `raw_extraction/extraction_profile.txt` instead of fabricating content.

Do not place raw extraction and analysis as separate sibling paper directories. The invariant is: one paper ID maps to one paper directory.

## Source Manifest

`00_source_manifest.txt` should record:

```text
Paper ID:
Original PDF Path:
Original Text Path:
Source Code Path or URL:
Artifact/Data Path or URL:
Extraction Date:
Extraction Tools:
Artifact Type:
Notes:
```

## Metadata

`metadata.json` should include fields when available:

```json
{
  "paper_id": "",
  "title": "",
  "authors": [],
  "venue": "",
  "year": "",
  "doi": "",
  "arxiv": "",
  "pdf_path": "",
  "artifact_type": "Type U",
  "page_count": null,
  "citation_status": "unverified"
}
```

Use empty strings or `null` for missing fields. Do not guess.

## Extraction Log

`extraction_log.txt` must include:

```text
Status:
Tools Used:
Successful Outputs:
Failed Outputs:
Pages With Empty Text:
OCR Needed:
Tables Extracted:
Figures/Captions Extracted:
References Extracted:
Known Losses:
Next Repair Step:
```

If the extraction used plain text only, record it explicitly. Typical pypdf-like output should be labeled:

```text
PDF Text Complete: yes/no
PDF Layout Partial: yes
Citation-Ready Tables: no, unless tables were repaired or verified
Figure-Ready: no, unless figure crops or page crops were extracted and checked
Agent Index: complete/partial/missing
```

## Text Extraction

Required outputs for PDFs:

```text
full_text.txt
page_text/page_NNN.txt
sections.txt
```

Rules:

- Preserve page boundaries in `full_text.txt` with clear page markers.
- Preserve original section headings when possible.
- If automatic section splitting is uncertain, keep `sections.txt` conservative and mark ambiguous headings.
- Do not clean away technical symbols, equations, code identifiers, benchmark names, or metric names.
- If the PDF is scanned or text extraction is empty, mark `OCR Needed: yes`.

## Section Text

Write section files only when the section boundary is reasonably clear.

Common section mapping:

```text
Abstract -> 01_abstract.txt
Introduction -> 02_introduction.txt
Background / Motivation / Overview -> 03_background.txt
Method / Design / Approach / System -> 04_method.txt
Evaluation / Experiments -> 05_experiments.txt or 06_evaluation.txt
Related Work -> 07_related_work.txt
Limitations / Discussion / Ethics -> 08_limitations.txt
References -> 09_references.txt and references.txt
```

If a paper uses unusual headings, preserve the original names and record the mapping in `sections.txt`.

## Table Extraction

For each table:

```text
Table ID:
Page:
Caption:
Column Names:
Raw Extracted Text:
CSV Path:
Extraction Confidence:
Notes:
```

If a table cannot be parsed into CSV, save raw text and/or markdown when available and mark `[NEEDS TABLE REPAIR]`. CSV is not mandatory for agent retrieval, but exact numeric claims require structured cells, CSV, or manual PDF verification.

## Figure and Caption Extraction

For each figure:

```text
Figure ID:
Page:
Caption:
What Evidence It Shows:
Image Extracted: yes/no
Image Path:
Notes:
```

Saving figure images or page crops is preferred for agent use. Captions and page anchors are required when available. If only captions are extracted, mark the figure evidence as caption-only and not figure-ready.

## Formula, Algorithm, and Prompt Extraction

When equations, pseudocode, algorithms, prompts, or examples are visible in the PDF text, save them as first-class evidence under:

```text
formulas/
algorithms/
prompts/
```

Preserve raw text and nearby context. If the layout is damaged, mark `[NEEDS FORMULA REPAIR]`, `[NEEDS ALGORITHM REPAIR]`, or `[NEEDS PROMPT REPAIR]`.

## References

Extract the references section into `references.txt`.

Rules:

- Do not invent BibTeX.
- Mark entries with `[NEEDS CITATION VERIFICATION]` if metadata is incomplete.
- Keep reference text as extracted for later citation verification.

## Artifact Links and Source Code

If the paper provides source code or artifact links:

```text
Link:
Where Found:
Local Path:
Access Status:
License:
Commit / Version:
Notes:
```

Then classify with `source_artifact_taxonomy.md`.

Use static inspection only by default. Record visible source/artifact evidence, but do not install packages, execute scripts, run tests, or reproduce reported results unless the user explicitly requests an execution/reproduction pass.

## Repair Policy

Use explicit labels:

```text
[NEEDS OCR] text extraction failed or scanned pages detected.
[NEEDS TABLE REPAIR] table layout was lost.
[NEEDS FIGURE EXTRACTION] figure image or caption is missing.
[NEEDS LAYOUT BLOCK EXTRACTION] page/block layout is unavailable.
[NEEDS FORMULA REPAIR] formula layout or symbols may be damaged.
[NEEDS ALGORITHM REPAIR] pseudocode order or indentation may be damaged.
[NEEDS PROMPT REPAIR] prompt/example formatting may be damaged.
[NEEDS SECTION SPLIT] section boundaries are uncertain.
[NEEDS CITATION VERIFICATION] reference metadata is not verified.
[PAPER-ONLY] only the PDF text is available.
```

Do not proceed to strong claims when the raw extraction is incomplete. Proceed with a partial analysis only if the missing parts are recorded.

## Copyright and Reuse

Raw extracted text is for local evidence tracing and private analysis. Do not paste full paper text into final answers or new papers. Use short references, paraphrase structure, and write original prose.

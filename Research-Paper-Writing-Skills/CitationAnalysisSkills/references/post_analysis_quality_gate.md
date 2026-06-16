# Post-Analysis Quality Gate

Use this gate after every paper analysis and before reporting completion. The purpose is to make the corpus reliable for later paper writing, not merely to produce many files.

## Required Final File

Every analyzed paper must include:

```text
Paper/reference/<paper_id>/analysis/13_completeness_audit.txt
```

The audit must answer:

```text
Raw Extraction:
- PDF text extracted: yes/no
- Page text extracted: yes/no, page count
- Section text extracted: yes/no, section file count
- Agent index exists: yes/no
- Extraction profile exists: yes/no
- Layout blocks extracted: full/partial/missing/not attempted
- References extracted: yes/no/uncertain
- Table extraction: full/caption-only/missing
- Figure extraction: image+caption/caption-only/missing
- Formula/algorithm/prompt extraction: full/partial/missing/not detected/not attempted
- OCR needed: yes/no

Section Analysis:
- 00_meta.txt through 12_artifact_consistency.txt: complete/missing list
- Are analysis files section-oriented enough for writing? yes/no

Source / Artifact Static Analysis:
- Source inventory exists: yes/no/not applicable
- README/config inspected: yes/no/not applicable
- Main entrypoints inspected: yes/no/not applicable
- Runtime behavior: [EXECUTION NOT REQUESTED] unless the user explicitly asked for execution

Writing Readiness:
- Abstract support: strong/partial/weak
- Introduction support: strong/partial/weak
- Background/motivation support: strong/partial/weak
- Method support: strong/partial/weak
- Experiment/evaluation support: strong/partial/weak
- Limitations support: strong/partial/weak
- Related work support: strong/partial/weak

Known Gaps:
- [NEEDS TABLE REPAIR]
- [NEEDS FIGURE EXTRACTION]
- [NEEDS CITATION VERIFICATION]
- [NEEDS ARTIFACT]
- [EXECUTION NOT REQUESTED]

Usefulness Grade:
high / medium / low, with one sentence explaining why.
```

## PDF Extraction Completeness Levels

Do not call a PDF extraction "complete" without a qualifier.

Use these labels:

```text
PDF Text Complete:
  full_text.txt and page_text/page_NNN.txt exist for all pages.

PDF Layout Partial:
  text exists, but tables/figures/equations/prompts/algorithms may lose layout.

Citation-Ready Tables:
  quantitative tables are repaired into reliable text or CSV and checked against the PDF.

Figure-Ready:
  figure images/page crops are extracted or manually verified, with captions and placement.

Agent-Indexed:
  agent_index.json and extraction_profile.txt exist and label evidence units with confidence, repair_needed, usable_for, and do_not_use_for.
```

Typical pypdf-only output is:

```text
PDF Text Complete: yes
PDF Layout Partial: yes
Citation-Ready Tables: no
Figure-Ready: no
Agent-Indexed: partial, if agent_index.json records the missing layout/table/figure evidence
```

## Source Inventory Requirement

If a source/artifact path exists, create:

```text
raw_extraction/source_static_inventory.txt
```

It must record:

```text
Source Path:
Analysis Mode: static-only
Repository / File Layout Observed:
Primary Files:
Key Static Evidence:
Static Consistency Notes:
Observed Local Output / Data Artifacts:
Missing Data / Missing Entrypoints:
```

If source exists but this file is missing, mark the paper as `Artifact Static Analysis: partial`.

## Section Retrieval Map

When the paper is expected to support later writing, create:

```text
analysis/14_section_retrieval_map.txt
```

This file should map future writing sections to retrieval targets:

```text
For Introduction:
- Read analysis/02_introduction.txt
- Read raw_extraction/section_text/<original_intro>.txt
- Useful claims:
- Must not claim:

For Background / Motivation:
...

For Method:
...

For Experiments / Evaluation:
...

For Limitations:
...

For Related Work:
...
```

This is optional for early testing, but required once the corpus is used to draft the user's paper.

## Cross-Paper Synthesis Trigger

After three or more papers have completed analysis, update or create:

```text
Paper/reference/cross_paper/abstract_patterns.txt
Paper/reference/cross_paper/introduction_patterns.txt
Paper/reference/cross_paper/background_motivation_patterns.txt
Paper/reference/cross_paper/method_patterns.txt
Paper/reference/cross_paper/experiment_patterns.txt
Paper/reference/cross_paper/evaluation_patterns.txt
Paper/reference/cross_paper/figure_table_patterns.txt
Paper/reference/cross_paper/writing_strategy_for_our_paper.txt
```

If cross-paper synthesis has not been done yet, record that explicitly in the final response and in the reference index as:

```text
Cross-Paper Synthesis: pending
```

## Index Fields

For each paper in `00_reference_index.txt`, include or preserve:

```text
PDF Text Status:
Agent Index Status:
Layout Block Status:
Table/Figure Status:
Formula/Algorithm/Prompt Status:
Artifact Static Status:
Writing Readiness:
Cross-Paper Synthesis:
Missing Evidence:
```

## Label Discipline

Default source/artifact policy is static-only. Do not use `[NEEDS REPRODUCTION]` as the default missing-evidence label.

Prefer:

```text
[EXECUTION NOT REQUESTED] runtime behavior or results were not checked because static-only mode was used.
[NEEDS ARTIFACT] required data/results/scripts are missing.
[NEEDS TABLE REPAIR] table layout or values are not citation-ready.
[NEEDS FIGURE EXTRACTION] figure image/page crop is missing.
[NEEDS LAYOUT BLOCK EXTRACTION] multi-column or page-block order is not preserved.
[NEEDS FORMULA REPAIR] equation symbols or layout are not reliable.
[NEEDS ALGORITHM REPAIR] pseudocode order or indentation is not reliable.
[NEEDS PROMPT REPAIR] prompt/example formatting is not reliable.
[NEEDS CITATION VERIFICATION] official metadata or BibTeX is not verified.
```

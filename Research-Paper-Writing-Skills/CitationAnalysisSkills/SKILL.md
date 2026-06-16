---
name: citation-analysis-skills
description: Use when statically analyzing reference research papers, extracting PDF evidence for later writing, comparing paper claims with source code/artifacts, or drafting paper sections from citation-analysis notes.
---

# CitationAnalysis Skills

Use this skill to build a reusable writing-support corpus from reference papers. The goal is not to copy reference papers. The goal is to extract their argument structure, evidence style, experiment design, and section-level writing patterns, then use those patterns to draft the user's own paper from verified project evidence.

Default behavior: parse and store raw paper evidence first, build an agent-oriented evidence package, then write section-level deep analysis. Raw extraction is required for PDFs unless the user explicitly asks for a quick analysis only. For papers with source code or artifacts, use static analysis only by default.

## Core Rules

1. Separate three evidence layers:
   - `reference-paper evidence`: claims and structure stated in the paper.
   - `reference-artifact evidence`: code, data, scripts, benchmarks, or appendices released with the paper.
   - `our-paper evidence`: source code, design docs, results, artifacts, and user-provided text for the user's project.
2. Do not invent citation metadata, results, implementation details, datasets, baselines, or paper claims.
3. Do not use long copied passages from papers. Prefer paraphrase, structure extraction, and short labeled snippets only when necessary.
4. If evidence is missing, write `[NEEDS EVIDENCE]`, `[NEEDS SOURCE]`, `[NEEDS ARTIFACT]`, or `[NEEDS CITATION VERIFICATION]`.
5. When analyzing a paper with source code or artifacts, check paper-code consistency by static inspection before using it as an engineering-writing model.
6. When analyzing a paper without source code, restrict conclusions to the paper layer. Do not infer implementation behavior.
7. When drafting the user's paper, use reference papers only for structure and rhetoric. Factual claims must come from our-paper evidence.
8. Preserve traceability: every analysis note should be recoverable from raw extracted text, page/section anchors, table files, figure captions, artifact files, or explicit user notes.
9. Do not run reference-paper code, install dependencies, execute scripts, launch experiments, or attempt local reproduction unless the user explicitly asks for an execution/reproduction pass.
10. Static source analysis may inspect file layout, imports, function/class names, comments, configs, README files, scripts, hardcoded paths, data references, and paper-code consistency. Mark runtime behavior as unverified unless it is directly stated in text or code.
11. Optimize extraction for agent use. Partial table, figure, layout, formula, algorithm, and prompt extraction is acceptable only when it is indexed with confidence, repair flags, and unsafe-use warnings.

## Artifact Type

Classify every reference before analysis:

- `Type A`: paper + source code + data/artifact.
- `Type B`: paper + source code only.
- `Type C`: paper + data/artifact only.
- `Type D`: paper only.
- `Type U`: unclear. Mark what must be checked.

Load `references/source_artifact_taxonomy.md` when the classification affects the analysis or when source/artifact paths are available.

## Default Output Layout

Unless the user gives another path, write all reference-paper outputs under the user's paper-reference root:

```text
E:\AI\Agent\workflow\Paper\reference
```

Use one top-level directory per paper. Do not create separate sibling paper folders for raw extraction and analysis. This keeps the corpus scalable for 1-20+ papers:

```text
Paper/reference/
  00_reference_index.txt
  p01_short-title_year/
    raw_extraction/
      00_source_manifest.txt
      agent_index.json
      extraction_profile.txt
      metadata.json
      extraction_log.txt
      full_text.txt
      page_text/
      layout_blocks/
      sections.txt
      section_text/
      tables/
      figures/
      formulas/
      algorithms/
      prompts/
      references.txt
      appendix.txt
    analysis/
      00_meta.txt
      01_abstract.txt
      02_introduction.txt
      03_background_motivation.txt
      04_problem_definition.txt
      05_method.txt
      06_experiments.txt
      07_evaluation.txt
      08_limitations_ethics.txt
      09_figures_tables.txt
      10_writing_patterns.txt
      11_relevance_to_our_paper.txt
      12_artifact_consistency.txt
  p02_short-title_year/
    raw_extraction/
    analysis/
  cross_paper/
```

Use stable paper IDs:

```text
p01_short-title_year
p02_short-title_year
```

## Path Handling

When the user provides a concrete target path, analyze that path directly. Do not stop to ask for confirmation of the path mapping.

If the target path contains multiple PDFs, multiple paper folders, or duplicate-looking PDF names, first load `references/batch_directory_workflow.md` and run a batch inventory pass before creating or updating any per-paper directory. Batch inventory is required even when the user asks to proceed without path confirmation, because paper IDs must be assigned from a single manifest rather than ad hoc across turns.

Internally lock these values before writing:

```text
Target Input Path:
Detected PDF Path:
Detected Source/Artifact Path:
Assigned paper_id:
Output Root:
Output Paper Directory:
```

Then proceed with extraction and analysis. Only ask the user before writing if one of these blockers exists:

- no candidate PDF or text source can be found;
- multiple unrelated PDFs exist and the intended paper cannot be inferred;
- an existing `paper_id` directory clearly belongs to a different paper;
- the target path is not visible from the filesystem.

All outputs must stay under:

```text
E:\AI\Agent\workflow\Paper\reference\<paper_id>\
```

Never write reference-analysis outputs into the input directory, `Paper/text/reference_analysis`, or any sibling analysis directory. The only allowed outputs outside a per-paper directory are corpus coordination files directly under `Paper/reference/`, such as `00_reference_index.txt`, `00_batch_inventory_<slug>.json`, `00_batch_inventory_<slug>.md`, and baseline/paper-id mapping tables.

For each paper, create these files under `Paper/reference/<paper_id>/analysis/`:

```text
00_meta.txt
01_abstract.txt
02_introduction.txt
03_background_motivation.txt
04_problem_definition.txt
05_method.txt
06_experiments.txt
07_evaluation.txt
08_limitations_ethics.txt
09_figures_tables.txt
10_writing_patterns.txt
11_relevance_to_our_paper.txt
12_artifact_consistency.txt
```

For cross-paper synthesis, create:

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

Load `references/analysis_schema.md` for the detailed decomposition template.
Load `references/raw_extraction_workflow.md` before processing PDFs or any paper whose raw text has not already been extracted.
Load `references/agent_extraction_workflow.md` before processing PDFs when the outputs will support Codex, Claude Code, or a multi-paper writing corpus.
Load `references/post_analysis_quality_gate.md` before reporting completion for any paper analysis, and after three or more papers have been analyzed.

## Scripts

Use scripts for mechanical checks and corpus maintenance. Do not use scripts as a substitute for section-level reading or evidence judgment.

```text
scripts/init_reference_paper.py
scripts/inventory_reference_inputs.py
scripts/build_agent_index.py
scripts/validate_reference_output.py
scripts/corpus_status.py
```

Recommended order for a new paper:

```text
python scripts/init_reference_paper.py --reference-root E:\AI\Agent\workflow\Paper\reference --title "<paper title>" --year "<year>"
python scripts/build_agent_index.py --reference-root E:\AI\Agent\workflow\Paper\reference --paper-id <paper_id>
python scripts/validate_reference_output.py --reference-root E:\AI\Agent\workflow\Paper\reference
python scripts/corpus_status.py --reference-root E:\AI\Agent\workflow\Paper\reference
```

Recommended order for a batch target:

```text
python scripts/inventory_reference_inputs.py --target "<target path>" --reference-root E:\AI\Agent\workflow\Paper\reference
```

Then process only candidates whose inventory status is `pending`, reuse candidates marked `analyzed`, and do not create paper directories for candidates marked `skipped_duplicate`.

Use `validate_reference_output.py` before reporting a paper analysis as complete. Use `corpus_status.py` after adding or updating papers. Use `build_agent_index.py` only to create an initial retrieval index from existing extraction files; it does not make tables or figures citation-ready.

## Paper Analysis Workflow

1. Inventory inputs: PDFs, text files, code repositories, artifact links, appendices, and any user notes. If the target path is concrete, proceed without asking for mapping confirmation unless a blocker in `Path Handling` applies. For multi-PDF targets, use `references/batch_directory_workflow.md` and `scripts/inventory_reference_inputs.py` first.
2. Assign a stable paper ID and artifact type.
3. Perform raw extraction and write it under `Paper/reference/<paper_id>/raw_extraction/`.
4. Build or update `raw_extraction/agent_index.json` and `raw_extraction/extraction_profile.txt` using `references/agent_extraction_workflow.md`.
5. Inspect the extraction log, extraction profile, and agent index. Mark missing OCR, layout-block, table, figure, formula, algorithm, prompt, or reference evidence.
6. Decompose the paper using the schema in `references/analysis_schema.md`.
7. If code/artifacts exist, apply the static consistency checks in `references/source_artifact_taxonomy.md`. Do not execute the code.
8. If source/artifact paths exist, write `raw_extraction/source_static_inventory.txt` with static file layout, key entrypoints, missing paths/data, and paper-code consistency notes.
9. Write per-paper analysis files under `Paper/reference/<paper_id>/analysis/`.
10. Always write `analysis/13_completeness_audit.txt` using `references/post_analysis_quality_gate.md`.
11. If the analyzed corpus has three or more completed papers, create or update `Paper/reference/cross_paper/*_patterns.txt`; if not updated, mark `Cross-Paper Synthesis: pending`.
12. Maintain an index file with status, missing evidence, extraction status, writing readiness, and usefulness for the user's paper.

## Section Drafting Workflow

When the user asks to draft a section of their own paper:

1. Read the user's immediate instruction.
2. Read our-paper evidence first, especially `00_evidence_map.txt` if present.
3. Read relevant `raw_extraction/agent_index.json` files and select evidence units by `usable_for`, confidence, and repair flags.
4. Read the relevant cross-paper pattern file.
5. Read the same section analysis from selected reference papers under `Paper/reference/<paper_id>/analysis/`.
6. Draft original prose for the user's paper.
7. Mark unsupported claims with `[NEEDS EVIDENCE]`.
8. Return a short evidence checklist after the draft.

Load `references/section_prompt_workflow.md` when generating prompts or drafting a target section.

## Quality Gate

Before finishing any analysis or draft, check:

- Did I store or locate raw extracted evidence before deep analysis?
- Did I create or update `raw_extraction/agent_index.json` and `raw_extraction/extraction_profile.txt` for agent retrieval?
- Did I distinguish `PDF Text Complete` from `PDF Layout Partial`, `Citation-Ready Tables`, and `Figure-Ready`?
- Did I label partial layout, table, figure, formula, algorithm, and prompt evidence with confidence and repair flags?
- Did I record page, section, table, and figure anchors where possible?
- Did I distinguish paper claims from artifact evidence?
- Did I keep source/artifact inspection static unless the user explicitly requested execution?
- Did I avoid copying long text?
- Did I avoid adding unsupported facts to the user's paper?
- Did I classify source-code availability?
- If source/artifacts exist, did I create `raw_extraction/source_static_inventory.txt`?
- Did I record missing evidence explicitly?
- Did I write `analysis/13_completeness_audit.txt`?
- If three or more papers are present, did I update cross-paper synthesis or mark it pending?
- Is the output useful for later section-level retrieval?
- For batch targets, did I create/update the batch inventory and keep paper IDs continuous without duplicate paper directories?

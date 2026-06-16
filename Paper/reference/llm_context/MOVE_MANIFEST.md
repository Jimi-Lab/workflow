# LLM Context Move Manifest

Moved by Codex on 2026-06-11.

Purpose: keep `Paper/text` limited to LaTeX paper source files, while storing LLM-readable draft evidence and cross-paper synthesis under `Paper/reference`.

## New layout

- `reference/llm_context/draft_scaffold/`: draft section notes, evidence maps, and status files used as LLM writing context.
- `reference/llm_context/reference_synthesis/`: cross-paper synthesis and transferable writing/method/experiment patterns.

## Moves

- `text\00_evidence_map.txt` -> `reference\llm_context\draft_scaffold\00_evidence_map.txt`
- `text\01_Abstract.txt` -> `reference\llm_context\draft_scaffold\01_Abstract.txt`
- `text\02_Introduction.txt` -> `reference\llm_context\draft_scaffold\02_Introduction.txt`
- `text\03_Background.txt` -> `reference\llm_context\draft_scaffold\03_Background.txt`
- `text\04_Method.txt` -> `reference\llm_context\draft_scaffold\04_Method.txt`
- `text\05_Experiments.txt` -> `reference\llm_context\draft_scaffold\05_Experiments.txt`
- `text\06_Evaluation.txt` -> `reference\llm_context\draft_scaffold\06_Evaluation.txt`
- `text\07_Conclusion.txt` -> `reference\llm_context\draft_scaffold\07_Conclusion.txt`
- `text\draft_status.md` -> `reference\llm_context\draft_scaffold\draft_status.md`
- `text\evidence_map.md` -> `reference\llm_context\draft_scaffold\evidence_map.md`
- `text\reference_synthesis` -> `reference\llm_context\reference_synthesis`

## Files intentionally left in `Paper/text`

- `main.tex`
- `references.bib`
- `sections/*.tex`
- `tables/*.tex`
# Paper Reference Layout

This directory stores materials for LLM-assisted paper writing and reference checking. The LaTeX paper source should stay under `Paper/text`.

## Layout

- `00_*`: corpus-level indexes, status files, and baseline-to-paper maps.
- `pXX_*`: per-paper reference corpora, including `analysis/` summaries and `raw_extraction/` artifacts.
- `llm_context/`: LLM-readable writing context moved out of `Paper/text`.

## LLM context

- `llm_context/draft_scaffold/`: section notes, draft status, and evidence maps for the current VulnVersion paper draft.
- `llm_context/reference_synthesis/`: cross-paper synthesis, transferable method patterns, experiment patterns, figure/table patterns, related-work taxonomy, and claim-to-reference mapping.
- `llm_context/MOVE_MANIFEST.md`: exact move log from the previous `Paper/text` locations.

## Working rule

Keep `Paper/text` limited to files needed by LaTeX compilation: `main.tex`, `references.bib`, `sections/*.tex`, `tables/*.tex`, and future paper-owned figures/tables. Put LLM-only context, extracted paper text, analysis notes, and synthesis files under `Paper/reference`.
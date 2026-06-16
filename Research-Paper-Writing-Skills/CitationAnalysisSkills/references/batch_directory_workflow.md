# Batch Directory Workflow

Use this workflow when the target path is a directory containing multiple PDFs, or a mix of PDFs, source folders, README files, datasets, and artifacts. The goal is to build a complete reference corpus without duplicate paper IDs, duplicate analysis folders, or confusion between main PDFs and auxiliary PDFs.

## Trigger

Apply this workflow when:

- the user says to analyze all papers under a directory;
- the target path contains multiple top-level PDFs;
- the target path contains multiple paper folders;
- the target path contains duplicate-looking PDFs with different file names;
- the target path contains auxiliary manuals or nested PDFs inside source/artifact folders.

## Non-Negotiable Rules

1. Do not ask the user to confirm path mapping when the target path is concrete.
2. Before analyzing any paper, run a batch inventory pass.
3. Assign all paper IDs from one manifest, not one ad hoc turn at a time.
4. Paper IDs must be globally continuous under the reference root:

```text
p01_...
p02_...
p03_...
...
```

5. Do not reuse an existing numeric prefix unless it is already the same paper directory.
6. Keep one paper directory per unique paper.
7. If two PDFs appear to be the same paper, keep one canonical PDF and record the duplicate path in the manifest.
8. Treat nested PDFs under source/artifact folders as artifact documents unless they are the only candidate paper PDF or the user explicitly targets them.
9. Never write into the input directory.
10. Never write outside `Paper/reference/<paper_id>/`, except for corpus-level index files directly under `Paper/reference/`.

## Required Batch Inventory Outputs

For a batch target, create or update these files directly under the reference root:

```text
Paper/reference/
  00_batch_inventory_<slug>.json
  00_batch_inventory_<slug>.md
  00_baseline_to_paper_id_map.json
  00_baseline_to_paper_id_map.md
  00_reference_index.txt
```

These corpus-level files are allowed because they are coordination artifacts for the reference corpus. They must not contain raw paper text.

## Inventory Fields

Each unique paper candidate should include:

```json
{
  "input_group": "",
  "canonical_pdf_path": "",
  "duplicate_pdf_paths": [],
  "detected_title": "",
  "detected_year": "",
  "detected_source_path": "",
  "artifact_type": "Type A / B / C / D / U",
  "assigned_paper_id": "",
  "status": "pending / analyzed / skipped_duplicate / needs_user",
  "notes": []
}
```

## Candidate Classification

Use this order:

1. Top-level PDF in a paper folder or target directory is the main paper candidate.
2. Sibling source folder with the same project/paper name is source/artifact evidence.
3. Nested PDFs under `docs`, `paper`, `manual`, `appendix`, `artifact`, or source folders are auxiliary artifacts.
4. Duplicate PDFs are detected by exact file hash first, then by normalized extracted title.
5. If multiple unrelated top-level PDFs exist, treat each unique PDF as one paper.

## Stable ID Assignment

1. Read all existing `pNN_` directories under `Paper/reference`.
2. Reuse existing paper IDs if metadata or manifest already points to the same canonical PDF.
3. For new papers, continue from the current maximum `pNN`.
4. Slug source priority:
   - PDF metadata title;
   - first-page title;
   - cleaned filename;
   - fallback `untitled`.
5. Include year only when detected from PDF metadata, venue text, filename, or user-provided context. Otherwise omit year and mark `[NEEDS CITATION VERIFICATION]`.

## Analysis Order

For each unique paper:

1. Initialize `Paper/reference/<paper_id>/`.
2. Extract raw PDF text first.
3. Build `agent_index.json` and `extraction_profile.txt`.
4. Inspect source/artifact statically only.
5. Write section-level analysis.
6. Write `analysis/13_completeness_audit.txt`.
7. Run:

```text
python scripts/build_agent_index.py --reference-root E:\AI\Agent\workflow\Paper\reference --paper-id <paper_id>
python scripts/validate_reference_output.py --reference-root E:\AI\Agent\workflow\Paper\reference
python scripts/corpus_status.py --reference-root E:\AI\Agent\workflow\Paper\reference
```

8. If a script writes `00_corpus_status.md`, keep it only if corpus-level status is requested. Otherwise final reports may summarize its output and remove accidental status files when the user required paper-directory-only writes.

## Duplicate Policy

For duplicate PDFs:

```text
Status: skipped_duplicate
Canonical Paper ID:
Duplicate PDF Path:
Reason: exact hash / same extracted title / same DOI
```

Do not create a second paper directory for a duplicate PDF.

## Completion Gate

Before reporting batch completion:

- all unique PDF candidates are either analyzed or explicitly marked duplicate/skipped with reason;
- paper IDs are continuous;
- `00_baseline_to_paper_id_map.*` or equivalent batch map exists;
- `validate_reference_output.py --reference-root ...` passes for all analyzed directories;
- missing table/figure/layout/citation/artifact evidence is explicitly labeled.

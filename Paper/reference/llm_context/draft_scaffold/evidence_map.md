# VulnVersion Paper Evidence Map

This file tracks which draft claims are currently source-backed and which claims must stay as placeholders.

## Source Roots

- Reference corpus: `E:\AI\Agent\workflow\Paper\reference`
- Main baseline/dataset: `E:\AI\Agent\workflow\Paper\reference\p01_vulnerability_affected_versions_how_far_are_we`
- Method design: `E:\AI\Agent\workflow\SystemDesign`
- Draft output: `E:\AI\Agent\workflow\Paper\text`

## Claim Status

| Claim | Current source | Status |
| --- | --- | --- |
| Task is CVE affected-version identification from CVE/project/released versions/fixing patch evidence. | `p01...\analysis\04_problem_definition.txt` | Source-backed |
| Existing methods divide into tracing-based and matching-based families. | `p01...\analysis\05_method.txt`, `p01...\analysis\06_experiments.txt` | Source-backed |
| Main evaluation should use CVE-level Accuracy, CVE-level NMR, and version-level Precision/Recall/F1. | `p01...\analysis\06_experiments.txt`, `SystemDesign\EvaluationMetrics\EvaluationScheme.md` | Source-backed |
| Best individual baseline below 45.0% CVE-level accuracy. | `p01...\analysis\07_evaluation.txt` | Usable with `[NEEDS TABLE REPAIR]` before exact citation |
| Dataset contains 1,128 C/C++ vulnerabilities from nine projects. | `p01...\analysis\06_experiments.txt` | Source-backed, table details need repair |
| VulnVersion Step1 filters fix-family and patch chunks. | `SystemDesign\Architecture\Develop\step1.md` | Design-backed |
| VulnVersion Step2 extracts root-cause-level VET. | `SystemDesign\Architecture\Develop\step2.md` | Design-backed |
| VulnVersion Step3 uses release-line planning, ASBS/sentinel probes, and agent tag verdicts. | `SystemDesign\Architecture\Develop\step3.md` | Design-backed |
| VulnVersion full effectiveness on 1,128 CVEs. | None yet | `[NEEDS EXPERIMENT]` |
| VulnVersion ablation results. | None yet | `[NEEDS EXPERIMENT]` |
| VulnVersion token/cost/runtime on full benchmark. | None yet | `[NEEDS EXPERIMENT]` |
| Official BibTeX metadata for all references. | Partial local extraction only | `[NEEDS CITATION VERIFICATION]` |
| Cross-paper writing/method/evaluation patterns. | `Paper\text\reference_synthesis\*.md` from all parsed `Paper\reference\pNN_` directories | Source-backed synthesis, still inherits each paper's repair labels |

## Citation Readiness

- Current `references.bib` is a compile-oriented placeholder bibliography.
- Entries with `unverified` keys are not yet citation-ready and should be replaced after PDF analysis or official metadata lookup.
- Do not submit the paper with placeholder BibTeX entries.

## Next Evidence Tasks

1. Repair p01 baseline/dataset tables that will be cited numerically.
2. Verify official BibTeX metadata for all cited papers.
3. Decide whether pilot 32-case results belong in the paper or should remain internal.
4. Run the full \toolname evaluation on the p01 dataset before writing final results.
5. Analyze remaining unprocessed replication PDFs if they will be discussed beyond title-level citation placeholders.
6. Use `reference_synthesis/07_vulnversion_paper_upgrade_plan.md` as the next section-edit checklist.

# VulnVersion Paper Upgrade Plan

## Stage 2 Edits to Apply Now

1. Introduction:
   - Strengthen the distinction among commit localization, clone/code resemblance, and per-tag vulnerability state verification.
   - Add a clearer design thesis: deterministic planning plus scoped agent verdicts.
   - Keep results out of the introduction except [NEEDS EXPERIMENT].

2. Background/Problem:
   - Add a taxonomy paragraph: direct affected-version methods, commit-localization methods, recurring-vulnerability matching, and LLM/agent methods.
   - Add requirements derived from references: patch-family awareness, root-cause evidence, version-line modeling, resource-aware agent verdicts.

3. Method Placeholder:
   - Add method patterns from the corpus without inventing final algorithms:
     - cheap-to-expensive evidence flow,
     - patch-family semantics,
     - VET as root-cause evidence,
     - release-line graph planning,
     - scoped agent API and cost logging.

4. Evaluation Design:
   - Expand RQs to include:
     - RQ1 main effectiveness,
     - RQ2 robustness by patch/scope/branch,
     - RQ3 ablation,
     - RQ4 cost/resource behavior,
     - RQ5 error analysis and manual workload/lower-bound recall if needed.

5. Related Work:
   - Reorganize by taxonomy rather than chronological list.
   - Add p32 and p33 more explicitly to direct affected-version work.
   - Separate SZZ/BIC methods from affected-version methods.

6. Threats:
   - Add artifact/citation validity and dual-use paragraph.
   - Add baseline-reproduction boundary.

## Edits to Delay Until Evidence Exists

- Any exact VulnVersion result.
- Any exact comparison against p01 baselines.
- Any full-benchmark claim.
- Any official BibTeX metadata not verified.
- Any figure/table numeric claim from references with [NEEDS TABLE REPAIR].

## Priority Evidence Tasks After This Upgrade

1. Repair p01 Table II/Table III/Table IV or cite them only qualitatively.
2. Verify BibTeX for p01, p09, p20, p25, p32, p33 first.
3. Select one VulnVersion running example and build a problem figure.
4. Run or assemble the full evaluation on p01's benchmark.
5. Decide whether agent memory/skill evolution is a main contribution or future work.

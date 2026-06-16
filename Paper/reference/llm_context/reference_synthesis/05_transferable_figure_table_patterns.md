# Transferable Figure and Table Patterns

## Required Figures for VulnVersion

1. Overview figure: CVE/fix evidence -> Step1 patch semantics -> Step2 VET -> Step3 version-line planning -> selected tag verdicts -> affected versions.
   - Sources: p01 overview, p02 staged pipeline, p16/p25 agent workflow, p32 version tree.
   - Boundary: solid edges for deterministic data flow, dotted edges for agent/memory support.

2. Problem example figure: one CVE where patch lines, root cause, release tags, and branch lines diverge.
   - Sources: p04 and p07 use patch examples effectively; p09 uses version-history cases.
   - Status: [NEEDS EVIDENCE] choose a VulnVersion case.

3. Evaluation result table: rows are baselines plus VulnVersion; columns are CVE exact TP/Accuracy/NM/NMR and version FP/FN/TP/P/R/F1.
   - Source: p01 Table III structure.
   - Status: [NEEDS EXPERIMENT].

4. Robustness table/figure: patch type, modification scope, branch context.
   - Source: p01 RQ3 figures.
   - Status: [NEEDS EXPERIMENT].

5. Ablation table: Step1, Step2, Step3 planning, agent verdict, memory/tooling variants.
   - Sources: p04, p06, p16, p20, p25, p33.
   - Status: [NEEDS EXPERIMENT].

6. Cost/behavior table: time, tokens, cost, tool calls, probe tags, failure rate.
   - Sources: p16, p20, p25, p33.
   - Status: [NEEDS EXPERIMENT].

7. Error taxonomy figure/table: failure bucket counts and representative examples.
   - Sources: p01, p04, p06, p07, p11, p32.
   - Status: [NEEDS EXPERIMENT].

## Figure/Table Design Rules

- Put task and data flow in the first overview figure, not only architecture internals. Source: p01.
- Use staged blocks where each block has a failure-mode purpose. Sources: p02, p06, p16.
- Separate CVE-level and version-level metrics in tables. Sources: p01, p20, p33.
- Include resource/cost table for any LLM/agent component. Sources: p16, p20, p25, p33.
- Use manual workload/lower-bound recall if complete FN validation is impractical. Source: p32.
- Do not reproduce any extracted table values until [NEEDS TABLE REPAIR] is resolved.

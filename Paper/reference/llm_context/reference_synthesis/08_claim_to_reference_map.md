# Claim-to-Reference Map

| Draft claim type | Supported by | Readiness | Notes |
| --- | --- | --- | --- |
| Affected-version identification is distinct from BIC/VIC localization. | p01, p04, p06, p08, p09, p16, p25 | Citation-ready qualitatively after BibTeX verification | Avoid mixing metrics. |
| Current methods can be grouped into tracing-based and matching-based families. | p01 | Strong, but official citation metadata pending | Use p01 as anchor. |
| Existing affected-version tools struggle with noisy patches, semantic mismatch, add-only patches, and multi-branch settings. | p01, p09, p20, p32, p33 | Qualitative strong; exact rates need [NEEDS TABLE REPAIR] | Good for motivation. |
| Staged filtering before expensive verification is a useful design pattern. | p02, p05, p07, p10, p12, p13 | Strong as structural inspiration | Not direct affected-version claim. |
| Patch signatures or clone matches are not equivalent to semantic vulnerable-state proof. | p05, p07, p10, p13, p33 | Strong qualitative claim | Use in related work and limitations. |
| LLM/agent systems should report cost, tokens, turns/tool calls, and model/backbone sensitivity. | p04, p16, p20, p25, p33 | Strong as evaluation-design pattern | p25 artifact tables are static-read candidates; still verify citation. |
| Version trees / temporal graphs help reason about branch history. | p19, p32, p03 | Qualitative usable | Exact p19/p32 tables need repair. |
| VulnVersion will outperform baselines. | None | [NEEDS EXPERIMENT] | Do not write as a claim yet. |
| VulnVersion Step1/Step2/Step3 architecture is confirmed. | SystemDesign plus p01/p02/p06/p16/p32 as inspiration | Design-backed, not result-backed | Mark method details as placeholders. |
| p01 benchmark is the planned evaluation dataset. | p01 and user instruction | Strong | Need artifact/data availability before reproduction claims. |
| Current `references.bib` is official. | None | [NEEDS CITATION VERIFICATION] | Keep TODO notes. |

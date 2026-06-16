# Corpus Inventory

Source root: `E:\AI\Agent\workflow\Paper\reference`

This inventory covers the 20 currently parsed `pNN_` reference directories. The corpus is usable for paper drafting, but citation readiness is uneven: most papers are strong for qualitative framing, method inspiration, and evaluation-design patterns; exact numeric claims still require table repair and official citation verification unless noted otherwise.

| paper_id | Role for VulnVersion paper | Best use | Current blockers |
| --- | --- | --- | --- |
| p01_vulnerability_affected_versions_how_far_are_we | Main baseline, dataset, task definition | Problem definition, baseline taxonomy, RQ/metrics, failure taxonomy | [NEEDS TABLE REPAIR], [NEEDS CITATION VERIFICATION], [NEEDS ARTIFACT] |
| p02_fire_combining_multi_stage_filtering_with_taint_analysis_for_scalable_recurring_vulnerability_detection | Staged recurring-vulnerability detector | Stage-gated filtering, expensive verifier after cheap filters, efficiency/ablation structure | [NEEDS TABLE REPAIR], [NEEDS FIGURE EXTRACTION], [NEEDS ARTIFACT] |
| p03_how_long_do_vulnerabilities_live_2021 | Empirical vulnerability-lifetime study | Question-driven empirical framing, repository-history measurement, validity boundaries | [NEEDS TABLE REPAIR], [NEEDS FIGURE EXTRACTION], [NEEDS CITATION VERIFICATION] |
| p04_llm4szz_2025 | LLM-assisted SZZ baseline | Branch-specific pipeline, model sensitivity, ablation and failure analysis | [NEEDS TABLE REPAIR], [NEEDS PROMPT REPAIR], [NEEDS ARTIFACT] |
| p05_movery_precise_modified_vulnerable_code_clone_discovery_2022 | Modified vulnerable-code clone detector | Vulnerability/patch signatures, modification taxonomy, search-space reduction | [NEEDS TABLE REPAIR], [NEEDS ARTIFACT] |
| p06_enhancing_bug_inducing_commit_identification_a_fine_grained_semantic_analysis_approach_2024 | Fine-grained semantic SZZ | Observation-to-component method writing, no-deletion/deletion split, parameter sensitivity | [NEEDS TABLE REPAIR], [NEEDS FIGURE EXTRACTION], [NEEDS ARTIFACT] |
| p07_redebug_finding_unpatched_code_clones_2012 | Classic syntax-based unpatched clone detector | Design-point tradeoff, database/query workflow, dual-use discussion | [NEEDS TABLE REPAIR], [NEEDS FIGURE EXTRACTION], [NEEDS ARTIFACT] |
| p08_evaluating_szz_implementations_linux_kernel_2024 | Empirical SZZ evaluation | Stronger oracle framing, ghost-commit failure taxonomy, dataset validity | [NEEDS TABLE REPAIR], [NEEDS FIGURE EXTRACTION], [NEEDS ARTIFACT] |
| p09_v_szz_automatic_identification_version_ranges_2022 | Direct affected-version ICSE baseline | Version-range problem framing, V-SZZ assumptions, false-negative caution | [NEEDS TABLE REPAIR], [NEEDS FIGURE EXTRACTION], [NEEDS ARTIFACT] |
| p10_v1scan_discovering_1_day_vulnerabilities_2023 | Version+code hybrid 1-day detector | Hybrid metadata/code evidence framing, FP/FN reduction narrative | [NEEDS TABLE REPAIR], [NEEDS FIGURE EXTRACTION], [NEEDS ARTIFACT] |
| p11_vccfinder_finding_potential_vulnerabilities_in_open_source_projects_to_assist_code_audits_2015 | VCC/audit prioritization baseline | Noisy-label caveat, data construction before model, temporal evaluation | [NEEDS TABLE REPAIR], [NEEDS ARTIFACT] |
| p12_enhancing_security_third_party_library_reuse_2025 | VULTURE/TPL vulnerability detector | Database -> reuse detection -> version/chunk vulnerability-state analysis | [NEEDS TABLE REPAIR], [NEEDS FIGURE EXTRACTION], [NEEDS ARTIFACT] |
| p13_vuddy_scalable_vulnerable_code_clone_discovery_2017 | Function-fingerprint vulnerable clone detector | Preprocess-once/query-fast architecture, scalability/case-study evaluation | [NEEDS TABLE REPAIR], [NEEDS FIGURE EXTRACTION], [NEEDS FORMULA REPAIR] |
| p14_accurate_identification_of_the_vulnerability_introducing_commit_based_on_differential_anal | Patch-pattern VIC method | Patching-pattern taxonomy, vulnerability-critical sequence extraction | [NEEDS TABLE REPAIR], [NEEDS FIGURE EXTRACTION], [NEEDS CITATION VERIFICATION] |
| p16_agentszz_teaching_the_llm_agent_to_play_detective_with_bug_inducing_commits | Agentic BIC method | Tool-interface design, context compression, cross-file/ghost motivation | [NEEDS TABLE REPAIR], [NEEDS ARTIFACT], [NEEDS CITATION VERIFICATION] |
| p19_beyond_blame_rethinking_szz_with_knowledge_graph_search | Temporal-KG/agentic SZZ | Temporal commit graph framing, graph search as historical reasoning | [NEEDS TABLE REPAIR], [NEEDS ARTIFACT], [NEEDS CITATION VERIFICATION] |
| p20_cavulner_automated_context_aware_identification_of_vulnerable_versions | LLM/context-aware vulnerable-version method | CVE-level and version-level evaluation, LLM resource metrics, vulnerable-version baselines | [NEEDS TABLE REPAIR], [NEEDS ARTIFACT], [NEEDS CITATION VERIFICATION] |
| p25_how_and_why_agents_can_identify_bug_introducing_commits | Artifact-backed agentic BIC analysis | Why-agent analysis, tool-call/cost figures, stage ablation, artifact-backed tables | [NEEDS CITATION VERIFICATION], [NEEDS TABLE REPAIR] for PDF crops |
| p32_tdsc_automatically_identifying_cve_affected_versions_with_patches_and_developer_logs | Patch+developer-log affected-version method | Version-tree directions R1/R2/R3, lower-bound recall, manual workload reporting | [NEEDS TABLE REPAIR], [NEEDS ARTIFACT], [NEEDS CITATION VERIFICATION] |
| p33_vercation_precise_vulnerable_open_source_software_version_identification_based_on_static_a | Static analysis + LLM vulnerable-version method | Static candidate extraction before LLM, statement-level clone/LLM framing, resource metrics | [NEEDS TABLE REPAIR], [NEEDS FIGURE EXTRACTION], [NEEDS CITATION VERIFICATION] |

## Corpus-Level Readiness

- Directly useful now: problem framing, related-work taxonomy, method-design inspiration, RQ design, metric definitions, threats-to-validity patterns.
- Use with caution: exact baseline numbers, exact dataset statistics, figure/table visual claims.
- Not ready without further work: official BibTeX, artifact reproducibility claims, our own VulnVersion effectiveness claims.

# expanded_27 v1 vs v2 comparison

## v1
- completed_cases: 27
- agent_failed_cases: 0
- finding_count: 38
- severity_counts: {'warn': 38}
- issue_counts: {'cert_fixed_with_uncertainty': 12, 'empty_line_risk_signals': 2, 'empty_negative_evidence': 12, 'reviewed_with_uncertainty': 12}

## v2
- completed_cases: 27
- agent_failed_cases: 0
- finding_count: 79
- severity_counts: {'error': 44, 'warn': 35}
- issue_counts: {'empty_evidence_item_source_refs': 8, 'empty_fix_evidence': 1, 'empty_necessary_conditions': 1, 'empty_negative_evidence': 22, 'empty_source_refs': 1, 'empty_vulnerable_condition_evidence': 1, 'missing_evidence_item_field': 40, 'reviewed_vet_with_uncertainty': 5}

## v2 evidence
- total evidence_items: 176
- evidence_items per case: {'min': 4, 'max': 10, 'avg': 6.518518518518518}

## v2 worst cases
- FFmpeg/CVE-2020-22019: findings=52, evidence_items=7, issues={'empty_source_refs': 1, 'empty_necessary_conditions': 1, 'empty_vulnerable_condition_evidence': 1, 'empty_fix_evidence': 1, 'empty_negative_evidence': 1, 'missing_evidence_item_field': 40, 'empty_evidence_item_source_refs': 7}
- qemu/CVE-2021-3416: findings=3, evidence_items=6, issues={'empty_negative_evidence': 1, 'reviewed_vet_with_uncertainty': 1, 'empty_evidence_item_source_refs': 1}
- openssl/CVE-2022-2097: findings=2, evidence_items=9, issues={'empty_negative_evidence': 1, 'reviewed_vet_with_uncertainty': 1}
- wireshark/CVE-2020-11647: findings=1, evidence_items=6, issues={'empty_negative_evidence': 1}
- httpd/CVE-2020-11985: findings=1, evidence_items=6, issues={'empty_negative_evidence': 1}
- httpd/CVE-2020-11993: findings=1, evidence_items=5, issues={'empty_negative_evidence': 1}
- qemu/CVE-2020-14394: findings=1, evidence_items=8, issues={'empty_negative_evidence': 1}
- FFmpeg/CVE-2020-20453: findings=1, evidence_items=6, issues={'empty_negative_evidence': 1}

## archetype changes
- qemu/CVE-2020-14394: loop_bound_missing -> loop_boundary_control
- FFmpeg/CVE-2020-20453: missing_clamp -> missing_lower_bound
- httpd/CVE-2020-9490: security_feature_removal_with_logic_correction -> status_error_handling_or_logic_correction
- qemu/CVE-2021-3416: reentrancy_guard_bypass -> bounds_length_check
- qemu/CVE-2021-3544: missing_cleanup -> multi_site_memory_leak_resource_lifecycle
- ImageMagick/CVE-2021-39212: missing_authorization_check -> missing_security_policy_enforcement
- wireshark/CVE-2021-4182: infinite_loop_bounds_check -> input_validation_invariant
- openssl/CVE-2022-2097: loop_boundary_off_by_one -> fencepost_loop_boundary

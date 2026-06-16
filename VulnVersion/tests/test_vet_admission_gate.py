from __future__ import annotations

from tests.simulate_vet_admission_gate import (
    CaseEvidence,
    TagChecks,
    _absent_gate_reasons,
    _clear_reasons,
    _fixed_gate_reasons,
)


def _case(**kwargs) -> CaseEvidence:
    base = dict(
        repo="repo",
        cve_id="CVE-X",
        cert_absent_allowed=True,
        cert_fixed_allowed=True,
        uncertainty=[],
        negative_evidence=["neg"],
        source_refs=[{"source_ref": "src:CVE-X:commit:path:git_diff"}],
        hard_certificate_candidates=[{"type": "guard_present"}],
        admission_requirements=["req"],
        forbidden_hard_certificates=["generic token"],
        line_risk_signals=[{"signal": "risk"}],
        scope_files=["src/a.c"],
        scope_functions=["vuln_fn"],
        fix_tokens=["if (x < n)"],
        vulnerable_tokens=["copy(dst, src, n)"],
        quality_issues=set(),
    )
    base.update(kwargs)
    return CaseEvidence(**base)


def test_fixed_gate_blocks_uncertainty_and_missing_negative_evidence():
    ev = _case(uncertainty=["needs review"], negative_evidence=[])
    reasons = _fixed_gate_reasons(ev)
    assert "uncertainty_present" in reasons
    assert "negative_evidence_missing" in reasons


def test_absent_gate_requires_structured_source_refs_and_line_signals():
    ev = _case(source_refs=["plain-text-ref"], line_risk_signals=[])
    reasons = _absent_gate_reasons(ev)
    assert "source_refs_not_structured" in reasons
    assert "line_risk_signals_missing" in reasons


def test_ultra_strict_fixed_requires_vulnerable_token_absent():
    ev = _case()
    checks = TagChecks(
        file_exists=True,
        function_hit=True,
        vulnerable_token_hit=True,
        fix_token_hit=True,
        checked_paths=["src/a.c"],
        errors=[],
    )
    assert _clear_reasons("strict_fixed_token_and_vuln_absent", ev, checks, True, True) == []


def test_scope_absent_can_clear_only_when_absent_gate_passes():
    ev = _case()
    checks = TagChecks(
        file_exists=False,
        function_hit=False,
        vulnerable_token_hit=False,
        fix_token_hit=False,
        checked_paths=["src/a.c"],
        errors=[],
    )
    assert _clear_reasons("strict_absent_scope_only", ev, checks, True, True) == ["strict_scope_file_absent"]
    assert _clear_reasons("strict_absent_scope_only", ev, checks, True, False) == []

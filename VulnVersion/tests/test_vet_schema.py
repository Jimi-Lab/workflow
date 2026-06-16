from vulnversion.stage2_rci_navigation.schema import RCIModel
from vulnversion.stage2_rci_navigation.vet_schema import RootCauseVet, VetPattern


def test_weak_vet_pattern_is_not_certificate_candidate():
  vet = RootCauseVet(
    cve_id="CVE-TEST",
    root_cause_files=[
      VetPattern(
        pattern_id="file:weak",
        kind="file",
        value="lib/example.c",
        strength="weak",
        allowed_uses=["priority", "prompt_context"],
      )
    ],
  )

  assert [p.value for p in vet.priority_patterns()] == ["lib/example.c"]
  assert vet.certificate_candidates() == []


def test_strong_localized_vet_pattern_can_be_certificate_candidate():
  vet = RootCauseVet(
    cve_id="CVE-TEST",
    vulnerable_sequences=[
      VetPattern(
        pattern_id="seq:root-cause",
        kind="vulnerable_sequence",
        value="len + offset",
        strength="strong",
        allowed_uses=["priority", "prompt_context", "certificate_candidate"],
      )
    ],
  )

  candidates = vet.certificate_candidates()
  assert len(candidates) == 1
  assert candidates[0].pattern_id == "seq:root-cause"


def test_rci_model_preserves_root_cause_vet():
  rci = RCIModel.model_validate(
    {
      "cve_id": "CVE-TEST",
      "fix_commit": "fix",
      "vuln_commit": "",
      "root_cause_vet": {
        "cve_id": "CVE-TEST",
        "repo": "repo",
        "root_cause_summary": "localized parser boundary issue",
        "grep_patterns": [
          {
            "pattern_id": "grep:guard",
            "kind": "grep_pattern",
            "value": "if (len < 0)",
            "strength": "medium",
            "allowed_uses": ["priority", "prompt_context"],
          }
        ],
      },
    }
  )

  assert rci.root_cause_vet.cve_id == "CVE-TEST"
  assert rci.root_cause_vet.root_cause_summary == "localized parser boundary issue"
  assert rci.root_cause_vet.priority_patterns()[0].value == "if (len < 0)"


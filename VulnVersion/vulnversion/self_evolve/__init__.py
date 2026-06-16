"""Offline self-evolution utilities for VulnVersion agent enhancement.

This package is deliberately kept out of the main CVE pipeline.  It builds
case-backed evidence for future memory, skill, prompt, and artifact changes.
"""

from vulnversion.self_evolve.case_pack import build_case_pack
from vulnversion.self_evolve.memory_store import build_memory_store
from vulnversion.self_evolve.schema import AgentEnhanceCase, CasePackManifest

__all__ = ["AgentEnhanceCase", "CasePackManifest", "build_case_pack", "build_memory_store"]

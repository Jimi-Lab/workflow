from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from vulnversion.agent_harness.config import default_agent_backend


def _project_root() -> Path:
  return Path(__file__).resolve().parents[1]


def _load_env_file(path: Path) -> dict[str, str]:
  if not path.exists():
    return {}
  out: dict[str, str] = {}
  for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
      continue
    if "=" not in line:
      continue
    name, val = line.split("=", 1)
    name = name.strip()
    val = val.strip()
    if not name:
      continue
    out[name] = val
  return out


def _bootstrap_dotenv() -> None:
  env_path = _project_root() / ".env"
  kv = _load_env_file(env_path)
  for k, v in kv.items():
    if k:
      os.environ[k] = v


_bootstrap_dotenv()


def _default_model_id() -> str | None:
  return os.getenv("OPENCODE_MODEL_ID") or os.getenv("OPENAI_MODEL") or None


def _default_provider_id() -> str | None:
  return os.getenv("OPENCODE_PROVIDER_ID") or None


class Config(BaseModel):
  model_config = {"protected_namespaces": ()}
  agent_backend: str = Field(default_factory=default_agent_backend)
  artifacts_dir: str = Field(default="Result")
  dataset_path: str = Field(default="DataSet/BaseDataOrder.json")
  nvd_cache_path: str = Field(default="DataSet/BaseData_nvd.json")
  nvd_crawler_path: str = Field(default="DataSet/nvd_crawler.py")
  opencode_base_url: str = Field(default="http://127.0.0.1:4096")
  opencode_username: str | None = Field(default=None)
  opencode_password: str | None = Field(default=None)
  opencode_provider_id: str | None = Field(default_factory=_default_provider_id)
  opencode_model_id: str | None = Field(default_factory=_default_model_id)
  opencode_agent: str | None = Field(default=None)
  repomaster_root: str | None = Field(default=None)
  gt_tag_match_mode: str = Field(default="loose")

  # ── Timeout configuration ──
  stage1_per_chunk_timeout_s: float = Field(default=300.0)    # 5min per chunk annotation
  stage2_rci_timeout_s: float = Field(default=900.0)          # 15min for RCI induction
  stage2_rci_retry_timeout_s: float = Field(default=600.0)    # 10min for strict JSON retry
  stage3_per_tag_timeout_s: float = Field(default=900.0)      # 15min per tag verification
  stage3_total_timeout_s: float = Field(default=7200.0)       # 2h for Stage 3 total
  cve_total_timeout_s: float = Field(default=10800.0)         # 3h per CVE total

  # ── Multi-LLM configuration ──
  # Override via --model CLI flag or OPENCODE_MODEL_PROFILE env var.
  # Each profile maps to a (provider_id, model_id) pair with per-model tuning.
  model_profile: str | None = Field(default=None)


# Pre-defined LLM profiles for benchmarking across different providers.
LLM_PROFILES: dict[str, dict[str, Any]] = {
    "deepseek-v3": {
        "provider_id": "deepseek",
        "model_id": "deepseek-chat",
        "per_tag_timeout_s": 600,
        "description": "DeepSeek V3 — fast, cost-effective",
    },
    "deepseek-r1": {
        "provider_id": "deepseek",
        "model_id": "deepseek-reasoner",
        "per_tag_timeout_s": 900,
        "description": "DeepSeek R1 — reasoning-focused",
    },
    "gpt-4o": {
        "provider_id": "openai",
        "model_id": "gpt-4o",
        "per_tag_timeout_s": 600,
        "description": "OpenAI GPT-4o",
    },
    "gpt-4.1": {
        "provider_id": "openai",
        "model_id": "gpt-4.1",
        "per_tag_timeout_s": 600,
        "description": "OpenAI GPT-4.1",
    },
    "claude-sonnet": {
        "provider_id": "anthropic",
        "model_id": "claude-sonnet-4-6",
        "per_tag_timeout_s": 600,
        "description": "Anthropic Claude Sonnet 4.6",
    },
    "claude-haiku": {
        "provider_id": "anthropic",
        "model_id": "claude-haiku-4-5-20251001",
        "per_tag_timeout_s": 600,
        "description": "Anthropic Claude Haiku 4.5",
    },
    "minimax": {
        "provider_id": "minimax",
        "model_id": "abab7-chat",
        "per_tag_timeout_s": 900,
        "description": "MiniMax abab7 — slower, needs longer timeout",
    },
    "qwen": {
        "provider_id": "dashscope",
        "model_id": "qwen-max",
        "per_tag_timeout_s": 600,
        "description": "Alibaba Qwen Max",
    },
}


def resolve_model_config(cfg: Config) -> tuple[str | None, str | None, float]:
    """Resolve (provider_id, model_id, per_tag_timeout_s) from config + profile."""
    profile_name = cfg.model_profile or os.getenv("OPENCODE_MODEL_PROFILE")
    if profile_name and profile_name in LLM_PROFILES:
        profile = LLM_PROFILES[profile_name]
        return (
            profile["provider_id"],
            profile["model_id"],
            float(profile.get("per_tag_timeout_s", cfg.stage3_per_tag_timeout_s)),
        )
    return cfg.opencode_provider_id, cfg.opencode_model_id, cfg.stage3_per_tag_timeout_s

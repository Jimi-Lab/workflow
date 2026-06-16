from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, cast

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
	sys.path.insert(0, str(_PROJECT_ROOT))

from vulnversion.config import Config
from vulnversion.opencode.client import OpenCodeAuth, OpenCodeClient


def _dig_model_hints(obj: Any, path: str = "") -> list[tuple[str, Any]]:
	hints: list[tuple[str, Any]] = []
	keys = {"model", "modelid", "providerid", "provider", "agent"}
	if isinstance(obj, dict):
		for k, v in obj.items():
			p = f"{path}.{k}" if path else str(k)
			if str(k).lower() in keys:
				hints.append((p, v))
			hints.extend(_dig_model_hints(v, p))
	elif isinstance(obj, list):
		for i, v in enumerate(obj):
			p = f"{path}[{i}]" if path else f"[{i}]"
			hints.extend(_dig_model_hints(v, p))
	return hints


def _pick_effective(value_from_cli: str | None, value_from_cfg: str | None) -> str | None:
	if value_from_cli:
		return value_from_cli
	if value_from_cfg:
		return value_from_cfg
	return None


def _load_json(path: Path) -> Any:
	return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
	parser = argparse.ArgumentParser(description="Probe OpenCode and print the model currently being used.")
	parser.add_argument("--base-url", default=None, help="OpenCode base URL, e.g. http://127.0.0.1:4096")
	parser.add_argument("--config", default="vuln_config.json", help="Path to VulnVersion config JSON")
	parser.add_argument("--username", default=None, help="OpenCode username")
	parser.add_argument("--password", default=None, help="OpenCode password")
	parser.add_argument("--provider-id", default=None, help="Force providerID for probe request")
	parser.add_argument("--model-id", default=None, help="Force modelID for probe request")
	parser.add_argument("--agent", default=None, help="Force agent id/name for probe request")
	parser.add_argument("--timeout", type=float, default=60.0, help="HTTP timeout seconds")
	parser.add_argument("--show-raw", action="store_true", help="Print full raw /agent and probe response")
	parser.add_argument("--reply-timeout", type=float, default=20.0, help="Seconds to wait for assistant reply")
	args = parser.parse_args()

	cfg = Config()
	cfg_path = Path(args.config)
	if not cfg_path.is_absolute():
		cfg_path = (_PROJECT_ROOT / cfg_path).resolve()
	if cfg_path.exists():
		cfg = Config.model_validate(_load_json(cfg_path))
	base_url = _pick_effective(args.base_url, cfg.opencode_base_url)
	if not base_url:
		base_url = "http://127.0.0.1:4096"
	username = _pick_effective(args.username, cfg.opencode_username)
	password = _pick_effective(args.password, cfg.opencode_password)
	provider_id = _pick_effective(args.provider_id, cfg.opencode_provider_id)
	model_id = _pick_effective(args.model_id, cfg.opencode_model_id)
	agent_id = _pick_effective(args.agent, cfg.opencode_agent)

	auth = OpenCodeAuth(username=username, password=password) if username and password else None
	client = OpenCodeClient(base_url=base_url, auth=auth, timeout_s=args.timeout)

	print("=== OpenCode Model Probe ===")
	print(f"base_url: {base_url}")
	print(f"env.OPENCODE_MODEL_ID: {os.getenv('OPENCODE_MODEL_ID')}")
	print(f"config.opencode_provider_id: {cfg.opencode_provider_id}")
	print(f"config.opencode_model_id: {cfg.opencode_model_id}")
	print(f"config.opencode_agent: {cfg.opencode_agent}")
	print()

	try:
		health = client.health()
		print("[OK] /global/health reachable")
		if args.show_raw:
			print(json.dumps(health, ensure_ascii=False, indent=2))
	except Exception as e:
		print(f"[ERROR] health check failed: {type(e).__name__}: {e}")
		return 2

	agents: list[dict[str, Any]] = []
	try:
		agents = client.list_agents()
		print(f"[OK] /agent count: {len(agents)}")
		for idx, agent in enumerate(agents[:10], start=1):
			hints = _dig_model_hints(agent)
			print(f"  agent[{idx}] hints:")
			if hints:
				for p, v in hints[:10]:
					print(f"    - {p} = {v}")
			else:
				print("    - (no explicit model fields found)")
		if len(agents) > 10:
			print(f"  ... ({len(agents) - 10} more agents omitted)")
		if args.show_raw:
			print("\n[RAW /agent]")
			print(json.dumps(agents, ensure_ascii=False, indent=2))
	except Exception as e:
		print(f"[WARN] list_agents failed: {type(e).__name__}: {e}")

	try:
		session = client.create_session(title="TestOpencode-model-probe")
		session_id = session.get("id")
		if not isinstance(session_id, str) or not session_id:
			raise RuntimeError("invalid session id")

		before = client.list_messages(session_id=session_id)

		probe_text = (
			"Reply with exactly this JSON: "
			'{"ok":true,"note":"model probe"}'
		)
		probe_msg = client.send_message(
			session_id=session_id,
			text=probe_text,
			provider_id=provider_id,
			model_id=model_id,
			agent=agent_id,
		)

		print("\n=== Effective Request Settings ===")
		print(f"provider_id used: {provider_id}")
		print(f"model_id used: {model_id}")
		print(f"agent used: {agent_id}")
		print("tip: if model_id above is None, OpenCode is using its server-side default model.")

		hints = _dig_model_hints(probe_msg)
		print("\n=== Probe Response Model Hints ===")
		if hints:
			for p, v in hints[:20]:
				print(f"- {p} = {v}")
		else:
			print("- No explicit model fields in immediate response payload.")

		deadline = time.monotonic() + max(0.1, float(args.reply_timeout))
		assistant_msg: dict[str, Any] | None = None
		assistant_err: str | None = None
		start = len(before)
		while time.monotonic() < deadline:
			msgs = client.list_messages(session_id=session_id)
			for m in reversed(msgs[start:]):
				raw_info = m.get("info")
				info = raw_info if isinstance(raw_info, dict) else {}
				if info.get("role") != "assistant":
					continue
				raw_err = info.get("error")
				err = raw_err if isinstance(raw_err, dict) else {}
				if err:
					name = err.get("name") or "assistant_error"
					raw_data = err.get("data")
					data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
					raw_msg = data.get("message")
					msg = raw_msg if isinstance(raw_msg, str) else ""
					assistant_err = f"{name}: {msg}" if msg else str(name)
					assistant_msg = m
					break
				assistant_msg = m
				break
			if assistant_msg is not None:
				break
			time.sleep(0.8)

		print("\n=== Assistant Reply Check ===")
		if assistant_msg is None:
			print("- No assistant reply observed within timeout.")
			print("- Immediate /message call can return 200 with empty body; this indicates provider/runtime issue.")
			return 4
		if assistant_err:
			print(f"- Assistant returned error: {assistant_err}")
			if args.show_raw:
				print("\n[RAW assistant error message]")
				print(json.dumps(assistant_msg, ensure_ascii=False, indent=2))
			return 5

		assistant = cast(dict[str, Any], assistant_msg)
		raw_parts = assistant.get("parts")
		parts: list[Any] = raw_parts if isinstance(raw_parts, list) else []
		text_parts = [p.get("text", "") for p in parts if isinstance(p, dict) and p.get("type") == "text"]
		combined = "\n".join(t for t in text_parts if isinstance(t, str)).strip()
		print("- Assistant reply received.")
		if combined:
			print(f"- First 200 chars: {combined[:200]}")
		else:
			print("- Assistant reply has no text parts.")

		if args.show_raw:
			print("\n[RAW probe response]")
			print(json.dumps(probe_msg, ensure_ascii=False, indent=2))

		print("\n=== Conclusion ===")
		if model_id:
			print(f"Current configured model appears to be: {model_id}")
		else:
			print("Current model is controlled by OpenCode server default (no explicit model_id from client config).")
			print("Use --show-raw and inspect /agent hints to identify exact server default model.")
		return 0
	except Exception as e:
		print(f"[ERROR] probe failed: {type(e).__name__}: {e}")
		return 3


if __name__ == "__main__":
	raise SystemExit(main())

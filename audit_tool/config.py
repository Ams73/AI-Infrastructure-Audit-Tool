"""Audit configuration: per-check overrides and run settings.

Example:
    {
      "command_timeout": 60,
      "checks": {
        "LNX-DISK-001": {"params": {"warn_percent": 75, "fail_percent": 85}},
        "WIN-DEF-001": {"severity": "high"},
        "LNX-CRON-001": {"enabled": false}
      }
    }

Validation is strict: unknown check IDs, keys and parameter names are errors,
so a typo cannot silently weaken an audit.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from audit_tool.checks import Check
from audit_tool.models import Severity

_TOP_LEVEL_KEYS = {"command_timeout", "checks"}
_OVERRIDE_KEYS = {"enabled", "severity", "params"}


class ConfigError(Exception):
    pass


def load_config(path: str) -> Dict[str, Any]:
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"Config file not found: {path}")
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Config file {path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigError("Config must be a JSON object")
    unknown = set(payload) - _TOP_LEVEL_KEYS
    if unknown:
        raise ConfigError(f"Unknown config keys: {', '.join(sorted(unknown))}")
    if "checks" in payload and not isinstance(payload["checks"], dict):
        raise ConfigError(
            "'checks' must be an object mapping check IDs to overrides "
            "(the list format from v0.1.0 is no longer supported; see sample_config.json)"
        )
    timeout = payload.get("command_timeout", 60)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout <= 0:
        raise ConfigError("'command_timeout' must be a positive integer (seconds)")
    return payload


def apply_config(checks: List[Check], config: Dict[str, Any]) -> List[Check]:
    overrides: Dict[str, Any] = config.get("checks", {})
    by_id = {check.id: check for check in checks}
    unknown_ids = set(overrides) - set(by_id)
    if unknown_ids:
        raise ConfigError(f"Unknown check IDs in config: {', '.join(sorted(unknown_ids))}")

    result = []
    for check in checks:
        override = overrides.get(check.id)
        if override is None:
            result.append(check)
            continue
        if not isinstance(override, dict):
            raise ConfigError(f"{check.id}: override must be an object")
        unknown_keys = set(override) - _OVERRIDE_KEYS
        if unknown_keys:
            raise ConfigError(f"{check.id}: unknown keys {', '.join(sorted(unknown_keys))}")

        severity = override.get("severity")
        if severity is not None and severity not in Severity.ALL:
            raise ConfigError(f"{check.id}: severity must be one of {', '.join(Severity.ALL)}")
        enabled = override.get("enabled")
        if enabled is not None and not isinstance(enabled, bool):
            raise ConfigError(f"{check.id}: 'enabled' must be true or false")
        params = override.get("params") or {}
        if not isinstance(params, dict):
            raise ConfigError(f"{check.id}: 'params' must be an object")
        unknown_params = set(params) - set(check.params)
        if unknown_params:
            allowed = ", ".join(sorted(check.params)) or "none"
            raise ConfigError(
                f"{check.id}: unknown params {', '.join(sorted(unknown_params))} (allowed: {allowed})"
            )
        result.append(check.with_overrides(severity=severity, params=params, enabled=enabled))
    return result

#!/usr/bin/env python3
"""Tool registration profile control."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable, Set


SUPPORTED_PROFILES = {"strict", "compliance", "full"}

# Module keys in mcp_server.setup_mcp_server
ALL_MODULE_KEYS = {
    "v3",
    "multi_agent",
    "recon",
    "ai_session",
    "code_audit",
    "misc",
    "apt",
    "ctf",
    "scan_workflow",
    "advanced_ctf",
    "session",
    "pwn",
    "adaptive",
    "vuln_mgmt",
    "chain_mgmt",
    "pentagi_bridge",
    "llm_react",
    "v2",
    "vuln_db",
    "deep_test",
    "assessment",
    "browser",       # v6.0: 反检测浏览器引擎
    "kali_extended", # v6.1: Kali 扩展工具补全
}

DEFAULT_DISABLED_BY_PROFILE = {
    # Strict profile: only assessment tools.
    "strict": {
        "v2",
        "v3",
        "multi_agent",
        "recon",
        "ai_session",
        "code_audit",
        "misc",
        "apt",
        "ctf",
        "scan_workflow",
        "advanced_ctf",
        "session",
        "pwn",
        "adaptive",
        "vuln_mgmt",
        "chain_mgmt",
        "pentagi_bridge",
        "llm_react",
        "vuln_db",
        "deep_test",
        "browser",
        "kali_extended",
    },
    # Compliance profile: disable high-risk modules.
    "compliance": {"apt", "deep_test", "pwn", "advanced_ctf", "browser"},
    "full": set(),
}


def _norm_set(values: Iterable[str]) -> Set[str]:
    normalized = set()
    for value in values:
        value = (value or "").strip().lower()
        if value:
            normalized.add(value)
    return normalized


def _env_csv(name: str) -> Set[str]:
    raw = os.getenv(name, "")
    if not raw:
        return set()
    return _norm_set(raw.split(","))


@dataclass(frozen=True)
class ToolProfile:
    name: str
    disabled: Set[str]
    force_enabled: Set[str]

    def allows(self, module_key: str) -> bool:
        key = (module_key or "").strip().lower()
        if not key:
            return False
        if key in self.force_enabled:
            return True
        return key not in self.disabled

    def summary(self) -> dict:
        return {
            "profile": self.name,
            "disabled_modules": sorted(self.disabled),
            "force_enabled_modules": sorted(self.force_enabled),
        }


def load_tool_profile(
    profile_name: str | None = None,
    force_enable: Iterable[str] | None = None,
    force_disable: Iterable[str] | None = None,
) -> ToolProfile:
    profile = (profile_name or os.getenv("KALI_MCP_TOOL_PROFILE", "compliance")).strip().lower()
    if profile not in SUPPORTED_PROFILES:
        profile = "compliance"

    disabled = set(DEFAULT_DISABLED_BY_PROFILE.get(profile, set()))
    disabled |= _env_csv("KALI_MCP_FORCE_DISABLE_MODULES")
    if force_disable:
        disabled |= _norm_set(force_disable)

    enabled = _env_csv("KALI_MCP_FORCE_ENABLE_MODULES")
    if force_enable:
        enabled |= _norm_set(force_enable)

    # Only keep known module keys
    disabled &= ALL_MODULE_KEYS
    enabled &= ALL_MODULE_KEYS

    # force-enabled always wins
    disabled -= enabled

    return ToolProfile(name=profile, disabled=disabled, force_enabled=enabled)

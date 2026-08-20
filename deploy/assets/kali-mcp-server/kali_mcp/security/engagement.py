#!/usr/bin/env python3
"""Engagement context and scope guard for compliant pentesting."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse


TARGET_PATTERN = re.compile(r"(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3}")


def _to_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    if not text:
        return []
    if "," in text:
        return [x.strip() for x in text.split(",") if x.strip()]
    return [text]


def _parse_dt(value: str) -> Optional[datetime]:
    try:
        # Accept RFC3339-ish or YYYY-MM-DD
        if "T" in value:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        return datetime.fromisoformat(value + "T00:00:00+00:00")
    except Exception:
        return None


@dataclass
class EngagementContext:
    authorization_id: str
    client: str
    authorized_by: str
    valid_from: str
    valid_until: str
    target_scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    allowed_actions: List[str] = field(default_factory=list)
    forbidden_actions: List[str] = field(default_factory=list)
    data_handling: str = "Minimize and protect sensitive data"
    reporting_standard: str = "OWASP/PTES"
    emergency_stop_contact: str = ""


class EngagementManager:
    """Holds engagement context and validates scope."""

    # No tools are denied by default — all tools are available.
    COMPLIANCE_DENY_TOOLS: set = set()

    def __init__(self) -> None:
        self.require_context = os.getenv("KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT", "0").lower() not in {
            "0",
            "false",
            "no",
        }
        self.profile = os.getenv("KALI_MCP_TOOL_PROFILE", "compliance").strip().lower()
        self.context: Optional[EngagementContext] = None
        self._load_from_env()

    def set_profile(self, profile: str) -> str:
        """Sync runtime profile from server startup arguments."""
        normalized = (profile or "").strip().lower() or "compliance"
        self.profile = normalized
        return self.profile

    def _load_from_env(self) -> None:
        payload = os.getenv("KALI_MCP_ENGAGEMENT_JSON", "").strip()
        file_path = os.getenv("KALI_MCP_ENGAGEMENT_FILE", "").strip()

        if payload:
            try:
                self.set_context(json.loads(payload))
                return
            except Exception:
                return

        if file_path:
            path = Path(file_path)
            if path.exists():
                try:
                    with path.open("r", encoding="utf-8") as f:
                        self.set_context(json.load(f))
                except Exception:
                    return

    def set_context(self, data: Dict[str, Any]) -> Dict[str, Any]:
        required = [
            "authorization_id",
            "client",
            "authorized_by",
            "valid_from",
            "valid_until",
            "target_scope",
        ]
        missing = [k for k in required if not data.get(k)]
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")

        context = EngagementContext(
            authorization_id=str(data["authorization_id"]).strip(),
            client=str(data["client"]).strip(),
            authorized_by=str(data["authorized_by"]).strip(),
            valid_from=str(data["valid_from"]).strip(),
            valid_until=str(data["valid_until"]).strip(),
            target_scope=_to_list(data.get("target_scope")),
            out_of_scope=_to_list(data.get("out_of_scope")),
            allowed_actions=_to_list(data.get("allowed_actions")),
            forbidden_actions=_to_list(data.get("forbidden_actions")),
            data_handling=str(data.get("data_handling", "Minimize and protect sensitive data")).strip(),
            reporting_standard=str(data.get("reporting_standard", "OWASP/PTES")).strip(),
            emergency_stop_contact=str(data.get("emergency_stop_contact", "")).strip(),
        )
        self.context = context
        return self.get_context()

    def clear_context(self) -> None:
        self.context = None

    def get_context(self) -> Dict[str, Any]:
        if not self.context:
            return {}
        payload = asdict(self.context)
        payload["active"] = self.is_context_active()
        return payload

    def is_context_active(self) -> bool:
        if not self.context:
            return False
        start = _parse_dt(self.context.valid_from)
        end = _parse_dt(self.context.valid_until)
        if not start or not end:
            return False
        now = datetime.now(timezone.utc)
        return start <= now <= end

    def render_context_block(self) -> str:
        if not self.context:
            return "No engagement context configured"
        c = self.context
        lines = [
            "Engagement Context Block (ECB)",
            f"Authorization ID: {c.authorization_id}",
            f"Client/Owner: {c.client}",
            f"Authorized By: {c.authorized_by}",
            f"Valid From: {c.valid_from}",
            f"Valid Until: {c.valid_until}",
            f"Target Scope: {', '.join(c.target_scope)}",
            f"Out of Scope: {', '.join(c.out_of_scope)}",
            f"Allowed Actions: {', '.join(c.allowed_actions)}",
            f"Forbidden Actions: {', '.join(c.forbidden_actions)}",
            f"Data Handling Rules: {c.data_handling}",
            f"Reporting Standard: {c.reporting_standard}",
            f"Emergency Stop Contact: {c.emergency_stop_contact}",
            "Constraint: Defensive, authorized testing only.",
        ]
        return "\n".join(lines)

    @staticmethod
    def extract_targets(text: str) -> List[str]:
        if not text:
            return []
        found = TARGET_PATTERN.findall(text)
        return sorted(set(found))

    def _normalize_host(self, value: str) -> str:
        v = (value or "").strip()
        if not v:
            return ""
        if "://" in v:
            parsed = urlparse(v)
            return (parsed.hostname or "").lower()
        return v.lower()

    def _domain_matches(self, host: str, scope: str) -> bool:
        """Check if host matches scope using proper domain hierarchy comparison.

        host='sub.example.com', scope='example.com'  True
        host='example.com', scope='example.com'  True
        host='notexample.com', scope='example.com'  False
        host='example.com', scope='ample.com'  False
        """
        if host == scope:
            return True
        host_labels = host.split('.')
        scope_labels = scope.split('.')
        # host must have MORE labels than scope for subdomain match
        if len(host_labels) <= len(scope_labels):
            return False
        # Check that the rightmost labels match exactly
        return host_labels[-len(scope_labels):] == scope_labels

    def _in_scope(self, host: str) -> bool:
        if not self.context:
            return not self.require_context

        host = self._normalize_host(host)
        if not host:
            return True

        out_scopes = [self._normalize_host(s) for s in self.context.out_of_scope]
        for blocked in out_scopes:
            if not blocked:
                continue
            if self._domain_matches(host, blocked):
                return False

        scopes = [self._normalize_host(s) for s in self.context.target_scope]
        for scope in scopes:
            if not scope:
                continue

            # CIDR
            try:
                network = ipaddress.ip_network(scope, strict=False)
                ip = ipaddress.ip_address(host)
                if ip in network:
                    return True
                continue
            except Exception:
                pass

            if scope.startswith("*."):
                suffix = scope[2:]
                if self._domain_matches(host, suffix):
                    return True
                continue

            if self._domain_matches(host, scope):
                return True

        return False

    def validate_targets(self, targets: Iterable[str]) -> Tuple[bool, str]:
        target_list = [t for t in targets if (t or "").strip()]

        if not self.context:
            if self.require_context:
                return False, "No engagement context configured"
            return True, "No context required"

        if not self.is_context_active():
            return False, "Engagement authorization is expired or invalid"

        if not target_list:
            # No explicit host found; allow and let command-level policy decide.
            return True, "No explicit target extracted"

        for target in target_list:
            if not self._in_scope(target):
                return False, f"Target out of scope: {target}"

        return True, "Targets within authorized scope"

    def is_tool_allowed(self, tool_name: str) -> Tuple[bool, str]:
        t = (tool_name or "").strip().lower()
        if self.profile not in {"strict", "compliance"}:
            return True, "Profile allows tool"
        if t in self.COMPLIANCE_DENY_TOOLS:
            return False, f"Tool denied in {self.profile} profile: {t}"
        return True, f"Tool allowed in {self.profile} profile"


engagement_manager = EngagementManager()

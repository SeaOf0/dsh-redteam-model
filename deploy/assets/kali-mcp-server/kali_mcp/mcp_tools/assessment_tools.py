#!/usr/bin/env python3
"""Neutral-name, authorized security assessment tools."""

from __future__ import annotations

import ipaddress
import time
from datetime import datetime
from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse

from kali_mcp.security import engagement_manager


DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
DEFAULT_PORTS = "21,22,25,53,80,110,143,443,445,3389,8080,8443"

DEPTH_PROFILES = {
    "quick": {
        "nmap_scan_type": "-sV -T3",
        "masscan_rate": "1000",
        "nuclei_severity": "critical,high",
        "gobuster_threads": "20",
    },
    "standard": {
        "nmap_scan_type": "-sV -sC -T3",
        "masscan_rate": "2500",
        "nuclei_severity": "critical,high",
        "gobuster_threads": "30",
    },
    "thorough": {
        "nmap_scan_type": "-sV -sC -O -T2",
        "masscan_rate": "5000",
        "nuclei_severity": "critical,high,medium",
        "gobuster_threads": "40",
    },
}

ACTION_ALIASES = {
    "credential-audit": {
        "credential-audit",
        "credential_audit",
        "credential-auditing",
        "credential-audit-validation",
    },
    "controlled-validation": {
        "controlled-validation",
        "active-validation",
        "exploitation-validation",
        "exploit-validation",
        "exploitation_validation",
    },
    "environment-review": {
        "environment-review",
        "post-validation",
        "post-exploitation-validation",
        "post_exploitation_validation",
        "post-assessment-review",
    },
}


def _now_iso() -> str:
    return datetime.now().isoformat()


def _normalize_depth(depth: str) -> str:
    normalized = (depth or "").strip().lower()
    if normalized not in DEPTH_PROFILES:
        return "standard"
    return normalized


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except Exception:
        return False


def _normalize_allowed_actions(actions: Iterable[str]) -> set[str]:
    normalized = set()
    for action in actions or []:
        text = str(action).strip().lower().replace("_", "-")
        if text:
            normalized.add(text)
    return normalized


def _action_allowed(allowed_actions: set[str], canonical: str) -> bool:
    aliases = ACTION_ALIASES.get(canonical, {canonical})
    return any(alias in allowed_actions for alias in aliases)


def _extract_host(raw_target: str) -> str:
    value = (raw_target or "").strip()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        return (parsed.hostname or "").strip().lower()

    # Accept host/path and host:port input styles.
    head = value.split("/", 1)[0]
    if ":" in head and head.count(":") == 1:
        head = head.split(":", 1)[0]
    return head.strip().strip("[]").lower()


def _prepare_target(target: str) -> Dict[str, Any]:
    raw = (target or "").strip()
    has_scheme = "://" in raw
    host = _extract_host(raw)
    ip_target = _is_ip(host)

    if has_scheme:
        parsed = urlparse(raw)
        scheme = parsed.scheme or ("http" if ip_target else "https")
        netloc = parsed.netloc or host
        path = parsed.path or ""
        primary_web_url = f"{scheme}://{netloc}{path}" if netloc else raw
        base_web_url = f"{scheme}://{netloc}" if netloc else raw
    else:
        default_scheme = "http" if ip_target else "https"
        primary_web_url = f"{default_scheme}://{host}" if host else raw
        base_web_url = primary_web_url

    if primary_web_url.startswith("https://"):
        fallback_url = primary_web_url.replace("https://", "http://", 1)
    elif primary_web_url.startswith("http://"):
        fallback_url = primary_web_url.replace("http://", "https://", 1)
    else:
        fallback_url = ""

    web_candidates = [u for u in [primary_web_url, fallback_url] if u]
    unique_candidates: List[str] = []
    for candidate in web_candidates:
        if candidate not in unique_candidates:
            unique_candidates.append(candidate)

    target_type = "host"
    if has_scheme:
        target_type = "url"
    elif ip_target:
        target_type = "ip"
    elif "." in host:
        target_type = "domain"

    return {
        "input": raw,
        "host": host,
        "domain": host if host and not ip_target and "." in host else "",
        "is_ip": ip_target,
        "target_type": target_type,
        "primary_web_url": primary_web_url,
        "base_web_url": base_web_url,
        "web_url_candidates": unique_candidates,
        "scope_candidates": [value for value in [raw, host] if value],
    }


def _execute_tool(executor, tool_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    started = time.monotonic()
    started_at = _now_iso()
    result = executor.execute_tool_with_data(tool_name, payload)
    finished_at = _now_iso()
    duration = round(time.monotonic() - started, 3)

    if not isinstance(result, dict):
        result = {
            "success": False,
            "error": "invalid tool response format",
            "raw_result": str(result),
        }

    return {
        "tool": tool_name,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": duration,
        "success": bool(result.get("success")),
        "payload": payload,
        "result": result,
    }


def _execute_with_fallback(executor, tool_name: str, payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
    attempts = [_execute_tool(executor, tool_name, payload) for payload in payloads]
    success = any(attempt.get("success") for attempt in attempts)
    selected = next((idx + 1 for idx, attempt in enumerate(attempts) if attempt.get("success")), len(attempts))
    return {
        "tool": tool_name,
        "success": success,
        "selected_attempt": selected,
        "attempts": attempts,
    }


def _phase_result(
    phase: str,
    tools: Dict[str, Any] | None = None,
    *,
    skipped: bool = False,
    reason: str = "",
) -> Dict[str, Any]:
    tools = tools or {}
    success = any(bool(item.get("success")) for item in tools.values()) if not skipped else True
    return {
        "phase": phase,
        "skipped": skipped,
        "reason": reason,
        "success": success,
        "tools": tools,
    }


def _summarize_phases(phases: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    total = len(phases)
    skipped = sum(1 for phase in phases.values() if phase.get("skipped"))
    executed = total - skipped
    succeeded = sum(1 for phase in phases.values() if not phase.get("skipped") and phase.get("success"))
    failed = max(executed - succeeded, 0)
    return {
        "phases_total": total,
        "phases_skipped": skipped,
        "phases_executed": executed,
        "phases_succeeded": succeeded,
        "phases_failed": failed,
    }


def _phase_asset_inventory(executor, prepared: Dict[str, Any], depth: str) -> Dict[str, Any]:
    domain = prepared.get("domain", "")
    if not domain:
        return _phase_result(
            "asset_inventory",
            skipped=True,
            reason="target is not a resolvable domain, skip external asset inventory",
        )

    tools: Dict[str, Any] = {}
    subfinder_args = "-silent"
    if depth == "thorough":
        subfinder_args = "-silent -all"

    amass_mode = "enum"
    amass_args = "-passive"
    if depth == "thorough":
        amass_args = ""

    tools["subdomain_inventory"] = _execute_tool(
        executor,
        "subfinder",
        {
            "domain": domain,
            "sources": "",
            "additional_args": subfinder_args,
        },
    )
    tools["domain_expansion"] = _execute_tool(
        executor,
        "amass",
        {
            "domain": domain,
            "mode": amass_mode,
            "additional_args": amass_args,
        },
    )
    tools["live_http_inventory"] = _execute_tool(
        executor,
        "httpx",
        {
            "targets": domain,
            "additional_args": "-status-code -title -td",
        },
    )
    return _phase_result("asset_inventory", tools)


def _phase_surface_mapping(executor, prepared: Dict[str, Any], depth: str, ports: str) -> Dict[str, Any]:
    host = prepared.get("host", "")
    if not host:
        return _phase_result("surface_mapping", skipped=True, reason="empty target host")

    depth_cfg = DEPTH_PROFILES[depth]
    tools: Dict[str, Any] = {}
    tools["service_discovery_nmap"] = _execute_tool(
        executor,
        "nmap",
        {
            "target": host,
            "scan_type": depth_cfg["nmap_scan_type"],
            "ports": ports,
            "additional_args": "--open",
        },
    )
    tools["port_exposure_masscan"] = _execute_tool(
        executor,
        "masscan",
        {
            "target": host,
            "ports": ports or DEFAULT_PORTS,
            "rate": depth_cfg["masscan_rate"],
            "additional_args": "",
        },
    )

    if prepared.get("domain"):
        tools["dns_enumeration"] = _execute_tool(
            executor,
            "dnsrecon",
            {
                "domain": prepared["domain"],
                "scan_type": "-t std",
                "additional_args": "",
            },
        )

    return _phase_result("surface_mapping", tools)


def _phase_web_exposure(
    executor,
    prepared: Dict[str, Any],
    depth: str,
    wordlist: str,
) -> Dict[str, Any]:
    host = prepared.get("host", "")
    web_urls = prepared.get("web_url_candidates") or []
    if not host or not web_urls:
        return _phase_result("web_exposure_review", skipped=True, reason="no web target detected")

    depth_cfg = DEPTH_PROFILES[depth]
    primary = web_urls[0]
    tools: Dict[str, Any] = {}
    tools["technology_fingerprint"] = _execute_with_fallback(
        executor,
        "whatweb",
        [{"target": candidate, "aggression": "1", "additional_args": ""} for candidate in web_urls],
    )
    tools["server_review"] = _execute_with_fallback(
        executor,
        "nikto",
        [{"target": candidate, "additional_args": "-Display V"} for candidate in web_urls],
    )
    tools["content_discovery"] = _execute_with_fallback(
        executor,
        "gobuster",
        [
            {
                "url": candidate,
                "mode": "dir",
                "wordlist": wordlist,
                "additional_args": f"-q -t {depth_cfg['gobuster_threads']}",
            }
            for candidate in web_urls
        ],
    )
    tools["fuzz_surface_check"] = _execute_with_fallback(
        executor,
        "ffuf",
        [
            {
                "url": f"{candidate.rstrip('/')}/FUZZ",
                "wordlist": wordlist,
                "mode": "FUZZ",
                "additional_args": "-ac -timeout 10",
            }
            for candidate in web_urls
        ],
    )
    tools["waf_observation"] = _execute_tool(
        executor,
        "wafw00f",
        {
            "target": primary,
            "additional_args": "-a",
        },
    )
    return _phase_result("web_exposure_review", tools)


def _phase_vulnerability_validation(
    executor,
    prepared: Dict[str, Any],
    depth: str,
    post_data: str = "",
) -> Dict[str, Any]:
    host = prepared.get("host", "")
    web_urls = prepared.get("web_url_candidates") or []
    if not host:
        return _phase_result("vulnerability_validation", skipped=True, reason="empty target host")

    depth_cfg = DEPTH_PROFILES[depth]
    tools: Dict[str, Any] = {}
    tools["template_validation"] = _execute_tool(
        executor,
        "nuclei",
        {
            "target": prepared.get("base_web_url") or host,
            "severity": depth_cfg["nuclei_severity"],
            "templates": "http/,network/",
            "tags": "",
            "output_format": "json",
            "additional_args": "-silent",
        },
    )

    if web_urls:
        sqlmap_args = "--batch --risk=1 --level=1 --threads=1 --timeout=15"
        if depth == "thorough":
            sqlmap_args = "--batch --risk=2 --level=2 --threads=2 --timeout=15"
        tools["injection_verification"] = _execute_with_fallback(
            executor,
            "sqlmap",
            [
                {
                    "url": candidate,
                    "data": post_data,
                    "additional_args": sqlmap_args,
                }
                for candidate in web_urls
            ],
        )

    return _phase_result("vulnerability_validation", tools)


def _phase_credential_audit(
    executor,
    prepared: Dict[str, Any],
    username_file: str,
    password_file: str,
    service: str,
) -> Dict[str, Any]:
    host = prepared.get("host", "")
    if not host:
        return _phase_result("credential_audit", skipped=True, reason="empty target host")
    if not username_file or not password_file:
        return _phase_result(
            "credential_audit",
            skipped=True,
            reason="username_file and password_file are required for credential audit",
        )

    tools = {
        "credential_strength_check": _execute_tool(
            executor,
            "hydra",
            {
                "target": host,
                "service": service or "ssh",
                "username_file": username_file,
                "password_file": password_file,
                "additional_args": "-t 2 -W 3",
            },
        )
    }
    return _phase_result("credential_audit", tools)


def _phase_controlled_validation(executor, prepared: Dict[str, Any]) -> Dict[str, Any]:
    host = prepared.get("host", "")
    if not host:
        return _phase_result("controlled_validation", skipped=True, reason="empty target host")

    tools = {
        "public_intel_lookup": _execute_tool(
            executor,
            "searchsploit",
            {
                "term": host,
                "additional_args": "",
            },
        ),
        "service_version_validation": _execute_tool(
            executor,
            "metasploit",
            {
                "module": "auxiliary/scanner/http/http_version",
                "options": {"RHOSTS": host},
            },
        ),
    }
    return _phase_result("controlled_validation", tools)


def _phase_environment_review(executor, prepared: Dict[str, Any]) -> Dict[str, Any]:
    host = prepared.get("host", "")
    if not host:
        return _phase_result("environment_review", skipped=True, reason="empty target host")

    tools = {
        "privilege_path_review": _execute_tool(
            executor,
            "enum4linux",
            {
                "target": host,
                "additional_args": "-a",
            },
        )
    }
    return _phase_result("environment_review", tools)


def _scope_denied(target: str, reason: str) -> Dict[str, Any]:
    return {
        "success": False,
        "target": target,
        "error": f"scope validation failed: {reason}",
        "authorization_context_active": engagement_manager.is_context_active(),
        "timestamp": _now_iso(),
    }


def register_assessment_tools(mcp, executor, adapter=None):
    """Register compliance-friendly assessment tools with neutral naming."""

    @mcp.tool()
    def authorized_surface_mapping(
        target: str,
        ports: str = "",
        depth: str = "quick",
    ) -> Dict[str, Any]:
        """Perform authorized attack-surface mapping (non-destructive)."""
        prepared = _prepare_target(target)
        in_scope, reason = engagement_manager.validate_targets(prepared["scope_candidates"])
        if not in_scope:
            return _scope_denied(target, reason)

        normalized_depth = _normalize_depth(depth)
        phase = _phase_surface_mapping(executor, prepared, normalized_depth, ports)
        return {
            "success": phase.get("success", False),
            "target": target,
            "target_profile": prepared,
            "depth": normalized_depth,
            "phase": phase,
        }

    @mcp.tool()
    def authorized_network_exposure_assessment(
        target: str,
        depth: str = "standard",
        ports: str = "",
    ) -> Dict[str, Any]:
        """Run authorized network exposure assessment with phase-level output."""
        prepared = _prepare_target(target)
        in_scope, reason = engagement_manager.validate_targets(prepared["scope_candidates"])
        if not in_scope:
            return _scope_denied(target, reason)

        normalized_depth = _normalize_depth(depth)
        phases = {
            "surface_mapping": _phase_surface_mapping(executor, prepared, normalized_depth, ports),
            "vulnerability_validation": _phase_vulnerability_validation(executor, prepared, normalized_depth),
        }
        summary = _summarize_phases(phases)
        return {
            "success": summary["phases_succeeded"] > 0,
            "target": target,
            "target_profile": prepared,
            "depth": normalized_depth,
            "summary": summary,
            "phases": phases,
        }

    @mcp.tool()
    def authorized_web_exposure_review(
        url: str,
        wordlist: str = DEFAULT_WORDLIST,
        depth: str = "standard",
    ) -> Dict[str, Any]:
        """Review web exposure through content discovery and service checks."""
        prepared = _prepare_target(url)
        in_scope, reason = engagement_manager.validate_targets(prepared["scope_candidates"])
        if not in_scope:
            return _scope_denied(url, reason)

        normalized_depth = _normalize_depth(depth)
        phase = _phase_web_exposure(executor, prepared, normalized_depth, wordlist)
        return {
            "success": phase.get("success", False),
            "target": url,
            "target_profile": prepared,
            "depth": normalized_depth,
            "phase": phase,
        }

    @mcp.tool()
    def authorized_web_application_assessment(
        target: str,
        depth: str = "standard",
        wordlist: str = DEFAULT_WORDLIST,
        post_data: str = "",
    ) -> Dict[str, Any]:
        """Run authorized web assessment with exposure review and vuln validation."""
        prepared = _prepare_target(target)
        in_scope, reason = engagement_manager.validate_targets(prepared["scope_candidates"])
        if not in_scope:
            return _scope_denied(target, reason)

        normalized_depth = _normalize_depth(depth)
        phases = {
            "web_exposure_review": _phase_web_exposure(executor, prepared, normalized_depth, wordlist),
            "vulnerability_validation": _phase_vulnerability_validation(executor, prepared, normalized_depth, post_data),
        }
        summary = _summarize_phases(phases)
        return {
            "success": summary["phases_succeeded"] > 0,
            "target": target,
            "target_profile": prepared,
            "depth": normalized_depth,
            "summary": summary,
            "phases": phases,
        }

    @mcp.tool()
    def authorized_injection_verification(
        url: str,
        post_data: str = "",
        depth: str = "standard",
    ) -> Dict[str, Any]:
        """Run non-destructive injection verification only (no dump/exfiltration)."""
        prepared = _prepare_target(url)
        in_scope, reason = engagement_manager.validate_targets(prepared["scope_candidates"])
        if not in_scope:
            return _scope_denied(url, reason)

        normalized_depth = _normalize_depth(depth)
        phase = _phase_vulnerability_validation(executor, prepared, normalized_depth, post_data)
        injection_part = phase.get("tools", {}).get("injection_verification")
        success = bool(injection_part and injection_part.get("success"))
        return {
            "success": success,
            "target": url,
            "target_profile": prepared,
            "depth": normalized_depth,
            "injection_verification": injection_part,
        }

    @mcp.tool()
    def authorized_template_validation(
        target: str,
        severity: str = "critical,high",
    ) -> Dict[str, Any]:
        """Run template-based security validation with constrained severity scope."""
        prepared = _prepare_target(target)
        in_scope, reason = engagement_manager.validate_targets(prepared["scope_candidates"])
        if not in_scope:
            return _scope_denied(target, reason)

        result = _execute_tool(
            executor,
            "nuclei",
            {
                "target": prepared.get("base_web_url") or prepared.get("host") or target,
                "severity": severity,
                "templates": "http/,network/",
                "tags": "",
                "output_format": "json",
                "additional_args": "-silent",
            },
        )
        return {
            "success": result.get("success", False),
            "target": target,
            "target_profile": prepared,
            "template_validation": result,
        }

    @mcp.tool()
    def authorized_asset_inventory(domain: str, depth: str = "standard") -> Dict[str, Any]:
        """Build authorized external asset inventory (subdomains + live hosts)."""
        prepared = _prepare_target(domain)
        in_scope, reason = engagement_manager.validate_targets(prepared["scope_candidates"])
        if not in_scope:
            return _scope_denied(domain, reason)

        normalized_depth = _normalize_depth(depth)
        phase = _phase_asset_inventory(executor, prepared, normalized_depth)
        return {
            "success": phase.get("success", False),
            "target": domain,
            "target_profile": prepared,
            "depth": normalized_depth,
            "phase": phase,
        }

    @mcp.tool()
    def authorized_credential_assessment(
        target: str,
        username_file: str = "",
        password_file: str = "",
        service: str = "ssh",
    ) -> Dict[str, Any]:
        """Run authorized credential audit phase only when allowed_actions permits it."""
        prepared = _prepare_target(target)
        in_scope, reason = engagement_manager.validate_targets(prepared["scope_candidates"])
        if not in_scope:
            return _scope_denied(target, reason)

        allowed_actions = _normalize_allowed_actions(engagement_manager.get_context().get("allowed_actions") or [])
        if not _action_allowed(allowed_actions, "credential-audit"):
            return {
                "success": False,
                "target": target,
                "error": "credential audit not authorized in allowed_actions",
                "required_action": "credential-audit",
                "allowed_actions": sorted(allowed_actions),
            }

        phase = _phase_credential_audit(executor, prepared, username_file, password_file, service)
        return {
            "success": phase.get("success", False),
            "target": target,
            "target_profile": prepared,
            "phase": phase,
        }

    @mcp.tool()
    def authorized_controlled_validation(target: str) -> Dict[str, Any]:
        """Run controlled validation phase only when allowed_actions permits it."""
        prepared = _prepare_target(target)
        in_scope, reason = engagement_manager.validate_targets(prepared["scope_candidates"])
        if not in_scope:
            return _scope_denied(target, reason)

        allowed_actions = _normalize_allowed_actions(engagement_manager.get_context().get("allowed_actions") or [])
        if not _action_allowed(allowed_actions, "controlled-validation"):
            return {
                "success": False,
                "target": target,
                "error": "controlled validation not authorized in allowed_actions",
                "required_action": "controlled-validation",
                "allowed_actions": sorted(allowed_actions),
            }

        phase = _phase_controlled_validation(executor, prepared)
        return {
            "success": phase.get("success", False),
            "target": target,
            "target_profile": prepared,
            "phase": phase,
        }

    @mcp.tool()
    def authorized_environment_review(target: str) -> Dict[str, Any]:
        """Run environment review phase only when allowed_actions permits it."""
        prepared = _prepare_target(target)
        in_scope, reason = engagement_manager.validate_targets(prepared["scope_candidates"])
        if not in_scope:
            return _scope_denied(target, reason)

        allowed_actions = _normalize_allowed_actions(engagement_manager.get_context().get("allowed_actions") or [])
        if not _action_allowed(allowed_actions, "environment-review"):
            return {
                "success": False,
                "target": target,
                "error": "environment review not authorized in allowed_actions",
                "required_action": "environment-review",
                "allowed_actions": sorted(allowed_actions),
            }

        phase = _phase_environment_review(executor, prepared)
        return {
            "success": phase.get("success", False),
            "target": target,
            "target_profile": prepared,
            "phase": phase,
        }

    @mcp.tool()
    def authorized_comprehensive_security_assessment(
        target: str,
        depth: str = "standard",
        include_credential_audit: bool = False,
        include_exploitation_validation: bool = False,
        include_post_exploitation_validation: bool = False,
        include_controlled_validation: bool = False,
        include_environment_review: bool = False,
        username_file: str = "",
        password_file: str = "",
        credential_service: str = "ssh",
        ports: str = "",
        wordlist: str = DEFAULT_WORDLIST,
        post_data: str = "",
    ) -> Dict[str, Any]:
        """
        Run authorized full-chain assessment using neutral external naming.

        High-risk phases are gated by engagement_context.allowed_actions.
        """
        if adapter and adapter.should_use_agent("authorized_comprehensive_security_assessment", {"target": target, "depth": depth}):
            return adapter.execute_via_agent("authorized_comprehensive_security_assessment", {
                "target": target, "depth": depth,
                "include_credential_audit": include_credential_audit,
                "include_exploitation_validation": include_exploitation_validation,
            })

        started_at = _now_iso()
        normalized_depth = _normalize_depth(depth)
        prepared = _prepare_target(target)
        in_scope, scope_reason = engagement_manager.validate_targets(prepared["scope_candidates"])
        if not in_scope:
            return _scope_denied(target, scope_reason)

        allowed_actions = _normalize_allowed_actions(engagement_manager.get_context().get("allowed_actions") or [])
        controlled_validation_required = include_controlled_validation or include_exploitation_validation
        environment_review_required = include_environment_review or include_post_exploitation_validation

        authorization_errors: List[Dict[str, Any]] = []
        if include_credential_audit and not _action_allowed(allowed_actions, "credential-audit"):
            authorization_errors.append(
                {
                    "requested_phase": "credential_audit",
                    "required_action": "credential-audit",
                }
            )
        if controlled_validation_required and not _action_allowed(allowed_actions, "controlled-validation"):
            authorization_errors.append(
                {
                    "requested_phase": "controlled_validation",
                    "required_action": "controlled-validation",
                }
            )
        if environment_review_required and not _action_allowed(allowed_actions, "environment-review"):
            authorization_errors.append(
                {
                    "requested_phase": "environment_review",
                    "required_action": "environment-review",
                }
            )

        if authorization_errors:
            return {
                "success": False,
                "target": target,
                "started_at": started_at,
                "finished_at": _now_iso(),
                "error": "requested optional phases are not authorized in allowed_actions",
                "authorization_errors": authorization_errors,
                "allowed_actions": sorted(allowed_actions),
            }

        phases: Dict[str, Dict[str, Any]] = {
            "asset_inventory": _phase_asset_inventory(executor, prepared, normalized_depth),
            "surface_mapping": _phase_surface_mapping(executor, prepared, normalized_depth, ports),
            "web_exposure_review": _phase_web_exposure(executor, prepared, normalized_depth, wordlist),
            "vulnerability_validation": _phase_vulnerability_validation(executor, prepared, normalized_depth, post_data),
        }

        if include_credential_audit:
            phases["credential_audit"] = _phase_credential_audit(
                executor,
                prepared,
                username_file,
                password_file,
                credential_service,
            )
        if controlled_validation_required:
            phases["controlled_validation"] = _phase_controlled_validation(executor, prepared)
        if environment_review_required:
            phases["environment_review"] = _phase_environment_review(executor, prepared)

        summary = _summarize_phases(phases)
        finished_at = _now_iso()
        has_success = summary["phases_succeeded"] > 0
        overall_status = "partial_success"
        if summary["phases_failed"] == 0:
            overall_status = "success"
        elif not has_success:
            overall_status = "failed"

        return {
            "success": has_success,
            "overall_status": overall_status,
            "target": target,
            "target_profile": prepared,
            "started_at": started_at,
            "finished_at": finished_at,
            "depth": normalized_depth,
            "authorization_context_active": engagement_manager.is_context_active(),
            "allowed_actions": sorted(allowed_actions),
            "summary": summary,
            "phases": phases,
        }

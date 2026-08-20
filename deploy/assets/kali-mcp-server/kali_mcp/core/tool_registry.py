#!/usr/bin/env python3
"""
Declarative Tool Registry — Kali MCP Server v6.0

Replaces the 1000+ line elif chain in local_executor._build_tool_command() with a
data-driven registry.  Every tool supported by the executor is represented either as
a declarative ``ToolSpec`` (simple flag/value patterns) or as a custom builder
function (pipes, branching, dict-iteration, etc.).

Usage
-----
    from kali_mcp.core.tool_registry import build_command, get_tool_spec, ALLOWED_TOOLS

    cmd = build_command("nmap", {"target": "10.0.0.1", "scan_type": "-sV -sC"})
    spec = get_tool_spec("nmap")

Public API
----------
- ``build_command(tool_name, data)`` — returns the full shell command string.
- ``get_tool_spec(tool_name)`` — returns the ``ToolSpec`` for metadata inspection.
- ``get_output_parser_name(tool_name)`` — returns the parser key for a tool.
- ``ALLOWED_TOOLS`` — auto-generated set of all recognized tool names.
- ``TOOL_REGISTRY`` — the canonical ``Dict[str, ToolSpec]`` mapping.
- ``CUSTOM_BUILDERS`` — ``Dict[str, Callable]`` for tools with non-declarative logic.
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from kali_mcp.core.shell_utils import (
    sanitize_shell_arg,
    sanitize_shell_fragment,
    EXEC_CONFIG,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolParam:
    """Describes a single CLI parameter for a tool.

    Attributes:
        name:          Key looked up in the *data* dict passed by the caller.
        flag:          CLI flag string (e.g. ``"-p"``, ``"--url"``).  Empty
                       string means the value is emitted as a bare positional
                       argument.
        required:      If ``True``, the parameter MUST be present in *data*
                       (currently informational — build_command does not raise).
        default:       Fallback value when *data* does not contain the key.
        sanitize:      ``"arg"``   ``shlex.quote(value)``
                       ``"fragment"``  tokenise then quote each token
                       ``"none"``  pass through raw (use with extreme care)
        position:      ``""`` — normal ordered position.
                       ``"first"`` — placed immediately after the binary.
                       ``"last"`` — placed after *additional_args*.
        condition_key: When non-empty, the parameter is only included when
                       ``data.get(condition_key)`` is truthy.
        alt_keys:      Alternative keys to try when ``data[name]`` is missing.
        join:          Character(s) inserted between *flag* and *value*.
                       ``" "`` (default)  ``-p value``.
                       ``"="``  ``--rate=value``.
                       ``""``  ``-pvalue`` (no separator).
    """

    name: str
    flag: str = ""
    required: bool = False
    default: str = ""
    sanitize: str = "arg"          # "arg" | "fragment" | "none"
    position: str = ""             # "" | "first" | "last"
    condition_key: str = ""
    alt_keys: Tuple[str, ...] = ()
    join: str = " "


@dataclass(frozen=True)
class ToolSpec:
    """Complete specification for building a tool's CLI command.

    Attributes:
        binary:                  Executable name (e.g. ``"nmap"``).
        params:                  Ordered list of :class:`ToolParam`.
        base_args:               Always-included arguments (e.g. ``"--batch"``
                                 for sqlmap).  Position is controlled by
                                 ``base_args_position``.
        base_args_position:      ``"after"`` (default) — base_args go after
                                 normal params.  ``"before"`` — base_args go
                                 before normal params (right after binary).
        timeout:                 Default execution timeout in seconds.
        output_parser:           Name of the parser to apply to stdout
                                 (``""`` means no special parser).
        aliases:                 Alternative tool names that resolve to this
                                 spec (e.g. ``("aircrack",)`` for aircrack-ng).
        additional_args_sanitize: How *additional_args* from the data dict
                                 should be sanitised.
                                 ``"fragment"`` (default) uses
                                 ``sanitize_shell_fragment``.
                                 ``"arg"`` uses ``sanitize_shell_arg``.
    """

    binary: str
    params: List[ToolParam] = field(default_factory=list)
    base_args: str = ""
    base_args_position: str = "after"    # "after" | "before"
    timeout: int = 300
    output_parser: str = ""
    aliases: Tuple[str, ...] = ()
    additional_args_sanitize: str = "fragment"


# ---------------------------------------------------------------------------
# Declarative registry — tools that fit the ToolSpec model cleanly
# ---------------------------------------------------------------------------

TOOL_REGISTRY: Dict[str, ToolSpec] = {

    # ==================== Network Scanning ====================

    "nmap": ToolSpec(
        binary="nmap",
        params=[
            ToolParam(name="scan_type", flag="", sanitize="fragment", default="-sV", position="first"),
            ToolParam(name="target", flag="", sanitize="arg"),
            ToolParam(name="ports", flag="-p", sanitize="arg", condition_key="ports"),
        ],
        timeout=600,
        output_parser="nmap",
        additional_args_sanitize="fragment",
    ),

    "masscan": ToolSpec(
        binary="masscan",
        params=[
            ToolParam(name="target", flag="", sanitize="arg", position="first"),
            ToolParam(name="ports", flag="-p", sanitize="arg", default="80,443", join=""),
            ToolParam(name="rate", flag="--rate", sanitize="arg", default="1000", join="="),
        ],
        timeout=300,
        output_parser="masscan",
        additional_args_sanitize="arg",
    ),

    "zmap": ToolSpec(
        binary="zmap",
        params=[
            ToolParam(name="port", flag="-p", sanitize="arg", default="80"),
            ToolParam(name="rate", flag="-r", sanitize="arg", default="10000"),
            ToolParam(name="target", flag="", sanitize="arg"),
        ],
        additional_args_sanitize="arg",
    ),

    "fping": ToolSpec(
        binary="fping",
        params=[
            ToolParam(name="count", flag="-c", sanitize="arg", default="3"),
            ToolParam(name="targets", flag="", sanitize="arg"),
        ],
        additional_args_sanitize="arg",
    ),

    # ==================== DNS Tools ====================

    "dnsrecon": ToolSpec(
        binary="dnsrecon",
        params=[
            ToolParam(name="domain", flag="-d", sanitize="arg"),
            ToolParam(name="scan_type", flag="", sanitize="fragment", default="-t std"),
        ],
        additional_args_sanitize="fragment",
    ),

    "dnsenum": ToolSpec(
        binary="dnsenum",
        params=[
            ToolParam(name="domain", flag="", sanitize="arg"),
        ],
        additional_args_sanitize="fragment",
    ),

    "fierce": ToolSpec(
        binary="fierce",
        params=[
            ToolParam(name="domain", flag="--domain", sanitize="arg"),
        ],
        additional_args_sanitize="fragment",
    ),

    "dnsmap": ToolSpec(
        binary="dnsmap",
        params=[
            ToolParam(name="domain", flag="", sanitize="arg"),
            ToolParam(name="wordlist", flag="-w", sanitize="arg", condition_key="wordlist"),
        ],
        additional_args_sanitize="fragment",
    ),

    "sublist3r": ToolSpec(
        binary="sublist3r",
        params=[
            ToolParam(name="domain", flag="-d", sanitize="arg"),
        ],
        # additional_args has default "-v" — handled in build_from_spec via
        # the default value in data.get (the original code uses
        # data.get("additional_args", "-v"))
        additional_args_sanitize="fragment",
    ),

    "subfinder": ToolSpec(
        binary="subfinder",
        params=[
            ToolParam(name="domain", flag="-d", sanitize="arg"),
            ToolParam(name="sources", flag="-sources", sanitize="arg", condition_key="sources"),
        ],
        additional_args_sanitize="fragment",
    ),

    "amass": ToolSpec(
        binary="amass",
        params=[
            ToolParam(name="mode", flag="", sanitize="arg", default="enum", position="first"),
            ToolParam(name="domain", flag="-d", sanitize="arg"),
        ],
        additional_args_sanitize="fragment",
    ),

    # ==================== Web Scanning ====================

    "gobuster": ToolSpec(
        binary="gobuster",
        params=[
            ToolParam(name="mode", flag="", sanitize="arg", default="dir", position="first"),
            ToolParam(name="url", flag="-u", sanitize="arg"),
            ToolParam(name="wordlist", flag="-w", sanitize="arg",
                      default="/usr/share/wordlists/dirb/common.txt"),
        ],
        base_args="--no-error -q",
        timeout=180,
        output_parser="gobuster",
        additional_args_sanitize="fragment",
    ),

    # sqlmap is in CUSTOM_BUILDERS due to --batch placement between -u and --data=

    "nikto": ToolSpec(
        binary="nikto",
        params=[
            ToolParam(name="target", flag="-h", sanitize="arg"),
        ],
        base_args="-maxtime 240s",
        timeout=300,
        output_parser="nikto",
        additional_args_sanitize="fragment",
    ),

    "dirb": ToolSpec(
        binary="dirb",
        params=[
            ToolParam(name="url", flag="", sanitize="arg"),
            ToolParam(name="wordlist", flag="", sanitize="arg",
                      default="/usr/share/wordlists/dirb/common.txt"),
        ],
        additional_args_sanitize="fragment",
    ),

    "wfuzz": ToolSpec(
        binary="wfuzz",
        params=[
            ToolParam(name="wordlist", flag="-w", sanitize="arg",
                      default="/usr/share/wordlists/dirb/common.txt"),
            # additional_args goes here (default "-c"), then target last
            ToolParam(name="target", flag="", sanitize="arg", position="last"),
        ],
        additional_args_sanitize="fragment",
    ),

    "ffuf": ToolSpec(
        binary="ffuf",
        params=[
            ToolParam(name="url", flag="-u", sanitize="arg"),
            ToolParam(name="wordlist", flag="-w", sanitize="arg",
                      default="/usr/share/wordlists/dirb/common.txt"),
        ],
        timeout=180,
        additional_args_sanitize="fragment",
    ),

    "feroxbuster": ToolSpec(
        binary="feroxbuster",
        params=[
            ToolParam(name="url", flag="-u", sanitize="arg"),
            ToolParam(name="wordlist", flag="-w", sanitize="arg",
                      default="/usr/share/wordlists/dirb/common.txt"),
            ToolParam(name="threads", flag="-t", sanitize="arg", default="50"),
        ],
        additional_args_sanitize="fragment",
    ),

    "wafw00f": ToolSpec(
        binary="wafw00f",
        params=[
            ToolParam(name="target", flag="", sanitize="arg"),
        ],
        # additional_args default is "-a" — handled by _get_additional_args
        additional_args_sanitize="fragment",
    ),

    "whatweb": ToolSpec(
        binary="whatweb",
        params=[
            ToolParam(name="aggression", flag="-a", sanitize="arg", default="1"),
            ToolParam(name="target", flag="", sanitize="arg"),
        ],
        additional_args_sanitize="fragment",
    ),

    "wpscan": ToolSpec(
        binary="wpscan",
        params=[
            ToolParam(name="target", flag="--url", sanitize="arg"),
            # api_token goes after additional_args (at end of command)
            ToolParam(name="api_token", flag="--api-token", sanitize="arg",
                      condition_key="api_token", position="last"),
        ],
        base_args="--no-update",
        timeout=300,
        output_parser="wpscan",
        additional_args_sanitize="fragment",
    ),

    "joomscan": ToolSpec(
        binary="joomscan",
        params=[
            ToolParam(name="target", flag="-u", sanitize="arg"),
        ],
        additional_args_sanitize="fragment",
    ),

    # ==================== Password Cracking ====================

    "john": ToolSpec(
        binary="john",
        params=[
            ToolParam(name="wordlist", flag="--wordlist", sanitize="arg",
                      default="/usr/share/wordlists/rockyou.txt", join="="),
            ToolParam(name="format_type", flag="--format", sanitize="arg",
                      condition_key="format_type", join="="),
            ToolParam(name="hash_file", flag="", sanitize="arg", position="last"),
        ],
        additional_args_sanitize="arg",
    ),

    "hashcat": ToolSpec(
        binary="hashcat",
        params=[
            ToolParam(name="attack_mode", flag="-a", sanitize="arg", default="0"),
            ToolParam(name="hash_type", flag="-m", sanitize="arg", condition_key="hash_type"),
            ToolParam(name="hash_file", flag="", sanitize="arg"),
            ToolParam(name="wordlist", flag="", sanitize="arg",
                      default="/usr/share/wordlists/rockyou.txt", position="last"),
        ],
        additional_args_sanitize="arg",
    ),

    "medusa": ToolSpec(
        binary="medusa",
        params=[
            ToolParam(name="target", flag="-h", sanitize="arg"),
            ToolParam(name="service", flag="-M", sanitize="arg", default="ssh"),
            ToolParam(name="password_list", flag="-P", sanitize="arg",
                      default="/usr/share/wordlists/rockyou.txt"),
            ToolParam(name="username", flag="-u", sanitize="arg", condition_key="username"),
        ],
        additional_args_sanitize="arg",
    ),

    "patator": ToolSpec(
        binary="patator",
        params=[
            ToolParam(name="module", flag="", sanitize="arg", default="ssh_login"),
            # host= is a bare key=value pattern used by patator
            ToolParam(name="target", flag="host", sanitize="arg", join="="),
        ],
        additional_args_sanitize="arg",
    ),

    "crowbar": ToolSpec(
        binary="crowbar",
        params=[
            ToolParam(name="service", flag="-b", sanitize="arg", default="ssh"),
            ToolParam(name="target", flag="-s", sanitize="arg"),
            ToolParam(name="username", flag="-u", sanitize="arg", condition_key="username"),
            ToolParam(name="wordlist", flag="-C", sanitize="arg", condition_key="wordlist"),
        ],
        additional_args_sanitize="arg",
    ),

    "brutespray": ToolSpec(
        binary="brutespray",
        params=[
            ToolParam(name="nmap_file", flag="-f", sanitize="arg"),
            ToolParam(name="threads", flag="-t", sanitize="arg", default="5"),
            ToolParam(name="username_file", flag="-U", sanitize="arg",
                      condition_key="username_file"),
            ToolParam(name="password_file", flag="-P", sanitize="arg",
                      condition_key="password_file"),
        ],
        additional_args_sanitize="arg",
    ),

    # ==================== Wireless ====================

    "reaver": ToolSpec(
        binary="reaver",
        params=[
            ToolParam(name="interface", flag="-i", sanitize="arg"),
            ToolParam(name="bssid", flag="-b", sanitize="arg"),
        ],
        # additional_args default is "-vv"
        additional_args_sanitize="arg",
    ),

    "bully": ToolSpec(
        binary="bully",
        params=[
            ToolParam(name="interface", flag="", sanitize="arg", position="first"),
            ToolParam(name="bssid", flag="-b", sanitize="arg"),
        ],
        # additional_args default is "-v"
        additional_args_sanitize="arg",
    ),

    "pixiewps": ToolSpec(
        binary="pixiewps",
        params=[
            ToolParam(name="pke", flag="-e", sanitize="arg"),
            ToolParam(name="pkr", flag="-r", sanitize="arg"),
            ToolParam(name="e_hash1", flag="-s", sanitize="arg"),
            ToolParam(name="e_hash2", flag="-z", sanitize="arg"),
        ],
        additional_args_sanitize="arg",
    ),

    "wifiphisher": ToolSpec(
        binary="wifiphisher",
        params=[
            ToolParam(name="interface", flag="-i", sanitize="arg"),
            ToolParam(name="phishing_scenario", flag="-p", sanitize="arg",
                      default="firmware-upgrade"),
            ToolParam(name="essid", flag="-e", sanitize="arg", condition_key="essid"),
        ],
        additional_args_sanitize="arg",
    ),

    # ==================== Bluetooth ====================

    "bluesnarfer": ToolSpec(
        binary="bluesnarfer",
        params=[
            ToolParam(name="target_mac", flag="-b", sanitize="arg"),
            ToolParam(name="channel", flag="-C", sanitize="arg", default="1"),
        ],
        additional_args_sanitize="arg",
    ),

    "btscanner": ToolSpec(
        binary="btscanner",
        params=[
            ToolParam(name="output_file", flag="-o", sanitize="arg",
                      default="/tmp/btscanner.xml"),
        ],
        additional_args_sanitize="arg",
    ),

    # ==================== Sniffing / MITM ====================

    "bettercap": ToolSpec(
        binary="bettercap",
        params=[
            ToolParam(name="interface", flag="-iface", sanitize="arg"),
            ToolParam(name="caplet", flag="-caplet", sanitize="arg", condition_key="caplet"),
        ],
        additional_args_sanitize="arg",
    ),

    "dsniff": ToolSpec(
        binary="dsniff",
        params=[
            ToolParam(name="interface", flag="-i", sanitize="arg", condition_key="interface"),
            ToolParam(name="filter_expr", flag="", sanitize="arg", condition_key="filter_expr"),
            ToolParam(name="output_file", flag="-w", sanitize="arg", condition_key="output_file"),
        ],
        additional_args_sanitize="arg",
    ),

    "ngrep": ToolSpec(
        binary="ngrep",
        params=[
            ToolParam(name="interface", flag="-d", sanitize="arg", condition_key="interface"),
            ToolParam(name="pattern", flag="", sanitize="arg", condition_key="pattern"),
            ToolParam(name="filter_expr", flag="", sanitize="arg", condition_key="filter_expr"),
        ],
        additional_args_sanitize="arg",
    ),

    "tshark": ToolSpec(
        binary="tshark",
        params=[
            ToolParam(name="packet_count", flag="-c", sanitize="arg", default="100"),
            ToolParam(name="interface", flag="-i", sanitize="arg", condition_key="interface"),
            ToolParam(name="capture_filter", flag="-f", sanitize="arg",
                      condition_key="capture_filter"),
            ToolParam(name="display_filter", flag="-Y", sanitize="arg",
                      condition_key="display_filter"),
            ToolParam(name="output_file", flag="-w", sanitize="arg", condition_key="output_file"),
        ],
        additional_args_sanitize="arg",
    ),

    # ==================== Vulnerability Scanning ====================

    "searchsploit": ToolSpec(
        binary="searchsploit",
        params=[
            ToolParam(name="term", flag="", sanitize="arg"),
        ],
        additional_args_sanitize="fragment",
    ),

    "enum4linux": ToolSpec(
        binary="enum4linux",
        params=[
            # additional_args (default "-a") is placed BEFORE target.
            # We handle this by putting target at position="last" and using
            # the default for additional_args.
            ToolParam(name="target", flag="", sanitize="arg", position="last"),
        ],
        additional_args_sanitize="fragment",
    ),

    "dirsearch": ToolSpec(
        binary="dirsearch",
        params=[
            ToolParam(name="target", flag="-u", sanitize="arg"),
            ToolParam(name="extensions", flag="-e", sanitize="arg"),
        ],
        timeout=300,
        additional_args_sanitize="fragment",
    ),
    "evil-winrm": ToolSpec(
        binary="evil-winrm",
        params=[
            ToolParam(name="target", flag="-i", sanitize="arg"),
            ToolParam(name="user", flag="-u", sanitize="arg"),
            ToolParam(name="password", flag="-p", sanitize="arg"),
        ],
        timeout=300,
        additional_args_sanitize="fragment",
    ),
    "smbclient": ToolSpec(
        binary="smbclient",
        params=[
            # target 形如 //host/share；-U 的值形如 user%pass 由调用方拼好
            ToolParam(name="target", flag="", sanitize="arg"),
            ToolParam(name="user", flag="-U", sanitize="arg"),
            ToolParam(name="command", flag="-c", sanitize="arg"),
        ],
        timeout=180,
        additional_args_sanitize="fragment",
    ),
    "rpcclient": ToolSpec(
        binary="rpcclient",
        params=[
            ToolParam(name="target", flag="", sanitize="arg"),
            ToolParam(name="user", flag="-U", sanitize="arg"),
            ToolParam(name="command", flag="-c", sanitize="arg"),
        ],
        timeout=180,
        additional_args_sanitize="fragment",
    ),
    "snmpcheck": ToolSpec(
        binary="snmpcheck",
        params=[
            ToolParam(name="target", flag="-t", sanitize="arg"),
        ],
        timeout=300,
        additional_args_sanitize="fragment",
    ),
    "onesixtyone": ToolSpec(
        binary="onesixtyone",
        params=[
            ToolParam(name="community", flag="", sanitize="arg", position="first", default="public"),
            ToolParam(name="target", flag="", sanitize="arg", position="last"),
        ],
        timeout=120,
        additional_args_sanitize="fragment",
    ),
    "socat": ToolSpec(
        binary="socat",
        additional_args_sanitize="fragment",
    ),
    "wifite": ToolSpec(
        binary="wifite",
        params=[
            ToolParam(name="interface", flag="-i", sanitize="arg"),
        ],
        timeout=600,
        additional_args_sanitize="fragment",
    ),

    # ==================== Protocol Attack ====================

    "yersinia": ToolSpec(
        binary="yersinia",
        params=[
            ToolParam(name="protocol", flag="", sanitize="arg", default="stp", position="first"),
            ToolParam(name="interface", flag="-i", sanitize="arg", condition_key="interface"),
            ToolParam(name="attack_type", flag="-attack", sanitize="arg",
                      condition_key="attack_type"),
        ],
        additional_args_sanitize="arg",
    ),

    # ==================== Forensics ====================

    "foremost": ToolSpec(
        binary="foremost",
        params=[
            ToolParam(name="file_path", flag="-i", sanitize="arg",
                      alt_keys=("target",)),
            ToolParam(name="output_dir", flag="-o", sanitize="arg",
                      default="/tmp/foremost_output"),
        ],
        additional_args_sanitize="fragment",
    ),

    "volatility": ToolSpec(
        # volatility3 的命令行入口为 vol（旧版 v2 机器可自行 symlink）
        binary="vol",
        params=[
            ToolParam(name="dump_path", flag="-f", sanitize="arg",
                      alt_keys=("target",)),
            ToolParam(name="profile", flag="--profile", sanitize="arg",
                      condition_key="profile", join="="),
            ToolParam(name="plugin", flag="", sanitize="arg", default="imageinfo"),
        ],
        additional_args_sanitize="fragment",
    ),

    "zsteg": ToolSpec(
        binary="zsteg",
        params=[
            # additional_args (default "-a") goes first, file_path last
            ToolParam(name="file_path", flag="", sanitize="arg", position="last",
                      alt_keys=("target",)),
        ],
        additional_args_sanitize="fragment",
    ),

    "exiftool": ToolSpec(
        binary="exiftool",
        params=[
            ToolParam(name="file_path", flag="", sanitize="arg", alt_keys=("target",)),
        ],
        additional_args_sanitize="fragment",
    ),

    "strings": ToolSpec(
        binary="strings",
        params=[
            ToolParam(name="file_path", flag="", sanitize="arg", alt_keys=("target",)),
        ],
        additional_args_sanitize="fragment",
    ),

    # ==================== Code Audit ====================

    # semgrep is in CUSTOM_BUILDERS due to --json placement between positional and optional params

    "flawfinder": ToolSpec(
        binary="flawfinder",
        params=[
            ToolParam(name="min_level", flag="--minlevel", sanitize="arg", default="1", join="="),
            ToolParam(name="target_path", flag="", sanitize="arg", default="."),
        ],
        base_args="--columns --context",
        base_args_position="before",
        additional_args_sanitize="arg",
    ),

    # shellcheck is in CUSTOM_BUILDERS due to -f json -S ordering

    # ==================== Basic Network Utilities ====================

    # wget is in CUSTOM_BUILDERS due to -q -O {output} --timeout=30 ordering

    "host": ToolSpec(
        binary="host",
        params=[
            ToolParam(name="target", flag="", sanitize="arg", alt_keys=("domain",)),
        ],
        additional_args_sanitize="fragment",
    ),

    "whois": ToolSpec(
        binary="whois",
        params=[
            ToolParam(name="target", flag="", sanitize="arg", alt_keys=("domain",)),
        ],
        additional_args_sanitize="fragment",
    ),

    "traceroute": ToolSpec(
        binary="traceroute",
        params=[
            ToolParam(name="target", flag="", sanitize="arg"),
        ],
        base_args="-m 20",
        base_args_position="before",
        additional_args_sanitize="fragment",
    ),

    # ==================== Text Processing ====================

    "awk": ToolSpec(
        binary="awk",
        params=[
            ToolParam(name="program", flag="", sanitize="arg",
                      alt_keys=("command",), default="{print}"),
            ToolParam(name="file_path", flag="", sanitize="arg",
                      condition_key="file_path", alt_keys=("target",)),
        ],
        additional_args_sanitize="fragment",
    ),

    "sed": ToolSpec(
        binary="sed",
        params=[
            ToolParam(name="expression", flag="", sanitize="arg",
                      alt_keys=("command",)),
            ToolParam(name="file_path", flag="", sanitize="arg",
                      condition_key="file_path", alt_keys=("target",)),
        ],
        additional_args_sanitize="fragment",
    ),

    "jq": ToolSpec(
        binary="jq",
        params=[
            ToolParam(name="filter", flag="", sanitize="arg",
                      alt_keys=("command",), default="."),
            ToolParam(name="file_path", flag="", sanitize="arg",
                      condition_key="file_path", alt_keys=("target",)),
        ],
        additional_args_sanitize="fragment",
    ),

    # ==================== Kali Extended Tools ====================

    # --- Web Security ---

    "commix": ToolSpec(
        binary="commix",
        params=[
            ToolParam(name="target", flag="-u", sanitize="arg"),
        ],
        base_args="--batch --random-agent",
        timeout=300,
        additional_args_sanitize="fragment",
    ),

    "nosqlmap": ToolSpec(
        binary="nosqlmap",
        params=[
            ToolParam(name="target", flag="--victim", sanitize="arg"),
        ],
        additional_args_sanitize="fragment",
    ),

    "xsstrike": ToolSpec(
        binary="xsstrike",
        params=[
            ToolParam(name="target", flag="-u", sanitize="arg"),
        ],
        additional_args_sanitize="fragment",
    ),

    "dalfox": ToolSpec(
        binary="dalfox",
        params=[
            ToolParam(name="target", flag="url", sanitize="arg", position="last"),
            ToolParam(name="mode", flag="", sanitize="arg", condition_key="mode", position="first"),
        ],
        additional_args_sanitize="fragment",
    ),

    "arjun": ToolSpec(
        binary="arjun",
        params=[
            ToolParam(name="target", flag="-u", sanitize="arg"),
            ToolParam(name="method", flag="-m", sanitize="arg", condition_key="method"),
        ],
        additional_args_sanitize="fragment",
    ),

    # --- Network Extended ---

    "tshark": ToolSpec(
        binary="tshark",
        params=[
            ToolParam(name="interface", flag="-i", sanitize="arg", condition_key="interface"),
            ToolParam(name="capture_filter", flag="-f", sanitize="arg", condition_key="capture_filter"),
            ToolParam(name="display_filter", flag="-Y", sanitize="arg", condition_key="display_filter"),
            ToolParam(name="count", flag="-c", sanitize="arg", condition_key="count"),
        ],
        additional_args_sanitize="fragment",
    ),

    "dsniff": ToolSpec(
        binary="dsniff",
        params=[
            ToolParam(name="interface", flag="-i", sanitize="arg", condition_key="interface"),
        ],
        additional_args_sanitize="fragment",
    ),

    "ngrep": ToolSpec(
        binary="ngrep",
        params=[
            ToolParam(name="pattern", flag="", sanitize="arg", position="first"),
            ToolParam(name="interface", flag="-i", sanitize="arg", condition_key="interface"),
        ],
        additional_args_sanitize="fragment",
    ),

    # --- Recon Extended ---

    "findomain": ToolSpec(
        binary="findomain",
        params=[
            ToolParam(name="domain", flag="-t", sanitize="arg"),
        ],
        additional_args_sanitize="fragment",
    ),

    "assetfinder": ToolSpec(
        binary="assetfinder",
        params=[
            ToolParam(name="domain", flag="", sanitize="arg"),
        ],
        additional_args_sanitize="fragment",
    ),

    # --- Wireless Extended ---

    "wifiphisher": ToolSpec(
        binary="wifiphisher",
        params=[
            ToolParam(name="interface", flag="-i", sanitize="arg", condition_key="interface"),
            ToolParam(name="essid", flag="-e", sanitize="arg", condition_key="essid"),
        ],
        additional_args_sanitize="fragment",
    ),

    "btscanner": ToolSpec(
        binary="btscanner",
        params=[
            ToolParam(name="interface", flag="-i", sanitize="arg", condition_key="interface"),
        ],
        additional_args_sanitize="fragment",
    ),

    # --- Tunneling ---

    "chisel": ToolSpec(
        binary="chisel",
        params=[
            ToolParam(name="mode", flag="", sanitize="arg", position="first"),
            ToolParam(name="target", flag="", sanitize="arg", condition_key="target"),
        ],
        additional_args_sanitize="fragment",
    ),

    "proxychains": ToolSpec(
        binary="proxychains",
        params=[
            ToolParam(name="command", flag="", sanitize="fragment"),
        ],
        additional_args_sanitize="fragment",
    ),

    # --- AD / Windows ---

    "crackmapexec": ToolSpec(
        # crackmapexec 已由继任者 netexec(nxc) 取代，参数兼容
        binary="netexec",
        params=[
            ToolParam(name="service", flag="", sanitize="arg", position="first"),
            ToolParam(name="target", flag="", sanitize="arg"),
        ],
        additional_args_sanitize="fragment",
        aliases=("netexec", "nxc"),
    ),

    "bloodhound-python": ToolSpec(
        binary="bloodhound-python",
        params=[
            ToolParam(name="domain", flag="-d", sanitize="arg"),
            ToolParam(name="username", flag="-u", sanitize="arg", condition_key="username"),
            ToolParam(name="password", flag="-p", sanitize="arg", condition_key="password"),
            ToolParam(name="collection_method", flag="-c", sanitize="arg", default="All"),
        ],
        additional_args_sanitize="fragment",
        aliases=("bloodhound",),
    ),

    "impacket-secretsdump": ToolSpec(
        binary="impacket-secretsdump",
        params=[
            ToolParam(name="target", flag="", sanitize="arg"),
        ],
        additional_args_sanitize="fragment",
    ),

    "impacket-psexec": ToolSpec(
        binary="impacket-psexec",
        params=[
            ToolParam(name="target", flag="", sanitize="arg"),
        ],
        additional_args_sanitize="fragment",
    ),

    "impacket-smbexec": ToolSpec(
        binary="impacket-smbexec",
        params=[
            ToolParam(name="target", flag="", sanitize="arg"),
        ],
        additional_args_sanitize="fragment",
    ),

    "impacket-wmiexec": ToolSpec(
        binary="impacket-wmiexec",
        params=[
            ToolParam(name="target", flag="", sanitize="arg"),
        ],
        additional_args_sanitize="fragment",
    ),

    "impacket-getnpusers": ToolSpec(
        binary="impacket-GetNPUsers",
        params=[
            ToolParam(name="domain", flag="", sanitize="arg"),
        ],
        additional_args_sanitize="fragment",
    ),

    "impacket-getTGT": ToolSpec(
        binary="impacket-getTGT",
        params=[
            ToolParam(name="domain", flag="", sanitize="arg"),
        ],
        additional_args_sanitize="fragment",
    ),

    "impacket-ntlmrelayx": ToolSpec(
        binary="impacket-ntlmrelayx",
        params=[
            ToolParam(name="target", flag="-t", sanitize="arg", condition_key="target"),
        ],
        additional_args_sanitize="fragment",
    ),
}


# ---------------------------------------------------------------------------
# Custom builder functions — tools that do not fit the declarative model
# ---------------------------------------------------------------------------

def _build_sqlmap(data: Dict[str, Any]) -> str:
    """sqlmap: ``--batch`` positioned between ``-u`` and ``--data=``."""
    url = sanitize_shell_arg(data.get("url", ""))
    data_param = sanitize_shell_arg(data.get("data", ""))
    additional_args = data.get("additional_args", "")
    cmd = f"sqlmap -u {url} --batch"
    if data.get("data", ""):
        cmd += f" --data={data_param}"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    return cmd


def _build_hydra(data: Dict[str, Any]) -> str:
    """hydra: mutually-exclusive ``-L``/``-l`` and ``-P``/``-p`` pairs."""
    target = sanitize_shell_arg(data.get("target", ""))
    service = sanitize_shell_arg(data.get("service", ""))
    username = data.get("username", "")
    username_file = data.get("username_file", "")
    password = data.get("password", "")
    password_file = data.get("password_file", "")
    additional_args = data.get("additional_args", "")
    cmd = "hydra"
    if username_file:
        cmd += f" -L {sanitize_shell_arg(username_file)}"
    elif username:
        cmd += f" -l {sanitize_shell_arg(username)}"
    if password_file:
        cmd += f" -P {sanitize_shell_arg(password_file)}"
    elif password:
        cmd += f" -p {sanitize_shell_arg(password)}"
    cmd += f" {target} {service}"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    return cmd


def _build_ncrack(data: Dict[str, Any]) -> str:
    """ncrack: combines ``service://target``."""
    target = sanitize_shell_arg(data.get("target", ""))
    service = sanitize_shell_arg(data.get("service", "ssh"))
    username_file = sanitize_shell_arg(data.get("username_file", ""))
    password_file = sanitize_shell_arg(data.get("password_file", ""))
    additional_args = data.get("additional_args", "")
    cmd = f"ncrack {target}"
    if data.get("service", ""):
        cmd = f"ncrack {service}://{target}"
    if data.get("username_file", ""):
        cmd += f" -U {username_file}"
    if data.get("password_file", ""):
        cmd += f" -P {password_file}"
    if additional_args:
        cmd += f" {sanitize_shell_arg(additional_args)}"
    return cmd


def _build_netdiscover(data: Dict[str, Any]) -> str:
    """netdiscover: boolean ``-p`` passive flag."""
    interface = sanitize_shell_arg(data.get("interface", ""))
    range_ip = sanitize_shell_arg(data.get("range_ip", ""))
    passive = data.get("passive", False)
    additional_args = data.get("additional_args", "")
    cmd = "netdiscover -P -N"
    if passive:
        cmd += " -p"
    if data.get("interface", ""):
        cmd += f" -i {interface}"
    if data.get("range_ip", ""):
        cmd += f" -r {range_ip}"
    if additional_args:
        cmd += f" {sanitize_shell_arg(additional_args)}"
    return cmd


def _build_arp_scan(data: Dict[str, Any]) -> str:
    """arp-scan: ``-I interface`` optional, ``--local`` fallback."""
    interface = sanitize_shell_arg(data.get("interface", ""))
    network = sanitize_shell_arg(data.get("network", "--local"))
    additional_args = data.get("additional_args", "")
    cmd = f"arp-scan {network}"
    if data.get("interface", ""):
        cmd = f"arp-scan -I {interface} {network}"
    if additional_args:
        cmd += f" {sanitize_shell_arg(additional_args)}"
    return cmd


def _build_arpscan(data: Dict[str, Any]) -> str:
    """arpscan (v5.2 alias): different structure with ``--localnet`` fallback."""
    network = data.get("network", data.get("target", ""))
    interface = data.get("interface", "")
    additional_args = data.get("additional_args", "")
    cmd = "arp-scan"
    if interface:
        cmd += f" -I {sanitize_shell_arg(interface)}"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    if network:
        cmd += f" {sanitize_shell_arg(network)}"
    else:
        cmd += " --localnet"
    return cmd


def _build_responder(data: Dict[str, Any]) -> str:
    """responder: boolean ``-A`` analyze_mode flag."""
    interface = sanitize_shell_arg(data.get("interface", ""))
    analyze_mode = data.get("analyze_mode", False)
    additional_args = data.get("additional_args", "")
    cmd = f"responder -I {interface}"
    if analyze_mode:
        cmd += " -A"
    if additional_args:
        cmd += f" {sanitize_shell_arg(additional_args)}"
    return cmd


def _build_ettercap(data: Dict[str, Any]) -> str:
    """ettercap: compound ``/target1// /target2//`` formatting."""
    interface = sanitize_shell_arg(data.get("interface", ""))
    target1 = sanitize_shell_arg(data.get("target1", ""))
    target2 = sanitize_shell_arg(data.get("target2", ""))
    filter_file = sanitize_shell_arg(data.get("filter_file", ""))
    additional_args = data.get("additional_args", "-T")
    cmd = f"ettercap {sanitize_shell_arg(additional_args)} -i {interface}"
    if data.get("target1", "") or data.get("target2", ""):
        cmd += f" -M arp:remote /{target1}// /{target2}//"
    if data.get("filter_file", ""):
        cmd += f" -F {filter_file}"
    return cmd


def _build_binwalk(data: Dict[str, Any]) -> str:
    """binwalk: boolean ``-e`` extract flag."""
    file_path = sanitize_shell_arg(data.get("file_path", ""))
    extract = data.get("extract", False)
    additional_args = data.get("additional_args", "")
    cmd = "binwalk"
    if extract:
        cmd += " -e"
    cmd += f" {file_path}"
    if additional_args:
        cmd += f" {sanitize_shell_arg(additional_args)}"
    return cmd


def _build_radare2(data: Dict[str, Any]) -> str:
    """radare2: ``-q -e scr.color=0 -c commands binary_path``."""
    binary_path = sanitize_shell_arg(data.get("binary_path", ""))
    additional_args = data.get("additional_args", "")
    analysis_cmds = data.get("commands", "aaa;afl;ii;iz")
    cmd = f"r2 -q -e scr.color=0 -c {sanitize_shell_arg(analysis_cmds)} {binary_path}"
    if additional_args:
        cmd += f" {sanitize_shell_arg(additional_args)}"
    return cmd


def _build_r2(data: Dict[str, Any]) -> str:
    """r2: same as radare2 (original elif catches both at line 910)."""
    return _build_radare2(data)


def _build_sherlock(data: Dict[str, Any]) -> str:
    """sherlock: boolean ``--json`` and optional ``--site``."""
    username = sanitize_shell_arg(data.get("username", ""))
    sites = sanitize_shell_arg(data.get("sites", ""))
    output_format = data.get("output_format", "json")
    additional_args = data.get("additional_args", "")
    cmd = f"sherlock {username}"
    if data.get("sites", ""):
        cmd += f" --site {sites}"
    if output_format == "json":
        cmd += " --json"
    if additional_args:
        cmd += f" {sanitize_shell_arg(additional_args)}"
    return cmd


def _build_nuclei(data: Dict[str, Any]) -> str:
    """nuclei: dynamic rate-limit / timeout from ``EXEC_CONFIG``."""
    target = sanitize_shell_arg(data.get("target", ""))
    templates = sanitize_shell_arg(data.get("templates", ""))
    severity = sanitize_shell_arg(data.get("severity", "critical,high,medium"))
    tags = sanitize_shell_arg(data.get("tags", ""))
    output_format = data.get("output_format", "json")
    additional_args = data.get("additional_args", "")
    rl = EXEC_CONFIG["nuclei_rate_limit"]
    nt = EXEC_CONFIG["nuclei_timeout"]
    cmd = f"nuclei -u {target} -s {severity} -silent -rl {rl} -timeout {nt}"
    if data.get("templates", ""):
        cmd += f" -t {templates}"
    if data.get("tags", ""):
        cmd += f" -tags {tags}"
    if output_format == "json":
        cmd += " -jsonl"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    return cmd


def _build_recon_ng(data: Dict[str, Any]) -> str:
    """recon-ng: complex module / workspace / commands branching."""
    workspace = sanitize_shell_arg(data.get("workspace", "default"))
    module = sanitize_shell_arg(data.get("module", ""))
    additional_args = data.get("additional_args", "")
    if data.get("module", ""):
        cmd = (f"recon-ng -w {workspace} -m {module} "
               f"-x {sanitize_shell_arg('run; exit')}")
    else:
        cmd = (f"recon-ng -w {workspace} "
               f"-x {sanitize_shell_arg('show modules; exit')}")
    if additional_args:
        cmd += f" {sanitize_shell_arg(additional_args)}"
    return cmd


def _build_slowhttptest(data: Dict[str, Any]) -> str:
    """slowhttptest: type_flag computed from ``attack_type``."""
    target = sanitize_shell_arg(data.get("target", ""))
    attack_type = data.get("attack_type", "slowloris")
    connections = sanitize_shell_arg(data.get("connections", "200"))
    timeout = sanitize_shell_arg(data.get("timeout", "240"))
    additional_args = data.get("additional_args", "")
    type_flag = "-H" if attack_type == "slowloris" else "-B"
    cmd = f"slowhttptest {type_flag} -c {connections} -l {timeout} -u {target}"
    if additional_args:
        cmd += f" {sanitize_shell_arg(additional_args)}"
    return cmd


def _build_aircrack_ng(data: Dict[str, Any]) -> str:
    """aircrack-ng: bssid optional, capture_file before additional_args."""
    capture_file = sanitize_shell_arg(data.get("capture_file", ""))
    wordlist = sanitize_shell_arg(
        data.get("wordlist", "/usr/share/wordlists/rockyou.txt"))
    bssid = sanitize_shell_arg(data.get("bssid", ""))
    additional_args = data.get("additional_args", "")
    cmd = f"aircrack-ng -w {wordlist}"
    if data.get("bssid", ""):
        cmd += f" -b {bssid}"
    cmd += f" {capture_file}"
    if additional_args:
        cmd += f" {sanitize_shell_arg(additional_args)}"
    return cmd


def _build_aircrack(data: Dict[str, Any]) -> str:
    """aircrack (v5.2 alias): additional_args before capture_file."""
    capture_file = sanitize_shell_arg(
        data.get("capture_file", data.get("target", "")))
    wordlist = sanitize_shell_arg(
        data.get("wordlist", "/usr/share/wordlists/rockyou.txt"))
    bssid = data.get("bssid", "")
    additional_args = data.get("additional_args", "")
    cmd = f"aircrack-ng -w {wordlist}"
    if bssid:
        cmd += f" -b {sanitize_shell_arg(bssid)}"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    cmd += f" {capture_file}"
    return cmd


def _build_httpx(data: Dict[str, Any]) -> str:
    """httpx: pipe-based ``echo targets | httpx``."""
    targets = sanitize_shell_arg(data.get("targets", ""))
    additional_args = data.get("additional_args", "").replace("-tech-detect", "-td")
    cmd = f"echo {targets} | httpx -silent"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    return cmd


def _build_metasploit(data: Dict[str, Any]) -> str:
    """metasploit: dict-based ``use/set/run`` script building."""
    module = sanitize_shell_arg(
        data.get("module", "auxiliary/scanner/http/http_version"))
    options = data.get("options", {})
    script_parts = [f"use {module}"]
    if isinstance(options, dict):
        for key, value in options.items():
            option_key = sanitize_shell_arg(str(key))
            option_value = sanitize_shell_arg(str(value))
            if option_key and option_value:
                script_parts.append(f"set {option_key} {option_value}")
    script_parts.extend(["run", "exit -y"])
    script = "; ".join(script_parts)
    return f"msfconsole -q -x {sanitize_shell_arg(script)}"


def _build_msfconsole(data: Dict[str, Any]) -> str:
    """msfconsole (v5.2): resource file or module pipe pattern."""
    module = data.get("module", "")
    resource_file = data.get("resource_file", "")
    if resource_file:
        return f"msfconsole -r {sanitize_shell_arg(resource_file)} -q"
    elif module:
        target = data.get("target", data.get("RHOSTS", ""))
        opts = []
        if target:
            opts.append(f"set RHOSTS {target}")
        for k, v in data.items():
            if k.isupper() and k not in ("RHOSTS",):
                opts.append(f"set {k} {v}")
        opts.append("run")
        opts.append("exit")
        rc_cmds = ";".join(
            f"echo '{o}'" for o in [f"use {module}"] + opts)
        return f"({rc_cmds}) | msfconsole -q"
    return "msfconsole -q -x 'exit'"


def _build_msfvenom(data: Dict[str, Any]) -> str:
    """msfvenom: ``LHOST=/LPORT=`` format, alt_keys for format/output."""
    payload = data.get("payload", "linux/x64/shell_reverse_tcp")
    lhost = data.get("lhost", data.get("LHOST", ""))
    lport = data.get("lport", data.get("LPORT", "4444"))
    fmt = data.get("format", data.get("f", "elf"))
    output = data.get("output", data.get("o", ""))
    additional_args = data.get("additional_args", "")
    cmd = f"msfvenom -p {sanitize_shell_arg(payload)}"
    if lhost:
        cmd += f" LHOST={sanitize_shell_arg(lhost)}"
    cmd += f" LPORT={sanitize_shell_arg(str(lport))}"
    cmd += f" -f {sanitize_shell_arg(fmt)}"
    if output:
        cmd += f" -o {sanitize_shell_arg(output)}"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    return cmd


def _build_curl(data: Dict[str, Any]) -> str:
    """curl: dict-based headers iteration, url last."""
    url = sanitize_shell_arg(data.get("url", data.get("target", "")))
    method = sanitize_shell_arg(data.get("method", "GET"))
    headers = data.get("headers", {})
    post_data = data.get("data", "")
    additional_args = data.get("additional_args", "")
    cmd = f"curl -s -S -L -m 30 -X {method}"
    if isinstance(headers, dict):
        for k, v in headers.items():
            cmd += f" -H {sanitize_shell_arg(f'{k}: {v}')}"
    if post_data:
        cmd += f" -d {sanitize_shell_arg(post_data)}"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    cmd += f" {url}"
    return cmd


def _build_ssh(data: Dict[str, Any]) -> str:
    """ssh: ``user@target`` combination, key_file optional."""
    target = sanitize_shell_arg(data.get("target", ""))
    user = data.get("username", data.get("user", ""))
    port = data.get("port", "22")
    command = data.get("command", "")
    key_file = data.get("key_file", "")
    cmd = "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10"
    if key_file:
        cmd += f" -i {sanitize_shell_arg(key_file)}"
    cmd += f" -p {sanitize_shell_arg(str(port))}"
    if user:
        cmd += f" {sanitize_shell_arg(user)}@{target}"
    else:
        cmd += f" {target}"
    if command:
        cmd += f" {sanitize_shell_arg(command)}"
    return cmd


def _build_scp(data: Dict[str, Any]) -> str:
    """scp: ``-P port``, key_file optional, source + dest positional."""
    source = sanitize_shell_arg(data.get("source", ""))
    dest = sanitize_shell_arg(data.get("dest", data.get("target", "")))
    port = data.get("port", "22")
    key_file = data.get("key_file", "")
    cmd = f"scp -o StrictHostKeyChecking=no -P {sanitize_shell_arg(str(port))}"
    if key_file:
        cmd += f" -i {sanitize_shell_arg(key_file)}"
    cmd += f" {source} {dest}"
    return cmd


def _build_openssl(data: Dict[str, Any]) -> str:
    """openssl: pipe-based ``echo | openssl s_client -connect host:port``."""
    subcmd = sanitize_shell_fragment(data.get("subcmd", "s_client"))
    target = sanitize_shell_arg(data.get("target", ""))
    port = sanitize_shell_arg(data.get("port", "443"))
    additional_args = data.get("additional_args", "")
    cmd = f"echo | openssl {subcmd} -connect {target}:{port} 2>/dev/null"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    return cmd


def _build_base64(data: Dict[str, Any]) -> str:
    """base64: pipe-based encode/decode branching."""
    action = data.get("action", "decode")
    input_data = data.get("input", data.get("data", ""))
    if action == "encode":
        return f"echo -n {sanitize_shell_arg(input_data)} | base64"
    else:
        return f"echo -n {sanitize_shell_arg(input_data)} | base64 -d"


def _build_steghide(data: Dict[str, Any]) -> str:
    """steghide: action-dependent ``info`` vs ``extract`` branching."""
    action = data.get("action", "info")
    file_path = sanitize_shell_arg(
        data.get("file_path", data.get("target", "")))
    password = data.get("password", "")
    if action == "extract":
        cmd = f"steghide extract -sf {file_path} -f"
    else:
        cmd = f"steghide info {file_path} -f"
    if password:
        cmd += f" -p {sanitize_shell_arg(password)}"
    else:
        cmd += " -p ''"
    return cmd


def _build_python3(data: Dict[str, Any]) -> str:
    """python3: three-way branch — script_file, inline script, or --version."""
    script = data.get("script", data.get("command", ""))
    script_file = data.get("script_file", "")
    if script_file:
        return f"python3 {sanitize_shell_arg(script_file)}"
    elif script:
        return f"python3 -c {sanitize_shell_arg(script)}"
    return "python3 --version"


def _build_xxd(data: Dict[str, Any]) -> str:
    """xxd: action-dependent hex dump vs reverse."""
    file_path = data.get("file_path", data.get("target", ""))
    action = data.get("action", "hex")
    if action == "reverse":
        return f"xxd -r {sanitize_shell_arg(file_path)}"
    else:
        return f"xxd {sanitize_shell_arg(file_path)}"


def _build_dig(data: Dict[str, Any]) -> str:
    """dig: ``@server`` prefix syntax for DNS server."""
    domain = sanitize_shell_arg(data.get("domain", data.get("target", "")))
    record_type = sanitize_shell_arg(data.get("record_type", "ANY"))
    server = data.get("server", "")
    additional_args = data.get("additional_args", "")
    cmd = f"dig {domain} {record_type}"
    if server:
        cmd += f" @{sanitize_shell_arg(server)}"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    return cmd


def _build_wget(data: Dict[str, Any]) -> str:
    """wget: ``-q -O {output} --timeout=30 [{additional_args}] {url}``."""
    url = sanitize_shell_arg(data.get("url", data.get("target", "")))
    output = sanitize_shell_arg(data.get("output", "-"))
    additional_args = data.get("additional_args", "")
    cmd = f"wget -q -O {output} --timeout=30"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    cmd += f" {url}"
    return cmd


def _build_grep(data: Dict[str, Any]) -> str:
    """grep: additional_args (default '-rn') placed BEFORE pattern."""
    pattern = sanitize_shell_arg(data.get("pattern", ""))
    file_path = data.get("file_path", data.get("target", ""))
    additional_args = data.get("additional_args", "-rn")
    cmd = f"grep {sanitize_shell_fragment(additional_args)} {pattern}"
    if file_path:
        cmd += f" {sanitize_shell_arg(file_path)}"
    return cmd


def _build_semgrep(data: Dict[str, Any]) -> str:
    """semgrep: ``--json`` positioned between target_path and --lang."""
    target_path = sanitize_shell_arg(data.get("target_path", "."))
    config = sanitize_shell_arg(data.get("config", "auto"))
    language = data.get("language", "")
    additional_args = data.get("additional_args", "")
    cmd = f"semgrep --config {config} {target_path} --json"
    if language:
        cmd += f" --lang {sanitize_shell_arg(language)}"
    if additional_args:
        cmd += f" {sanitize_shell_arg(additional_args)}"
    return cmd


def _build_shellcheck(data: Dict[str, Any]) -> str:
    """shellcheck: ``{target_path} -f json -S {severity}``."""
    target_path = sanitize_shell_arg(data.get("target_path", ""))
    severity = sanitize_shell_arg(data.get("severity", "warning"))
    additional_args = data.get("additional_args", "")
    cmd = f"shellcheck {target_path} -f json -S {severity}"
    if additional_args:
        cmd += f" {sanitize_shell_arg(additional_args)}"
    return cmd


def _build_bandit(data: Dict[str, Any]) -> str:
    """bandit: complex severity / confidence level-to-flag-repetition logic."""
    target_path = sanitize_shell_arg(data.get("target_path", "."))
    severity = data.get("severity", "")
    confidence = data.get("confidence", "")
    additional_args = data.get("additional_args", "")
    cmd = f"bandit -r {target_path} -f json"
    if severity:
        level_map = {"low": 1, "medium": 2, "high": 3}
        idx = level_map.get(severity.lower(), 0)
        if idx:
            cmd += f" -l {'l' * idx}"
    if confidence:
        level_map = {"low": 1, "medium": 2, "high": 3}
        idx = level_map.get(confidence.lower(), 0)
        if idx:
            cmd += f" -i {'i' * idx}"
    if additional_args:
        cmd += f" {sanitize_shell_arg(additional_args)}"
    return cmd


def _build_nc(data: Dict[str, Any]) -> str:
    """nc/ncat/netcat: first elif match (line 1044 — ``nc -w 5 -v``)."""
    target = sanitize_shell_arg(data.get("target", ""))
    port = sanitize_shell_arg(data.get("port", ""))
    additional_args = data.get("additional_args", "")
    cmd = "nc -w 5 -v"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    cmd += f" {target} {port}"
    return cmd


def _build_theharvester_lower(data: Dict[str, Any]) -> str:
    """theharvester (lowercase match — line 858)."""
    domain = sanitize_shell_arg(data.get("domain", ""))
    sources = sanitize_shell_arg(
        data.get("sources", "anubis,crtsh,dnsdumpster,hackertarget,rapiddns"))
    limit = sanitize_shell_arg(data.get("limit", "500"))
    additional_args = data.get("additional_args", "")
    cmd = f"theHarvester -d {domain} -b {sources} -l {limit}"
    if additional_args:
        cmd += f" {sanitize_shell_arg(additional_args)}"
    return cmd


def _build_theHarvester_upper(data: Dict[str, Any]) -> str:
    """theHarvester (mixed-case match — line 1249)."""
    domain = sanitize_shell_arg(data.get("domain", data.get("target", "")))
    sources = data.get("sources",
                       "anubis,crtsh,dnsdumpster,hackertarget,rapiddns,urlscan")
    limit = data.get("limit", "100")
    additional_args = data.get("additional_args", "")
    cmd = (f"theHarvester -d {domain} "
           f"-b {sanitize_shell_arg(sources)} "
           f"-l {sanitize_shell_arg(str(limit))}")
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    return cmd


# ---------------------------------------------------------------------------
# Custom builders — Kali extended tools (impacket suite, etc.)
# ---------------------------------------------------------------------------

def _build_crackmapexec(data: Dict[str, Any]) -> str:
    """crackmapexec/netexec: ``service [options] target``."""
    service = sanitize_shell_arg(data.get("service", "smb"))
    target = sanitize_shell_arg(data.get("target", ""))
    username = data.get("username", "")
    password = data.get("password", "")
    hash_value = data.get("hash_value", "")
    additional_args = data.get("additional_args", "")
    cmd = f"crackmapexec {service}"
    if username:
        cmd += f" -u {sanitize_shell_arg(username)}"
    if password:
        cmd += f" -p {sanitize_shell_arg(password)}"
    if hash_value:
        cmd += f" -H {sanitize_shell_arg(hash_value)}"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    cmd += f" {target}"
    return cmd


def _build_impacket_secretsdump(data: Dict[str, Any]) -> str:
    """impacket-secretsdump: ``domain/user:pass@target`` format."""
    target = data.get("target", "")
    domain = data.get("domain", "")
    username = data.get("username", "")
    password = data.get("password", "")
    hash_value = data.get("hash_value", "")
    additional_args = data.get("additional_args", "")

    if "@" in target:
        auth_target = sanitize_shell_arg(target)
    else:
        parts = []
        if domain:
            parts.append(sanitize_shell_fragment(domain))
            parts.append("/")
        if username:
            parts.append(sanitize_shell_fragment(username))
        if hash_value:
            parts.append(f" -hashes :{sanitize_shell_arg(hash_value)}")
        elif password:
            parts.append(f":{sanitize_shell_fragment(password)}")
        parts.append(f"@{sanitize_shell_arg(target)}")
        auth_target = "".join(parts)

    cmd = f"impacket-secretsdump {auth_target}"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    return cmd


def _build_impacket_remote_exec(tool_binary: str, data: Dict[str, Any]) -> str:
    """Generic builder for impacket psexec/smbexec/wmiexec."""
    target = data.get("target", "")
    username = data.get("username", "")
    password = data.get("password", "")
    hash_value = data.get("hash_value", "")
    command = data.get("command", "")
    additional_args = data.get("additional_args", "")

    if "@" in target:
        auth_target = sanitize_shell_arg(target)
    else:
        parts = []
        if username:
            parts.append(sanitize_shell_fragment(username))
        if hash_value:
            parts.append(f" -hashes :{sanitize_shell_arg(hash_value)}")
        elif password:
            parts.append(f":{sanitize_shell_fragment(password)}")
        parts.append(f"@{sanitize_shell_arg(target)}")
        auth_target = "".join(parts)

    cmd = f"{tool_binary} {auth_target}"
    if command:
        cmd += f" -c {sanitize_shell_arg(command)}"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    return cmd


def _build_impacket_getnpusers(data: Dict[str, Any]) -> str:
    """impacket-GetNPUsers: ``domain/ -usersfile`` format."""
    domain = sanitize_shell_arg(data.get("domain", ""))
    username = data.get("username", "")
    password = data.get("password", "")
    additional_args = data.get("additional_args", "")
    cmd = f"impacket-GetNPUsers {domain}"
    if username:
        cmd += f" -u {sanitize_shell_arg(username)}"
    if password:
        cmd += f" -p {sanitize_shell_arg(password)}"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    return cmd


def _build_impacket_gettgt(data: Dict[str, Any]) -> str:
    """impacket-getTGT: ``domain/username:password`` format."""
    domain = sanitize_shell_arg(data.get("domain", ""))
    username = data.get("username", "")
    password = data.get("password", "")
    hash_value = data.get("hash_value", "")
    additional_args = data.get("additional_args", "")
    cmd = f"impacket-getTGT {domain}"
    if username:
        cmd += f"/{sanitize_shell_fragment(username)}"
    if hash_value:
        cmd += f" -hashes :{sanitize_shell_arg(hash_value)}"
    elif password:
        cmd += f":{sanitize_shell_fragment(password)}"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    return cmd


def _build_impacket_ntlmrelayx(data: Dict[str, Any]) -> str:
    """impacket-ntlmrelayx: ``-t target`` format."""
    target = data.get("target", "")
    additional_args = data.get("additional_args", "")
    cmd = "impacket-ntlmrelayx"
    if target:
        cmd += f" -t {sanitize_shell_arg(target)}"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    return cmd


def _build_bloodhound_python(data: Dict[str, Any]) -> str:
    """bloodhound-python: ``-d domain -u user -p pass -c method``."""
    domain = sanitize_shell_arg(data.get("domain", ""))
    username = sanitize_shell_arg(data.get("username", ""))
    password = sanitize_shell_arg(data.get("password", ""))
    collection = sanitize_shell_arg(data.get("collection_method", "All"))
    additional_args = data.get("additional_args", "")
    cmd = f"bloodhound-python -d {domain}"
    if username:
        cmd += f" -u {username}"
    if password:
        cmd += f" -p {password}"
    cmd += f" -c {collection}"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    return cmd


def _build_tshark(data: Dict[str, Any]) -> str:
    """tshark: capture and display filter combination."""
    interface = data.get("interface", "")
    capture_filter = data.get("capture_filter", "")
    display_filter = data.get("display_filter", "")
    count = data.get("count", "")
    additional_args = data.get("additional_args", "")
    cmd = "tshark"
    if interface:
        cmd += f" -i {sanitize_shell_arg(interface)}"
    if capture_filter:
        cmd += f" -f {sanitize_shell_arg(capture_filter)}"
    if display_filter:
        cmd += f" -Y {sanitize_shell_arg(display_filter)}"
    if count:
        cmd += f" -c {sanitize_shell_arg(str(count))}"
    if additional_args:
        cmd += f" {sanitize_shell_fragment(additional_args)}"
    return cmd


# ---------------------------------------------------------------------------
# Custom builders map
# ---------------------------------------------------------------------------

CUSTOM_BUILDERS: Dict[str, Callable[[Dict[str, Any]], str]] = {
    # Web scanning
    "sqlmap":       _build_sqlmap,

    # Authentication / brute-force
    "hydra":        _build_hydra,
    "ncrack":       _build_ncrack,

    # Network discovery
    "netdiscover":  _build_netdiscover,
    "arp-scan":     _build_arp_scan,
    "arpscan":      _build_arpscan,

    # Sniffing / MITM
    "responder":    _build_responder,
    "ettercap":     _build_ettercap,

    # Wireless
    "aircrack-ng":  _build_aircrack_ng,
    "aircrack":     _build_aircrack,

    # Vulnerability scanning
    "nuclei":       _build_nuclei,

    # Exploitation frameworks
    "metasploit":   _build_metasploit,
    "msfconsole":   _build_msfconsole,
    "msfvenom":     _build_msfvenom,

    # Reverse engineering
    "radare2":      _build_radare2,
    "r2":           _build_r2,
    "binwalk":      _build_binwalk,

    # OSINT / recon
    "sherlock":     _build_sherlock,
    "recon-ng":     _build_recon_ng,
    "theharvester": _build_theharvester_lower,
    "theHarvester": _build_theHarvester_upper,

    # HTTP / network utilities
    "httpx":        _build_httpx,
    "curl":         _build_curl,
    "wget":         _build_wget,
    "dig":          _build_dig,
    "nc":           _build_nc,
    "ncat":         _build_nc,
    "netcat":       _build_nc,

    # Remote access
    "ssh":          _build_ssh,
    "scp":          _build_scp,

    # Crypto / encoding
    "openssl":      _build_openssl,
    "base64":       _build_base64,

    # Forensics / stego
    "steghide":     _build_steghide,
    "xxd":          _build_xxd,

    # Code audit
    "bandit":       _build_bandit,
    "semgrep":      _build_semgrep,
    "shellcheck":   _build_shellcheck,

    # Text processing
    "grep":         _build_grep,

    # Scripting
    "python3":      _build_python3,
    "python":       _build_python3,

    # DoS testing
    "slowhttptest": _build_slowhttptest,

    # --- Kali Extended: AD / Windows ---
    "crackmapexec":         _build_crackmapexec,
    "netexec":              _build_crackmapexec,
    "nxc":                  _build_crackmapexec,
    "impacket-secretsdump": _build_impacket_secretsdump,
    "impacket-psexec":      lambda d: _build_impacket_remote_exec("impacket-psexec", d),
    "impacket-smbexec":     lambda d: _build_impacket_remote_exec("impacket-smbexec", d),
    "impacket-wmiexec":     lambda d: _build_impacket_remote_exec("impacket-wmiexec", d),
    "impacket-getnpusers":  _build_impacket_getnpusers,
    "impacket-GetNPUsers":  _build_impacket_getnpusers,
    "impacket-getTGT":      _build_impacket_gettgt,
    "impacket-ntlmrelayx":  _build_impacket_ntlmrelayx,
    "bloodhound-python":    _build_bloodhound_python,
    "bloodhound":           _build_bloodhound_python,

    # --- Kali Extended: Network ---
    "tshark":               _build_tshark,
}


# ---------------------------------------------------------------------------
# Internal: declarative command builder
# ---------------------------------------------------------------------------

def _resolve_param_value(param: ToolParam, data: Dict[str, Any]) -> Optional[str]:
    """Resolve a parameter's value from the data dict.

    Returns the raw string value, or ``None`` if the parameter should be
    skipped (condition not met / no value available).
    """
    # If condition_key is set, the parameter is skipped unless the condition
    # key is present AND truthy in the data dict.
    if param.condition_key:
        if not data.get(param.condition_key):
            return None

    # Try primary key first, then alt_keys, then default.
    value = data.get(param.name)
    if value is None or value == "":
        for alt in param.alt_keys:
            value = data.get(alt)
            if value is not None and value != "":
                break

    if value is None or value == "":
        if param.default:
            value = param.default
        else:
            # No value and no default — for non-required params this means
            # the param is silently omitted.
            if not param.required:
                return None
            # Required but missing — return empty string so the caller can
            # still build the command (matches original executor behaviour).
            value = ""

    return str(value)


def _sanitize_value(value: str, mode: str) -> str:
    """Apply the requested sanitisation mode to a value."""
    if mode == "arg":
        return sanitize_shell_arg(value)
    elif mode == "fragment":
        return sanitize_shell_fragment(value)
    # mode == "none"
    return value


def _build_from_spec(spec: ToolSpec, data: Dict[str, Any]) -> str:
    """Build a complete shell command from a :class:`ToolSpec` and data dict.

    Ordering convention (base_args_position="after", default):
        binary [first-params] [normal-params] [base_args] [additional_args] [last-params]

    Ordering convention (base_args_position="before"):
        binary [base_args] [first-params] [normal-params] [additional_args] [last-params]
    """
    parts: List[str] = [spec.binary]

    # Base args BEFORE params when specified
    if spec.base_args and spec.base_args_position == "before":
        parts.append(spec.base_args)

    first_parts: List[str] = []
    normal_parts: List[str] = []
    last_parts: List[str] = []

    for param in spec.params:
        value = _resolve_param_value(param, data)
        if value is None:
            continue

        sanitized = _sanitize_value(value, param.sanitize)

        if param.flag:
            # Flag-based: combine flag + value with the specified join char
            token = f"{param.flag}{param.join}{sanitized}"
        else:
            # Positional: bare value
            token = sanitized

        if param.position == "first":
            first_parts.append(token)
        elif param.position == "last":
            last_parts.append(token)
        else:
            normal_parts.append(token)

    # Assemble
    parts.extend(first_parts)
    parts.extend(normal_parts)

    # Base args AFTER params (default position)
    if spec.base_args and spec.base_args_position == "after":
        parts.append(spec.base_args)

    # additional_args — universal passthrough
    additional_args = data.get("additional_args", "")

    # Some tools have a non-empty default for additional_args when the caller
    # does not supply one.  The original executor uses
    # ``data.get("additional_args", "<default>")``.  We replicate that here
    # by inspecting well-known per-tool defaults.
    aa_defaults = _ADDITIONAL_ARGS_DEFAULTS.get(spec.binary, "")
    if not additional_args and aa_defaults:
        additional_args = aa_defaults

    if additional_args:
        if spec.additional_args_sanitize == "fragment":
            parts.append(sanitize_shell_fragment(additional_args))
        else:
            parts.append(sanitize_shell_arg(additional_args))

    parts.extend(last_parts)

    return " ".join(p for p in parts if p)


# Per-binary default values for ``additional_args`` when the caller omits it.
# Only populated for tools whose original elif block supplies a non-empty
# default via ``data.get("additional_args", "<value>")``.
_ADDITIONAL_ARGS_DEFAULTS: Dict[str, str] = {
    "wfuzz":     "-c",
    "wafw00f":   "-a",
    "sublist3r": "-v",
    "reaver":    "-vv",
    "bully":     "-v",
    "enum4linux": "-a",
    "zsteg":     "-a",
    "grep":      "-rn",
    "wpscan":    "--enumerate p,t,u",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Reverse-lookup cache:  alias  canonical registry key
_ALIAS_INDEX: Dict[str, str] = {}


def _ensure_alias_index() -> None:
    """Lazily build the alias  canonical-name index."""
    if _ALIAS_INDEX:
        return
    for name, spec in TOOL_REGISTRY.items():
        for alias in spec.aliases:
            _ALIAS_INDEX[alias] = name


def get_tool_spec(tool_name: str) -> Optional[ToolSpec]:
    """Return the :class:`ToolSpec` for *tool_name*, or ``None``.

    Checks primary names first, then aliases.  For tools that only live in
    ``CUSTOM_BUILDERS`` (no declarative spec), a minimal ``ToolSpec`` is
    returned with at least the binary name set.
    """
    if tool_name in TOOL_REGISTRY:
        return TOOL_REGISTRY[tool_name]

    _ensure_alias_index()
    canonical = _ALIAS_INDEX.get(tool_name)
    if canonical:
        return TOOL_REGISTRY[canonical]

    # For custom-only tools, return a minimal spec
    if tool_name in CUSTOM_BUILDERS:
        return _CUSTOM_TOOL_SPECS.get(tool_name)

    return None


def get_output_parser_name(tool_name: str) -> str:
    """Return the output parser key for *tool_name*, or ``""``."""
    spec = get_tool_spec(tool_name)
    if spec is not None:
        return spec.output_parser
    return ""


def build_command(tool_name: str, data: Dict[str, Any]) -> str:
    """Build the full shell command for *tool_name* from a *data* dict.

    Resolution order:
        1. ``CUSTOM_BUILDERS`` — if a custom builder exists, use it.
        2. ``TOOL_REGISTRY`` (primary key) — declarative build.
        3. ``TOOL_REGISTRY`` (alias lookup) — declarative build.
        4. Return ``""`` if the tool is unknown.

    Args:
        tool_name: Canonical or aliased tool name.
        data: Parameter dict as passed by the MCP tool functions.

    Returns:
        Complete shell command string, or ``""`` if the tool is not
        recognised.
    """
    # 1. Custom builder takes priority
    if tool_name in CUSTOM_BUILDERS:
        return CUSTOM_BUILDERS[tool_name](data)

    # 2. Declarative registry — primary name
    if tool_name in TOOL_REGISTRY:
        return _build_from_spec(TOOL_REGISTRY[tool_name], data)

    # 3. Declarative registry — alias
    _ensure_alias_index()
    canonical = _ALIAS_INDEX.get(tool_name)
    if canonical:
        # Check if the alias itself has a custom builder
        if canonical in CUSTOM_BUILDERS:
            return CUSTOM_BUILDERS[canonical](data)
        return _build_from_spec(TOOL_REGISTRY[canonical], data)

    logger.warning("tool_registry: unknown tool '%s'", tool_name)
    return ""


# ---------------------------------------------------------------------------
# Minimal ToolSpecs for custom-only tools (metadata / timeout / parser info)
# ---------------------------------------------------------------------------

_CUSTOM_TOOL_SPECS: Dict[str, ToolSpec] = {
    "sqlmap":       ToolSpec(binary="sqlmap", timeout=600, output_parser="sqlmap"),
    "hydra":        ToolSpec(binary="hydra", timeout=600, output_parser="hydra"),
    "ncrack":       ToolSpec(binary="ncrack"),
    "netdiscover":  ToolSpec(binary="netdiscover"),
    "arp-scan":     ToolSpec(binary="arp-scan"),
    "arpscan":      ToolSpec(binary="arp-scan"),
    "responder":    ToolSpec(binary="responder"),
    "ettercap":     ToolSpec(binary="ettercap"),
    "aircrack-ng":  ToolSpec(binary="aircrack-ng"),
    "aircrack":     ToolSpec(binary="aircrack-ng"),
    "nuclei":       ToolSpec(binary="nuclei", timeout=300, output_parser="nuclei"),
    "metasploit":   ToolSpec(binary="msfconsole", timeout=600),
    "msfconsole":   ToolSpec(binary="msfconsole", timeout=600),
    "msfvenom":     ToolSpec(binary="msfvenom"),
    "radare2":      ToolSpec(binary="r2"),
    "r2":           ToolSpec(binary="r2"),
    "binwalk":      ToolSpec(binary="binwalk"),
    "sherlock":     ToolSpec(binary="sherlock"),
    "recon-ng":     ToolSpec(binary="recon-ng"),
    "theharvester": ToolSpec(binary="theHarvester"),
    "theHarvester": ToolSpec(binary="theHarvester"),
    "httpx":        ToolSpec(binary="httpx"),
    "curl":         ToolSpec(binary="curl"),
    "dig":          ToolSpec(binary="dig"),
    "nc":           ToolSpec(binary="nc"),
    "ncat":         ToolSpec(binary="ncat"),
    "netcat":       ToolSpec(binary="nc"),
    "ssh":          ToolSpec(binary="ssh"),
    "scp":          ToolSpec(binary="scp"),
    "openssl":      ToolSpec(binary="openssl"),
    "base64":       ToolSpec(binary="base64"),
    "steghide":     ToolSpec(binary="steghide"),
    "xxd":          ToolSpec(binary="xxd"),
    "bandit":       ToolSpec(binary="bandit"),
    "semgrep":      ToolSpec(binary="semgrep"),
    "shellcheck":   ToolSpec(binary="shellcheck"),
    "grep":         ToolSpec(binary="grep"),
    "wget":         ToolSpec(binary="wget"),
    "python3":      ToolSpec(binary="python3"),
    "python":       ToolSpec(binary="python3"),
    "slowhttptest": ToolSpec(binary="slowhttptest"),
}


# ---------------------------------------------------------------------------
# Auto-generated ALLOWED_TOOLS set
# ---------------------------------------------------------------------------

def _build_allowed_tools() -> Set[str]:
    """Derive the complete set of recognised tool names from the registry.

    Includes:
    - All primary keys in ``TOOL_REGISTRY``
    - All ``aliases`` declared in each ``ToolSpec``
    - All keys in ``CUSTOM_BUILDERS``
    - All keys in ``_CUSTOM_TOOL_SPECS``
    """
    names: Set[str] = set()

    # Registry primary keys + aliases
    for name, spec in TOOL_REGISTRY.items():
        names.add(name)
        for alias in spec.aliases:
            names.add(alias)

    # Custom builders
    names.update(CUSTOM_BUILDERS.keys())

    # Custom tool specs (some may overlap, that's fine)
    names.update(_CUSTOM_TOOL_SPECS.keys())

    return names


ALLOWED_TOOLS: Set[str] = _build_allowed_tools()

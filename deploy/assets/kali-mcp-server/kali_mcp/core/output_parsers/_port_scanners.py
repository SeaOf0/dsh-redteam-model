#!/usr/bin/env python3
"""Port scanner output parsers: NmapParser, MasscanParser."""

import re
import logging
from typing import Dict, Any, List, Optional

from ._base import BaseOutputParser, ParsedResult, detect_flags, smart_truncate

logger = logging.getLogger(__name__)

class NmapParser(BaseOutputParser):
    """
    Nmap 输出解析器。

    解析内容:
    - 开放端口（端口号、协议、状态、服务、版本）
    - OS 检测结果
    - NSE 脚本输出
    - 主机存活状态

    structured_data 格式:
    {
        "ports": [{"port": 80, "protocol": "tcp", "state": "open",
                   "service": "http", "version": "Apache 2.4.41"}],
        "os": "Ubuntu Linux",
        "hostname": "target.com",
        "scripts": {"http-title": "Welcome"},
        "host_up": True
    }
    """

    tool_name = "nmap"

    # 端口行: 80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
    _PORT_RE = re.compile(
        r'(\d+)/(tcp|udp)\s+'
        r'(open|closed|filtered|open\|filtered)\s+'
        r'(\S+)'
        r'(?:\s+(.*))?'
    )
    _OS_RE = re.compile(r'OS details?:\s*(.+)', re.IGNORECASE)
    _HOST_RE = re.compile(r'Nmap scan report for\s+(\S+)(?:\s+\(([^)]+)\))?')
    _SCRIPT_HEADER_RE = re.compile(r'^\|[\s_]+([\w-]+):\s*(.*)')
    _SCRIPT_CONT_RE = re.compile(r'^\|[\s_]+\s+(.*)')

    # 端口到服务映射 — 建议下一步工具
    _PORT_NEXT_STEPS = {
        'http': '发现HTTP服务(端口{port})  建议使用 gobuster_scan 扫描目录, nikto_scan 扫描漏洞',
        'https': '发现HTTPS服务(端口{port})  建议使用 gobuster_scan 扫描目录, nuclei_web_scan 扫描漏洞',
        'ssh': '发现SSH服务(端口{port})  建议使用 hydra_attack 爆破弱密码',
        'ftp': '发现FTP服务(端口{port})  检查匿名登录, 建议使用 hydra_attack 爆破',
        'mysql': '发现MySQL服务(端口{port})  建议使用 hydra_attack 爆破, 检查空密码',
        'postgresql': '发现PostgreSQL服务(端口{port})  建议使用 hydra_attack 爆破',
        'smb': '发现SMB服务(端口{port})  建议使用 enum4linux_scan 枚举共享和用户',
        'microsoft-ds': '发现SMB服务(端口{port})  建议使用 enum4linux_scan 枚举',
        'netbios-ssn': '发现NetBIOS服务(端口{port})  建议使用 enum4linux_scan 枚举',
        'redis': '发现Redis服务(端口{port})  检查未授权访问',
        'mongodb': '发现MongoDB服务(端口{port})  检查未授权访问',
        'rdp': '发现RDP服务(端口{port})  建议使用 hydra_attack 爆破, 检查BlueKeep',
        'ms-wbt-server': '发现RDP服务(端口{port})  建议使用 hydra_attack 爆破',
        'telnet': '发现Telnet服务(端口{port})  建议使用 hydra_attack 爆破',
        'vnc': '发现VNC服务(端口{port})  建议使用 hydra_attack 爆破',
        'smtp': '发现SMTP服务(端口{port})  枚举用户, 检查开放中继',
        'pop3': '发现POP3服务(端口{port})  建议使用 hydra_attack 爆破',
        'imap': '发现IMAP服务(端口{port})  建议使用 hydra_attack 爆破',
        'dns': '发现DNS服务(端口{port})  建议使用 dnsrecon_scan 检查区域传送',
        'domain': '发现DNS服务(端口{port})  建议使用 dnsrecon_scan 检查区域传送',
        'ldap': '发现LDAP服务(端口{port})  检查匿名绑定, 枚举信息',
        'snmp': '发现SNMP服务(端口{port})  使用 community string 枚举信息',
    }

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        ports: List[Dict[str, Any]] = []
        os_info = ""
        hostname = ""
        target = data.get("target", "")
        host_up = True
        scripts: Dict[str, str] = {}
        current_script_name = ""
        current_script_value = ""

        if not output.strip():
            return ParsedResult(
                tool_name=self.tool_name,
                success=return_code == 0,
                summary="Nmap 扫描无输出",
                structured_data={"ports": [], "os": "", "hostname": "", "scripts": {}, "host_up": False},
                raw_output="",
                next_steps=[],
                severity="info",
                confidence=0.5,
            )

        for line in output.split('\n'):
            stripped = line.strip()

            # 主机行
            host_match = self._HOST_RE.search(stripped)
            if host_match:
                hostname = host_match.group(1)
                if host_match.group(2):
                    target = target or host_match.group(2)
                elif not target:
                    target = hostname
                continue

            # 主机存活
            if 'Host is up' in stripped:
                host_up = True
                continue
            if 'Host seems down' in stripped:
                host_up = False
                continue

            # 端口行
            port_match = self._PORT_RE.match(stripped)
            if port_match:
                # 先保存前一个脚本
                if current_script_name:
                    scripts[current_script_name] = current_script_value.strip()
                    current_script_name = ""
                    current_script_value = ""

                port_num = int(port_match.group(1))
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4)
                version_raw = (port_match.group(5) or "").strip()

                # 清理 ssl/http  https
                if service.startswith("ssl/"):
                    service = service.replace("ssl/http", "https").replace("ssl/", "")

                # 版本提取
                version = version_raw
                ver_match = re.search(r'([\d.]+(?:p\d+)?)', version_raw)
                if ver_match:
                    version = ver_match.group(1)

                port_entry = {
                    "port": port_num,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "version": version,
                    "version_raw": version_raw,
                }
                ports.append(port_entry)
                continue

            # OS 检测
            os_match = self._OS_RE.search(stripped)
            if os_match:
                os_info = os_match.group(1).strip()
                continue

            # NSE 脚本输出
            script_header = self._SCRIPT_HEADER_RE.match(line)
            if script_header:
                if current_script_name:
                    scripts[current_script_name] = current_script_value.strip()
                current_script_name = script_header.group(1)
                current_script_value = script_header.group(2)
                continue

            script_cont = self._SCRIPT_CONT_RE.match(line)
            if script_cont and current_script_name:
                current_script_value += "\n" + script_cont.group(1)
                continue

        # 保存最后一个脚本
        if current_script_name:
            scripts[current_script_name] = current_script_value.strip()

        # 构建 next_steps
        open_ports = [p for p in ports if p["state"] == "open"]
        next_steps = self._build_next_steps(open_ports)

        # 构建摘要
        if not open_ports:
            summary = f"Nmap 扫描 {target or hostname}: 未发现开放端口"
            if not host_up:
                summary = f"Nmap 扫描 {target or hostname}: 主机似乎不在线"
        else:
            port_desc = ", ".join(
                f"{p['port']}({p['service']})" for p in open_ports[:8]
            )
            extra = f" 等共 {len(open_ports)} 个" if len(open_ports) > 8 else ""
            summary = f"Nmap 扫描 {target or hostname}: 发现 {len(open_ports)} 个开放端口: {port_desc}{extra}"

        # 严重性判断
        severity = "info"
        for p in open_ports:
            svc = p["service"].lower()
            if svc in ("telnet", "ftp", "snmp"):
                severity = "medium"
            if svc in ("redis", "mongodb") and not p.get("version_raw", ""):
                severity = "high"  # 可能未授权访问

        structured_data = {
            "ports": ports,
            "os": os_info,
            "hostname": hostname,
            "scripts": scripts,
            "host_up": host_up,
            "open_port_count": len(open_ports),
        }

        # 通用建议
        if open_ports:
            web_ports = [p for p in open_ports if p["service"] in ("http", "https", "http-proxy", "http-alt")]
            if web_ports:
                next_steps.append(
                    f"发现 {len(web_ports)} 个Web端口  建议使用 nuclei_web_scan 进行全面漏洞扫描"
                )

        return ParsedResult(
            tool_name=self.tool_name,
            success=return_code == 0,
            summary=summary,
            structured_data=structured_data,
            raw_output="",  # 由基类填充
            next_steps=next_steps,
            severity=severity,
            confidence=0.95 if open_ports else 0.7,
        )

    def _build_next_steps(self, open_ports: List[Dict[str, Any]]) -> List[str]:
        """根据开放端口生成下一步建议"""
        steps: List[str] = []
        seen_services: set = set()

        for p in open_ports:
            service = p["service"].lower()
            # 避免同一服务重复建议
            if service in seen_services:
                continue
            seen_services.add(service)

            template = self._PORT_NEXT_STEPS.get(service)
            if template:
                steps.append(template.format(port=p["port"]))

            # 版本特定建议
            version_raw = p.get("version_raw", "").lower()
            if "apache" in version_raw:
                steps.append(f"Apache 服务(端口{p['port']})  建议使用 nuclei_cve_scan 检查已知CVE")
            elif "nginx" in version_raw:
                steps.append(f"Nginx 服务(端口{p['port']})  建议使用 nuclei_cve_scan 检查已知CVE")
            elif "openssh" in version_raw:
                ver_match = re.search(r'openssh[_\s]*([\d.]+)', version_raw)
                if ver_match:
                    steps.append(
                        f"OpenSSH {ver_match.group(1)}  使用 searchsploit_search 检查版本漏洞"
                    )

        return steps


class MasscanParser(BaseOutputParser):
    """
    Masscan 快速端口扫描输出解析器。

    Masscan 输出格式:
        Discovered open port 80/tcp on 192.168.1.1
        Discovered open port 443/tcp on 192.168.1.1

    structured_data 格式:
    {
        "ports": [{"port": 80, "protocol": "tcp", "host": "192.168.1.1"}],
        "hosts": ["192.168.1.1"],
        "open_port_count": 2
    }
    """

    tool_name = "masscan"

    _PORT_RE = re.compile(
        r'Discovered open port (\d+)/(tcp|udp) on (\S+)'
    )

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        target = data.get("target", "")
        ports: List[Dict[str, Any]] = []
        hosts: set = set()

        if not output.strip():
            return ParsedResult(
                tool_name=self.tool_name,
                success=return_code == 0,
                summary=f"Masscan 扫描 {target}: 未发现开放端口",
                structured_data={"ports": [], "hosts": [], "open_port_count": 0},
                raw_output="",
                next_steps=[],
                severity="info",
                confidence=0.6,
            )

        for line in output.split('\n'):
            match = self._PORT_RE.search(line.strip())
            if match:
                host = match.group(3)
                hosts.add(host)
                ports.append({
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "host": host,
                })

        # next_steps
        next_steps: List[str] = []
        if ports:
            host_list = sorted(hosts)
            port_str = ",".join(str(p["port"]) for p in sorted(ports, key=lambda x: x["port"]))
            next_steps.append(
                f"发现 {len(ports)} 个开放端口  建议使用 nmap_scan -sV "
                f"对这些端口进行服务版本检测"
            )
            web_ports = [p for p in ports if p["port"] in (80, 443, 8080, 8443, 8888)]
            if web_ports:
                next_steps.append(
                    f"发现Web端口  建议使用 whatweb_scan 识别技术栈"
                )

        summary = (
            f"Masscan 扫描 {target}: 发现 {len(ports)} 个开放端口 "
            f"在 {len(hosts)} 个主机上"
        )

        return ParsedResult(
            tool_name=self.tool_name,
            success=return_code == 0,
            summary=summary,
            structured_data={
                "ports": ports,
                "hosts": sorted(hosts),
                "open_port_count": len(ports),
            },
            raw_output="",
            next_steps=next_steps,
            severity="info",
            confidence=0.85 if ports else 0.6,
        )


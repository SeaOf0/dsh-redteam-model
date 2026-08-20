#!/usr/bin/env python3
"""
工具输出结果解析器 - 将原始文本转为结构化数据

这是整个系统产生真正渗透测试能力的关键模块。
没有结果解析，工具链就只是串行执行的脚本。
有了结果解析，nmap的端口发现可以驱动后续所有工具的参数选择。

支持的解析器:
- NmapParser: 端口、服务、版本、脚本输出
- GobusterParser: 路径、状态码、大小
- NucleiParser: CVE、严重性、匹配模板
- SqlmapParser: 注入点、数据库类型、表名
- WhatwebParser: 技术栈、CMS、框架
- Wafw00fParser: WAF类型
- MasscanParser: 开放端口
- NiktoParser: 发现的问题
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ============================================================
# 结构化结果数据类
# ============================================================

@dataclass
class PortInfo:
    """端口信息"""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    product: str = ""
    extra_info: str = ""
    scripts: Dict[str, str] = field(default_factory=dict)


@dataclass
class NmapResult:
    """Nmap扫描结果"""
    target: str = ""
    ports: List[PortInfo] = field(default_factory=list)
    os_guess: str = ""
    hostname: str = ""
    is_up: bool = True
    raw_output: str = ""

    @property
    def open_ports(self) -> List[int]:
        return [p.port for p in self.ports if p.state == "open"]

    @property
    def http_ports(self) -> List[int]:
        return [p.port for p in self.ports
                if p.state == "open" and p.service in ("http", "https", "http-proxy", "http-alt")]

    @property
    def has_web_service(self) -> bool:
        web_services = {"http", "https", "http-proxy", "http-alt"}
        return any(p.service in web_services for p in self.ports if p.state == "open")

    @property
    def has_ssh(self) -> bool:
        return any(p.service == "ssh" for p in self.ports if p.state == "open")

    @property
    def has_database(self) -> bool:
        db_services = {"mysql", "postgresql", "mssql", "oracle", "mongodb", "redis"}
        return any(p.service in db_services for p in self.ports if p.state == "open")

    @property
    def web_urls(self) -> List[str]:
        urls = []
        for p in self.ports:
            if p.state != "open":
                continue
            if p.service in ("https",) or p.port == 443:
                urls.append(f"https://{self.target}:{p.port}")
            elif p.service in ("http", "http-proxy", "http-alt") or p.port in (80, 8080, 8443, 8888):
                urls.append(f"http://{self.target}:{p.port}")
        if not urls and self.has_web_service:
            urls.append(f"http://{self.target}")
        return urls

    @property
    def service_versions(self) -> Dict[str, str]:
        """服务 -> 版本映射"""
        return {p.service: p.version for p in self.ports
                if p.state == "open" and p.version}


@dataclass
class PathInfo:
    """发现的路径"""
    path: str
    status_code: int = 200
    size: int = 0
    redirect: str = ""


@dataclass
class GobusterResult:
    """Gobuster/目录扫描结果"""
    target: str = ""
    paths: List[PathInfo] = field(default_factory=list)
    raw_output: str = ""

    @property
    def interesting_paths(self) -> List[str]:
        """有价值的路径 (排除404/403)"""
        return [p.path for p in self.paths if p.status_code in (200, 301, 302)]

    @property
    def admin_paths(self) -> List[str]:
        """管理后台路径"""
        admin_keywords = {"admin", "manager", "dashboard", "console", "panel",
                          "wp-admin", "administrator", "backend", "control"}
        return [p.path for p in self.paths
                if any(kw in p.path.lower() for kw in admin_keywords)]

    @property
    def api_paths(self) -> List[str]:
        """API路径"""
        api_keywords = {"api", "graphql", "rest", "v1", "v2", "swagger", "docs"}
        return [p.path for p in self.paths
                if any(kw in p.path.lower() for kw in api_keywords)]

    @property
    def upload_paths(self) -> List[str]:
        """文件上传路径"""
        upload_keywords = {"upload", "file", "attach", "media", "image"}
        return [p.path for p in self.paths
                if any(kw in p.path.lower() for kw in upload_keywords)]

    @property
    def login_paths(self) -> List[str]:
        """登录页面路径"""
        login_keywords = {"login", "signin", "auth", "sso", "cas", "register", "signup"}
        return [p.path for p in self.paths
                if any(kw in p.path.lower() for kw in login_keywords)]


@dataclass
class VulnFinding:
    """漏洞发现"""
    template_id: str = ""
    name: str = ""
    severity: str = "info"
    url: str = ""
    matched_at: str = ""
    cve_id: str = ""
    description: str = ""


@dataclass
class NucleiResult:
    """Nuclei扫描结果"""
    target: str = ""
    findings: List[VulnFinding] = field(default_factory=list)
    raw_output: str = ""

    @property
    def critical_findings(self) -> List[VulnFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high_findings(self) -> List[VulnFinding]:
        return [f for f in self.findings if f.severity == "high"]

    @property
    def cve_list(self) -> List[str]:
        return [f.cve_id for f in self.findings if f.cve_id]

    @property
    def has_critical(self) -> bool:
        return len(self.critical_findings) > 0


@dataclass
class SqlmapResult:
    """Sqlmap扫描结果"""
    target: str = ""
    is_vulnerable: bool = False
    injection_type: str = ""  # boolean-based, time-based, union-based, error-based
    dbms: str = ""            # MySQL, PostgreSQL, MSSQL, Oracle, SQLite
    databases: List[str] = field(default_factory=list)
    tables: Dict[str, List[str]] = field(default_factory=dict)  # db -> [tables]
    injectable_params: List[str] = field(default_factory=list)
    raw_output: str = ""


@dataclass
class TechInfo:
    """技术栈信息"""
    name: str
    version: str = ""
    category: str = ""  # cms, framework, server, language, js-lib


@dataclass
class WhatwebResult:
    """Whatweb扫描结果"""
    target: str = ""
    technologies: List[TechInfo] = field(default_factory=list)
    cms: str = ""           # WordPress, Joomla, Drupal, etc.
    server: str = ""        # Apache, Nginx, IIS
    framework: str = ""     # Django, Rails, Laravel, Spring
    language: str = ""      # PHP, Python, Java, .NET
    raw_output: str = ""

    @property
    def is_wordpress(self) -> bool:
        return self.cms.lower() == "wordpress" or any(
            "wordpress" in t.name.lower() for t in self.technologies)

    @property
    def is_php(self) -> bool:
        return self.language.lower() == "php" or any(
            "php" in t.name.lower() for t in self.technologies)


@dataclass
class WafResult:
    """WAF检测结果"""
    target: str = ""
    has_waf: bool = False
    waf_name: str = ""  # cloudflare, akamai, imperva, modsecurity, etc.
    raw_output: str = ""


# ============================================================
# 解析器实现
# ============================================================

class ResultParser:
    """工具输出解析器集合"""

    @staticmethod
    def parse_nmap(output: str, target: str = "") -> NmapResult:
        """
        解析nmap输出

        支持格式:
        - 标准nmap文本输出
        - nmap -sV 服务版本检测输出

        示例输入:
        80/tcp   open  http    Apache httpd 2.4.41
        443/tcp  open  ssl/http nginx 1.18.0
        22/tcp   open  ssh     OpenSSH 8.2p1
        """
        result = NmapResult(target=target, raw_output=output)

        if not output:
            return result

        lines = output.split("\n")

        for line in lines:
            line = line.strip()

            # 解析端口行: 80/tcp open http Apache httpd 2.4.41
            port_match = re.match(
                r'(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?', line
            )
            if port_match:
                port_num = int(port_match.group(1))
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4)
                version_info = port_match.group(5) or ""

                # 解析版本信息
                product = ""
                version = ""
                if version_info:
                    # "Apache httpd 2.4.41" -> product="Apache httpd", version="2.4.41"
                    ver_match = re.search(r'([\d.]+(?:p\d+)?)', version_info)
                    if ver_match:
                        version = ver_match.group(1)
                        product = version_info[:ver_match.start()].strip()
                    else:
                        product = version_info.strip()

                # 清理service名 (ssl/http -> https)
                if service.startswith("ssl/"):
                    service = service.replace("ssl/http", "https").replace("ssl/", "")

                port_info = PortInfo(
                    port=port_num,
                    protocol=protocol,
                    state=state,
                    service=service,
                    version=version,
                    product=product,
                    extra_info=version_info,
                )
                result.ports.append(port_info)
                continue

            # 解析OS检测
            os_match = re.search(r'OS details?:\s*(.+)', line)
            if os_match:
                result.os_guess = os_match.group(1).strip()
                continue

            # 解析主机名
            host_match = re.search(r'Nmap scan report for (\S+)', line)
            if host_match:
                hostname = host_match.group(1)
                if not result.target:
                    result.target = hostname
                result.hostname = hostname
                continue

            # 检测主机是否存活
            if "Host is up" in line:
                result.is_up = True
            elif "Host seems down" in line:
                result.is_up = False

            # 解析nmap脚本输出 (|_ 前缀)
            if result.ports and (line.startswith("|") or line.startswith("|_")):
                script_line = line.lstrip("|_").strip()
                if ":" in script_line:
                    key, _, value = script_line.partition(":")
                    result.ports[-1].scripts[key.strip()] = value.strip()

        return result

    @staticmethod
    def parse_masscan(output: str, target: str = "") -> NmapResult:
        """
        解析masscan输出

        格式: Discovered open port 80/tcp on 192.168.1.1
        """
        result = NmapResult(target=target, raw_output=output)

        if not output:
            return result

        for line in output.split("\n"):
            match = re.search(r'Discovered open port (\d+)/(tcp|udp) on (\S+)', line)
            if match:
                port_info = PortInfo(
                    port=int(match.group(1)),
                    protocol=match.group(2),
                    state="open",
                )
                result.ports.append(port_info)
                if not result.target:
                    result.target = match.group(3)

        return result

    @staticmethod
    def parse_gobuster(output: str, target: str = "") -> GobusterResult:
        """
        解析gobuster输出

        格式:
        /admin                (Status: 200) [Size: 1234]
        /login                (Status: 302) [Size: 0] [--> /auth/login]
        """
        result = GobusterResult(target=target, raw_output=output)

        if not output:
            return result

        for line in output.split("\n"):
            line = line.strip()

            # gobuster dir模式: /path (Status: 200) [Size: 1234]
            match = re.match(
                r'(/\S*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?'
                r'(?:\s+\[--> (\S+)\])?',
                line
            )
            if match:
                path_info = PathInfo(
                    path=match.group(1),
                    status_code=int(match.group(2)),
                    size=int(match.group(3)) if match.group(3) else 0,
                    redirect=match.group(4) or "",
                )
                result.paths.append(path_info)
                continue

            # ffuf/feroxbuster 格式: 200 GET 1234l 5678w 9012c http://target/path
            match2 = re.match(r'(\d{3})\s+\S+\s+\d+l\s+\d+w\s+(\d+)c\s+(\S+)', line)
            if match2:
                url = match2.group(3)
                path = "/" + url.split("/", 3)[-1] if "/" in url[8:] else "/"
                path_info = PathInfo(
                    path=path,
                    status_code=int(match2.group(1)),
                    size=int(match2.group(2)),
                )
                result.paths.append(path_info)

        return result

    @staticmethod
    def parse_nuclei(output: str, target: str = "") -> NucleiResult:
        """
        解析nuclei输出

        格式 (JSON模式):
        [critical] [CVE-2021-44228] [http] http://target/path
        [high] [apache-struts-rce] [http] http://target/path

        也支持nuclei -json 输出
        """
        result = NucleiResult(target=target, raw_output=output)

        if not output:
            return result

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            # 标准文本格式: [severity] [template-id] [protocol] url
            match = re.match(
                r'\[(\w+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)',
                line
            )
            if match:
                severity = match.group(1).lower()
                template_id = match.group(2)
                url = match.group(4)

                # 提取CVE
                cve_match = re.search(r'(CVE-\d{4}-\d+)', template_id, re.IGNORECASE)
                cve_id = cve_match.group(1) if cve_match else ""

                finding = VulnFinding(
                    template_id=template_id,
                    name=template_id,
                    severity=severity,
                    url=url,
                    cve_id=cve_id,
                )
                result.findings.append(finding)
                continue

            # JSON格式
            if line.startswith("{"):
                try:
                    import json
                    data = json.loads(line)
                    finding = VulnFinding(
                        template_id=data.get("template-id", ""),
                        name=data.get("info", {}).get("name", ""),
                        severity=data.get("info", {}).get("severity", "info"),
                        url=data.get("matched-at", ""),
                        cve_id=data.get("info", {}).get("classification", {}).get("cve-id", ""),
                    )
                    result.findings.append(finding)
                except (json.JSONDecodeError, KeyError):
                    pass

        return result

    @staticmethod
    def parse_sqlmap(output: str, target: str = "") -> SqlmapResult:
        """
        解析sqlmap输出

        关键标记:
        - "is vulnerable" = 发现注入
        - "back-end DBMS: MySQL" = 数据库类型
        - "available databases" = 数据库列表
        """
        result = SqlmapResult(target=target, raw_output=output)

        if not output:
            return result

        lines = output.split("\n")

        for line in lines:
            line = line.strip()

            # 检测注入 — 排除否定短语 "not injectable" / "might not be injectable"
            ll = line.lower()
            if "is vulnerable" in ll:
                result.is_vulnerable = True
            elif "injectable" in ll and "not" not in ll:
                result.is_vulnerable = True

            # 检测注入类型
            for inj_type in ["boolean-based", "time-based", "UNION query",
                             "error-based", "stacked queries"]:
                if inj_type.lower() in line.lower():
                    if result.injection_type:
                        result.injection_type += ", " + inj_type
                    else:
                        result.injection_type = inj_type

            # 检测数据库类型
            dbms_match = re.search(r'back-end DBMS:\s*(.+)', line)
            if dbms_match:
                result.dbms = dbms_match.group(1).strip()

            # 检测注入参数
            param_match = re.search(r"Parameter:\s+'?(\w+)'?", line)
            if param_match:
                param = param_match.group(1)
                if param not in result.injectable_params:
                    result.injectable_params.append(param)

            # 检测数据库列表
            if re.match(r'^\[\*\]\s+\w+', line):
                db_name = line.replace("[*]", "").strip()
                if db_name and db_name not in result.databases:
                    result.databases.append(db_name)

        return result

    @staticmethod
    def parse_whatweb(output: str, target: str = "") -> WhatwebResult:
        """
        解析whatweb输出

        格式:
        http://target [200 OK] Apache[2.4.41], PHP[7.4.3], WordPress[5.7]
        """
        result = WhatwebResult(target=target, raw_output=output)

        if not output:
            return result

        # whatweb输出用逗号分隔技术
        # 格式: TechName[Version] 或 TechName
        tech_pattern = re.compile(r'(\w[\w\s.-]*?)(?:\[([^\]]*)\])?(?:,|$)')

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            for match in tech_pattern.finditer(line):
                name = match.group(1).strip()
                version = match.group(2) or ""

                if not name or name in ("200 OK", "301", "302", "403", "404"):
                    continue

                # 分类
                name_lower = name.lower()
                category = "other"
                if name_lower in ("apache", "nginx", "iis", "lighttpd", "litespeed"):
                    category = "server"
                    result.server = f"{name} {version}".strip()
                elif name_lower in ("php", "python", "java", "asp.net", "ruby", "perl", "node.js"):
                    category = "language"
                    result.language = name
                elif name_lower in ("wordpress", "joomla", "drupal", "magento",
                                     "shopify", "typo3", "mediawiki"):
                    category = "cms"
                    result.cms = name
                elif name_lower in ("django", "rails", "laravel", "spring",
                                     "flask", "express", "angular", "react", "vue"):
                    category = "framework"
                    result.framework = name
                elif name_lower in ("jquery", "bootstrap", "modernizr"):
                    category = "js-lib"

                tech = TechInfo(name=name, version=version, category=category)
                result.technologies.append(tech)

        return result

    @staticmethod
    def parse_wafw00f(output: str, target: str = "") -> WafResult:
        """
        解析wafw00f输出

        格式:
        [*] The site http://target is behind Cloudflare (Cloudflare Inc.)
        [*] No WAF detected by the generic detection
        """
        result = WafResult(target=target, raw_output=output)

        if not output:
            return result

        for line in output.split("\n"):
            line = line.strip()

            if "is behind" in line:
                result.has_waf = True
                waf_match = re.search(r'is behind (.+?)(?:\s*\(|$)', line)
                if waf_match:
                    result.waf_name = waf_match.group(1).strip()
            elif "No WAF" in line or "no WAF" in line:
                result.has_waf = False

        return result

    @staticmethod
    def auto_parse(tool_name: str, output: str, target: str = ""):
        """根据工具名自动选择解析器"""
        parsers = {
            "nmap": ResultParser.parse_nmap,
            "masscan": ResultParser.parse_masscan,
            "gobuster": ResultParser.parse_gobuster,
            "dirb": ResultParser.parse_gobuster,
            "ffuf": ResultParser.parse_gobuster,
            "feroxbuster": ResultParser.parse_gobuster,
            "nuclei": ResultParser.parse_nuclei,
            "sqlmap": ResultParser.parse_sqlmap,
            "whatweb": ResultParser.parse_whatweb,
            "wafw00f": ResultParser.parse_wafw00f,
        }

        parser = parsers.get(tool_name)
        if parser:
            return parser(output, target)
        return None


# ============================================================
# 智能参数构建器 - 基于解析结果为下一个工具构建最优参数
# ============================================================

class SmartParamsBuilder:
    """基于前序工具结果，为后续工具构建最优参数"""

    @staticmethod
    def build_gobuster_params(nmap_result: NmapResult, base_target: str) -> Optional[Dict]:
        """根据nmap结果构建gobuster参数"""
        if not nmap_result.has_web_service:
            return None

        urls = nmap_result.web_urls
        if not urls:
            return None

        return {
            "url": urls[0],  # 使用第一个web URL
            "mode": "dir",
            "additional_args": "-q --no-error -t 30",
        }

    @staticmethod
    def build_sqlmap_params(gobuster_result: GobusterResult,
                            waf_result: Optional[WafResult] = None,
                            base_target: str = "") -> Optional[Dict]:
        """根据目录扫描和WAF检测构建sqlmap参数"""
        # 找有参数的页面
        dynamic_paths = [p.path for p in gobuster_result.paths
                         if p.status_code == 200 and
                         any(ext in p.path for ext in (".php", ".asp", ".jsp", ".do", ".action"))]

        if not dynamic_paths:
            return None

        target_url = f"{base_target.rstrip('/')}{dynamic_paths[0]}"

        args = "--batch --random-agent --level 3 --risk 2"

        # WAF绕过参数
        if waf_result and waf_result.has_waf:
            waf_name = waf_result.waf_name.lower()
            if "cloudflare" in waf_name:
                args += " --tamper=between,space2comment,randomcase"
            elif "modsecurity" in waf_name:
                args += " --tamper=modsecurityzeroversioned,space2mysqlblank"
            elif "akamai" in waf_name:
                args += " --tamper=charunicodeencode,space2plus"
            else:
                args += " --tamper=space2comment,between"

        return {
            "url": target_url,
            "additional_args": args,
        }

    @staticmethod
    def build_nuclei_params(nmap_result: NmapResult, base_target: str) -> Optional[Dict]:
        """根据nmap结果构建nuclei参数"""
        urls = nmap_result.web_urls
        if not urls:
            return None

        # 根据发现的服务选择模板
        templates = []
        for port in nmap_result.ports:
            if port.state != "open":
                continue
            if port.service in ("http", "https"):
                templates.extend(["http/cves/", "http/misconfiguration/"])
            if port.product:
                product_lower = port.product.lower()
                if "apache" in product_lower:
                    templates.append("http/cves/apache/")
                if "nginx" in product_lower:
                    templates.append("http/cves/nginx/")
                if "iis" in product_lower:
                    templates.append("http/cves/iis/")

        template_arg = ",".join(set(templates)) if templates else ""

        return {
            "target": urls[0],
            "templates": template_arg,
            "severity": "critical,high,medium",
        }

    @staticmethod
    def build_wpscan_params(whatweb_result: WhatwebResult,
                            base_target: str) -> Optional[Dict]:
        """如果检测到WordPress，构建wpscan参数"""
        if not whatweb_result.is_wordpress:
            return None

        return {
            "target": base_target,
            "additional_args": "--enumerate vp,vt,u --detection-mode aggressive",
        }

    @staticmethod
    def choose_wordlist(whatweb_result: Optional[WhatwebResult] = None) -> str:
        """根据技术栈选择最佳字典"""
        if not whatweb_result:
            return "/usr/share/wordlists/dirb/common.txt"

        if whatweb_result.is_wordpress:
            return "/usr/share/wordlists/wfuzz/general/common.txt"

        if whatweb_result.is_php:
            return "/usr/share/wordlists/dirb/common.txt"

        # 默认字典
        return "/usr/share/wordlists/dirb/common.txt"

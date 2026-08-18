---
name: ioc-management
description: >
  IOC（妥协指标）生命周期管理完整手册：覆盖 IOC 提取（恶意软件样本→哈希/IP/域名/URL）、
  自动化富化（VirusTotal/Shodan/URLscan/PassiveTotal）、OpenCTI 平台集成、
  IOC 去标识化（Defanging）与安全共享、IP 信誉分析、恶意 URL 分析、
  证书透明度日志钓鱼检测、Typosquatting 域名检测（DNSTwist）、
  IOC 老化/退役、检测规则自动生成（Sigma/Snort/YARA）。
  Part A 攻击视角：红队 IOC 对抗（如何减少指标暴露）。Part B 防御视角：全流程 IOC 管理。
domain: cybersecurity
subdomain: threat-intelligence
tags: [IOC, indicators-of-compromise, enrichment, OpenCTI, defanging, IP-reputation, URLscan, certificate-transparency, typosquatting, DNSTwist, Sigma, YARA, Snort, VT, Shodan]
version: 2.0.0
---

# IOC 管理与富化 — 完整攻防手册

## 适用场景

**适用：** 从恶意样本/日志中提取 IOC 并进行富化分析；构建自动化 IOC 管道（收集→处理→富化→分发→退役）；检测 Typosquatting/钓鱼域名；证书透明度日志监控。
**不适用：** 威胁狩猎（参考 threat-hunting）；情报平台建设（参考 threat-intel-platform）；恶意软件深度分析（参考 malware-analysis-static）。

## 前置条件

- 恶意样本或日志数据
- API 密钥：VirusTotal、Shodan、URLscan.io（免费层即可）
- Python 3.10+
- OpenCTI 或 MISP 实例（可选，用于富化管道）

---

## Part A：攻击视角 — IOC 对抗

### 1. 红队如何减少 IOC 暴露

```
IOC 最小化策略：

网络层：
  - 使用 CDN/云服务中转 C2（IP 不直接暴露）
  - 域名使用 Whois 隐私保护 + 短生命周期
  - 快速轮换 C2 基础设施（每次行动后更换）
  - 使用 DGA（域名生成算法）替代固定域名
  - 使用合法 Web 服务（Slack/GitHub/Telegram）作为 C2

文件层：
  - 使用无文件攻击（不落地文件）
  - 动态生成恶意文档（模板化，每次哈希不同）
  - 代码混淆/加密（增加静态分析难度）
  - 使用合法工具（LOLBins）避免自定义恶意软件

主机层：
  - 内存中执行（不写入磁盘）
  - 清理事件日志（T1070.001）
  - 清除 Prefetch/Amcache 痕迹
  - 使用反取证技术（T1070.004）
```

---

## Part B：防御视角 — IOC 全生命周期管理

### 2. IOC 提取

```python
# ioc_extractor.py — 从多种来源提取 IOC
import re
from dataclasses import dataclass
from typing import List

@dataclass
class IOC:
    type: str       # ipv4, ipv6, domain, url, sha256, sha1, md5, email
    value: str
    source: str
    context: str = ""

class IOCExtractor:
    """从文本/文件中提取 IOC"""
    
    PATTERNS = {
        "ipv4": re.compile(
            r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
        ),
        "ipv6": re.compile(
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        ),
        "domain": re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+'
            r'[a-zA-Z]{2,}\b'
        ),
        "url": re.compile(
            r'https?://[^\s<>"\']+[^\s.,;:!?)]'
        ),
        "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
        "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
        "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
        "email": re.compile(
            r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        ),
        "cve": re.compile(r'CVE-\d{4}-\d{4,}'),
        "c2_path": re.compile(r'\b/[a-zA-Z0-9_\-/.]{4,}(?:\.(?:php|asp|jsp|cgi|py))?\b'),
    }
    
    # 排除白名单（减少误报）
    WHITELIST_DOMAINS = {
        "google.com", "microsoft.com", "apple.com", "amazon.com",
        "github.com", "cloudflare.com", "akamai.com",
    }
    
    def extract_from_text(self, text, source="unknown"):
        """从文本中提取所有 IOC"""
        iocs = []
        seen = set()
        
        # 按优先级提取（URL 优先于 Domain，Hash 优先于通用字符串）
        for ioc_type in ["url", "sha256", "sha1", "md5", "ipv6", "ipv4", "email", "cve", "domain"]:
            pattern = self.PATTERNS[ioc_type]
            for match in pattern.finditer(text):
                value = match.group(0).rstrip(".,;:)]}>")
                
                # 去重
                key = (ioc_type, value.lower())
                if key in seen:
                    continue
                seen.add(key)
                
                # 域名白名单过滤
                if ioc_type == "domain":
                    base = ".".join(value.split(".")[-2:]).lower()
                    if base in self.WHITELIST_DOMAINS:
                        continue
                
                # IP 私有地址过滤
                if ioc_type == "ipv4" and self._is_private_ip(value):
                    continue
                
                iocs.append(IOC(type=ioc_type, value=value, source=source))
        
        return iocs
    
    def extract_from_pe(self, pe_path):
        """从 PE 文件提取 IOC（导入表、字符串、资源）"""
        iocs = []
        try:
            import pefile
            pe = pefile.PE(pe_path)
            
            # 文件哈希
            import hashlib
            with open(pe_path, "rb") as f:
                data = f.read()
            iocs.append(IOC("sha256", hashlib.sha256(data).hexdigest(), pe_path))
            iocs.append(IOC("md5", hashlib.md5(data).hexdigest(), pe_path))
            
            # 从节区名称提取
            for section in pe.sections:
                name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
                if name and len(name) > 2:
                    pass  # 节区名称可作为特征
            
            # 从导入表提取
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore")
                    # 可疑 DLL 导入
                    suspicious_dlls = ["ws2_32.dll", "wininet.dll", "winhttp.dll", 
                                     "advapi32.dll", "crypt32.dll"]
                    if dll_name.lower() in suspicious_dlls:
                        for imp in entry.imports:
                            if imp.name:
                                func = imp.name.decode("utf-8", errors="ignore")
                                # 记录可疑 API 调用
                                suspicious_apis = [
                                    "InternetOpen", "HttpSendRequest", "URLDownloadToFile",
                                    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
                                    "RegSetValueEx", "CryptEncrypt",
                                ]
                                if func in suspicious_apis:
                                    iocs.append(IOC("api_call", f"{dll_name}!{func}", pe_path))
            
            # 从资源节提取嵌入的域名/IP
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                # 提取资源中的字符串
                pass
            
            pe.close()
        except ImportError:
            print("[!] pefile not installed: pip install pefile")
        
        # 从嵌入字符串提取
        try:
            strings = self._extract_strings(pe_path)
            text_iocs = self.extract_from_text(strings, f"{pe_path}:strings")
            iocs.extend(text_iocs)
        except Exception:
            pass
        
        return iocs
    
    def _extract_strings(self, file_path, min_length=4):
        """提取文件中的 ASCII/Unicode 字符串"""
        with open(file_path, "rb") as f:
            data = f.read()
        
        # ASCII strings
        ascii_strings = re.findall(rb'[\x20-\x7e]{%d,}' % min_length, data)
        # Unicode strings (UTF-16LE)
        unicode_strings = re.findall(
            rb'(?:[\x20-\x7e]\x00){%d,}' % min_length, data)
        
        all_strings = []
        for s in ascii_strings:
            all_strings.append(s.decode("ascii", errors="ignore"))
        for s in unicode_strings:
            all_strings.append(s.decode("utf-16le", errors="ignore"))
        
        return "\n".join(all_strings)
    
    def _is_private_ip(self, ip):
        """检查是否为私有 IP"""
        parts = [int(p) for p in ip.split(".")]
        if parts[0] == 10: return True
        if parts[0] == 172 and 16 <= parts[1] <= 31: return True
        if parts[0] == 192 and parts[1] == 168: return True
        if parts[0] == 127: return True
        return False
```

### 3. 自动化富化管道

```python
# ioc_enricher.py — IOC 自动化富化
import requests
import json
from typing import Dict, List

class IOCEnricher:
    """多源 IOC 富化"""
    
    def __init__(self, vt_api_key="", shodan_api_key="", 
                 urlscan_api_key="", passivetotal_user="", passivetotal_key=""):
        self.vt_key = vt_api_key
        self.shodan_key = shodan_api_key
        self.urlscan_key = urlscan_api_key
        self.pt_user = passivetotal_user
        self.pt_key = passivetotal_key
    
    def enrich(self, ioc: dict) -> dict:
        """根据 IOC 类型选择富化方法"""
        enrichers = {
            "ipv4": self._enrich_ip,
            "ipv6": self._enrich_ip,
            "domain": self._enrich_domain,
            "url": self._enrich_url,
            "sha256": self._enrich_hash,
            "sha1": self._enrich_hash,
            "md5": self._enrich_hash,
        }
        
        enricher = enrichers.get(ioc["type"])
        if enricher:
            enriched = enricher(ioc["value"])
            ioc.update(enriched)
        
        return ioc
    
    def _enrich_ip(self, ip):
        """IP 地址富化"""
        result = {"enrichment": {}}
        
        # Shodan
        if self.shodan_key:
            try:
                resp = requests.get(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": self.shodan_key},
                    timeout=10
                )
                if resp.status_code == 200:
                    data = resp.json()
                    result["enrichment"]["shodan"] = {
                        "org": data.get("org", ""),
                        "isp": data.get("isp", ""),
                        "country": data.get("country_name", ""),
                        "city": data.get("city", ""),
                        "ports": data.get("ports", []),
                        "hostnames": data.get("hostnames", []),
                        "last_update": data.get("last_update", ""),
                    }
            except Exception:
                result["enrichment"]["shodan"] = {"error": "lookup_failed"}
        
        # VirusTotal
        if self.vt_key:
            try:
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": self.vt_key},
                    timeout=10
                )
                if resp.status_code == 200:
                    data = resp.json()["data"]["attributes"]
                    result["enrichment"]["virustotal"] = {
                        "reputation": data.get("reputation", 0),
                        "total_votes": data.get("total_votes", {}),
                        "continent": data.get("continent", ""),
                        "country": data.get("country", ""),
                        "as_owner": data.get("as_owner", ""),
                        "network": data.get("network", ""),
                    }
            except Exception:
                result["enrichment"]["virustotal"] = {"error": "lookup_failed"}
        
        return result
    
    def _enrich_domain(self, domain):
        """域名富化"""
        result = {"enrichment": {}}
        
        # VirusTotal
        if self.vt_key:
            try:
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": self.vt_key},
                    timeout=10
                )
                if resp.status_code == 200:
                    data = resp.json()["data"]["attributes"]
                    result["enrichment"]["virustotal"] = {
                        "reputation": data.get("reputation", 0),
                        "total_votes": data.get("total_votes", {}),
                        "creation_date": data.get("creation_date", ""),
                        "whois": data.get("whois", "")[:500],
                        "last_dns_records": data.get("last_dns_records", []),
                    }
            except Exception:
                result["enrichment"]["virustotal"] = {"error": "lookup_failed"}
        
        return result
    
    def _enrich_hash(self, file_hash):
        """文件哈希富化"""
        result = {"enrichment": {}}
        
        if self.vt_key:
            try:
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers={"x-apikey": self.vt_key},
                    timeout=10
                )
                if resp.status_code == 200:
                    data = resp.json()["data"]["attributes"]
                    stats = data.get("last_analysis_stats", {})
                    result["enrichment"]["virustotal"] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "undetected": stats.get("undetected", 0),
                        "file_type": data.get("type_description", ""),
                        "size": data.get("size", 0),
                        "names": data.get("meaningful_name", ""),
                        "tags": data.get("tags", [])[:10],
                        "trid": data.get("trid", [])[:5],
                    }
            except Exception:
                result["enrichment"]["virustotal"] = {"error": "lookup_failed"}
        
        return result
    
    def _enrich_url(self, url):
        """URL 富化"""
        result = {"enrichment": {}}
        
        if self.urlscan_key:
            try:
                resp = requests.post(
                    "https://urlscan.io/api/v1/scan/",
                    headers={"API-Key": self.urlscan_key},
                    json={"url": url, "visibility": "public"},
                    timeout=10
                )
                if resp.status_code == 200:
                    result["enrichment"]["urlscan"] = {
                        "scan_id": resp.json().get("uuid", ""),
                        "scan_url": resp.json().get("result", ""),
                    }
            except Exception:
                result["enrichment"]["urlscan"] = {"error": "submission_failed"}
        
        return result
```

### 4. IOC 去标识化（Defanging）

```python
# ioc_defanger.py — IOC 去标识化与还原
class IOCDefanger:
    """IOC 去标识化（用于安全共享）与还原"""
    
    @staticmethod
    def defang(ioc_value, ioc_type="auto"):
        """将 IOC 去标识化，使其不可点击"""
        value = ioc_value
        
        # IP 地址
        value = value.replace(".", "[.]")
        
        # HTTP/HTTPS URL
        value = value.replace("http://", "hxxp://")
        value = value.replace("https://", "hxxps://")
        
        # @ 符号
        value = value.replace("@", "[AT]")
        
        # 域名中的点
        if "@" not in ioc_value and "://" not in ioc_value:
            # 已经在上面替换了，这里不重复
            pass
        
        return value
    
    @staticmethod
    def refang(defanged_value):
        """将去标识化的 IOC 还原"""
        value = defanged_value
        
        # 还原 IP
        value = value.replace("[.]", ".")
        value = value.replace("(.)", ".")
        value = value.replace(" . ", ".")
        value = value.replace("[dot]", ".")
        value = value.replace("(dot)", ".")
        
        # 还原 URL
        value = value.replace("hxxp://", "http://")
        value = value.replace("hxxps://", "https://")
        value = value.replace("hxtp://", "http://")
        value = value.replace("ftp://", "ftp://")
        
        # 还原邮箱
        value = value.replace("[AT]", "@")
        value = value.replace("(AT)", "@")
        value = value.replace("[at]", "@")
        value = value.replace("(at)", "@")
        value = value.replace(" @ ", "@")
        
        return value
    
    @staticmethod
    def defang_text(text):
        """批量去标识化文本中的所有 IOC"""
        extractor = IOCExtractor()
        iocs = extractor.extract_from_text(text)
        
        result = text
        for ioc in iocs:
            defanged = IOCDefanger.defang(ioc.value, ioc.type)
            result = result.replace(ioc.value, defanged)
        
        return result
```

### 5. 证书透明度日志钓鱼检测

```python
# ct_log_monitor.py — 证书透明度日志监控
import requests
from datetime import datetime, timedelta

class CTLogMonitor:
    """监控证书透明度日志查找钓鱼域名"""
    
    def __init__(self, target_domains):
        self.target_domains = target_domains  # 要保护的域名列表
    
    def check_crtsh(self, domain):
        """通过 crt.sh 查询证书透明度日志"""
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=30
        )
        
        if resp.status_code != 200:
            return []
        
        results = []
        seen = set()
        
        for entry in resp.json():
            name = entry.get("name_value", "")
            for n in name.split("\n"):
                n = n.lower().strip()
                if n and n not in seen:
                    seen.add(n)
                    results.append({
                        "domain": n,
                        "issuer": entry.get("issuer_name", ""),
                        "not_before": entry.get("not_before", ""),
                        "not_after": entry.get("not_after", ""),
                        "serial": entry.get("serial_number", ""),
                    })
        
        return results
    
    def detect_phishing_domains(self, lookback_days=7):
        """检测疑似钓鱼域名"""
        suspicious = []
        
        for target in self.target_domains:
            certs = self.check_crtsh(target)
            
            for cert in certs:
                domain = cert["domain"]
                
                # 跳过合法子域名
                if domain == target or domain.endswith(f".{target}"):
                    continue
                
                # 检测钓鱼特征
                phishing_indicators = []
                
                # 1. 目标品牌名 + 其他词
                brand = target.split(".")[0]  # 如 "paypal"
                if brand in domain:
                    parts = domain.split(".")
                    for part in parts:
                        if part != brand and len(part) > 2:
                            phishing_indicators.append(f"brand+word({part})")
                
                # 2. 连字符化
                if f"-{brand}-" in domain or f"{brand}-" in domain:
                    phishing_indicators.append("hyphenated")
                
                # 3. 数字替换
                leet_map = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s"}
                for num, letter in leet_map.items():
                    if num in domain and letter in brand:
                        phishing_indicators.append(f"leet_sub({num}→{letter})")
                        break
                
                # 4. 新注册（7天内）
                try:
                    not_before = cert["not_before"]
                    if isinstance(not_before, str):
                        not_before = datetime.fromisoformat(not_before.replace("Z", ""))
                    if (datetime.utcnow() - not_before).days <= lookback_days:
                        phishing_indicators.append("newly_registered")
                except:
                    pass
                
                # 5. Let's Encrypt（钓鱼常用免费证书）
                if "Let's Encrypt" in cert.get("issuer", ""):
                    phishing_indicators.append("free_certificate")
                
                if phishing_indicators:
                    suspicious.append({
                        "domain": domain,
                        "target": target,
                        "indicators": phishing_indicators,
                        "cert": cert,
                        "risk": "high" if len(phishing_indicators) >= 3 else "medium",
                    })
        
        return sorted(suspicious, key=lambda x: len(x["indicators"]), reverse=True)
```

### 6. Typosquatting 检测

```python
# typosquatting_detector.py — Typosquatting 域名检测
class TyposquattingDetector:
    """检测 Typosquatting 域名"""
    
    def __init__(self, target_domains):
        self.targets = target_domains
    
    def generate_typosquatting_variants(self, domain):
        """生成可能的 Typosquatting 变体"""
        variants = set()
        parts = domain.split(".")
        name = parts[0]
        tld = ".".join(parts[1:])
        
        # 1. 字符遗漏
        for i in range(len(name)):
            variants.add(name[:i] + name[i+1:] + "." + tld)
        
        # 2. 字符交换
        for i in range(len(name) - 1):
            swapped = name[:i] + name[i+1] + name[i] + name[i+2:]
            variants.add(swapped + "." + tld)
        
        # 3. 字符替换（键盘邻近键）
        keyboard_adj = {
            'a': 'sq', 'b': 'vn', 'c': 'xv', 'd': 'sf', 'e': 'wr',
            'f': 'dg', 'g': 'fh', 'h': 'gj', 'i': 'uo', 'j': 'hk',
            'k': 'jl', 'l': 'k', 'm': 'n', 'n': 'bm', 'o': 'ip',
            'p': 'o', 'q': 'w', 'r': 'et', 's': 'ad', 't': 'ry',
            'u': 'yi', 'v': 'cb', 'w': 'qe', 'x': 'zc', 'y': 'tu',
            'z': 'x',
        }
        for i, char in enumerate(name):
            if char.lower() in keyboard_adj:
                for adj in keyboard_adj[char.lower()]:
                    variants.add(name[:i] + adj + name[i+1:] + "." + tld)
        
        # 4. 字符插入
        for i in range(ord('a'), ord('z') + 1):
            for pos in range(len(name) + 1):
                variants.add(name[:pos] + chr(i) + name[pos:] + "." + tld)
        
        # 5. 连字符插入
        for i in range(1, len(name)):
            variants.add(name[:i] + "-" + name[i:] + "." + tld)
        
        # 6. 子域名前缀
        prefixes = ["www", "mail", "secure", "login", "account", "verify", "update"]
        for prefix in prefixes:
            variants.add(f"{prefix}-{name}.{tld}")
            variants.add(f"{prefix}.{domain}")
        
        # 7. TLD 替换
        alt_tlds = ["com", "net", "org", "io", "co", "info", "biz"]
        for alt in alt_tlds:
            if alt != tld:
                variants.add(f"{name}.{alt}")
        
        return variants
    
    def check_variants_registered(self, variants):
        """检查变体是否已注册（批量 DNS 查询）"""
        import socket
        
        registered = []
        for domain in variants:
            try:
                socket.getaddrinfo(domain, None)
                registered.append(domain)
            except socket.gaierror:
                pass  # 未注册
        
        return registered
    
    def run_dnstwist_style(self, domain):
        """运行类似 DNSTwist 的完整检测"""
        variants = self.generate_typosquatting_variants(domain)
        registered = self.check_variants_registered(variants)
        
        return {
            "target": domain,
            "variants_generated": len(variants),
            "registered_squats": registered,
            "risk": "HIGH" if len(registered) > 5 else "MEDIUM" if registered else "LOW",
        }

# DNSTwist 命令行使用
# pip install dnstwist
# dnstwist --registered example.com
# dnstwist --format json example.com > squats.json
```

### 7. 检测规则自动生成

```python
# ioc_to_detection.py — 从 IOC 自动生成检测规则
class IOCDetectionGenerator:
    """从 IOC 列表生成多种格式的检测规则"""
    
    def generate_sigma(self, iocs, title="Threat Intel IOC Match"):
        """生成 Sigma 规则"""
        ips = [i["value"] for i in iocs if i["type"] in ("ipv4", "ipv6")]
        domains = [i["value"] for i in iocs if i["type"] == "domain"]
        hashes = [i["value"] for i in iocs if i["type"] in ("sha256", "sha1", "md5")]
        
        rules = []
        
        if ips:
            rules.append({
                "title": f"{title} - Network Connection",
                "logsource": {"category": "network_connection"},
                "detection": {
                    "selection": {
                        "DestinationIp|cidr": ips[:100],
                    },
                    "condition": "selection"
                },
                "level": "high",
            })
        
        if domains:
            rules.append({
                "title": f"{title} - DNS Query",
                "logsource": {"category": "dns_query"},
                "detection": {
                    "selection": {
                        "QueryName|endswith": domains[:100],
                    },
                    "condition": "selection"
                },
                "level": "high",
            })
        
        if hashes:
            rules.append({
                "title": f"{title} - File Hash",
                "logsource": {"category": "file_event"},
                "detection": {
                    "selection": {
                        "Hashes|contains": hashes[:50],
                    },
                    "condition": "selection"
                },
                "level": "critical",
            })
        
        return rules
    
    def generate_snort(self, iocs):
        """生成 Snort 规则"""
        rules = []
        for ioc in iocs:
            if ioc["type"] == "ipv4":
                rules.append(
                    f'alert ip any any -> {ioc["value"]} any '
                    f'(msg:"ET TI - Connection to known malicious IP {ioc["value"]}"; '
                    f'sid:{hash(ioc["value"]) % 10000000 + 1000000}; rev:1;)')
            elif ioc["type"] == "domain":
                rules.append(
                    f'alert dns any any -> any any '
                    f'(msg:"ET TI - DNS query for known malicious domain {ioc["value"]}"; '
                    f'dns.query; content:"{ioc["value"]}"; nocase; '
                    f'sid:{hash(ioc["value"]) % 10000000 + 2000000}; rev:1;)')
        return rules
    
    def generate_yara(self, iocs):
        """生成 YARA 规则（文件哈希匹配）"""
        hashes = [i for i in iocs if i["type"] in ("sha256", "sha1", "md5")]
        if not hashes:
            return ""
        
        lines = [
            'rule threat_intel_ioc_match {',
            '  meta:',
            '    description = "Auto-generated from threat intel IOC feed"',
            '    date = "' + datetime.now().strftime("%Y-%m-%d") + '"',
            '  condition:',
            '    any of ($hash*)',
        ]
        
        for i, h in enumerate(hashes):
            hash_type = {"sha256": "hash.sha256", "sha1": "hash.sha1", "md5": "hash.md5"}[h["type"]]
            lines.append(f'    $hash{i} = {hash_type}("{h["value"]}")')
        
        lines.append("}")
        return "\n".join(lines)
```

---

## 速查表

### IOC 类型与富化源矩阵

| IOC 类型 | VT | Shodan | URLscan | PassiveTotal | CT Logs | DNSTwist |
|---------|-----|--------|---------|-------------|---------|----------|
| IPv4/IPv6 | ✅ | ✅ | - | ✅ | - | - |
| Domain | ✅ | - | - | ✅ | ✅ | ✅ |
| URL | ✅ | - | ✅ | - | - | - |
| SHA256/SHA1/MD5 | ✅ | - | - | - | - | - |
| Email | - | - | - | ✅ | - | - |
| CVE | - | ✅ | - | - | - | - |

### IOC 老化时间建议

| IOC 类型 | 有效期 | 原因 |
|---------|--------|------|
| IP 地址 | 30 天 | IP 轮换快，易误报 |
| Domain | 90 天 | 域名相对稳定 |
| URL | 30 天 | 页面可能被移除 |
| File Hash | 365 天 | 文件内容不变 |
| Email | 60 天 | 邮箱可能被关闭 |
| SSL 证书 | 90 天 | 证书有过期时间 |

### IOC 去标识化格式对照

| 原始 | 去标识化 | 用途 |
|------|---------|------|
| `192.168.1.1` | `192.168.1[.]1` | 防止点击 |
| `http://evil.com` | `hxxp://evil.com` | 防止浏览器解析 |
| `user@evil.com` | `user[AT]evil.com` | 防止邮件抓取 |
| `evil.com` | `evil[.]com` | 通用去标识化 |

---

## MITRE ATT&CK 映射

| 战术 | 技术 | IOC 管理应用 |
|------|------|-------------|
| Command & Control | T1071 | C2 IP/域名提取与监测 |
| Initial Access | T1566 | 钓鱼域名/URL 采集 |
| Resource Development | T1583 | 恶意基础设施 CT 日志监控 |
| Defense Evasion | T1027 | 混淆样本哈希提取 |
| Persistence | T1547 | 持久化机制 IOC 收集 |
| Exfiltration | T1048 | 数据外泄目标 IOC 生成 |

---

## C. 补充章节（2025-2026 联网复核）

### C.1 VirusTotal → Google Threat Intelligence (GTI) 过渡

```
重大变更（2025-2026）：
- VirusTotal Enterprise 正过渡为 Google Threat Intelligence (GTI)
- GTI 融合 Google + Mandiant + VirusTotal 能力
- API v2 已弃用，v3 为唯一版本
- 新增 gti_assessment 评分字段（替代纯引擎计数）
- GTI-G YARA 规则跟踪相关漏洞
- 分类 IOC 威胁列表（Curated Threat Lists）
- 私有 URL 扫描增强
- Saved Searches 功能（2025.12）保存复用复杂查询
- 新逆向工程 API 端点：预分析反编译代码，高亮行为特征
- GTI Dev Kit（开源）：https://github.com/VirusTotal/gti-dev-kit

API 调用变更示例：
  # 旧 v3 端点仍兼容，但响应增加 GTI 字段
  GET /api/v3/ip_addresses/{ip}
  响应新增：gti_assessment.verdict, gti_assessment.confidence
  
  # 新增威胁行为者画像端点
  GET /api/v3/collections/{id}
  
  # 策划攻击活动报告
  GET /api/v3/ioc_streams
```

### C.2 OpenCTI 6.0+ 指标衰减规则（Score Decay）

```
OpenCTI 6.0 引入自动指标衰减：
- 可配置衰减规则：不同 IOC 类型使用不同衰减曲线
- 指数衰减函数：score(t) = base_score × e^(-decay_rate × t)
- 过期指标自动标记为 revoked
- 例外处理：持久恶意基础设施（如 APT C2）可设为不衰减
- PIR（优先情报需求）驱动 IOC 优先级
- 企业版：自动 Playbooks + AI 辅助分析

衰减规则配置示例（OpenCTI UI）：
  规则名称：IP_Address_Decay
  指标类型：IPv4-Addr
  衰减基数：100
  衰减因子：0.85（每30天衰减15%）
  撤销阈值：20（低于此分数标记 revoked）
  
  规则名称：File_Hash_Decay
  指标类型：File-SHA256
  衰减基数：100
  衰减因子：0.95（每90天衰减5%）
  撤销阈值：30

参考：https://filigran.io/blog/introducing-decay-rules-implementation-for-indicators-in-opencti/
```

### C.3 置信度衰减模型细化

```python
# ioc_decay_model.py — IOC 置信度衰减计算
import math
from datetime import datetime, timedelta

class IOCDecayModel:
    """基于 Netresec/OpenCTI 研究的 IOC 衰减模型"""
    
    # 不同类型的衰减参数
    DECAY_PROFILES = {
        "ipv4":     {"base": 80, "half_life_days": 14, "revoke_threshold": 20},
        "ipv6":     {"base": 80, "half_life_days": 14, "revoke_threshold": 20},
        "domain":   {"base": 90, "half_life_days": 45, "revoke_threshold": 25},
        "url":      {"base": 75, "half_life_days": 14, "revoke_threshold": 15},
        "sha256":   {"base": 95, "half_life_days": 180, "revoke_threshold": 30},
        "sha1":     {"base": 90, "half_life_days": 180, "revoke_threshold": 30},
        "md5":      {"base": 85, "half_life_days": 120, "revoke_threshold": 25},
        "email":    {"base": 70, "half_life_days": 30, "revoke_threshold": 15},
    }
    
    def calculate_score(self, ioc_type, observed_date, 
                        verification_count=0, is_apt=False, 
                        last_seen=None):
        """
        计算当前置信度分数
        
        参数:
          ioc_type: IOC 类型
          observed_date: 首次观测日期
          verification_count: 独立验证源数量（每源+5分）
          is_apt: APT 相关基础设施（不衰减标记）
          last_seen: 最后观测日期（如果有则用此计算）
        """
        profile = self.DECAY_PROFILES.get(ioc_type, 
                                           {"base": 70, "half_life_days": 30, 
                                            "revoke_threshold": 20})
        
        base_score = profile["base"] + min(verification_count * 5, 20)
        base_score = min(base_score, 100)
        
        # APT 持久基础设施不衰减
        if is_apt:
            return base_score
        
        # 使用 last_seen 或 observed_date
        reference_date = last_seen or observed_date
        days_elapsed = (datetime.utcnow() - reference_date).days
        
        # 指数衰减: score = base × 2^(-days/half_life)
        half_life = profile["half_life_days"]
        decayed_score = base_score * math.pow(2, -days_elapsed / half_life)
        
        return round(decayed_score, 1)
    
    def should_revoke(self, ioc_type, current_score):
        """判断是否应撤销此 IOC"""
        threshold = self.DECAY_PROFILES.get(ioc_type, {}).get("revoke_threshold", 20)
        return current_score <= threshold
    
    def batch_evaluate(self, iocs_with_dates):
        """批量评估 IOC 衰减状态"""
        results = []
        for item in iocs_with_dates:
            score = self.calculate_score(
                item["type"], item["observed_date"],
                item.get("verification_count", 0),
                item.get("is_apt", False),
                item.get("last_seen")
            )
            results.append({
                "ioc": item["value"],
                "type": item["type"],
                "current_score": score,
                "should_revoke": self.should_revoke(item["type"], score),
                "days_since_observed": (datetime.utcnow() - item["observed_date"]).days,
            })
        return sorted(results, key=lambda x: x["current_score"])
```

### C.4 AI/LLM 辅助 IOC 提取与富化

```
AI/LLM 在 IOC 管理中的关键应用（2025-2026）：

1. PRISM 基准（arXiv 2025）
   - 50 份真实威胁报告，1,791 个标记 IOC
   - 用于评估 LLM IOC 提取准确性
   - 论文：https://arxiv.org/html/2506.11325v2

2. SentinelOne Labs: 叙事→知识图谱
   - LLM 从非结构化报告中提取上下文富化情报
   - 构建 ATT&CK 映射的知识图谱
   - 比正则提取准确率提升 30-40%

3. AI 代理工作流（研究→调查→响应闭环）
   - 自动分类告警与 IOC 关联
   - LLM 生成 Sigma/YARA 规则
   - 自动威胁行为者画像

4. 微步 XGPT（国内首个双备案安全大模型）
   - 深度融合威胁情报
   - IOC 自动研判与拓线分析

5. MCP 协议 IOC 自动化
   - Model Context Protocol 集成 SIEM 事件关联
   - SOAR 集成自动化响应
```

```python
# llm_ioc_extractor.py — LLM 辅助 IOC 提取（基于 PRISM 方法论）
import json

class LLMIOCExtractor:
    """使用 LLM 从非结构化威胁报告中提取结构化 IOC"""
    
    EXTRACTION_PROMPT = """
    从以下威胁报告文本中提取所有 IOC（妥协指标）。
    对于每个 IOC，提供：
    1. type: ipv4|ipv6|domain|url|sha256|sha1|md5|email|cve|filename|mutex|registry
    2. value: IOC 值
    3. context: 上下文描述（该 IOC 的角色：C2、钓鱼、载荷、持久化等）
    4. confidence: high|medium|low
    5. mitre_tactic: 关联的 MITRE ATT&CK 战术（如有）
    6. threat_actor: 威胁行为者名称（如有）
    
    以 JSON 数组格式返回结果。
    
    报告文本：
    {report_text}
    """
    
    ENRICHMENT_PROMPT = """
    基于以下 IOC 信息，进行威胁情报研判：
    1. 关联的威胁行为者（APT 组织）
    2. 攻击目标行业/地域
    3. 使用的技术手段（MITRE ATT&CK）
    4. 关联的 CVE（如有）
    5. 缓解建议
    
    IOC: {ioc_json}
    上下文: {context}
    """
    
    def extract_from_report(self, report_text, llm_client):
        """从威胁报告提取结构化 IOC"""
        prompt = self.EXTRACTION_PROMPT.format(report_text=report_text)
        response = llm_client.generate(prompt)
        
        try:
            iocs = json.loads(response)
            return iocs
        except json.JSONDecodeError:
            return self._fallback_parse(response)
    
    def _fallback_parse(self, text):
        """LLM 输出不是合法 JSON 时的回退解析"""
        import re
        results = []
        # 尝试提取 JSON 块
        json_match = re.search(r'\[.*\]', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except:
                pass
        return results
```

### C.5 证书透明度日志迁移：RFC 6962 → Static CT API

```
重大变更（2025-2026）：

RFC 6962 日志淘汰时间线：
  - 2025-11-30: Let's Encrypt RFC 6962 日志设为只读
  - 全面转向 Static CT API（C2SP 规范）
  
Static CT API 核心变化：
  - 日志数据组织为静态、可缓存的 tiles（而非动态查询）
  - 支持大规模并行读取和 CDN 分发
  - 更高效的监控和审计
  
新工具/平台：
  1. Cloudflare Azul CT 日志
     - 基于 Static CT API 的下一代日志
     - https://blog.cloudflare.com/azul-certificate-transparency-log/
  
  2. MerkleMap.com
     - 新 CT 日志监控和搜索工具
  
  3. SpoofGuard (spoofguard.io)
     - 品牌保护的 CT 日志早期预警系统
     - 自动检测疑似冒充域名
  
  4. Apple CT 日志
     - 同时接受 RFC 6962 和 Static CT API
  
影响：
  - 所有依赖 crt.sh 的工具需评估兼容性
  - CT 日志钓鱼检测脚本需适配新 API
  - Static CT API 规范：https://github.com/C2SP/C2SP/blob/main/static-ct-api.md
```

### C.6 CACAO v2.0 + STIX 2.1 自动化响应标准

```
OASIS CACAO (Connected, Automated, and Cloud-Oriented Operations) v2.0：

核心概念：
  - 定义自动化网络安全 Playbook 的标准模式
  - 与 STIX 2.1 配合使用
  - 实现从情报共享到自动响应的全链路标准化
  - 支持组织间 Playbook 协作与共享

关键能力：
  1. Playbook 工作流定义（序列/并行/条件分支）
  2. 与 STIX 2.1 对象无缝集成
  3. 支持多种执行目标（SOAR/SIEM/防火墙/EDR）
  4. 可视化 Playbook 编辑器

工具：
  - CACAO Roaster：开源 Web 应用
    生成/解析/验证/可视化/执行 CACAO v2.0 Playbook
    https://github.com/opencybersecurityalliance/cacao-roaster

标准文档：
  - https://docs.oasis-open.org/cacao/security-playbooks/v2.0/
  
与 IOC 管理的集成：
  IOC 富化结果 → STIX 2.1 Bundle → CACAO Playbook 自动触发响应
  例如：检测到恶意 IP → 自动生成防火墙阻断规则 → 分发给边界设备
```

### C.7 IOC 富化源更新矩阵

```
新增/更新富化源（2025-2026）：

1. Google Threat Intelligence (GTI)
   - 替代 VirusTotal Enterprise
   - gti_assessment 评分 + Mandiant 情报
   - API: https://gtidocs.virustotal.com/

2. RST Cloud Noise Control
   - 与 OpenCTI 集成
   - 自动过滤噪音 IOC（如 CDN IP、云服务 IP）
   - IOC Lookup API 添加上下文

3. Silent Push
   - "未来攻击指标"（IOFA）概念
   - 攻击者基础设施预判视角
   - 比静态 IOC 误报更低
   - OpenCTI 集成已发布

4. ThreatFox (abuse.ch)
   - 广泛 IOC 类型共享（IPs/域名/哈希/URLs）
   - 免费开放 API

5. isMalicious.com
   - 5 亿+恶意 IP 和域名数据库
   - 支持批量查询

6. Spamhaus + abuse.ch 实时情报源
   - 商业实时恶意软件数据源
   - 直接集成到 SIEM/SOAR

7. Elastic TIP (Threat Intelligence Platform)
   - 实时搜索、分类、过滤 IOC
   - 与 Elastic Security 深度集成
```

### C.8 从 IOC 到 IOFA：指标演进

```
Silent Push 提出的指标类型演进：

IOC（妥协指标）→ IOA（攻击指标）→ IOFA（未来攻击指标）

IOC: 已知恶意，高误报，快速过期
  例：已知恶意 IP 1.2.3.4

IOA: 攻击行为模式，MITRE ATT&CK 映射
  例：观察到 PowerShell 下载+执行模式

IOFA: 攻击者基础设施预判
  例：新注册域名使用特定 NS 服务器集群 + Let's Encrypt
      + 相似页面模板 = 即将发起钓鱼攻击

IOFA 优势：
  1. 在攻击发生前预警
  2. 误报率远低于传统 IOC
  3. 不会过期（攻击者基础设施模式持续有效）
  4. 适合主动防御而非被动检测

实践意义：
  - CT 日志监控 → IOFA（证书模式预判）
  - DNS 行为分析 → IOFA（域名注册模式）
  - 指纹关联 → IOFA（基础设施聚类）
```

### C.9 中文社区精华参考

```
奇安信：
  - 2025 安全十大趋势：威胁情报运营深化发展
    https://www.qianxin.com/news/detail?news_id=13035
  - 能力图谱更新：新增 AI 辅助绕过分析
  - 集成 DeepSeek 大模型赋能威胁研判
  - 2025 漏洞态势报告：基于情报的漏洞优先级评估
    https://www.qianxin.com/news/detail?news_id=14507

微步在线：
  - NGTIP 下一代威胁情报平台
  - XGPT：国内首个通过中央网信办双备案的安全大模型
  - 深度融合威胁情报加速研判

360 威胁情报中心：
  - 持续追踪 APT 组织
  - HitlerBot 僵尸网络 IOC 分析
  - MuddyWater 钓鱼攻击 IOC 报告

阿里云：
  - 安全态势月报：海量云安全威胁情报驱动
  - 平均每天防御攻击数十亿次

腾讯云：
  - TIX 威胁情报中心
  - 赋能 SOC/NDR/CFW/主机安全等

先知社区（xz.aliyun.com）：
  - IOC 自动化提取与富化实践
  - 威胁情报共享标准落地
```

### C.10 防御升级路线图

```
P0（立即行动）：
  - 评估 VirusTotal → GTI 迁移时间表，更新 API 集成
  - 在 OpenCTI/MISP 中启用指标衰减规则
  - 更新 CT 日志监控脚本适配 Static CT API

P1（30天内）：
  - 部署 IOFA 概念到威胁狩猎流程
  - 集成 ThreatFox/Silent Push 等新富化源
  - 建立 IOC 置信度衰减自动化脚本

P2（90天内）：
  - 评估 CACAO v2.0 Playbook 标准集成
  - 部署 AI/LLM 辅助 IOC 提取管道
  - 实施网络上下文过滤减少误报

P3（持续改进）：
  - 定期评估 IOC 老化时间建议（每季度）
  - 跟踪 PRISM 基准评估提取准确性
  - 中国威胁情报产品评估（奇安信/微步/360/阿里云/腾讯云）
```

---

## 前置条件

1. **API 密钥**：VirusTotal/GTI（免费层 500 req/day）、Shodan（免费层有限）、URLscan.io（免费层）
2. **工具**：DNSTwist（pip install dnstwist）、crt.sh/MerkleMap（CT 日志查询）、YARA/Sigma 引擎
3. **平台**：OpenCTI 6.0+（含衰减规则）或 MISP 2.5+（含指标衰减）
4. **流程**：定义 IOC 采集→富化→评分→衰减→分发→退役的完整周期
5. **自动化**：建议 CI/CD 管道定时运行提取和富化脚本
6. **标准**：STIX 2.1 数据模型 + CACAO v2.0 响应 Playbook

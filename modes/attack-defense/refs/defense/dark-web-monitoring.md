---
name: dark-web-monitoring
description: >
  暗网与深网监控完整手册：覆盖暗网情报源（Tor 论坛、Paste 站点、Telegram 频道、
  黑市市场）的监控方法论、凭证泄露监测（Paste 站点扫描）、品牌冒充检测、
  数据泄露发现、暗网爬虫技术、OpSec 安全实践（隔离环境、匿名访问）。
  Part A 攻击视角：红队如何利用暗网情报。Part B 防御视角：建立暗网监控能力。
domain: cybersecurity
subdomain: threat-intelligence
tags: [dark-web, deep-web, credential-monitoring, paste-site, brand-protection, data-breach, Tor, OpSec, credential-leak, impersonation]
version: 2.0.0
---

# 暗网监控 — 完整攻防手册

## 适用场景

**适用：** 监控组织凭证是否泄露；检测品牌冒充/钓鱼域名；发现数据泄露在暗网的传播；跟踪特定威胁行为者在暗网的活动。
**不适用：** 主动渗透暗网市场（需要法律授权）；一般威胁狩猎（参考 threat-hunting）；IOC 管理（参考 ioc-management）。

## 前置条件

- Tor 浏览器或安全隔离环境
- 了解暗网结构（.onion、Telegram 频道、Pastebin 类站点）
- 品牌域名和已知凭证列表（用于匹配）
- 代理/VPN 用于匿名访问

---

## Part A：攻击视角 — 红队如何利用暗网

### 1. 暗网情报收集

```
红队暗网情报用途：

1. 目标组织信息收集
   - 在暗网搜索目标组织名称、域名
   - 查找已泄露的内部文档、网络拓扑
   - 发现员工凭证泄露

2. 工具与漏洞获取
   - 查找针对特定技术的利用工具
   - 获取 0-day 信息（监控 Exploit 论坛）
   - 购买/租用攻击基础设施

3. 社工素材
   - 收集已泄露的员工 PII
   - 获取组织内部通信记录
   - 了解组织安全产品的配置细节

红队 OpSec 注意事项：
  - 使用独立隔离的 VM/硬件
  - Tor + VPN 双层匿名
  - 不下载可执行文件（或仅在隔离沙箱中）
  - 不使用真实身份或与工作相关的账号
  - 记录所有操作以备审计
```

---

## Part B：防御视角 — 建立暗网监控能力

### 2. 暗网监控架构

```
┌─────────────────────────────────────────────────────┐
│              暗网监控架构                              │
│                                                     │
│  情报源层                                            │
│  ├ Tor 论坛/市场 (.onion)                           │
│  ├ Paste 站点 (PasteBin/GhostBin/Rentry)           │
│  ├ Telegram 频道 (黑产频道/数据泄露频道)              │
│  ├ IRC/Discord 频道                                 │
│  └ 商业暗网情报平台 (Flashpoint/DarkOwl)             │
│                                                     │
│  采集层（安全隔离环境）                                │
│  ├ Tor 代理 + 轮换身份                               │
│  ├ Telegram Bot/API                                 │
│  └ Paste 站点 RSS/API                               │
│                                                     │
│  处理层                                              │
│  ├ 正则匹配（域名/邮箱/凭证模式）                      │
│  ├ 实体识别（PII/凭证/品牌名）                        │
│  └ 去重与富化                                        │
│                                                     │
│  告警层                                              │
│  ├ 凭证泄露 → 重置密码 + MFA 推送                    │
│  ├ 品牌冒充 → 下架请求 + 法律行动                    │
│  └ 数据泄露 → IR 触发 + 损害评估                     │
└─────────────────────────────────────────────────────┘
```

### 3. Paste 站点凭证监控

```python
# paste_monitor.py — Paste 站点凭证泄露监控
import re
import requests
import json
from datetime import datetime

class PasteMonitor:
    """监控 Paste 站点的凭证泄露"""
    
    # 常见 Paste 站点
    PASTE_SOURCES = {
        "pastebin": "https://pastebin.com",
        "ghostbin": "https://ghostbin.com",
        "dpaste": "https://dpaste.org",
        "rentry": "https://rentry.co",
    }
    
    # 凭证匹配模式
    CREDENTIAL_PATTERNS = {
        "email_password": re.compile(
            r'[\w.+-]+@[\w-]+\.[\w.]+[:\|\s,;]+[\w!@#$%^&*()]{6,}',
            re.IGNORECASE
        ),
        "api_key": re.compile(
            r'(?:api[_-]?key|apikey|token|secret|bearer)\s*[=:]\s*["\']?[\w\-]{20,}["\']?',
            re.IGNORECASE
        ),
        "aws_key": re.compile(
            r'(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}',
        ),
        "private_key": re.compile(
            r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
        ),
        "db_connection": re.compile(
            r'(?:mysql|postgres|mongodb|redis)://[\w:]+@[\w.-]+:\d+',
            re.IGNORECASE
        ),
        "jwt_token": re.compile(
            r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*',
        ),
    }
    
    def __init__(self, monitored_domains=None, monitored_emails=None):
        self.monitored_domains = monitored_domains or []
        self.monitored_emails = monitored_emails or []
    
    def scan_paste_content(self, content, source_url=""):
        """扫描 Paste 内容中的凭证泄露"""
        findings = []
        
        # 检查每种凭证模式
        for cred_type, pattern in self.CREDENTIAL_PATTERNS.items():
            matches = pattern.findall(content)
            for match in matches:
                finding = {
                    "type": cred_type,
                    "value": match if isinstance(match, str) else match[0],
                    "source": source_url,
                    "timestamp": datetime.utcnow().isoformat(),
                    "matches_domain": False,
                    "matches_email": False,
                }
                
                # 检查是否匹配监控域名
                for domain in self.monitored_domains:
                    if domain.lower() in finding["value"].lower():
                        finding["matches_domain"] = True
                        finding["matched_domain"] = domain
                        break
                
                # 检查是否匹配监控邮箱
                for email in self.monitored_emails:
                    if email.lower() in content.lower():
                        finding["matches_email"] = True
                        finding["matched_email"] = email
                        break
                
                findings.append(finding)
        
        # 额外：检查是否包含监控域名
        for domain in self.monitored_domains:
            if domain.lower() in content.lower():
                domain_findings = re.findall(
                    rf'[\w.+-]+@{re.escape(domain)}[:\|\s,;]+\S+',
                    content, re.IGNORECASE
                )
                for cred in domain_findings:
                    findings.append({
                        "type": "domain_credential",
                        "value": cred,
                        "source": source_url,
                        "timestamp": datetime.utcnow().isoformat(),
                        "matches_domain": True,
                        "matched_domain": domain,
                    })
        
        return findings
    
    def monitor_pastebin_archive(self):
        """监控 Pastebin 公开归档"""
        findings = []
        
        try:
            resp = requests.get("https://pastebin.com/archive", timeout=15)
            if resp.status_code == 200:
                # 提取最近的 Paste ID
                paste_ids = re.findall(r'href="/(\w{8})"', resp.text)
                
                for pid in paste_ids[:20]:  # 限制请求数量
                    try:
                        raw = requests.get(
                            f"https://pastebin.com/raw/{pid}", timeout=10)
                        if raw.status_code == 200:
                            paste_findings = self.scan_paste_content(
                                raw.text, f"https://pastebin.com/{pid}")
                            findings.extend(paste_findings)
                    except Exception:
                        continue
        except Exception as e:
            print(f"[!] Pastebin monitoring failed: {e}")
        
        return findings
```

### 4. 品牌冒充检测

```python
# brand_monitor.py — 品牌冒充检测
class BrandMonitor:
    """检测品牌冒充（域名/社交媒体/App Store）"""
    
    def __init__(self, brand_names, brand_domains):
        self.brand_names = brand_names        # ["YourBrand", "YourProduct"]
        self.brand_domains = brand_domains    # ["yourbrand.com"]
    
    def check_domain_registrations(self):
        """检查新注册的疑似冒充域名"""
        all_suspicious = []
        
        for domain in self.brand_domains:
            # 使用 crt.sh 查找包含品牌名的证书
            try:
                resp = requests.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    timeout=30
                )
                if resp.status_code != 200:
                    continue
                
                for entry in resp.json():
                    name = entry.get("name_value", "").lower()
                    
                    # 排除合法域名
                    if name == domain or name.endswith(f".{domain}"):
                        continue
                    
                    # 检查冒充指标
                    for brand in self.brand_names:
                        if brand.lower() in name:
                            risk = self._assess_risk(name, brand)
                            if risk["score"] > 0:
                                all_suspicious.append({
                                    "domain": name,
                                    "brand": brand,
                                    "risk_score": risk["score"],
                                    "risk_factors": risk["factors"],
                                    "issuer": entry.get("issuer_name", ""),
                                    "not_before": entry.get("not_before", ""),
                                })
            except Exception:
                continue
        
        return sorted(all_suspicious, key=lambda x: x["risk_score"], reverse=True)
    
    def _assess_risk(self, domain, brand):
        """评估冒充风险"""
        factors = []
        score = 0
        
        # 包含登录/安全等关键词
        keywords = ["login", "secure", "account", "verify", "update", 
                    "password", "reset", "auth", "signin", "signup",
                    "wallet", "payment", "support", "help", "service"]
        for kw in keywords:
            if kw in domain:
                score += 20
                factors.append(f"suspicious_keyword({kw})")
                break
        
        # 使用免费证书
        # （在结果中检查 issuer）
        
        # 使用不常见 TLD
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", 
                          ".top", ".club", ".online", ".site", ".icu"]
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                score += 15
                factors.append(f"suspicious_tld({tld})")
                break
        
        # 品牌名 + 连字符
        if f"-{brand.lower()}-" in domain or f"{brand.lower()}-" in domain:
            score += 15
            factors.append("hyphenated_brand")
        
        # 品牌名 + 额外词
        parts = domain.split(".")[0].split("-")
        if len(parts) > 1:
            for part in parts:
                if part.lower() == brand.lower() and len(parts) > 1:
                    score += 10
                    factors.append("brand_with_extrawords")
                    break
        
        return {"score": min(score, 100), "factors": factors}
    
    def check_social_media(self, platform="twitter"):
        """检查社交媒体冒充（使用公开 API）"""
        results = []
        
        for brand in self.brand_names:
            # 使用平台搜索 API 查找冒充账号
            # 实际实现需要各平台 API 密钥
            pass
        
        return results
    
    def check_app_stores(self):
        """检查应用商店冒充"""
        results = []
        
        for brand in self.brand_names:
            # Google Play 搜索
            try:
                resp = requests.get(
                    "https://play.google.com/store/search",
                    params={"q": brand, "c": "apps"},
                    timeout=15
                )
                if resp.status_code == 200:
                    # 解析结果查找可疑应用
                    apps = re.findall(
                        r'data-peek-threshold="[^"]*"[^>]*>'
                        r'[^<]*<[^>]*title="([^"]*)"',
                        resp.text
                    )
                    for app_name in apps:
                        if brand.lower() in app_name.lower():
                            # 检查是否为官方应用
                            is_official = any(
                                d.split(".")[0] in app_name.lower()
                                for d in self.brand_domains
                            )
                            if not is_official:
                                results.append({
                                    "platform": "Google Play",
                                    "app_name": app_name,
                                    "brand": brand,
                                    "risk": "medium",
                                })
            except Exception:
                pass
        
        return results
```

### 5. 暗网论坛监控

```python
# darkweb_monitor.py — 暗网论坛监控（需 Tor 环境）
class DarkWebMonitor:
    """暗网论坛和市场的监控"""
    
    # Tor 代理配置
    TOR_PROXY = {
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050",
    }
    
    def __init__(self, monitored_keywords):
        self.keywords = monitored_keywords
    
    def check_tor_site(self, onion_url, timeout=30):
        """安全访问 .onion 站点"""
        try:
            import requests
            session = requests.Session()
            session.proxies = self.TOR_PROXY
            session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0"
            })
            
            resp = session.get(onion_url, timeout=timeout, verify=False)
            return resp.text
        except Exception as e:
            return f"[ERROR] {e}"
    
    def search_keyword_on_site(self, content, keywords=None):
        """在页面内容中搜索关键词"""
        if keywords is None:
            keywords = self.keywords
        
        matches = []
        content_lower = content.lower()
        
        for keyword in keywords:
            if keyword.lower() in content_lower:
                # 提取上下文
                idx = content_lower.index(keyword.lower())
                context_start = max(0, idx - 100)
                context_end = min(len(content), idx + len(keyword) + 100)
                context = content[context_start:context_end]
                
                matches.append({
                    "keyword": keyword,
                    "context": context,
                })
        
        return matches
    
    def monitor_telegram_channel(self, channel_name):
        """监控 Telegram 频道（需要 Telethon 库）"""
        # 实际使用需要 Telegram API credentials
        # pip install telethon
        
        monitor_code = '''
from telethon import TelegramClient, events

api_id = YOUR_API_ID
api_hash = 'YOUR_API_HASH'
client = TelegramClient('monitor_session', api_id, api_hash)

MONITORED_KEYWORDS = {keywords}
CHANNELS = ['@{channel}']

@client.on(events.NewMessage(chats=CHANNELS))
async def handler(event):
    text = event.raw_text.lower()
    for keyword in MONITORED_KEYWORDS:
        if keyword.lower() in text:
            print(f"[ALERT] {{keyword}} found in {{event.chat.title}}")
            print(f"  Message: {{event.raw_text[:200]}}")
            print(f"  Time: {{event.date}}")

client.start()
client.run_until_disconnected()
'''.format(keywords=str(self.keywords), channel=channel_name)
        
        return monitor_code

# 常见暗网情报源类别
DARKWEB_SOURCE_CATEGORIES = {
    "forums": {
        "description": "黑客论坛，讨论漏洞利用和攻击技术",
        "examples": ["HackForums 类 .onion 站点", "Exploit.in", "XXX"],
        "monitoring": "关键词匹配 + 定期抓取",
    },
    "markets": {
        "description": "黑市市场，售卖数据/工具/服务",
        "examples": ["各类 .onion 市场"],
        "monitoring": "品牌名/数据类型搜索",
    },
    "paste_sites": {
        "description": "文本分享站点，常用于泄露数据",
        "examples": ["Pastebin", "GhostBin", "各类 .onion paste 站"],
        "monitoring": "自动爬取 + 正则匹配",
    },
    "telegram": {
        "description": "Telegram 频道，实时性最强",
        "examples": ["数据泄露频道", "黑产工具频道"],
        "monitoring": "Bot 实时监听",
    },
    "irc": {
        "description": "IRC 频道，传统黑客交流",
        "examples": ["Undernet", "EFnet 上的黑产频道"],
        "monitoring": "IRC Bot 常驻监控",
    },
}
```

### 6. OpSec 安全实践

```
暗网监控 OpSec 清单：

环境隔离：
  □ 使用专用 VM（Tails OS 或 Whonix）
  □ 物理隔离网络（不与办公网络连接）
  □ 使用专用硬件（避免使用工作笔记本）

匿名保护：
  □ Tor Browser 用于 Web 访问
  □ Tor + VPN 双层（VPN → Tor 顺序）
  □ 不使用真实姓名、邮箱、电话
  □ 使用临时身份注册账号
  □ 定期更换 Tor 身份（New Identity）

数据安全：
  □ 不在监控环境存储敏感数据
  □ 所有下载文件在隔离沙箱中分析
  □ 截图/报告去除可能暴露身份的元数据
  □ 监控结果通过安全通道传输到生产环境

法律合规：
  □ 确认暗网监控的法律授权
  □ 不参与非法交易（仅被动观察）
  □ 记录所有访问和操作日志
  □ 与法务团队确认监控范围
  □ 发现儿童虐待等非法内容依法举报
```

### 7. 监控报告模板

```markdown
# 暗网监控报告 — [日期]

## 执行摘要
- 监控周期：YYYY-MM-DD ~ YYYY-MM-DD
- 新增告警：X 条
- 高优先级：X 条

## 凭证泄露
| 域名 | 泄露邮箱数 | 来源 | 风险 | 状态 |
|------|-----------|------|------|------|
| yourbrand.com | 23 | PasteBin | 高 | 已通知重置 |

## 品牌冒充
| 域名/账号 | 类型 | 冒充方式 | 风险 | 处置 |
|----------|------|---------|------|------|
| login-yourbrand.xyz | 域名 | 钓鱼 | 高 | 已提交下架 |

## 数据泄露
| 泄露类型 | 数据量 | 来源 | 风险 | 状态 |
|---------|--------|------|------|------|
| 客户数据库 | ~10K记录 | 市场 | 严重 | IR 启动 |

## 暗网活动观察
| 主题 | 讨论热度 | 关联度 | 备注 |
|------|---------|--------|------|
| [主题] | [高/中/低] | [直接/间接] | |

## 建议措施
1. [紧急措施]
2. [短期措施]
3. [长期措施]
```

---

## 速查表

### 暗网情报源对比

| 源类型 | 实时性 | 覆盖面 | 访问难度 | 误报率 | 推荐工具 |
|--------|--------|--------|---------|--------|---------|
| Paste 站点 | 高 | 广 | 低 | 中 | 自动爬虫 |
| Tor 论坛 | 中 | 中 | 高 | 低 | Tor + 手动 |
| Telegram | 高 | 广 | 中 | 中 | Telethon Bot |
| IRC 频道 | 高 | 窄 | 中 | 低 | IRC Bot |
| 商业平台 | 低 | 广 | 低 | 低 | Flashpoint/DarkOwl |

### 品牌冒充检测维度

| 维度 | 检测方法 | 自动化程度 |
|------|---------|-----------|
| 域名注册 | CT 日志 + DNSTwist | 高 |
| SSL 证书 | crt.sh 监控 | 高 |
| 社交媒体 | API 搜索 | 中 |
| App Store | 搜索结果爬取 | 中 |
| 钓鱼 Kit | 网页内容分析 | 中 |
| 电子邮件 | DMARC 报告 | 高 |

---

## MITRE ATT&CK 映射

| 战术 | 技术 | 暗网监控应用 |
|------|------|-------------|
| Reconnaissance | T1589 | 收集目标组织信息 |
| Resource Development | T1583 | 购买/租用攻击基础设施 |
| Resource Development | T1586 | 获取 compromised 账号 |
| Initial Access | T1566 | 监控钓鱼 Kit 销售 |
| Credential Access | T1110 | 凭证泄露监控与告警 |
| Collection | T1530 | 数据泄露发现 |

---

## 前置条件

1. **环境**：Tails OS 或 Whonix VM、Tor 浏览器、隔离网络
2. **工具**：Telethon（Telegram 监控）、requests + socks（Tor 代理）
3. **商业平台**（可选）：Flashpoint、DarkOwl、Digital Shadows
4. **数据**：监控关键词列表、品牌域名列表、已知员工邮箱格式
5. **合规**：与法务确认监控范围、记录操作日志、不参与非法交易

---

## Part C：2025-2026 精细化补充

### C.1 Stealer 日志监控 — 凭证泄露的头号威胁

```
Stealer 日志威胁态势（2025-2026）：

背景：
  - Infostealer（LummaC2/RedLine/Raccoon/StealC/Vidar）成为凭证泄露主要来源
  - 单个 Stealer 日志包含：浏览器保存密码、Cookie、自动填充、加密钱包、SSH 密钥
  - 日志在暗网市场批量出售，$1-50/条（取决于内容价值）
  - Flare 2025 报告：Stealer 日志量同比+300%

关键指标：
  - LummaC2 2025 被拆除前感染 100 万+ 设备
  - FBI 2025-05 打击 LummaC2（Operation End Game）后 StealC/Meta 填补空缺
  - 平均每个企业每月 50-200 条员工 Stealer 日志在暗网流通

监控要点：
  1. 监控 Stealer 日志交易市场（Russian Market/Genesis Market 替代品）
  2. 按企业域名过滤日志中的凭证
  3. 重点关注 Session Cookie → Account Takeover 攻击路径
  4. 检查日志中的 SSH 密钥 → 横向移动风险
  5. 关联日志时间戳与员工 VPN/SSO 登录时间检测入侵
```

```python
# stealer_log_monitor.py — Stealer 日志凭证匹配增强
import re
import hashlib
import json
from datetime import datetime

class StealerLogAnalyzer:
    """增强型 Stealer 日志分析器"""

    # Stealer 日志中常见的数据结构
    LOG_PATTERNS = {
        "browser_credentials": re.compile(
            r'URL:\s*(https?://[^\s]+)\s+'
            r'(?:Login|Username|Email):\s*([^\s]+)\s+'
            r'(?:Password|Pass):\s*(\S+)',
            re.IGNORECASE
        ),
        "cookies": re.compile(
            r'([^\s]+)\t(TRUE|FALSE)\t([^\s]+)\t([^\s]+)\t(\d+)\t([^\s]+)\t(.+)',
        ),
        "crypto_wallets": re.compile(
            r'(?:wallet|address|seed|phrase|private.?key)[\s:=]+[\w]{20,}',
            re.IGNORECASE
        ),
        "ssh_keys": re.compile(
            r'ssh-(?:rsa|ed25519|ecdsa)\s+AAAA[A-Za-z0-9+/=]+',
        ),
        "discord_tokens": re.compile(
            r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}',
        ),
        "ftp_credentials": re.compile(
            r'(?:ftp|sftp)://[\w+-\.]+:[\w!@#$%^&*]+@[\w.-]+',
            re.IGNORECASE
        ),
    }

    def __init__(self, monitored_domains, monitored_email_domains):
        self.monitored_domains = monitored_domains
        self.monitored_email_domains = monitored_email_domains
        self.findings = []

    def analyze_log(self, log_content, source="unknown"):
        """分析单个 Stealer 日志"""
        findings = []

        # 1. 浏览器凭证提取
        for match in self.LOG_PATTERNS["browser_credentials"].finditer(log_content):
            url, username, password = match.groups()
            if self._is_relevant(url, username):
                findings.append({
                    "type": "browser_credential",
                    "url": url,
                    "username": username,
                    "password_hash": hashlib.sha256(password.encode()).hexdigest()[:16],
                    "source": source,
                    "risk": self._assess_url_risk(url),
                })

        # 2. Session Cookie 检测（最高风险）
        for match in self.LOG_PATTERNS["cookies"].finditer(log_content):
            domain = match.group(1)
            if any(d in domain for d in self.monitored_domains):
                cookie_name = match.group(6)
                if any(kw in cookie_name.lower() for kw in
                       ["session", "token", "auth", "sid", "jwt"]):
                    findings.append({
                        "type": "session_cookie",
                        "domain": domain,
                        "cookie_name": cookie_name,
                        "source": source,
                        "risk": "critical",
                        "note": "Session cookie = 直接 Account Takeover 无需密码",
                    })

        # 3. SSH 密钥检测
        ssh_keys = self.LOG_PATTERNS["ssh_keys"].findall(log_content)
        for key in ssh_keys:
            findings.append({
                "type": "ssh_key",
                "key_fingerprint": hashlib.sha256(key.encode()).hexdigest()[:16],
                "source": source,
                "risk": "high",
                "note": "SSH key → 潜在横向移动/基础设施访问",
            })

        # 4. Discord Token 检测（常见于社工链）
        tokens = self.LOG_PATTERNS["discord_tokens"].findall(log_content)
        for token in tokens:
            findings.append({
                "type": "discord_token",
                "token_hash": hashlib.sha256(token.encode()).hexdigest()[:16],
                "source": source,
                "risk": "medium",
            })

        return findings

    def _is_relevant(self, url, username):
        """检查 URL 或用户名是否与监控目标相关"""
        for domain in self.monitored_domains:
            if domain in url:
                return True
        for email_domain in self.monitored_email_domains:
            if email_domain in username:
                return True
        return False

    def _assess_url_risk(self, url):
        """评估 URL 对应的风险等级"""
        critical_keywords = ["admin", "vpn", "owa", "webmail", "portal",
                           "sso", "auth", "login", "mfa"]
        for kw in critical_keywords:
            if kw in url.lower():
                return "critical"
        return "high"
```

### C.2 Telegram 地下生态 — 2025-2026 主导平台

```
Telegram 地下生态演变：

为什么 Telegram 取代传统暗网论坛：
  1. 无需 Tor → 降低准入门槛
  2. 端到端加密 + 频道广播 → 既私密又可大规模传播
  3. 内置支付（TON）→ 交易闭环
  4. 不受 Western 執法管辖 → 相对安全
  5. 移动优先 → 随时随地操作

主要频道类别（2025-2026）：
  ├ 数据泄露频道：实时发布新泄露数据样本
  │   例："Daily Leaks" 类频道，10K+ 订阅者
  ├ Stealer 日志交易：出售按域名/行业分类的日志
  │   例：按企业域名过滤的日志包 $10-100
  ├ Initial Access 销售：出售企业网络访问权
  │   例：VPN/RDP 凭证 $50-5000（取决于企业规模）
  ├ Phishing Kit 分发：钓鱼工具包和模板
  │   例：AiTM 钓鱼 Kit $100-500
  ├ 0-day/Exploit 交易：漏洞利用信息
  │   例：私有 Exploit 拍卖
  └ 赃物/卡务：被盗支付卡、身份信息
      例：全息身份包（SSN+DL+CC）$50-200

Telegram 监控技术升级：
  1. Telethon/Pyrogram 多账号轮换（避免封号）
  2. 频道发现：从已知频道 → 转发链 → 新频道（图遍历）
  3. 自动化内容分析：关键词+ML分类+NER实体提取
  4. 频道活跃度追踪：消息频率、订阅者变化、管理员行为
  5. 邀请链接监控：私有频道的入口点追踪
```

```python
# telegram_ecosystem_monitor.py — Telegram 地下生态监控增强
import asyncio
import re
import json
from datetime import datetime, timedelta

class TelegramEcosystemMonitor:
    """Telegram 地下生态监控（基于 Pyrogram）"""

    # 黑产频道关键词分类
    THREAT_CATEGORIES = {
        "data_leak": [
            "leak", "breach", "dump", "database", "db", "数据泄露",
            "fresh", "updated", "combo", "全球泄露",
        ],
        "stealer_log": [
            "stealer", "log", "redline", "lumma", "raccoon", "vidar",
            "stealc", "meta", "infected", "日志",
        ],
        "initial_access": [
            "access", "vpn", "rdp", "shell", "root", "admin", "cpanel",
            "wordpress", "初始访问", "access sale",
        ],
        "phishing": [
            "phishing", "phish", "kit", "template", "scam", "page",
            "login", "钓鱼", "钓鱼页",
        ],
        "malware": [
            "malware", "rat", "trojan", "miner", "loader", "botnet",
            "c2", "panel", "木马", "远控",
        ],
        "credential": [
            "account", "combo", "mail", "password", "email", "smtp",
            "crack", "brute", "凭证", "账密",
        ],
    }

    def __init__(self):
        self.channel_graph = {}  # 频道关系图
        self.alert_rules = []

    async def discover_channels(self, seed_channels, depth=2):
        """
        从种子频道出发，通过转发关系发现新频道
        seed_channels: 已知黑产频道列表
        depth: 图遍历深度
        """
        discovered = set(seed_channels)
        to_explore = list(seed_channels)
        explored = set()

        for _ in range(depth):
            new_channels = []
            for channel in to_explore:
                if channel in explored:
                    continue
                explored.add(channel)

                # 获取频道转发来源
                forwarded_from = await self._get_forward_sources(channel)
                for source in forwarded_from:
                    if source not in discovered:
                        discovered.add(source)
                        new_channels.append(source)
                        self.channel_graph[source] = {
                            "discovered_from": channel,
                            "discovered_at": datetime.utcnow().isoformat(),
                        }

            to_explore = new_channels

        return {
            "total_discovered": len(discovered),
            "seed_count": len(seed_channels),
            "new_count": len(discovered) - len(seed_channels),
            "channels": list(discovered),
            "graph": self.channel_graph,
        }

    async def _get_forward_sources(self, channel):
        """获取频道消息的转发来源（需 Pyrogram 实现）"""
        # 实际实现需要 Pyrogram client
        return []

    def classify_message(self, text):
        """分类消息威胁类型"""
        text_lower = text.lower()
        classifications = {}

        for category, keywords in self.THREAT_CATEGORIES.items():
            matched_keywords = [kw for kw in keywords if kw in text_lower]
            if matched_keywords:
                classifications[category] = {
                    "matched_keywords": matched_keywords,
                    "confidence": len(matched_keywords) / len(keywords),
                }

        return classifications

    def generate_channel_report(self, channel_data):
        """生成频道分析报告"""
        return {
            "channel": channel_data.get("username", "unknown"),
            "subscriber_count": channel_data.get("subscribers", 0),
            "message_frequency": channel_data.get("msgs_per_day", 0),
            "threat_categories": self.classify_message(
                channel_data.get("recent_content", "")
            ),
            "risk_level": self._assess_channel_risk(channel_data),
            "recommended_action": self._recommend_action(channel_data),
        }

    def _assess_channel_risk(self, data):
        """评估频道风险等级"""
        score = 0
        subs = data.get("subscribers", 0)
        freq = data.get("msgs_per_day", 0)

        if subs > 10000: score += 30
        elif subs > 1000: score += 20
        elif subs > 100: score += 10

        if freq > 50: score += 30
        elif freq > 10: score += 20
        elif freq > 1: score += 10

        categories = self.classify_message(data.get("recent_content", ""))
        if "initial_access" in categories: score += 25
        if "data_leak" in categories: score += 20
        if "stealer_log" in categories: score += 15

        if score >= 70: return "critical"
        elif score >= 50: return "high"
        elif score >= 30: return "medium"
        else: return "low"

    def _recommend_action(self, data):
        """推荐处置动作"""
        risk = self._assess_channel_risk(data)
        categories = self.classify_message(data.get("recent_content", ""))

        actions = ["持续监控"]
        if "data_leak" in categories:
            actions.append("检查组织数据是否出现在泄露中")
        if "stealer_log" in categories:
            actions.append("按域名搜索 Stealer 日志")
            actions.append("强制相关账户密码重置+MFA")
        if "initial_access" in categories:
            actions.append("检查 VPN/RDP 凭证泄露")
            actions.append("审查远程访问日志")
        if "phishing" in categories:
            actions.append("检查是否有针对组织的钓鱼 Kit")

        return actions
```

### C.3 现代暗网监控工具生态（2025-2026 对比矩阵）

```
暗网监控 / 数字风险保护（DRPS）工具对比矩阵 v2.0

| 工具/平台 | 类型 | 核心能力 | Stealer日志 | Telegram | 凭证监控 | 价格区间 | 特色 |
|-----------|------|---------|------------|----------|---------|---------|------|
| Flare | 商业SaaS | 曝露面管理 | ✓ 实时 | ✓ | ✓ | $$/用户/月 | 最友好的UI、Stealer日志深度 |
| Recorded Future | 商业TI | 全源情报 | ✓ | ✓ | ✓ | $$$ | ML优先级排序、SOAR集成 |
| Intel 471 | 商业TI | 地下情报 | ✓ | ✓ | ✓ | $$$ | IAB追踪、Adversary-centric |
| Flashpoint | 商业TI | 深暗网情报 | ✓ | ✓ | ✓ | $$$ | 论坛渗透深度、语言覆盖 |
| DarkOwl | 商业TI | 数据源覆盖 | ✓ | ✓ | ✓ | $$ | 历史数据最深、API友好 |
| SpyCloud | 商业DRPS | 凭证保护 | ✓ 核心 | ✓ | ✓ 核心 | $$ | 最大Stealer日志库、ATO防护 |
| Digital Shadows (ReliaQuest) | 商业DRPS | 品牌保护 | ✓ | ✓ | ✓ | $$$ | 品牌冒充检测最强 |
| ZeroFox | 商业DRPS | 社交威胁 | ✓ | ✓ | ✓ | $$$ | 社交媒体+暗网+表面网 |
| Mandiant Advantage | 商业TI | 威胁分析 | ✓ | ✓ | ✓ | $$$$ | APT级别分析、Google集成 |
| Kela | 商业TI | 地下监控 | ✓ | ✓ | ✓ | $$ | 俄罗斯地下生态专长 |

开源/免费工具：
| 工具 | 用途 |
|------|------|
| Ahmia (ahmia.fi) | Tor 搜索引擎 |
| OnionScan | .onion 站点扫描 |
| TorBot | 暗网爬虫框架 |
| Photon | 快速爬虫 |
| SpiderFoot | OSINT 自动化（含暗网模块） |
| Hunchly | Web 捕获和追踪 |
| DNSTwist | 域名变异检测（品牌冒充） |
| URLscan.io | URL 分析（表面+发现恶意站点） |
| Have I Been Pwned | 公开泄露检查 |
| DeHashed | 凭证泄露搜索引擎 |
```

### C.4 勒索软件泄露站点（DLS）监控

```
勒索软件 DLS 监控方法论（2025-2026）：

为什么监控 DLS：
  - 勒索软件 DLS 是受害者组织的"早期预警系统"
  - 从数据发布到完全公开通常有 7-14 天窗口期
  - 监控 DLS 可在客户/媒体/监管之前发现泄露

活跃 DLS 监控清单（2025-2026）：
  ├ Qilin (骨料) — 2025 份额最大 29%
  ├ LockBit — 死灰复燃 QoY +106%
  ├ Play — 持续活跃
  ├ BlackSuit — 新兴增长
  ├ Akira — 跨平台（Linux/ESXi）
  ├ Rhysida — 间歇加密
  ├ RansomHub — RaaS 新势力
  ├ Medusa — MedusaLocker 变种
  └ Hunters International — 重组品牌

DLS 监控自动化脚本设计：

  1. Onion 地址变更追踪
     - 勒索软件 DLS 经常更换 .onion 地址
     - 监控备用域名和 Redirect 链

  2. 受害者列表定期抓取
     - 每日/每周抓取新增受害者
     - 提取：公司名、行业、国家、声称数据量

  3. 样本数据下载与检查
     - DLS 通常发布样本数据（10-50MB）
     - 自动下载 → 检查是否包含组织域名/数据

  4. 时间线分析
     - 追踪从"倒计时"到"完全发布"的时间线
     - 受害者是否在期限前支付？数据是否被撤回？

  5. 勒索软件团伙关联分析
     - 追踪团伙品牌变更（如 Hive→Hunters International）
     - 识别新出现的团伙及其 TTP

关键指标监控：
  - 新增受害者/周 → 组织是否被列名
  - 数据声称量级 → 潜在影响范围
  - 倒计时状态 → 紧急程度
  - 团伙活跃度变化 → 威胁态势调整
```

```python
# ransomsite_monitor.py — 勒索软件 DLS 监控
import re
import json
import hashlib
from datetime import datetime, timedelta

class RansomSiteMonitor:
    """勒索软件泄露站点监控"""

    TOR_PROXY = {
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050",
    }

    def __init__(self, monitored_orgs):
        self.monitored_orgs = monitored_orgs  # ["MyCorp", "MyCorp Inc", "mycorp.com"]
        self.victim_cache = {}

    def parse_victim_list(self, page_content, group_name):
        """解析勒索软件站点的受害者列表"""
        victims = []

        # 常见 DLS 页面模式
        patterns = [
            # 模式1：表格/列表格式
            re.compile(
                r'(?:company|organization|victim)[\s:]+([^<\n]{3,100})',
                re.IGNORECASE
            ),
            # 模式2：带日期的条目
            re.compile(
                r'(\d{4}[-/]\d{2}[-/]\d{2})[\s|]+([^<\n]{3,100})',
            ),
            # 模式3：倒计时格式
            re.compile(
                r'([^<\n]{3,100})[\s]+(?:deadline|timer|countdown)[\s:]*(\d+)',
                re.IGNORECASE
            ),
        ]

        for pattern in patterns:
            for match in pattern.finditer(page_content):
                victim_info = {
                    "group": group_name,
                    "raw_entry": match.group(0).strip(),
                    "timestamp": datetime.utcnow().isoformat(),
                }
                victims.append(victim_info)

        return victims

    def check_monitored_orgs(self, victims):
        """检查受害者列表中是否包含监控组织"""
        alerts = []

        for victim in victims:
            raw = victim["raw_entry"].lower()
            for org in self.monitored_orgs:
                if org.lower() in raw:
                    alerts.append({
                        "alert_type": "RANSOMWARE_LISTING",
                        "severity": "critical",
                        "organization": org,
                        "group": victim["group"],
                        "raw_entry": victim["raw_entry"],
                        "timestamp": victim["timestamp"],
                        "recommended_actions": [
                            "立即启动 IR 流程",
                            "确认是否确实存在入侵",
                            "检查 EDR/日志中与该团伙相关的 IOC",
                            "通知管理层和法务",
                            "准备外部沟通方案",
                        ],
                    })

        return alerts

    def track_group_changes(self, current_groups, previous_groups):
        """追踪勒索软件团伙变化"""
        changes = {
            "new_groups": [],
            "disappeared": [],
            "rebranded": [],
        }

        current_names = {g["name"].lower() for g in current_groups}
        previous_names = {g["name"].lower() for g in previous_groups}

        changes["new_groups"] = list(current_names - previous_names)
        changes["disappeared"] = list(previous_names - current_names)

        return changes
```

### C.5 AI/LLM 辅助暗网情报分析

```
AI/LLM 在暗网监控中的应用（2025-2026）：

1. 多语言暗网内容理解
   - 暗网论坛使用混合语言、俚语、代码词
   - LLM 可翻译和理解俄语/中文/阿拉伯语/西班牙语地下论坛内容
   - 识别编码通信：如 "steaks" = stealer logs, "combo" = credential list

2. 自动化威胁分类与优先级排序
   - 输入：大量暗网原始数据
   - 输出：结构化威胁报告 + 优先级评分
   - 减少分析师工作量 70-80%（Gartner 2025 估计）

3. 暗网趋势预测
   - 分析历史数据预测新兴威胁趋势
   - 识别零日漏洞交易模式
   - 追踪 IAB 定价变化预示攻击活动

4. 实体自动提取（NER 增强）
   - 从暗网帖子中自动提取：CVE、IP、域名、加密钱包地址、Telegram 链接
   - 与内部资产数据库自动关联

5. 对抗性 AI 检测
   - 攻击者使用 LLM 生成逼真的钓鱼内容
   - 防御者使用 LLM 检测 AI 生成的暗网内容
   - 双方 AI 对抗持续升级
```

```python
# ai_darkweb_analyzer.py — LLM 辅助暗网分析脚本
import json
import re

class AIDarkWebAnalyzer:
    """使用 LLM API 辅助暗网情报分析"""

    def __init__(self, llm_client=None):
        self.llm = llm_client  # OpenAI/Anthropic client

    def analyze_darkweb_post(self, post_text, context=""):
        """使用 LLM 分析暗网帖子"""
        prompt = f"""分析以下暗网/地下论坛帖子，提取威胁情报：

帖子内容：
{post_text}

上下文：{context}

请以 JSON 格式返回：
{{
  "threat_type": "data_leak|credential_sale|malware|initial_access|phishing|0day|other",
  "severity": "critical|high|medium|low",
  "affected_entities": ["提取的组织名、产品名、技术"],
  "indicators": {{
    "domains": [],
    "ips": [],
    "cves": [],
    "crypto_addresses": [],
    "telegram_links": []
  }},
  "summary": "一句话威胁摘要",
  "recommended_action": "建议处置动作"
}}"""
        return prompt  # 实际调用 self.llm.chat.completions.create(...)

    def batch_classify_channels(self, channels_data):
        """批量分类 Telegram 频道"""
        results = []
        for channel in channels_data:
            recent_msgs = channel.get("recent_messages", [])
            combined = "\n".join(recent_msgs[:20])

            analysis = {
                "channel": channel["username"],
                "subscribers": channel.get("subscribers", 0),
                "threat_categories": self._classify_content(combined),
                "risk_score": self._calculate_risk(channel),
            }
            results.append(analysis)

        return sorted(results, key=lambda x: x["risk_score"], reverse=True)

    def _classify_content(self, text):
        """基于规则+关键词的快速分类（LLM 前置过滤）"""
        categories = {
            "data_leak": ["leak", "dump", "breach", "database", "数据"],
            "credential": ["combo", "log", "stealer", "password", "mail"],
            "initial_access": ["vpn", "rdp", "shell", "access", "root"],
            "malware": ["rat", "trojan", "botnet", "loader", "miner"],
        }

        text_lower = text.lower()
        matched = []
        for cat, keywords in categories.items():
            if any(kw in text_lower for kw in keywords):
                matched.append(cat)
        return matched

    def _calculate_risk(self, channel):
        """综合风险评估"""
        score = 0
        subs = channel.get("subscribers", 0)
        msgs = channel.get("msgs_per_day", 0)

        if subs > 5000: score += 25
        elif subs > 500: score += 15

        if msgs > 20: score += 25
        elif msgs > 5: score += 15

        cats = self._classify_content(
            "\n".join(channel.get("recent_messages", [])[:10])
        )
        score += len(cats) * 15

        return min(score, 100)
```

### C.6 2025-2026 重大暗网事件速查

```
2025-2026 重大暗网事件与执法行动：

# 2025
1. Operation End Game (2025-05)
   - FBI/欧洲刑警联合行动，打击 LummaC2 僵尸网络
   - 查封 1,300+ 服务器，逮捕多人
   - 影响暗网凭证供应链，Stealer 日志量短暂下降

2. Genesis Market 关闭后续 (2025)
   - 2023 FBI 查封后，替代品涌现
   - Russian Market 成为主流替代平台
   - 新市场更注重 OpSec（多签托管、评级系统）

3. NCA/ICO Telegram 数据泄露调查 (2025)
   - 英国国家犯罪署加强 Telegram 地下监控
   - 多个英国企业数据在 Telegram 频道泄露

4. Snowflake 数据泄露事件 (2025-06)
   - 攻击者通过 Stealer 日志获取 Snowflake 工程师凭证
   - 165+ 客户受影响，数据在暗网出售
   - 凸显 Stealer 日志 → 云服务攻击链

5. HPE 邮箱泄露 (2025)
   - 国家支持的攻击者利用窃取的凭证访问 HPE 邮箱
   - 数据在暗网流出

# 2026
6. LockBit 死灰复燃 (2026 Q1)
   - LockBit 在 2024 Operation Cronos 后重组
   - DLS 恢复运营，季度受害者数 +106%
   - 但"预吹嘘"比例升高（约40%受害者无实际加密）

7. AI 生成钓鱼 Kit 暗网交易 (2026)
   - AI 生成的定制化钓鱼 Kit 在暗网批量出售
   - 每个 Kit 针对特定企业定制，$100-500
   - Bypass 传统邮件网关检测率提升 3x

8. DORA/NIS2 推动暗网监控合规 (2025-2026)
   - EU DORA (2025-01) 要求金融机构监控暗网威胁
   - NIS2 (2024-10) 要求关键实体"主动威胁情报"
   - 暗网监控从"最佳实践"→"合规要求"
```

### C.7 加密货币追踪与暗网资金流

```
加密货币追踪在暗网监控中的角色：

关键概念：
  - 比特币区块链公开可查 → 追踪支付流
  - 混币器（Tumbler/Mixer）→ 模糊资金来源
  - 隐私币（Monero/Zcash）→ 更难追踪
  - TON（Telegram）→ 2025 地下交易新通道

追踪工具矩阵：
| 工具 | 类型 | 功能 | 特色 |
|------|------|------|------|
| Chainalysis | 商业 | 区块链分析 | 政府/交易所首选，KYT |
| Elliptic | 商业 | 合规监控 | 钱包评分、风险标签 |
| TRM Labs | 商业 | 链上调查 | 多链支持、API 集成 |
| CipherTrace (Mastercard) | 商业 | 合规 | Mastercard 生态集成 |
| Blockstream Explorer | 免费 | BTC 浏览器 | 开源、隐私友好 |
| BTCPFY | 开源 | BTC 追踪 | 命令行、脚本友好 |

暗网支付追踪流程：
  1. 从 DLS/帖子中提取加密货币地址
  2. 区块链浏览器查询交易历史
  3. 标签关联（交易所、混币器、暗网市场）
  4. 资金流向可视化（输入→输出地址图）
  5. 确定终点（是否流入合规交易所 → 可冻结/识别）
```

### C.8 中文社区精华参考

```
暗网监控/威胁情报中文社区精华（2025-2026）：

1. 奇安信威胁情报中心 (ti.qianxin.com)
   - ALPHATI 威胁情报平台，暗网情报源整合
   - 国内外 APT 组织画像和 IOC
   - 勒索软件态势报告（年度/季度）

2. 微步在线 (threatbook.cn)
   - X 情报中心，含暗网/地下论坛情报
   - XGPT AI 辅助威胁分析
   - 社区情报分享

3. 360 威胁情报中心 (ti.360.net)
   - APT 报告（海莲花、毒云藤等中国相关 APT）
   - 勒索软件态势报告
   - 2025 年度安全态势报告

4. 阿里云威胁情报
   - 阿里云 AVD 漏洞数据库
   - 云上威胁情报联动
   - WAF/CDN 集成暗网 IOC

5. FreeBuf (freebuf.com)
   - 暗网入门指南系列
   - Stealer 日志威胁分析
   - OSINT 工具测评

6. 安全客 (anquanke.com)
   - 勒索软件事件跟踪
   - 暗网市场动态分析
   - 国际执法行动报道

7. 先知社区 (xz.aliyun.com)
   - OSINT 技术实践
   - 暗网爬虫开发教程
   - 企业暗网监控方案设计

8. 天融信/深信服威胁情报
   - 国内暗网情报生态分析
   - 等保2.0 威胁情报合规指南
   - 关基设施暗网威胁评估

中国暗网监控特色：
  - 重点关注：Telegram 中文黑产频道 > 传统 Tor 暗网
  - 本土威胁：国内黑产生态（羊毛党、社工库、卡商）
  - 合规驱动：等保2.0、关基条例、数据安全法
  - 国产化替代：奇安信/微步/360 替代 Flashpoint/Recorded Future
```

### C.9 防御升级路线图

```
暗网监控防御升级路线图（P0-P3 分级）

P0 — 立即实施（0-1 个月）
  ├ 部署凭证泄露监控（SpyCloud/Flare/HIBP API）
  ├ 监控组织域名在 crt.sh 的新注册
  ├ 建立 Telegram 监控（种子频道 + Telethon Bot）
  ├ 订阅勒索软件 DLS RSS/Alert（Ransomfeed/RansomLook）
  └ 制定暗网监控操作规程和 OpSec 规范

P1 — 短期完善（1-3 个月）
  ├ 集成暗网告警到 SIEM/SOAR（Splunk/elastic → 自动工单）
  ├ 部署品牌冒充自动化检测（DNSTwist + CT 日志 + App Store）
  ├ 建立 Stealer 日志定期查询流程（按企业域名过滤）
  ├ 配置加密货币地址监控（如组织钱包地址）
  └ 培训 IR 团队暗网情报使用能力

P2 — 中期建设（3-6 个月）
  ├ 评估商业 DRPS 平台（Flare/Recorded Future/Digital Shadows）
  ├ 建立 Telegram 地下生态频道发现自动化
  ├ 部署 LLM 辅助暗网内容分析管线
  ├ 建立暗网情报 → 漏洞管理联动（暗网0day → 优先修补）
  └ 建立跨部门暗网情报分享机制（安全+法务+品牌+PR）

P3 — 长期优化（6-12 个月）
  ├ 构建全自动化暗网监控管线（采集→分析→告警→响应）
  ├ AI 驱动暗网趋势预测和威胁建模
  ├ 与行业 ISAC/信息共享组织交换暗网情报
  ├ 暗网监控能力纳入合规审计（DORA/NIS2/等保2.0）
  └ 定期 Red Team 评估暗网监控覆盖率

度量指标（KPI）：
  - 凭证泄露检测时间（目标：< 24h 从泄露到告警）
  - 品牌冒充检测时间（目标：< 48h 从注册到告警）
  - 勒索 DLS 列名检测时间（目标：< 4h 从发布到告警）
  - Stealer 日志覆盖率（目标：> 90% 企业域名已监控）
  - 误报率（目标：< 15%）
  - 平均响应时间（目标：< 4h 从告警到处置）
```

### C.10 MITRE ATT&CK 扩展映射

```
暗网监控 MITRE ATT&CK 扩展映射（v18/v19）：

| 战术 | 技术 ID | 技术名 | 暗网监控应用 |
|------|---------|--------|-------------|
| Reconnaissance | T1589.001 | Gather Victim Identity Info | 监控员工 PII 在暗网出售 |
| Reconnaissance | T1589.002 | Gather Victim Identity Info: Email | 监控企业邮箱凭证泄露 |
| Reconnaissance | T1591 | Gather Victim Org Info | 监控组织内部文档在暗网传播 |
| Reconnaissance | T1592 | Gather Victim Host Info | 监控 Stealer 日志中的主机信息 |
| Resource Development | T1583.001 | Acquire Infrastructure: Domains | 监控仿冒域名注册 |
| Resource Development | T1583.004 | Acquire Infrastructure: Server | 监控 C2 服务器出租广告 |
| Resource Development | T1586.001 | Compromise Accounts: Social Media | 监控企业社交媒体账号泄露 |
| Resource Development | T1586.002 | Compromise Accounts: Email Accounts | 监控员工邮箱凭证泄露 |
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | 监控钓鱼 Kit 销售 |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | 监控钓鱼域名注册 |
| Initial Access | T1190 | Exploit Public-Facing Application | 监控 0-day/Exploit 出售 |
| Credential Access | T1110.004 | Brute Force: Credential Stuffing | 监控 Combo 列表出售 |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | 监控 Stealer 日志 |
| Credential Access | T1558 | Steal or Forge Kerberos Tickets | 监控 Golden/Silver Ticket 工具出售 |
| Collection | T1530 | Data from Local System | 监控数据泄露在暗网的传播 |
| Collection | T1560 | Archive Collected Data | 监控打包数据在暗网出售 |
| Exfiltration | T1567 | Exfiltration Over Web Service | 监控 MEGA/GoFile 等文件分享链接 |
| Command and Control | T1573.002 | Encrypted Channel: Asymmetric Cryptography | 监控暗网 C2 基础设施出租 |

v18/v19 新增影响：
  - Defense Evasion 拆分为 Stealth + Defense Impairment → 监控绕过工具交易
  - ICS 子技术扩展 → 监控 OT/ICS 相关 0-day 交易
  - AI 对抗技术 → 监控 AI/LLM 攻击工具在暗网的传播
```

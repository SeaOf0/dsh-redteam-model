---
name: threat-intel-platform
description: >
  威胁情报平台建设与运营完整手册：覆盖情报生命周期管理（规划→收集→处理→分析→传播→反馈）、
  MISP/OpenCTI 平台部署与运维、STIX/TAXII 标准数据交换、情报源接入与质量评估、
  TTP 提取与 ATT&CK 映射、自动化情报编排、情报驱动防御（SOAR 集成）、
  情报共享框架（TLP、AIS）、指标老化与退役、情报团队角色与流程。
  Part A 攻击视角：红队如何利用公开情报源规划行动。
  Part B 防御视角：从零搭建情报平台到生产运营。
domain: cybersecurity
subdomain: threat-intelligence
tags: [threat-intelligence, MISP, OpenCTI, STIX, TAXII, MITRE-ATTCK, threat-sharing, CTI, TTP, IOC, SOAR, intelligence-lifecycle]
version: 2.0.0
---

# 威胁情报平台 — 完整攻防手册

## 适用场景

**适用：** 需要从零搭建或优化 CTI 能力的企业/团队；需要接入多源情报并自动化分发的 SOC/CSIRT；需要建立情报共享联盟的组织；红队需要利用 OSINT 规划攻击路径。
**不适用：** 纯实时告警响应（参考 ir-triage）；纯威胁狩猎（参考 threat-hunting）；纯漏洞管理（参考 devsecops-sast）。

## 前置条件

- SOC/CSIRT 基础设施已就绪（SIEM、日志采集）
- 网络访问情报源 API（VirusTotal、AlienVault OTX、Abuse.ch 等）
- Python 3.10+ / Docker 用于平台部署
- 了解 MITRE ATT&CK 框架基础

---

## Part A：攻击视角 — 红队如何利用情报

### 1. 开源情报收集（OSINT）用于攻击规划

红队使用与蓝队相同的情报源，但目的不同：识别目标暴露面、技术栈、已知漏洞模式。

```bash
# 使用 theHarvester 收集目标信息
theHarvester -d target.com -b all -l 500

# 使用 SpiderFoot 自动化 OSINT
spiderfoot -l 127.0.0.1:5001
# Web UI 中添加目标，启用所有模块

# 使用 Shodan 发现暴露资产
shodan search "org:\"Target Corp\"" --fields ip_str,port,product
shodan count "http.title:\"Dashboard\" org:\"Target\""

# 使用 crt.sh 查找子域名证书
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# GitHub dorking 查找泄露凭证
gitdorker -tf tokens.txt -q "target.com" -d gitdorks/dork_list.txt
```

### 2. 威胁情报源攻击性利用

```python
# 从 MITRE ATT&CK 查找特定技术的检测弱点
# 红队：找到未被检测覆盖的 TTP
from mitreattack.stix20 import MitreAttackData

attack_data = MitreAttackData("enterprise-attack.json")
# 查找与目标行业相关的技术
techniques = attack_data.get_techniques()
for t in techniques:
    # 查找检测数据为空的技术（蓝队未覆盖）
    if not t.get("x_mitre_detection"):
        print(f"[Weak Detection] {t['name']} - {t['id']}")
```

### 3. 利用情报共享延迟

红队利用情报共享中的时间差（从发现到共享可能滞后数天到数周）：

```
时间线攻击窗口分析：
  T0: 新漏洞/技术出现
  T1: 研究人员发现（T0+数天）
  T2: 情报产生 IOC/TTP（T1+数小时）
  T3: 情报通过 TAXII 共享（T2+数小时到数天）
  T4: 蓝队消费并部署检测（T3+数天）
  
  攻击窗口 = T4 - T0（通常 1-4 周）
  红队策略：使用最新披露但尚未被广泛防御的技术
```

---

## Part B：防御视角 — 情报平台建设与运营

### 4. 情报生命周期管理

```
┌──────────────────────────────────────────────────────────┐
│              情报生命周期 (Intelligence Lifecycle)           │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────┐   ┌─────┐   ┌─────┐   ┌─────┐   ┌─────┐     │
│  │规划  │──→│收集  │──→│处理  │──→│分析  │──→│传播  │     │
│  │Plan │   │Collect│  │Process│ │Analyze│ │Dissem│     │
│  └──┬──┘   └─────┘   └─────┘   └─────┘   └──┬──┘     │
│     │         ↑                              │          │
│     └─────────┴──── 反馈 (Feedback) ─────────┘          │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

#### 4.1 规划阶段 — 定义情报需求 (PIR)

```yaml
# intelligence_requirements.yaml
requirements:
  strategic:
    - "本行业最新威胁行为者及其动机"
    - "地缘政治对网络威胁的影响"
    - "新兴攻击技术趋势（季度更新）"
  
  operational:
    - "针对本组织或同行业的活跃攻击活动"
    - "关键供应链伙伴的威胁态势"
    - "正在被利用的 CVE（24h 内通知）"
  
  tactical:
    - "与组织 IP/域名范围相关的 IOC"
    - "新发现的恶意软件家族及哈希"
    - "钓鱼域名和 C2 基础设施"
  
  priority_intelligence_requirements:
    PIR_001:
      question: "哪些 APT 组织正在攻击我们所在行业？"
      consumer: "CISO / 安全总监"
      update_frequency: "月度"
      sources: ["MITRE ATT&CK", "厂商报告", "ISAC"]
    
    PIR_002:
      question: "有哪些活跃的 IOC 与我们的资产重叠？"
      consumer: "SOC 分析师"
      update_frequency: "实时"
      sources: ["MISP feeds", "STIX/TAXII", "商业情报源"]
```

#### 4.2 收集阶段 — 多源情报接入

```python
# multi_source_collector.py — 多源情报收集器
import requests
import json
from datetime import datetime, timedelta

class ThreatIntelCollector:
    """从多个开源情报源收集 IOC"""
    
    def __init__(self, output_dir="./collected_iocs"):
        self.output_dir = output_dir
        self.sources = {
            "abuse_ch_malwarebazaar": self._collect_malwarebazaar,
            "abuse_ch_feodotracker": self._collect_feodotracker,
            "abuse_ch_threatfox": self._collect_threatfox,
            "alienvault_otx": self._collect_otx,
            "virustotal": self._collect_virustotal,
        }
    
    def collect_all(self):
        all_iocs = []
        for name, collector in self.sources.items():
            try:
                iocs = collector()
                all_iocs.extend(iocs)
                print(f"[+] {name}: collected {len(iocs)} IOCs")
            except Exception as e:
                print(f"[-] {name}: failed - {e}")
        return all_iocs
    
    def _collect_malwarebazaar(self):
        """从 MalwareBazaar 获取近期恶意样本哈希"""
        resp = requests.post("https://mb-api.abuse.ch/api/v1/", 
            data={"query": "get_recent", "selector": "time"})
        data = resp.json()
        iocs = []
        for entry in data.get("data", [])[:100]:
            iocs.append({
                "type": "sha256_hash",
                "value": entry["sha256_hash"],
                "source": "malwarebazaar",
                "tags": entry.get("tags", []),
                "signature": entry.get("signature", ""),
                "timestamp": entry.get("first_seen_utc", "")
            })
        return iocs
    
    def _collect_feodotracker(self):
        """从 Feodo Tracker 获取 C2 服务器"""
        resp = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
        data = resp.json()
        return [{
            "type": "ipv4",
            "value": entry.get("ip_address", entry.get("ip")),
            "source": "feodotracker",
            "malware": entry.get("malware", ""),
            "timestamp": entry.get("date", "")
        } for entry in data]
    
    def _collect_threatfox(self):
        """从 ThreatFox 获取 IOC"""
        resp = requests.post("https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_recent", "days": 7})
        data = resp.json()
        iocs = []
        for entry in data.get("data", []):
            iocs.append({
                "type": entry.get("ioc_type", ""),
                "value": entry.get("ioc", ""),
                "source": "threatfox",
                "malware": entry.get("malware_printable", ""),
                "confidence": entry.get("confidence_level", 0),
                "timestamp": entry.get("first_seen_utc", "")
            })
        return iocs
    
    def _collect_otx(self, api_key="YOUR_OTX_KEY"):
        """从 AlienVault OTX 获取订阅脉冲"""
        headers = {"X-OTX-API-KEY": api_key}
        resp = requests.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers=headers)
        pulses = resp.json().get("results", [])
        iocs = []
        for pulse in pulses[:20]:
            for indicator in pulse.get("indicators", []):
                iocs.append({
                    "type": indicator.get("indicator_type", "").split(" ")[0].lower(),
                    "value": indicator.get("indicator", ""),
                    "source": f"otx:{pulse['name']}",
                    "pulse_id": pulse.get("id", ""),
                    "timestamp": pulse.get("modified", "")
                })
        return iocs
    
    def _collect_virustotal(self, api_key="YOUR_VT_KEY"):
        """VirusTotal 情报收集（按配额）"""
        # VT 主要用于查询验证，不用于批量拉取
        return []

# 运行收集器
if __name__ == "__main__":
    collector = ThreatIntelCollector()
    iocs = collector.collect_all()
    with open(f"collected_iocs_{datetime.now().strftime('%Y%m%d')}.json", "w") as f:
        json.dump(iocs, f, indent=2)
    print(f"\n[*] Total: {len(iocs)} IOCs collected")
```

#### 4.3 处理阶段 — 数据标准化与富化

```python
# ioc_processor.py — IOC 标准化与富化
import hashlib
import re
from datetime import datetime

class IOCProcessor:
    """处理、标准化、富化、去重 IOC"""
    
    # STIX 2.1 类型映射
    TYPE_MAP = {
        "ipv4": "ipv4-addr",
        "ipv6": "ipv6-addr",
        "domain": "domain-name",
        "url": "url",
        "sha256_hash": "file",  # 需要 hashes 子对象
        "sha1_hash": "file",
        "md5_hash": "file",
        "email": "email-addr",
    }
    
    def normalize(self, ioc_list):
        """标准化所有 IOC 到统一格式"""
        normalized = []
        seen = set()  # (type, value) 去重
        
        for ioc in ioc_list:
            key = (ioc["type"], ioc["value"])
            if key in seen:
                continue
            seen.add(key)
            
            # 类型推断（如果 type 缺失或不准确）
            ioc["type"] = self._infer_type(ioc["value"])
            
            # 标准化值
            ioc["value"] = self._normalize_value(ioc["type"], ioc["value"])
            
            # 添加处理时间戳
            ioc["processed_at"] = datetime.utcnow().isoformat()
            ioc["stix_type"] = self.TYPE_MAP.get(ioc["type"], "unknown")
            
            normalized.append(ioc)
        
        return normalized
    
    def _infer_type(self, value):
        """自动推断 IOC 类型"""
        # IPv4
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            return "ipv4"
        # IPv6
        if re.match(r'^[0-9a-fA-F:]+$', value) and ':' in value:
            return "ipv6"
        # Hash
        if re.match(r'^[a-fA-F0-9]{64}$', value):
            return "sha256_hash"
        if re.match(r'^[a-fA-F0-9]{40}$', value):
            return "sha1_hash"
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return "md5_hash"
        # URL
        if value.startswith(('http://', 'https://')):
            return "url"
        # Email
        if re.match(r'^[^@]+@[^@]+\.[^@]+$', value):
            return "email"
        # Domain（最后判断）
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$', value):
            return "domain"
        return "unknown"
    
    def _normalize_value(self, ioc_type, value):
        """标准化值格式"""
        if ioc_type in ("ipv4", "ipv6"):
            return value.strip()
        if ioc_type in ("domain", "email"):
            return value.lower().strip()
        if ioc_type == "url":
            return value.rstrip("/")
        if ioc_type in ("sha256_hash", "sha1_hash", "md5_hash"):
            return value.lower()
        return value
```

#### 4.4 分析阶段 — TTP 提取与 ATT&CK 映射

```python
# attack_mapper.py — 将情报映射到 MITRE ATT&CK
import requests

class AttackMapper:
    """将 IOC/TTP 映射到 ATT&CK 框架"""
    
    ATTCK_TECHNIQUE_MAP = {
        # 恶意软件家族 → 典型技术映射
        "TrickBot": ["T1566.001", "T1059.001", "T1005", "T1056.001", "T1115"],
        "Emotet":   ["T1566.001", "T1204.002", "T1059.001", "T1027"],
        "Cobalt Strike": ["T1059.001", "T1053.005", "T1547.001", "T1071.001", "T1573.002"],
        "QakBot":   ["T1566.001", "T1059.001", "T1056.001", "T1115", "T1021.001"],
        "IcedID":   ["T1566.001", "T1204.002", "T1059.001", "T1027"],
        "Ryuk":     ["T1486", "T1490", "T1059.001", "T1027"],
        "LockBit":  ["T1486", "T1490", "T1059.001", "T1078", "T1087"],
        "Conti":    ["T1486", "T1490", "T1059.001", "T1021.001", "T1078"],
    }
    
    def map_malware_to_techniques(self, malware_name):
        """根据恶意软件名称映射 ATT&CK 技术"""
        for key, techniques in self.ATTCK_TECHNIQUE_MAP.items():
            if key.lower() in malware_name.lower():
                return techniques
        return []
    
    def map_iocs_to_attack(self, ioc_list):
        """为 IOC 列表添加 ATT&CK 映射"""
        for ioc in ioc_list:
            malware = ioc.get("malware", "")
            if malware:
                ioc["attack_techniques"] = self.map_malware_to_techniques(malware)
            else:
                ioc["attack_techniques"] = []
        return ioc_list
    
    def generate_attack_heatmap(self, ioc_list):
        """生成 ATT&CK 覆盖热图数据"""
        technique_count = {}
        for ioc in ioc_list:
            for t in ioc.get("attack_techniques", []):
                technique_count[t] = technique_count.get(t, 0) + 1
        
        # 排序返回
        return sorted(technique_count.items(), key=lambda x: x[1], reverse=True)
```

#### 4.5 传播阶段 — 自动化分发

```python
# disseminate.py — 将处理后的 IOC 分发到防御工具
import json
import subprocess

class IOCDisseminator:
    """将 IOC 推送到各种防御平台"""
    
    def push_to_firewall(self, iocs, firewall_type="pf"):
        """生成防火墙阻断规则"""
        ips = [i["value"] for i in iocs if i["type"] == "ipv4"]
        domains = [i["value"] for i in iocs if i["type"] == "domain"]
        
        rules = []
        if firewall_type == "pf":
            for ip in ips:
                rules.append(f"block in quick from {ip} to any")
                rules.append(f"block out quick from any to {ip}")
        elif firewall_type == "iptables":
            for ip in ips:
                rules.append(f"iptables -A INPUT -s {ip} -j DROP")
                rules.append(f"iptables -A OUTPUT -d {ip} -j DROP")
        elif firewall_type == "checkpoint":
            for ip in ips:
                rules.append(f"add rule type=drop src={ip}")
        
        return "\n".join(rules)
    
    def push_to_sigma(self, iocs):
        """从 IOC 生成 Sigma 检测规则"""
        ips = [i["value"] for i in iocs if i["type"] == "ipv4"]
        domains = [i["value"] for i in iocs if i["type"] == "domain"]
        hashes = [i["value"] for i in iocs if i["type"] in ("sha256_hash", "sha1_hash", "md5_hash")]
        
        sigma_rules = []
        
        if ips:
            sigma_rules.append(self._sigma_template(
                title="Threat Intel - Malicious IP Communication",
                detection={"selection": {"DestinationIp|cidr": ips + ["::/128"]}},
                tags=["attack.command_and_control"]
            ))
        
        if hashes:
            sigma_rules.append(self._sigma_template(
                title="Threat Intel - Known Malicious Hash",
                detection={"selection": {"Hashes|contains": hashes[:50]}},
                tags=["attack.execution"]
            ))
        
        return sigma_rules
    
    def _sigma_template(self, title, detection, tags):
        return {
            "title": title,
            "status": "experimental",
            "description": f"Auto-generated from threat intel feed",
            "author": "CTI Platform",
            "date": datetime.now().strftime("%Y/%m/%d"),
            "logsource": {"category": "network_connection", "product": "firewall"},
            "detection": detection,
            "level": "high",
            "tags": tags
        }
    
    def push_to_siema(self, iocs, siem="splunk"):
        """生成 SIEM 查询"""
        ips = [i["value"] for i in iocs if i["type"] == "ipv4"]
        domains = [i["value"] for i in iocs if i["type"] == "domain"]
        
        if siem == "splunk":
            ip_list = " OR ".join(f'"{ip}"' for ip in ips[:100])
            return f'search (src_ip IN ({ip_list})) OR (dest_ip IN ({ip_list})) | stats count by src_ip, dest_ip, dest_port'
        elif siem == "elastic":
            return {
                "query": {
                    "bool": {
                        "should": [
                            {"terms": {"source.ip": ips[:100]}},
                            {"terms": {"destination.ip": ips[:100]}}
                        ]
                    }
                }
            }
```

#### 4.6 反馈阶段 — 有效性评估

```python
# feedback.py — 情报有效性度量
from datetime import datetime, timedelta

class IntelEffectiveness:
    """度量情报平台效果"""
    
    def __init__(self):
        self.metrics = {
            "collection_rate": 0,       # 每日收集 IOC 数
            "false_positive_rate": 0,    # 误报率
            "detection_coverage": 0,     # ATT&CK 技术覆盖率
            "mean_time_to_alert": 0,     # 从情报到告警的平均时间
            "actionable_ratio": 0,       # 可操作情报比例
        }
    
    def calculate_effectiveness(self, iocs, alerts, detections):
        """计算情报效果指标"""
        total = len(iocs)
        if total == 0:
            return self.metrics
        
        # 命中率：IOC 触发告警的比例
        triggered = sum(1 for ioc in iocs if ioc.get("triggered_alert", False))
        self.metrics["hit_rate"] = triggered / total * 100
        
        # 误报率
        false_positives = sum(1 for ioc in iocs if ioc.get("is_false_positive", False))
        self.metrics["false_positive_rate"] = false_positives / total * 100
        
        # 时效性：情报产生到本地部署的时间
        deploy_times = []
        for ioc in iocs:
            if ioc.get("deployed_at") and ioc.get("source_timestamp"):
                dt = datetime.fromisoformat(ioc["deployed_at"]) - \
                     datetime.fromisoformat(ioc["source_timestamp"])
                deploy_times.append(dt.total_seconds() / 3600)
        
        if deploy_times:
            self.metrics["mean_time_to_deploy_hours"] = sum(deploy_times) / len(deploy_times)
        
        return self.metrics
```

### 5. MISP 平台部署与运维

#### 5.1 Docker 快速部署

```bash
# 使用 Docker Compose 部署 MISP
git clone https://github.com/MISP/misp-docker
cd misp-docker

# 配置环境变量
cat > .env << 'EOF'
MISP_HOST=https://misp.yourorg.local
MYSQL_ROOT_PASSWORD=ChangeMeStrongPassword123!
MISP_ADMIN_EMAIL=admin@yourorg.local
MISP_ADMIN_PASSWORD=ChangeMeAdminPassword123!
MISP_ORG=YourOrg
EOF

# 启动
docker compose up -d

# 验证
docker compose ps
curl -k https://localhost/users/login
```

#### 5.2 MISP 情报源配置

```python
# misp_feed_manager.py — 管理 MISP Feed
from pymisp import PyMISP

misp = PyMISP("https://misp.yourorg.local", "YOUR_API_KEY", False)

# 启用内置 Feed
BUILTIN_FEEDS = [
    "CIRCL OSINT Feed",
    "Malware Bazaar",
    "Abuse.ch Feodo Tracker",
    "ThreatFox",
    "URLhaus",
    "Botvrij.eu",
    "blocklist.de",
    "hydrabox",
]

for feed_name in BUILTIN_FEEDS:
    feeds = misp.search_feeds(value=feed_name)
    if feeds:
        feed = feeds[0]
        misp.toggle_feed(feed["Feed"]["id"], enable=True)
        print(f"[+] Enabled: {feed_name}")

# 添加自定义 STIX Feed
misp.add_feed({
    "Feed": {
        "name": "Custom ISAC STIX Feed",
        "provider": "My ISAC",
        "url": "https://isac.example.org/taxii2/collections/abc/objects/",
        "input_source": "network",
        "source_format": "misp",
        "enabled": True,
        "distribution": 0,  # Your organization only
        "tag_id": 1,
        "override_ids": True,  # 自动将 IOC 添加到 IDS 列表
    }
})
```

#### 5.3 MISP 自动化：Taxonomy 与 Tagging

```python
# misp_tagging.py — 自动标记和分类
from pymisp import PyMISP, MISPEvent

misp = PyMISP("https://misp.yourorg.local", "YOUR_API_KEY", False)

# 为事件添加 ATT&CK 标签
def tag_with_attack(event_id, techniques):
    """为 MISP 事件添加 ATT&CK 技术标签"""
    for technique in techniques:
        tag = f'misp-galaxy:mitre-attack-pattern="{technique["name"]} - {technique["id"]}"'
        misp.tag(event_id, tag)
    
    # 添加威胁.actor 标签（如果有）
    # misp.tag(event_id, 'misp-galaxy:threat-actor="APT29"')

# 创建新事件并自动标记
event = MISPEvent()
event.info = "Phishing Campaign Targeting Finance Dept - Q2 2026"
event.distribution = 0  # Org only
event.threat_level_id = 2  # Medium
event.analysis = 2  # Completed

# 添加 IOC
event.add_attribute("ip-dst", "198.51.100.23", comment="Phishing C2")
event.add_attribute("domain", "secure-docs-verify.com", comment="Phishing domain")
event.add_attribute("email-subject", "Urgent: Invoice Payment Required", comment="Phishing subject")
event.add_attribute("sha256", "abc123...", comment="Attachment hash")

# 添加标签
event.add_tag("tlp:amber")  # TLP 标记
event.add_tag("type:phishing")
event.add_tag("sector:financial")

result = misp.add_event(event)
print(f"[+] Event created: {result['Event']['id']}")
```

### 6. STIX/TAXII 标准化数据交换

#### 6.1 STIX 2.1 对象生成

```python
# stix_generator.py — 生成 STIX 2.1 对象
from stix2 import (
    Indicator, Malware, AttackPattern, Relationship,
    Bundle, ThreatActor, IntrusionSet, Campaign,
    IPv4Address, DomainName, File, URL
)
from datetime import datetime, timedelta

def create_stix_bundle_from_iocs(iocs, threat_actor_name="Unknown"):
    """从 IOC 列表创建完整的 STIX 2.1 Bundle"""
    
    objects = []
    
    # 1. 创建 Indicator 对象
    for ioc in iocs:
        pattern = _create_pattern(ioc)
        if not pattern:
            continue
        
        indicator = Indicator(
            name=f"{ioc['type']}: {ioc['value']}",
            description=f"Source: {ioc.get('source', 'unknown')}, "
                       f"Malware: {ioc.get('malware', 'unknown')}",
            pattern=pattern,
            pattern_type="stix",
            valid_from=datetime.utcnow(),
            valid_until=datetime.utcnow() + timedelta(days=90),
            labels=["malicious-activity"],
            confidence=_map_confidence(ioc.get("confidence", 50)),
            kill_chain_phases=_map_kill_chain(ioc.get("attack_techniques", [])),
        )
        objects.append(indicator)
    
    # 2. 创建 Malware 对象
    malware_names = set(ioc.get("malware", "") for ioc in iocs if ioc.get("malware"))
    malware_objects = []
    for name in malware_names:
        malware = Malware(
            name=name,
            is_family=True,
            labels=["remote-access-trojan"],
        )
        objects.append(malware)
        malware_objects.append(malware)
    
    # 3. 创建关系
    for indicator in objects[:len(iocs)]:
        for malware in malware_objects:
            rel = Relationship(
                relationship_type="indicates",
                source_ref=indicator.id,
                target_ref=malware.id,
            )
            objects.append(rel)
    
    # 4. 打包
    bundle = Bundle(objects=objects)
    return bundle

def _create_pattern(ioc):
    """根据 IOC 类型生成 STIX pattern"""
    patterns = {
        "ipv4": f"[ipv4-addr:value = '{ioc['value']}']",
        "ipv6": f"[ipv6-addr:value = '{ioc['value']}']",
        "domain": f"[domain-name:value = '{ioc['value']}']",
        "url": f"[url:value = '{ioc['value']}']",
        "sha256_hash": f"[file:hashes.'SHA-256' = '{ioc['value']}']",
        "sha1_hash": f"[file:hashes.'SHA-1' = '{ioc['value']}']",
        "md5_hash": f"[file:hashes.'MD5' = '{ioc['value']}']",
        "email": f"[email-addr:value = '{ioc['value']}']",
    }
    return patterns.get(ioc["type"], "")

def _map_confidence(value):
    """映射置信度到 STIX 标准"""
    if isinstance(value, str):
        value = int(value)
    if value >= 80: return 95  # High
    if value >= 50: return 75  # Medium
    return 30  # Low

def _map_kill_chain(techniques):
    """映射到 kill chain phases"""
    if not techniques:
        return []
    phases = []
    kc_map = {
        "T1566": "initial-access",
        "T1059": "execution",
        "T1053": "persistence",
        "T1071": "command-and-control",
        "T1486": "impact",
        "T1005": "collection",
        "T1078": "defense-evasion",
    }
    for t in techniques:
        prefix = t.split(".")[0]
        if prefix in kc_map and kc_map[prefix] not in phases:
            phases.append(kc_map[prefix])
    return [{"kill_chain_name": "mitre-attack", "phase_name": p} for p in phases]

# 使用
bundle = create_stix_bundle_from_iocs(iocs)
print(bundle.serialize(pretty=True))
```

#### 6.2 TAXII 服务器部署（OpenTAXII）

```bash
# Docker 部署 OpenTAXII
docker run -d \
  --name opentaxii \
  -p 9000:9000 \
  -e TAXII_AUTH_SECRET=your-secret-key \
  -e TAXII_DB=sqlite:////data/taxii.db \
  -v taxii_data:/data \
  eclecticiq/opentaxii

# 创建 API Root 和 Collection
curl -X POST http://localhost:9000/api/manage/api-roots \
  -H "Authorization: Bearer your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "cti-feed",
    "title": "CTI Intelligence Feed",
    "description": "Primary threat intel feed"
  }'

curl -X POST http://localhost:9000/api/manage/collections \
  -H "Authorization: Bearer your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "stix-indicators",
    "title": "STIX Indicators",
    "description": "IOC indicators in STIX 2.1 format",
    "can_read": true,
    "can_write": true,
    "media_types": ["application/stix+json;version=2.1"]
  }'
```

```python
# taxii_client.py — TAXII 客户端推送/拉取
from taxii2client.v20 import Collection, Server

# 推送 STIX 对象到 TAXII Server
collection_url = "http://localhost:9000/api/cti-feed/collections/stix-indicators/"
collection = Collection(collection_url, user="admin", password="password")

# 推送
bundle = create_stix_bundle_from_iocs(iocs)
collection.add_objects(bundle.serialize(pretty=True))
print("[+] Pushed to TAXII server")

# 拉取
objects = collection.get_objects()
print(f"[*] Retrieved {len(objects['objects'])} objects")
```

### 7. OpenCTI 平台部署

```bash
# Docker Compose 部署 OpenCTI
git clone https://github.com/OpenCTI-Platform/docker
cd docker

# 配置 .env
cat > .env << 'EOF'
OPENCTI_ADMIN_EMAIL=admin@yourorg.local
OPENCTI_ADMIN_PASSWORD=ChangeMeAdminPassword123!
OPENCTI_ADMIN_TOKEN=ChangeMeToken123!
ELASTICSEARCH_URL=http://elastic:9200
MINIO_ENDPOINT=minio:9000
REDIS_HOSTNAME=redis
REDIS_PORT=6379
EOF

docker compose up -d

# 访问
# https://localhost:8080
```

```python
# opencti_client.py — OpenCTI Python SDK
from pycti import OpenCTIApiHelper

# 连接
helper = OpenCTIApiHelper(
    "https://localhost:8080",
    "ChangeMeToken123!"
)

# 创建并关联对象
threat_actor = helper.api.threat_actor.create(
    name="APT-DEMO",
    description="Demo threat actor for testing",
    primary_motivation="financial",
)

malware = helper.api.malware.create(
    name="DEMO-MALWARE",
    is_family=True,
    description="Demo malware family",
)

indicator = helper.api.indicator.create(
    name="Malicious IP",
    pattern_type="stix",
    pattern="[ipv4-addr:value = '198.51.100.23']",
    x_opencti_main_observable_type="IPv4-Addr",
)

# 创建关系
helper.api.stix_core_relationship.create(
    fromId=threat_actor["id"],
    toId=malware["id"],
    relationship_type="uses",
)

helper.api.stix_core_relationship.create(
    fromId=indicator["id"],
    toId=malware["id"],
    relationship_type="indicates",
)
```

### 8. 情报源质量评估框架

```python
# feed_evaluator.py — 评估情报源质量
class FeedEvaluator:
    """情报源质量评估"""
    
    CRITERIA = {
        "timeliness": {         # 时效性
            "weight": 0.25,
            "metrics": ["avg_delay_hours", "update_frequency"]
        },
        "accuracy": {           # 准确性
            "weight": 0.25,
            "metrics": ["false_positive_rate", "verified_ratio"]
        },
        "relevance": {          # 相关性
            "weight": 0.20,
            "metrics": ["hit_rate", "industry_match"]
        },
        "completeness": {       # 完整性
            "weight": 0.15,
            "metrics": ["coverage_ratio", "context_richness"]
        },
        "reliability": {        # 可靠性
            "weight": 0.15,
            "metrics": ["uptime", "source_reputation"]
        }
    }
    
    def evaluate_feed(self, feed_name, stats):
        """评估单个情报源"""
        scores = {}
        total = 0
        
        for criterion, config in self.CRITERIA.items():
            score = self._calculate_criterion(criterion, stats)
            scores[criterion] = score
            total += score * config["weight"]
        
        return {
            "feed": feed_name,
            "total_score": round(total, 2),
            "grade": self._score_to_grade(total),
            "details": scores,
            "recommendation": self._recommend(total, stats)
        }
    
    def _calculate_criterion(self, criterion, stats):
        """计算各维度得分 (0-100)"""
        if criterion == "timeliness":
            delay = stats.get("avg_delay_hours", 24)
            if delay <= 1: return 95
            if delay <= 4: return 80
            if delay <= 12: return 60
            if delay <= 24: return 40
            return 20
        
        if criterion == "accuracy":
            fp_rate = stats.get("false_positive_rate", 50)
            return max(0, 100 - fp_rate * 2)
        
        if criterion == "relevance":
            hit_rate = stats.get("hit_rate", 0)
            return min(100, hit_rate * 10)
        
        if criterion == "completeness":
            context = stats.get("context_richness", 0.5)
            return context * 100
        
        if criterion == "reliability":
            uptime = stats.get("uptime", 95)
            return uptime
        
        return 50
    
    def _score_to_grade(self, score):
        if score >= 85: return "A (Excellent)"
        if score >= 70: return "B (Good)"
        if score >= 55: return "C (Average)"
        if score >= 40: return "D (Below Average)"
        return "F (Poor)"
    
    def _recommend(self, score, stats):
        if score >= 70:
            return "KEEP - High-value feed, maintain current subscription"
        if score >= 50:
            return "REVIEW - Moderate value, consider tuning filters"
        return "DROP - Low value, investigate replacement"

# 使用示例
evaluator = FeedEvaluator()
result = evaluator.evaluate_feed("AlienVault OTX", {
    "avg_delay_hours": 2,
    "false_positive_rate": 15,
    "hit_rate": 8,
    "context_richness": 0.7,
    "uptime": 99.5,
})
print(result)
```

### 9. 情报老化与退役策略

```python
# ioc_lifecycle.py — IOC 老化管理
from datetime import datetime, timedelta

class IOCLifecycleManager:
    """管理 IOC 的整个生命周期"""
    
    # 不同类型 IOC 的有效期
    LIFESPAN = {
        "ipv4": timedelta(days=30),        # IP 变化快
        "domain": timedelta(days=90),       # 域名相对稳定
        "url": timedelta(days=30),          # URL 可能被移除
        "sha256_hash": timedelta(days=365), # 文件哈希长期有效
        "email": timedelta(days=60),        # 邮箱可能被关闭
    }
    
    def __init__(self, db_connection):
        self.db = db_connection
    
    def check_expiration(self):
        """检查过期 IOC"""
        now = datetime.utcnow()
        expired = []
        expiring_soon = []
        
        for ioc in self.db.get_all_iocs():
            lifespan = self.LIFESPAN.get(ioc["type"], timedelta(days=30))
            created = datetime.fromisoformat(ioc["created_at"])
            expires_at = created + lifespan
            
            if now >= expires_at:
                expired.append(ioc)
            elif now >= expires_at - timedelta(days=7):
                expiring_soon.append(ioc)
        
        return {
            "expired": expired,
            "expiring_soon": expiring_soon,
            "action_required": len(expired) + len(expiring_soon)
        }
    
    def auto_retire(self, iocs_to_retire):
        """自动退役过期 IOC"""
        for ioc in iocs_to_retire:
            # 在部署的防御工具中移除
            # 1. 从防火墙规则中删除
            # 2. 从 SIEM watchlist 中移除
            # 3. 标记为 retired
            self.db.update_ioc(ioc["id"], {
                "status": "retired",
                "retired_at": datetime.utcnow().isoformat(),
                "retired_reason": "auto_expiration"
            })
```

---

## 速查表

### 情报平台选型矩阵

| 平台 | 优势 | 劣势 | 适用场景 | 成本 |
|------|------|------|---------|------|
| **MISP** | 社区生态强、Feed 丰富、共享成熟 | UI 一般、自定义报表弱 | ISAC/联盟共享、SOC 集成 | 免费 |
| **OpenCTI** | 现代化 UI、STIX 2.1 原生、可视化强 | 资源消耗大（ES+Redis+MinIO） | 企业级 CTI 管理、攻击链分析 | 免费 |
| **ThreatConnect** | 商业支持、SOAR 集成 | 费用高、定制性弱 | 大型企业、需要商业支持 | 商业 |
| **ThreatQuotient** | Analyst 工作流好 | 扩展性一般 | SOC 分析师工作台 | 商业 |
| **Anomali ThreatStream** | 云原生、集成广 | 数据主权问题 | 云优先企业 | 商业 |

### STIX 2.1 核心对象速查

| 对象类型 | 用途 | 关键字段 |
|---------|------|---------|
| `indicator` | 可观测指标 | pattern, pattern_type, valid_from |
| `malware` | 恶意软件家族 | name, is_family, malware_types |
| `attack-pattern` | 攻击技术 | name, kill_chain_phases |
| `threat-actor` | 威胁行为者 | name, sophistication, resource_level |
| `intrusion-set` | 入侵集合（APT组） | name, primary_motivation |
| `campaign` | 攻击活动 | name, first_seen, last_seen |
| `tool` | 使用的工具 | name, tool_types |
| `vulnerability` | 漏洞 | name, external_references (CVE) |
| `relationship` | 对象间关系 | relationship_type, source_ref, target_ref |

### 情报共享标准 (TLP)

| TLP 等级 | 含义 | 共享范围 |
|----------|------|---------|
| `TLP:CLEAR` | 可公开 | 无限制 |
| `TLP:GREEN` | 社区共享 | 特定社区/行业 |
| `TLP:AMBER` | 有限共享 | 仅本组织 + 需要知道的伙伴 |
| `TLP:AMBER+STRICT` | 严格有限 | 仅本组织 |
| `TLP:RED` | 仅个人 | 仅情报生产者和消费者本人 |

### ATT&CK 情报映射矩阵

```
                战略情报    运营情报    战术情报
                (Strategic) (Operational) (Tactical)
─────────────────────────────────────────────────
Threat Actor    高层级分析  活跃组织    关联IOC
Malware Family  趋势分析    活跃家族    Hash/行为
TTP/Technique   技术趋势    活跃技术    检测规则
Vulnerability   漏洞趋势    活跃利用    CVE/POC
Infrastructure  基础设施趋势  C2/CDN    IP/域名/SSL
```

---

## MITRE ATT&CK 映射

| 战术 | 相关技术 | 情报应用 |
|------|---------|---------|
| Reconnaissance | T1595 Active Scanning | 从 C2 基础设施 IP 反推侦察源 |
| Resource Development | T1583 Acquire Infrastructure | 追踪恶意基础设施注册模式 |
| Initial Access | T1566 Phishing | 钓鱼域名/发件人 IOC 共享 |
| Execution | T1059 Command Scripting | 恶意脚本哈希共享 |
| Persistence | T1053 Scheduled Task | 持久化机制 IOC 交换 |
| C2 | T1071 Application Layer Protocol | C2 通信模式/域名共享 |
| Exfiltration | T1048 Alternative Protocol | 数据外泄行为指标共享 |

---

## 前置条件

1. **基础设施**：Docker/K8s 环境、4C8G 以上服务器（MISP 最小），16C32G（OpenCTI 推荐）
2. **网络**：能访问情报源 API（VirusTotal、OTX、Abuse.ch 等）、TAXII 端点
3. **技能**：Python 编程、MITRE ATT&CK 框架理解、STIX/TAXII 标准
4. **组织**：定义好的 PIR（优先情报需求）、TLP 共享协议、情报团队角色
5. **集成**：SIEM（Splunk/Elastic）、SOAR（Cortex XSOAR/Shuffle）、防火墙/EDR API

---

## C. 补充章节（2025-2026 联网更新）

### C.1 平台生态重大更新

#### C.1.1 OpenCTI 7.0（2025-2026）

OpenCTI 7.0 是 Filigran 发布的最新主版本，带来多项重大变更：

| 特性 | 说明 |
|------|------|
| **长期支持 (LTS)** | 首次提供企业级 LTS 版本，稳定维护周期延长 |
| **Filigran XTM 浏览器扩展** | 浏览器内直接上下文关联威胁情报，分析师无需切换窗口 |
| **RBAC 改进** | 细粒度权限控制，支持组织级/工作组级访问策略 |
| **Enterprise Edition** | 新增自动化 Playbook、PIR（优先情报需求）、FINTEL（Finished Intelligence）报告功能 |
| **AI 辅助分析** | 6.8 引入 AI 驱动的 IOC 富化与关系建议；7.0 进一步集成 |

```bash
# OpenCTI 7.0 Docker 部署（更新版）
git clone https://github.com/OpenCTI-Platform/docker
cd docker
git checkout 7.x  # 切换到 7.x 分支

cat > .env << 'EOF'
OPENCTI_ADMIN_EMAIL=admin@yourorg.local
OPENCTI_ADMIN_PASSWORD=ChangeMeAdminPassword123!
OPENCTI_ADMIN_TOKEN=ChangeMeToken123!
ELASTICSEARCH_URL=http://elastic:9200
MINIO_ENDPOINT=minio:9000
REDIS_HOSTNAME=redis
REDIS_PORT=6379
# Enterprise Edition（可选）
OPENCTI_ENTERPRISE_LICENSE=your-license-key
EOF

docker compose up -d
```

```python
# OpenCTI 7.0 PIR（优先情报需求）API 使用
from pycti import OpenCTIApiClient

client = OpenCTIApiClient("https://localhost:8080", "YOUR_TOKEN")

# 创建 PIR
pir = client.put_pir({
    "name": "检测针对金融行业的钓鱼活动",
    "description": "关注针对银行/证券行业的钓鱼域名和C2基础设施",
    "priority": "high",
    "filters": {
        "objectMarking": ["TLP:GREEN"],
        "objectLabel": ["phishing", "financial"],
        "targets": ["sector:financial"]
    },
    "auto_trigger": True,  # 自动触发相关IOC收集
})
print(f"[+] PIR created: {pir['id']}")
```

#### C.1.2 MISP 2.5.x（2025-2026 重大更新）

MISP 2.5 分支是一次重大 UI/UX 重构：

| 版本/特性 | 说明 |
|-----------|------|
| **2.5.39**（当前稳定） | 全新仪表盘体验、分析师专用 Widget、STIX 增强支持 |
| **UI/UX 全面改造** | 从 2.4 到 2.5 的最大变更：现代化界面、改善分析师工作流 |
| **搜索引擎重构** | 全新搜索体验，支持更复杂的查询语法 |
| **API 增强** | REST API 扩展，更完善的批量操作支持 |
| **关联引擎优化** | 底层关联引擎性能提升，大数据量下更快 |
| **后台处理现代化** | 后台任务队列重构，提升大规模Feed处理效率 |

```bash
# MISP 2.5.x Docker 部署更新
git clone https://github.com/MISP/misp-docker
cd misp-docker
git pull  # 确保获取最新 2.5 版本

# 配置
cat > .env << 'EOF'
MISP_HOST=https://misp.yourorg.local
MYSQL_ROOT_PASSWORD=ChangeMeStrongPassword123!
MISP_ADMIN_EMAIL=admin@yourorg.local
MISP_ADMIN_PASSWORD=ChangeMeAdminPassword123!
MISP_ORG=YourOrg
MISP_MODULE=true  # 启用 MISP 模块（富化、导入导出）
EOF

docker compose pull  # 拉取最新镜像
docker compose up -d

# 验证版本
docker compose exec misp bash -c "cat /var/www/MISP/VERSION.json | jq '.version'"
```

```python
# MISP 2.5 新 Dashboard Widget API
from pymisp import PyMISP

misp = PyMISP("https://misp.yourorg.local", "YOUR_API_KEY", False)

# 利用新的搜索 API（2.5 增强）
# 支持更复杂的布尔查询
events = misp.search(
    tags={"AND": ["tlp:amber", "type:phishing"]},
    threat_level_id=[1, 2],  # High + Medium
    date_from="2025-01-01",
    date_to="2026-06-30",
    pythonify=True,
    metadata=True,  # 仅返回元数据，提升性能
)
print(f"[*] Found {len(events)} matching events")

# 批量添加 ATT&CK 标签（2.5 增强）
for event in events[:10]:
    galaxy_tags = [
        'misp-galaxy:mitre-attack-pattern="Phishing - T1566"',
        'misp-galaxy:sector="Financial"',
    ]
    for tag in galaxy_tags:
        misp.tag(event.uuid, tag)
```

#### C.1.3 2026 情报平台选型矩阵 v2.0

| 平台 | 类型 | 2025-2026 亮点 | 适用场景 | 成本 |
|------|------|---------------|---------|------|
| **MISP 2.5.x** | 开源 | UI/UX重构、Dashboard Widget、搜索增强、关联引擎优化 | ISAC/联盟共享、CERT、社区情报 | 免费 |
| **OpenCTI 7.0** | 开源+企业 | LTS、XTM浏览器、PIR、AI分析、Enterprise Playbook | 企业级CTI、攻击链分析、AI辅助 | 免费/企业版 |
| **Recorded Future** | 商业 | AI驱动优先级排序、Splunk SOAR原生集成、实时风险评分 | 大型企业、需要商业情报+SOAR联动 | 商业 |
| **ThreatConnect** | 商业 | 自适应Playbook、TI Ops（情报运营）工作流 | 情报团队成熟度高、需要SOAR+TIP统一 | 商业 |
| **Anomali ThreatStream** | 商业 | AI+SOAR融合、预测性情报、多云集成 | 云优先企业、需要预判性分析 | 商业 |
| **Cyware** | 商业 | Agentic AI CTI、主动预测、CTIX平台 | 需要AI驱动自主情报分析 | 商业 |
| **微步在线 X情报中心** | 商业(中国) | 国内最大综合性威胁分析平台、域名/IP反查、行业情报 | 中国企业、合规驱动、本地化 | 商业 |
| **奇安信 TIP/ALPHA** | 商业(中国) | 本地化部署+API、多源融合(CNVD/CNNVD)、AI化 | 政府/央企/关基、等保合规 | 商业 |

### C.2 AI/LLM 辅助威胁情报分析

#### C.2.1 AI 驱动 CTI 前沿

2025-2026 年 AI/LLM 在 CTI 领域的关键发展：

| 方向 | 进展 | 影响 |
|------|------|------|
| **Agentic AI CTI** | Cyware 等推出自主情报智能体（BlackHat 2025） | 从被动响应→主动预测 |
| **POLAR 框架** | LLM 驱动自动化威胁优先级排序（OpenReview 2025） | 替代人工Triage，提升效率 |
| **CTI→AI 安全** | 攻击AI系统的新型威胁情报（arXiv 2603.05068） | 情报覆盖范围扩展至AI攻击面 |
| **AI 节省成本** | 使用AI/自动化的组织每起数据泄露节省 $1.9M（IBM 2025） | 商业价值量化 |
| **MDPI 综述** | 学术界系统分析AI在CTI架构中的应用（2025） | 理论框架成熟 |

```python
# llm_cti_analyzer.py — LLM 辅助威胁情报分析脚本
"""
使用 LLM API 自动化 CTI 分析工作流：
1. IOC 上下文富化
2. 威胁报告自动摘要
3. TTP 自动提取与 ATT&CK 映射
4. 情报优先级排序
"""

import json
import requests
from datetime import datetime

class LLMCTIAnalyzer:
    """LLM 辅助 CTI 分析"""
    
    def __init__(self, api_endpoint, api_key):
        self.api_endpoint = api_endpoint
        self.api_key = api_key
    
    def enrich_ioc(self, ioc_value, ioc_type):
        """使用 LLM 富化 IOC 上下文"""
        prompt = f"""作为威胁情报分析师，分析以下 IOC：
类型: {ioc_type}
值: {ioc_value}

请提供：
1. 该 IOC 可能关联的恶意软件家族（最新已知）
2. 相关 MITRE ATT&CK 技术（精确到子技术）
3. 可能的威胁行为者
4. 建议的检测规则（Sigma 格式）
5. 置信度评估 (1-100)
6. 该 IOC 的时效性判断（活跃/历史/通用）

以 JSON 格式输出。"""
        
        return self._call_llm(prompt)
    
    def summarize_threat_report(self, report_text):
        """自动摘要威胁报告"""
        prompt = f"""请对以下威胁情报报告进行结构化摘要：

{report_text[:8000]}

输出格式：
{{
  "title": "报告标题",
  "threat_actor": "关联威胁行为者",
  "malware_families": ["家族列表"],
  "target_sectors": ["目标行业"],
  "key_techniques": ["MITRE ATT&CK 技术 ID 列表"],
  "ioc_count": IOC总数,
  "severity": "critical/high/medium/low",
  "tlp": "建议的TLP等级",
  "key_findings": ["发现1", "发现2", "发现3"],
  "defensive_actions": ["建议的防御措施列表"]
}}"""
        
        return self._call_llm(prompt)
    
    def prioritize_intelligence(self, intel_list):
        """基于 POLAR 框架思路，LLM 自动排序情报优先级"""
        prompt = f"""基于以下情报列表，按照 POLAR（Prioritization of Leveraged Analysis Results）
框架进行优先级排序。

排序维度：
1. 紧急性（正在被利用 vs 历史威胁）
2. 相关性（针对本行业 vs 通用）
3. 可操作性（有明确检测/缓解方案 vs 仅有IOC）
4. 置信度（多源验证 vs 单源）
5. 影响范围（广域 vs 定向）

情报列表（前20条摘要）：
{json.dumps([{
    "title": i.get("title", ""),
    "severity": i.get("severity", ""),
    "source": i.get("source", ""),
    "date": i.get("date", ""),
} for i in intel_list[:20]], indent=2)}

输出 JSON 数组，按优先级从高到低排列，每条包含 priority_score (1-100) 和排序理由。"""
        
        return self._call_llm(prompt)
    
    def _call_llm(self, prompt):
        """调用 LLM API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "claude-sonnet-4-6-20250514",
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}]
        }
        try:
            resp = requests.post(
                self.api_endpoint,
                headers=headers,
                json=payload,
                timeout=60
            )
            result = resp.json()
            content = result["content"][0]["text"]
            # 尝试解析 JSON
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            return json.loads(content)
        except Exception as e:
            return {"error": str(e), "raw": content if 'content' in dir() else ""}

# 使用示例
if __name__ == "__main__":
    analyzer = LLMCTIAnalyzer(
        api_endpoint="https://api.anthropic.com/v1/messages",
        api_key="YOUR_API_KEY"
    )
    
    # 富化单个 IOC
    result = analyzer.enrich_ioc("198.51.100.23", "ipv4")
    print(json.dumps(result, indent=2, ensure_ascii=False))
```

#### C.2.2 CTI-Transmute（FIRST CTI 2026）

2026 年 FIRST CTI 大会重点展示的 CTI-Transmute 工具：

- 基于 `misp-stix` 库的灵活转换层
- 解决不同平台间 STIX 格式转换的实际操作难题
- 支持多版本 STIX 互操作（STIX 1.x ↔ 2.0 ↔ 2.1）
- 真实运营环境中的格式兼容性处理

### C.3 情报平台安全漏洞（2025-2026）

#### C.3.1 OpenCTI 关键 CVE

| CVE | 严重性 | 影响范围 | 描述 | 修复版本 |
|-----|--------|---------|------|---------|
| **CVE-2025-61781** | 高危 | < 6.8.1 | 授权绕过：低权限用户可删除工作空间，甚至获取管理员权限 | 6.8.1+ |
| **CVE-2025-24887** | 中高危 | 6.4.8 - 6.4.10 | Allow/Deny 列表绕过，未授权访问受限数据 | 6.4.10+ |

**CVE-2025-61781 缓解检查脚本：**

```bash
#!/bin/bash
# check_opencti_cve-2025-61781.sh
# 检查 OpenCTI 是否受 CVE-2025-61781 影响

echo "[*] Checking OpenCTI version for CVE-2025-61781..."

# 方法1：通过 API 检查版本
VERSION=$(curl -sk -H "Authorization: Bearer $OPENCTI_TOKEN" \
  "$OPENCTI_URL/graphql" \
  -d '{"query":"{ about { version } }"}' | jq -r '.data.about.version')

echo "[*] Current OpenCTI version: $VERSION"

# 版本比较（需要 >= 6.8.1）
MAJOR=$(echo $VERSION | cut -d. -f1)
MINOR=$(echo $VERSION | cut -d. -f2)
PATCH=$(echo $VERSION | cut -d. -f3)

if [ "$MAJOR" -lt 6 ] || \
   [ "$MAJOR" -eq 6 -a "$MINOR" -lt 8 ] || \
   [ "$MAJOR" -eq 6 -a "$MINOR" -eq 8 -a "$PATCH" -lt 1 ]; then
    echo "[!] VULNERABLE - OpenCTI $VERSION is affected by CVE-2025-61781"
    echo "[!] Upgrade to >= 6.8.1 immediately"
    echo "[!] Belgium CCB Advisory: https://ccb.belgium.be/advisories/warning-high-improper-authorization-vulnerability-opencti"
    exit 1
else
    echo "[+] SAFE - OpenCTI $VERSION is not affected by CVE-2025-61781"
    exit 0
fi
```

#### C.3.2 平台安全加固检查清单

```bash
#!/bin/bash
# ctip_security_hardening.sh — CTI平台安全加固检查

echo "=== CTI Platform Security Hardening Check ==="

# 1. HTTPS 强制
echo "[1] Checking HTTPS enforcement..."
curl -sk -o /dev/null -w "%{http_code}" http://$CTIP_HOST && echo " [!] HTTP still accessible" || echo " [+] HTTP redirect OK"

# 2. 认证配置
echo "[2] Checking authentication..."
# MISP: 检查是否启用 MFA
# OpenCTI: 检查 SSO/OIDC 配置

# 3. API Key 轮换
echo "[3] API Key age check..."
for key_file in /etc/ctip/keys/*.json; do
    if [ -f "$key_file" ]; then
        age_days=$(( ($(date +%s) - $(stat -f %m "$key_file" 2>/dev/null || stat -c %Y "$key_file")) / 86400 ))
        if [ $age_days -gt 90 ]; then
            echo "  [!] $key_file: ${age_days} days old - ROTATE NOW"
        fi
    fi
done

# 4. 网络隔离
echo "[4] Checking network isolation..."
# CTI 平台应仅在内部网络可达
# 检查是否有外部可访问的端口

# 5. 日志审计
echo "[5] Checking audit logging..."
# 确保所有 API 调用被记录
# 确保有异常访问告警

# 6. 备份验证
echo "[6] Checking backup status..."
# 验证最新备份时间 < 24h

echo "=== Check Complete ==="
```

### C.4 SOAR + CTI 深度集成

#### C.4.1 2025-2026 SOAR+CTI 集成趋势

| 趋势 | 说明 |
|------|------|
| **Agentic AI SOAR** | 2026年从传统SOAR向AI Agent驱动转变（Prophet Security） |
| **自适应 Playbook** | 根据对手TTP变化动态调整（ThreatConnect TI Ops） |
| **CTI→SOAR 原生集成** | Recorded Future + Splunk SOAR、Anomali + Playbook |
| **自主SOC** | Open XDR + AI驱动的自主安全运营（Stellar Cyber） |

#### C.4.2 CTI→SOAR 自动化 Playbook 示例

```python
# cti_soar_playbook.py — CTI 驱动 SOAR 自动化 Playbook
"""
情报驱动的 SOAR Playbook 架构：
新情报IOC → 自动富化 → 风险评分 → 触发检测/阻断 → 反馈度量
"""

class CTISOARPlaybook:
    """CTI 驱动的 SOAR Playbook"""
    
    def __init__(self, ctip_client, siem_client, firewall_client, soar_client):
        self.ctip = ctip_client      # MISP/OpenCTI
        self.siem = siem_client       # Splunk/Elastic
        self.fw = firewall_client     # Firewall API
        self.soar = soar_client       # SOAR 平台
    
    def execute_new_ioc_playbook(self, ioc):
        """新 IOC 到达时的自动化 Playbook"""
        results = {}
        
        # Step 1: 自动富化
        enrichment = self.ctip.enrich_observable(ioc["value"])
        results["enrichment"] = {
            "vt_score": enrichment.get("vt_malicious", 0),
            "related_malware": enrichment.get("malware_families", []),
            "geo": enrichment.get("geo_country", "Unknown"),
        }
        
        # Step 2: 风险评分（基于多因素）
        risk_score = self._calculate_risk(ioc, enrichment)
        results["risk_score"] = risk_score
        
        # Step 3: 根据风险等级执行不同动作
        if risk_score >= 80:
            # 高风险：立即阻断 + 创建检测规则
            self.fw.block_ip(ioc["value"], reason=f"CTI: {ioc.get('malware', 'unknown')}")
            sigma_rule = self._generate_sigma_rule(ioc)
            self.siem.add_detection_rule(sigma_rule)
            results["action"] = "block_and_detect"
            
        elif risk_score >= 50:
            # 中风险：创建检测规则 + 监控
            sigma_rule = self._generate_sigma_rule(ioc)
            self.siem.add_detection_rule(sigma_rule)
            self.siem.add_to_watchlist(ioc["value"], ioc["type"])
            results["action"] = "detect_and_watch"
            
        else:
            # 低风险：仅添加到观察列表
            self.siem.add_to_watchlist(ioc["value"], ioc["type"])
            results["action"] = "watch_only"
        
        # Step 4: 通知
        if risk_score >= 50:
            self.soar.create_case({
                "title": f"CTI Alert: {ioc['type']} {ioc['value']}",
                "severity": "high" if risk_score >= 80 else "medium",
                "description": f"Risk: {risk_score}, Action: {results['action']}",
                "source": ioc.get("source", "CTI Feed"),
            })
        
        return results
    
    def _calculate_risk(self, ioc, enrichment):
        """多因素风险评分"""
        score = 0
        
        # VT 恶意评分
        vt = enrichment.get("vt_malicious", 0)
        if vt >= 50: score += 30
        elif vt >= 20: score += 20
        elif vt >= 5: score += 10
        
        # 情报源置信度
        confidence = int(ioc.get("confidence", 50))
        score += confidence * 0.3
        
        # 时间新鲜度（7天内 +20, 30天内 +10）
        from datetime import datetime, timedelta
        created = datetime.fromisoformat(ioc.get("created_at", "2000-01-01"))
        age_days = (datetime.utcnow() - created).days
        if age_days <= 7: score += 20
        elif age_days <= 30: score += 10
        
        # 是否有关联恶意软件家族
        if enrichment.get("malware_families"):
            score += 10
        
        return min(100, int(score))
    
    def _generate_sigma_rule(self, ioc):
        """从 IOC 生成 Sigma 规则"""
        return {
            "title": f"CTI IOC - {ioc.get('malware', 'Unknown')} - {ioc['type']}",
            "status": "experimental",
            "description": f"Auto-generated from CTI feed. Source: {ioc.get('source', 'unknown')}",
            "date": datetime.now().strftime("%Y/%m/%d"),
            "references": ioc.get("references", []),
            "tags": ["attack.command_and_control", f"cti.{ioc.get('source', 'unknown')}"],
            "logsource": {"category": "network_connection"},
            "detection": {
                "selection": {
                    f"Destination{ioc['type'].replace('ipv4', 'Ip')}": ioc["value"]
                },
                "condition": "selection"
            },
            "level": "high",
            "falsepositives": ["Legitimate traffic to this IP may occur"],
        }
```

### C.5 中国威胁情报市场与生态

#### C.5.1 主要平台与厂商

| 厂商/平台 | 产品 | 特点 | 适用场景 |
|-----------|------|------|---------|
| **奇安信** | TIP + ALPHA 威胁分析平台 | 本地化部署+SaaS API、多源融合(CNVD/CNNVD/VulnCheck)、AI化产品线 | 政府/央企/关基/等保合规 |
| **微步在线** | X 情报中心 (x.threatbook.com) | 国内首个综合性威胁分析平台、域名/IP反查、行业情报社区 | 企业安全团队、威胁查询、情报共享 |
| **阿里云** | 安全威胁分析 | 云原生情报、与WAF/DDoS/CDN联动 | 阿里云用户 |
| **华为云** | 态势感知 + 情报 | 政企合规驱动、全栈安全 | 华为生态用户 |
| **腾讯安全** | 威胁情报中心 | 腾讯黑灰产数据优势、反诈骗情报 | 互联网/金融 |
| **360** | 360威胁情报中心 | 海量样本数据、高级威胁追踪 | APT分析、应急响应 |

#### C.5.2 2026 中国 CTI 关键趋势

- **AI 攻防重构**：奇安信发布2026十大趋势，"十五五"规划驱动安全投入
- **产品 AI 化**：各大厂商利用 AI 重新赋能情报产品线（奇安信已量产）
- **多源融合深化**：CNVD + CNNVD + VulnCheck + 国际情报源交叉验证
- **合规驱动**：等保 2.0 + 关基条例 + 数据安全法要求情报能力建设
- **国产化替代**：信创生态下，开源平台(MISP/OpenCTI)与国产化平台并行

### C.6 防御升级路线图（P0-P3）

| 优先级 | 行动 | 时间线 | 前置条件 |
|--------|------|--------|---------|
| **P0** | 升级 OpenCTI 至 ≥6.8.1（修复 CVE-2025-61781） | 立即 | 运行版本检查脚本 |
| **P0** | 升级 MISP 至 2.5.x（获取安全补丁+UI改进） | 1 周内 | 备份数据库 |
| **P1** | 接入 LLM 辅助分析（IOC富化+报告摘要） | 1 月内 | LLM API 调用权限 |
| **P1** | 部署 CTI→SOAR 自动化 Playbook | 1 月内 | SIEM/SOAR API 就绪 |
| **P1** | 实施情报老化策略（IOC自动退役） | 1 月内 | 生命周期管理脚本 |
| **P2** | 评估 OpenCTI 7.0 Enterprise（PIR+Playbook） | 1 季度内 | 预算审批 |
| **P2** | 接入中文情报源（微步/奇安信/CNVD） | 1 季度内 | 商业合同/社区注册 |
| **P2** | 建立 ATT&CK 覆盖度量体系 | 1 季度内 | 检测工程流程 |
| **P3** | 建设 FINTEL（Finished Intelligence）报告能力 | 半年内 | 分析师培训 |
| **P3** | 参与 ISAC/CERT 情报共享联盟 | 半年内 | 组织授权 |

---

## 来源

- [OpenCTI 7.0: Key Features and Updates - Filigran Blog](https://filigran.io/blog/opencti-v7/)
- [MISP 2025 Retrospective - Cosive](https://www.cosive.com/blog/misp-2025-retrospective)
- [Redefining Cyber Threat Intelligence with AI - MDPI](https://www.mdpi.com/2076-3417/16/3/1668)
- [2026: The Year CTI Becomes Proactive, AI-Driven - Cyware](https://www.cyware.com/blog/2026-the-year-when-cyber-threat-intelligence-evolves-into-proactive-ai)
- [POLAR: Automating Cyber Threat Prioritization through LLM - OpenReview](https://openreview.net/forum?id=eLDjevX5p5)
- [CTI for Artificial Intelligence Systems - arXiv](https://arxiv.org/html/2603.05068v1)
- [2026 FIRST CTI Conference Program](https://www.first.org/conference/firstcti26/program)
- [Top 14 Threat Intelligence Platforms for 2026 - Flare](https://flare.io/glossary/top-14-threat-intelligence-platforms-for-2026)
- [Top 10 CTI Platforms for 2026 - Stellar Cyber](https://stellarcyber.ai/learn/top-cyber-threat-intelligence-cti-platforms/)
- [CVE-2025-61781: OpenCTI Auth Bypass - SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-61781/)
- [CVE-2025-24887: OpenCTI Allow/Deny Bypass - NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-24887)
- [Belgium CCB Advisory - OpenCTI](https://ccb.belgium.be/advisories/warning-high-improper-authorization-vulnerability-opencti-can-lead-workspace-deletion)
- [Automating TI Actions with Splunk SOAR - Recorded Future](https://www.recordedfuture.com/blog/automate-threat-intelligence-actions-with-splunk-soar-playbooks)
- [Agentic AI-Driven CTI - BlackHat 2025](https://www.youtube.com/watch?v=DBpKweFX8HA)
- [Top 6 SOAR Platforms of 2026 - Prophet Security](https://www.prophetsecurity.ai/blog/top-6-soar-platforms-of-2026)
- [奇安信威胁情报平台 TIP](https://www.qianxin.com/product/detail/pid/390)
- [奇安信 2026 网络安全十大趋势](https://www.secrss.com/articles/86947)
- [微步在线 X 情报中心](https://x.threatbook.com/)
- [2024 中国威胁情报行业发展研究报告](https://pdf.dfcfw.com/pdf/H3_AP202502201643327113_1.pdf)

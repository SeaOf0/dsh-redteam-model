---
name: threat-intel-correlation
description: >-
  Threat intelligence correlation covering MISP integration, STIX/TAXII processing,
  IOC enrichment pipelines (OpenCTI), threat campaign correlation, and MITRE ATT&CK mapping.
---

# Threat Intelligence Correlation

> **AI LOAD INSTRUCTION**: Use when correlating indicators with threat intelligence, mapping to ATT&CK, enriching IOCs, or analyzing threat campaigns during incident response.

## 1. MISP Integration

### Event Management
```python
# Create event
misp.add_event({
    "info": "Suspicious C2 communication detected",
    "threat_level_id": 2,  # High
    "analysis": 1,          # Ongoing
    "distribution": 0       # Your org only
})

# Add attributes (IOCs)
misp.add_attribute(event_id, {
    "type": "ip-dst",
    "value": "203.0.113.50",
    "category": "Network activity",
    "to_ids": True
})
```

### Taxonomy & Tags
| Taxonomy | Use |
|----------|-----|
| ATT&CK | technique mapping (e.g., `mitre-attack-pattern="T1059.001"`) |
| Veris | incident classification |
| Circl | confidence levels |
| Threat actor | APT group attribution |
| Diamond model | adversary/capability/infrastructure/victim |

### Sharing Groups
- **Organization only**: internal use
- **Community**: trusted sharing group
- **TLP**: Traffic Light Protocol (TLP:RED/AMBER/GREEN/WHITE)

## 2. STIX/TAXII

### STIX 2.1 Objects
```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--uuid",
  "pattern": "[ipv4-addr:value = '203.0.113.50']",
  "pattern_type": "stix",
  "valid_from": "2024-01-01T00:00:00Z",
  "labels": ["command-and-control"]
}
```

### Key Object Types
| Type | Purpose |
|------|---------|
| Indicator | observable pattern (IP, hash, domain) |
| Malware | malware family description |
| Attack Pattern | TTP description |
| Threat Actor | attributed group |
| Campaign | coordinated attack campaign |
| Relationship | links between objects |
| Course of Action | response/remediation |

### TAXII Operations
```
Discovery  → GET /api/taxii2/
Collections → GET /api/taxii2/collections/
Objects    → GET /api/taxii2/collections/{id}/objects/
Manifest   → GET /api/taxii2/collections/{id}/manifest/
```

## 3. IOC Enrichment Pipeline (OpenCTI)

### Pipeline Architecture
```
Raw IOC → Normalize → Enrich → Correlate → Score → Action
  │          │           │          │         │       │
  ├─ Input   ├─ Format   ├─ WHOIS   ├─ STIX   ├─ Risk ├─ Alert
  ├─ Feed    ├─ Deconf   ├─ DNS     ├─ Graph  ├─ Conf ├─ Block
  └─ Manual  └─ Dedup    ├─ GeoIP   └─ ATT&CK └─ TI   └─ Hunt
                         ├─ PDNS
                         ├─ SSL
                         └─ Shodan
```

### Connectors
| Connector | Enrichment |
|-----------|------------|
| VirusTotal | file hash reputation |
| Shodan | IP service/port info |
| AlienVault OTX | pulse/indicator matching |
| MITRE ATT&CK | technique mapping |
| AbuseIPDB | IP abuse confidence |
| URLhaus | malicious URL database |

## 4. Campaign Correlation

### Analysis Framework
```
1. Identify indicators → IOCs from incident
2. Pivot → search TI platforms for related indicators
3. Cluster → group indicators by infrastructure overlap
4. Attribution → match TTPs to known threat actors
5. Timeline → map campaign activity chronologically
6. Report → produce intelligence report with confidence level
```

### Correlation Techniques
- **Infrastructure overlap**: shared IPs, domains, SSL certs
- **TTP matching**: same tools, techniques, procedures
- **Malware family**: same code, mutexes, C2 protocol
- **Timing**: campaigns active during same period
- **Targeting**: same industry/region/geography

## 5. MITRE ATT&CK Mapping

### Mapping Process
```
Observed behavior → ATT&CK technique → sub-technique → tactic
Example:
  "Used PowerShell to download and execute payload"
  → Execution (TA0002) → T1059.001 PowerShell
  → Command and Control (TA0011) → T1105 Ingress Tool Transfer
```

### Coverage Analysis
```python
# Map detections to ATT&CK
detections = {
    "T1059.001": "PowerShell encoded command",
    "T1059.003": "Suspicious cmd.exe",
    "T1078":    "Failed login threshold",
    # ... map all detections
}
# Identify gaps: techniques without detection coverage
```

## 6. Decision Tree

```
Threat intelligence task
├── Enrich IOCs?
│   ├── IP → WHOIS + GeoIP + Shodan + PDNS + AbuseIPDB
│   ├── Domain → WHOIS + DNS + PDNS + SSL cert
│   ├── Hash → VirusTotal + MalwareBazaar + sandbox
│   ├── URL → URLhaus + VirusTotal + screenshot
│   └── Email → sender reputation + attachment hash
├── Correlate campaign?
│   ├── Infrastructure pivot → shared hosting/certs/registrars
│   ├── TTP match → same ATT&CK techniques
│   ├── Malware family → code/tools overlap
│   └── Targeting → same victim profile
├── Map to ATT&CK?
│   ├── Observed → technique ID → sub-technique → tactic
│   ├── Gap analysis → uncovered techniques → priority detections
│   └── Report → technique timeline + evidence
└── Share intelligence?
    ├── MISP → event + attributes + taxonomy
    ├── STIX/TAXII → bundle → publish to collection
    └── TLP marking → appropriate sharing level
```

## 7. Tools

| Tool | Purpose | Key Use |
|------|---------|---------|
| MISP | TI platform | IOC management, sharing, correlation |
| OpenCTI | TI platform | enrichment pipeline, knowledge graph |
| STIX/TAXII | Standard | structured threat information exchange |
| MITRE ATT&CK Navigator | Mapping | technique layer visualization |
| Virustotal | Enrichment | multi-engine file/URL/IP reputation |
| Shodan | Enrichment | internet-facing service intelligence |
| AbuseIPDB | Enrichment | IP abuse confidence score |

## 8. Detection Indicators

- IOC matches in network traffic or endpoint logs
- Infrastructure reuse across campaigns (shared hosting, certs)
- Known malware family indicators (mutexes, registry keys)
- ATT&CK techniques without corresponding detection rules (coverage gaps)
- Correlation between seemingly unrelated incidents via shared infrastructure

## collecting-threat-intelligence-with-misp

name: collecting-threat-intelligence-with-misp
description: MISP（恶意软件信息共享平台）是一个开源威胁情报平台，用于收集、共享、存储和关联定向攻击的失陷指标（IOC）、威胁情报、金融欺诈信息、漏洞信息或反恐信息。
domain: cybersecurity
subdomain: threat-intelligence
tags: [threat-intelligence, cti, ioc, mitre-attack, stix, misp, taxii, threat-sharing]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# 使用 MISP 收集威胁情报

## 概述

MISP（恶意软件信息共享平台）是一个开源威胁情报平台，用于收集、共享、存储和关联定向攻击的失陷指标（IOC）、威胁情报、金融欺诈信息、漏洞信息或反恐信息。本技能涵盖部署 MISP、配置威胁推送、使用 PyMISP API 进行编程访问，以及构建自动化收集流水线，从多个社区和商业来源聚合 IOC。

## 前置条件

- Python 3.9+，已安装 `pymisp` 库
- Docker 和 Docker Compose，用于 MISP 部署
- 了解 STIX 2.1 和 TAXII 2.1 协议
- 熟悉 IOC 类型：哈希值、IP 地址、域名、URL、电子邮件地址
- 能够访问 MISP 社区推送的网络（circl.lu、botvrij.eu）

## 核心概念

### MISP 架构

MISP 采用基于事件的模型，将威胁情报组织为包含属性（IOC）、对象（属性的结构化分组）、Galaxy（链接到 MITRE ATT&CK 的威胁行为者/恶意软件集群）和分类标签的事件。MISP 实例之间的同步使用基于 HTTPS 的推/拉模型，并以 API 密钥进行身份验证。

### 推送类型

- **MISP 推送**：来自 MISP 社区的原生 JSON/CSV 推送（CIRCL OSINT、botvrij.eu）
- **自由文本推送**：解析 IOC 的非结构化文本推送（abuse.ch、Feodo Tracker）
- **TAXII 推送**：来自商业和政府来源的 STIX/TAXII 2.1 兼容推送
- **CSV 推送**：具有可配置列映射的结构化 CSV 推送

### PyMISP API

PyMISP 是通过 REST API 访问 MISP 平台的官方 Python 库。它支持获取事件、添加/更新事件和属性、上传样本，以及在整个 MISP 数据集中搜索。身份验证使用在 `Authorization` 请求头中传递的 API 密钥。

## 实践步骤

### 步骤 1：使用 Docker 部署 MISP

```bash
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
cp template.env .env
# 编辑 .env 设置 MISP_BASEURL、MISP_ADMIN_EMAIL、MISP_ADMIN_PASSPHRASE
docker compose up -d
```

### 步骤 2：配置默认推送

通过 Web 界面或 API 启用内置 MISP 推送：

```python
from pymisp import PyMISP

misp = PyMISP('https://misp.local', 'YOUR_API_KEY', ssl=False)

# 列出可用推送
feeds = misp.feeds()
for feed in feeds:
    print(f"{feed['Feed']['id']}: {feed['Feed']['name']} - 已启用: {feed['Feed']['enabled']}")

# 启用 CIRCL OSINT 推送
misp.enable_feed(feed_id=1)
misp.cache_feed(feed_id=1)
misp.fetch_feed(feed_id=1)
```

### 步骤 3：添加自定义威胁推送

```python
# 添加 abuse.ch URLhaus 推送
feed_data = {
    'name': 'URLhaus 近期 URL',
    'provider': 'abuse.ch',
    'url': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
    'source_format': 'csv',
    'input_source': 'network',
    'publish': False,
    'enabled': True,
    'headers': '',
    'distribution': 0,
    'sharing_group_id': 0,
    'tag_id': 0,
    'default': False,
    'lookup_visible': True
}
result = misp.add_feed(feed_data)
print(f"推送已添加: {result}")
```

### 步骤 4：以编程方式搜索和检索事件

```python
from pymisp import PyMISP, MISPEvent
from datetime import datetime, timedelta

misp = PyMISP('https://misp.local', 'YOUR_API_KEY', ssl=False)

# 搜索过去 7 天的事件
result = misp.search(
    controller='events',
    date_from=(datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d'),
    type_attribute='ip-dst',
    to_ids=True,
    pythonify=True
)

for event in result:
    print(f"事件 {event.id}: {event.info}")
    for attr in event.attributes:
        if attr.type == 'ip-dst' and attr.to_ids:
            print(f"  IOC: {attr.value} (类别: {attr.category})")
```

### 步骤 5：导出 IOC 到下游工具

```python
# 导出为 STIX 2.1 bundle
stix_output = misp.search(
    controller='events',
    return_format='stix2',
    tags=['tlp:white'],
    published=True
)

# 将 IDS 标记的属性导出为 Suricata 规则
suricata_rules = misp.search(
    controller='attributes',
    return_format='suricata',
    to_ids=True,
    type_attribute=['ip-dst', 'domain', 'url']
)

# 导出为 CSV 以供 SIEM 摄取
csv_output = misp.search(
    controller='attributes',
    return_format='csv',
    type_attribute='ip-dst',
    to_ids=True
)
```

## 验收标准

- MISP 实例已部署并可通过 HTTPS 访问
- 至少 3 个社区推送已启用并成功获取数据
- PyMISP 脚本可以完成认证、搜索事件和检索 IOC
- 事件包含正确标记和分类的属性
- 导出为 STIX 2.1 可生成有效的 STIX bundle
- 自动推送获取按计划运行（cron 或 MISP 调度器）

## 参考资料

- [MISP 项目官网](https://www.misp-project.org/)
- [PyMISP 文档](https://pymisp.readthedocs.io/)
- [MISP GitHub 仓库](https://github.com/MISP/MISP)
- [MISP OpenAPI 规范](https://www.misp-project.org/openapi/)
- [CIRCL OSINT 推送](https://www.circl.lu/doc/misp/feed-osint/)

## performing-threat-intelligence-sharing-with-misp

name: performing-threat-intelligence-sharing-with-misp
description: 使用 PyMISP 在 MISP 平台上创建、丰富和共享威胁情报事件，包括 IOC 管理、情报源集成、STIX 导出及社区共享工作流
domain: cybersecurity
subdomain: threat-intelligence
tags: [misp, pymisp, threat-intelligence, ioc-sharing, stix, taxii, threat-feeds, information-sharing]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# 使用 MISP 执行威胁情报共享

## 概述

MISP（恶意软件信息共享平台，Malware Information Sharing Platform）是一个开源威胁情报平台，专为收集、存储、分发和共享网络安全指标及威胁信息而设计。PyMISP 是通过 REST API 与 MISP 实例交互的官方 Python 库，支持程序化事件创建、属性管理、标签分配、星系簇（Galaxy Cluster）附加及情报源同步。本技能涵盖使用 PyMISP 创建包含结构化 IOC（IP 地址、域名、文件哈希、URL）的事件、用 MITRE ATT&CK 标签丰富事件、管理共享组（Sharing Group）和分发级别（Distribution Level）、搜索已有情报，以及导出为 STIX 2.1 格式以实现与其他平台的互操作性。

## 前置条件

- MISP 实例（v2.4+），已启用 API 访问
- Python 3.9+，安装 `pymisp`（`pip install pymisp`）
- MISP API 密钥（设置 > 认证密钥）
- 理解 MISP 数据模型（事件、属性、对象、标签、星系）
- 了解 TLP 标记和共享协议

## 步骤

1. 安装 PyMISP：`pip install pymisp`
2. 初始化 `ExpandedPyMISP(url, key, ssl=True)` 连接
3. 创建包含信息描述、分发级别、威胁等级和分析状态的 `MISPEvent`
4. 通过 `event.add_attribute(type, value)` 添加 IP、域名、哈希等属性
5. 应用 TLP 标签和 MITRE ATT&CK 技术标签
6. 使用 `misp.publish(event)` 发布事件
7. 使用 `misp.search(controller='events', value=..., type_attribute=...)` 搜索已有事件
8. 启用并配置威胁情报源以自动摄入 IOC
9. 导出为 STIX 2.1 格式用于跨平台共享
10. 验证共享组配置和同步服务器设置

## 预期输出

JSON 报告，汇总已创建的事件、添加的属性、应用的标签、情报源同步状态，以及与已有情报的关联命中，包含事件 ID 和分发元数据。

## building-ioc-enrichment-pipeline-with-opencti

name: building-ioc-enrichment-pipeline-with-opencti
description: OpenCTI 是一个以 STIX 2.1 为原生数据模型的开源网络威胁情报知识管理平台。本技能涵盖使用 OpenCTI 连接器生态系统构建自动化 IOC 富化流水线，通过 VirusTotal、Shodan、AbuseIPDB、GreyNoise 等来源对指标进行富化。
domain: cybersecurity
subdomain: threat-intelligence
tags: [threat-intelligence, cti, ioc, mitre-attack, stix, opencti, enrichment, virustotal]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# 使用 OpenCTI 构建 IOC 富化流水线

## 概述

OpenCTI 是一个以 STIX 2.1 为原生数据模型的开源网络威胁情报知识管理平台。本技能涵盖使用 OpenCTI 连接器生态系统构建自动化 IOC 富化流水线，通过 VirusTotal、Shodan、AbuseIPDB、GreyNoise 等来源对指标进行富化。该流水线自动对新摄入的指标进行富化，将其与已知威胁行为者和攻击活动关联，并为分析师优先排序进行评分。

## 前置条件

- 用于部署 OpenCTI 的 Docker 和 Docker Compose
- Python 3.9+，安装 `pycti` 库
- 富化服务 API 密钥：VirusTotal、Shodan、AbuseIPDB、GreyNoise
- 了解 STIX 2.1 数据模型和关系
- OpenCTI 后端需要 ElasticSearch 或 OpenSearch
- 连接器消息队列需要 RabbitMQ 或 Redis

## 核心概念

### OpenCTI 架构

OpenCTI 使用 GraphQL API 前端，以 ElasticSearch 作为存储后端，以 Redis/RabbitMQ 用于连接器通信。数据以 STIX 2.1 对象和关系的形式原生存储。连接器分为以下类别：外部导入（推送摄取）、内部导入（文件解析）、内部富化（上下文添加）和流式处理（实时导出）。

### 富化连接器模型

内部富化连接器在创建新可观测对象时自动触发，或由分析师手动触发。每个连接器接收 STIX 对象、查询外部服务，并返回 STIX 2.1 bundle，以附加的上下文、标签和关系扩充原始可观测对象。

### 置信度评分

OpenCTI 对指标使用 0-100 置信度等级。富化连接器可根据外部验证更新置信度分数：VirusTotal 检测率、Shodan 暴露数据、AbuseIPDB 报告数量和 GreyNoise 分类结果。

## 实践步骤

### 步骤 1：使用 Docker Compose 部署 OpenCTI

```yaml
# docker-compose.yml（核心服务）
version: '3'
services:
  opencti:
    image: opencti/platform:6.4.4
    environment:
      - APP__PORT=8080
      - APP__ADMIN__EMAIL=admin@opencti.io
      - APP__ADMIN__PASSWORD=ChangeMeNow
      - APP__ADMIN__TOKEN=your-admin-token-uuid
      - ELASTICSEARCH__URL=http://elasticsearch:9200
      - MINIO__ENDPOINT=minio
      - RABBITMQ__HOSTNAME=rabbitmq
    ports:
      - "8080:8080"
    depends_on:
      - elasticsearch
      - minio
      - rabbitmq
      - redis

  connector-virustotal:
    image: opencti/connector-virustotal:6.4.4
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=your-admin-token-uuid
      - CONNECTOR_ID=connector-virustotal-id
      - CONNECTOR_NAME=VirusTotal
      - CONNECTOR_SCOPE=StixFile,Artifact,IPv4-Addr,Domain-Name,Url
      - CONNECTOR_AUTO=true
      - VIRUSTOTAL_TOKEN=your-vt-api-key
      - VIRUSTOTAL_MAX_TLP=TLP:AMBER

  connector-shodan:
    image: opencti/connector-shodan:6.4.4
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=your-admin-token-uuid
      - CONNECTOR_ID=connector-shodan-id
      - CONNECTOR_NAME=Shodan
      - CONNECTOR_SCOPE=IPv4-Addr
      - CONNECTOR_AUTO=true
      - SHODAN_TOKEN=your-shodan-api-key
      - SHODAN_MAX_TLP=TLP:AMBER

  connector-abuseipdb:
    image: opencti/connector-abuseipdb:6.4.4
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=your-admin-token-uuid
      - CONNECTOR_ID=connector-abuseipdb-id
      - CONNECTOR_NAME=AbuseIPDB
      - CONNECTOR_SCOPE=IPv4-Addr
      - CONNECTOR_AUTO=true
      - ABUSEIPDB_API_KEY=your-abuseipdb-key
```

### 步骤 2：构建自定义富化连接器

```python
import os
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import (
    Bundle, Indicator, Note, Relationship,
    IPv4Address, DomainName
)
import requests


class CustomEnrichmentConnector:
    def __init__(self):
        config = {
            "opencti": {
                "url": os.environ.get("OPENCTI_URL"),
                "token": os.environ.get("OPENCTI_TOKEN"),
            },
            "connector": {
                "id": os.environ.get("CONNECTOR_ID"),
                "name": "CustomEnrichment",
                "scope": "IPv4-Addr,Domain-Name,Url",
                "auto": True,
                "type": "INTERNAL_ENRICHMENT",
            },
        }
        self.helper = OpenCTIConnectorHelper(config)
        self.helper.listen(self._process_message)

    def _process_message(self, data):
        entity_id = data["entity_id"]
        stix_object = self.helper.api.stix_cyber_observable.read(id=entity_id)

        if not stix_object:
            return "未找到可观测对象"

        observable_type = stix_object["entity_type"]
        observable_value = stix_object.get("value", "")

        enrichment_results = []

        if observable_type == "IPv4-Addr":
            enrichment_results = self._enrich_ip(observable_value, entity_id)
        elif observable_type == "Domain-Name":
            enrichment_results = self._enrich_domain(observable_value, entity_id)

        if enrichment_results:
            bundle = Bundle(objects=enrichment_results, allow_custom=True)
            self.helper.send_stix2_bundle(bundle.serialize())

        return "富化完成"

    def _enrich_ip(self, ip_address, entity_id):
        """使用 GreyNoise、AbuseIPDB 上下文富化 IP 地址。"""
        objects = []

        # GreyNoise Community API
        try:
            gn_response = requests.get(
                f"https://api.greynoise.io/v3/community/{ip_address}",
                headers={"key": os.environ.get("GREYNOISE_API_KEY")},
                timeout=30,
            )
            if gn_response.status_code == 200:
                gn_data = gn_response.json()
                classification = gn_data.get("classification", "unknown")
                noise = gn_data.get("noise", False)
                riot = gn_data.get("riot", False)

                note_content = (
                    f"## GreyNoise 富化\n"
                    f"- 分类: {classification}\n"
                    f"- 互联网噪声: {noise}\n"
                    f"- RIOT（良性服务）: {riot}\n"
                    f"- 名称: {gn_data.get('name', 'N/A')}\n"
                    f"- 最后发现: {gn_data.get('last_seen', 'N/A')}"
                )

                note = Note(
                    content=note_content,
                    object_refs=[entity_id],
                    abstract=f"GreyNoise: {classification}",
                    allow_custom=True,
                )
                objects.append(note)

                # 根据分类添加标签
                if classification == "malicious":
                    self.helper.api.stix_cyber_observable.add_label(
                        id=entity_id, label_name="greynoise:malicious"
                    )
                elif riot:
                    self.helper.api.stix_cyber_observable.add_label(
                        id=entity_id, label_name="greynoise:benign-service"
                    )

        except Exception as e:
            self.helper.log_error(f"GreyNoise 富化失败: {e}")

        return objects

    def _enrich_domain(self, domain, entity_id):
        """使用 WHOIS 和 DNS 上下文富化域名。"""
        objects = []

        try:
            # 使用 SecurityTrails API 进行域名富化
            st_response = requests.get(
                f"https://api.securitytrails.com/v1/domain/{domain}",
                headers={"APIKEY": os.environ.get("SECURITYTRAILS_API_KEY")},
                timeout=30,
            )
            if st_response.status_code == 200:
                st_data = st_response.json()
                current_dns = st_data.get("current_dns", {})

                a_records = [
                    r.get("ip") for r in current_dns.get("a", {}).get("values", [])
                ]

                note_content = (
                    f"## SecurityTrails 富化\n"
                    f"- A 记录: {', '.join(a_records)}\n"
                    f"- Alexa 排名: {st_data.get('alexa_rank', 'N/A')}\n"
                    f"- 主机名: {st_data.get('hostname', 'N/A')}"
                )

                note = Note(
                    content=note_content,
                    object_refs=[entity_id],
                    abstract=f"SecurityTrails: {domain}",
                    allow_custom=True,
                )
                objects.append(note)

        except Exception as e:
            self.helper.log_error(f"SecurityTrails 富化失败: {e}")

        return objects


if __name__ == "__main__":
    connector = CustomEnrichmentConnector()
```

## 验收标准

- OpenCTI 实例成功部署并可访问
- VirusTotal 和 Shodan 连接器自动富化新指标
- 自定义连接器处理 GreyNoise 和 SecurityTrails 富化
- 置信度分数随富化结果更新
- 标签根据分类结果自动应用
- STIX bundle 正确通过连接器通信传递

## 参考资料

- [OpenCTI 文档](https://docs.opencti.io/)
- [OpenCTI GitHub](https://github.com/OpenCTI-Platform/opencti)
- [pycti Python 库](https://github.com/OpenCTI-Platform/client-python)
- [OpenCTI 连接器库](https://github.com/OpenCTI-Platform/connectors)
- [GreyNoise API](https://docs.greynoise.io/)

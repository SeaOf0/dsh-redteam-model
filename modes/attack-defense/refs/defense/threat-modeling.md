---
name: threat-modeling
description: >
  威胁建模完整手册：覆盖 STRIDE/LINDDUN/PASTA/DREAD/攻击树/杀伤链/钻石模型/
  ATT&CK 映射/OWASP Threat Dragon 等全部主流方法论。Part A 攻击视角：红队如何利用
  威胁模型发现攻击路径。Part B 防御视角：从系统架构出发识别威胁、量化风险、优先修复。
  内含决策树（选方法论）、方法论对比矩阵、杀伤链阶段速查表。
domain: cybersecurity
subdomain: threat-intelligence
tags: [threat-modeling, STRIDE, PASTA, attack-tree, kill-chain, diamond-model, MITRE-ATTCK, OWASP-Threat-Dragon, risk-assessment, DREAD]
version: 2.0.0
---

# 威胁建模 — 完整攻防手册

## 适用场景

**适用：** 系统设计阶段的安全需求识别；现有系统的威胁评估与优先修复；红队攻击路径规划；合规审计（PCI-DSS、ISO 27001 要求威胁建模）；ATT&CK 覆盖率度量。
**不适用：** 实时漏洞扫描（参考 web-pentest-comprehensive）；具体漏洞利用（参考各 injection skill）；事件响应（参考 ir-triage-scoping）。

## 前置条件

- 系统架构文档（数据流图、组件图）
- 了解业务逻辑和数据分类
- MITRE ATT&CK 框架基础知识
- Python 3.10+（用于自动化脚本）

---

## 方法论选择决策树

```
                    你要做什么？
                        │
          ┌─────────────┼─────────────┐
          │             │             │
     设计新系统     评估现有系统    分析攻击活动
          │             │             │
     ┌────┴────┐   ┌────┴────┐   ┌────┴────┐
     │         │   │         │   │         │
  Web应用?  IoT/OT?  需要量化?  红队规划?  归因分析?  技术映射?
     │         │   │         │   │         │      │
  STRIDE   STRIDE  PASTA    攻击树    钻石模型   ATT&CK
  +DREAD   +LINDDUN         +杀伤链              Navigator
```

## Part A：攻击视角 — 红队威胁建模

### 1. 攻击树构建

攻击树是从攻击者目标出发，逐层分解攻击路径的结构化方法。

```python
# attack_tree.py — 攻击树建模与评分
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum

class GateType(Enum):
    AND = "AND"  # 所有子节点都需要满足
    OR = "OR"    # 任一子节点满足即可

@dataclass
class AttackNode:
    name: str
    description: str
    children: List['AttackNode'] = field(default_factory=list)
    gate: GateType = GateType.OR
    difficulty: int = 1  # 1-10, 10 最难
    impact: int = 1      # 1-10, 10 影响最大
    likelihood: float = 0.0  # 0-1
    mitigated: bool = False
    
    @property
    def risk_score(self):
        """风险评分 = 影响 × 可能性 / 难度"""
        return (self.impact * self.likelihood * 10) / max(self.difficulty, 1)
    
    def find_paths(self, current_path=None):
        """找到所有可执行的攻击路径"""
        if current_path is None:
            current_path = []
        
        current_path = current_path + [self.name]
        
        if not self.children:
            yield current_path, self.risk_score
        
        if self.gate == GateType.OR:
            for child in self.children:
                yield from child.find_paths(current_path)
        else:  # AND
            # AND 门：所有子节点必须在同一路径
            sub_paths = [list(child.find_paths([])) for child in self.children]
            if all(sub_paths):
                # 合并所有子路径
                combined = current_path.copy()
                total_risk = 1.0
                for sp_list in sub_paths:
                    if sp_list:
                        path, risk = sp_list[0]
                        combined.extend([p for p in path if p not in combined])
                        total_risk *= risk
                yield combined, total_risk

# 构建攻击树示例：数据库访问
root = AttackNode("访问生产数据库", "获取敏感客户数据", difficulty=5, impact=10, likelihood=0.7)

# 路径1：通过网络应用
app_attack = AttackNode("通过 Web 应用", "利用应用漏洞", gate=GateType.OR)
sqli = AttackNode("SQL 注入", difficulty=4, impact=9, likelihood=0.6)
idor = AttackNode("IDOR", difficulty=3, impact=7, likelihood=0.7)
auth_bypass = AttackNode("认证绕过", difficulty=6, impact=9, likelihood=0.3)
app_attack.children = [sqli, idor, auth_bypass]

# 路径2：通过内部网络
internal = AttackNode("通过内部网络", "内部威胁", gate=GateType.OR)
phishing = AttackNode("钓鱼获取凭证", difficulty=3, impact=8, likelihood=0.8)
priv_esc = AttackNode("权限提升", difficulty=7, impact=9, likelihood=0.4)
internal.children = [phishing, priv_esc]

# 路径3：通过云配置错误
cloud = AttackNode("通过云配置错误", gate=GateType.OR)
s3_bucket = AttackNode("公开 S3 存储桶", difficulty=2, impact=10, likelihood=0.5)
iam_misconfig = AttackNode("IAM 过度授权", difficulty=5, impact=9, likelihood=0.6)
cloud.children = [s3_bucket, iam_misconfig]

root.children = [app_attack, internal, cloud]

# 分析攻击路径
print("=== 攻击路径分析 ===")
for path, risk in sorted(
    root.find_paths(), 
    key=lambda x: x[1], 
    reverse=True
)[:5]:
    print(f"  风险={risk:.1f} | {' → '.join(path)}")
```

### 2. 杀伤链分析（Cyber Kill Chain）

```
┌─────────────────────────────────────────────────────────────┐
│              Lockheed Martin Cyber Kill Chain                 │
├──────┬──────┬──────┬──────┬──────┬──────┬──────┤
│侦察   │武器化 │交付   │利用   │安装   │C2    │目标达成│
│Recon │Weapon│Deliv │Expl  │Inst  │C2    │ActObj│
├──────┼──────┼──────┼──────┼──────┼──────┼──────┤
│OSINT │CVE   │钓鱼  │漏洞  │后门  │HTTP  │数据  │
│扫描  │漏洞  │水坑  │利用  │Rootkit│DNS  │破坏  │
│社工  │恶意  │供应链│零日  │RAT   │社交  │勒索  │
│      │文档  │USB   │绕过  │计划  │媒体  │挖矿  │
├──────┼──────┼──────┼──────┼──────┼──────┼──────┤
│检测: │检测: │检测: │检测: │检测: │检测: │检测: │
│WAF日志│YARA  │邮件  │IDS   │文件  │DNS   │DLP   │
│DNS日志│沙箱  │网关  │EDR   │完整性│代理  │UEBA  │
│威胁  │威胁  │URL   │日志  │监控  │流量  │SIEM  │
│情报   │情报  │过滤  │分析  │      │分析  │      │
└──────┴──────┴──────┴──────┴──────┴──────┴──────┘
```

### 3. 钻石模型分析（Diamond Model）

```
        对手 (Adversary)
            │
            │  能力 (Capability)
            │    ↗         ↘
            │  /             \
            │ /               \
            ↓/                 \↓
    基础设施 ───────────────→ 目标 (Victim)
  (Infrastructure)
```

```python
# diamond_model.py — 钻石模型分析器
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime

@dataclass
class DiamondEvent:
    """钻石模型事件"""
    adversary: str          # 对手（APT组、个人）
    infrastructure: str     # 基础设施（C2 IP、域名）
    capability: str         # 能力（漏洞利用、恶意软件）
    victim: str             # 受害者（行业、组织）
    
    # 元特征
    timestamp: datetime = field(default_factory=datetime.utcnow)
    phase: str = ""         # 杀伤链阶段
    result: str = ""        # 成功/失败
    direction: str = ""     # 推断方向
    
    # 关系扩展
    related_events: List[str] = field(default_factory=list)
    confidence: float = 0.5

@dataclass 
class DiamondAnalysis:
    """钻石模型分析"""
    events: List[DiamondEvent] = field(default_factory=list)
    
    def add_event(self, event: DiamondEvent):
        self.events.append(event)
    
    def find_adversary_infrastructure(self, adversary: str):
        """查找对手使用的所有基础设施"""
        return list(set(
            e.infrastructure for e in self.events 
            if e.adversary == adversary
        ))
    
    def find_capability_targets(self, capability: str):
        """查找特定能力针对的目标"""
        return list(set(
            e.victim for e in self.events
            if e.capability == capability
        ))
    
    def pivot(self, from_vertex: str, from_value: str, to_vertex: str):
        """枢轴分析：从一个顶点追踪到另一个"""
        results = []
        for event in self.events:
            from_val = getattr(event, from_vertex, None)
            if from_val and from_value.lower() in from_val.lower():
                to_val = getattr(event, to_vertex, None)
                if to_val:
                    results.append({
                        "from": f"{from_vertex}={from_val}",
                        "to": f"{to_vertex}={to_val}",
                        "event": event
                    })
        return results
    
    def generate_activity_graph(self):
        """生成活动-资源二元图"""
        graph = {"nodes": set(), "edges": []}
        for event in self.events:
            for vertex in ["adversary", "infrastructure", "capability", "victim"]:
                val = getattr(event, vertex)
                graph["nodes"].add(f"{vertex}:{val}")
        
        for event in self.events:
            pairs = [
                (f"adversary:{event.adversary}", f"infrastructure:{event.infrastructure}"),
                (f"infrastructure:{event.infrastructure}", f"capability:{event.capability}"),
                (f"capability:{event.capability}", f"victim:{event.victim}"),
            ]
            for src, dst in pairs:
                graph["edges"].append((src, dst))
        
        return graph

# 使用示例
analysis = DiamondAnalysis()
analysis.add_event(DiamondEvent(
    adversary="APT28", infrastructure="evil-domain.com",
    capability="Spearphishing + Mimikatz", victim="Government",
    phase="Initial Access", result="success", confidence=0.9
))
analysis.add_event(DiamondEvent(
    adversary="APT28", infrastructure="198.51.100.45",
    capability="Zero-day exploit", victim="Defense Contractor",
    phase="Exploitation", result="success", confidence=0.85
))

# 枢轴分析
infra = analysis.find_adversary_infrastructure("APT28")
print(f"APT28 Infrastructure: {infra}")
```

---

## Part B：防御视角 — 系统化威胁建模

### 4. STRIDE 威胁分析

```
┌──────────────────────────────────────────────────────────────┐
│                        STRIDE 分析框架                         │
├──────────┬──────────────┬──────────────┬─────────────────────┤
│ 威胁类型  │ 安全属性      │ 典型攻击      │ 缓解措施            │
├──────────┼──────────────┼──────────────┼─────────────────────┤
│S 欺骗     │ 认证          │ 身份冒充      │ MFA、证书、Kerberos │
│T 篡改     │ 完整性        │ 数据修改      │ HMAC、签名、WAF     │
│R 否认     │ 不可否认性    │ 操作否认      │ 审计日志、SIEM      │
│I 信息泄露 │ 机密性        │ 数据窃取      │ 加密、DLP、RBAC     │
│D 拒绝服务 │ 可用性        │ 资源耗尽      │ 限流、CDN、冗余     │
│E 权限提升 │ 授权          │ 越权访问      │ 最小权限、审计      │
└──────────┴──────────────┴──────────────┴─────────────────────┘
```

```python
# stride_analyzer.py — STRIDE 自动化分析
from dataclasses import dataclass
from typing import List, Dict
from enum import Enum

class ThreatType(Enum):
    SPOOFING = "S - 欺骗 (Spoofing)"
    TAMPERING = "T - 篡改 (Tampering)"
    REPUDIATION = "R - 否认 (Repudiation)"
    INFO_DISCLOSURE = "I - 信息泄露 (Information Disclosure)"
    DENIAL_OF_SERVICE = "D - 拒绝服务 (Denial of Service)"
    ELEVATION_OF_PRIVILEGE = "E - 权限提升 (Elevation of Privilege)"

@dataclass
class DataFlow:
    source: str
    destination: str
    protocol: str
    data_type: str
    authentication: bool
    encryption: bool
    boundary_crossed: bool  # 是否跨越信任边界

@dataclass
class Threat:
    type: ThreatType
    target: str
    description: str
    severity: str  # High/Medium/Low
    mitigation: str

class STRIDEAnalyzer:
    """基于数据流图自动生成 STRIDE 威胁"""
    
    def analyze_flow(self, flow: DataFlow) -> List[Threat]:
        threats = []
        
        # S - 欺骗
        if not flow.authentication:
            threats.append(Threat(
                type=ThreatType.SPOOFING,
                target=f"{flow.source} → {flow.destination}",
                description=f"从 {flow.source} 到 {flow.destination} 的通信未认证，"
                           f"攻击者可冒充 {flow.source}",
                severity="High" if flow.boundary_crossed else "Medium",
                mitigation="添加双向认证（mTLS/API Key/OAuth2）"
            ))
        
        # T - 篡改
        if not flow.encryption:
            threats.append(Threat(
                type=ThreatType.TAMPERING,
                target=f"{flow.protocol}://{flow.source}/{flow.destination}",
                description=f"通过 {flow.protocol} 的传输未加密，数据可被篡改",
                severity="High",
                mitigation="启用 TLS 1.3 或应用层加密"
            ))
        
        # I - 信息泄露
        if flow.data_type in ("PII", "financial", "health", "credentials"):
            if not flow.encryption or flow.boundary_crossed:
                threats.append(Threat(
                    type=ThreatType.INFO_DISCLOSURE,
                    target=flow.data_type,
                    description=f"{flow.data_type} 数据在 {flow.source}→{flow.destination} "
                               f"传输中可能泄露",
                    severity="High",
                    mitigation="端到端加密 + 数据分类标记 + DLP 监控"
                ))
        
        # D - 拒绝服务
        if flow.boundary_crossed and flow.protocol in ("HTTP", "TCP"):
            threats.append(Threat(
                type=ThreatType.DENIAL_OF_SERVICE,
                target=flow.destination,
                description=f"{flow.destination} 暴露在信任边界外，可被 DoS 攻击",
                severity="Medium",
                mitigation="限流 + CDN/DDoS 防护 + 健康检查"
            ))
        
        # E - 权限提升
        if flow.data_type == "admin" or "admin" in flow.destination.lower():
            threats.append(Threat(
                type=ThreatType.ELEVATION_OF_PRIVILEGE,
                target=flow.destination,
                description=f"如果 {flow.source} 被攻陷，可直接访问管理功能",
                severity="High",
                mitigation="最小权限原则 + 独立管理网络 + MFA"
            ))
        
        return threats

# 使用示例
analyzer = STRIDEAnalyzer()
flow = DataFlow(
    source="Web Frontend",
    destination="API Server",
    protocol="HTTPS",
    data_type="PII",
    authentication=True,
    encryption=True,
    boundary_crossed=True
)
threats = analyzer.analyze_flow(flow)
for t in threats:
    print(f"[{t.severity}] {t.type.value}: {t.description[:80]}...")
    print(f"  Mitigation: {t.mitigation}\n")
```

### 5. PASTA 威胁建模（七步法）

```
┌──────────────────────────────────────────────────┐
│           PASTA (Process for Attack              │
│           Simulation and Threat Analysis)         │
├──────────────────────────────────────────────────┤
│ Step 1: 定义业务目标                              │
│   → 识别关键资产、业务影响、合规要求               │
│ Step 2: 定义技术范围                              │
│   → 架构图、数据流、信任边界                       │
│ Step 3: 分解应用                                  │
│   → 用例、数据输入、第三方依赖                     │
│ Step 4: 威胁分析                                  │
│   → STRIDE + 威胁情报 + ATT&CK 映射               │
│ Step 5: 漏洞分析                                  │
│   → 漏洞扫描 + 代码审计 + 配置审查                │
│ Step 6: 攻击模拟                                  │
│   → 攻击树 + 攻击面枚举 + 利用链                   │
│ Step 7: 风险与影响分析                             │
│   → DREAD 评分 + 优先级排序 + 修复建议             │
└──────────────────────────────────────────────────┘
```

### 6. DREAD 风险评分

```
DREAD 评分矩阵（每项 1-10 分，总分 = 平均值）:

  D - Damage Potential (损害潜力)
      1-3:  影响有限，无业务影响
      4-6:  部分业务受影响
      7-9:  关键业务中断
      10:   完全业务接管/数据泄露

  R - Reproducibility (可复现性)
      1-3:  很难复现
      4-6:  需要特定条件
      7-9:  容易复现
      10:   每次都成功

  E - Exploitability (可利用性)
      1-3:  需要高级技能
      4-6:  需要中级技能
      7-9:  初级技能即可
      10:   自动化工具可利用

  A - Affected Users (受影响用户)
      1-3:  少数用户
      4-6:  部分用户
      7-9:  多数用户
      10:   所有用户

  D - Discoverability (可发现性)
      1-3:  很难发现
      4-6:  需要主动搜索
      7-9:  容易发现
      10:   显而易见
```

```python
# dread_scorer.py — DREAD 风险评分
@dataclass
class DREADScore:
    damage: int        # 1-10
    reproducibility: int
    exploitability: int
    affected_users: int
    discoverability: int
    
    @property
    def total(self):
        return (self.damage + self.reproducibility + self.exploitability +
                self.affected_users + self.discoverability) / 5
    
    @property
    def severity(self):
        avg = self.total
        if avg >= 8: return "CRITICAL"
        if avg >= 6: return "HIGH"
        if avg >= 4: return "MEDIUM"
        if avg >= 2: return "LOW"
        return "INFO"
    
    @property
    def priority(self):
        """修复优先级"""
        s = self.severity
        if s == "CRITICAL": return "P0 - 立即修复（24h 内）"
        if s == "HIGH": return "P1 - 本周修复"
        if s == "MEDIUM": return "P2 - 本月修复"
        return "P3 - 下个版本"

# 评分示例
sql_injection = DREADScore(
    damage=9, reproducibility=9, exploitability=8,
    affected_users=8, discoverability=9
)
print(f"SQL Injection: {sql_injection.total:.1f} ({sql_injection.severity}) - {sql_injection.priority}")
```

### 7. OWASP Threat Dragon 使用

OWASP Threat Dragon 是免费开源的威胁建模工具。

```bash
# 方式1：Web 版本（Docker）
docker run -d -p 3000:3000 threatdragon/owasp-threat-dragon:latest
# 访问 http://localhost:3000

# 方式2：桌面版
# macOS: brew install --cask threat-dragon
# Windows: winget install OWASP.ThreatDragon
# Linux: snap install threat-dragon
```

```
OWASP Threat Dragon 工作流：
1. 创建新项目 → 选择模型类型（STRIDE/LINDDUN/CIA）
2. 绘制数据流图（DFD）
   - 添加外部实体（矩形）
   - 添加进程（圆形）
   - 添加数据存储（双横线）
   - 添加数据流（箭头）
   - 标记信任边界（虚线框）
3. 为每个元素添加威胁
   - 选择威胁类型（STRIDE 自动匹配）
   - 描述威胁
   - 设置严重程度
   - 添加缓解措施
4. 导出报告（PDF/JSON）
```

### 8. ATT&CK 覆盖率映射

```python
# attack_coverage.py — ATT&CK 覆盖率度量
import json
from pathlib import Path

class AttackCoverageMapper:
    """度量 ATT&CK 检测覆盖率"""
    
    def __init__(self, enterprise_attack_path=None):
        self.techniques = {}
        self.detections = {}
        if enterprise_attack_path:
            self.load_attack(enterprise_attack_path)
    
    def load_attack(self, path):
        """加载 ATT&CK STIX 数据"""
        with open(path) as f:
            data = json.load(f)
        for obj in data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                tid = next(
                    (e["external_id"] for e in obj.get("external_references", [])
                     if e.get("source_name") == "mitre-attack"),
                    None
                )
                if tid:
                    self.techniques[tid] = {
                        "name": obj["name"],
                        "tactic": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
                        "platforms": obj.get("x_mitre_platforms", []),
                        "detection": obj.get("x_mitre_detection", ""),
                    }
    
    def register_detection(self, technique_id, detection_name, coverage="full"):
        """注册检测规则覆盖率
        coverage: full(100%), partial(50%), none(0%)
        """
        scores = {"full": 100, "partial": 50, "none": 0}
        self.detections[technique_id] = {
            "name": detection_name,
            "coverage": coverage,
            "score": scores.get(coverage, 0)
        }
    
    def coverage_report(self, filter_tactic=None, filter_platform=None):
        """生成覆盖率报告"""
        total = 0
        covered = 0
        partial = 0
        missing = []
        
        for tid, info in self.techniques.items():
            # 过滤
            if filter_tactic and filter_tactic not in info["tactic"]:
                continue
            if filter_platform and filter_platform not in info["platforms"]:
                continue
            
            total += 1
            det = self.detections.get(tid)
            if det and det["coverage"] == "full":
                covered += 1
            elif det and det["coverage"] == "partial":
                partial += 1
            else:
                missing.append({
                    "id": tid,
                    "name": info["name"],
                    "tactic": info["tactic"],
                    "detection_guidance": info.get("detection", "N/A")[:100]
                })
        
        coverage_pct = (covered + partial * 0.5) / max(total, 1) * 100
        
        return {
            "total_techniques": total,
            "fully_covered": covered,
            "partially_covered": partial,
            "not_covered": total - covered - partial,
            "coverage_percentage": round(coverage_pct, 1),
            "gap_list": sorted(missing, key=lambda x: x["id"])[:20],
        }
    
    def navigator_layer(self, output_path="coverage_layer.json"):
        """生成 ATT&CK Navigator 图层文件"""
        layer = {
            "name": "Detection Coverage",
            "versions": {"attack": "15", "navigator": "4.9"},
            "techniques": [],
            "gradient": {
                "colors": ["#ff6666", "#ffe766", "#8ec843"],
                "minValue": 0, "maxValue": 100
            },
            "legendItems": [
                {"label": "Full Coverage", "color": "#8ec843"},
                {"label": "Partial Coverage", "color": "#ffe766"},
                {"label": "No Coverage", "color": "#ff6666"},
            ]
        }
        
        for tid, det in self.detections.items():
            layer["techniques"].append({
                "techniqueID": tid,
                "score": det["score"],
                "comment": det["name"]
            })
        
        with open(output_path, "w") as f:
            json.dump(layer, f, indent=2)
        
        return output_path

# 使用示例
mapper = AttackCoverageMapper()
mapper.register_detection("T1566.001", "Email Gateway + Attachment Sandboxing", "full")
mapper.register_detection("T1059.001", "PowerShell Script Block Logging + AMSI", "full")
mapper.register_detection("T1078", "Failed Login Anomaly Detection", "partial")
mapper.register_detection("T1486", "File Encryption Rate Monitoring", "full")

report = mapper.coverage_report()
print(f"Coverage: {report['coverage_percentage']}% | "
      f"Full={report['fully_covered']} Partial={report['partially_covered']} "
      f"Gap={report['not_covered']}")
```

### 9. 威胁建模文档模板

```markdown
# 威胁建模报告 — [系统名称]

## 1. 系统概述
- **系统名称：**
- **版本：**
- **业务目标：**
- **数据分类：** [PII/Financial/Health/Internal/Public]

## 2. 架构图与数据流
（插入 DFD 图）

## 3. 信任边界
| 边界 | 左侧 | 右侧 | 跨越数据 |
|------|------|------|---------|

## 4. 威胁清单（STRIDE）

| ID | 威胁类型 | 描述 | 目标 | DREAD | 优先级 | 缓解措施 |
|----|---------|------|------|-------|--------|---------|
| T1 | S-欺骗 | ... | ... | 7.2 | P1 | ... |

## 5. ATT&CK 映射
| 技术 | 检测状态 | 检测规则 | 覆盖率 |
|------|---------|---------|--------|

## 6. 攻击树分析
（关键攻击路径与风险评分）

## 7. 修复优先级
| 优先级 | 威胁 | 修复措施 | 负责人 | 截止日期 |
|--------|------|---------|--------|---------|

## 8. 附录
- 完整 DREAD 评分
- ATT&CK Navigator 图层
```

---

## 速查表

### 威胁建模方法论对比矩阵

| 方法论 | 类型 | 最佳场景 | 输出 | 复杂度 |
|--------|------|---------|------|--------|
| **STRIDE** | 威胁识别 | 新系统设计 | 威胁清单 | 低 |
| **STRIDE+DREAD** | 威胁+风险 | 需要量化 | 评分+优先级 | 中 |
| **PASTA** | 完整流程 | 企业级评估 | 七步完整报告 | 高 |
| **攻击树** | 攻击路径 | 红队规划 | 路径+概率 | 中 |
| **杀伤链** | 攻击阶段 | 检测覆盖分析 | 阶段映射 | 低 |
| **钻石模型** | 威胁归因 | 威胁情报分析 | 事件关联图 | 中 |
| **LINDDUN** | 隐私威胁 | 隐私影响评估 | 隐私威胁清单 | 中 |
| **ATT&CK** | 技术/检测 | 检测覆盖率 | 覆盖热图 | 高 |

### MITRE ATT&CK 战术速查（Enterprise v19 — 2025-10）

> **v19 重大变更**：Defense Evasion（TA0005）已拆分为 **Stealth**（隐蔽）+ **Defense Impairment**（防御破坏）两个新战术；新增 ESXi 平台；追踪 178 个威胁组织；37 个新软件条目。Navigator 图层需同步更新。

| 战术 | ID | 关键检测点 | v17-v19 变更 |
|------|-----|-----------|-------------|
| 侦察 | TA0043 | 外部扫描日志、DNS 查询 | — |
| 资源开发 | TA0042 | 基础设施注册、社工预警 | — |
| 初始访问 | TA0001 | 钓鱼检测、漏洞利用告警 | +有效账户子技术 |
| 执行 | TA0002 | 进程监控、脚本审计 | — |
| 持久化 | TA0003 | 注册表、计划任务、WMI | — |
| 权限提升 | TA0004 | UAC 绕过、令牌操作 | — |
| **Stealth（隐蔽）** | **新增** | 日志清除、混淆、进程注入 | v19 从 TA0005 拆分 |
| **Defense Impairment（防御破坏）** | **新增** | 禁用安全工具、破坏EDR | v19 从 TA0005 拆分 |
| 凭证访问 | TA0006 | LSASS、SAM 数据库访问 | — |
| 发现 | TA0007 | 网络扫描、账号枚举 | — |
| 横向移动 | TA0008 | PsExec、WMI、RDP | — |
| 收集 | TA0009 | 邮箱访问、屏幕截取 | v17 优化 |
| C2 | TA0011 | DNS 隧道、HTTPS beacon | — |
| 数据外泄 | TA0010 | 大量外传、加密通道 | — |
| 影响 | TA0040 | 文件加密、数据删除 | — |

> 来源：[MITRE ATT&CK Updates](https://attack.mitre.org/resources/updates/) | [v19 Cymulate 解析](https://cymulate.com/blog/mitre-attack-v19-breakdown/) | [v17 ESXi 新增](https://medium.com/mitre-attack/att-ck-v17-new-platform-esxi-collection-optimization-more-countermeasures-dfb59eae2204)

---

## MITRE ATT&CK 映射

本 skill 覆盖全部 14 个 Enterprise 战术的建模与映射方法，核心映射关系：

| 建模活动 | ATT&CK 集成点 |
|---------|---------------|
| 威胁识别 | Techniques → STRIDE 威胁类型映射 |
| 攻击树构建 | Techniques → 攻击树节点映射 |
| 检测覆盖 | Navigator Layer → 覆盖热图 |
| 风险优先级 | DREAD × ATT&CK Sub-techniques |
| 对手分析 | Groups → Software → Techniques 关联 |
| 杀伤链映射 | Kill Chain Phase → ATT&CK Tactics |

---

## Part C：2025-2026 威胁建模前沿与补充

### C.1 STRIDE-AI — AI/GenAI 系统威胁建模框架

STRIDE-AI（arXiv 2025）将经典 STRIDE 适配到 AI/大模型系统，定义六阶段评估生命周期：

```
STRIDE-AI 六阶段评估生命周期：
  Phase 1: AI 系统范围定义 → 模型、数据、推理管道、用户接口
  Phase 2: 数据流分解 → 训练数据流、推理数据流、反馈数据流
  Phase 3: AI 特定 STRIDE 映射 → 新增 Prompt 注入、模型窃取、数据投毒等威胁
  Phase 4: AI 攻击树构建 → 对抗样本 → 推理滥用 → 数据外泄路径
  Phase 5: 风险量化 → DREAD × AI 影响矩阵（模型机密性、训练数据完整性）
  Phase 6: 缓解措施 → 安全护栏、内容过滤、模型水印、差分隐私
```

**STRIDE-AI 威胁类型映射：**

| 经典 STRIDE | AI 特定扩展 | 典型 AI 攻击 | 缓解措施 |
|------------|------------|-------------|---------|
| S-欺骗 | Prompt 注入冒充 | 越狱、系统提示泄露 | 输入验证、Prompt 加固 |
| T-篡改 | 训练数据投毒 | 后门植入、数据操纵 | 数据溯源、完整性校验 |
| R-否认 | 模型输出否认 | 生成内容不可追溯 | 水印、审计日志 |
| I-信息泄露 | 模型记忆泄露 | 训练数据提取、成员推断 | 差分隐私、输出过滤 |
| D-拒绝服务 | 推理资源耗尽 | 对抗样本致计算爆炸 | 限流、输入长度限制 |
| E-权限提升 | 工具调用滥用 | Agent 越权、MCP 注入 | 最小权限、沙箱隔离 |

> 参考：[STRIDE-AI arXiv 论文](https://arxiv.org/abs/2605.17163) | [Adam Shostack AI威胁建模策略](https://shostack.org/blog/strategy-for-threat-modeling-ai/)

### C.2 AI/LLM 驱动的威胁建模工具

#### C.2.1 STRIDE-GPT（开源）

STRIDE-GPT 利用 LLM 自动生成威胁模型和攻击树。

```bash
# 安装
pip install stride-gpt
# 或从源码
git clone https://github.com/mrwadams/stride-gpt.git
cd stride-gpt && pip install -r requirements.txt

# 使用（需要 OpenAI API Key）
export OPENAI_API_KEY="sk-..."
python -m stride_gpt --app-name "MyApp" \
  --app-description "Web application with user auth and payment" \
  --framework STRIDE \
  --output threat_model.json
```

输出包含：STRIDE 分类威胁清单、攻击树 JSON、DREAD 评分、缓解建议。

> 参考：[STRIDE-GPT GitHub](https://github.com/mrwadams/stride-gpt) | [IEEE Computer Society 专访](https://www.computer.org/csdl/magazine/so/2025/03/10953344/25ICEcfnksM)

#### C.2.2 Arrows（Fuzzing Labs）

LLM 驱动的自动化 STRIDE 威胁建模，面向 Web 应用快速生成安全洞察。支持从 URL 或架构描述自动生成威胁模型。

> 参考：[Arrows AI Threat Modeling](https://fuzzinglabs.com/ai-threat-modeling-arrows/)

### C.3 威胁建模自动化工具矩阵 v2.0（2025-2026）

| 工具 | 类型 | 方法 | 威胁库 | 输出 | 适用场景 | 可用性评分 |
|------|------|------|--------|------|---------|-----------|
| **OWASP Threat Dragon** | 开源 | 图形化 DFD + STRIDE | 基础 | PDF/JSON | 小中型团队 | ★★★★ |
| **pytm (OWASP)** | 开源 | Python 代码即模型 | 基础 | 报告+图 | 开发者 CI/CD 集成 | ★★★ |
| **Threagile** | 开源 | YAML 架构即代码 | 中等 | PDF/风险追踪 | DevSecOps 敏捷团队 | ★★★ |
| **IriusRisk** | 商业+社区版 | 规则引擎(数千规则) | 丰富 | 风险管理+报告 | 组织级扩展 | ★★★★★ |
| **ThreatModeler** | 商业 | 企业自动化平台 | 丰富 | 仪表盘+合规报告 | 大型企业 | ★★★★ |
| **MS TMT** | 免费 | 图形化 | 基础 | 报告 | Windows 生态 | ★★★ |
| **STRIDE-GPT** | 开源 | LLM 自动生成 | 动态 | JSON/Markdown | 快速原型 | ★★★ |
| **TaaC-AI** | 开源 | AI 威胁建模即代码 | 动态 | 报告 | CI/CD 集成 | ★★★ |

> IEEE 可用性研究（5 工具评估）结论：IriusRank 可用性最高。参考：[IEEE Usability Evaluation](https://ieeexplore.ieee.org/iel8/6287639/10820123/10963669.pdf) | [工具目录](https://github.com/Toreon/Threat-Modeling-Tool-Directory)

### C.4 NIST CSF 2.0 与威胁建模对齐

NIST CSF 2.0（2024-02 发布，2026-03 扩展工具包）新增 **Govern（治理）** 函数，要求威胁建模直接服务于治理层：

```
NIST CSF 2.0 六大函数 × 威胁建模集成点：

  GOVERN (治理)  ← 威胁建模策略、风险偏好定义、供应链风险管理
    ↓
  IDENTIFY (识别) ← 资产识别、威胁场景定义、ATT&CK 映射
    ↓
  PROTECT (保护)  ← 威胁模型→控制措施映射、设计阶段安全需求
    ↓
  DETECT (检测)   ← 攻击树→检测规则、ATT&CK 覆盖率度量
    ↓
  RESPOND (响应)  ← 威胁模型指导事件分类与优先级
    ↓
  RECOVER (恢复)  ← 关键资产恢复优先级（基于威胁模型影响评分）
```

**供应链威胁建模要点（CSF 2.0 ID.SC）：**

1. SBOM 驱动威胁识别：从 SBOM 提取组件→映射已知 CVE→构建攻击树
2. 第三方风险评估：供应商威胁画像→信任边界→数据流威胁分析
3. 软件物料清单集成：`sbom2threats.py` 自动化脚本

```python
# sbom2threats.py — 从 SBOM 自动生成威胁列表（概念示例）
import json
from pathlib import Path

def sbom_to_threats(sbom_path: str):
    """从 CycloneDX/SPDX SBOM 提取组件并映射已知威胁"""
    with open(sbom_path) as f:
        sbom = json.load(f)

    threats = []
    for comp in sbom.get("components", []):
        name = comp.get("name", "unknown")
        version = comp.get("version", "unknown")
        purl = comp.get("purl", "")

        # 检查已知漏洞组件
        threat_entry = {
            "component": f"{name}@{version}",
            "purl": purl,
            "stride_mapping": [],
            "risk_factors": []
        }

        # 基于组件类型映射 STRIDE 威胁
        comp_type = comp.get("type", "")
        if comp_type == "library":
            threat_entry["stride_mapping"].extend([
                "T-篡改: 依赖库可被供应链攻击替换",
                "I-信息泄露: 第三方库可能包含数据收集",
            ])
            threat_entry["risk_factors"].append("供应链依赖")

        if purl and "npm" in purl:
            threat_entry["stride_mapping"].append(
                "S-欺骗: npm 包名混淆(typosquatting)风险"
            )

        threats.append(threat_entry)

    return threats
```

> 参考：[NIST CSF 2.0 官方](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf) | [CSF 2.0 供应链](https://blog.riskrecon.com/nist-csf-2-0-updated-third-party-supply-chain-risk-management-part-2) | [2026-03 工具包扩展](https://industrialcyber.co/nist/nist-expands-csf-2-0-toolkit-with-quick-start-guides-aligning-cyber-risk-risk-management-workforce-strategy/)

### C.5 云原生威胁建模

云环境需要扩展传统 STRIDE，增加云特定威胁类别：

```
云原生 STRIDE 扩展（Cloud-STRIDE）：

  S-欺骗: IAM 角色冒充、STS 临时凭证窃取、跨账户 AssumeRole
  T-篡改: S3 对象覆盖、Lambda 函数篡改、容器镜像替换
  R-否认: CloudTrail 日志篡改/禁用、API 调用抵赖
  I-信息泄露: S3 公开存储桶、Secrets Manager 泄露、跨租户数据泄露
  D-拒绝服务: API Gateway 限流绕过、Lambda 并发耗尽、账单 DoS
  E-权限提升: IAM 策略提权、容器逃逸→宿主机、K8s RBAC 滥用
```

**云威胁建模检查清单：**

| 层级 | 威胁焦点 | 关键问题 |
|------|---------|---------|
| IAM 层 | 身份与访问 | 谁能 Assume 这个角色？是否有 Admin 权限？ |
| 网络层 | 网络隔离 | 安全组是否过于宽松？是否有公网暴露？ |
| 数据层 | 数据保护 | 加密 at-rest/in-transit？是否有跨区域复制风险？ |
| 计算层 | 工作负载安全 | 容器是否以 root 运行？是否有特权容器？ |
| 日志层 | 可观测性 | CloudTrail 是否启用？是否有日志完整性保护？ |

### C.6 Microsoft SFI AI 威胁建模框架

Microsoft Security Future Initiative (SFI) 发布的 AI 系统威胁建模指南，核心四步：

1. **确定保护目标**：模型权重、训练数据、推理输入/输出、系统提示
2. **了解端到端行为**：从用户输入→预处理→模型推理→后处理→输出全链路
3. **对有意滥用建模**：攻击者视角→Prompt 注入→模型窃取→数据投毒→权限滥用
4. **设计安全约束**：输入/输出护栏、速率限制、沙箱隔离、审计日志

> 参考：[Microsoft SFI AI 威胁建模](https://learn.microsoft.com/zh-cn/security/zero-trust/sfi/threat-modeling-ai)

### C.7 ATT&CK v17-v19 变更速查（威胁建模影响）

| 版本 | 日期 | 关键变更 | 威胁建模影响 |
|------|------|---------|-------------|
| **v17** | 2024-10 | +ESXi 平台、Collection 优化、Countermeasure 扩展 | 虚拟化环境威胁模型需更新 |
| **v18** | 2025-04 | +12 新技术、检测策略增强 | 检测覆盖率矩阵需扩展 |
| **v19** | 2025-10 | TA0005 拆分为 Stealth+Defense Impairment、+37 软件、178 威胁组 | **重大**：现有映射需全面更新，攻击树需调整 |

**v19 迁移检查清单：**
- [ ] 更新 Navigator 图层版本为 v19
- [ ] 重新映射原 TA0005（Defense Evasion）相关技术到 Stealth/Defense Impairment
- [ ] 更新攻击树中引用的 ATT&CK 技术编号
- [ ] 重新计算检测覆盖率（分母可能变化）
- [ ] 更新 STIX 数据源为 v19.1

> 参考：[ATT&CK v19 Updates](https://attack.mitre.org/resources/updates/updates-october-2025/) | [Scythe v19 解析](https://scythe.io/scythe-labs/mitre-attck-v19) | [v18 Picus 解析](https://www.picussecurity.com/resource/blog/whats-new-in-mitre-attack-v18)

### C.8 中文社区精华参考

| 来源 | 内容 | 链接 |
|------|------|------|
| **安全客** | STRIDE GPT：AI 驱动的威胁建模工具介绍 | [anquanke.com/post/id/306523](https://www.anquanke.com/post/id/306523) |
| **安全内参** | 10 大免费自动化威胁建模工具对比 | [secrss.com/articles/55964](https://www.secrss.com/articles/55964) |
| **Microsoft Learn** | AI 系统完整威胁建模（SFI 计划） | [learn.microsoft.com](https://learn.microsoft.com/zh-cn/security/zero-trust/sfi/threat-modeling-ai) |
| **CSDN** | AI 7层架构威胁建模需求表 | [blog.csdn.net](https://blog.csdn.net/qq_35388992/article/details/146440915) |
| **知乎** | 2026 国际 AI 安全报告解读（威胁建模+红队） | [zhuanlan.zhihu.com](https://zhuanlan.zhihu.com/p/2030928074536169529) |
| **东方财富** | AI 重塑网络安全：智能化产品与市场报告 | [pdf.dfcfw.com](https://pdf.dfcfw.com/pdf/H3_AP202604281821651603_1.pdf) |

### C.9 防御升级路线图（P0-P3）

```
威胁建模能力成熟度路线图：

  P0 - 基础（立即）
    ├─ 选择一种方法论（推荐 STRIDE）并完成首个威胁模型
    ├─ 安装 OWASP Threat Dragon 或使用 STRIDE-GPT 快速启动
    ├─ 对核心系统绘制 DFD 图并执行 STRIDE 分析
    └─ 建立威胁模型文档模板

  P1 - 进阶（1-3 月）
    ├─ 引入 ATT&CK 映射，使用 Navigator 生成覆盖热图
    ├─ 将威胁建模集成到 SDLC 设计评审阶段
    ├─ 建立攻击树库（按场景分类）
    ├─ 引入自动化工具（pytm/Threagile）到 CI/CD
    └─ 对齐 NIST CSF 2.0 Govern 函数

  P2 - 成熟（3-6 月）
    ├─ 部署 AI/LLM 辅助威胁建模（STRIDE-GPT/Arrows）
    ├─ 建立 ATT&CK 检测覆盖率度量体系
    ├─ 扩展到云原生和供应链威胁建模
    ├─ 引入 STRIDE-AI 评估 AI/LLM 系统
    └─ 建立 SBOM→威胁自动化映射管线

  P3 - 领先（6-12 月）
    ├─ Agentic AI 自主威胁建模管线
    ├─ 威胁模型→检测规则自动生成
    ├─ 实时威胁模型更新（基于安全事件反馈）
    ├─ 跨组织威胁情报共享威胁模型
    └─ MITRE ATT&CK v19+ 持续同步机制
```

---

## 前置条件

1. **文档**：系统架构图、数据流图、资产清单
2. **工具**：OWASP Threat Dragon（免费）、STRIDE-GPT（开源）、ATT&CK Navigator（免费）
3. **知识**：STRIDE/PASTA/STRIDE-AI 方法论基础、ATT&CK v19 框架结构
4. **数据**：ATT&CK STIX v19 数据（https://github.com/mitre/cti）、内部安全事件历史
5. **团队**：架构师（系统知识）、安全工程师（威胁分析）、开发（修复评估）、AI 工程师（AI 系统威胁建模）

# 成果登记字段语义词典（finding-fields）

> redteam_finding_register / redteam_finding_update 三工具的完整字段语义。工具 schema 内
> 只留极简描述，本手册是唯一全量语义源（随预设分发；从任一技能基目录按 `shared/refs/finding-fields.md`
> 相对定位，或 fs-search 文件名定位）。字段名/类型/枚举与工具 schema 完全一致。

## 登记纪律（三工具共用）

- **会话 × 模式自动隔离**：归属由当前会话推导，不可也不需指定他模式；子代理的登记落入子代理
  自身会话库——需进主会话成果页的，由主会话（总控/报告员）登记。
- **每条进入报告的 finding 必登**；status 保持诚实：复核通过前一律 `pending`，复核后
  `verified` / `false-positive`（误报），修复复测后 `fixed`。
- 模式原生富字段按「当前模式 persona 的成果登记条款」填（各模式板式语义见下），不发明字段。
- update 仅用于：状态流转（verified/false-positive/fixed）、severity/字段修订、verifyNote
  记复核结论、retestNote 记复测结论；delete 两步确认后删行（页面删除按钮同源）。

## 通用字段（全模式）

| 字段 | 语义 | 填写要点 |
|---|---|---|
| title | 漏洞/战果/交付物/路径名 | 简短；列表展示用 |
| severity | critical/high/medium/low | 严重/高危/中危/低危；战果与交付物=权限/价值级别 |
| target | 漏洞地址/目标/位置 | URL、主机、对象路径、产物路径 |
| summary | 核心简介一句话 | 列表页展示；控制在一句 |
| type | 漏洞/战果/交付物类型 | 按各模式类型词表（如 SQLi/XSS/未授权；可含 CWE） |
| description | 描述 | 影响与成因；战果=内容摘要（凭据数/数据范围/权限级） |
| poc | 测试过程/复现 EXP/使用方法 | 完整可复现步骤或脚本；代码审计填复现条件或利用前提 |
| evidence | 证据引用 | evidence-index 编号/产物路径；审计=双链比对文件 `artifacts/<id>-chains.md` |
| fix | 修复建议 | 针对该问题点；免杀类=检测侧建议 |
| status | pending/verified/false-positive/fixed | 默认 pending；已复核才填 verified/false-positive |
| evidenceLevel | confirmed/partial/unknown | 证据等级，默认 unknown |

## 代码审计富字段（findings 板式）

| 字段 | 语义 |
|---|---|
| chain | 调用链 entry→sink；审计双链第一侧（审计工人链），每行一链，如 `Controller.x() → Service.y() → Dao.z(sql)` |
| chainTracer | 追踪员链（双链第二侧，独立重追的 entry→sink；与 chain 对照） |
| chainVerdict | 双链一致性结论（一致 / 不一致+差异说明；不一致=疑似，不进 confirmed） |
| snippetEntry | 入口代码片段（entry 处关键代码） |
| snippetSink | sink 代码片段（危险点实际代码） |
| cwe | CWE 编号（如 CWE-89） |
| patch | 修复 diff 建议（diff 格式） |
| sourceOrigin | manual=人工深审 / scan-confirmed=扫描命中复核确认 / scan-false-positive=扫描误报复核（对账台账用） |

## 二进制分析富字段（assets 产物板式）

| 字段 | 语义 |
|---|---|
| sampleHash | 样本 SHA256（唯一标识；页面按样本分组） |
| family | 家族/变种归属（如 AgentTesla、CobaltStrike） |
| packer | 壳/保护（如 UPX、VMProtect、无壳） |
| iocs | IOC 清单（C2/URL/IP/互斥量/注册表/持久化位置，每行一条） |
| detectionRule | 检测规则（YARA/Sigma 原文） |

## 渗透测试富字段（findings 板式；attack-defense 战果同用）

| 字段 | 语义 |
|---|---|
| baseline | 对照三件套①基线（正常请求的行数/内容） |
| diffEvidence | 对照三件套②差分（注入后真实翻转证据） |
| markerEcho | 对照三件套③marker 逐字回显 |
| impact | 影响证明（拿到什么数据/执行到什么程度，如 whoami 输出、脱库行数） |
| cvss | CVSS 向量与评分（如 `CVSS:3.1/AV:N/... (8.6)`） |
| requestPkt | 完整请求包（决定性请求原文） |
| responsePkt | 关键响应（证明影响的响应原文/片段） |
| retestNote | 复测注记（修复后复测结论：已修复/部分/未修复+依据；update 专用） |
| chain | attack-defense 战果=获取路径；利用链以 `L<级>:` 前缀标链级（L1-L5，见 ad-playbook「验证与评分」） |

## 云安全富字段（cloudpath 攻击路径板式）

| 字段 | 语义 |
|---|---|
| entry | 入口凭证或身份（AK/SK、实例身份、公开入口） |
| identity | 利用身份（IAM 用户/角色/服务身份） |
| permission | 权限（策略名/权限清单） |
| resource | 目标资源（ARN/桶名/实例 ID） |

## 应急溯源富字段（timeline 时间线板式）

| 字段 | 语义 |
|---|---|
| timelineAt | 攻击时间节点（时间线排序：ISO 或 `YYYY-MM-DD HH:MM`；未知填 unknown） |

## verifyNote（update 专用）

复核注记：结论+依据，简短——「确认/挑战」二选一结论、对照三件套/确定性信号的判定要点、
跨 harness 双签结论（如触发）。

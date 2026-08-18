# cloud-security 参考手册库 · 检测侧（refs/detection/）

> 本目录随 cloud-security 预设打包分发。所有文件为预设内自包含资源，不依赖任何机器特定路径。
> 定位：检测侧深度手册——cloud-playbook 是速查卡，这里的文件是「云检测缺口评估（C5 门）」
> 的判定底座与规则产出工具面；需要细节时用 read 直接读取。
> 路径解析：加载 cloud-playbook 技能时得到 SKILL.md 所在目录（`skills/cloud-playbook/`），
> refs/ 相对该目录 = `../../refs/`。
> 口径：全部中文原创；正文不引用任何外部 URL，不出现任何出处性表述；技术事实（API 名、
> 事件名、端点、字段名、策略语法、ATT&CK ID）为公开标准信息正常保留。共 4 篇 md。

## 快速路由（按评估阶段找文件）

| 阶段/任务 | 文件 |
|---|---|
| 查「某厂商产生什么审计事件、留不留、投哪」 | `cloud-audit-log-systems.md` |
| 查「关键攻击动作 → 各厂商审计事件名 → 检测规则要点/Sigma」 | `cloud-detection-rule-design.md` |
| 判定「这条路径检测到/未检测到/无法评估」并落 C5 编码 | `cloud-detection-gap-methodology.md` |
| 对照「控制面告警清单 + 日志投递完整性」打分 | `cloud-monitoring-alerting-baseline.md` |

## 目录索引

| 文件 | 内容 | 何时读 |
|---|---|---|
| cloud-audit-log-systems.md | 六厂商审计日志体系（AWS CloudTrail / Azure Monitor Activity Log + Entra ID / GCP Cloud Audit Logs / 阿里云 ActionTrail / 腾讯云 CloudAudit / 华为云 CTS）：事件类型、关键字段、留存与投递配置、跨厂商字段对照 | 判定「应留什么日志」前 |
| cloud-detection-rule-design.md | 云检测规则设计：关键攻击动作 → 审计事件名映射总表、各厂商高价值事件清单、检测规则三问、Sigma 规则云版思路、规则产出优先级 | 产出检测规则建议 / 判「对应什么规则」 |
| cloud-detection-gap-methodology.md | 云检测缺口分析方法论：三态判定（检测到/未检测到/无法评估 + 不适用）→ C5 门编码（gap=1/无法评估=0/不适用=2）、判定流程、四要素检查点、判定示例、detection-gap.md 模板 | C5 检测缺口评估全程 |
| cloud-monitoring-alerting-baseline.md | 云安全监控与告警基线：控制面变更告警清单（身份权限/暴露面/反取证/侦察）、日志投递完整性检查清单、告警基线自测打分表、各厂商告警配置锚点 | 检测缺口收口对照打分 |

## 计数

- md 文件总数：**4 篇**（不含本 README.md）
- cloud-audit-log-systems.md / cloud-detection-rule-design.md /
  cloud-detection-gap-methodology.md / cloud-monitoring-alerting-baseline.md 各 1 篇

## 原创与许可说明

- 本目录正文**全部自写原创**，未照抄任何第三方正文，正文不引用任何外部 URL。
- 技术事实（事件名、字段名、端点、策略语法、ATT&CK 编号）为公开标准信息，属正常保留范畴。
- 只写授权测试与检测知识，不含攻击载荷；攻击框架类工具仅在授权范围内使用。

## 路径与链接约定

- 库内文件一律相对路径引用，**禁止任何本机绝对路径**（预设将打包给其他用户使用）。
- 跨目录引用用相对路径：检测侧 ↔ 知识侧用 `../knowledge/<文件>.md`。
- refs/ 不经技能加载器发现，仅由 read 按需读取；本目录面向云安全评估的检测侧，
  与知识侧 `../knowledge/`（附录 A/B、IAM 速查、工具卡、ATT&CK）配合使用。

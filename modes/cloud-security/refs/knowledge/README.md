# cloud-security 参考手册库 · 知识索引（refs/knowledge/）

> 本目录随 cloud-security 预设打包分发。所有文件为预设内自包含资源，不依赖任何机器特定路径。
> 定位：知识索引——六厂商元数据端点、只读探测纪律、IAM 策略语法、工具卡、ATT&CK 云矩阵五类
> 跨阶段速查底座；cloud-playbook「附录」指向本目录（附录 A / 附录 B）。需要细节时用 read 读取。
> 路径解析：加载 cloud-playbook 技能时得到 SKILL.md 所在目录（`skills/cloud-playbook/`），
> refs/ 相对该目录 = `../../refs/`。
> 口径：全部中文原创；正文不引用任何外部 URL，不出现任何出处性表述；技术事实（端点、API 名、
> 策略语法、ATT&CK 编号）为公开标准信息正常保留。共 5 篇 md。

## 快速路由（按任务找文件）

| 阶段/任务 | 文件 |
|---|---|
| 元数据 SSRF / 实例身份接管（附录 A） | `metadata-service-endpoints.md` |
| 只读 API 验证纪律、限速与账单意识（附录 B） | `cloud-api-readonly-probing.md` |
| IAM/策略语法对比、过宽权限判定 | `iam-policy-language-cheatsheet.md` |
| 选云安全评估工具 | `cloud-security-tool-cards.md` |
| 报告 ATT&CK Cloud Matrix 映射 | `attck-cloud-matrix.md` |

## 目录索引

| 文件 | 内容 | 何时读 |
|---|---|---|
| metadata-service-endpoints.md | 六厂商元数据服务端点与实例身份对照（附录 A）：端点 IP/域名/认证方式总览、AWS IMDS v1/v2、Azure IMDS、GCP 元数据、阿里云/腾讯云/华为云元数据、身份凭证路径对照、禁用方法对照、检测侧映射 | 元数据 SSRF 探测与实例身份接管验证 |
| cloud-api-readonly-probing.md | 云 API 只读探测纪律与速率默认值（附录 B）：只读 API 示例、速率/限流与退避、账单意识、最小影响验证原则、探测前检查清单 | 任何云 API 验证动作前 |
| iam-policy-language-cheatsheet.md | IAM/权限策略语言速查：AWS IAM / Azure RBAC / GCP IAM / 阿里云 RAM 语法对比、常见过宽权限模式清单、权限链收口口径 | 权限链收口（C4）与过宽权限判定 |
| cloud-security-tool-cards.md | 云安全工具卡（ScoutSuite / Prowler / Pacu / CloudFox / endgame / cloudsplaining / CDK / kube-hunter / peirates / trufflehog / gitleaks / checkov / terrascan）：每卡用途/获取/核心用法/检测侧价值，工具选型组合 | 选工具、查用法 |
| attck-cloud-matrix.md | ATT&CK Cloud Matrix 速查：云矩阵战术总表、技术 ID 与 Azure/GCP 变体对照、云攻击路径 → ATT&CK 映射速查 | 报告第 7 章映射 |

## 计数

- md 文件总数：**5 篇**（不含本 README.md）
- metadata-service-endpoints.md / cloud-api-readonly-probing.md /
  iam-policy-language-cheatsheet.md / cloud-security-tool-cards.md /
  attck-cloud-matrix.md 各 1 篇

## 原创与许可说明

- 本目录正文**全部自写原创**，未照抄任何第三方正文，正文不引用任何外部 URL。
- 技术事实（端点、API 名、策略语法、ATT&CK 编号）为公开标准信息，属正常保留范畴。
- 工具二进制一律不随附，只写获取路径（包管理器安装命令或「官方仓库 Release 下载」，不写 URL）；
  攻击框架类工具（Pacu / CloudFox / endgame / peirates / CDK）仅在授权范围内使用，不做武器化。

## 路径与链接约定

- 库内文件一律相对路径引用，**禁止任何本机绝对路径**（预设将打包给其他用户使用）。
- 跨目录引用用相对路径：知识侧 ↔ 检测侧用 `../detection/<文件>.md`。
- refs/ 不经技能加载器发现，仅由 read 按需读取；本目录与检测侧 `../detection/`
  （审计日志体系 / 检测规则设计 / 缺口方法论 / 监控告警基线）配合使用。

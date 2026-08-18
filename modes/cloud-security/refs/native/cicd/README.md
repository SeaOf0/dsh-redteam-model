# cicd/ 参考手册（云原生 · CI-CD）

> 本目录随 cloud-security 预设打包分发，是 `refs/native/cicd/` 下关于持续集成/持续交付链
> （代码仓库 → 流水线 → 制品仓库 → IaC 落地）攻击面的深度手册。所有文件为预设内自包含
> 资源，互相引用只用相对路径，不依赖机器特定路径。路径解析：相对 `refs/native/` 即 `cicd/`；
> 从 SKILL 侧访问用 `refs/native/cicd/`。

## 授权立场提醒（先读）

- 本目录属 cloud-security 授权攻防立场：攻击视角默认授权，只读命令优先，破坏性/变更性操作
  先询问，删除操作只出清单由用户确认后执行。
- 每篇利用路径条目都配**检测侧对照**（CI/仓库/云审计 + secret scanning + CSPM）；检测侧
  情报回馈 attack-defense 与 `detection-gap.md`。
- 破坏性步骤一律标「授权内人工确认后执行」；凭证发现登记后提示轮换。

## 快速路由（按研究类型找文件）

| 研究类型 | 文件 |
|---|---|
| CI-CD 流水线攻击面（构建凭据泄露/Runner 接管） | `01-pipeline-attack-surface.md` |
| 代码仓库权限滥用 | `02-code-repo-permission-abuse.md` |
| 制品仓库投毒与签名绕过 | `03-artifact-repo-poisoning.md` |
| IaC 模板缺陷引入（Terraform/CFN 权限过宽） | `04-iac-template-misconfig.md` |

## 目录索引

| 文件 | 内容 | 何时读 |
|---|---|---|
| 01-pipeline-attack-surface.md | 流水线入口/构建凭据/Runner 接管/配置篡改 | 评估 CI/CD 通道时 |
| 02-code-repo-permission-abuse.md | 仓库可见性/历史密钥/.git 暴露/分支保护 | 从源码找凭证时 |
| 03-artifact-repo-poisoning.md | 制品仓库访问/投毒/签名绕过/依赖混淆 | 评估制品交付链时 |
| 04-iac-template-misconfig.md | Terraform/CFN 权限过宽/公开资源/state 泄露/漂移 | 审计基础设施配置时 |

## 计数

共 4 篇 md。

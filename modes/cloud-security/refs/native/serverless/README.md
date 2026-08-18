# serverless/ 参考手册（云原生 · Serverless）

> 本目录随 cloud-security 预设打包分发，是 `refs/native/serverless/` 下关于云函数（Lambda/
> Functions/函数计算/SCF 等）攻击面的深度手册。所有文件为预设内自包含资源，互相引用只用
> 相对路径，不依赖机器特定路径。路径解析：相对 `refs/native/` 即 `serverless/`；从 SKILL 侧
> 访问用 `refs/native/serverless/`。

## 授权立场提醒（先读）

- 本目录属 cloud-security 授权攻防立场：攻击视角默认授权，只读命令优先，破坏性/变更性操作
  先询问，删除操作只出清单由用户确认后执行。
- 每篇利用路径条目都配**检测侧对照**（云审计事件名 / 函数日志 / SCA）；检测侧情报回馈
  attack-defense 与 `detection-gap.md`。
- 破坏性步骤一律标「授权内人工确认后执行」；凭证发现登记后提示轮换。

## 快速路由（按研究类型找文件）

| 研究类型 | 文件 |
|---|---|
| 函数权限与触发器滥用（事件注入/S3 触发链） | `01-function-permission-trigger-abuse.md` |
| 环境变量与密钥 | `02-env-secrets.md` |
| 函数供应链与依赖投毒 | `03-supply-chain-dependency-poisoning.md` |
| 云函数特有持久化 | `04-function-persistence.md` |

## 目录索引

| 文件 | 内容 | 何时读 |
|---|---|---|
| 01-function-permission-trigger-abuse.md | 触发器面/函数权限面/事件注入/S3 触发链/越权调用 | 评估函数入口与事件源时 |
| 02-env-secrets.md | 环境变量凭证面、只读提取、AK/SK 放大链 | 找函数密钥时 |
| 03-supply-chain-dependency-poisoning.md | 依赖投毒/部署包泄露/Layer 投毒/CI 打包 | 审计函数供应链时 |
| 04-function-persistence.md | 定时后门/事件源追加/凭证后门/版本别名后门/信任策略 | 做持久化与检测侧评估时 |

## 计数

共 4 篇 md。

# 云安全工具卡

> 定位：知识索引手册。云安全评估常用工具速查，每卡「用途 / 获取 / 核心用法 / 检测侧价值」。
> 工具二进制一律不随附，只写获取路径（包管理器安装命令，或「官方仓库 Release 下载」，不写
> 下载 URL）；工具缺装且用户不让装时，按主观念用脚本等价实现（python3 优先，落 scripts/，
> 登记 evidence-index）。所有工具仅在授权范围内使用，攻击框架（Pacu/CloudFox/endgame/peirates/
> CDK）只用于授权演练，不做武器化。

## 1. ScoutSuite

| 项 | 内容 |
|---|---|
| 用途 | 多云安全配置审计（AWS/Azure/GCP/阿里云/OCI），一次性拉全账号/订阅/项目配置并产出报告 |
| 获取 | `pip install scoutsuite`（或 `pipx run scoutsuite`） |
| 核心用法 | `scout aws` / `scout azure` / `scout gcp` / `scout aliyun`；用只读凭证/CLI 已登录身份扫描，产出 HTML 报告与 JSON 结果 |
| 检测侧价值 | 基线「配置缺陷清单」：公开桶、过宽安全组、未加密存储、MFA 缺失；结果可对照 C5 缺口与配置缺陷清单 |

## 2. Prowler

| 项 | 内容 |
|---|---|
| 用途 | 云安全合规与配置基线检查（AWS/Azure/GCP/K8s），对标 CIS 等基线，逐项 PASS/FAIL |
| 获取 | `pip install prowler`（或 `pipx`） |
| 核心用法 | `prowler aws` / `prowler azure` / `prowler gcp` / `prowler kubernetes`；`-M` 指定合规框架，输出 HTML/JSON/CSV |
| 检测侧价值 | 直接给「合规缺口」与 CIS 对照；可作为配置缺陷与检测基线证据，报告里引用其 FAIL 项 |

## 3. Pacu

| 项 | 内容 |
|---|---|
| 用途 | AWS 攻击模拟框架（授权演练）：模块化枚举、提权、横向、持久化模拟 |
| 获取 | `pip install pacu` |
| 核心用法 | `pacu` 进入交互 shell → `set_keys` 或 `import_keys` 载入凭证 → `ls` 列模块 → `run <module>`；模块分 recon/privesc/lateral/persistence 等 |
| 检测侧价值 | 演练动作可对照 `cloud-detection-rule-design.md` 判定「哪些动作会留日志、规则是否覆盖」；仅授权范围使用 |

## 4. CloudFox

| 项 | 内容 |
|---|---|
| 用途 | 云环境枚举与攻击路径发现（AWS/Azure/GCP，Go 编写，可单二进制跑） |
| 获取 | 官方仓库 Release 下载二进制（不随附）；或源码 `go build` |
| 核心用法 | 用云凭证/配置运行子命令（`aws`/`azure`/`gcp` 命名空间），枚举 IAM 角色、信任关系、可提权路径、密钥等 |
| 检测侧价值 | 输出「可提权/可横向路径」，与 C4 权限链收口互证；枚举动作可映射检测规则 |

## 5. endgame

| 项 | 内容 |
|---|---|
| 用途 | AWS 攻击路径自动化（授权演练）：从给定凭证出发找可滥用权限链 |
| 获取 | `pip install endgame` |
| 核心用法 | 载入 AK/SK/Token → 枚举可执行动作，自动生成「攻击路径」与利用建议 |
| 检测侧价值 | 与 CloudFox/Pacu 同定位，用于攻击路径闭环证据；仅授权范围使用 |

## 6. cloudsplaining

| 项 | 内容 |
|---|---|
| 用途 | AWS IAM 最小权限审计：找出策略里的过宽权限与可提权路径 |
| 获取 | `pip install cloudsplaining` |
| 核心用法 | `cloudsplaining download`（拉 IAM）→ `cloudsplaining scan` → 产出 HTML 报告，标出 `*` 资源、`iam:*`、`sts:AssumeRole` 无条件等 |
| 检测侧价值 | 直接支撑 `iam-policy-language-cheatsheet.md` 的过宽权限清单；结果进配置缺陷清单与 C4 权限链 |

## 7. CDK（容器渗透工具包）

| 项 | 内容 |
|---|---|
| 用途 | 容器/K8s 渗透测试工具包（零依赖），容器逃逸、K8s 提权、云元数据利用（授权演练） |
| 获取 | 官方仓库 Release 下载二进制（不随附） |
| 核心用法 | 在目标容器内运行 `cdk evaluate`（评估逃逸面）/ `cdk run` 等；覆盖逃逸、K8s 攻击、元数据探测 |
| 检测侧价值 | 演练容器逃逸/K8s 提权路径，对照检测规则判定覆盖；仅授权范围使用 |

## 8. kube-hunter

| 项 | 内容 |
|---|---|
| 用途 | Kubernetes 集群渗透测试（扫描集群暴露面与已知弱点） |
| 获取 | `pip install kube-hunter`（或官方容器镜像） |
| 核心用法 | `kube-hunter --remote <api-server>`（远程）或 `kube-hunter`（集群内 active/passive）；输出漏洞报告 |
| 检测侧价值 | K8s 暴露面与弱点的配置缺陷证据；结果进 C1 资产测绘与配置缺陷清单 |

## 9. peirates

| 项 | 内容 |
|---|---|
| 用途 | Kubernetes 后渗透工具包（已进入集群后的横向/提权/凭证搜集，授权演练） |
| 获取 | 官方仓库 Release 下载二进制（不随附）；源码 `go build` |
| 核心用法 | 交互式菜单：枚举 secrets、service account token、尝试提权与横向 |
| 检测侧价值 | 演练 K8s 内后渗透，对照 K8s 审计日志判定检测覆盖；仅授权范围使用 |

## 10. trufflehog

| 项 | 内容 |
|---|---|
| 用途 | 密钥/凭证泄露扫描（git 历史、仓库、S3、容器镜像等） |
| 获取 | 官方仓库 Release 下载二进制（不随附）；或 `brew install trufflehog` |
| 核心用法 | `trufflehog git <repo>` / `trufflehog s3` / `trufflehog filesystem <dir>`；多数据源扫描并验证凭据有效性 |
| 检测侧价值 | 支撑「AK/SK 与凭证泄露」入口发现；发现的凭证登记出处与权限范围后提示轮换 |

## 11. gitleaks

| 项 | 内容 |
|---|---|
| 用途 | Git 仓库密钥扫描（提交历史与工作区），CI 可嵌入 |
| 获取 | 官方仓库 Release 下载二进制（不随附）；或 `brew install gitleaks` |
| 核心用法 | `gitleaks detect`（含历史）/ `gitleaks git --log`；输出匹配的密钥类型与位置 |
| 检测侧价值 | 与 trufflehog 同定位，代码仓库凭证泄露入口发现 |

## 12. checkov

| 项 | 内容 |
|---|---|
| 用途 | IaC 静态审计（Terraform/CloudFormation/K8s/Helm/Dockerfile 等），云配置与合规检查 |
| 获取 | `pip install checkov` |
| 核心用法 | `checkov -d <dir>`；内置上千条策略，输出 PASS/FAIL 与修复建议 |
| 检测侧价值 | IaC 侧配置缺陷与合规缺口（对应 code-audit 协同）；结果进配置缺陷清单 |

## 13. terrascan

| 项 | 内容 |
|---|---|
| 用途 | IaC 与云配置安全扫描（多 IaC 与多厂商） |
| 获取 | 官方仓库 Release 下载二进制（不随附）；或 `brew install terrascan` |
| 核心用法 | `terrascan scan -d <dir>`；按策略框架输出违规与修复 |
| 检测侧价值 | 与 checkov 互补的 IaC 配置缺陷证据；可做跨工具复核 |

## 14. 工具选型与组合

| 任务 | 首选 | 备注 |
|---|---|---|
| 全账号配置基线 | ScoutSuite / Prowler | 只读、一次性、报告友好 |
| CIS 合规对照 | Prowler | 框架 `-M` 指定 |
| 过宽权限/提权路径 | cloudsplaining / CloudFox / endgame | 与 C4 权限链互证 |
| 攻击路径演练 | Pacu / CloudFox / endgame | 仅授权范围 |
| 容器/K8s 暴露面 | kube-hunter | 远程或集群内 |
| 容器/K8s 后渗透演练 | CDK / peirates | 仅授权范围 |
| 凭证泄露入口 | trufflehog / gitleaks | 前端 JS/小程序包另走 pentest 协同 |
| IaC 配置审计 | checkov / terrascan | 与 code-audit 协同 |

> 工具检测到才用（开工 `command -v` 探测并登记 evidence-index tool-plane 节）；
> 检测到的优先 → 缺装走脚本兜底 → 用户确认安装兜底，绝不自动安装（主观念工具策略）。

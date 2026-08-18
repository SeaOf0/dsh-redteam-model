# IaC 模板缺陷引入：Terraform / CloudFormation 权限过宽

> 定位：基础设施即代码（IaC）把云资源配置固化成模板，配置缺陷在「代码评审期」埋下、在
> 「部署期」落地成真实攻击面。本手册梳理 Terraform/CloudFormation 的权限过宽、密钥硬编码、
> 漂移与只读审计方法，每条路径配检测侧对照。破坏性步骤标「授权内人工确认后执行」。

## 1. 攻击面

IaC 缺陷的引入面：

| 面 | 形态 | 风险 |
|---|---|---|
| 权限面 | IAM 策略 `*`、过度 `Allow`、公开桶 | 落地即过宽权限 |
| 密钥面 | 模板硬编码密钥、state 文件泄露 | 凭证外泄 |
| 漂移面 | 手动改过的资源与模板不一致 | 审计盲区、未登记后门 |
| 状态面 | Terraform state 含明文敏感值、未加密存储 | state 泄露 = 配置泄露 |

核心风险：IaC 缺陷是「预先授权的错误」——评审放过 → CI 自动部署 → 生产暴露，且可复现、
可扩散（一套模板复制到多环境）。

## 2. 暴露面探测（只读命令优先）

### 2.1 模板只读静态审计

```bash
# 用 IaC 扫描工具只读扫模板（不联网不改动）
tfsec . 2>/dev/null | head
checkov -d . 2>/dev/null | head
terrascan scan -d . 2>/dev/null | head
kics scan -p . 2>/dev/null | head
# 直接 grep 高危模式
grep -rniE 'Effect.*Allow|Action.*\*|Principal.*\*|"AccessKey|SecretKey' *.tf *.json *.yaml 2>/dev/null
```

判定口径：命中 `Action: *`、`Resource: *`、`Principal: *`、公开桶（`acl=public-read`）、
明文密钥 = 权限过宽/凭证泄露。

### 2.2 state 文件与锁只读盘点

```bash
# Terraform state 是否明文含敏感值、是否加密存储（只读检查配置与远端存储）
grep -rniE 'password|secret|access_key|private_key' terraform.tfstate 2>/dev/null
# state 远端存储（S3/OSS）是否加密、是否公开（只读查询）
aws s3api get-bucket-encryption --bucket <state-bucket> 2>/dev/null
aws s3api get-bucket-acl --bucket <state-bucket> 2>/dev/null
```

判定口径：state 含明文密钥 / state 桶公开或未加密 = 高价值泄露面。

### 2.3 漂移只读检测

```bash
# 检测已部署资源与模板的差异（只读 plan，不 apply）
terraform plan -refresh-only 2>/dev/null | head
# CloudFormation drift detection（只读）
aws cloudformation detect-stack-drift --stack-name <s> 2>/dev/null
```

判定口径：`refresh-only` 显示差异 = 存在漂移（可能含未登记的手动后门）。

## 3. 缺陷与利用路径

### 3.1 IAM 权限过宽（`*` 策略 / 过度 Allow）

- 缺陷：模板里 `Action: "*"`、`Resource: "*"`，或给服务角色/用户绑了过宽策略；生产角色
  权限远大于所需。
- 验证命令（只读）：`tfsec`/`checkov` 命中 + grep 高危模式；`aws iam get-role-policy` 读
  实际落地策略。
- 影响：任一身份被利用即越权到全账号资源。
- 检测侧：云审计记录该身份的资源操作；IaC 扫描告警（CI 门禁）；权限清单登记 `cloud-assets.md`。

### 3.2 公开资源落地（公开桶 / 公开端口 / 公开函数）

- 缺陷：模板把桶设 `public-read`/`public-write`、安全组全开 `0.0.0.0/0`、函数/API 公开。
- 验证命令（只读）：`tfsec`/`checkov` 命中；部署后 `aws s3api get-bucket-acl`/安全组只读
  查询复核。
- 影响：数据公开可读/可写，入口暴露公网。
- 检测侧：云审计记录资源配置；云配置审计（CSPM）告警公开资源；网络流日志记录异常访问。

### 3.3 模板硬编码密钥 / state 泄露

- 缺陷：模板把 AK/SK/密码写死；Terraform state 明文存敏感值且桶公开/未加密。
- 验证命令（只读）：grep 模板与 state 的密钥模式；state 桶加密/ACL 只读查询。
- 影响：凭证外泄，横向到云/内部系统。
- 检测侧：secret scanning 命中；云审计记录 state 桶访问（匿名/异常）；凭证使用审计。

### 3.4 配置漂移引入未登记后门

- 缺陷：生产资源被手动改动（开端口、加权限、加用户），模板未更新，审计只看模板会漏；
  或攻击者利用漂移隐藏持久化。
- 验证命令（只读）：`terraform plan -refresh-only` / `detect-stack-drift` 找差异。
- 影响：未登记的暴露面/后门持续存在。
- 检测侧：云配置审计（CSPM）与模板持续对账；漂移检测告警；云审计记录手动配置变更。

### 3.5 供应商标注缺陷（模块/Provider 引入过宽权限）

- 缺陷：引用的第三方 Terraform 模块/CloudFormation 宏/Provider 内嵌过宽策略或后门。
- 验证命令（只读）：读模块源码（`terraform init` 拉取后本地只读审计）+ IaC 扫描覆盖模块。
- 影响：过宽权限/后门随模块扩散到所有使用者。
- 检测侧：模块供应链审计 + 扫描；云审计记录落地权限异常。

### 3.6 漂移检测与模板权威化缺失的检测盲区

- 缺陷：组织未定期跑漂移检测、未强制「改资源走代码」，手动改动积累成未登记的暴露面与后门。
- 验证命令（只读）：`terraform plan -refresh-only` / `detect-stack-drift` 只读找差异；
  读资源与模板的映射台账。
- 影响：后门/暴露面长期存在且不被审计发现。
- 检测侧：云配置审计（CSPM）与模板持续对账；漂移检测告警；云审计记录手动配置变更。

## 4. 提权与持久化

- 提权链：过宽 IAM → 任一身份越权 → 云账号；state 密钥 → 云/内部系统；漂移后门 → 长期
  入口。
- 持久化（授权内人工确认后执行）：在模板加隐蔽后门用户/角色/安全组规则，利用「模板即
  权威」让后续部署自动重建后门；逐项登记 `environment-restore.md`。

## 5. 检测与加固要点

### 5.1 检测事件名对照

| 攻击行为 | 检测层 + 事件 |
|---|---|
| 过宽策略落地 | IaC 扫描告警（CI 门禁）+ 云配置审计 |
| 公开资源落地 | CSPM 告警 + 云审计资源配置事件 |
| state/模板密钥泄露 | secret scanning + state 桶访问审计 |
| 手动配置变更（漂移/后门） | 云审计资源写事件 + 漂移检测告警 |
| 模块供应链投毒 | 模块审计 + 扫描 + 云审计异常权限 |

### 5.2 加固要点

- IaC 扫描（tfsec/checkov/terrascan/kics）进 CI 门禁，高危即阻断；策略最小化，禁 `*`。
- state 远程存储加密 + 私有 + 访问审计；state 内敏感值用变量/托管密钥，禁明文。
- 定期漂移检测 + 模板权威化（改资源走代码，禁手动改）；公开资源默认私有。
- 模块/Provider 归属审计 + 锁定版本；落地权限与模板持续对账。

## 6. MITRE ATT&CK 映射

| 技术 | ATT&CK ID |
|---|---|
| 配置/权限篡改 | T1098 Account Manipulation |
| 模板供应链投毒 | T1195 Supply Chain Compromise |
| 复用过宽身份 | T1078 Valid Accounts |
| 云存储数据窃取 | T1530 Data from Cloud Storage |

## 7. 证据记录要点

- 每条路径登记四要素（身份→权限→资源→影响）+ 证据编号，落 attack-paths.md。
- IaC 扫描命中、漂移差异、state 泄露结论登记 evidence-index.md。
- 破坏性步骤在 environment-restore.md 逐项登记还原方式。

## 8. 只读探测命令速查

| 探测目标 | 只读命令 |
|---|---|
| 模板高危模式 | `tfsec`/`checkov`/`terrascan`/`kics` 只读扫 |
| state 敏感值 | `grep terraform.tfstate` 密钥模式 |
| state 桶加密/ACL | `get-bucket-encryption`/`get-bucket-acl` |
| 漂移差异 | `terraform plan -refresh-only` / `detect-stack-drift` |

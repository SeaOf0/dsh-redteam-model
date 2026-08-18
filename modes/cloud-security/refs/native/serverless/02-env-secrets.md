# Serverless 环境变量与密钥

> 定位：Serverless 函数把配置与密钥塞进环境变量，成为比传统主机更集中的凭证面。本手册
> 梳理环境变量里的密钥类型、只读提取方法、凭证到云账号的放大链与检测侧对照。凭证发现后
> 提示轮换，破坏性步骤标「授权内人工确认后执行」。

## 1. 攻击面

函数环境变量承载的敏感面：

| 类型 | 载体 | 风险 |
|---|---|---|
| 云凭证 | AK/SK、服务账号 key、临时 token | 函数 → 云账号越权 |
| 第三方密钥 | 数据库密码、API Key、私钥 | 横向到第三方系统 |
| 内部配置 | 内部端点、连接串、加解密盐 | 内网渗透跳板 |
| 运行时元数据 | 函数名、区域、执行角色 ARN | 后续攻击路径拼接 |

环境变量的泄露面：函数配置读权限、代码注入读取 `process.env`、依赖投毒读环境、日志把
环境变量打出来、前序环节（CI/仓库）泄露。

## 2. 暴露面探测（只读命令优先）

### 2.1 函数环境变量只读盘点（有权限时）

```bash
# AWS：读函数配置里的 Environment（只读）
aws lambda get-function-configuration --function-name <f> --query 'Environment'
aws lambda get-function --function-name <f> --query 'Configuration.Environment.Variables'
```

判定口径：环境变量键命中 `*KEY*`/`*SECRET*`/`*PASSWORD*`/`*TOKEN*`/`*AK*`/`*SK*` 即登记；
值脱敏引用，不进报告原文。

### 2.2 泄露面只读盘点

```bash
# 函数代码是否读取 env（本地只读分析源码）
aws lambda get-function --function-name <f> --query 'Code.Location'   # 拿代码位置（临时 URL，只读下载）
# 函数日志是否把 env 打进输出（只读查日志）
aws logs filter-log-events --log-group-name /aws/lambda/<f> --filter-pattern '"AKIA"' 2>/dev/null
```

判定口径：日志命中 `AKIA`/`SecretKey`/token 前缀 = 环境变量被日志泄露（高危，须提示轮换）。

### 2.3 执行角色与密钥放大只读盘点

```bash
aws sts get-caller-identity          # 若已在函数上下文，自省身份
aws iam list-attached-role-policies --role-name <role>
```

判定口径：环境变量里的 AK/SK 对应身份 = 执行角色；其权限清单决定放大面。

## 3. 缺陷与利用路径

### 3.1 环境变量明文存云凭证（AK/SK 直接写死）

- 缺陷：函数环境变量写死长期 AK/SK 或高权服务账号 key，而非用执行角色/临时凭证。
- 验证命令（只读）：`get-function-configuration` 读 `Environment.Variables`，命中 AK/SK 键。
- 影响：长期凭证泄露即长期越权；即使函数被删，静态凭证仍可被复用。
- 检测侧：云审计记录该 AK/SK 后续调用（`GetCallerIdentity`、资源操作）；凭证轮换审计；
  配置变更审计记录环境变量修改。

### 3.2 代码注入 / 依赖投毒读取 process.env

- 缺陷：函数存在命令注入/反序列化/依赖投毒，攻击者读 `process.env` 批量窃取全部环境变量。
- 验证命令（只读）：源码只读分析可注入点；依赖清单（`requirements.txt`/`package.json`）只读
  比对已知恶意依赖。
- 影响：一次性拖走全部密钥。
- 检测侧：函数日志异常输出；运行时行为审计（若开）；云审计记录函数调用异常；依赖扫描命中。

### 3.3 环境变量被日志 / 错误信息打出

- 缺陷：函数把 `env` 或异常堆栈（含请求头/环境）打进日志，日志落到 CloudWatch/日志服务。
- 验证命令（只读）：`filter-log-events` 搜密钥前缀/键名。
- 影响：日志读取权限即可拿到密钥；日志被导出/订阅后进一步外泄。
- 检测侧：日志服务访问审计（谁读了日志）；secret scanning 对日志内容扫描；云审计记录日志
  导出/订阅配置变更。

### 3.4 环境变量加密未用 / KMS 权限过宽

- 缺陷：环境变量未用 KMS 加密（`KMSKeyArn` 为空），或 KMS 密钥策略过宽使低权主体能解密。
- 验证命令（只读）：`get-function-configuration` 看 `Environment` 是否配 `KMSKeyArn`；读 KMS
  密钥策略（`get-key-policy`）看可解密主体。
- 影响：明文环境变量 + 过宽解密权限 = 密钥面扩大。
- 检测侧：云审计记录 `Decrypt` 调用；KMS 密钥策略变更审计。

### 3.5 第三方密钥泄露横向（数据库/API Key/私钥）

- 缺陷：环境变量里的第三方密钥（数据库密码、内部 API Key、TLS 私钥）泄露后，横向到对应
  第三方系统，而不止于云账号。
- 验证命令（只读）：环境变量键命中第三方密钥特征（`DB_PASSWORD`/`API_KEY`/`PRIVATE_KEY`）；
  只读探测对应系统的可达性与身份。
- 影响：横向到内部数据库/服务，扩大影响面。
- 检测侧：第三方系统访问审计；云审计记录函数调用；secret scanning 命中；日志脱敏审计。

### 3.6 临时凭证过期/残留滥用（IAM 长期凭证残留）

- 缺陷：函数本应用临时凭证，但环境变量残留了长期 IAM 用户 AK/SK；或临时凭证过期后未清理，
  被其它身份复用。
- 验证命令（只读）：`get-function-configuration` 读环境变量找长期 AK；`GetCallerIdentity`
  自省身份类型（用户/角色）；`list-access-keys` 看密钥状态。
- 影响：长期凭证不随实例销毁，泄露后长期可用。
- 检测侧：云审计记录该 AK 调用与源 IP；凭证轮换与过期审计；配置变更审计。

## 4. 提权与持久化

- 提权链：环境变量 AK/SK → 云账号自省 → 权限放大（IAM 提权）→ 资源接管；
  环境变量第三方密钥 → 第三方系统横向。
- 持久化（授权内人工确认后执行）：在函数环境变量写入攻击者可控凭证/后门回调；创建低检测
  的定时函数。逐项登记 `environment-restore.md`。

## 5. 检测与加固要点

### 5.1 检测事件名对照

| 攻击行为 | 检测层 + 事件 |
|---|---|
| 读函数配置/环境变量 | 云审计 `GetFunction`/`GetFunctionConfiguration` |
| 日志密钥搜索 | 日志服务访问审计 + secret scanning |
| AK/SK 异常调用 | 云审计 `GetCallerIdentity` + 资源操作（异常源 IP/时间） |
| 环境变量修改 | 云审计 `UpdateFunctionConfiguration`（含 Environment 变更） |
| 解密调用 | 云审计 KMS `Decrypt` |

### 5.2 加固要点

- 环境变量优先用执行角色 + 临时凭证（IRSA/Workload Identity），禁长期 AK/SK。
- 敏感环境变量用 KMS 加密 + 密钥策略最小化；日志脱敏（禁打 env/堆栈明文）。
- 函数代码防注入；依赖锁定 + 扫描；日志读取权限最小化。
- 凭证集中管理（Secrets Manager/SSM），函数运行时按需取，短生命周期。

## 6. MITRE ATT&CK 映射

| 技术 | ATT&CK ID |
|---|---|
| 环境变量凭证泄露 | T1552 Unsecured Credentials |
| 复用泄露凭证 | T1078 Valid Accounts |
| 凭证存储窃取 | T1555 Credentials from Password Stores |

## 7. 证据记录要点

- 每条路径登记四要素（身份→权限→资源→影响）+ 证据编号，落 attack-paths.md。
- 环境变量键命中敏感模式即登记，值脱敏引用，登记归属后提示轮换。
- 破坏性步骤在 environment-restore.md 逐项登记还原方式。

## 8. 只读探测命令速查

| 探测目标 | 只读命令 |
|---|---|
| 环境变量 | `get-function-configuration` --query Environment |
| 日志密钥搜索 | `filter-log-events` --filter-pattern 密钥模式 |
| 身份自省 | `sts get-caller-identity` |

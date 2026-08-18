# 从 SSRF 到元数据 CAM 临时凭证攻防

> 面向授权安全测试的元数据服务攻击面梳理与方法论，聚焦 SSRF 到元数据接口、再到 CAM 角色临时凭证的完整链路。所有验证以只读探测优先，破坏性操作需「授权内人工确认后执行」。

## 一、攻击面

腾讯云元数据服务为实例提供自身配置、网络信息与身份凭证，是 SSRF 与任意文件读取类漏洞升级为云 API 越权的关键跳板。攻击面可归纳为：

- **元数据接口面**：`169.254.0.23`（别名 `metadata.tencentyun.com`）上的各类只读路径。
- **身份凭证面**：实例绑定 CAM 角色后，元数据服务返回该角色的临时凭证。
- **触发源面**：应用内 SSRF、URL 重定向、文件读取、代理转发等可访问链路。
- **凭证使用面**：临时凭证被用于调用云 API，实现资源枚举与横向移动。

下表列出元数据攻击面与对应防守视角：

| 攻击面 | 攻击者关注点 | 防守者关注点 |
| --- | --- | --- |
| 元数据接口 | 实例信息、角色名枚举 | 实例侧访问日志、网络策略 |
| 临时凭证 | 角色凭证窃取 | `AssumeRole` 审计 |
| SSRF 触发源 | 应用层 SSRF/文件读取 | 应用日志、WAF |
| 凭证使用 | 云 API 越权调用 | CloudAudit API 调用日志 |

## 二、信息收集 / 暴露面探测

以下命令均为只读探测，用于在实例内确认元数据服务可达性与返回内容。

```bash
# 基础连通性（只读）
curl http://metadata.tencentyun.com/latest/meta-data/

# 等价 IP 形式（只读）
curl http://169.254.0.23/latest/meta-data/
```

常见元数据路径（均为只读）：

```bash
# 实例 ID
curl http://metadata.tencentyun.com/latest/meta-data/instance-id

# 本机内网 IP
curl http://metadata.tencentyun.com/latest/meta-data/local-ipv4

# 公网 IP
curl http://metadata.tencentyun.com/latest/meta-data/public-ipv4

# 绑定角色名（若绑定角色）
curl http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/
```

返回为空或报错通常表示实例未绑定 CAM 角色；返回角色名则进入临时凭证获取环节。

## 三、常见配置缺陷与利用路径

### 3.1 应用内 SSRF 直达元数据接口

**缺陷描述**：应用存在 SSRF（服务端请求伪造），且未对目标地址做过滤（未拦截链路本地地址、内网地址与 `metadata.tencentyun.com`），攻击者构造请求访问元数据接口。

**验证命令（只读优先）**：

```bash
# 经 SSRF 目标探测元数据接口（只读，最小影响）
curl "$APP_URL/fetch?url=http://metadata.tencentyun.com/latest/meta-data/"
```

**影响**：SSRF 可读取实例元数据，若实例绑定 CAM 角色，可进一步窃取临时凭证并调用云 API。

**检测侧建议**：SSRF 触发行为由应用访问日志记录（异常目标地址、内网/链路地址访问）；防守侧应部署出站过滤与 SSRF 防护，SOC 对访问元数据地址的请求建立告警；凭证签发由 CloudAudit `AssumeRole` 记录。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | SSRF → 元数据接口读取 |
| 防守者 | 应用日志异常目标、CloudAudit `AssumeRole` |

### 3.2 任意文件读取/代理转发访问元数据

**缺陷描述**：应用存在任意文件读取、SSRF 变体或反向代理转发漏洞，可被用于请求元数据服务。

**验证命令（只读优先）**：

```bash
# 经文件读取/转发漏洞探测元数据（只读，最小影响）
curl "$APP_URL/proxy?target=http://metadata.tencentyun.com/latest/meta-data/local-ipv4"
```

**影响**：与 SSRF 类似，可读取元数据并进一步获取角色临时凭证。

**检测侧建议**：文件读取/转发行为由应用日志与 WAF 记录；防守侧应限制出站目标、隔离元数据访问；SOC 对异常读取路径建立告警。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 文件读取/转发 → 元数据读取 |
| 防守者 | WAF、应用日志、SOC 异常路径告警 |

### 3.3 元数据 CAM 角色临时凭证窃取

**缺陷描述**：实例绑定 CAM 角色后，元数据接口可返回该角色的临时凭证（TmpSecretId/TmpSecretKey/Token），且该凭证默认有效期较长、权限继承自角色策略。

**验证命令（只读优先）**：

```bash
# 先获取角色名（只读）
curl http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/

# 获取角色临时凭证（只读，返回 JSON 含 TmpSecretId/TmpSecretKey/Token）
curl http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/<role-name>
```

**影响**：临时凭证泄露后，攻击者可在有效期内以角色权限调用云 API，实现资源枚举、数据导出、配置篡改等越权操作。

**检测侧建议**：临时凭证签发由 CloudAudit `AssumeRole` 记录（含角色与调用方）；凭证被用于 API 调用时，CloudAudit 记录调用者与调用方 IP；SOC 对实例外环境使用角色凭证建立告警。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 元数据 → 角色临时凭证 → 云 API 调用 |
| 防守者 | CloudAudit `AssumeRole`、API 调用方审计 |

### 3.4 临时凭证配置到本地 CLI 复用

**缺陷描述**：攻击者将窃取的临时凭证配置到本地 tccli，以角色身份持续调用云 API。

**验证命令（只读优先）**：

```bash
# 使用临时凭证确认身份（只读）
tccli sts GetCallerIdentity \
  --secret-id <TmpSecretId> \
  --secret-key <TmpSecretKey> \
  --token <Token>

# 用临时凭证枚举实例（只读）
tccli cvm DescribeInstances --secret-id <TmpSecretId> --secret-key <TmpSecretKey> --token <Token>
```

**影响**：临时凭证在有效期内被外部长期复用，扩大越权调用范围与持续时间。

**检测侧建议**：`GetCallerIdentity` 高频/异常调用方调用是凭证泄露典型信号，由 CloudAudit 记录；SOC 对临时凭证（`TmpSecretId` 前缀）从实例外环境调用建立告警。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 本地复用临时凭证调用 API |
| 防守者 | CloudAudit `GetCallerIdentity`、临时凭证调用方告警 |

### 3.5 实例角色权限过宽放大影响

**缺陷描述**：实例绑定角色的策略过宽（如绑定 `AdministratorAccess` 或 `*` 资源策略），一旦元数据凭证泄露，攻击者权限被放大到账号级。

**验证命令（只读优先）**：

```bash
# 确认角色及其策略（只读）
tccli cam DescribeRoleList
tccli cam GetRole --RoleName <role-name>
```

**影响**：元数据凭证泄露 + 角色权限过宽 = 账号级接管，攻击者可在全账号范围内横向移动。

**检测侧建议**：角色策略绑定由 CloudAudit `AttachPolicyToRole`、`DetachRolePolicy` 记录；防守侧应对实例角色做最小权限收敛，SOC 对高权限角色绑定建立告警。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 元数据凭证 + 高权限角色 = 账号接管 |
| 防守者 | CloudAudit `AttachPolicyToRole`、最小权限基线 |

## 四、权限提升与持久化路径

- **SSRF → 元数据 → 角色凭证 → 云 API 越权**：完整提权链路，检测点：`AssumeRole` + CloudAudit API 调用异常。
- **凭证持久复用**：将临时凭证保存并持续调用，检测点：`GetCallerIdentity`、临时凭证调用方告警。
- **角色信任策略放宽**：持高权限凭证的攻击者修改角色信任策略引入外部主体（破坏性，授权内人工确认后执行），检测点：CloudAudit 角色信任策略变更事件。
- **新增高权限用户/密钥**：见 `./cam.md`，检测点：`CreateUser`、`CreateAccessKey`。

上述操作若涉及角色/用户/密钥变更，一律标注「授权内人工确认后执行」。

## 五、防御与检测要点

核心审计事件清单（CloudAudit 操作审计，辅以应用日志与 WAF）：

- `AssumeRole` — 角色临时凭证签发（元数据凭证窃取核心信号）
- `GetCallerIdentity` — 身份确认（泄露凭证探测信号）
- `AttachPolicyToRole` / `DetachRolePolicy` — 角色策略绑定变更
- `UpdateRoleDescription` — 角色信任策略变更
- `CreateUser` / `CreateAccessKey` — 持久化后门（见 `./cam.md`）
- 应用访问日志 — SSRF/文件读取异常目标（元数据地址、链路本地地址）
- WAF 日志 — 出站 SSRF 拦截

防御建议：

1. 应用层修复 SSRF/文件读取漏洞，出站目标白名单化，拦截链路本地地址、内网地址与 `metadata.tencentyun.com`。
2. 实例角色遵循最小权限，杜绝 `AdministratorAccess` 等高权限策略。
3. 缩短元数据临时凭证有效期，监控 `AssumeRole` 与异常调用方调用。
4. 对 `GetCallerIdentity`、`AssumeRole` 建立 SOC 告警与关联分析。
5. 需要时采用元数据访问加固方案（如按需关闭、网络策略隔离）。

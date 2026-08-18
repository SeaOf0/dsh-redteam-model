# 从 SSRF 到元数据服务账号 token 攻防

这是 GCP 云安全中最关键的提权链路之一：应用存在服务端请求伪造（SSRF）→ 请求被转发到实例元数据服务 → 读取附加服务账号的访问令牌（access token）→ 用该令牌以服务账号身份调用 GCP API，把「应用层 SSRF」升级为「云控制面权限」。GCP 元数据服务地址为 `metadata.google.internal`（等价链路本地地址 169.254.169.254），仅在实例内部可达，且强制要求 `Metadata-Flavor: Google` 请求头，这是与其它云平台的关键差异，也是防护与检测的重要分界。

## 一、攻击面

元数据 SSRF 链路的攻击面由「入口」与「出口」两端构成：

1. **SSRF 入口**：Web 应用中的 URL 抓取、文件导入、Webhook、图片处理、PDF 生成、SSRF 型反代等可被诱导向内部地址发请求的功能点。入口决定能否触达元数据服务。
2. **元数据服务可达性**：GCP 元数据服务仅绑定在链路本地地址，只能从实例内部访问；SSRF 若运行在 Compute Engine 实例或 GKE 节点/Pod 内，即可命中。
3. **请求头注入**：元数据服务强制要求 `Metadata-Flavor: Google`（旧接口还需 `X-Google-Metadata-Request: True`）；SSRF 若无法控制请求头，则需依赖应用是否自带该头，或通过 `Host` 头、重定向等方式绕过。
4. **服务账号与 scope**：元数据返回的 token 权限取决于实例附加服务账号及其 scope；scope 为 `cloud-platform` 时 token 权限最大（见 `./compute-engine.md`）。
5. **身份令牌（identity token）**：`/instance/service-accounts/<email>/identity?audience=...` 可签发以该服务账号为身份的 OIDC 身份令牌，用于访问受 IAP 保护或要求身份令牌的下游服务。
6. **自定义属性与启动脚本**：`/instance/attributes/` 下可能存放团队写入的敏感自定义元数据，SSRF 可直接读取。

## 二、信息收集 / 暴露面探测

在已获得实例内执行能力（或确认 SSRF 可达）后，用以下只读请求枚举元数据面。命令用途见注释。

```bash
# 枚举实例附加的服务账号列表（根路径必须以 / 结尾）
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"

# 查看某服务账号的 scope（判断 token 权限范围）
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/<EMAIL>/scopes"

# 读取某服务账号的访问令牌（核心目标，返回 JSON 含 access_token 与过期时间）
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/<EMAIL>/token"

# 签发以该服务账号为身份的 OIDC 身份令牌（audience 为下游服务客户端 ID）
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/<EMAIL>/identity?audience=<AUDIENCE>"

# 读取实例基本信息（机器类型、主机名、区域、自定义属性键名）
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/"

# 读取项目信息（项目 ID、数字编号）
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/"

# 读取实例自定义属性（常含团队写入的敏感配置）
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/"
```

**SSRF 可达性判断**：先确认应用能否向内部地址发起请求；GCP 元数据地址等价于链路本地 169.254.169.254（仅实例内可达）。若 SSRF 能携带自定义请求头，直接携带 `Metadata-Flavor: Google`；若不能，观察应用是否会在内部请求中自动附加该头。

## 三、常见配置缺陷与利用路径

### 3.1 SSRF 可达元数据服务且可控制请求头

**缺陷描述**：应用存在可向任意内部地址发起请求的 SSRF，且允许控制请求头（或应用默认附加 `Metadata-Flavor: Google`）。攻击者即可直接读取元数据 token。

**验证命令（只读优先）**：

```bash
# 通过 SSRF 触发应用向元数据服务发起只读请求（根路径）
# 请求头须含：Metadata-Flavor: Google
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
```

**影响**：读取到 token 后，攻击者可在实例外以服务账号身份调用 GCP API，权限随 scope 与角色放大；这是 SSRF 的「最高价值终点」。

**检测侧建议**：元数据服务本身的访问不产生 Cloud Audit Logs（链路本地，无 Admin Activity 记录），这是关键检测缺口——攻击者「读取 token」这一步在云审计日志中不可见。真正可观测的是：随后用该 token 调用 API 时，在 Data Access / Admin Activity 日志中出现的「服务账号首次从非预期调用方/非预期 API 调用」；以及应用侧 SSRF 出口的网络流量（VPC Flow Logs 中实例向链路本地地址的异常连接）。SCC 的「元数据服务访问」相关发现与 VPC 防火墙出站监控是主要防线。

### 3.2 应用自动附加 Metadata-Flavor 头（无需控制头）

**缺陷描述**：部分 GCP SDK 或中间件在实例内发起请求时会自动附加 `Metadata-Flavor: Google`。若 SSRF 复用这类 HTTP 客户端，即使攻击者无法手动注入请求头，也能命中元数据服务。

**验证命令（只读优先）**：

```bash
# 通过 SSRF 触发复用 SDK 客户端的内部请求，验证是否可读到元数据
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

**影响**：即使 SSRF 本身「只能传 URL、不能改头」，只要底层客户端自动带头发起请求，token 仍会泄露，攻击门槛显著降低。

**检测侧建议**：与 3.1 相同的检测缺口——token 读取本身不可见。应关注应用侧日志中异常的内部地址访问模式、以及后续服务账号的异常 API 调用。防御上优先通过「元数据响应头过滤」与限制服务账号 scope 降低泄露影响。

### 3.3 Host 头 / 重定向绕过元数据地址过滤

**缺陷描述**：应用对 SSRF 做了域名黑名单（如拦截 `metadata.google.internal` 字符串），但未处理 Host 头改写或外部重定向。攻击者可用一个自己控制的外部域名，让其 HTTP 302 重定向到元数据服务，或改写 `Host` 头为元数据地址，绕过字符串级过滤。

**验证命令（只读优先）**：

```bash
# 概念验证：以重定向方式让应用最终请求元数据（外部域名 → 302 → 元数据地址）
# 请求头仍须满足 Metadata-Flavor: Google
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
```

**影响**：字符串级过滤形同虚设，攻击者通过重定向或 Host 改写绕过，仍可触达元数据服务读取 token。

**检测侧建议**：应用侧应基于「最终解析地址」而非 URL 字符串做 SSRF 防护（如 DNS 解析后校验是否为链路本地/内网地址、禁用重定向跟随）。云侧同样存在「token 读取不可见」的检测缺口，需靠后续服务账号异常 API 调用与 VPC Flow Logs 中的链路本地连接补位。

### 3.4 元数据返回高权限 scope 的 token

**缺陷描述**：实例 scope 被配置为 `https://www.googleapis.com/auth/cloud-platform`（全量），元数据返回的 token 因此可调用几乎所有 GCP API。此时 SSRF 泄露 token 的后果等于实例服务账号权限的完全暴露。

**验证命令（只读优先）**：

```bash
# 只读查看某服务账号的 scope
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/<EMAIL>/scopes"
```

**影响**：scope 过宽使一次 SSRF 泄 token 即获得全量 API 访问，放大为「SSRF → 云控制面接管」。

**检测侧建议**：scope 配置在实例创建/模板中体现，可通过 SCC 的「过宽 scope」发现项识别；`compute.instances.setMetadata`、`compute.instanceTemplates.insert` 等事件记录模板与实例变更。token 泄露本身不可见，需结合服务账号后续 API 调用监控。

### 3.5 自定义属性泄露敏感配置

**缺陷描述**：团队把口令、内部地址、配置片段写入实例自定义属性（`instance/attributes/`），SSRF 无需 token 即可直接读取这些明文敏感信息。

**验证命令（只读优先）**：

```bash
# 只读列出并读取实例自定义属性
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/"
```

**影响**：自定义属性泄露可直接暴露凭据与内部拓扑，即使拿不到 token，也能为后续横向移动提供弹药。

**检测侧建议**：自定义属性读取不产生 Admin Activity 日志（检测缺口），但「写入自定义属性」的 `compute.instances.setMetadata` 事件可审计。应禁止在自定义属性中存放敏感信息，敏感值改用 Secret Manager 注入。

## 四、权限提升与持久化路径

**权限提升主线**：

1. **SSRF → access token → gcloud 冒充**：把 token 注入 gcloud 环境变量，以服务账号身份调用 API：

```bash
# 将元数据 token 作为凭据注入 gcloud（只读验证身份）
export GOOGLE_OAUTH_ACCESS_TOKEN="<ACCESS_TOKEN>"
gcloud auth list
gcloud projects list
```

2. **access token → 更高权限服务账号**：若当前服务账号持有 `iam.serviceAccounts.actAs`、`iam.serviceAccountTokenCreator` 等角色，可进一步冒充其它高权限服务账号（见 `./iam.md`），形成多级提权。
3. **identity token → 受 IAP 保护资源**：用 `/identity?audience=...` 签发身份令牌，访问受 IAP 或要求 OIDC 身份令牌的内部服务。
4. **token → 长期凭据**：若服务账号允许创建密钥，用 token 调用 `iam.serviceAccounts.createKey` 生成长期密钥持有（授权内人工确认后执行），把短期 token 转化为持久后门。

**持久化路径**：

1. **服务账号密钥化**：将短期 token 升级为长期密钥（授权内人工确认后执行），见 `./iam.md`。
2. **SSRF 入口常驻**：在应用内保留可重复触发的 SSRF 点，作为长期 token 获取通道。
3. **写入自定义属性/启动脚本**：若已获得 `compute.instances.setMetadata` 权限，写入启动脚本或自定义属性实现持久执行（见 `./compute-engine.md`）。

## 五、防御与检测要点

审计日志事件名清单（注意：元数据 token 读取本身不在 Cloud Audit Logs 中，需靠间接信号）：

| 事件名 | 含义 | 关注点 |
| --- | --- | --- |
| `compute.instances.setMetadata` | 修改实例 metadata | 写入敏感属性/启动脚本 |
| `compute.instances.setServiceAccount` | 更换实例服务账号 | 权限面变更 |
| `compute.instanceTemplates.insert` | 创建实例模板 | 模板内 scope 过宽 |
| `iam.serviceAccounts.getAccessToken` | 生成访问令牌 | 异常调用方的 token 生成（Data Access） |
| `iam.serviceAccounts.createKey` | 创建服务账号密钥 | 短期 token 升级为长期密钥 |
| `iam.serviceAccounts.actAs` | 以服务账号身份动作 | 冒充 |
| VPC Flow Logs 记录 | 实例向链路本地地址的连接 | 元数据访问的间接信号 |

防御建议：

- 应用层 SSRF 防护基于最终解析地址（DNS 解析后校验内网/链路本地，禁用重定向跟随），而非 URL 字符串黑名单。
- 实例 scope 最小化，禁止默认 `cloud-platform` 全量；服务账号最小权限。
- 禁用实例元数据中的敏感自定义属性，敏感值走 Secret Manager。
- GKE 场景启用 Workload Identity，并配合 GKE 元数据隐藏（`--workload-metadata-from-node`），从节点层阻断元数据访问。
- 开启 VPC Flow Logs，监控实例向链路本地地址（169.254.169.254）的异常连接；对服务账号「首次/异常调用方 API 调用」建立告警。
- 优先使用短期凭据，组织策略禁用服务账号密钥创建，切断「token → 长期密钥」的持久化路径。

# COS 对象存储攻防

> 面向授权安全测试的 COS（对象存储）攻击面梳理与方法论，涵盖 bucket、object、ACL、公有读、桶接管与静态网站。所有验证以只读探测优先，破坏性操作需「授权内人工确认后执行」。

## 一、攻击面

COS 是腾讯云对象存储服务，存储单元为 bucket（桶）与 object（对象）。其攻击面集中于访问控制配置与匿名暴露，可归纳为：

- **Bucket 级 ACL 与 Policy**：公有读/公有写、跨账号授权、匿名访问。
- **Object 级 ACL**：单个对象被误设为公有读。
- **桶命名与接管**：已删除桶的访问域名被重新注册（桶接管/悬挂域名）。
- **静态网站托管**：静态网站端点暴露敏感页面或配置。
- **签名 URL 泄露**：预签名 URL 长期有效导致未授权访问。
- **数据传输与生命周期**：版本残留、跨域复制、历史快照中的敏感数据。

下表列出 COS 攻击面与对应防守视角：

| 攻击面 | 攻击者关注点 | 防守者关注点 |
| --- | --- | --- |
| Bucket ACL | 公有读/公有写 | `PutBucketACL` 审计 |
| Object ACL | 单个对象公有读 | `PutObjectACL` 审计 |
| Bucket Policy | 宽松策略/跨账号 | `PutBucketPolicy` 审计 |
| 静态网站 | 敏感页面泄露 | `PutBucketWebsite` 审计 |
| 桶接管 | 悬挂域名重注册 | 域名解析监控、删除事件审计 |

## 二、信息收集 / 暴露面探测

以下命令均为只读探测，用于枚举当前账号授权范围内的 COS 资源与配置。执行前确认已配置 coscmd（SecretId/SecretKey/region）或 tccli。

```bash
# 配置 coscmd（只读探测前置，需凭据与地域）
coscmd config -a <SecretId> -s <SecretKey> -b <bucket-appid> -r <region>

# 列出桶内对象（只读）
coscmd -b <bucket-appid> list

# 查看桶 ACL（只读）
coscmd -b <bucket-appid> getbucketacl

# 查看对象信息与 ACL（只读）
coscmd -b <bucket-appid> info <object-key>
```

桶命名规则为 `<bucketname>-<appid>`，访问域名形如 `<bucket-appid>.cos.<region>.myqcloud.com`（此处仅描述域名形态，不含协议前缀）。对未持有凭据的桶，可构造匿名无签名 GET 请求探测是否公有读。

## 三、常见配置缺陷与利用路径

### 3.1 桶公有读（ACL/Policy 误配）

**缺陷描述**：桶 ACL 被设为公有读（`public-read`）或 Bucket Policy 允许匿名 `GetObject`，导致桶内全部对象可被未授权下载。

**验证命令（只读优先）**：

```bash
# 查看桶 ACL，识别 public-read（只读）
coscmd -b <bucket-appid> getbucketacl

# 未持凭据场景：对对象访问域名发起匿名无签名 GET 探测
# 返回 200 且含对象内容即确认公有读
```

**影响**：攻击者可批量枚举并下载桶内对象，造成敏感数据（源码、备份、用户数据、密钥文件）泄露。

**检测侧建议**：公有读对象的下载行为由 COS 访问日志记录（源 IP、对象 key、返回码）；ACL 变更由 CloudAudit 事件 `PutBucketACL`、`PutBucketPolicy` 追踪；SOC 可对匿名 200 请求建立基线告警。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 匿名 GET 枚举 + 下载对象 |
| 防守者 | COS 访问日志、CloudAudit `PutBucketACL`/`PutBucketPolicy` |

### 3.2 桶公有写（可覆盖/可上传）

**缺陷描述**：桶 ACL 被设为公有写（`public-write`）或 Policy 允许匿名 `PutObject`，攻击者可向桶内写入任意对象。

**验证命令（只读优先）**：

```bash
# 查看桶 ACL，识别 public-write（只读）
coscmd -b <bucket-appid> getbucketacl
```

**影响**：攻击者可向静态网站桶上传恶意页面实现持久化投毒，或覆盖关键对象造成数据污染（覆盖属破坏性操作，需授权内人工确认后执行）。

**检测侧建议**：匿名写入由 COS 访问日志记录 `PutObject`/`PostObject` 事件；CloudAudit 事件 `PutObjectACL`、`PutBucketACL` 可追踪 ACL 变更；SOC 对匿名写请求设置高危告警。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 匿名 PUT 上传/覆盖对象 |
| 防守者 | COS 访问日志、CloudAudit `PutObjectACL` |

### 3.3 桶接管（悬挂域名/已删除桶重注册）

**缺陷描述**：应用仍引用已删除 bucket 的访问域名，而该桶名被攻击者重新注册，导致应用流量被接管。

**验证命令（只读优先）**：

```bash
# 枚举应用/前端引用的桶名，检查桶是否仍存在（只读）
coscmd -b <bucket-appid> info

# 桶不存在时确认域名是否可被重新注册（评估，不实际注册）
```

**影响**：攻击者接管悬挂桶后，可向其中投毒（放置恶意资源）或拦截应用写入的数据，实现供应链式持久化。

**检测侧建议**：桶删除由 CloudAudit `DeleteBucket` 事件记录；防守侧应对桶删除与引用关系建立资产台账，监测已删除桶域名的重新注册（需授权内人工确认后评估）。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 注册悬挂域名，投毒/截获数据 |
| 防守者 | CloudAudit `DeleteBucket`、域名解析监控 |

### 3.4 静态网站托管敏感信息泄露

**缺陷描述**：桶开启静态网站托管后，站点目录中残留备份包、`.git` 目录、配置文件、源码或密钥。

**验证命令（只读优先）**：

```bash
# 列出桶内对象，识别可疑文件（只读）
coscmd -b <bucket-appid> list -r

# 对常见敏感路径（.git/config、backup、env 等）匿名探测
```

**影响**：敏感文件泄露可直接获取源码、配置与凭据，进而扩大攻击面。

**检测侧建议**：静态网站端点访问由 COS 访问日志记录；网站托管配置变更由 CloudAudit `PutBucketWebsite` 事件追踪；SOC 对常见敏感路径访问建立告警。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 枚举敏感路径并下载 |
| 防守者 | COS 访问日志、CloudAudit `PutBucketWebsite` |

### 3.5 预签名 URL 长期泄露

**缺陷描述**：预签名 URL（signed URL）被泄露到日志、前端或邮件中，且过期时间设置过长，导致未授权访问。

**验证命令（只读优先）**：

```bash
# 对泄露的预签名 URL 发起 GET 探测，确认是否仍有效（只读）
# 返回 200 即表明签名有效且可下载
```

**影响**：攻击者无需凭据即可通过预签名 URL 下载或上传对象，绕过 ACL 限制。

**检测侧建议**：预签名 URL 的生成与使用在 COS 访问日志中体现为带签名参数的请求；防守侧应限制签名有效期、避免明文入日志，并通过 SOC 关联异常调用方访问。

| 视角 | 可见性 |
| --- | --- |
| 攻击者 | 复用泄露的签名 URL |
| 防守者 | COS 访问日志、异常调用方告警 |

## 四、权限提升与持久化路径

- **公有写桶投毒**：向静态网站桶上传恶意脚本，实现面向访客的持久化投毒。检测点：COS 访问日志 `PutObject`、CloudAudit `PutObjectACL`。
- **Bucket Policy 跨账号授权**：误配 `PutBucketPolicy` 引入外部账号，形成隐蔽数据通道。检测点：CloudAudit `PutBucketPolicy`。
- **生命周期规则篡改**：修改生命周期规则触发数据删除或转储（破坏性，授权内人工确认后执行）。检测点：CloudAudit `PutBucketLifecycle`。
- **版本残留挖掘**：对开启版本控制的桶遍历历史版本，提取已删除对象的旧内容。检测点：COS 访问日志 `GetObject` 带 version 参数。

上述操作若涉及删除/覆盖/策略篡改，一律标注「授权内人工确认后执行」。

## 五、防御与检测要点

核心审计事件清单（CloudAudit 操作审计，辅以 COS 访问日志）：

- `PutBucketACL` / `PutObjectACL` — 桶/对象 ACL 变更
- `PutBucketPolicy` / `DeleteBucketPolicy` — 桶策略变更
- `PutBucketWebsite` — 静态网站配置
- `PutBucketLifecycle` — 生命周期规则变更
- `DeleteBucket` — 桶删除（悬挂域名风险）
- `PutObject` / `PostObject` / `GetObject` — 对象读写（COS 访问日志）
- `DeleteObject` — 对象删除

防御建议：

1. 桶与对象默认私有，杜绝公有读/公有写。
2. Bucket Policy 最小化，严格限制跨账号与匿名授权。
3. 桶删除前评估应用引用关系，建立域名接管监测。
4. 静态网站目录定期清理敏感文件，禁止提交 `.git`、备份包。
5. 预签名 URL 缩短有效期，避免明文入日志。
6. 开启 COS 访问日志与 CloudAudit，对匿名读写建立告警。

# OSS 对象存储攻防

本文覆盖阿里云 OSS 对象存储在授权评估中的攻击面、暴露面探测、常见配置缺陷与利用路径、权限提升与持久化，以及对应检测要点。所有命令以只读探测为优先，破坏性操作须在授权范围内人工确认后执行。

## 一、攻击面

OSS 的攻击面主要围绕「桶（Bucket）与对象（Object）」的访问控制配置与凭据管理：

- **Bucket ACL**：`public-read`、`public-read-write` 使桶或对象对匿名用户可读/可写。
- **Object ACL**：单个对象覆盖桶级策略设为公开。
- **防盗链 Referer**：未配置或配置可绕过的 Referer 白名单，导致资源被直接引用。
- **静态网站托管**：开启后通过默认域名可浏览，若桶内含敏感文件即泄漏。
- **桶接管**：已删除的桶名可被重新注册，原引用方（应用、CDN、证书验证）仍指向该名导致投毒。
- **AccessKey 泄漏**：前端硬编码、代码仓库、小程序反编译等渠道泄漏的 AK 直接控制桶。
- **跨域 CORS、版本控制、生命周期**：错误配置放大读写与历史数据暴露面。

## 二、信息收集 / 暴露面探测

已获得 AK 或需探测桶暴露情况时，用只读命令枚举桶与对象。

```bash
# 列出当前账号下全部桶
aliyun oss ls
# 或使用 ossutil
ossutil ls oss://

# 列出指定桶内对象（前缀枚举）
aliyun oss ls oss://bucket-name/ --long
ossutil ls oss://bucket-name/

# 查看桶的 ACL 与区域、版本控制、静态网站等属性
aliyun oss bucket-info --bucket bucket-name
ossutil stat oss://bucket-name

# 查看单个对象的 ACL
ossutil stat oss://bucket-name/path/key.txt
```

对匿名访问与桶名接管，可用只读 HTTP 探测（不携带任何凭据，仅观察响应）。OSS 默认访问域名为 `<bucket>.<region>.aliyuncs.com`，示例中 `oss-cn-hangzhou.aliyuncs.com` 为华东 1 地域接入点：

```bash
ENDPOINT=oss-cn-hangzhou.aliyuncs.com
BUCKET=bucket-name

# 匿名读取桶（公开桶会返回对象清单或目录结构）
curl -I "$BUCKET.$ENDPOINT/"

# 直接读取公开对象
curl "$BUCKET.$ENDPOINT/path/key.txt"
```

> 探测对象须为授权目标，禁止对非授权桶做匿名枚举。

## 三、常见配置缺陷与利用路径

### 3.1 Bucket 或 Object 被设为公开读/写

**缺陷描述**：桶级 ACL 为 `public-read`/`public-read-write`，或个别对象被单独设为公开，导致匿名用户可读敏感数据或写入任意对象。

**验证命令（只读优先）**：

```bash
ossutil stat oss://bucket-name
# 关注输出中的 ACL 字段是否为 public-read / public-read-write

# 匿名探测桶（返回对象清单说明存在公开枚举）
curl -I "bucket-name.oss-cn-hangzhou.aliyuncs.com/"
```

**影响**：公开读导致敏感文件（备份、密钥、用户数据）泄漏；公开写可被上传恶意对象（挂马、篡改前端资源、投毒）。

**检测侧建议**：OSS 访问日志记录每次读写请求（含请求者身份）；ActionTrail 记录 `PutBucketAcl`、`PutObjectAcl`、`PutBucketPolicy` 等 ACL 变更事件。防守方可按「匿名访问 + 高频读」建立告警。

### 3.2 静态网站托管泄漏敏感文件

**缺陷描述**：开启静态网站托管后，桶内文件可经默认域名直接浏览，若桶内混入 `.bak`、`.git`、备份压缩包、密钥文件即造成泄漏。

**验证命令（只读优先）**：

```bash
ossutil stat oss://bucket-name
# 观察 Website 配置是否开启

# 常见敏感路径逐一探测（授权内只读）
curl "bucket-name.oss-cn-hangzhou.aliyuncs.com/index.html"
curl "bucket-name.oss-cn-hangzhou.aliyuncs.com/.git/config"
curl "bucket-name.oss-cn-hangzhou.aliyuncs.com/backup.zip"
```

**影响**：源代码、配置、凭据、备份被匿名获取，可直接用于进一步渗透。

**检测侧建议**：OSS 访问日志可定位对敏感后缀（`.git`、`.bak`、`.zip`）的异常读取；防守方可定期用对象扫描工具盘点桶内敏感文件类型并告警。

### 3.3 已删除桶名可被抢注（桶接管）

**缺陷描述**：OSS 桶名全局唯一，桶删除后名称可被他人重新注册。若旧桶仍被应用、CDN 加速域名、证书验证或第三方服务引用，攻击者可注册同名桶注入恶意内容。

**验证命令（只读优先）**：

```bash
# 探测目标引用中的桶名是否已不存在（返回 NoSuchBucket）
curl -I "target-bucket.oss-cn-hangzhou.aliyuncs.com/"
# 若返回 404/NoSuchBucket，说明该名称可能可注册
```

**影响**：接管桶后可向引用方投毒（恶意 JS、木马、钓鱼页面），影响面取决于引用方的重要程度。

**检测侧建议**：桶接管难在攻击者侧观测，防守侧应在应用上线阶段用自有账号占位关键桶名、关闭不必要的外部引用，并对「已删除桶名被重新创建」通过 `CreateBucket` 事件与资产清单比对发现。

### 3.4 AccessKey 硬编码或泄漏

**缺陷描述**：AK 泄漏于前端 JS、APK/小程序、代码仓库、CI 配置，攻击者获取后直接操作桶乃至账号下其他资源。

**验证命令（只读优先）**：

```bash
# 用泄漏 AK 确认身份（只读，验证凭据有效性）
aliyun sts GetCallerIdentity --AccessKeyId AKID --AccessKeySecret AKSEC

# 确认后枚举桶（只读）
aliyun oss ls
```

**影响**：AK 权限直接决定影响范围；若 AK 绑定 `AdministratorAccess` 或 `AliyunOSSFullAccess` 及以上，可读写、删除桶内数据（删除类操作须授权内人工确认后执行）。

**检测侧建议**：ActionTrail 记录 `GetCallerIdentity`、`ListBuckets`、`GetObject` 等调用及其调用方 IP；防守方可对「陌生 IP + 新 AK 首次调用」配置告警，并结合云监控对 AK 异常调用告警。

## 四、权限提升与持久化路径

- **公开写 → 前端投毒**：向公开写桶上传恶意 JS/HTML，劫持引用该桶的页面，形成持续控制。
- **桶接管 → 长期投毒**：注册被引用但已删除的桶名，长期向引用方投递恶意内容。
- **AK 提权**：泄漏的低权限 AK 若含 `CreateUser`、`AttachPolicyToUser` 等 RAM 权限，可横向创建高权限子用户（见 `./ram.md`）。
- **历史版本滥用**：开启版本控制的桶，删除对象后仍可读取历史版本；攻击者利用 `DeleteObject` 掩盖痕迹或恢复敏感数据（删除须授权内人工确认后执行）。
- **生命周期规则投毒**：具备写权限时篡改生命周期规则定向删除/转移对象，须授权内人工确认后执行。

## 五、防御与检测要点

审计日志事件名清单（ActionTrail + OSS 访问日志）：

| 事件名 | 含义 | 风险提示 |
| --- | --- | --- |
| `CreateBucket` | 创建桶 | 关注已删除桶名被重新创建 |
| `DeleteBucket` | 删除桶 | 高影响，须关联审批 |
| `PutBucketAcl` | 修改桶 ACL | 关注设为公开读写 |
| `PutObjectAcl` | 修改对象 ACL | 关注单对象公开 |
| `PutBucketPolicy` | 设置桶策略 | 关注宽泛授权 |
| `GetObject` / `ListObjects` | 读取对象/列举 | 匿名与陌生 IP 高频读取 |
| `DeleteObject` / `DeleteObjects` | 删除对象 | 关注批量删除与历史版本清理 |

防御建议：

- 默认私有，桶与对象禁止公开读写；确需公开的静态资源使用独立桶并仅放行必要前缀。
- 静态网站托管与防盗链 Referer 按需开启，Referer 白名单做严格校验。
- 关键桶名用自有账号长期占位，删除桶前评估外部引用。
- AK 不落入前端与代码仓库，使用 STS 临时凭证或实例角色替代长期 AK。
- 开启 OSS 访问日志与 ActionTrail，对匿名读写、陌生 IP、ACL 变更、批量删除建立告警。

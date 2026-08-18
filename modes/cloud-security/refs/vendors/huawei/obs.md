# 华为云 OBS 对象存储攻防

> 定位：围绕桶（bucket）、对象（object）、ACL、桶策略、静态网站托管、桶接管六类攻击面，
> 给出只读优先的探测命令与配置缺陷利用路径。工具以 `obsutil` 与 `hcloud obs` 为主，
> 写/删操作统一标注「授权内人工确认后执行」。每条路径配检测侧对照（CTS 事件名 + OBS 日志）。
> 身份凭证见 `./iam.md`，元数据 SSRF 链见 `./metadata-ssrf.md`。

## 一、攻击面

OBS 是华为云的对象存储服务，攻击面集中在「桶与对象的访问控制是否收敛」：

- 桶 ACL / 桶策略：PublicRead / PublicReadWrite、桶策略对匿名或任意主体放行。
- 对象 ACL：单个对象被设为公开读，绕过桶级私有设置。
- 静态网站托管：开启后整桶可被匿名访问，误放非公开文件即泄露。
- 桶接管（bucket takeover）：桶被删除后同名桶可被他人抢占注册，形成投毒/钓鱼入口。
- 服务端加密与版本控制：未开启加密、版本控制缺失导致泄露后无法溯源与回滚。
- 访问日志：OBS 日志未开启，读取行为不可审计（数据面盲区）。

四要素落点：身份（匿名或 AK/SK）→ 权限（ACL/桶策略）→ 资源（桶/对象）→ 影响（公开读、
数据下载、桶接管投毒）。

## 二、信息收集 / 暴露面探测

以下命令只读，用于枚举桶清单、ACL 与对象可见性。

### 2.1 桶清单与基本信息

```bash
# 列出当前账号下全部桶（需 AK/SK 已配置）
obsutil ls

# 用 hcloud 列出桶（OBS 控制面命令）
hcloud obs ls

# 查看单个桶的元信息（区域、创建时间、版本控制状态）
obsutil stat obs://<bucket>
```

### 2.2 匿名访问探测（只读，对授权目标）

匿名探测通过桶访问域名发起（域名格式 `<bucket>.obs.<region>.myhuaweicloud.com`，不含
协议头；仅对授权目标执行）：

```bash
# 探测桶是否可匿名列出对象（公开读时返回对象列表，否则 403）
curl -s -o /dev/null -w "%{http_code}\n" "<bucket>.obs.cn-north-4.myhuaweicloud.com"

# 探测已知对象键是否匿名可读（只读，仅验证状态码，不做爆破）
curl -s -o /dev/null -w "%{http_code}\n" "<bucket>.obs.cn-north-4.myhuaweicloud.com/<key>"
```

判定口径：返回 200 表示匿名可读；返回 403/404 表示未公开或对象不存在。未授权目标禁止执行。

### 2.3 ACL 与桶策略读取

```bash
# 查看桶 ACL（只读，需桶所有者权限）
obsutil get-acl obs://<bucket>

# 查看对象 ACL（只读）
obsutil get-acl obs://<bucket>/<key>

# 查看桶策略（只读，需策略读权限）
hcloud obs get-bucket-policy --bucket <bucket>
```

### 2.4 静态网站托管状态

```bash
# 查看桶是否开启静态网站托管及其首页/错误页配置
obsutil get-website obs://<bucket> 2>/dev/null || \
hcloud obs get-bucket-website --bucket <bucket>
```

## 三、常见配置缺陷与利用路径

### 3.1 桶被设为公开读（PublicRead / PublicReadWrite）

- 缺陷描述：桶 ACL 被设为 PublicRead（匿名可读全部对象）或 PublicReadWrite（匿名可写），
  前者导致数据泄露，后者导致数据被篡改、被写入恶意文件。
- 验证命令（只读优先）：

```bash
# 只读验证匿名列举（200 表示可列桶）
curl -s "<bucket>.obs.cn-north-4.myhuaweicloud.com" 2>&1 | head -50
# 只读验证匿名读取已知对象
curl -s -o /dev/null -w "%{http_code}\n" "<bucket>.obs.cn-north-4.myhuaweicloud.com/<key>"
```

- 影响：敏感数据（备份、日志、源代码包）被匿名批量下载；PublicReadWrite 更可被植入恶意
  文件形成投毒。
- 检测侧建议：CTS 事件 `setBucketAcl`、`putBucketAcl` 记录 ACL 变更主体与时间；匿名读取属
  数据面，需开启 OBS 日志（访问日志）才能看到匿名源 IP 与读取对象，未开启即检测缺口。

### 3.2 桶策略对任意主体放行

- 缺陷描述：桶策略（Bucket Policy）写入了 `Principal: *` 或对任意账号/匿名放行 GetObject、
  ListBucket，等价于匿名公开，但比 ACL 更难被一眼发现（策略 JSON 中藏匿）。
- 验证命令（只读）：

```bash
hcloud obs get-bucket-policy --bucket <bucket>   # 读策略原文，检查 Principal 与 Action
# 用策略允许的主体做只读探测（匿名）
curl -s -o /dev/null -w "%{http_code}\n" "<bucket>.obs.cn-north-4.myhuaweicloud.com/<key>"
```

- 影响：策略级匿名放行常覆盖多个对象或整桶，泄露面大且隐蔽。
- 检测侧建议：CTS 事件 `setBucketPolicy`、`putBucketPolicy` 留痕；与 ACL 同样，匿名读取需
  OBS 访问日志佐证，缺日志即检测缺口。

### 3.3 静态网站托管误公开非公开文件

- 缺陷描述：开启静态网站托管后，桶内所有对象默认可被匿名访问；若桶内混有备份、配置、
  密钥等非静态资源文件，将被一并公开。
- 验证命令（只读）：

```bash
# 只读探测静态网站端点首页（托管域名为 <bucket>.obs-website.<region>.myhuaweicloud.com）
curl -s -o /dev/null -w "%{http_code}\n" "<bucket>.obs-website.cn-north-4.myhuaweicloud.com/"
# 猜测常见敏感对象键（只读，仅验证状态码，不做爆破）
for k in backup.zip .env config.json db.sql; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "<bucket>.obs-website.cn-north-4.myhuaweicloud.com/$k")
  echo "$k -> $code"
done
```

- 影响：敏感文件经静态网站端点匿名可读，泄露数据库备份、环境配置等。
- 检测侧建议：CTS 事件 `putBucketWebsite`、`setBucketWebsite` 记录托管开启；匿名下载依赖
  OBS 访问日志（数据面），未开启即检测缺口。

### 3.4 桶接管（bucket takeover）

- 缺陷描述：应用引用了已被删除的桶域名（如静态资源、回源地址、CDN 源站），桶删除后同区域
  同名桶可被他人抢注，攻击者注册同名桶后托管恶意内容，形成投毒与钓鱼。
- 验证命令（只读优先）：

```bash
# 探测目标引用域名对应的桶是否存在（只读，判断是否已被删除）
curl -s -o /dev/null -w "%{http_code}\n" "<bucket>.obs.cn-north-4.myhuaweicloud.com/"
# 若返回 404 NoSuchBucket，说明桶名可被抢注；是否抢注属破坏性动作，授权内人工确认后执行
```

- 影响：应用继续向该桶域名请求资源，攻击者即可劫持内容分发、投毒前端资源、窃取引用方流量。
- 检测侧建议：CTS 事件 `deleteBucket` 记录桶删除；但「外部应用仍引用已删桶」属资产关联盲区，
  需通过资产测绘与引用关系盘点（CMS/配置巡检）发现，检测缺口明显。

### 3.5 对象级 ACL 绕过桶级私有

- 缺陷描述：桶为私有，但个别对象被单独设为公开读（对象 ACL），形成「桶看似安全、对象实际
  泄露」的认知差。
- 验证命令（只读）：

```bash
obsutil get-acl obs://<bucket>/<key>          # 读对象 ACL
curl -s -o /dev/null -w "%{http_code}\n" "<bucket>.obs.cn-north-4.myhuaweicloud.com/<key>"
```

- 影响：单个对象泄露（如泄露的日志文件、私有签名 URL 误配为公开），绕过整体安全策略。
- 检测侧建议：CTS 事件 `setObjectAcl`、`putObjectAcl` 记录对象级 ACL 变更；配合 OBS 访问
  日志定位匿名读取，缺日志即检测缺口。

### 3.6 服务端加密与版本控制缺失

- 缺陷描述：桶未开启服务端加密（SSE-KMS/SSE-OBS）与版本控制，数据以明文落盘、删除后不可
  回滚，泄露后影响不可控、取证困难。
- 验证命令（只读）：

```bash
obsutil stat obs://<bucket>   # 查看桶元信息中的加密与版本控制字段
# 查看桶加密配置（只读）
hcloud obs get-bucket-encryption --bucket <bucket> 2>/dev/null
# 查看版本控制状态（只读）
hcloud obs get-bucket-versioning --bucket <bucket> 2>/dev/null
```

- 影响：明文存储放大泄露后果；无版本控制则删除/篡改不可逆，且无法通过历史版本溯源。
- 检测侧建议：CTS 事件 `putBucketEncryption`、`putBucketVersioning` 记录配置变更；未开启加密
  属配置态，需配置合规（SA）扫描发现，检测缺口集中在配置态而非行为态。

## 四、权限提升与持久化路径

- 匿名写 → 投毒提权：PublicReadWrite 或策略允许 PutObject 时，攻击者写入恶意静态资源/前端
  脚本，劫持访问者（存储型投毒）。
- AK/SK 复用：从桶内泄露的代码包/配置中提取 AK/SK，横向访问其他服务（见 `./iam.md`）。
- 桶接管持久化：抢注被应用引用的已删桶，长期托管恶意内容（前述 3.4）。
- 以上写/删/抢注动作均属「授权内人工确认后执行」，本文不提供武器化脚本。

## 五、防御与检测要点

| 层 | 关键动作 | 审计/监控事件 |
|---|---|---|
| 桶生命周期 | 创建/删除桶 | `createBucket`、`deleteBucket` |
| ACL | 桶/对象 ACL 变更 | `setBucketAcl`、`putBucketAcl`、`setObjectAcl`、`putObjectAcl` |
| 桶策略 | 策略写入 | `setBucketPolicy`、`putBucketPolicy` |
| 静态托管 | 开启托管 | `putBucketWebsite`、`setBucketWebsite` |
| 加密/版本 | 配置变更 | `putBucketEncryption`、`putBucketVersioning` |
| 对象写入 | 上传对象 | `putObject`、`postObject` |
| 数据面读取 | 匿名/账号读取 | OBS 访问日志（非 CTS，需显式开启） |

防御建议：

- 默认私有：桶默认拒绝匿名访问，公开需走审批；用桶策略 + ACL 双重最小化。
- 关闭 PublicReadWrite：绝对禁止匿名写，公开读仅限确需静态托管的目录。
- 开启 OBS 访问日志并投递 SIEM，补齐数据面读取盲区（核心缺口）。
- 开启服务端加密（SSE-KMS）与版本控制，泄露后可追溯、可回滚。
- 资产关联盘点：下线应用时同步清理桶引用，防止桶接管（referer/回源/CMS 配置巡检）。
- 密钥与备份禁入公开桶：定期用配置合规扫描公开桶内容物。

## 审计事件名清单（本节汇总）

`createBucket`、`deleteBucket`、`setBucketAcl`、`putBucketAcl`、`setObjectAcl`、
`putObjectAcl`、`setBucketPolicy`、`putBucketPolicy`、`putBucketWebsite`、
`setBucketWebsite`、`putBucketEncryption`、`putBucketVersioning`、`putObject`、
`postObject`。

---
name: php-ssrf-audit
description: PHP Web 源码 SSRF 审计工具。识别用户可控 URL/地址进入网络请求 Sink，追踪内网/协议/端口限制与回显，输出可利用性分级、PoC 与修复建议（禁止省略）。
---

# PHP SSRF 审计（php-ssrf-audit）

分析 PHP 项目源码，识别 SSRF 风险：用户可控 URL/主机/路径进入网络请求或读取类函数，且缺少协议 allowlist、DNS/IP 内网拒绝、端口限制等控制。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-SSRF-{序号}`

## SSRF Sink（必做）
识别至少以下网络/地址访问点：
- `curl_setopt(CURLOPT_URL, $url)` / `curl_exec`
- `file_get_contents($url)` / `readfile($url)` / `fopen($url, {value})`
- `stream_get_contents($stream)` / `fsockopen` / `pfsockopen`
- `get_headers($url)` / `dns_get_record`（配合地址解析时）
危险模式：
- URL/Host/Port/Path 来自用户输入且可控
- 协议未限制（允许 `file://`、`gopher://`、`php://` 等）

## 必做的安全检查点
- 协议白名单：仅允许 `http/https`（如有必要）
- DNS/IP 解析后内网网段拦截：拒绝 `127.0.0.1/::1/10.0.0.0/8/172.16.0.0/12/192.168.0.0/16` 等
- 端口限制：拒绝内网高危端口（由项目策略决定）
- 重定向处理：跟随跳转的限制（如 `CURLOPT_FOLLOWLOCATION`）
- 重定向与最终地址校验：即使初始 URL 通过 allowlist，仍必须对“重定向后的最终 URL”执行同等拦截与协议校验
- DNS rebinding 防护：允许域名访问时，必须在实际发起请求前进行最终解析，或使用安全解析策略避免“先外网后内网”
- URL 归一化：对编码后的主机/路径（双重编码、大小写、用户信息段 `user:pass@host`）先归一化再做 allowlist 判断

## 触发 tracer 的条件
- URL 由多字段拼接（schema + host + path + query）
- 存在多层函数调用或编码/解码/替换
- 安全判断依赖字符串规范化（必须追踪真实最终 URL）

## 报告输出
```
{output_path}/vuln_audit/ssrf_{timestamp}.md
```

## 漏洞条目模板（强制）
与 `php-sql-audit` 同结构，但在数据流链里必须覆盖：
- 最终用于发起请求的 URL/Host/Port 变量来源与拼接过程
- 协议选择与内网拦截判断的分支证据

## 证据引用（强制：来自 php-route-tracer）
每条 SSRF 疑似漏洞必须逐项引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **SSRF 行**对应证据要点（禁止只写“可能”；允许状态为待验证，但证据引用必须存在）：
1. `EVID_SSRF_URL_NORMALIZATION`：URL 归一化步骤（对应 SSRF 行中的证据点）
2. `EVID_SSRF_FINAL_URL_HOST_PORT`：发起请求前的最终 URL/Host/Port（对应 SSRF 行中的证据点）
3. `EVID_SSRF_FINAL_REDIRECT_URL`：若存在重定向/跟随跳转：最终重定向后地址证据（对应 SSRF 行中的证据点）
4. `EVID_SSRF_DNSIP_AND_INNER_BLOCK`：DNS/IP 解析与内网拦截判定证据（对应 SSRF 行中的证据点）

## tracer 证据缺失处理（强制）
- 若在 trace 中找不到上述 1~4 任一关键证据点：该条漏洞状态只能标记为 `⚠️待验证`，不得给出 `✅已确认可利用`。

#### PoC（强制）
- 必须给出可执行请求（HTTP 代码块）
- PoC URL 必须使用真实路由并替换为真实可控字段名

---

## 附 A：SSRF → 云元数据源码侧判据（IMDSv1/v2 + 各云端点）

> SSRF 的最高价值落点是**云元数据服务**（instance metadata）——拿到 IAM/实例凭据即达
> 云控制面/数据面权限。审计时把「SSRF 是否可达元数据」作为独立判据链。

### A.1 元数据端点清单（各云）

| 云 | 元数据地址 | 凭据路径 | 说明 |
|----|-----------|----------|------|
| AWS | `169.254.169.254` | `/latest/meta-data/iam/security-credentials/<role>` | IMDSv1 直接 GET；IMDSv2 需 `X-aws-ec2-metadata-token` 头 |
| GCP | `metadata.google.internal` / `169.254.169.254` | `/computeMetadata/v1/instance/service-accounts/default/token` | 必须带 `Metadata-Flavor: Google` 头 |
| Azure | `169.254.169.254` | `/metadata/instance/...` + `/metadata/identity/oauth2/token` | 必须带 `Metadata: true` 头 |
| Aliyun | `100.100.100.200` | `/latest/meta-data/ram/security-credentials/<role>` | 阿里云 ECS 元数据 |
| 腾讯云 | `metadata.tencentyun.com` / `169.254.0.23` | `/latest/meta-data/cam/security-credentials/<role>` | 腾讯云 CVM 元数据 |

### A.2 IMDSv1 vs IMDSv2 判据（决定 SSRF 是否可达）

- **IMDSv1**（无 token）：SSRF 只需能 GET `169.254.169.254/...` 即可直接取凭据——**SSRF 即凭据窃取**。
- **IMDSv2**（需 token）：必须先 `PUT http://169.254.169.254/latest/api/token` 带
  `X-aws-ec2-metadata-token-ttl-seconds` 头拿 token，再带 `X-aws-ec2-metadata-token` 头取凭据。
  **SSRF 客户端若只支持 GET 且无法自定义 PUT/头，则难以达 IMDSv2** → 降级为「SSRF 可达但元数据不可达」。
- **判据链**：SSRF 客户端能力（GET-only vs 可 PUT + 自定义头）→ IMDS 版本 → 是否可达凭据。

### A.3 源码侧判据清单

1. **地址可达性**：SSRF 的内网拦截是否覆盖 `169.254.169.254`（link-local）——
   仅拦 `127.0.0.1/10/172/192` 而漏 `169.254.0.0/16` 是常见绕过。
2. **协议能力**：SSRF 客户端是否支持自定义 HTTP 方法/头（决定 IMDSv2 可达性）。
3. **重定向**：元数据服务响应是否可被 SSRF 回显（有无响应体回显能力）。
4. **DNS rebinding**：域名白名单场景下 `169.254.169.254` 可被 rebinding 指到（最终解析判据）。

### A.4 CVE-2025-51591 Pandoc SSRF（EC2 IMDS 锚点）

> 来源：<https://safeguard.sh/resources/blog/pandoc-ssrf-cve-2025-51591-ec2-iam-theft>

- **性质**：Pandoc 文档转换过程 SSRF → 攻击者诱导访问 EC2 IMDS → 窃取 IAM 临时凭据。
- **审计锚点**：这是「文档/转换/导入类功能 SSRF → 云元数据」的典型形态——
  转换器、预览器、导入器这类「服务端主动取 URL 内容」的组件是 SSRF 高发面。
- **迁移审计法**：任何「服务端取远程资源」（文档转换、图片代理、webhook、导入 URL）都按
  A.1–A.3 判据走一遍；云环境部署时 IMDSv2 强制是纵深防御。

### A.5 修复建议

1. 内网拦截覆盖 `169.254.0.0/16` 与各云专用元数据地址；重定向后的最终地址同等拦截。
2. 生产云环境强制 IMDSv2（`HttpTokens=required`）作为 SSRF 纵深兜底。
3. SSRF 客户端最小化协议/方法能力（禁用 gopher/自定义 PUT）；元数据响应不回显给用户。


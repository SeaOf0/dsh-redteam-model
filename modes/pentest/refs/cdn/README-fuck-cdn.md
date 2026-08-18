# FUCK-CDN

**穷尽一切手段，扒光 CDN 的底裤，找到真实 IP。**

一个为 [Claude Code](https://claude.ai/code) 打造的自动化 CDN 源站溯源技能（Skill）。输入目标域名，自动按优先级执行 40+ 种 OSINT 方法，构建证据链，输出最终判定。

```
╔══════════════════════════════════════════════════╗
║  真实 IP:  103.***.**.32                        ║
║  置信度:  确定 (95%+)                            ║
║  归属地:  中国广东深圳 · 电信                     ║
║  证据链:  [S] SSL证书精确匹配                    ║
║          [A] 历史DNS记录确认                     ║
║          [A] HTTP行为差异验证                     ║
╚══════════════════════════════════════════════════╝

```

<img width="1098" height="502" alt="1" src="./imgs/769523f3-e947-4ac4-849f-84aa665a0a64.png" />

---

## 它能做什么

无论目标藏在哪家 CDN 后面——Cloudflare、腾讯 EdgeOne、阿里云、AWS CloudFront、Akamai、Fastly、Azure、Imperva、Sucuri、华为云、网宿、百度云，**乃至任何不在名单里的未知 CDN**——FUCK-CDN 都会按成本从低到高依次尝试：

| 优先级 | 方法 | Token 成本 |
|:---:|---|:---:|
| **P0** | SPF/MX/TXT 记录泄露、IPv6 直连、历史 DNS 回溯 | 极低 |
| **P1** | SSL 证书序列号精确比对、子域名枚举、HTTP Server 头行为差异分析 | 中 |
| **P2** | Shodan / FOFA / Censys / ZoomEye / Quake / Hunter 空间搜索、Favicon Hash、全端口扫描 | 较高 |
| **P3** | 邮件头溯源、JS 源码审计、同组织域名关联、GA/AdSense ID 反查、CDN 特定绕过 | 高 |
| **P4** | 深度挖掘：Web Archive 考古、源码配置审计、被动情报、云厂商元数据、WAF 穿透、时间维度攻击、社工辅助、网络拓扑推断 | 极高 |

**P0 命中就收工，不浪费一个 Token。** 没命中才升级到下一级。P0-P3 + CDN 特定/通用绕过全部失败？P4 会穷尽一切非常规手段死磕到底。找到候选 IP 后自动进入验证阶段——SSL 证书比对 + HTTP 行为对比 + IP 反查——三重交叉验证，给出置信度评级。

---

## 安装

### 方式一：克隆整个项目（推荐）

```bash
git clone <repo_url> FUCK-CDN
cd FUCK-CDN
claude
```

克隆后直接在项目目录启动 Claude Code，技能自动加载。

### 方式二：只装技能文件

如果你已有自己的项目，只需把技能文件复制进去：

```bash
# 在你的项目根目录执行
mkdir -p .claude/skills
curl -o .claude/skills/fuck-cdn.md \
  <repo_raw_url>/.claude/skills/fuck-cdn.md
```

或者手动操作：

1. 下载 `.claude/skills/fuck-cdn.md`
2. 放到你项目的 `.claude/skills/` 目录下（没有就新建）
3. 在项目目录启动 Claude Code

### 方式三：全局安装（所有项目可用）

```bash
# 放到用户级 skills 目录，所有项目共享
mkdir -p ~/.claude/skills
cp .claude/skills/fuck-cdn.md ~/.claude/skills/
```

### 验证安装

启动 Claude Code 后输入 `/` 查看可用技能列表，应能看到 `fuck-cdn`。

---

## 使用

### 基本用法

在 Claude Code 中直接调用：

```
/fuck-cdn example.com
```

或者用自然语言：

```
帮我查 example.com 的真实IP
```

### API Key 配置

有两种方式配置 API Key：

#### 方式一：直接编辑 Skill 文件（推荐，一劳永逸）

打开 `.claude/skills/fuck-cdn.md`，找到顶部的 API Key 配置区，把你的 Key 填进去：

```
SHODAN_API_KEY     = "你的Key"
FOFA_EMAIL         = "你的邮箱"
FOFA_API_KEY       = "你的Key"
CENSYS_API_ID      = "你的ID"
CENSYS_API_SECRET  = "你的Secret"
SECURITYTRAILS_KEY = "你的Key"
ZOOMEYE_API_KEY    = "你的Key"
QUAKE_API_KEY      = "你的Key"
HUNTER_API_KEY     = "你的Key"
VIRUSTOTAL_KEY     = "你的Key"
```

填好后每次调用自动使用，无需重复输入。

> **安全提示**：如果你的项目是公开仓库，**不要提交含 Key 的 skill 文件**。建议将 `.claude/skills/fuck-cdn.md` 加入 `.gitignore`，或只在本地 / 全局安装（`~/.claude/skills/`）中填写 Key。

#### 方式二：对话中临时提供

在对话中直接告诉 Claude 你的 Key，仅在当前会话内存中使用，不写入任何文件：

```
我的 Shodan key 是 xxxx，FOFA 邮箱是 xxx key 是 xxx
帮我查 example.com 的真实IP
```

#### 支持的平台

| 平台 | Key 格式 | 免费额度 | 用途 |
|---|---|---|---|
| [Shodan](https://shodan.io) | `SHODAN_API_KEY` | 注册即有 | 按证书/favicon/标题搜索持有相同特征的 IP |
| [FOFA](https://fofa.info) | `FOFA_EMAIL` + `FOFA_API_KEY` | 注册即有 | icon_hash、证书、body 关键字搜索 |
| [Censys](https://search.censys.io) | `CENSYS_API_ID` + `CENSYS_API_SECRET` | 注册即有 | 证书指纹 SHA256 精确搜索 |
| [SecurityTrails](https://securitytrails.com) | `SECURITYTRAILS_KEY` | 免费 50次/月 | 历史 DNS 记录、子域名枚举 |
| [ZoomEye](https://www.zoomeye.org) | `ZOOMEYE_API_KEY` | 注册即有 | 证书、标题搜索 |
| [360 Quake](https://quake.360.net) | `QUAKE_API_KEY` | 注册即有 | 证书搜索 |
| [鹰图 Hunter](https://hunter.qianxin.com) | `HUNTER_API_KEY` | 注册即有 | 证书搜索 |
| [VirusTotal](https://www.virustotal.com) | `VIRUSTOTAL_KEY` | 免费 500次/天 | 解析历史、子域名枚举 |

**没有任何 Key 也能用。** P0 和 P1 阶段的所有方法（历史 DNS、证书比对、子域名枚举、HTTP 行为分析）不需要 Key，命中率已经很高。Key 的价值在 P2 阶段——空间搜索引擎能大幅提升对高防目标的命中率。

---

## 覆盖的 CDN

不只是识别，每家 CDN 都有**专属绕过方法**：

| CDN | 识别 | 专属绕过 |
|---|:---:|---|
| Cloudflare | ✅ | 非代理端口直达、CrimeFlare 数据库、direct 子域名 |
| 腾讯 EdgeOne | ✅ | 网络层拦截识别、CVM 网段特征、证书同步机制 |
| 阿里云 CDN/DCDN | ✅ | 回源 Host 差异、ECS 网段、OSS/FC 判断 |
| AWS CloudFront | ✅ | S3 Bucket 源站、ALB 域名、AWS IP 段筛选 |
| Akamai | ✅ | SureRoute 测试对象、Ghost 调试头、Staging 网络 |
| Azure CDN/Front Door | ✅ | Azure VM 域名、health probe 泄露 |
| Fastly | ✅ | Anycast 特征、X-Served-By 泄露、Shield 区域 |
| Imperva/Incapsula | ✅ | 回源不验证 Host、X-Iinfo 泄露 |
| Sucuri WAF | ✅ | 非标准端口直达、历史 DNS 高泄露率 |
| 华为云 CDN | ✅ | X-HW-Via 调试头、ECS 网段 |
| 网宿 CDN | ✅ | 运营商网段特征、历史 DNS |
| 百度云 CDN | ✅ | BCH/BOS 源站、高泄露率 |
| CDN77 / KeyCDN / StackPath | ✅ | 通用方法 |
| Vercel / Netlify | ✅ | 通用方法 |
| 加速乐 / 云盾 / 安全宝 | ✅ | 通用方法 |
| **其他 / 未知 CDN** | ✅ | **通用兜底流程**：自动识别 CDN 类型 → 非标端口扫描 → 协议层绕过 → EDNS 绕过 → 空间搜索引擎交叉验证 |

> **不在名单里怎么办？** P0-P2 的所有方法（历史 DNS、SSL 证书比对、子域名枚举、空间搜索引擎等）本身就是 CDN 无关的，对任何厂商都有效。CDN 特定绕过只是锦上添花——通用方法失败时的最后手段。即使遇到完全没见过的小众 CDN，skill 也会自动走通用兜底流程：先识别 CDN 类型，再按端口/协议/EDNS 等通用思路绕过。

---

## 完整方法清单

### DNS 系列
- SPF/TXT 记录直接泄露源站 IP
- MX 记录邮件服务器泄露
- DMARC 报告地址泄露
- IPv6 AAAA 记录未接 CDN
- 多 DNS 服务器查询（8 个公共 DNS）
- 子域名枚举（50+ 高优先级子域名）
- 通配符检测与绕过
- DNS Zone Transfer (AXFR)
- DNSSEC NSEC Walking
- 权威 DNS 直查

### 历史数据系列
- ipchaxun.com 历史 DNS
- ip138.com 域名反查
- ViewDNS.info IP History
- SecurityTrails 历史记录
- VirusTotal 解析历史
- Web Archive 历史快照

### SSL 证书系列
- 证书透明度日志 (crt.sh)
- 证书序列号精确比对（决定性验证）
- 证书 SHA256 指纹搜索
- SNI vs 默认证书差异分析
- SAN 域名发现

### 空间搜索引擎系列
- Shodan（证书 / 标题 / favicon / body hash）
- FOFA（证书 / icon_hash / 标题 / body 关键字）
- Censys（证书指纹 / CN / body hash）
- ZoomEye（证书 / 标题）
- 360 Quake（证书）
- 鹰图 Hunter（证书）

### HTTP 行为分析系列
- Server 响应头差异（CDN 标识 vs 真实服务器）
- 响应头泄露（X-Real-IP / X-Backend-Server / X-Upstream-Addr）
- CORS 头分析
- CSP 头分析
- 多端口扫描（24 个常用端口）
- SSH / FTP 服务探测
- WebSocket 探测

### 高级技术系列
- Favicon mmh3 Hash 反查
- 网站特征指纹匹配（标题 / body hash / 唯一关键字）
- 邮件头溯源（注册 / 找回密码触发）
- 源码审计（phpinfo / .env / JS 中的 API 地址）
- Google Analytics / AdSense ID 关联
- 同组织域名关联（WHOIS 反查）
- /24 邻居扫描
- CDN 特定绕过（12 家 CDN 专属方法 + 通用兜底流程）

### P4 深度挖掘系列（穷尽一切手段）
- Web Archive 时间线考古（历史快照资源引用分析）
- 源码与配置文件深度审计（40+ 敏感路径探测、JS/HTML 中 IP 提取、WebSocket 地址）
- 被动情报聚合（DNSDumpster / ThreatCrowd / AlienVault OTX / RiskIQ / URLScan.io）
- 云厂商元数据探测（AWS / Azure / GCP / 腾讯云 / 阿里云内部域名拼接）
- WAF 穿透（HTTP 方法绕过、路径混淆、Host 头注入、X-Forwarded-For 欺骗、大请求体绕过）
- 时间维度攻击（SSL 证书续期窗口、CDN 配置变更监控、新子域名监控）
- 社工辅助情报（GitHub/GitLab 代码搜索、Pastebin 泄露、搜索引擎缓存、安全报告）
- 网络拓扑推断（Traceroute / MTR 分析、TCP 指纹比对、地域差异利用）

### 辅助验证系列
- WHOIS 查询
- ICP 备案查询
- IP 归属地 / 运营商查询
- IP 反查域名绑定历史
- CDN ASN 排除

---

## 验证机制

找到候选 IP 不算完。FUCK-CDN 有完整的验证流水线：

```
候选 IP
  │
  ├─ V-1: SSL 证书序列号是否与 CDN 一致？
  │       └─ 默认证书是否是另一个域名的？（源站多虚拟主机特征）
  │
  ├─ V-2: 直连 Server 头是 nginx/apache 还是 CDN 标识？
  │
  ├─ V-3: IP 反查是否有目标域名的绑定记录？
  │
  └─ V-4: SSH/FTP 端口是否开放？（CDN 节点不开这些）
         │
         ▼
    证据评级: S(决定性) / A(强佐证) / B(佐证) / C(弱线索) / X(已排除)
         │
         ▼
    置信度: 确定(95%+) / 高度可信(80-95%) / 可能(60-80%) / 猜测(<60%)
         │
         ▼
    ╔═══════════════════════════════════╗
    ║  真实 IP: x.x.x.x               ║
    ║  置信度: 确定 (95%+)              ║
    ╚═══════════════════════════════════╝
```

---

## 跨平台

自动检测运行环境并适配：

| | Windows | Linux / macOS |
|---|:---:|:---:|
| DNS 查询 | `nslookup` | `nslookup` / `dig` / `host` |
| HTTP 请求 | `curl` (Git Bash) | `curl` |
| SSL 证书 | `openssl` (Git Bash) | `openssl` |
| WHOIS | WebFetch 替代 | `whois` |
| Python | `python` | `python3` |
| 临时文件 | `$env:TEMP` | `/tmp` |

---

## 实战截图


### 案例一

<img width="821" height="1172" alt="2" src="./imgs/9f263809-f0c9-4654-8ef5-664f75fd000d.png" />
<img width="817" height="1164" alt="3" src="./imgs/1a74c9ba-f8af-4b56-b7e0-d373bdb98fb9.png" />


---

---

## 免责声明

本工具仅用于**授权安全测试**、**网络安全教学**、**CTF 竞赛**等合法场景。使用者应确保已获得目标系统所有者的明确授权。因使用本工具产生的一切法律责任由使用者自行承担。


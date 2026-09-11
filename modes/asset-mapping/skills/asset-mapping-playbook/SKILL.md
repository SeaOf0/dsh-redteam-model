---
name: asset-mapping-playbook
description: 资产测绘模式作战手册：S0→S7 管线（目标展开与 scope 定界 → 五平台查询与 ICP 备案链路 → 子域枚举与 DNS 校验 → 合并去重与归属判定 → 温和探测与指纹 → Excel 六表交付）、key 三分支启动（keys.json / dsh-hunter key 借用 / 免费降级链）、归属判定优先级链与假阳性四类防线（伪造备案/泛解析/tarpit/CDN）、补充情报源矩阵（爱企查控股穿透/DNS 历史/小程序/搜索引擎/favicon 反查）、编排（管线主体走脚本断点续跑，subagent 用于半自动环节）、边界条款（止步测绘+指纹、范围外只测绘不探测、配额纪律）。
tools: curl, dig, python3
---

# 资产测绘作战手册

> 本技能随 asset-mapping 预设走。
> persona 中的硬规则（准确性>数量、只读探测、scope 白名单、表达纪律、删除纪律）不在此重复。
> 管线脚本随本技能目录自带：`scripts/`（s0→s7 + fpdb_update + _common）与 `assets/`（模板与种子库）。以下 `$S` 指本技能目录（从技能目录解析获得），所有脚本在测绘工作目录 `<work>` 下运行（`--work` 参数）。

## 0. 定位与口径

把一个集团企业（母公司 + 授权二级/三级单位）的公网资产测成一份**可审计**的测绘 Excel：每条资产有归属单位、ICP 备案、来源、指纹、关联度。

- 口径 = **范围内单位全部公网资产**；**准确性优先于数量**——一条错归属比漏十条更伤。
- 止步于测绘 + 指纹（只读、温和速率）；打点/弱口令/漏洞利用走攻击类模式与各自授权。
- 交付物落工作区根目录（`<项目名>_资产测绘_<日期>.xlsx`），不落 reports/。

## 1. 启动检查（每次先做）

**key 三分支**（按序判定）：

1. `<work>/keys.json` 存在且非空 → 照常用，先跑 `--doctor` 体检每个 key 的有效性与剩余配额（Hunter 体检耗 1 积分，其余免费），并打印能力矩阵（ICP 反查/证书 org 反查/中文公司名反查是否可用）。
2. keys.json 缺失或为空 → 脚本自动只读探测 `~/.dsh/hunter/hunter.db`（dsh-hunter 已配的 fofa/hunter/quake key）：有则进程内借用（输出标注「来源: dsh-hunter」，不落盘），doctor 照常体检；读取失败静默当无。
3. 全无 key → 询问用户是否提供（附各平台申请地址，见 refs/api-docs.md）；用户不给则走**免费降级链**：crt.sh/RapidDNS 子域 → DNS 存活/泛解析 → 温和探测 + 种子指纹（缺平台查询 = 缺 ICP 反查与组件字段，资产面收窄到子域名展开，如实告知用户）。

前置输入两文件（模板在 `assets/`）：

- `keys.json`：五平台密钥（FOFA/Hunter/Quake/ZoomEye/Shodan），缺哪个跳过哪个，不强制配齐。
- `scope.json`：授权范围。`units[]` = 单位名 + 主域 + 备案号；`sub_overrides` = 手工归属例外；`group_domains_out_of_scope` = 集团域（未授权子域一律范围外）；`keywords` = 靶标关联度打分词。初稿允许只有单位名和少量主域——S1/S2 会迭代补全。

```bash
python3 $S/scripts/s0_expand.py --work <work> --doctor   # 启动体检（key 三分支内建于脚本）
```

## 2. S0 目标展开 + 范围定界（半自动，有人工核对关卡）

用户给五种入口之一，统一展开成 scope 草稿：

```bash
python3 $S/scripts/s0_expand.py --work <work> --domain a.com,b.com   # 域名入口
python3 $S/scripts/s0_expand.py --work <work> --ip 1.2.3.4           # IP 入口（--cidr 1.2.3.0/24）
python3 $S/scripts/s0_expand.py --work <work> --group "XX集团"        # 集团/单位名入口（--unit 同）
python3 $S/scripts/s0_expand.py --work <work> --keyword "XX平台"      # 关键字入口（给查询词建议）
```

- 域名入口：FOFA `domain=` / Hunter `domain.suffix=` 小样本（50 条）→ 备案号 + 关联主域候选。
- IP/CIDR 入口：FOFA `ip=` 反查归属 → 写入草稿 `targets_ip`，s5 阶段网段内资产自动算范围内。
- 集团名入口：Hunter `company="名"`（中文备案公司名，唯一支持）+ FOFA `org="名"`（证书 O 字段，多为英文）→ 主体/备案号/主域候选。**多级控股子公司穿透（二级/三级/四级/全资）全自动不可行**——按脚本输出的 checklist 走爱企查 BFS（持股 ≥50% 或授权口径，深度 ≤4），操作矩阵见 refs/osint-sources.md §1。
- 注册域归约内置国内二级后缀处理（com.cn 等），不会把 `sub.n1b.com` 切错成三段。

**人工核对关卡（HITL 门，管线不得越过）**：草稿 `runs/scope_draft.json` → 人工核对（爱企查核控股、备案真伪、读授权书列排除主体）→ 改名 `scope.json` 生效。核对发现的备案号回填 scope 后，重跑 S1 的 ICP 反查补资产。

## 3. S1/S2 平台查询与备案链路（核心，全自动）

```bash
python3 $S/scripts/s2_engines.py --work <work>                       # 全部已配 key 平台
python3 $S/scripts/s2_engines.py --work <work> --only fofa,hunter --max-pages 5
python3 $S/scripts/s1_scope_tools.py --work <work> --icp-census      # 备案号→主体/域名清册草稿
python3 $S/scripts/s1_scope_tools.py --beianx example.com            # 单域备案快查
```

- 每平台对每个主域跑域名查询、每个备案号跑 ICP 反查（支持的平台）；输出 `runs/engines/engines_all.jsonl`（统一 schema，`host:port:scheme` 归一）。
- 备案反查只在 FOFA/Hunter/Quake 三家（ZoomEye/Shodan 无 ICP 面）。
- 中文公司名反查只有 Hunter `company=`；FOFA `org=`/Quake `org:` 是证书口径（英文全称）。
- 配额纪律：每查询打印剩余配额，见底通知用户；断点重跑自动 [skip] 不重复扣费。
- 平台语法、错误码、坑清单（Hunter page_size 合法值 1/10/50/100、ICP 号剥尾序号比对等）见 refs/api-docs.md。

## 4. S3/S4 子域与 DNS

```bash
python3 $S/scripts/s3_subdomains.py --work <work> [--proxy http://127.0.0.1:7890]
python3 $S/scripts/s4_dns_alive.py --work <work> [--dns 223.5.5.5] [--threads 12]
```

- S3：crt.sh（3 次重试）+ RapidDNS 双源 → `runs/crt/<域>.txt`。
- S4：先泛解析检测（随机子域双探针）再并行存活解析；泛解析域的假存活自动剔除；CDN CNAME 标记。产物 `runs/dns/wildcard.json` + `alive_subs.txt`。
- **泛解析不检测，子域存活全是假数据**——S4 不可跳过。
- DNS 历史考古（A 记录消失 ≠ 服务下线，`--connect-to` 直达验证）见 refs/osint-sources.md §3。

## 5. S5 合并去重 + 归属判定

```bash
python3 $S/scripts/s5_dedupe.py --work <work>
```

- 多源按 `host:port:scheme` 归一合并，字段互补不覆盖，来源留痕（source_tag）。
- **归属判定优先级链**：子域例外表 > 域名后缀 > ICP 主体匹配（剥尾序号） > 集团域范围外 > 未知（范围外）。ICP 归属但域名不在主域表 → 标「需人工确认」。
- 自动剔伪造备案垃圾（IP 垃圾段 + 博彩标题）；tarpit 标记（单 IP ≥30 端口）；CDN/共享托管标记；非 web 端口资产保留不误删；靶标关联度打分。产物 `runs/assets.jsonl`。

## 6. S6 温和探测 + 指纹（只碰 in_scope）

```bash
python3 $S/scripts/s6_probe_fp.py --work <work> [--threads 10] [--skip-paths]
```

- 根路径（状态/标题/Server/JS 标记/favicon mmh3/WAF 识别）→ 敏感路径（actuator/druid/swagger/nacos…轻量判定）→ 指纹匹配。
- 默认 `assets/fpdb_seed.json` 种子库（实战验证签名）；全量库（5600+ 规则）用 `fpdb_update.py --proxy ...` 重建后 `--fpdb` 指定。
- 指纹假阳性甄别（SPA fallback / 302 回显 / JSON 404 / 关键词过泛）见 refs/quality-rules.md §C；**高价值命中必须人工复核响应原文**。
- 范围外资产（灰底）只测绘不探测——S6 只碰 in_scope。

## 7. S7 Excel 交付

```bash
python3 $S/scripts/s7_excel.py --work <work> [--name 项目名]   # 依赖 openpyxl
```

六工作表：测绘总表（逐资产 18 列，含 ICP/来源/备注） / 域名清单 / 子域名清单(DNS 存活) / 单位汇总 / **框架资产(指纹命中)** / 测绘说明（方法论+准确性控制+局限，必须按实情改写）。配色：高关联=橙，范围外=灰，泛解析=绿。交付前按 refs/quality-rules.md §E 检查单核对；局限性一节如实写（内网型系统无公网暴露、平台采样深度、crt.sh 失败域、待人工确认项）。

## 8. 补充情报源（穿插 S0-S3 按需做）

- **搜索引擎**：`site:*.domain.com -www`、备案号反查、`ext:xlsx` 泄露文档——操作矩阵见 refs/osint-sources.md §4。
- **DNS 历史**：SecurityTrails/ViewDNS；DNS 已删目标 `curl --connect-to host:443:IP:443` 验证 vhost 存活（§3）。
- **小程序/APP/公众号**：反编译抓 API 域名/云 AK；favicon mmh3 反查同模板兄弟站（§5）。
- **GitHub**：`site:github.com "domain"` 代码泄漏。

## 9. 编排

- **管线主体 = 脚本**：S0→S7 按序执行、每步产物落 `runs/`、断点可续；不把管线步骤改写成手工逐条调用。
- **subagent 三用途**（可并行）：① 爱企查 BFS 控股穿透（网页读取，频控 3-5s/页）；② 搜索引擎/小程序/APP 补充源检索；③ scope 草稿整理与人工核对关卡的材料准备。
- **跨模式交接**：交付后把框架资产表（第 5 表）作为 pentest/attack-defense 打点优先级输入（生态流表见 ecosystem-cooperation 技能）；本模式收到打点类请求时反向交接，不越界执行。

## 10. 边界条款（执行任何阶段前默读）

1. 准确性 > 数量：错归属比漏报更伤。归属拿不准 → 标「需人工确认」，不强判。
2. 伪造备案过滤必须跑：央企备案号被赌博站批量伪造，IP 集中 154.x/156.x/179.x。
3. 泛解析不检测，子域存活全是假数据。
4. 范围外资产只测绘不探测；集团域子域默认范围外。
5. 止步于测绘+指纹；打点/弱口令/漏洞利用走攻击类模式，另需授权。
6. 删除文件用 trash 不用 rm；备份先行。

## 11. 工具手册与知识库（refs/，正文不在此重复）

| 文档 | 内容 | 何时读 |
|---|---|---|
| refs/api-docs.md | 五平台 API 细节、查询语法、错误码、十大坑清单、key 申请入口 | 构造查询前 / 平台报错时 |
| refs/osint-sources.md | 爱企查控股穿透 SOP、备案渠道矩阵、DNS 历史、搜索引擎语法、小程序/favicon/C 段 | S0 展开与补充情报源阶段 |
| refs/quality-rules.md | 归属判定细则、假阳性四类、指纹假阳性五条、平台数据口径、Excel 交付规范、授权纪律 | S5/S6 判定与 S7 交付前 |

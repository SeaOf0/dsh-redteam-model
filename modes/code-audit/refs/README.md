# code-audit 参考手册库（refs/）

> 本目录随 code-audit 预设打包分发。所有文件为预设内自包含资源，不依赖任何机器特定路径。
> 定位：手册库——audit-playbook 是速查卡，这里的文件是深度手册、专项审计技能与可直接使用的
> semgrep 规则；需要细节时用 read 直接读取。
> 路径解析：加载 audit-playbook 技能时你会得到该技能的 base 目录（SKILL.md 所在目录，
> 即 `skills/audit-playbook/`）；refs/ 相对 base 目录 = `../../refs/`。
> 覆盖面：六语言审计手册 / Java 与 PHP 专项审计技能集（含 semgrep 规则）/ 组件漏洞识别 /
> 供应链与密钥 / 密码学实现审计 / 容器与 K8s 配置 / SAST·DAST 方法论 / AI 与 Agent 审计 /
> 定级标准参照（内置 Fortify 分类学 + 规则知识库 + 开源规则集）/ 趋势。共 226 篇 md + 1482 条 semgrep 规则（402 条自建 + 1080 条开源）。

## 快速路由（按任务类型找目录）

| 任务类型 | 目录 |
|---|---|
| 按语言的全量审计 | `lang/`（6 篇总手册） |
| Java/前端深度专项（逐漏洞类/框架/流程/规则） | `lang/java-audit/`（27 篇 + semgrep-rules 14 条） |
| PHP 深度专项（逐漏洞类/框架/流程） | `lang/php-audit/`（39 篇） |
| 已知漏洞组件识别（fastjson/shiro/log4j/struts2/weblogic） | `components/`（5 篇） |
| 供应链与密钥（SBOM/依赖混淆/SCM/硬编码凭据） | `sca/`（4 篇） |
| 密码学实现与误用审计 | `crypto/`（2 篇） |
| 容器与 K8s 配置审计 | `config/`（2 篇） |
| 审计方法论（SAST/DAST/深审/覆盖率纪律） | `methodology/`（4 篇） |
| 定级与分类标准参考（内置 Fortify 分类学，随预设分发） | `standards/`（fortify-kingdom-reference + chanzi-rules 122 条 + semgrep-oss 开源规则集） |
| AI/LLM/Agent/MCP 应用审计 | `ai/`（7 篇） |
| 2025–2026 标准与基准风向 | `trends/`（2 篇） |

## 目录索引

### lang/（语言总手册，7 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| code-audit-java.md | Java 代码审计全解 | Java/Spring 项目 |
| code-audit-python.md | Python 代码审计全解 | Python/Django/Flask 项目 |
| code-audit-php.md | PHP 代码审计全解 | PHP 项目总览（深度走 php-audit/） |
| code-audit-javascript.md | JS/Node 代码审计全解 | 前端/Node/小程序 JS |
| code-audit-go-rust.md | Go/Rust 代码审计 | Go/Rust 项目 |
| code-audit-c-cpp.md | C/C++ 代码审计全解 | 原生/二进制相邻项目 |
| dotnet-deser-audit.md | C#/.NET 反序列化审计手册（ysoserial.net 链 + ViewState 机器密钥判据；规则降级兜底） | .NET 反序列化 |

### lang/java-audit/（Java/前端专项，27 篇 + semgrep-rules/）

| 文件 | 内容 | 何时读 |
|---|---|---|
| java-audit-framework.md | AI+Java/前端审计框架协议：语言×框架矩阵、覆盖率与低幻觉工作法 | Java 深度审计总入口 |
| java-audit-pipeline.md | Java 审计流水线（分阶段执行协议） | 组织一次完整 Java 审计 |
| java-vuln-scanner.md | 漏洞扫描器编排（组合规则与扫描策略） | 扫描阶段 |
| java-sql-audit.md | SQL 注入审计专项（sink/过滤绕过/MyBatis 场景） | Java 注入审计 |
| java-auth-audit.md | 认证与授权审计专项 | Java 鉴权链审计 |
| java-xxe-audit.md | XXE 审计专项 | XML 解析面 |
| java-file-upload-audit.md | 文件上传审计专项 | 上传功能 |
| java-file-read-audit.md | 文件读取/路径穿越审计专项 | 下载/读取功能 |
| java-route-mapper.md | 路由映射：从代码还原全部端点 | 资产/入口面盘点（先跑） |
| java-route-tracer.md | 路由追踪：入口→sink 数据流追踪 | 调用链引用规范落地 |
| java-decompile-strategy.md | CFR 反编译 CLI 统一使用策略 | 审 jar/反编译产物 |
| security-checklist.md | 安全检查清单（框架级） | 收尾核对 |
| vulnerability-conditions.md | 漏洞成立条件表（判定） | 定级与误报排除 |
| logic-vulnerability-cot.md | 逻辑漏洞思维链审计法 | 业务逻辑审计 |
| cve-offline-lookup.md | 离线 CVE 核对思路 | 已知漏洞核对（无网环境） |
| dktss-scoring.md | DKTSS 评分模型 | 定级 |
| business-scenario-tags.md | 业务场景标签体系 | 场景化覆盖 |
| report-template.md / report-quick-ref.md | 审计报告模板与速查 | 报告阶段 |
| java-output-standard.md / java-severity-rating.md | 输出规范与严重度评级（子技能共享） | 全流程 |
| java-sink-reference.md | Java 危险 sink 大表（SQL/CMD/SSRF/XSS/FILE/UPLOAD/XXE/DESER/TPL/LDAP/EXPR/JNDI/AUTH/CSRF/REDIR/CRLF/SESS/CFG/ARCHIVE/UNAUTH-RCE 20 类，覆盖矩阵的 sink 类型轴地基） | 面映射/覆盖矩阵 |
| java-deser-gadget-chains.md | Java 反序列化 gadget 链库全景（CC1–CC7 逐条 + JDK7u21 + Hessian only-JDK + fastjson/Jackson TemplatesImpl + ysoserial 全 payload 表） | 深度反序列化主线 |
| java-archive-extract-audit.md | Java 归档解压路径穿越（Zip Slip：ZipFile/ZipInputStream/ZipEntry.getName）专项，对齐 PHP 五证据点 | 压缩包解压 |
| java-unauth-rce.md | Java 未授权 RCE 危险接口清单（actuator heapdump/env/jolokia/restart + JMX/RMI/远程 debug） | 未授权 RCE 主线 |
| java-exploit-chain-audit.md | Java 跨漏洞利用链聚合器（任意写→webroot/cron、SSRF→gopher→内网、反序列化→命令执行 + 最弱环节判据） | 组合 RCE 主线 |
| java-expr-injection-audit.md | Java 表达式注入专项（SpEL/OGNL/MVEL/EL 四引擎 sink 表 + 安全上下文判据） | 表达式注入 |
| semgrep-rules/ | 14 条可直接 `semgrep --config` 使用的规则（java 注入/crypto/file/rce/ssrf/microservice/api/config/emerging + js/react/vue/frontend-config，含 README） | 扫描阶段直接挂载 |

### lang/php-audit/（PHP 专项，39 篇 + semgrep-rules/）

**可直接挂载的 semgrep 规则**：semgrep-rules/php-cmd-sink.yaml（命令执行 sink 全集，
补齐 DVWA 验收漏掉的 shell_exec/passthru/pcntl_exec/eval；
实测 DVWA 18 命中含 webshell；`semgrep --config` 直跑，命中后走 A2 双链确认）。

**流程与工具**：php-audit-pipeline.md（审计流水线）、php-vuln-scanner.md（扫描编排）、
php-route-mapper.md / php-route-tracer.md（路由映射与数据流追踪）、
php-exploit-chain-audit.md（利用链审计——从 sink 串联到可利用链）。

**漏洞类专项**：php-sql-audit、php-nosql-audit、php-cmd-audit、php-expr-audit（代码执行）、
php-deser-audit（反序列化）、php-file-upload-audit、php-file-read-audit、php-file-write-audit、
php-filesystem-audit、php-archive-extract-audit（压缩包解压）、php-ssrf-audit、php-xxe-audit、
php-xss-audit、php-csrf-audit、php-crlf-audit、php-ldap-audit、
php-open-redirect-audit、php-tpl-audit（模板注入）、php-session-cookie-audit、php-auth-audit、
php-crypto-audit、php-config-audit、php-logging-audit（日志注入/敏感信息）、php-logic-audit。

**框架专项**：php-thinkphp-audit、php-laravel-audit、php-symfony-audit、php-codeigniter-audit、
php-yii-audit、php-wordpress-audit（插件/主题审计）。

**共享规范**：php-sink-reference.md（PHP 危险 sink 大表——审计优先级的地基）、
php-severity-rating.md、php-io-path-convention.md（输入输出路径约定）、
php-evidence-point-ids.md（证据点编号——调用链引用规范的同构实现）。

### components/（漏洞组件识别，5 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| fastjson.md | fastjson 利用链与漏洞模式（autotype 系） | 依赖命中 fastjson |
| shiro.md | Shiro 反序列化/rememberMe 与密钥模式 | 依赖命中 shiro |
| log4j.md | Log4j2 JNDI（Log4Shell 家族）模式 | 依赖命中 log4j2 |
| struts2.md | Struts2 OGNL 系列漏洞模式 | 依赖命中 struts2 |
| weblogic.md | WebLogic 反序列化/T3 系列模式 | 中间件为 WebLogic |

> 定位说明：这五篇来自渗透侧技能，这里取其「漏洞成立条件与代码特征」用于**识别与核对**；
实际利用验证按生态规则交 pentest 模式。

### sca/（供应链与密钥，4 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| devsecops-supply-chain.md | 供应链安全全景（SBOM/依赖/投毒） | 供应链审计总览 |
| dependency-confusion.md | 依赖混淆攻击与审计（931 行：命名空间/私有源/投毒链） | 私有依赖环境 |
| insecure-scm.md | 不安全 SCM 配置审计 | 代码仓库配置面 |
| devsecops-secrets.md | 密钥管理检测（硬编码凭据） | 凭据排查 |

### crypto/（2 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| crypto-implementation.md | 密码学工程与审计：AES-GCM/Ed25519/TLS1.3/mTLS 实现、密码学审计方法论、Padding Oracle/侧信道、后量子迁移 | crypto-audit 专项与加密相关 finding 定级 |
| crypto-misuse-audit.md | 加密误用源码审计：逐语言 sink 表 + 签名验证绕过模式（JWT alg=none/verify 忽略/length extension/弱随机数） | 签名验证/加密误用审计 |

### config/（2 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| container-security-scanning.md | 容器/Dockerfile 扫描 | 配置与部署资产审计 |
| kubernetes-security.md | K8s 安全审计 | K8s manifest/集群配置 |

### methodology/（4 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| devsecops-sast.md | SAST 方法论全景 | 静态审计流程设计 |
| devsecops-dast.md | DAST 方法论全景 | 动态验证环境搭建 |
| evidence-first-audit.md | 深度审计方法论（分层下钻/证伪纪律，证据优先四阶段） | 深度审计级（三级深度之一） |
| coverage.md | 覆盖率纪律（覆盖什么、怎么算覆盖） | 审计收尾防漏报 |

### ai/（7 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| ai-prompt-injection.md | 提示注入攻击面 | LLM 应用审计基础 |
| ai-jailbreak-techniques.md | 越狱技术 | LLM 应用红队/审计交叉 |
| ai-agent-safety.md | Agent/Multi-Agent 安全：工具滥用、间接注入、memory 投毒、MCP server 利用（LangChain/AutoGen/CrewAI/MCP） | Agent/MCP 架构审计主手册（Agentic Top 10 2026 对应） |
| ai-rag-poisoning.md | RAG 安全：知识库投毒、向量索引污染、跨会话泄露 | RAG/知识库应用 |
| ai-system-prompt-extraction.md | 系统提示词提取与泄露审计 | 系统提示词面 |
| ai-model-security.md | 模型层安全：投毒/对抗样本/模型提取/ML 供应链 | 自训模型/ML 管线 |
| ai-mcp-audit.md | MCP 生态安全审计：工具描述投毒/资源投毒（MCP-Scan inspect/proxy、MCP-Shield、mcp-audit+Semgrep 分层）+ MCP 配置审计清单 | MCP server/agent 审计 |

### trends/（2 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| audit-trends-2025-2026.md | OWASP Top 10:2025 审计含义（供应链/异常处理新检查面）、Agentic Top 10 2026（ASI01-04）、LLM Top 10 2026、SEC-bench/SEC-bench Pro 自测基准、MCP server 审计工具（全部附来源，2026-08 核实） | 开审前校准标准参照 |
| cve-2025-rce-patterns.md | CVE-2025 系列 RCE 审计模式：CVE-2025-24813 Tomcat session 反序列化、CVE-2025-49113 Roundcube、CVE-2025-64512 pdfminer、CVE-2025-55182 Next.js Server Actions（入口→sink→利用链→版本判据） | 2025 新 RCE 面核对 |

### standards/（定级与分类标准参考 + 规则库）

| 文件/目录 | 内容 | 何时读 |
|---|---|---|
| fortify-kingdom-reference.md | 内置标准参考实体：Fortify 分类学（八王国）→ CWE 映射 → 与本预设审计手册的对应表 → 证据化定级指南 → 使用 SOP。**不依赖本机/外部 Fortify 安装**（外部 Fortify 仅作增强参照）；persona Rule baseline 引用本文档 | 每次定级/分类时（audit-playbook「静态审计标准」章的标准参考） |
| chanzi-rules/（122 条 + INDEX + 开发规范） | Java 生态漏洞规则知识库：SQLi/SSRF/SSTI/XXE/XSS/反序列化/代码执行/命令注入/越权/上传/弱口令/硬编码等 20 类，每条含关键 sink 清单 + 中文详解 | 按类别深审时（先读 INDEX.md 定位） |
| semgrep-oss/（开源规则集，见其 README） | 1080 条可执行 semgrep 规则：semgrep-rules 788 条/10 语言（锁定 LGPL-2.1+Commons Clause 合规快照 f4b63d5，HEAD 已变专有禁止分发）+ trailofbits 120 条（AGPL-3.0，附 LICENSE）+ gitleaks 厂商密钥枚举 172 条；全量 validate 通过 | 扫描阶段直接 `semgrep --config` 挂载（audit-playbook「静态扫描」节：本地规则集优先） |

## 内容与许可说明

- 库内内容分两类：本模式自写条目（外部技术点在文中以 URL 注明出处）与第三方开源内容
  （许可注记见各 README 与 semgrep-oss/README 的开源规则集合规快照）。
- **lang/java-audit/**：含框架协议、references 与 semgrep 规则（semgrep-rules 为可直接使用的
  yaml 规则）；scripts/ 与 requirements 未随附。
- **components/**：渗透侧组件利用技能，取识别视角。
- **standards/fortify-kingdom-reference.md**：playbook 自建——把「Fortify 规则体系作标准参考」的
  业务逻辑改为 preset 内置实体：分类学为公开的 Fortify Taxonomy（Seven Pernicious Kingdoms 体系），
  CWE 映射取自 MITRE 公开目录，**不含任何 Fortify 版权规则文件**；外部 Fortify 安装为可选增强参照。
- **ai/**：与 pentest/refs/ai/ 保持一致（六篇）——为保证单预设分发自包含，接受整体分发时的重复。
- **trends/**：自建综述，条目联网核实并附来源链接。
- 本目录随预设打包分发；与 playbook 的关系：速查卡（playbook）→ 深度手册（refs/）→ 证据落盘
  （任务工作区，见 ecosystem-cooperation 技能「产物落盘与交接约定」）。

## 路径与链接约定

- 库内文件一律相对路径引用，**禁止任何本机绝对路径**（预设将打包给其他用户使用）。
- 库内文件内部的相对链接在本库内不直接解析；
  按链接中的技能名在本库对应目录检索同名 md 文件即可（多数兄弟技能在库内）。
- frontmatter（name/description）保留原样；refs/ 不经技能加载器发现，
  仅由 read 按需读取，frontmatter 无副作用。
- 已知边界：C#/.NET 与 Ruby 无独立审计手册（库内暂无）——按 playbook「规则降级」
  （通用模式兜底）执行；移动端反编译审计用 java-audit/java-decompile-strategy.md（CFR）
  + audit-playbook「移动端/小程序反编译审计」章；解包/脱壳产物经生态规则交 binary-analysis。

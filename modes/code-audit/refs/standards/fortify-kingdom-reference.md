# Fortify 分类学参照（静态审计标准参考 · 内置版）

> 本文档是本预设的**标准参考实体**：code-audit 的「Rule baseline」引用本文档做漏洞分类、
> CWE 映射与定级，不依赖任何本机/外部 Fortify 安装。随预设打包分发，任何机器可用。
> 外部安装的 Fortify 只能作为**增强参照**，缺失不影响标准参考。

## 来源与边界

- 分类学结构源自 Fortify Taxonomy（《Seven Pernicious Kingdoms》，Gary McGraw / Katrina
  Tsipenyuk / Chess & West 等公开体系）与 Fortify Software Security 分类惯例——这是
  Fortify 规则库的组织方式（公开知识），本文档是其可读化映射，**不是** Fortify 规则文件
  的拷贝（规则本体是编译产物且属 OpenText 版权，本预设不收录）。
- CWE 映射取自 MITRE CWE 公开目录；OWASP 列取自 OWASP Top 10:2021/2025 公开资料。
- 定级指南为工程通用原则（可利用性 × 影响），非 Fortify 私有评分。

## 八王国（Fortify Taxonomy: 7 Kingdoms + Environment）

| # | Kingdom | 核心问题 | 典型类别（sink 面） | CWE 映射 | OWASP |
|---|---|---|---|---|---|
| 1 | **Input Validation and Representation**（输入验证与表示） | 未验证/未规范化输入进入危险操作 | SQLi、命令注入、XSS、路径穿越、XXE、SSTI、LDAP/XPATH 注入、格式串 | CWE-89/78/79/22/611/94/90/134 | A03 |
| 2 | **API Abuse**（API 误用） | 调用方违反 API 契约 | 随机数误用、DNS 不验证、文件权限误设、反射滥用 | CWE-330/350/732 | A02/A04 |
| 3 | **Security Features**（安全特性） | 认证/授权/加密/机密管理的实现缺陷 | 弱加密、弱哈希、硬编码口令、缺认证、越权、证书校验缺失 | CWE-798/287/862/327/295 | A01/A02/A07 |
| 4 | **Time and State**（时间与状态） | 并发/共享状态的竞态 | TOCTOU、竞态条件、会话固定 | CWE-367/362/384 | A01/A04 |
| 5 | **Error Handling**（错误处理） | 错误路径泄露信息或吞掉异常 | 信息泄露、错误吞没、空指针 | CWE-209/391/476 | A05 |
| 6 | **Code Quality**（代码质量） | 劣质实现引入可利用面 | 空指针解引用、资源泄漏、不完整清理 | CWE-476/404 | — |
| 7 | **Encapsulation**（封装） | 信任边界被穿透 | 不安全的反序列化、信息泄露（成员/日志）、可克隆性 | CWE-502/200/498 | A08 |
| 8 | **Environment**（环境） | 外部依赖/配置引入风险 | 不安全配置、依赖漏洞、容器/K8s 配置、供应链 | CWE-16/1104/1395 | A05/A06 |

## 与本预设手册的对应（按 kingdom 找审计手册）

| Kingdom | refs/ 内手册 |
|---|---|
| 1 Input Validation | `lang/java-audit/`（java-sql-audit / java-xxe-audit / java-file-read-audit 等）、`lang/php-audit/`（php-sql-audit / php-cmd-audit / php-tpl-audit 等） |
| 3 Security Features | `lang/java-audit/java-auth-audit.md`、`lang/php-audit/php-auth-audit.md`、`crypto/crypto-implementation.md` |
| 4 Time and State | 语言手册中的竞态节；审计要点见 `methodology/evidence-first-audit.md` |
| 5 Error Handling | 语言手册错误处理节；`lang/php-audit/php-logging-audit.md` |
| 7 Encapsulation | `lang/java-audit/java-file-upload-audit.md`（反序列化段）、`components/`（fastjson/shiro 等反序列化组件） |
| 8 Environment | `config/container-security-scanning.md`、`kubernetes-security.md`、`sca/` 四篇 |
| LLM Agent 应用（独立参照系） | `ai/ai-agent-safety.md` + OWASP Agentic Top 10 (2026) |

## 定级指南（Evidence-based，禁叙事性定级）

| 级别 | 判据 | 示例 |
|---|---|---|
| **Critical / 严重** | 无需交互、可直接造成远程代码执行/数据全量泄露，或影响证明级 | 未认证 SQLi→RCE、硬编码云 AK/SK、反序列化 RCE |
| **High / 高危** | 需少量前提（已认证/特定组件）的 RCE/越权到敏感数据/关键逻辑绕过 | 后台 SSTI、水平越权到任意用户、JWT 密钥硬编码 |
| **Medium / 中危** | 信息泄露、需复杂利用链、影响范围受限 | 版本泄露、低敏 XSS、弱加密算法 |
| **Low / 低危** | 理论面/最佳实践偏离，无直接利用 | 资源未释放、缺安全头 |

- 定级与 persona 验证等级挂钩：**疑似不评级**；已触发未利用降一档；完整利用链/影响证明
  才可按上表定级。同一条链既有静态证据又有动态证据时以动态为准。

## 使用方式（SOP）

1. 审计前置识别后，按语言取对应 sink 清单（见各语言手册）；
2. 每个候选 finding 落到上表 kingdom → 确认 sink 类别 → 查对应手册深审；
3. 报告「漏洞等级」按定级指南 + 验证等级共同判定；
4. 本机若有 Fortify 安装，可用其跑分作为**交叉参照**（绝不调用、绝不写死路径）；
   无安装时本文档即完整标准参考——**标准参考缺失不算阻断**。

## 配套规则知识库（chanzi-rules，同目录）

- `standards/chanzi-rules/`：122 条 Java 生态漏洞规则知识（SQLi/SSRF/SSTI/XXE/XSS/反序列化/
  代码执行/命令注入/越权/上传/弱口令/硬编码等 20 类），每条含**关键 sink API 清单** +
  **中文漏洞详解**（本质/触发场景/危险与安全 API 对比/示例代码），提取自 ChanziSAST 规则库。
- 用法：先读 `chanzi-rules/INDEX.md` 按类别定位，再 read 具体规则文件；
  其 sink 清单与各语言手册（php-sink-reference 等）互为印证，命中即按本文档定级。
- 与可执行规则的边界：chanzi 规则是**语义知识**（cypher 查询引擎依赖，不可离线重放）；
  可执行的扫描规则在 `lang/java-audit/semgrep-rules/`、`lang/php-audit/semgrep-rules/`
  与 `standards/semgrep-oss/`（开源规则集 1080 条：semgrep-rules 788〔LGPL-2.1+Commons Clause 合规快照〕
  + trailofbits 120〔AGPL-3.0〕 + gitleaks 厂商密钥 172；全量 semgrep --validate 通过——见其 README）。

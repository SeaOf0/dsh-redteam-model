---
name: audit-trends-2025-2026
description: 2025–2026 代码审计侧趋势速览（2026-08 联网核实）：OWASP Top 10:2025 审计含义、OWASP Agentic Top 10 2026（ASI01-04）、LLM Top 10 2026、SEC-bench/SEC-bench Pro 等自测基准、MCP server 审计工具。全部条目附来源。
---

# 2025–2026 代码审计趋势速览（code-audit 侧）

> 本文件为自建综述，条目均于 2026-08-16 联网核实，附来源。
> 用途：开审前校准标准参照与测试面；与 refs/ 各手册配合（手册是方法本体，这里是风向）。

## 1. OWASP Top 10:2025 的审计含义（2025-11 发布）

- 官方：https://owasp.org/Top10/2025/en/
- 新增 **A03 Software Supply Chain Failures**（供应链失败）与
  **A10 Mishandling of Exceptional Conditions**（异常条件处理不当）；
  **Security Misconfiguration 升至第 2**；取向从症状转**根因**。
- **审计落点**：
  - 供应链 → sca/ 三篇（SBOM→osv-scanner→版本核对）成为一级审计章；
  - 异常处理 → 错误路径/降级逻辑/异常分支的 sink 与信息泄露是新增检查面
    （catch 块中的 SQL/命令执行、异常堆栈回显、失败放行逻辑）；
  - 配置 → config/ 两篇（容器/K8s）权重上调。

## 2. OWASP Top 10 for Agentic Applications 2026（已发布，核实）

- 官方入口：https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
- 条目（ASI 编号，多份分析交叉确认）：**ASI01 Agent Goal Hijack、
  ASI02 Tool Misuse & Exploitation、ASI03 Identity & Privilege Abuse、
  ASI04 Insecure Inter-Agent Communication**，另有供应链、不安全代码执行、
  rogue agents、级联失败等。
- 分析参考：Cycode（https://cycode.com/blog/owasp-top-10-agentic-applications/）、
  Modulos（https://docs.modulos.ai/frameworks/owasp-top-10-agentic）、
  Auth0（https://auth0.com/blog/owasp-top-10-agentic-applications-lessons/）。
- **审计落点**：LLM Agent 应用审计的 checklist 锚点（与 audit-playbook 既定的
  Agentic Top 10 参照一致）——工具权限声明 vs 实际能力、agent 间通信的信任边界、
  目标可劫持性（外部输入进 goal/plan）、身份与权限传递链。配合 ai/ 六篇。

## 3. LLM Top 10 的 2026 版

- OWASP GenAI LLM Top 10 有 2026 伴随更新：
  https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
- 审计侧与 2025 版差异不大（提示注入仍居首）；系统提示词泄露、RAG/向量库弱点
  的代码侧检查点见 refs/ai/。

## 4. 自测基准（对齐 PROGRESS 下一步⑥）

- **SEC-bench**（NeurIPS 2025）：自动化评测 LLM agent 于真实 CVE 代码库
  （含可复现 PoC 与验证过的补丁），集成 CodeQL。
  https://github.com/SEC-bench/SEC-bench ｜ https://www.alphaxiv.org/abs/2506.11791
- **SEC-bench Pro**：扩展版——以**长程代码审计**（而非 fuzz 驱动测试）衡量
  漏洞发现能力，正对本模式的审计定位。arXiv：https://arxiv.org/html/2605.26548v1
- 相关：CVE-Bench（NAACL 2025，漏洞修复）、SecureAgentBench（安全代码生成）。
- **用法**：模式能力自测用（基准自测待办）；审计任务中不作运行时依赖。

## 5. MCP server 代码审计工具链

- **MCP-Scan（Invariant Labs）**：检测工具描述投毒（Tool Poisoning），
  inspect/proxy 模式，可 hash 固定进 CI。https://invariantlabs.ai/blog/introducing-mcp-scan
- arXiv 2506.13538：MCP server 安全与可维护性系统研究。https://arxiv.org/html/2506.13538v5
- **审计落点**：审计 MCP server / agent 应用时，工具描述与指令流的注入面是
  一级检查项（配合 ai/ai-agent-safety.md）。

## 来源清单（2026-08-16 核实）

- OWASP Top 10:2025：https://owasp.org/Top10/2025/en/
- OWASP Agentic Top 10 2026：https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
- OWASP LLM Top 10 2026：https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
- SEC-bench：https://github.com/SEC-bench/SEC-bench ｜ https://www.alphaxiv.org/abs/2506.11791
- SEC-bench Pro：https://arxiv.org/html/2605.26548v1
- MCP-Scan：https://invariantlabs.ai/blog/introducing-mcp-scan


## 2026-08 组件 CVE 速查（先知/补天社区核源）

> 本轮（2026-08）社区调研沉淀：审计/指纹命中下列组件时按下表复查版本窗口；细节与利用见各模式 refs。

| CVE/主题 | 组件 | 版本窗口 | 要点 | 来源 |
|---|---|---|---|---|
| CVE-2026-61835/61836 | Directus | <12.0.0 全中；12.0-12.2 仍有 import 盲区 | SSRF 0.0.0.0 绕过 + 缓存权限归约（user null 共享）；deny list 默认不含私网 | xz.aliyun.com/news/92635 |
| Milvus 三洞（64513/26190/53100） | Milvus | <2.6.10；2.6.5 最尴尬（修一留二） | sourceid 后门头/9091 /expr 弱 token/53100 无认证 | xz.aliyun.com/news/92652 |
| CVE-2026-41844/41843/22731 | Spring 系 | 见补天浅析 | 开放重定向/路径遍历/Actuator 认证绕过 | forum.butian.net/share/4951/4953/4957 |
| fastjson 1.2.83 复活链 | fastjson1 ≤1.2.83 | 全窗口 | jar:http + /proc/self/fd 爆破（无 gadget 依赖）→ 见 components/fastjson.md §2.10 | forum.butian.net/share/5001 |
| fastjson2 TypeReference 绕过 | fastjson2（2.0.43/51 实测） | safeMode 开启也中 | Type 入口六层无 checkAutoType + cache 抢跑 → §2.11 | forum.butian.net/share/5005 |
| CVE-2026-59692 | GStreamer | 见分析 | DTLS 握手栈溢出（binary 模式深析） | xz.aliyun.com/news/92679 |
| CVE-2026-42945 | NGINX | 18 年窗口 | Rift 堆溢出 RCE（binary 模式深析） | forum.butian.net/share/4982 |
| CVE-2026-40369 | Windows 内核 | Win11 25H2 仍在 | ProbeForWrite Length=0（binary/攻防提权面） | forum.butian.net/share/4958 |
| CVE-2026-62737 | Windows 11 | 25H2 最新版 | ExecutionContext.sys 0day 内核提权（原创挖掘思路篇） | xz.aliyun.com/news/92658 |
| CVE-2026-45623 | PostCSS | 前端构建链 | 一行 CSS 注释起的攻击链（供应链面） | xz.aliyun.com/news/92653 |
| Langflow 双 RCE | Langflow 1.9.0 | CVSS 9.6×2 | AI 编排框架（pentest refs/ai-infra） | forum.butian.net/share/4968 |
| Containerd checkpoint | containerd | 2026 | 容器运行时检查点逃逸 | forum.butian.net/share/4954 |
| MariaDB RCE | MariaDB | 见复现 | 远程代码执行分析与复现 | xz.aliyun.com/news/92636 |

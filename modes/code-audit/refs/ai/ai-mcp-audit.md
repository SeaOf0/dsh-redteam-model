---
name: ai-mcp-audit
description: MCP（Model Context Protocol）生态安全审计专项。工具描述投毒（Tool Poisoning）/资源投毒（resources/templates）的可执行审计方法：MCP-Scan inspect/proxy、MCP-Shield、mcp-audit + Semgrep 分层静态审计；MCP 配置审计清单（明文密钥/权限过大/工具滥用入口）。配合 ai-agent-safety.md 主手册。
---

# MCP 生态安全审计（ai-mcp-audit）

> 定位：`ai-agent-safety.md` 是 Agent/MCP 架构审计主手册（攻击面 + 加固），本篇把
> 「工具描述投毒 / 资源投毒」补成**可执行审计方法**——分层静态扫描 + 配置手工检查。
> 依据 OWASP Agentic Top 10 (2026) 的 ASI02（工具滥用）与供应链视角。

## 0. 攻击面速览（入口识别）

| 攻击面 | 描述 | 审计点 |
|--------|------|--------|
| 工具描述投毒（Tool Poisoning） | MCP server 的工具 description 中藏指令，诱导 agent 执行恶意动作 | 工具 description/annotations 是否含隐藏指令 |
| 资源投毒（Resource Poisoning） | resources/templates/prompts 返回的内容含诱导/恶意指令 | 资源内容是否被当成可信输入 |
| 同名工具覆盖 | 恶意 server 注册同名工具覆盖合法工具 | 工具名冲突/优先级 |
| 明文密钥 | MCP client 配置里明文存储 API key/token | `mcpServers` 配置项 |
| 权限过大 | server 声明能力远超业务所需（文件读写/命令执行） | 工具清单 vs 最小权限 |

## 1. 分层静态审计（入口识别 → 危险模式 → 验证）

### 1.1 MCP-Scan（工具描述投毒检测）

> MCP-Scan（Invariant Labs）：<https://invariantlabs.ai/blog/introducing-mcp-scan> ｜
> PyPI `mcp-scan`。可 hash 固定进 CI。

```bash
# 安装
pip install mcp-scan

# inspect 模式：静态扫描 MCP server 源码，检测工具描述中的投毒/隐藏指令
mcp-scan inspect <path-to-mcp-server>

# proxy 模式：代理 MCP 流量，动态检测工具描述注入
mcp-scan proxy --config <mcp-client-config.json>

# 输出：投毒命中（工具描述含可疑指令、覆盖、混淆）→ 人工复核
```

### 1.2 MCP-Shield（工具投毒/隐藏指令扫描）

> MCP-Shield：<https://arxiv.org/html/2604.07551>（工具投毒/隐藏指令扫描）。

- 定位：对 MCP server 的工具描述与资源做隐藏指令/注入扫描；
- 用法：作为静态分析补充（与 MCP-Scan inspect 互补），关注「描述中夹带系统提示词/越权指令」。

### 1.3 mcp-audit + Semgrep 分层

> 分层方法论（FreeBuf）：<https://www.freebuf.com/articles/others-articles/489211.html>

```
第 1 层：mcp-scan inspect      —— 工具描述投毒/隐藏指令（MCP 语义层）
第 2 层：mcp-audit             —— MCP server 通用安全审计（协议/权限/配置）
第 3 层：Semgrep（自定义规则）—— server 源码的语言级 sink（命令执行/文件写/网络外连）
```

**Semgrep 自定义规则示例（MCP server 源码危险 sink）：**

```yaml
rules:
  - id: mcp-tool-description-suspicious
    languages: [python]
    severity: WARNING
    message: "MCP 工具描述可能包含隐藏指令（工具投毒面）"
    patterns:
      - pattern-either:
          - pattern: |
              @mcp.tool(...)
              def $F(...): ...
          - pattern: |
              Tool(name=..., description=$D, ...)
      - metavariable-regex:
          metavariable: $D
          regex: (?i)(ignore|override|system prompt|execute|curl|wget|secret|api[_-]?key)
    metadata:
      category: security
      cwe: "CWE-1039"

  - id: mcp-server-command-exec
    languages: [python]
    severity: ERROR
    message: "MCP 工具内执行命令，需核对是否权限过大"
    pattern-either:
      - pattern: os.system(...)
      - pattern: subprocess.run(..., shell=True, ...)
      - pattern: eval(...)
      - pattern: exec(...)
    metadata:
      category: security
      cwe: "CWE-78"
```

## 2. MCP 配置审计清单（手工检查，必做）

1. **明文密钥**：`mcpServers.<name>.env` / headers 中是否有明文 API key/token；
   应走密钥托管（环境变量引用/secret manager）。
2. **权限过大**：server 声明的工具是否含文件读写/命令执行/网络外连，且业务不必要；
   对照最小权限原则。
3. **工具滥用入口**：工具描述/参数是否允许任意 URL、任意命令、任意文件路径（`url`/`cmd`/
   `path` 参数无白名单）。
4. **同名工具覆盖**：多 server 是否注册同名工具，agent 的调用优先级是否可被投毒覆盖。
5. **来源与签名**：MCP server 的安装来源/版本/SBOM 是否可验证（供应链投毒面）。
6. **资源投毒**：server 提供的 resources/templates 是否含诱导性内容（会被 agent 当可信数据）。

### 2.1 配置审计 grep

```bash
# mcpServers 配置中的明文密钥/URL
grep -rniE 'api[_-]?key|token|secret|authorization|bearer' <mcp-config.json> <*.mcp.json> 2>/dev/null

# 工具声明中可疑的任意执行参数
grep -rniE 'description.*(ignore|execute|curl|wget|system|secret|override)' --include='*.py' --include='*.ts' --include='*.js' .
```

## 3. 审计结论模板（强制三要素）

每条 MCP 审计 finding 必须给：
1. **入口**：哪个 MCP server / 哪个工具 / 哪条配置（server 名 + 工具名 + 行号）；
2. **危险模式**：工具描述投毒 / 资源投毒 / 明文密钥 / 权限过大 / 同名覆盖；
3. **验证方法**：mcp-scan inspect/proxy 命中、Semgrep 命中、配置项证据。

## 4. 修复建议（按层）

1. **工具描述/资源**：对 MCP server 的工具描述与资源内容做投毒扫描（MCP-Scan/MCP-Shield），
   描述视为**不可信内容**不进入 agent 指令流。
2. **配置**：密钥走 secret manager；工具权限最小化；禁用不必要的能力。
3. **来源**：MCP server 固定版本 + 签名/SBOM 验证；工具名冲突检测。
4. **运行**：agent 对 MCP 工具调用加「工具白名单 + 敏感操作需人工确认」。

## 来源

- MCP-Scan（Invariant Labs）：<https://invariantlabs.ai/blog/introducing-mcp-scan>
- MCP-Shield：<https://arxiv.org/html/2604.07551>
- MCP server 安全系统研究：<https://arxiv.org/html/2506.13538v5>
- 分层静态审计方法论（FreeBuf）：<https://www.freebuf.com/articles/others-articles/489211.html>

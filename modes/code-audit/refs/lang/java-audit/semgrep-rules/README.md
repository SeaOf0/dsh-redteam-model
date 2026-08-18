# Semgrep Rules for Java Security Audit

本目录包含 Java 代码安全审计的 Semgrep 规则，对应 Java Audit Skill 的 Phase 4 输出。

## 规则文件

| 文件 | 风险等级 | 规则数 | 覆盖漏洞 |
|------|----------|--------|----------|
| `java-rce.yaml` | P0 (Critical) | 21 | 反序列化、SSTI、表达式注入、JNDI注入、命令注入 |
| `java-sqli.yaml` | P1 (High) | 11 | SQL 注入、MyBatis `${}` 注入、JPA/HQL 注入 |
| `java-ssrf.yaml` | P1 (High) | 8 | SSRF (URL、HttpClient、RestTemplate、WebClient) |
| `java-file.yaml` | P1 (High) | 14 | 路径遍历、任意文件读写/删除、文件上传 |
| `java-crypto.yaml` | P2 (Medium) | 8 | 弱加密算法、弱哈希算法、不安全随机数、硬编码密钥 |
| `java-misc.yaml` | P1/P2 | 51 | XXE、XSS、认证授权、会话安全、日志安全、开放重定向、LDAP注入 |
| `java-config.yaml` | P0/P1/P2 | 101 | Log4j2、Spring Security、Actuator、Shiro、Swagger、Druid、Fastjson、Nacos、JWT、H2 |
| `java-microservice.yaml` | P0/P1/P2 | 39 | Feign、Gateway、Dubbo、gRPC、NoSQL注入、数据库安全、OWASP Top 10 |
| `java-api-security.yaml` | P1/P2 | 42 | API 安全、输入验证、敏感数据处理、异常处理、重定向安全 |
| `java-emerging.yaml` | P0/P1/P2 | 33 | LLM/AI 安全、GraphQL、Kotlin 特有漏洞、Java 21、并发安全 |
| `js-security.yaml` | P0/P1/P2 | 22 | JS/TS XSS（innerHTML/document.write/eval）、动态代码执行、原型污染、JSON.parse 用户输入 |
| `react-security.yaml` | P0/P1 | 14 | dangerouslySetInnerHTML XSS、href 注入、jsx-no-bind、危险链接 |
| `vue-security.yaml` | P0/P1 | 18 | v-html XSS、动态组件、模板注入、危险 href |
| `frontend-config.yaml` | P1/P2 | 20 | CORS 通配、CSP 配置错误、API Key/Secret/口令硬编码、Nginx 信息泄露与弱 SSL（generic 语言匹配 .conf/.json/.yaml） |

**总计**: 402 条规则（实测校验；含修复后的 4 个前端规则文件）

> 规则修复记录：js-security / react-security / vue-security / frontend-config
> 四文件曾因 YAML 转义与 pattern 语法问题无法被 semgrep 加载（单引号标量内嵌 `'` 未转义、
> 裸 `{{ }}` 流式标量、`where ... is string` 非 semgrep 语法、`languages: [nginx]` 不受支持），
> 现已全部通过 `semgrep --validate`，14 个文件可直接 `semgrep --config` 挂载。

## 使用方法

### 安装 Semgrep

```bash
# macOS
brew install semgrep

# Linux
pip install semgrep

# Windows (PowerShell)
pip install semgrep
```

**Windows 用户验证安装**：

```powershell
semgrep --version
```

### 扫描项目

**Windows (PowerShell)**:

```powershell
# 设置 UTF-8 编码（Windows 必须）
$env:PYTHONUTF8=1

# 扫描所有规则
semgrep --config rules\semgrep\ C:\Projects\myapp --no-git-ignore

# 扫描单个规则文件
semgrep --config rules\semgrep\java-rce.yaml C:\Projects\myapp --no-git-ignore

# 只显示 ERROR 级别
semgrep --config rules\semgrep\ C:\Projects\myapp --no-git-ignore --severity ERROR

# 输出 JSON 格式
semgrep --config rules\semgrep\ C:\Projects\myapp --no-git-ignore --json > results.json

# 输出 SARIF 格式 (用于 GitHub Code Scanning)
semgrep --config rules\semgrep\ C:\Projects\myapp --no-git-ignore --sarif > results.sarif
```

**Linux/macOS (Bash)**:

```bash
# 扫描所有规则
semgrep --config rules/semgrep/ /path/to/project --no-git-ignore

# 只显示 ERROR 级别
semgrep --config rules/semgrep/ /path/to/project --no-git-ignore --severity ERROR
```

### CI/CD 集成

```yaml
# GitHub Actions 示例
name: Security Audit
on: [push, pull_request]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: returntocorp/semgrep-action@v1
        with:
          config: ./rules/semgrep/
```

## 规则优先级

| 严重程度 | 说明 | 响应时效 |
|----------|------|----------|
| ERROR | 确认存在漏洞，需立即修复 | 24h 内 |
| WARNING | 疑似漏洞或潜在风险，需人工确认 | 7 天内 |

## 快速速查表

| 组件 | 安全版本 | 备注 |
|------|----------|------|
| Log4j2 | ≥ 2.17.1 | Log4Shell |
| Fastjson | ≥ 1.2.83 | 反序列化 |
| Spring Framework | ≥ 5.3.33 | Spring4Shell |
| Shiro | ≥ 1.13.0 | 认证绕过 |
| Tomcat | ≥ 9.0.62 | Ghostcat |

详见 [cve-offline-lookup.md](../../references/cve-offline-lookup.md)
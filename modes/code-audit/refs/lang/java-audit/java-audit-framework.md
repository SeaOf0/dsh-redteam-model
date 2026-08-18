---
name: java-audit-skill
description: |
  AI驱动的Java/前端代码安全审计技能，实现系统化、高覆盖率的漏洞挖掘。使用场景：
  (1) 审计Java/Kotlin项目寻找安全漏洞（0day挖掘、代码审计、安全评估）
  (2) 审计前端项目（JavaScript/TypeScript/React/Vue）寻找安全漏洞
  (3) 企业级代码库的安全审计（支持大型项目）
  (4) 需要高质量、低幻觉率的安全审计报告
  (5) CI/CD集成的前期漏洞发现
  触发关键词：Java审计、代码审计、安全审计、漏洞挖掘、0day、安全评估、前端审计、React审计、Vue审计、Java security audit、code review for security
---

# AI+Java/前端 代码审计 Skill

本 Skill 将资深审计员的工作方法和质量标准编码成 LLM 可执行的协议，解决裸跑 LLM 覆盖率低、幻觉高、优先级混乱等核心痛点。

## 支持的语言类型

| 语言类型 | 框架支持 | 主要检查内容 |
|----------|----------|--------------|
| **Java/Kotlin** | Spring、Spring Boot、Struts、Jersey、Dubbo、gRPC | 反序列化、SQL注入、命令执行、认证绕过、SSRF、文件操作 |
| **JavaScript/TypeScript** | 原生、Node.js | XSS、代码注入、原型污染、敏感信息泄露 |
| **React** | React 16+、Next.js | dangerouslySetInnerHTML、href注入、SSR XSS |
| **Vue** | Vue 2/3、Nuxt.js | v-html XSS、模板注入、不安全渲染 |
| **混合项目** | 前后端分离 | 后端API安全 + 前端XSS/配置安全 |

## 脚本架构

**⚠️ 重要：脚本已按语言类型拆分，职责清晰**

```
scripts/
├── audit.py              # 通用入口（语言检测 + 路由分发）
├── java_audit.py         # Java/Kotlin 后端审计
└── frontend_audit.py     # JavaScript/React/Vue 前端审计
```

### 脚本职责

| 脚本 | 职责 | 包含功能 |
|------|------|----------|
| **audit.py** | 通用入口 | 语言检测、路由分发、统一参数解析 |
| **java_audit.py** | Java 审计 | Java Tier 分类、Java 危险模式、EALOC 计算、覆盖率检查 |
| **frontend_audit.py** | 前端审计 | 前端 Tier 分类、前端危险模式、依赖检查、配置安全 |

### 调用流程

```
用户执行: python audit.py /path/to/project --scan --tier
                    ↓
              [audit.py]
                    ↓
         语言检测: detect_project_language()
                    ↓
    ┌───────────────┼───────────────┐
    │               │               │
  java          react/vue      mixed
    │               │               │
    ↓               ↓               ↓
[java_audit.py] [frontend_audit.py] [两者都执行]
```

### 使用方法

```bash
# 自动检测语言并执行审计
python scripts/audit.py /path/to/project --scan --tier

# Java 项目审计（直接调用）
python scripts/java_audit.py /path/to/java-project --scan --tier

# 前端项目审计（直接调用）
python scripts/frontend_audit.py /path/to/frontend-project --language react --scan --tier
```

## 核心理念

**LLM 有能力，缺纪律。** Skill 不教 LLM "什么是 SQL 注入"，而是给它装上资深审计员的工作骨架——定义工作流、分配资源、设置护栏、标准化输出。

## 6 阶段审计流水线

```
Phase 0 → Phase 1 → Phase 2 → Phase 2.5 → Phase 3 → Phase 5 → Phase 4（可选）
 代码度量   项目侦察   多层审计   覆盖率门禁  漏洞验证  标准化报告   规则沉淀
```

每个 Phase 有明确的输入、输出和质量标准，中间结果全量持久化到文件。

**⚠️ Phase 编号说明**：

- Phase 0-3：核心审计流程（必须执行）
- Phase 5：标准化报告（在验证后生成）
- **Phase 4：规则沉淀（可选，在报告后执行）**

Phase 4 放在最后的原因：规则沉淀基于**最终确认的漏洞**（Phase 3 输出），且需要完整的报告（Phase 5 输出）作为参考。

---

## Phase 0: 代码库度量

**目标**: 统计项目规模，计算审计工作量，为 Agent 分配提供依据。

### 语言检测（新增）

**⚠️ 在开始审计前，必须先检测项目语言类型**：

```bash
# 执行语言检测
python scripts/java_audit.py /path/to/project --detect-lang
```

**检测结果决定审计流程**：

| 语言类型 | 审计流程 | Semgrep 规则集 |
|----------|----------|----------------|
| **java** | Java 后端审计流程 | java-rce.yaml, java-config.yaml, java-sqli.yaml |
| **javascript** | 前端通用审计流程 | js-security.yaml, frontend-config.yaml |
| **react** | React 审计流程 | react-security.yaml, js-security.yaml |
| **vue** | Vue 审计流程 | vue-security.yaml, js-security.yaml |
| **mixed** | 前后端分离审计流程 | Java 规则 + 前端规则 |

**语言检测逻辑**：

```
1. 统计文件扩展名：
   - .java/.kt → Java/Kotlin
   - .js/.ts/.jsx/.tsx/.vue → 前端

2. 检测框架特征：
   - pom.xml/build.gradle → Java 项目
   - package.json → 前端项目
   - react/vue 依赖 → React/Vue 项目

3. 判断项目类型：
   - 纯 Java/Kotlin → java
   - 纯前端 → javascript/react/vue
   - 前后端分离 → mixed
```

### 执行脚本

**Linux/macOS (Bash):**

```bash
# 统计代码行数和文件数（注意括号）
find . \( -name "*.java" -o -name "*.kt" -o -name "*.xml" \) | xargs wc -l | tail -1

# 统计各类型文件
find . -name "*.java" | wc -l
find . -name "*.kt" | wc -l
find . -name "*.xml" | wc -l

# 统计 Controller/入口点数量（多种框架）
# 入口点定义详见 Phase 1 Tier 分类规则 Rule 2

# Spring MVC
grep -r "@Controller\|@RestController" --include="*.java" | wc -l

# 原生 Servlet
grep -r "@WebServlet\|extends HttpServlet\|implements Servlet" --include="*.java" | wc -l

# Struts Action
grep -r "extends ActionSupport\|implements Action\|@Action" --include="*.java" | wc -l

# Filter（也是 T1 级文件）
grep -r "@WebFilter\|implements Filter\|extends OncePerRequestFilter" --include="*.java" | wc -l

# 统计模块数（Maven 多模块项目）
find . -name "pom.xml" | wc -l

# 统计模块数（Gradle 多模块项目）
find . -name "build.gradle" -o -name "build.gradle.kts" | wc -l
```

**Windows (PowerShell):**

```powershell
# 统计代码行数和文件数
Get-ChildItem -Recurse -Include *.java,*.kt,*.xml | Measure-Object -Property Length -Sum

# 统计各类型文件数
(Get-ChildItem -Recurse -Filter *.java).Count
(Get-ChildItem -Recurse -Filter *.kt).Count
(Get-ChildItem -Recurse -Filter *.xml).Count

# 统计 Controller/入口点数量（多种框架）
# Spring MVC
Select-String -Path (Get-ChildItem -Recurse -Filter *.java).FullName -Pattern "@Controller|@RestController" | Measure-Object | Select-Object -ExpandProperty Count

# 原生 Servlet
Select-String -Path (Get-ChildItem -Recurse -Filter *.java).FullName -Pattern "@WebServlet|extends HttpServlet|implements Servlet" | Measure-Object | Select-Object -ExpandProperty Count

# Struts Action
Select-String -Path (Get-ChildItem -Recurse -Filter *.java).FullName -Pattern "extends ActionSupport|implements Action|@Action" | Measure-Object | Select-Object -ExpandProperty Count

# Filter（也是 T1 级文件）
Select-String -Path (Get-ChildItem -Recurse -Filter *.java).FullName -Pattern "@WebFilter|implements Filter|extends OncePerRequestFilter" | Measure-Object | Select-Object -ExpandProperty Count

# 统计模块数（Maven）
(Get-ChildItem -Recurse -Filter pom.xml).Count

# 统计模块数（Gradle）
(Get-ChildItem -Recurse -Include build.gradle,build.gradle.kts).Count
```

### 输出文件: `audit-metrics.json`

```json
{
  "total_loc": 131000,
  "java_files": 847,
  "kt_files": 0,
  "xml_files": 156,
  "controllers": 40,
  "modules": 5,
  "t1_loc": 14000,
  "t2_loc": 30000,
  "t3_loc": 87000,
  "ealoc": 37700,
  "project_size": "中型",
  "coverage_requirement": "95%",
  "build_system": "maven"
}
```

### EALOC 计算

EALOC（Effective Audit Lines of Code）在 Phase 0 计算，用于判断项目规模和后续执行策略：

```
EALOC = T1_LOC × 1.0 + T2_LOC × 0.5 + T3_LOC × 0.1
```

| 项目规模 | EALOC | 覆盖率要求 | 执行策略 |
|----------|-------|------------|----------|
| 小型 | < 15,000 | 100% | 单会话完成，可简化流程 |
| 中型 | 15,000 - 50,000 | 95% | 按模块拆分 |
| 大型 | > 50,000 | 90% | 必须拆分多 Agent |

**Tier 分类规则**（用于 EALOC 计算）：

| Tier | 文件类型 | 权重 |
|------|----------|------|
| T1 | Controller、Filter、Servlet、Action | × 1.0 |
| T2 | Service、DAO、Util、配置文件 | × 0.5 |
| T3 | Entity、VO、DTO | × 0.1 |

**使用 Python 脚本可生成更多输出**：

```bash
# 度量 + Tier 分类
python scripts/java_audit.py /path/to/project --tier

# 度量 + 场景标签（Phase 1）
python scripts/java_audit.py /path/to/project --scenario

# 度量 + Layer 1 预扫描
python scripts/java_audit.py /path/to/project --scan
```

**可生成的输出文件**：
- `audit-metrics.json` - 项目度量数据
- `tier-classification.md` - Tier 分类报告（--tier）
- `scenario-tags.json` - API 场景标签（--scenario，Phase 1）
- `p0-critical.md`, `p1-high.md`, `p2-medium.md` - Layer 1 扫描报告（--scan）
- `coverage-report.md` - 覆盖率验证报告（--coverage）

---

## Phase 1: 项目侦察 & EALOC 资源分配

### 1.1 业务场景标签

**核心理念**：不是所有 API 都需要深度审计。通过业务场景标签快速识别高风险 API，精准分配审计资源。

#### 场景类型分类

| 场景类型 | 典型 API | 默认风险等级 | 重点检查 |
|----------|----------|-------------|----------|
| **FINANCIAL_TRANSACTION** | 支付、退款、转账 | CRITICAL | 金额篡改、并发竞争、状态机绕过 |
| **PRIVILEGED_OPERATION** | 用户管理、系统配置 | HIGH | 垂直越权、权限绕过 |
| **RESOURCE_ALLOCATION** | 下单、抢购、预约 | HIGH | 并发竞争、库存绕过 |
| **STATE_TRANSITION** | 审批、发货、退款 | HIGH | 状态机绕过、流程跳跃 |
| **DATA_ACCESS** | 订单详情、用户列表 | MEDIUM | 水平越权、信息泄露 |
| **USER_OPERATION** | 个人资料、修改密码 | MEDIUM | 认证绕过、密码安全 |
| **PUBLIC_ACCESS** | 首页、公告、公开文章 | LOW | XSS、SSRF（可快速模式） |

#### 自动识别脚本

**Linux/macOS (Bash):**

```bash
# 识别资金交易接口
grep -rn "pay\|payment\|refund\|transfer\|withdraw" --include="*.java" --include="*.kt" | grep -i "mapping"

# 识别特权操作接口
grep -rn "@PreAuthorize.*ADMIN\|@Secured.*ADMIN\|hasRole.*ADMIN" --include="*.java" --include="*.kt"

# 识别公开访问接口
grep -rn "permitAll\|anonymous" --include="*.java" --include="*.kt"
```

**Windows (PowerShell):**

```powershell
# 识别资金交易接口
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "pay|payment|refund|transfer|withdraw" | Select-String -Pattern "mapping" -CaseSensitive:$false

# 识别特权操作接口
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "@PreAuthorize.*ADMIN|@Secured.*ADMIN|hasRole.*ADMIN"

# 识别公开访问接口
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "permitAll|anonymous"
```

**详细说明**: [references/business-scenario-tags.md](references/business-scenario-tags.md)

### 1.2 Tier 分类规则

| 规则 | 条件 | Tier | 分析深度 |
|------|------|------|----------|
| Rule 0 | 第三方库源码 | SKIP | 不审计 |
| Rule 1 | Layer 1 预扫描有 P0/P1 候选项 | T1 | 动态提升 |
| Rule 2 | **入口点类**（详见下方） | T1 | 完整深度分析 |
| Rule 3 | 含 @Service/@Repository/@Mapper | T2 | 聚焦关键维度 |
| Rule 4 | 类名含 Util/Helper/Handler | T2 | 聚焦关键维度 |
| Rule 5 | .properties/.yml/security.xml | T2 | 聚焦关键维度 |
| Rule 6 | 含 @Entity/@Table/@Data | T3 | 快速模式匹配 |
| Rule 7 | 未匹配任何规则 | T2 | 保守兜底 |

#### Rule 2: 入口点类定义（T1 级文件）

入口点是接收外部 HTTP 请求的类，必须 100% 覆盖审计：

| 框架类型 | 入口点特征 | 示例 |
|----------|-----------|------|
| **Spring MVC** | @Controller, @RestController | `@RestController public class UserController` |
| **原生 Servlet** | @WebServlet, extends HttpServlet, implements Servlet | `@WebServlet("/api/user") public class UserServlet` |
| **Struts 2** | extends ActionSupport, implements Action, @Action | `public class UserAction extends ActionSupport` |
| **Filter** | @WebFilter, implements Filter, extends OncePerRequestFilter | `@WebFilter("/*") public class AuthFilter` |
| **Jersey/JAX-RS** | @Path, @Provider | `@Path("/users") public class UserResource` |
| **Play Framework** | extends Controller, extends Action | `public class UserController extends Controller` |

**扫描命令**：

```powershell
# Spring MVC
Select-String -Pattern "@Controller|@RestController"

# 原生 Servlet
Select-String -Pattern "@WebServlet|extends HttpServlet|implements Servlet"

# Struts 2
Select-String -Pattern "extends ActionSupport|implements Action|@Action"

# Filter
Select-String -Pattern "@WebFilter|implements Filter|extends OncePerRequestFilter"

# Jersey/JAX-RS
Select-String -Pattern "@Path|@Provider"

# 全部入口点
Select-String -Pattern "@Controller|@RestController|@WebServlet|extends HttpServlet|implements Servlet|extends ActionSupport|implements Action|@Action|@WebFilter|implements Filter|@Path"
```

### 1.3 EALOC 场景修正

**基础 EALOC 计算**：见 Phase 0（`EALOC = T1_LOC × 1.0 + T2_LOC × 0.5 + T3_LOC × 0.1`）

**场景修正系数**（用于高风险 API）：

| 场景 | 修正系数 | 原因 |
|------|----------|------|
| FINANCIAL_TRANSACTION（资金交易） | × 1.5 | 需要更深度审计 |
| PRIVILEGED_OPERATION（特权操作） | × 1.2 | 越权风险高 |
| RESOURCE_ALLOCATION（资源分配） | × 1.2 | 并发竞争风险 |
| STATE_TRANSITION（状态变更） | × 1.2 | 状态机绕过风险 |
| DATA_ACCESS（数据访问） | × 1.0 | 基准 |
| USER_OPERATION（用户操作） | × 1.0 | 基准 |
| PUBLIC_ACCESS（公开访问） | × 0.5 | 风险较低 |

**修正后 EALOC**：`Adjusted_EALOC = Σ (API_EALOC × Scenario_Multiplier)`

**Agent 分配**: `Agent数量 = ceil(Adjusted_EALOC / 15000)`

> **说明**：此处的 "Agent" 为概念性描述，指审计任务拆分后的独立执行单元。实际执行时：
> - **小型项目**（EALOC < 15000）：单会话完成，无需拆分
> - **中型项目**（EALOC 15000-50000）：按模块拆分，可用 `sessions_spawn` 启动子会话并行执行
> - **大型项目**（EALOC > 50000）：必须拆分，每个子任务独立输出 `findings-raw.md`，最后合并

### 1.4 依赖安全检查

**执行时机**：在 Phase 1 读取 pom.xml/build.gradle 时，同步检查依赖安全。

#### 检查流程（mvnrepository.com 联网核实）

**核心理念**：不再依赖离线规则表，直接查询 Maven 仓库官方数据，获取准确的漏洞信息。

```
Step 1: 读取 pom.xml/build.gradle 提取依赖版本
  ↓
Step 2: 构建 mvnrepository.com 查询 URL
  ↓
Step 3: 使用 tavily + web_fetch 查询组件页面
  ↓
Step 4: 检查 "Direct vulnerabilities" 标记
  ↓
Step 5: 找到无漏洞的安全版本
```

#### mvnrepository.com 查询方法

**URL 格式**：
```
https://mvnrepository.com/artifact/{groupId}/{artifactId}
```

**示例 URL**：
```
https://mvnrepository.com/artifact/org.apache.httpcomponents/httpclient
https://mvnrepository.com/artifact/com.alibaba/fastjson
https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core
https://mvnrepository.com/artifact/org.apache.shiro/shiro-core
```

**页面漏洞标记识别**：
- 有漏洞版本：显示 `Direct vulnerabilities: CVE-XXXX-XXXXX`
- 安全版本：无 `Direct vulnerabilities` 标记

#### 执行命令

**方式一：tavily 搜索定位 + web_fetch 提取**

```bash
# 1. tavily 搜索组件 mvnrepository 页面
web_search "mvnrepository {groupId} {artifactId}" -n 5

# 2. web_fetch 提取页面内容
# 使用 web_fetch 工具访问组件页面
```

**方式二：直接 web_fetch 组件页面**

```
访问 https://mvnrepository.com/artifact/{groupId}/{artifactId}

在页面内容中搜索：
- "Direct vulnerabilities" → 存在漏洞
- 无此标记 → 安全版本
```

#### ⚠️ CVE 核实铁律

1. **禁止凭记忆编造 CVE 编号或安全版本** - 必须联网核实
2. **必须使用 mvnrepository.com 官方数据** - 这是最准确的来源
3. **必须检查 "Direct vulnerabilities" 标记** - 不是间接依赖漏洞
4. **必须找到无漏洞的安全版本** - 在版本列表中寻找无标记的最新版本

#### 检查示例：httpclient 4.5.12

**Step 1**: 访问 `https://mvnrepository.com/artifact/org.apache.httpcomponents/httpclient`

**Step 2**: 检查版本列表：
- 4.5.12: `Direct vulnerabilities: CVE-2020-13956` → ❌ 有漏洞
- 4.5.13: `Direct vulnerabilities: CVE-2020-13956` → ❌ 有漏洞
- 4.5.14: 无标记 → ✅ 安全版本

**结论**: 当前版本 4.5.12 存在漏洞，建议升级到 4.5.14+

#### 高优先级检查组件

以下组件历史上频繁出现高危漏洞，**必须逐一检查**：

| 组件 | groupId | artifactId | 检查 URL |
|------|---------|------------|----------|
| Log4j2 | org.apache.logging.log4j | log4j-core | mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core |
| Fastjson | com.alibaba | fastjson | mvnrepository.com/artifact/com.alibaba/fastjson |
| Shiro | org.apache.shiro | shiro-core | mvnrepository.com/artifact/org.apache.shiro/shiro-core |
| Jackson | com.fasterxml.jackson.core | jackson-databind | mvnrepository.com/artifact/com.fasterxml.jackson.core/jackson-databind |
| HttpClient | org.apache.httpcomponents | httpclient | mvnrepository.com/artifact/org.apache.httpcomponents/httpclient |
| Netty | io.netty | netty-all | mvnrepository.com/artifact/io.netty/netty-all |
| Hessian | com.caucho | hessian | mvnrepository.com/artifact/com.caucho/hessian |
| XStream | com.thoughtworks.xstream | xstream | mvnrepository.com/artifact/com.thoughtworks.xstream/xstream |
| SnakeYAML | org.yaml | snakeyaml | mvnrepository.com/artifact/org.yaml/snakeyaml |
| Commons Collections | commons-collections | commons-collections | mvnrepository.com/artifact/commons-collections/commons-collections |
| Commons Text | org.apache.commons | commons-text | mvnrepository.com/artifact/org.apache.commons/commons-text |
| Nacos | com.alibaba.nacos | nacos-core | mvnrepository.com/artifact/com.alibaba.nacos/nacos-core |
| Dubbo | org.apache.dubbo | dubbo | mvnrepository.com/artifact/org.apache.dubbo/dubbo |

#### 输出模板：dependency-security.md

```markdown
## 依赖安全检查报告

**检查方法**：通过 mvnrepository.com 联网核实
**检查时间**：YYYY-MM-DD

| 组件 | groupId | artifactId | 当前版本 | Direct vulnerabilities | 安全版本 | 状态 |
|------|---------|------------|----------|------------------------|----------|------|
| httpclient | org.apache.httpcomponents | httpclient | 4.5.12 | CVE-2020-13956 | 4.5.14+ | ❌ 需升级 |
| log4j-core | org.apache.logging.log4j | log4j-core | 2.17.1 | 无 | - | ✅ 安全 |
| fastjson | com.alibaba | fastjson | 1.2.83 | 无 | - | ✅ 安全 |

### 详细检查记录

#### httpclient 4.5.12
- 检查 URL: https://mvnrepository.com/artifact/org.apache.httpcomponents/httpclient
- 当前版本状态: Direct vulnerabilities: CVE-2020-13956
- 安全版本: 4.5.14（无 Direct vulnerabilities 标记）
- 建议: 升级到 4.5.14+

#### log4j-core 2.17.1
- 检查 URL: https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core
- 当前版本状态: 无 Direct vulnerabilities
- 结论: 安全，无需升级
```

#### 离线环境处理

**无法联网时**：
1. 标记为 `HYPOTHESIS`：无法确认版本安全性
2. 报告备注：注明"离线环境无法确认，建议联网后复查 mvnrepository.com"
3. 保守评估：按"可能存在漏洞"处理，但不作为 CONFIRMED 漏洞

### 1.5 输出文件

- `tier-classification.md`: Tier 分类结果
- `scenario-tags.json`: API 场景标签
- `dependency-security.md`: 依赖安全检查结果

#### tier-classification.md 示例

```markdown
# Tier 分类结果

## 模块: module-biz (131,000 LOC)

| 子任务 | Agent | 文件范围 | 文件数 | Tier分布 | EALOC |
|--------|-------|---------|-------|---------|-------|
| 1a | Agent 1 | controller/ | 147 | T1: 14K | 14,000 |
| 1b | Agent 2 | service/ + dao/ | 200 | T2: 30K | 15,000 |
| 1c | Agent 3 | entity/ + vo/ | 500 | T3: 87K | 8,700 |

**总 EALOC**: 37,700 → 需要 3 个 Agent
```

---

## Phase 2: 多层审计架构

### Layer 1: 全量预扫描（不用 LLM）

使用 ripgrep + Semgrep 扫描所有文件，按 P0-P3 标记危险模式。

#### P0 级危险模式（RCE/反序列化）

**Linux/macOS (Bash):**

```bash
# 反序列化全家族（同时检查 Java 和 Kotlin 文件）
grep -rn "ObjectInputStream\|XMLDecoder\|XStream" --include="*.java" --include="*.kt"
grep -rn "JSON\.parseObject\|JSON\.parse\|@type" --include="*.java" --include="*.kt"  # Fastjson
grep -rn "enableDefaultTyping\|activateDefaultTyping" --include="*.java" --include="*.kt"  # Jackson
grep -rn "HessianInput\|Hessian2Input" --include="*.java" --include="*.kt"  # Hessian
grep -rn "Yaml\(\)\.load\|Yaml\(\)\.loadAll\|new Yaml" --include="*.java" --include="*.kt"  # SnakeYAML
grep -rn "Kryo\|Kryo\.readObject\|FSTObjectInput" --include="*.java" --include="*.kt"  # Kryo/FST

# SSTI 全引擎
grep -rn "Velocity\.evaluate\|VelocityEngine\|mergeTemplate" --include="*.java" --include="*.kt"
grep -rn "freemarker\.template\|Template\.process\|FreeMarkerConfigurer" --include="*.java" --include="*.kt"
grep -rn "SpringTemplateEngine\|TemplateEngine\.process" --include="*.java" --include="*.kt"  # Thymeleaf

# 表达式注入
grep -rn "SpelExpressionParser\|parseExpression\|evaluateExpression" --include="*.java" --include="*.kt"
grep -rn "OgnlUtil\|Ognl\.getValue\|ActionContext" --include="*.java" --include="*.kt"

# JNDI 注入
grep -rn "InitialContext\.lookup\|JdbcRowSetImpl\|setDataSourceName" --include="*.java" --include="*.kt"

# 命令执行
grep -rn "Runtime\.getRuntime\|ProcessBuilder\|exec(" --include="*.java" --include="*.kt"

# 脚本引擎代码执行
grep -rn "ScriptEngine\.eval\|ScriptEngineManager\|NashornScriptEngine" --include="*.java" --include="*.kt"

# 动态类加载（配合反射可 RCE）
grep -rn "Class\.forName\|ClassLoader\.loadClass\|URLClassLoader" --include="*.java" --include="*.kt"
grep -rn "getMethod\|invoke\|newInstance" --include="*.java" --include="*.kt"  # 反射调用
```

**Windows (PowerShell):**

```powershell
# 反序列化全家族（同时检查 Java 和 Kotlin 文件）
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "ObjectInputStream|XMLDecoder|XStream"
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "JSON\.parseObject|JSON\.parse|@type"  # Fastjson
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "enableDefaultTyping|activateDefaultTyping"  # Jackson
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "HessianInput|Hessian2Input"  # Hessian
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "Yaml\.load|new Yaml"  # SnakeYAML
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "Kryo|FSTObjectInput"  # Kryo/FST

# SSTI 全引擎
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "Velocity\.evaluate|VelocityEngine|mergeTemplate"
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "freemarker\.template|Template\.process|FreeMarkerConfigurer"
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "SpringTemplateEngine|TemplateEngine\.process"  # Thymeleaf

# 表达式注入
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "SpelExpressionParser|parseExpression|evaluateExpression"
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "OgnlUtil|Ognl\.getValue|ActionContext"

# JNDI 注入
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "InitialContext\.lookup|JdbcRowSetImpl|setDataSourceName"

# 命令执行
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "Runtime\.getRuntime|ProcessBuilder|exec\("

# 脚本引擎代码执行
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "ScriptEngine\.eval|ScriptEngineManager|NashornScriptEngine"

# 动态类加载（配合反射可 RCE）
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "Class\.forName|ClassLoader\.loadClass|URLClassLoader"
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "getMethod|invoke|newInstance"  # 反射调用
```

#### P1 级危险模式（SQL 注入/SSRF/文件操作/XXE/LDAP）

**Linux/macOS (Bash):**

```bash
# SQL 注入风险
grep -rn "Statement\|createStatement\|executeQuery\|executeUpdate" --include="*.java" --include="*.kt"
grep -rn '\$\{' --include="*.xml"  # MyBatis ${} 注入
grep -rn "createQuery\|createNativeQuery" --include="*.java" --include="*.kt"  # JPA/HQL 注入

# SSRF
grep -rn "URL\(|HttpURLConnection\|HttpClient\|RestTemplate\|WebClient" --include="*.java" --include="*.kt"

# 文件操作
grep -rn "FileInputStream\|FileOutputStream\|FileWriter\|Files\.read\|Files\.write" --include="*.java" --include="*.kt"
grep -rn "getOriginalFilename\|transferTo\|MultipartFile" --include="*.java" --include="*.kt"  # 文件上传
grep -rn "\.\./\|getAbsolutePath" --include="*.java" --include="*.kt"  # 路径穿越

# XXE（XML 外部实体）
grep -rn "DocumentBuilder\|SAXParser\|XMLReader\|SAXReader" --include="*.java" --include="*.kt"
grep -rn "setFeature.*external.*false\|setExpandEntityReferences.*false" --include="*.java" --include="*.kt"  # XXE 防护检查

# LDAP 注入
grep -rn "SearchControls\|DirContext\.search\|ldapsearch" --include="*.java" --include="*.kt"

# 开放重定向
grep -rn "sendRedirect\|Response\.sendRedirect" --include="*.java" --include="*.kt"

# 日志注入
grep -rn "log\.info\|log\.debug\|log\.error" --include="*.java" --include="*.kt" | grep -i "request\|param\|input"  # 日志记录用户输入
```

**Windows (PowerShell):**

```powershell
# SQL 注入风险
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "Statement|createStatement|executeQuery|executeUpdate"
Get-ChildItem -Recurse -Include *.xml | Select-String -Pattern '\$\{'  # MyBatis ${} 注入
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "createQuery|createNativeQuery"  # JPA/HQL 注入

# SSRF
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "URL\(|HttpURLConnection|HttpClient|RestTemplate|WebClient"

# 文件操作
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "FileInputStream|FileOutputStream|FileWriter|Files\.read|Files\.write"
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "getOriginalFilename|transferTo|MultipartFile"  # 文件上传
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "\.\./|getAbsolutePath"  # 路径穿越

# XXE（XML 外部实体）
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "DocumentBuilder|SAXParser|XMLReader|SAXReader"
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "setFeature.*external|setExpandEntityReferences"  # XXE 防护检查

# LDAP 注入
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "SearchControls|DirContext\.search|ldapsearch"

# 开放重定向
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "sendRedirect|Response\.sendRedirect"

# 日志注入
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "log\.info|log\.debug|log\.error"
```

#### P2 级危险模式（认证/授权/加密/敏感信息）

**Linux/macOS (Bash):**

```bash
# 认证相关
grep -rn "@PreAuthorize\|@Secured\|@RolesAllowed\|hasRole\|hasAuthority" --include="*.java" --include="*.kt"
grep -rn "permitAll\|anonymous\|authenticated" --include="*.java" --include="*.kt"

# 加密相关
grep -rn "MessageDigest\|Cipher\|SecretKey\|PasswordEncoder" --include="*.java" --include="*.kt"
grep -rn "MD5\|SHA1\|DES\|AES/ECB" --include="*.java" --include="*.kt"  # 弱加密算法

# 不安全随机数
grep -rn "new Random\(\)\|Math\.random\(\)" --include="*.java" --include="*.kt"

# 硬编码敏感信息
grep -rn "password\s*=\s*\"\|secret\s*=\s*\"\|apiKey\s*=\s*\"" --include="*.java" --include="*.kt"
grep -rn "jdbc:mysql://\|jdbc:oracle:" --include="*.java" --include="*.kt"  # 数据库连接字符串

# @InitBinder 配置检查
grep -rn "@InitBinder\|setDisallowedFields" --include="*.java" --include="*.kt"  # Spring 参数绑定配置
```

**Windows (PowerShell):**

```powershell
# 认证相关
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "@PreAuthorize|@Secured|@RolesAllowed|hasRole|hasAuthority"
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "permitAll|anonymous|authenticated"

# 加密相关
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "MessageDigest|Cipher|SecretKey|PasswordEncoder"
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "MD5|SHA1|DES|AES/ECB"  # 弱加密算法

# 不安全随机数
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "new Random\(\)|Math\.random\(\)"

# 硬编码敏感信息
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "password\s*=\s*\"|secret\s*=\s*\"|apiKey\s*=\s*\""
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "jdbc:mysql://|jdbc:oracle:"  # 数据库连接字符串

# @InitBinder 配置检查
Get-ChildItem -Recurse -Include *.java,*.kt | Select-String -Pattern "@InitBinder|setDisallowedFields"  # Spring 参数绑定配置
```

#### ⚠️ @InitBinder 分析指南（重要）

当发现 `@InitBinder` 或 `setDisallowedFields` 时，**必须按以下步骤验证**：

**Step 1：验证类继承关系**

```powershell
# 检查 Controller 是否继承了父类
Select-String -Path $controllerFile -Pattern "class.*Controller.*extends|class.*Controller\s*\{"
```

| 情况 | 结论 |
|------|------|
| 继承父类 + 有自己的 `@InitBinder` | 可能是"覆盖" |
| 未继承父类 + 有自己的 `@InitBinder` | 不是"覆盖"，是"新增配置" |

**Step 2：验证参数绑定方式**

```powershell
# 检查接口参数注解
Select-String -Path $controllerFile -Pattern "@RequestBody|@ModelAttribute|@RequestParam|public.*\("
```

| 参数注解 | 受 @InitBinder 影响 | 分析重点 |
|---------|-------------------|---------|
| `@RequestBody` | ❌ 否（JSON 反序列化） | 检查 DTO 字段 |
| `@ModelAttribute` | ✅ 是 | 高风险，需详细分析 |
| 无注解（对象参数） | ✅ 是 | 高风险，需详细分析 |
| `@RequestParam` | ⚠️ 部分（单个字段） | 低风险 |

**Step 3：验证业务场景**

```powershell
# 检查是否涉及用户管理
Select-String -Path $files -Pattern "UserService|UserRepository|isAdmin|role|permission"
```

**Step 4：验证 DTO 字段**

```powershell
# 读取 DTO 类定义，检查字段
Get-Content $dtoFile
```

**正确结论格式**：

```markdown
在 XxxController 中存在危险的 @InitBinder 配置：`binder.setDisallowedFields(new String[]{})`。
当前该控制器有 X 个接口，其中 Y 个使用表单参数绑定（受影响），Z 个使用 @RequestBody（不受影响）。
受影响的接口 DTO 只含 [字段列表]，无敏感字段。
若后续新增参数绑定接口，可能存在批量分配风险。
```

**错误案例（2026-04-01）**：
> 错误：报告"批量分配防护被覆盖"，但 Controller 未继承父类，且全部使用 @RequestBody。
> 教训：未验证继承关系、参数绑定方式、业务场景、攻击路径。

### Layer 2: 双轨审计模型

每个 Agent 执行两条并行的审计轨道：

#### 轨道 1: Sink-driven（从危险代码往上追）

发现 `Runtime.exec(cmd)` → 追踪 `cmd` 参数来源 → 检查是否有过滤 → 判断是否来自用户输入

#### 轨道 2: Control-driven（从端点往下查安全控制）

发现 `/api/admin/deleteUser` 端点 → 检查是否有认证注解 → 检查是否有权限校验

**为什么需要两条轨道？** 认证绕过这类漏洞，单独用 Sink-driven 找不到——该漏洞不是某行代码有问题，而是某个端点缺少了应有的权限检查。

### Layer 2 执行流程

```
Step 1: 执行轨道 1 (Sink-driven)
  ↓ 对 L1 发现的危险 Sink 追踪参数来源
  ↓ 判断是否用户可控
  ↓ 输出普通漏洞候选列表

Step 2: 执行轨道 2 (Control-driven)
  ↓ 列出所有 Controller 入口
  ↓ 检查权限控制
  ↓ 输出越权/认证绕过候选列表

Step 3: 执行 Layer 2.5（仅对逻辑漏洞）
  ↓ 对资金交易、状态变更等敏感接口
  ↓ 执行 CoT 四步推理
  ↓ 输出逻辑漏洞候选列表
```

### Layer 2.5: 逻辑漏洞 CoT 四步推理

**执行时机**：当发现以下场景时，必须执行 Layer 2.5：

| 场景 | 触发条件 | 示例 |
|------|----------|------|
| 资金交易 | 涉及支付、退款、转账 | `pay()`, `refund()`, `transfer()` |
| 状态变更 | 涉及订单状态、审批流程 | `updateStatus()`, `approve()` |
| 资源分配 | 涉及库存、名额 | `createOrder()`, `book()` |
| 数据访问 | 涉及敏感数据查询 | `getUserInfo()`, `getOrderDetail()` |

**⚠️ Layer 2.5 触发条件检查清单**：

在执行 Layer 2 之前，必须先检查是否需要触发 Layer 2.5：

```markdown
□ API 路径包含 pay/payment/refund/transfer/withdraw？
□ 方法名包含 updateStatus/approve/reject/confirm/cancel？
□ 涉及金额、价格、库存、数量字段？
□ 涉及状态机流转（订单状态、审批状态）？
□ 涉及用户间数据隔离（水平越权风险）？
□ 涉及特权操作（管理员功能、系统配置）？

→ 任一为是 → 必须执行 Layer 2.5
→ 全部为否 → 可跳过 Layer 2.5
```

**注意**：Layer 2.5 专门用于逻辑漏洞分析，普通漏洞（SQL注入、命令注入等）用 Layer 2 双轨审计即可。

对于 Semgrep 规则无法覆盖的漏洞类型，需要通过代码分析进行判断。

#### 逻辑漏洞 CoT 四步推理

**核心理念**：逻辑漏洞的本质是"合法的代码执行了非预期的业务流程"，需要强制 AI 像安全专家一样进行攻防推演。

```
Step 1: 场景与入口识别 → 识别 API 功能场景，分析用户可控参数
Step 2: 防御机制审计 → 寻找代码中的"锁"和"盾"，分析完备性
Step 3: 对抗性沙箱模拟 → AI 设计 PoC，模拟真实链路处理
Step 4: 漏洞结果判定 → 基于推演给出负责任结论
```

**Step 1: 场景与入口识别**

```markdown
识别内容：
1. API 功能场景（资金交易/数据访问/状态变更等）
2. 用户可控参数列表
3. 参数风险标签：
   - ID 类（userId, orderId）→ 数据定位，可能越权
   - 金额类（amount, price）→ 资金相关，可能篡改
   - 状态类（status, state）→ 状态控制，可能绕过状态机
   - 数量类（count, quantity）→ 资源相关，可能并发问题
```

**Step 2: 防御机制审计**

寻找代码中的"锁"和"盾"：

| 锁类型 | 代码特征 | 检查点 |
|--------|----------|--------|
| 权限锁 | `@PreAuthorize`, `hasRole()` | 是否存在？是否完整？ |
| 归属锁 | `userId.equals(currentUser.getId())` | 数据是否校验归属？ |
| 状态锁 | `if (order.getStatus() == PAID)` | 状态前置条件是否完整？ |
| 金额锁 | `amount.equals(order.getAmount())` | 金额是否后端校验？ |
| 并发锁 | `synchronized`, `SELECT FOR UPDATE` | 是否有并发控制？ |

**Step 3: 对抗性沙箱模拟**

基于业务语义生成对抗性测试用例：

| 参数类型 | 测试值 | 目标漏洞 |
|----------|--------|----------|
| 金额 | 负数、0、极大值 | 0元支付、负金额退款 |
| 数量 | 负数、超库存上限 | 库存为负、超量下单 |
| 状态 | 跳跃状态值 | 状态机绕过 |
| ID | 他人 ID | 水平越权 |

**Step 4: 漏洞结果判定**

- **CONFIRMED**: PoC 可执行，调用链完整，影响明确
- **HYPOTHESIS**: 发现可疑模式但无法完全确认，需人工验证

**详细推理模板**: [references/logic-vulnerability-cot.md](references/logic-vulnerability-cot.md)

#### 业务逻辑漏洞检查要点

```
支付金额检查：
1. 金额是否来自前端？是否有后端校验？
2. 价格是否可被篡改？
3. 是否有金额一致性校验？

库存并发检查：
1. 是否有并发控制（锁/原子操作）？
2. 检查和扣减是否原子操作？

状态机检查：
1. 状态流转规则是否明确？
2. 敏感操作是否校验前置状态？
3. 是否有非法状态跳转？
```

#### 越权漏洞检查要点

```
水平越权检查：
1. 数据查询是否校验归属？
2. userId 是否从 Session 获取（不可伪造）？
3. UPDATE/DELETE 是否有 userId 条件？

垂直越权检查：
1. 管理接口是否有权限注解？
2. 前后端权限是否一致？
3. 是否有权限配置遗漏？
```

#### 依赖安全检查

⚠️ **必须通过 mvnrepository.com 联网核实**，不再使用离线规则表。

```
检查流程：
1. 读取 pom.xml/build.gradle 提取依赖版本
2. 构建 mvnrepository.com 查询 URL
3. 使用 tavily + web_fetch 查询组件页面
4. 检查当前版本的 "Direct vulnerabilities" 标记
5. 找到无漏洞的安全版本
```

**mvnrepository.com 查询方法**：

```
URL 格式: https://mvnrepository.com/artifact/{groupId}/{artifactId}

示例:
https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core
https://mvnrepository.com/artifact/com.alibaba/fastjson
https://mvnrepository.com/artifact/org.apache.shiro/shiro-core
```

**漏洞标记识别**：
- 有漏洞版本：页面显示 `Direct vulnerabilities: CVE-XXXX-XXXXX`
- 安全版本：无 `Direct vulnerabilities` 标记

**执行命令**：

```bash
# 方式一：tavily 搜索定位
web_search "mvnrepository {groupId} {artifactId}" -n 5

# 方式二：直接 web_fetch 组件页面
# 使用 web_fetch 工具访问 mvnrepository.com 页面
```

**检查示例**：

```
发现依赖: httpclient 4.5.12

Step 1: 访问 mvnrepository.com/artifact/org.apache.httpcomponents/httpclient

Step 2: 检查版本列表:
  - 4.5.12: Direct vulnerabilities: CVE-2020-13956 → ❌ 有漏洞
  - 4.5.14: 无标记 → ✅ 安全版本

结论: 需要升级到 4.5.14+
```

**⚠️ 核实铁律**：

1. **禁止凭记忆编造安全版本** - 必须在 mvnrepository.com 上核实
2. **必须检查 "Direct vulnerabilities"** - 这是直接依赖漏洞，非间接依赖
3. **必须找到无标记的安全版本** - 在版本列表中寻找无漏洞标记的最新版本

#### 运行时配置

```
检查要点：
1. Session 超时、Cookie Secure/HttpOnly
2. Actuator 端点暴露
3. 数据库密码明文存储
4. 调试模式开启
```

**详细判断方法见**: [references/vulnerability-conditions.md](references/vulnerability-conditions.md) 第 16-19 节

### Layer 3: 调用链语义级验证

优先使用 LSP 做语义级追踪：

```
候选 Sink (Statement.executeUpdate(sql))
↓ goToDefinition → 确认实际实现
↓ findReferences → 向上追踪所有调用者
↓ hover → 获取中间变量类型
↓ 重复 findReferences → 直到到达 Controller 入口或确认不可达
↓ 记录完整调用链，每一跳标注 文件:行号
```

LSP 不可用时退化到 Grep + Read 手动追踪。

---

## Phase 2.5: 覆盖率门禁

**这是反 LLM 天性的核心设计**——LLM 倾向于跳过"看起来不重要"的代码，而漏洞恰恰喜欢藏在那些地方。

### 自动化覆盖率检查

使用 `scripts/java_audit.py` 自动检查覆盖率：

```bash
# Python 脚本（跨平台）
python scripts/java_audit.py /path/to/project --coverage --reviewed-file findings-raw.md

# 输出示例：
# [*] 覆盖率统计:
#   实际文件总数: 847
#   已审阅文件数: 820
#   遗漏文件数: 27
#   覆盖率: 96.8%
#
# [!] 门禁未通过 - 覆盖率 < 100%，需要补扫
```

### 门禁阈值

**⚠️ 核心原则**：T1 文件（Controller/Filter）必须 100% 覆盖，无例外。

| 项目规模 | EALOC | T1 覆盖率 | T2 覆盖率 | T3 覆盖率 | 总体覆盖率 |
|----------|-------|-----------|-----------|-----------|------------|
| 小型项目 | < 15,000 | **100%** | 95% | 90% | **100%** |
| 中型项目 | 15,000 - 50,000 | **100%** | 95% | 85% | **95%** |
| 大型项目 | > 50,000 | **100%** | 90% | 80% | **90%** |

**门禁判断逻辑**：

```
门禁通过条件（必须全部满足）：
1. T1 覆盖率 == 100%（硬性要求，无例外）
2. T2 覆盖率 >= 阈值（中型 95%，大型 90%）
3. T3 覆盖率 >= 阈值（中型 85%，大型 80%）
4. 总体覆盖率 >= 阈值（小型 100%，中型 95%，大型 90%）
```

**说明**：
- **T1（Controller/Filter）**：入口点文件，安全风险最高，必须全部审计
- **T2（Service/DAO）**：业务逻辑层，覆盖率要求较高
- **T3（Entity/VO）**：数据模型层，覆盖率要求相对较低

### 模块覆盖矩阵

```markdown
| # | 模块路径 | LOC | EALOC | Controller数 | 风险评估 | 分配 Agent | Phase2 状态 | Phase3 状态 |
|---|---------|-----|-------|-------------|---------|-----------|------------|------------|
| 1 | module-auth | 8,000 | 5,200 | 6 | HIGH | Agent 1 | 完成 | 完成 |
| 2 | module-gateway | 12,000 | 7,800 | 8 | HIGH | Agent 2 | 完成 | 进行中 |
| 3 | module-biz | 131,000 | 37,700 | 40 | HIGH | Agent 3a~3c | 部分完成 | 未开始 |
```

### 文件级覆盖率验证

每个 Agent 输出必须包含审阅文件清单：

```markdown
| # | 文件路径 | Tier | 状态 | 发现数 |
|---|---------|------|------|-------|
| 1 | AuthController.java | T1 | 完成 已审阅 | 2 |
| 2 | ShiroConfig.java | T1 | 完成 已审阅 | 1 |
| 3 | UserServiceImpl.java | T2 | 完成 已审阅 | 0 |
| 4 | User.java | T3 | 完成 已审阅 | 0 |
| 5 | com/alibaba/fastjson/JSON.java | SKIP | 跳过 第三方库 | - |
```

**门禁检查**: 拿这份清单和 `find` 命令的实际文件列表做 diff。清单里没出现的文件 = 漏审。

### 门禁判断逻辑

```
收到每个 Agent 结果后立即执行：
1. 读取 Agent 输出的「审阅文件清单」
2. 与实际文件列表交叉验证
3. 覆盖率达到阈值 → 该 Agent 通过
   覆盖率未达标 → 立即为未覆盖文件启动补扫 Agent

所有 Agent 完成后：
- 全部模块 Phase2 = 完成 → 进入 Phase 3
- 存在 未开始 或 部分完成 → 启动补充 Agent → 循环直到达标
```

### 覆盖率不达标处理流程

```
┌─────────────────────────────────────────────────────────────────┐
│                覆盖率门禁回溯机制                                 │
└─────────────────────────────────────────────────────────────────┘

  Phase 2.5: 检查覆盖率
  ┌─────────────────────────────────────┐
  │ 计算覆盖率 = 已审阅文件 / 总文件数  │
  └─────────────────────────────────────┘
              ↓
        ┌─────┴─────┐
        │ 覆盖率达标？│
        └─────┬─────┘
         是 ↓     ↓ 否
  ┌──────────┐  ┌──────────────────────┐
  │进入      │  │ 1. 列出遗漏文件列表  │
  │Phase 3   │  │ 2. 返回 Phase 2      │
  └──────────┘  │ 3. 补扫遗漏文件      │
                │ 4. 更新审阅清单      │
                │ 5. 再次检查覆盖率    │
                └──────────┬───────────┘
                           ↓
                     ┌─────┴─────┐
                     │ 达标？    │
                     └─────┬─────┘
                      是 ↓     ↓ 否
                ┌──────────┐  ┌──────────┐
                │Phase 3   │  │ 循环补扫 │
                └──────────┘  └──────────┘
```

**补扫命令**：

```powershell
# 1. 获取遗漏文件列表
# 对比实际文件列表和已审阅清单
$allFiles = Get-ChildItem -Recurse -Filter *.java | Select-Object -ExpandProperty Name
$reviewedFiles = Get-Content findings-raw.md | Select-String -Pattern "\.java" 
$missingFiles = Compare-Object $allFiles $reviewedFiles

# 2. 对遗漏文件执行审计
foreach ($file in $missingFiles) {
    Read $file
    # 执行 Layer 2 分析
}

# 3. 更新 findings-raw.md
# 4. 重新计算覆盖率
```

**阈值说明**：见上门禁阈值表，按项目规模分级执行。T1 文件必须 100% 覆盖。

### 质量校验自动化

每个阶段输出后，自动运行质量校验脚本检查输出质量。

#### 校验脚本

```bash
# Linux/macOS
./scripts/quality-checker.sh <phase> <project_path>

# Windows PowerShell
.\scripts\quality-checker.ps1 -Phase <phase> -ProjectPath <project_path>

# 全量校验
./scripts/quality-checker.sh all /path/to/project
```

#### 校验阶段与检查项

| 阶段 | 校验项 | 不通过条件 |
|------|--------|-----------|
| **phase1** | EALOC 计算 | 缺失 |
| **phase1** | Tier 分类 | 缺失或 T1=0 |
| **phase2-layer1** | 危险模式文件 | p0/p1/p2 全缺失 |
| **phase2-layer2** | 精确行号 | 无 `文件:行号` 格式 |
| **phase2-layer2** | 调用链分析 | 0 个调用链 |
| **phase25** | 覆盖率 | 总体 < 90% |
| **phase25** | T1 覆盖率 | < 100% |
| **phase3** | CONFIRMED/HYPOTHESIS | 无状态标记 |
| **phase3** | DKTSS 评分 | 缺失 |
| **phase5** | 报告结构 | 缺少漏洞列表/审计进度 |
| **phase5** | 完整路径 | 代码位置非绝对路径 |
| **phase5** | 标题格式 | 包含严重程度标签 |

#### 自动化流程

```
Phase 1 执行完成
  ↓ 自动运行
  quality-checker.sh phase1 /project/path
  ↓
  通过 → 继续执行 Phase 2
  不通过 → 返回 Phase 1 补充
  
Phase 2 Layer 1 执行完成
  ↓ 自动运行
  quality-checker.sh phase2-layer1 /project/path
  ↓
  通过 → 继续执行 Layer 2
  不通过 → 检查扫描命令
  
...以此类推...
```

#### 校验示例

```bash
# Phase 5 报告校验
$ ./scripts/quality-checker.sh phase5 /path/to/project

[*] Phase 5 质量校验...
[✓] 「漏洞列表」部分存在
[✓] 「审计进度」部分存在
[✓] 代码位置格式正确（完整绝对路径）
[✓] 标题格式正确（无严重程度标签）
[✓] 调用链分析完整
[✓] 修复建议存在
[*] Phase 5 校验完成: 0 错误, 0 警告
```

---

## Phase 3: 漏洞验证 & DKTSS 评分

### ⚠️ Phase 3 与 Layer 3 的区别

| 名称 | 所属阶段 | 作用 |
|------|----------|------|
| **Layer 3** | Phase 2 内部 | 调用链语义验证，用 Read 验证每一跳 |
| **Phase 3** | 独立阶段 | 最终漏洞确认、反幻觉检查、DKTSS 评分 |

```
Phase 2 内部:
  Layer 1 → Layer 2 → Layer 3（调用链验证）
                ↓
         输出 findings-raw.md

Phase 3:
  读取 findings-raw.md
    → 反幻觉铁律检查
    → CVE 联网核实
    → DKTSS 评分
    → 状态标记
                ↓
         输出 findings-verified.md
```

### 反幻觉 7 条铁律

1. **报告漏洞前必须用 Read 验证文件存在**
2. **代码片段必须来自实际 Read 输出，不得编造**
3. **调用链每一跳必须标注 文件:行号**
4. **不确定的发现标记为 HYPOTHESIS，不得标记为 CONFIRMED**
5. **宁可漏报，不可误报**
6. **CVE 编号必须联网核实，禁止凭记忆编造**
7. **行号必须用 Read 验证，禁止模糊范围或猜测**

#### CVE 核实铁律详解

```markdown
❌ 错误做法：
  报告 CVE-2020-1948 为 Hessian 漏洞
  实际情况：CVE-2020-1948 是 Apache Dubbo 漏洞，与 Hessian 库无关

✅ 正确做法：
  1. 使用 tavily 搜索 "<组件名> <版本号> CVE"
  2. 从 NVD/Snyk 官方数据确认 CVE 真实性
  3. 确认影响版本范围
  4. 确认 CVE 影响的具体组件（artifact）
```

#### 行号验证铁律详解

```markdown
❌ 错误做法：
  grep 搜索后直接使用 grep 输出的行号
  报告模糊范围：HeaderModelUtils.java:18-35

✅ 正确做法：
  1. grep 搜索定位关键代码
  2. 使用 Read 工具读取文件，验证实际行号
  3. 精确标注：HeaderModelUtils.java:35
  4. 多段代码分开标注：HttpUtil.java:252-253, 321

行号验证示例：
  # grep 搜索
  Select-String -Path $file -Pattern "getLoginUserByStr" | ForEach-Object { "Line $($_.LineNumber)" }
  
  # Read 验证（必须执行）
  Read 文件，确认 grep 输出的行号与实际内容匹配
```

### 分析深度铁律

**漏洞分析必须达到 L3 级别，禁止写成三点式（成因+攻击+影响），禁止片面分析**。

必须包含以下所有要素：
- ✅ **具体方法名**：精确到 `ClassName.methodName()`
- ✅ **具体行为**：方法具体做了什么
- ✅ **缺少的安全控制**：什么保护措施没有（列表形式）
- ✅ **攻击路径**：攻击者可以如何利用（步骤形式）
- ✅ **调用链追踪**：从入口到漏洞点的完整路径
- ✅ **漏洞类型归纳**：标准漏洞分类（CWE）
- ✅ **未使用的安全机制**：项目中存在但未启用的安全配置

**禁止片面分析**：

```markdown
❌ 片面分析（不可接受）：
`CommonController.uploadFile()` 方法接收用户上传的文件，没有对文件类型进行校验，
攻击者可以上传恶意文件。

问题：
- 没有说明具体哪个方法有问题
- 没有调用链追踪
- 没有说明缺少哪些具体的安全控制
- 没有对比分析
- 没有攻击路径说明

✅ 全面分析（符合要求）：
`CommonController.uploadFile()` 方法（CommonController.java:49）接收 MultipartFile 参数，
直接调用 `FileUtil.saveFile()` 保存到服务器。

**调用链追踪**：
Controller → Service → FileUtil

**缺少的安全控制**：
1. 文件类型校验：未检查 Content-Type 和文件扩展名
2. 文件内容校验：未检查文件魔数/文件头
3. 文件名处理：使用原始文件名，未重命名

**攻击路径**：
1. 攻击者构造恶意 JSP WebShell
2. 修改 Content-Type 为 image/jpeg 绕过前端校验
3. 上传到服务器可访问目录
4. 访问上传的文件执行任意命令

**归纳漏洞类型**：任意文件上传（CWE-434）
```

**样例**（必须参照此格式）：
```
`HeaderModelUtils.getLoginUserByStr()` 方法仅对 Header 中的 Base64 编码数据进行解码，
然后直接反序列化为 LoginUserBo 对象。系统没有对用户信息进行任何签名验证或加密保护，
攻击者可以轻松伪造任意用户的登录信息。

控制器层（如 `FlightController.setFlightCityHistory()`）直接从请求头 `la517_loginUser`
获取用户信息，该信息未经服务器端验证就传递给服务层使用，形成**客户端信任漏洞**。

经审查 `pom.xml` 发现项目已引入 JWT 相关依赖（`jjwt`），但全局搜索显示实际并未使用。
`LogInterceptor` 拦截器仅用于日志追踪（requestId 生成），不包含任何认证逻辑。
```

### 漏洞成立条件判断

**详见 [references/vulnerability-conditions.md](references/vulnerability-conditions.md)**

示例 - Fastjson 反序列化判断流程：
```
发现 JSON.parseObject() / JSON.parse() 调用
↓
检查版本：
  < 1.2.68 → 直接可利用
  1.2.68-1.2.80 → 检查 classpath 是否有特定依赖（groovy/jython/aspectj/commons-io）
  ≥ 1.2.83 → 检查 safeMode 配置
```

### DKTSS 评分体系

**详见 [references/dktss-scoring.md](references/dktss-scoring.md)**

核心公式：`Score = Base - Friction + Weapon + Ver`

- **Base**: 按漏洞类型和实际影响评分
- **Friction**: 实战阻力（访问路径/权限门槛/交互复杂度）
- **Weapon**: 武器化程度
- **Ver**: 版本因子

### 状态定义

| 状态 | 定义 | 要求 |
|------|------|------|
| **CONFIRMED** | 已验证可利用 | PoC 可执行，调用链完整，影响明确 |
| **HYPOTHESIS** | 疑似漏洞，需人工验证 | 发现可疑模式但无法完全确认 |

**关键原则**: 宁可标记为 HYPOTHESIS 让人工验证，也不要把不确定的发现标记为 CONFIRMED 污染报告可信度。

---

## Phase 4: Semgrep 规则沉淀（可选）

**目标**：将确认的漏洞模式转换为 Semgrep 静态分析规则，可集成到 CI/CD 流水线。

### Semgrep 安装

**详见 [rules/semgrep/README.md](rules/semgrep/README.md)**

```bash
# macOS
brew install semgrep

# Linux
pip install semgrep

# Windows (通过 pip)
pip install semgrep

# 验证安装
semgrep --version
```

**快速扫描**：

```bash
# 扫描所有规则（含新增的新兴技术安全规则）
semgrep --config rules/semgrep/ /path/to/project

# 仅扫描 P0 级规则
semgrep --config rules/semgrep/java-rce.yaml /path/to/project
semgrep --config rules/semgrep/java-emerging.yaml /path/to/project

# 输出 JSON 格式
semgrep --config rules/semgrep/ --json /path/to/project > semgrep-results.json
```

**规则列表**：见 [rules/semgrep/README.md](rules/semgrep/README.md)，共 314 条规则覆盖：
- **传统漏洞**：RCE、SQL注入、SSRF、文件操作、加密安全
- **新兴技术**：LLM/AI 安全、GraphQL、Kotlin 特有漏洞、Java 21 新特性
- **微服务安全**：Feign、Gateway、Dubbo、gRPC、NoSQL 注入
- **组件配置**：Log4j2、Spring Security、Shiro、Fastjson、JWT 等
- **业务安全**：并发安全、输入验证、敏感数据处理

### 执行条件

Phase 4 为**可选步骤**，在以下情况下执行：

- 发现了新的漏洞模式，现有 Semgrep 规则未覆盖
- 需要将漏洞检测集成到 CI/CD 流水线
- 项目需要长期的自动化安全检测

### 输出文件

| 文件 | 说明 |
|------|------|
| `custom-rules.yaml` | 自定义 Semgrep 规则文件 |
| `semgrep-results.json` | 规则测试结果 |

### 规则编写规范

```yaml
rules:
  - id: custom-vulnerability-id
    patterns:
      - pattern: 危险模式
      - pattern-not: 安全模式（排除误报）
    message: 规则描述，说明漏洞风险和修复建议
    severity: ERROR  # ERROR / WARNING / INFO
    languages: [java]
    metadata:
      category: security
      cwe: "CWE-XXX"
      references:
        - https://example.com/reference
```

### 示例规则

```yaml
rules:
  - id: velocity-ssti
    patterns:
      - pattern: Velocity.evaluate($CONTEXT, $WRITER, $NAME, $USER_INPUT)
      - pattern-not: Velocity.evaluate($CONTEXT, $WRITER, $NAME, "...")
    message: 检测到用户可控的 Velocity 模板输入，存在 SSTI 风险
    severity: ERROR
    languages: [java]
    metadata:
      category: security
      cwe: "CWE-94"
```

### 规则测试

```bash
# 测试单个规则
semgrep --config custom-rules.yaml /path/to/test/code

# 验证规则语法
semgrep --validate --config custom-rules.yaml
```

### 跳过条件

以下情况可跳过 Phase 4：

- 所有发现的漏洞都已被现有 Semgrep 规则覆盖
- 不需要 CI/CD 集成
- 时间紧迫，优先完成报告

---

## Phase 5: 标准化报告生成

### ⚠️ 必须先阅读模板

**在生成报告之前，必须完整阅读 [references/report-template.md](references/report-template.md)**。

报告格式以 `report-template.md` 为准，SKILL.md 不再重复定义格式细节。

### 报告整体结构

报告包含以下部分：

1. **漏洞列表**：包含漏洞的名字
2. **审计进度**：包含 L1-L3 审计的进度
3. **详细漏洞报告**：每个漏洞包含三部分
   - **描述**：漏洞归纳描述，100字左右
   - **漏洞详情**：代码位置、问题代码展示、漏洞分析（300字以上）
   - **修复建议**：完整的解决方案

### 报告格式规范

| 内容 | 标签 | 说明 |
|------|------|------|
| 漏洞名称 | h1 (`#`) | 单独一个大名称 |
| 描述 | h3 (`###`) | 漏洞归纳描述，100字左右 |
| 漏洞详情 | h3 (`###`) | 包含代码位置、代码展示、漏洞分析 |
| 修复建议 | h3 (`###`) | 完整解决方案 |

### ⚠️ 报告格式铁律

#### 1. 代码位置必须使用完整绝对路径

```markdown
❌ 错误：
**代码位置**：
CommonController.java:49-62

✅ 正确：
**代码位置**：
E:\工作代码\xx\xx\src\main\java\com\example\controller\CommonController.java:49-62
```

#### 2. 漏洞分析必须详细完整（300字以上）

漏洞分析部分必须包含：

| 要素 | 说明 |
|------|------|
| 1. 调用链追踪 | 从入口到漏洞点的完整路径，每一跳标注 文件:行号 |
| 2. 缺少的安全控制 | 表格形式列出 |
| 3. 攻击路径 | 步骤形式（1、2、3...） |
| 4. 对比分析 | 与安全代码的差异 |
| 5. 未使用的安全机制 | 项目中存在但未启用 |
| 6. 漏洞类型归纳 | CWE 标准分类 |

**详细示例见 report-template.md**。

#### 3. 禁止在标题中添加严重程度标签

```markdown
❌ 错误：
# 任意文件上传漏洞（Critical）

✅ 正确：
# 任意文件上传漏洞
```

### 反幻觉铁律（再次强调）

1. **报告漏洞前必须用 Read 验证文件存在**
2. **代码片段必须来自实际 Read 输出，不得编造**
3. **调用链每一跳必须标注 文件:行号**
4. **不确定的发现标记为 HYPOTHESIS，不得标记为 CONFIRMED**
5. **分析深度必须达到 L3 级别**（见 report-template.md）

#### 行号定位规范

- **必须使用实际验证的行号**，禁止模糊范围
- 精确到方法起始行，多段代码分开标注
- 示例：`HttpUtil.java:252-253, 321` 而非 `HttpUtil.java:177-193`

### 报告输出文件

- `findings-raw.md`: Phase 2 发现的候选漏洞
- `findings-verified.md`: Phase 3 验证后的确认漏洞（最终数据源）
- `audit-report.md`: Phase 5 格式化的最终报告

---

## AI 代码审计 6 大核心方法

### 1. 语义化规则匹配

传统工具的规则是"死"的——只能匹配固定参数名。AI 通过语义识别核心业务含义，适配任意命名规范。

**示例**：越权漏洞检测
- 传统规则：检查是否存在 `user_id` 参数
- AI 语义规则：识别接口中所有代表用户身份标识的参数，校验该参数用于定位业务数据归属时，是否与当前登录用户的身份存在强制绑定

**适用场景**：未授权访问、通用越权、验证码绕过、密码重置漏洞

### 2. 基于因果推理的业务流程异常审计

AI 先构建业务的因果关系基准与状态机模型，明确每个业务操作的强制前置条件（因）与合法后置状态（果），再通过反事实推理验证。

**示例**：电商支付场景
- 强制前置条件：订单已创建且未支付、支付金额一致、回调凭证合法
- 合法后置状态：订单变为待发货、库存扣减、生成发货单
- 测试用例：跳过支付直接调用发货确认接口

**适用场景**：流程绕过、步骤颠倒、非法状态跳转

### 3. 权限与访问控制的逻辑一致性审计

构建完整的权限-资源绑定模型，执行三类校验：

| 校验类型 | 方法 | 覆盖漏洞 |
|----------|------|----------|
| 水平越权校验 | 用同角色不同用户凭证测试 | 访问他人私有数据 |
| 垂直越权校验 | 用低权限凭证测试高权限接口 | 权限提升 |
| 一致性校验 | 对比同类接口权限校验逻辑 | 部分遗漏校验 |

**适用场景**：水平/垂直越权、未授权访问、前后端权限不一致

### 4. 边界条件与异常分支的对抗性生成审计

基于参数的业务语义生成对抗性测试用例，而非随机字符串：

| 参数类型 | 测试值 | 目标漏洞 |
|----------|--------|----------|
| 金额 | 负数、0、极大值、超2位小数 | 0元支付、负金额退款 |
| 数量 | 负数、超库存上限 | 库存为负、超量下单 |
| 时间 | 超期时间、早于当前时间 | 绕过有效期限制 |

**白盒扫描重点**：异常捕获分支是否存在"跳过权限校验"、"异常时返回成功"、"泄露敏感信息"

### 5. 多维度关联的漏洞链推理

将单个缺陷按业务场景、接口依赖、数据流转关系关联，自动识别可串联的漏洞点。

**示例漏洞链**：
1. `/api/user/list` 未授权访问 → 获取全量用户手机号和 user_id
2. `/api/user/password/reset` 仅校验手机号和 user_id，无验证码

→ 串联形成完整攻击链，实现任意用户密码重置

### 6. 白盒场景的代码语义级逻辑缺陷审计

重点扫描高频逻辑缺陷场景：

- 权限校验缺失（仅校验登录，未校验数据归属）
- 业务逻辑错误（金额计算顺序、库存扣减顺序）
- 异常处理缺陷（捕获异常后直接返回成功）
- 接口设计缺陷（无幂等性、敏感操作无二次校验）

---

## 长上下文问题 5 层解决方案

### 层级 1: 源头治理（性价比最高，降低 60%+ 上下文）

**必过滤内容**：
- 注释、空行、纯日志打印代码
- 单元测试文件
- 第三方依赖库
- 构建配置文件
- 自动生成代码（protobuf、MyBatis Mapper）

**可过滤低风险内容**：
- 仅含 get/set 的纯数据实体类
- 无安全风险的工具方法
- 非核心统计报表代码

**注意**：过滤必须基于语义识别，不能误删权限校验、加密解密、输入过滤等核心安全代码。

### 层级 2: 三层递进式审计架构（核心方案）

| 层级 | 内容 | Token 控制 |
|------|------|------------|
| 第一层：全局架构层 | 项目架构说明、模块划分、全局权限模型、核心拦截器规则、对外接口清单 | ≤ 8K |
| 第二层：模块级审计 | 按业务域拆分独立审计单元，输入模块代码+全局安全基线+依赖接口元数据 | 32K-64K |
| 第三层：跨模块验证 | 仅输入关联模块核心代码片段+调用链路元数据 | ≤ 64K |

### 层级 3: 结构化语义压缩（降低 70%+ Token）

将代码转化为结构化元数据：

```
函数名：updateOrder
输入参数：orderId（用户可控字符串）、orderStatus（整型枚举）
核心业务逻辑：根据 orderId 修改订单状态
安全特征：无订单归属用户校验，无操作权限校验
下游依赖：orderDao.update
风险标签：越权风险高
```

### 层级 4: RAG + 多轮对话（突破窗口物理限制）

1. **构建代码知识库**：按函数/类拆分，生成向量嵌入存入向量库
2. **精准检索相关上下文**：通过自然语言或风险特征检索相关代码片段
3. **多轮对话增量审计**：每轮处理一个细分目标，上一轮输出作为下一轮轻量上下文

### 层级 5: 增量审计机制（工程化落地）

与 Git/CI/CD 集成，仅审计本次提交变更的代码及相关调用链路，减少 90%+ 上下文量。

---

## 5 大落地误区

### ❌ 误区 1：简单按行数拆分代码

**问题**：破坏代码语义关联，导致跨文件调用链路无法理解，严重漏报

**正确做法**：按业务边界、依赖关系拆分，采用三层递进式架构

### ❌ 误区 2：过度依赖长窗口模型

**问题**：超过 128K token 后注意力严重衰减，且成本极高

**正确做法**：中等窗口 + 裁剪分块 + RAG，长窗口仅作跨模块验证辅助

### ❌ 误区 3：全量代码丢给 AI

**问题**：上下文溢出、无关信息干扰、误报率飙升、速度极慢

**正确做法**：完成无效信息过滤与风险分级，遵循"非必要不输入"

### ❌ 误区 4：完全抛弃传统工具

**问题**：大模型存在幻觉问题，无法被规则匹配弥补

**正确做法**：传统工具前置过滤 + AI 深度推理 + 传统工具后置验证

### ❌ 误区 5：只关注已知漏洞

**问题**：浪费 AI 核心能力——检测业务逻辑漏洞

**正确做法**：聚焦传统工具无法覆盖的逻辑缺陷、越权漏洞、流程绕过

---

## 参考文档

| 文档 | 内容 |
|------|------|
| [vulnerability-conditions.md](references/vulnerability-conditions.md) | 漏洞成立条件判断表（Fastjson、JNDI、SSTI 等） |
| [dktss-scoring.md](references/dktss-scoring.md) | DKTSS 评分体系详细说明 |
| [cve-offline-lookup.md](references/cve-offline-lookup.md) | 常见 CVE 离线速查表（Log4j、Fastjson、Spring、Shiro 等） |
| [report-template.md](references/report-template.md) | 标准化漏洞报告模板 |
| [logic-vulnerability-cot.md](references/logic-vulnerability-cot.md) | 逻辑漏洞 CoT 四步推理流程 |
| [business-scenario-tags.md](references/business-scenario-tags.md) | 业务场景标签系统 |
| [security-checklist.md](references/security-checklist.md) | Java Web 应用安全审计检查清单 |

### Semgrep 规则文件

| 文件 | 覆盖内容 | 规则数 |
|------|----------|--------|
| [java-rce.yaml](rules/semgrep/java-rce.yaml) | 反序列化、SSTI、表达式注入、命令注入 | 21 |
| [java-sqli.yaml](rules/semgrep/java-sqli.yaml) | SQL 注入、MyBatis ${} 注入 | 12 |
| [java-ssrf.yaml](rules/semgrep/java-ssrf.yaml) | SSRF 漏洞 | 8 |
| [java-file.yaml](rules/semgrep/java-file.yaml) | 文件操作漏洞 | 14 |
| [java-crypto.yaml](rules/semgrep/java-crypto.yaml) | 加密算法安全 | 8 |
| [java-misc.yaml](rules/semgrep/java-misc.yaml) | XXE、XSS、认证授权等 | 56 |
| [java-config.yaml](rules/semgrep/java-config.yaml) | 组件配置安全（60+ 组件） | 95 |
| [java-emerging.yaml](rules/semgrep/java-emerging.yaml) | LLM/AI、GraphQL、Kotlin、Java 21、并发安全 | 14 |

**总计 314 条规则**

### 示例项目

| 目录 | 说明 |
|------|------|
| [examples/vulnerable-springboot/](examples/vulnerable-springboot/audit-report.md) | 完整审计报告示例（含 4 个漏洞详细分析） |

---

## 执行检查清单

### 审计开始前

- [ ] 确认项目路径和技术栈（Java/Kotlin 版本、框架）
- [ ] 运行 Phase 0 度量脚本
- [ ] 完成项目侦察，生成 Tier 分类和 EALOC 计算
- [ ] **生成业务场景标签（scenario-tags.json）**

### 审计过程中

- [ ] Layer 1 预扫描完成，P0-P3 标记到位
- [ ] 每个 Agent 双轨审计（Sink-driven + Control-driven）
- [ ] **逻辑漏洞执行 CoT 四步推理**
- [ ] 实时更新覆盖矩阵
- [ ] 文件级覆盖率验证（清单 vs 实际文件 diff）

### 审计完成后

- [ ] 覆盖率门禁达标（小型 100% / 中型 95% / 大型 90%）
- [ ] 每个漏洞遵循反幻觉 **7 条铁律**
- [ ] **CVE 编号已联网核实（禁止凭记忆编造）**
- [ ] **行号已用 Read 验证（禁止模糊范围）**
- [ ] **依赖安全检查使用 tavily（禁止 web_search）**
- [ ] **逻辑漏洞有完整 CoT 推理记录**
- [ ] DKTSS 评分完整
- [ ] 报告三段式格式齐全（描述 + 漏洞详情 + 修复建议）
- [ ] 分析达到 **L4 级别**（1500字以上，包含完整 7 要素）
- [ ] CONFIRMED vs HYPOTHESIS 状态正确
- [ ] **已阅读 references/report-template.md**

---

## 注意事项

1. **不要信任 LLM 的"记忆"**：所有中间结果都持久化到文件
2. **"没有发现也是有效结果"**：每个文件必须有"已审阅，无发现"或发现记录
3. **javax.* 和 jakarta.* 双命名空间**：Java EE → Jakarta EE 迁移历史，扫描规则必须同时匹配两个命名空间
4. **大模块拆分追踪**：EALOC > 15000 的模块必须拆分成多个子任务

---

## 大型项目增强：CPG 工具支持

对于 EALOC > 50000 的大型项目，推荐使用代码属性图（CPG）工具增强分析能力。

### 推荐工具：Joern

**优势**：
- 支持反编译伪代码分析（可用于 jar 包审计）
- 提供完整的代码属性图（AST + CFG + PDG）
- 支持复杂的跨文件调用链追踪
- 内置查询语言（Joern Query）进行自定义规则

**集成方式**：

```bash
# 安装 Joern
./joern --script audit.sc

# audit.sc 示例
importCode("path/to/project")
cpg.method.name("exec").callIn.l.foreach { call =>
  println(s"Potential RCE: ${call.location}")
}
```

**适用场景**：
- 超大型项目（>50 万行）
- 需要跨模块调用链分析
- 反编译代码审计

### 与现有架构整合

```
Layer 0: Joern CPG 构建（大型项目可选）
    ↓
Layer 1: ripgrep + Semgrep 预扫描
    ↓
Layer 2: LLM 双轨审计
    ↓
Layer 2.5: CoT 四步推理（逻辑漏洞）
    ↓
Layer 3: LSP/Joern 语义级验证
```

---

## 输出文件清单

| 文件 | 生成阶段 | 说明 |
|------|----------|------|
| `audit-metrics.json` | Phase 0 | 项目度量数据（文件数、行数、EALOC） |
| `tier-classification.md` | Phase 1 | Tier 分类结果 |
| `scenario-tags.json` | Phase 1 | API 场景标签 |
| `dependency-security.md` | Phase 1 | 依赖安全检查结果 |
| `p0-critical.md` | Phase 2 Layer 1 | P0 级危险模式（需 `--scan` 参数） |
| `p1-high.md` | Phase 2 Layer 1 | P1 级危险模式（需 `--scan` 参数） |
| `p2-medium.md` | Phase 2 Layer 1 | P2 级危险模式（需 `--scan` 参数） |
| `findings-raw.md` | Phase 2 | 候选漏洞列表（未验证） |
| `findings-verified.md` | Phase 3 | 验证后漏洞列表（已确认） |
| `audit-report.md` | Phase 5 | 最终审计报告 |
| `custom-rules.yaml` | Phase 4（可选） | 自定义 Semgrep 规则 |

**说明**：
- 标注"需 `--scan` 参数"的文件需要执行 `python scripts/java_audit.py --scan` 才会生成
- Phase 4 的 `custom-rules.yaml` 为可选输出，仅当需要将漏洞模式沉淀为规则时生成

---

## ⚠️ 输入长度限制应对策略（重要）

**问题**: LLM 存在输入长度限制（约 200KB），一次性加载过多内容会导致 `Range of input length should be [1, 202745]` 错误。

### 分阶段执行策略

**⚠️ 必须遵循以下分阶段执行策略，避免输入长度超限**：

```
┌─────────────────────────────────────────────────────────────┐
│                    分阶段执行策略                              │
└─────────────────────────────────────────────────────────────┘

Step 1: 脚本执行（不直接读取文件）
  ├── python audit.py --detect-lang     # 仅获取语言检测结果
  ├── python java_audit.py --scan --tier # 仅获取扫描摘要
  └── 输出内容是精简的摘要信息（< 10KB）

Step 2: 针对性搜索（不全文件读取）
  ├── search_content "password|secret"  # 只返回匹配行
  ├── search_content "Runtime.getRuntime"
  └── 输出内容是匹配的关键行（< 5KB）

Step 3: 分段读取关键文件（限制行数）
  ├── read_file offset=50 limit=30      # 只读取 30 行
  ├── read_file offset=100 limit=50     # 分段读取
  └── 每次读取限制在 50-100 行以内

Step 4: 分段生成报告（分段写入）
  ├── write_to_file 先写框架
  ├── replace_in_file 逐个添加漏洞
  └── 避免一次性写入大量内容
```

### 内容量限制规则

| 操作类型 | 限制 | 说明 |
|----------|------|------|
| **脚本执行输出** | < 10KB | 脚本输出是精简摘要，不会超限 |
| **search_content 结果** | < 5KB | 只返回匹配行，使用 headLimit 限制 |
| **read_file 单次读取** | < 100 行 | 使用 offset 和 limit 参数分段读取 |
| **单次响应总内容** | < 50KB | 控制单次响应中的总内容量 |

### 大型项目处理策略（EALOC > 10000）

**⚠️ 当 EALOC > 10000 时，必须采用以下策略**：

```
┌─────────────────────────────────────────────────────────────┐
│                   大型项目审计流程                             │
└─────────────────────────────────────────────────────────────┘

Phase 0: 仅执行脚本
  ├── python audit.py --detect-lang
  ├── python java_audit.py --scan --tier
  └── 不直接读取任何源文件

Phase 1: 根据扫描结果确定重点
  ├── 读取 p0-critical.md、p1-high.md（脚本生成的报告）
  ├── 确定需要深入分析的文件列表（< 10 个）
  └── 不全量读取所有文件

Phase 2: 针对性分析关键文件
  ├── 只读取 P0/P1 级危险模式涉及的文件
  ├── 分段读取（每次 < 100 行）
  └── 使用 search_content 搜索关键模式

Phase 3: 分段生成报告
  ├── 先写入报告框架
  ├── 逐个添加漏洞详情
  └── 每次添加 1-2 个漏洞
```

### 禁止的操作

| 禁止操作 | 原因 | 正确做法 |
|----------|------|----------|
| ❌ 一次性读取整个文件 | 可能超过 200KB | ✅ 使用 offset/limit 分段读取 |
| ❌ 一次性读取多个大文件 | 累积超限 | ✅ 逐个读取，控制总量 |
| ❌ 不使用脚本直接读取源文件 | 内容量不可控 | ✅ 先执行脚本获取摘要 |
| ❌ 在单次响应中处理过多漏洞 | 报告内容超限 | ✅ 分多次响应处理 |

### 正确的审计流程示例

```markdown
# 正确流程（避免超限）

## Step 1: 执行脚本获取摘要
→ python audit.py /path/to/project --detect-lang
→ 输出: 语言类型、文件数量（< 2KB）

## Step 2: 执行扫描获取危险模式
→ python java_audit.py /path/to/project --scan --tier
→ 输出: P0/P1/P2 发现数量、文件列表（< 10KB）

## Step 3: 读取扫描报告确定重点
→ read_file p0-critical.md（< 5KB）
→ read_file p1-high.md（< 5KB）
→ 确定需要深入分析的文件（< 10 个）

## Step 4: 针对性搜索关键模式
→ search_content "password|secret" --headLimit 20
→ search_content "Runtime.getRuntime" --headLimit 10
→ 输出: 匹配的关键行（< 5KB）

## Step 5: 分段读取关键文件
→ read_file Controller.java offset=50 limit=30
→ read_file Service.java offset=100 limit=50
→ 每次读取 < 100 行

## Step 6: 分段生成报告
→ write_to_file findings-raw.md（先写框架）
→ replace_in_file（添加漏洞 1）
→ replace_in_file（添加漏洞 2）
→ 分多次添加，避免一次性写入过多
```

---

## 小型项目简化流程

**适用条件**：EALOC < 15,000（小型项目）

### 简化执行策略

| 标准流程 | 简化流程 | 说明 |
|----------|----------|------|
| Phase 0 + Phase 1 分开执行 | 合并执行 | 一次性统计 + 读取 pom.xml |
| Phase 2 Layer 1/2/3 分开 | 合并执行 | 直接 Read 所有文件 |
| Phase 2.5 覆盖率检查 | 可跳过 | 小型项目必须 100% 覆盖 |
| Phase 3 + Phase 5 分开 | 合并执行 | 验证 + 报告一起生成 |

### 简化流程图

```
Step 1: 度量 + 侦察
  ↓
  - 统计文件数、行数
  - 计算 EALOC，判断项目规模
  - 读取 pom.xml，检查依赖安全
  - 列出所有 Controller 入口

Step 2: 全量代码审计
  ↓
  - Read 所有 Java 文件
  - 检查权限控制（Control-driven）
  - 追踪危险模式（Sink-driven）
  - 记录所有发现

Step 3: 验证 + 报告
  ↓
  - 应用反幻觉铁律
  - CVE 联网核实
  - 生成 audit-report.md
  - 报告末尾添加覆盖率统计
```

### 小型项目执行命令

```powershell
# Step 1: 度量
$files = Get-ChildItem -Recurse -Filter *.java
$files.Count  # 文件数
($files | Get-Content | Measure-Object -Line).Lines  # 行数

# Step 2: 列出所有文件
$files | Select-Object -ExpandProperty FullName

# Step 3: 逐个读取审计
foreach ($file in $files) {
    Read $file.FullName
    # 检查权限控制、危险模式
}

# Step 4: 生成报告
# 按 report-template.md 格式书写
```

### 覆盖率统计模板

```markdown
## 审计覆盖率统计

| 层级 | 扫描内容 | 覆盖数量 | 总数量 | 覆盖率 |
|------|----------|----------|--------|--------|
| Layer 1 | 危险模式预扫描 | 18 个文件 | 18 个 Java 文件 | 100% |
| Layer 2 | 双轨审计 | 11 个 Controller | 11 个 Controller | 100% |
| Layer 3 | 调用链验证 | 6 个漏洞 | 6 个候选漏洞 | 100% |
```

---

**文档版本**: v1.9.2  
**最后更新**: 2026-04-03

## 版本历史

| 版本 | 日期 | 变更内容 |
|------|------|----------|
| v1.9.2 | 2026-04-03 | 新增：前端审计支持（JS/React/Vue）、语言检测功能、前端 Semgrep 规则 |
| v1.9.1 | 2026-04-03 | 修复：Tier 分类扩展支持多框架、覆盖率正则修复、Jakarta EE 规则、Layer 2.5 触发条件检查清单 |
| v1.9.0 | 2026-04-02 | 依赖安全检查重构（mvnrepository.com 联网核实）、新增质量校验脚本 |
| v1.8.0 | 2026-04-01 | 重构报告格式：h1漏洞名称 + 漏洞列表 + 审计进度 + 三段式漏洞详情 |
| v1.7.0 | 2026-03-31 | 初始版本


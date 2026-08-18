# Java Spring Boot Actuator 未授权访问漏洞全量描述

> 规则 ID：`config_actuator2_misconfig` · 类别：misconfig · 关键 sink：（cypher 结构提取，见原文）
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java Spring Boot Actuator 未授权访问漏洞全量描述
Spring Boot Actuator 是 Spring Boot 核心组件之一，旨在提供应用运行时的监控、运维、诊断能力（如健康检查、指标监控、环境配置、日志查看等），但因配置不当或版本特性问题，极易引发**未授权访问漏洞**——攻击者无需身份验证即可访问 Actuator 暴露的敏感端点，窃取应用核心信息甚至执行高危操作，严重威胁应用安全。

## 一、漏洞核心成因
Actuator 未授权访问的本质是**端点访问控制机制失效**，核心成因可分为以下维度：
1. **默认配置风险**：低版本 Spring Boot（≤2.0.x）中，Actuator 端点默认开启且无权限校验，暴露在公网时直接可被访问；2.0+ 版本虽默认只暴露 `/health` `/info` 两个低风险端点，但若手动开启高危端点且未配置鉴权，仍会触发漏洞。
2. **鉴权机制缺失**：未集成 Spring Security、Shiro 等安全框架，或虽集成但未对 Actuator 端点配置访问规则（如未设置角色、未校验 Token/密码）。
3. **配置错误**：
   - 手动将 `management.endpoints.web.exposure.include` 设置为 `*`（暴露所有端点），且未限制访问来源；
   - `management.security.enabled=false`（2.0 前版本）或 `management.endpoint.health.show-details=always`（泄露健康检查详情）；
   - 端点路径未自定义，使用默认路径（如 `/actuator`）且未做路径隐藏/重命名。
4. **版本兼容问题**：部分老旧版本（如 1.5.x）存在配置项失效、鉴权逻辑漏洞，即使配置了基础鉴权也可能被绕过。

## 二、漏洞覆盖的核心场景
### 场景1：基础未授权访问（全版本通用）
#### 触发条件
- Actuator 端点已暴露（如 `/actuator` 根路径可访问）；
- 未配置任何身份验证（无 Spring Security、无反向代理鉴权、无 IP 白名单）；
- 应用部署在公网或可被攻击者访问的内网环境。

#### 危害表现
攻击者可直接访问所有暴露的端点，例如：
- `/actuator/health`：获取应用健康状态，包括数据库、缓存、第三方服务等依赖的连接状态，为后续攻击提供目标；
- `/actuator/info`：获取应用版本、Git 提交信息、构建信息等，可精准定位漏洞版本；
- `/actuator/env`：读取应用环境变量、配置项（如数据库账号密码、Redis 连接信息、API 密钥等敏感数据）；
- `/actuator/configprops`：查看所有配置属性的详细值，包括框架内置和自定义配置；
- `/actuator/mappings`：获取所有 HTTP 接口映射关系，暴露未公开的接口路径；
- `/actuator/metrics`：查看应用性能指标（如请求量、JVM 内存、CPU 使用率），可用于判断应用负载和攻击时机。

### 场景2：高危端点未授权访问（2.0+ 版本重点）
#### 触发条件
- 通过配置 `management.endpoints.web.exposure.include=beans,threaddump,heapdump,loggers,shutdown` 主动暴露高危端点；
- 未对这些端点做权限控制，仅依赖默认配置。

#### 危害表现
此类场景危害远超基础访问，可直接影响应用运行甚至接管应用：
1. `/actuator/beans`：查看所有 Spring Bean 的定义和依赖关系，暴露应用内部架构，辅助攻击者寻找漏洞入口；
2. `/actuator/threaddump`：导出线程快照，包含线程状态、调用栈、锁信息，可挖掘死锁、敏感操作线程（如密码加密、数据查询），甚至通过调用栈找到代码漏洞；
3. `/actuator/heapdump`：下载 JVM 堆转储文件（hprof 格式），通过分析堆文件可提取内存中的敏感数据（如用户会话、数据库连接池密码、缓存中的用户信息）；
4. `/actuator/loggers`：修改日志级别（如将 `INFO` 改为 `DEBUG`），获取更多敏感日志输出，甚至通过日志注入执行恶意操作；
5. `/actuator/shutdown`：触发应用优雅关闭，直接导致服务不可用（需手动开启 `management.endpoint.shutdown.enabled=true`）；
6. `/actuator/scheduledtasks`：查看定时任务列表，可利用定时任务执行周期发起针对性攻击（如定时数据同步接口的重放攻击）。

### 场景3：1.5.x 版本特有未授权风险
Spring Boot 1.5.x 作为 Actuator 早期版本，配置逻辑与 2.x 差异较大，漏洞场景更突出：
#### 触发条件
- 配置 `endpoints.enabled=true`（默认开启），且 `management.security.enabled=false`（关闭鉴权）；
- 端点默认路径为 `/health` `/env` `/beans` 等（无 `/actuator` 统一前缀），易被扫描器发现；
- 未配置 `endpoints.<endpoint>.sensitive=true`（敏感端点未标记，导致鉴权失效）。

#### 危害表现
- 1.5.x 中 `/env` 端点可直接查看 `spring.datasource.password` 等明文配置，且无任何过滤；
- `/refresh` 端点可触发配置刷新（需开启 `spring.cloud.config.refresh.enabled=true`），攻击者可通过构造 POST 请求修改配置项；
- `/metrics` 端点包含 `jvm.memory.used` `tomcat.sessions.active` 等更详细的敏感指标，易被用于横向渗透。

### 场景4：反向代理/网关层配置不当导致的未授权
即使应用层配置了基础鉴权，若反向代理（Nginx、Apache）或 API 网关（Spring Cloud Gateway、Zuul）配置错误，仍会绕过鉴权：
#### 触发条件
- 反向代理将 `/actuator` 路径直接转发至应用，且未在代理层配置身份验证/IP 白名单；
- 网关层未对 Actuator 端点配置路由过滤规则，导致外网可直接访问内网应用的 Actuator 端点；
- 代理层配置了 `allow all` 的 CORS 策略，攻击者可通过跨域请求访问 Actuator 端点。

#### 危害表现
- 内网应用的 Actuator 端点被暴露到公网，攻击者可获取内网服务的敏感信息（如内网数据库地址、服务间调用凭证）；
- 跨域访问可窃取 Actuator 返回的敏感数据（如 `/env` 中的配置信息），突破同源策略限制。

### 场景5：Actuator 与其他组件结合的复合漏洞
Actuator 未授权访问常与其他组件漏洞叠加，放大危害：
#### 场景5.1：结合 Spring Cloud Config 未授权
- 触发条件：Actuator 暴露 `/configprops` 端点，且应用集成了 Spring Cloud Config；
- 危害：攻击者可通过 `/configprops` 获取 Config Server 地址、配置文件路径，进而访问 Config Server 未授权的配置仓库（如 Git 仓库），窃取所有微服务的配置信息。

#### 场景5.2：结合 JMX 暴露的未授权
- 触发条件：Actuator 开启 `/jolokia` 端点（JMX 监控），且未配置 JMX 鉴权；
- 危害：攻击者可通过 `/jolokia` 执行 JMX 操作，调用 MBean 方法（如修改应用配置、执行系统命令），甚至触发 RMI 反序列化漏洞（若 JDK 版本存在漏洞）。

#### 场景5.3：结合 Actuator 端点数据泄露的二次攻击
- 触发条件：通过 Actuator 获取数据库账号密码后，攻击者利用这些凭证尝试登录数据库；
- 危害：从应用层未授权升级为数据层入侵，窃取/篡改业务数据。

## 三、漏洞触发的技术特征
1. **访问特征**：攻击者通常通过端口扫描（8080、8081、9090 等常用端口）+ 路径扫描（`/actuator` `/health` `/env` 等）发现漏洞；
2. **请求特征**：以 GET 请求为主（大部分端点支持 GET），高危操作（如 `/shutdown` `/loggers` 修改）为 POST 请求；
3. **响应特征**：未授权访问成功时，返回 200 OK 状态码，且响应体包含 JSON 格式的敏感数据（如配置项、线程信息）；若鉴权生效，应返回 401 Unauthorized 或 403 Forbidden。

## 四、漏洞影响范围
- **版本范围**：Spring Boot 1.0.0 ~ 2.7.x（3.x 版本默认加固，但配置不当仍可触发）；
- **部署场景**：所有暴露 Actuator 端点的场景（包括生产环境、测试环境、内网环境）；
- **业务影响**：信息泄露（配置、凭证、架构）、服务不可用（shutdown）、数据篡改（配置刷新）、横向渗透（内网服务信息泄露）。

综上，Spring Boot Actuator 未授权访问漏洞的核心风险在于“敏感端点暴露 + 鉴权缺失”，不同版本、不同配置、不同部署架构下的漏洞表现和危害程度存在差异，但本质均是未对 Actuator 提供的运维能力做足够的访问控制，导致攻击者可无成本获取应用核心信息或执行高危操作。

参考：https://docs.spring.io/spring-boot/reference/actuator/endpoints.html


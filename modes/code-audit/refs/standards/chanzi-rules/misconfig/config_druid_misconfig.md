# Java Druid监控页面未授权访问漏洞 完整描述

> 规则 ID：`config_druid_misconfig` · 类别：misconfig · 关键 sink：（cypher 结构提取，见原文）
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java Druid监控页面未授权访问漏洞 完整描述
Druid是阿里巴巴开源的Java数据库连接池，因其内置的监控功能（可实时查看数据库连接、SQL执行、慢查询等核心指标）被广泛应用于Java Web项目中。但在配置不当的情况下，其监控页面（Druid StatView）会存在**未授权访问漏洞**，攻击者无需身份验证即可直接访问监控页面，窃取敏感信息甚至进一步攻击系统。


## 一、漏洞核心成因
Druid监控页面的访问控制依赖显式配置的`allow`/`deny` IP白名单、登录账号密码等鉴权规则，若这些规则未正确配置（或完全缺失），则任何网络可达的攻击者都能直接访问监控端点（默认`/druid/*`），突破访问限制。

核心配置项（Spring Boot/Spring MVC场景）：
- `spring.datasource.druid.stat-view-servlet.enabled=true`（开启监控页面，默认开启）
- `spring.datasource.druid.stat-view-servlet.allow`（允许访问的IP白名单，未配置则默认允许所有IP）
- `spring.datasource.druid.stat-view-servlet.deny`（拒绝访问的IP黑名单，优先级低于allow）
- `spring.datasource.druid.stat-view-servlet.login-username`/`login-password`（登录账号密码，未配置则无需登录）

漏洞本质：**鉴权机制未启用/配置失效**，导致监控页面的访问控制完全失效。


## 二、漏洞触发的典型场景
### 场景1：完全未配置任何访问控制（最常见）
开发者仅开启Druid监控，但未配置IP白名单、登录账号密码等任何鉴权规则，是漏洞出现的核心场景。

#### 配置示例（Spring Boot）：
```properties
# 仅开启监控，无任何鉴权配置
spring.datasource.druid.stat-view-servlet.enabled=true
# 未配置 allow/deny IP，未配置登录账号密码
```
#### 触发条件：
攻击者只需访问 `${域名/IP}:${端口}/druid/index.html`（默认端点），即可直接进入监控页面，无任何身份验证或IP限制。

### 场景2：IP白名单配置错误/过宽
开发者试图通过`allow`配置IP白名单，但因配置错误导致白名单失效或覆盖范围过宽，仍可被未授权IP访问。

#### 子场景2.1：白名单配置为空/格式错误
```properties
# 错误1：allow配置为空字符串（等同于未配置）
spring.datasource.druid.stat-view-servlet.allow=
# 错误2：IP格式错误（如多IP分隔符错误、网段格式错误）
spring.datasource.druid.stat-view-servlet.allow=192.168.1.1;10.0.0.0/8  # 正确分隔符应为逗号，此处用分号导致配置失效
spring.datasource.druid.stat-view-servlet.allow=192.168.1.256  # 无效IP，配置失效
```
#### 子场景2.2：白名单配置为“0.0.0.0”/“*”（允许所有IP）
```properties
# 错误配置：0.0.0.0 表示允许所有IP访问（Druid默认逻辑）
spring.datasource.druid.stat-view-servlet.allow=0.0.0.0
# 或错误配置通配符（Druid不识别*，视为无效配置，退化为允许所有IP）
spring.datasource.druid.stat-view-servlet.allow=*
```
#### 触发条件：
即使配置了`allow`，但因格式错误/范围过宽，攻击者仍可通过任意IP访问`/druid/index.html`。

### 场景3：仅配置黑名单（deny），未配置白名单（allow）
Druid的鉴权逻辑为：先判断是否在`deny`黑名单（拒绝），再判断是否在`allow`白名单（允许）；若未配置`allow`，则默认允许所有未被`deny`的IP访问。

#### 配置示例：
```properties
spring.datasource.druid.stat-view-servlet.enabled=true
# 仅配置黑名单，未配置白名单
spring.datasource.druid.stat-view-servlet.deny=192.168.1.100
```
#### 触发条件：
攻击者只需使用非黑名单内的IP（如192.168.1.101），即可直接访问监控页面。

### 场景4：登录账号密码配置失效/未生效
开发者试图配置账号密码鉴权，但因配置项错误、框架版本兼容问题等导致鉴权失效。

#### 子场景4.1：配置项名称错误（Spring Boot）
```properties
# 错误配置项：正确应为 login-username/login-password，此处少“login-”前缀
spring.datasource.druid.stat-view-servlet.username=admin
spring.datasource.druid.stat-view-servlet.password=123456
```
#### 子场景4.2：Druid版本兼容问题
低版本Druid（如1.0.28及以下）存在配置项解析bug，即使正确配置账号密码，仍可能跳过登录验证。

#### 触发条件：
攻击者访问`/druid/index.html`时，无需输入账号密码，直接进入监控页面。

### 场景5：反向代理/网关层绕过IP白名单
开发者在应用层配置了IP白名单（如仅允许127.0.0.1访问），但前端部署了Nginx等反向代理，且代理未正确传递客户端真实IP，导致Druid获取的是代理服务器IP（而非攻击者真实IP），绕过白名单限制。

#### 配置示例（Nginx反向代理未传递真实IP）：
```nginx
server {
    listen 80;
    server_name example.com;
    # 反向代理到应用，但未配置X-Real-IP/X-Forwarded-For
    location /druid/ {
        proxy_pass http://127.0.0.1:8080;
    }
}
```
#### 应用层配置：
```properties
spring.datasource.druid.stat-view-servlet.enabled=true
# 仅允许127.0.0.1访问（代理服务器IP）
spring.datasource.druid.stat-view-servlet.allow=127.0.0.1
```
#### 触发条件：
攻击者访问`example.com/druid/index.html`时，Druid获取到的IP是Nginx的127.0.0.1（在白名单内），因此允许访问，绕过应用层IP限制。

### 场景6：多环境配置混用（测试环境配置泄露到生产）
开发者在测试环境为方便调试，关闭了Druid监控的鉴权规则，上线生产环境时未修改配置，导致生产环境暴露未授权访问漏洞。

#### 典型问题：
- 生产环境直接复用测试环境的`application.yml`/`application.properties`，包含`allow=0.0.0.0`、未配置账号密码等；
- 配置中心（如Nacos/Apollo）将测试环境配置推送到生产环境，未做环境隔离。


## 三、漏洞可访问的敏感信息与风险影响
未授权访问Druid监控页面后，攻击者可获取以下核心敏感信息：
1. **数据库核心信息**：数据库连接URL（含IP、端口、库名）、用户名（部分版本会明文显示）、连接池数量、活跃连接数等；
2. **SQL执行详情**：实时执行的SQL语句（含参数，可能泄露用户手机号、密码、订单等业务数据）、慢SQL列表、SQL执行耗时/次数；
3. **应用运行信息**：JVM内存使用、线程堆栈、类加载信息、请求响应时间等；
4. **系统环境信息**：服务器IP、操作系统版本、Java版本、应用部署路径等。

这些信息可被攻击者用于后续精准攻击（如数据库爆破、SQL注入、服务器横向渗透等）。


## 四、漏洞触发的边界条件
1. **Druid监控是否开启**：必须满足`stat-view-servlet.enabled=true`（默认开启），若关闭则无此漏洞；
2. **监控端点是否暴露**：默认端点为`/druid/*`，若通过`url-pattern`修改为非默认路径（如`/admin/druid/*`），但未配置鉴权，仍存在漏洞；
3. **网络可达性**：攻击者需能访问应用的端口（如8080、80等），若端口仅内网开放，漏洞影响范围受限；
4. **Druid版本**：部分高版本Druid（如1.2.16+）默认强化了鉴权（需显式配置allow/账号密码），但配置不当仍会触发漏洞。



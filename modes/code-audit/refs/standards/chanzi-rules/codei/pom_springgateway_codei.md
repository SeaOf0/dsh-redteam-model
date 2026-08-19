# Java Spring Gateway 远程代码执行（RCE）漏洞

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`pom_springgateway_codei` · 类别：codei · 关键 sink：（cypher 结构提取，见原文）
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java Spring Gateway 远程代码执行（RCE）漏洞
Spring Cloud Gateway 是 Spring 生态中基于 Spring Framework 5、Spring Boot 2 和 Project Reactor 构建的 API 网关，用于实现路由转发、负载均衡、熔断、限流等核心能力。其远程代码执行漏洞主要源于**路由配置的不安全处理**、**spel表达式注入**、**网关过滤器/断言的设计缺陷**等，以下从漏洞成因、触发场景、影响版本、利用路径等维度完整描述各类情况：

## 一、核心漏洞类型及成因
Spring Gateway RCE 漏洞的核心根源可归纳为两类：**SpEL 表达式注入** 和 **恶意BeanDefinition/类加载**，其中 SpEL 注入是最主流、最易利用的类型。

### 1. SpEL 表达式注入导致的 RCE
Spring 表达式语言（SpEL）是 Spring 框架的核心表达式语言，支持运行时评估表达式、调用方法、访问类属性等。Spring Gateway 在处理路由断言（Predicate）、过滤器（Filter）配置时，若直接将用户可控的参数代入 SpEL 表达式并执行，会导致表达式注入，进而执行任意代码。

#### （1）漏洞触发的核心逻辑
Spring Gateway 的路由配置支持通过 `spring.cloud.gateway.routes` 定义，其中断言（如 `Path`、`Header`、`Query`）和过滤器（如 `AddRequestHeader`、`RewritePath`）的参数可配置为 SpEL 表达式（以 `#{}` 包裹）。当网关解析这些配置时，会通过 `SpelExpressionParser` 解析表达式并执行，若表达式内容可被用户控制，则攻击者可注入恶意 SpEL 代码。

#### （2）典型场景1：动态路由配置接口未授权访问
Spring Gateway 提供了 `/actuator/gateway/routes` 等 actuator 端点（默认未授权），用于动态添加/修改路由配置。攻击者可通过该端点提交包含恶意 SpEL 表达式的路由配置，网关解析时执行代码：
- 利用路径：发送 POST 请求到 `/actuator/gateway/routes/{恶意路由ID}`，请求体中构造包含 SpEL 注入的路由断言/过滤器；
- 触发条件：网关启用 `spring-boot-starter-actuator` 且暴露 `gateway` 端点（配置 `management.endpoints.web.exposure.include=gateway`）；
- 示例恶意配置（JSON）：
  ```json
  {
    "id": "malicious-route",
    "uri": "http://example.com",
    "predicates": [
      {
        "name": "Path",
        "args": {
          "_genkey_0": "#{T(java.lang.Runtime).getRuntime().exec('calc.exe')}"
        }
      }
    ],
    "filters": []
  }
  ```
  提交后触发 `POST /actuator/gateway/refresh` 刷新路由，即可执行 `calc.exe`（Windows）或任意系统命令。

#### （3）典型场景2：配置文件中硬编码/动态拼接用户输入到SpEL
若开发者在 `application.yml`/`application.properties` 中，将用户可控的参数（如请求参数、Header、路径变量）直接拼接进 SpEL 表达式配置，也会触发注入：
- 示例配置（application.yml）：
  ```yaml
  spring:
    cloud:
      gateway:
        routes:
          - id: vulnerable-route
            uri: http://backend-service
            predicates:
              - Header=X-User, #{new java.lang.ProcessBuilder('bash','-c','id').start()}
  ```
  当请求携带 `X-User` Header 时，网关解析该 SpEL 表达式，直接执行 `id` 命令。

#### （4）典型场景3：自定义过滤器/断言的SpEL处理不当
开发者自定义 GatewayFilter 或 RoutePredicate 时，若手动解析用户输入为 SpEL 表达式且未做过滤，会引入漏洞：
- 示例漏洞代码（自定义过滤器）：
  ```java
  @Component
  public class VulnerableFilter implements GatewayFilter {
      @Override
      public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
          String userInput = exchange.getRequest().getHeaders().getFirst("X-Input");
          // 直接解析用户输入为SpEL表达式，无过滤
          SpelExpressionParser parser = new SpelExpressionParser();
          Expression exp = parser.parseExpression(userInput);
          exp.getValue(); // 执行表达式
          return chain.filter(exchange);
      }
  }
  ```
  攻击者只需在 `X-Input` Header 中传入 `T(java.lang.Runtime).getRuntime().exec('whoami')`，即可触发 RCE。

### 2. 恶意BeanDefinition注册导致的RCE
Spring Gateway 基于 Spring Context 运行，若攻击者能通过网关的配置接口或漏洞点向 Spring 容器中注册恶意的 BeanDefinition，可触发类加载或方法执行，进而实现 RCE。

#### （1）触发条件
- 网关启用了动态路由配置（如 actuator gateway 端点）；
- 攻击者可构造包含 `BeanDefinition` 的路由配置，或利用 Spring 容器的漏洞注入 Bean；
- Spring 版本未修复 BeanDefinition 注册的权限控制问题。

#### （2）利用路径
攻击者通过 `/actuator/gateway/routes` 提交包含恶意 `BeanDefinition` 的路由配置，利用 SpEL 表达式调用 `BeanFactory` 注册 Bean：
```json
{
  "id": "bean-inject-route",
  "uri": "http://example.com",
  "predicates": [
    {
      "name": "Path",
      "args": {
        "_genkey_0": "#{T(org.springframework.beans.factory.support.BeanDefinitionBuilder).genericBeanDefinition(T(java.lang.Runtime)).getBeanDefinition()}"
      }
    }
  ]
}
```
结合 SpEL 调用 `Runtime.getRuntime().exec()`，可在 Bean 初始化时执行任意代码。

### 3. 其他衍生漏洞场景
#### （1）网关转发时的请求参数篡改+后端SpEL注入
若 Spring Gateway 仅做路由转发，未过滤请求参数，而后端服务（如 Spring MVC）存在 SpEL 注入漏洞，攻击者可通过网关构造恶意参数，经转发后触发后端 RCE（虽非网关自身漏洞，但属于网关场景下的 RCE 利用链）。

#### （2）GatewayFilter链的顺序执行漏洞
部分自定义过滤器链未做输入校验，攻击者可通过构造特殊请求，让过滤器链中多个组件的漏洞叠加，最终触发代码执行（如先绕过参数过滤，再注入 SpEL）。

#### （3）基于Reactor的异步执行漏洞
Spring Gateway 基于 Reactor 异步框架，若过滤器中处理用户输入时，在 `Mono`/`Flux` 的异步回调中执行 SpEL 表达式，且未做隔离，攻击者可利用异步执行的特性绕过部分防护，触发 RCE。

## 二、影响版本范围
不同漏洞变种的影响版本存在差异，核心 SpEL 注入漏洞的主要影响版本：
1. Spring Cloud Gateway < 3.1.0（2022年修复的 actuator 端点未授权+SpEL 注入漏洞，CVE-2022-22947）；
2. Spring Cloud Gateway < 2.2.10.RELEASE、< 3.0.6（早期 SpEL 注入变种）；
3. 所有自定义过滤器/断言中未做 SpEL 输入过滤的 Spring Gateway 版本（无论官方版本，属于代码实现漏洞）；
4. Spring Framework < 5.3.18（SpEL 表达式解析的安全加固，间接影响 Gateway）。

## 三、漏洞触发的前置条件
不同场景下的前置条件略有差异，但核心共性条件：
1. **用户输入可控**：攻击者能将恶意内容传入网关的路由配置、请求参数、Header、路径等可被 SpEL 解析的位置；
2. **SpEL 表达式执行**：网关将用户输入作为 SpEL 表达式解析并执行（未禁用 SpEL 或未做白名单过滤）；
3. **权限绕过/未授权访问**：如 actuator 端点未授权、动态路由配置接口无认证；
4. **网关处于运行状态**：漏洞利用需网关正常处理请求，且相关组件（如 actuator、SpEL 解析器）已加载。

## 四、漏洞利用的特征
1. **请求特征**：
   - 访问 `/actuator/gateway/routes`、`/actuator/gateway/refresh` 等端点；
   - 请求体/参数中包含 `#{}` 包裹的 SpEL 表达式（如 `#{T(java.lang.Runtime).getRuntime().exec()}`）；
   - 包含恶意类调用（如 `java.lang.Runtime`、`java.lang.ProcessBuilder`、`org.springframework.beans.factory.BeanFactory`）。
2. **行为特征**：
   - 网关进程执行异常系统命令（如 `nc`、`bash -i`、`powershell`）；
   - Spring 容器中出现未知 BeanDefinition；
   - 网关日志中出现 SpEL 解析错误（如 `SpelEvaluationException`）。

## 五、漏洞的危害程度
1. **高危/严重**：未授权访问的 SpEL 注入可直接执行任意代码，控制网关服务器；
2. **横向渗透**：网关通常作为流量入口，控制网关后可进一步攻击后端服务；
3. **持久化攻击**：通过动态路由配置注入恶意路由，可实现持久化 RCE（即使重启网关，若配置未清理仍会触发）；
4. **权限提升**：利用网关进程权限（通常为 `root`/`administrator`）执行高权限操作。

以上为 Spring Gateway 远程代码执行漏洞的核心场景与细节，未包含修复建议，仅聚焦漏洞本身的成因、场景、影响等维度。


# Spring 全家桶专项审计手册（Boot / Security / Cloud / MVC）

> 定位：Java 企业应用事实标准底座——专项覆盖 Spring Boot（actuator/配置）、Spring MVC
> （视图/路由/数据绑定）、Spring Security（认证授权）、Spring Cloud（网关/函数）。
> 锁版本：`spring-boot-starter-parent`、`spring-framework`、`spring-cloud` 三处版本对照。

## 已知漏洞面清单（逐项核对）

1. **Actuator 暴露面**：
   - `env`/`configprops`：配置与凭据泄露；`heapdump`：内存快照可解析出明文密码/token；
   - `jolokia`（配合注册的 MBean）：文件写/SpEL → RCE 链；
   - `gateway` 端点 + Spring Cloud Gateway：路由添加 + SpEL 断言 → RCE
     （CVE-2022-22947 形态——actuator 暴露是前置）；
   - 核对点：`management.endpoints.web.exposure` 清单、管理端口是否独立、是否有鉴权。
2. **Spring Cloud Function SpEL**：路由/函数头可控 SpEL 执行（CVE-2022-22963 形态）。
3. **Spring4Shell（数据绑定 RCE）**：JDK9+ + WAR 部署 + 参数绑定到 ClassLoader 属性
   （CVE-2022-22965 形态）——条件四件套全列，缺一不成立（多数场景不满足，如实标注）。
4. **SpEL 注入面（业务代码）**：`SpelExpressionParser.parseExpression(` 参数含用户输入；
   `@Value` 注入点；消息模板/规则引擎场景的动态表达式。
5. **Spring Security 配置缺陷**：
   - `permitAll()`/`antMatchers` 通配错配（`/**` 早于具体规则=全放行）；
   - 路径绕过：URL 编码/分号/双斜杠历史绕过形态（版本相关）；
   - CSRF 关闭面、会话固定、remember-me 密钥硬编码。
6. **视图名注入（MVC）**：Controller 返回值拼进视图名 + Thymeleaf/Freemarker 视图解析
   → SSTI（`return "redirect:" + user` 类形态同样过一遍解析链）。
7. **装配生态面**：H2 console（`spring.h2.console.enabled`）、XStream、内嵌 Fastjson
   版本——对照各自专项核对。

## Sink 快速核对

- grep `parseExpression(` / `StandardEvaluationContext`（对比 `SimpleEvaluationContext`
  受限形态——用 Standard 且入参可控=候选）；
- grep `antMatchers`/`requestMatchers` 全量清单与路由清单对账（未覆盖路由=越权候选）；
- `@RequestParam`/POJO 绑定字段直进 `Runtime.exec`/文件路径/模板。

## 审计流程建议

锁三处版本 → 上表七面逐项核（actuator 清单第一——它常是其他面的入口）→ 业务侧 SpEL
与视图名 grep → Security 规则对账 → 覆盖矩阵登记。利用条件纪律同 `jeecg-boot.md`。

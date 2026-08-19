# Java语言Swagger信息泄露漏洞

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`java_swagger_misconfig` · 类别：infoleak · 关键 sink：（cypher 结构提取，见原文）
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。

## Java语言Swagger信息泄露漏洞
Swagger（通常指Swagger 2.x/Springfox、OpenAPI 3.x/SpringDoc）是Java生态中主流的API文档自动生成工具，其核心通过注解扫描、配置解析自动生成可视化API文档（如/swagger-ui.html、/v3/api-docs等端点），方便开发调试，但配置或使用不当会导致**敏感信息泄露**，成为攻击者的信息收集入口。以下从漏洞本质、触发场景、泄露内容、影响范围、典型案例等维度完整描述该漏洞。

## 一、漏洞核心本质
Swagger信息泄露的本质是：**生产环境中未对Swagger的文档访问端点、元数据接口做严格的访问控制/禁用处理，或Swagger配置中包含敏感业务字段/接口信息，导致未授权攻击者可通过公开的HTTP端点获取完整的API设计细节**，进而为后续的越权访问、参数注入、业务逻辑攻击等提供关键信息。

## 二、漏洞触发的核心场景
### 场景1：生产环境未禁用Swagger相关端点（最常见）
Java项目中集成Swagger后，默认会暴露多个HTTP端点，若开发/运维人员仅在测试环境开启Swagger，但上线生产环境时未移除依赖、未禁用端点，会导致这些端点对外可访问。
#### 1.1 不同Swagger版本的默认暴露端点
| Swagger版本/框架       | 核心暴露端点                          | 功能说明                                  |
|------------------------|---------------------------------------|-------------------------------------------|
| Springfox（Swagger 2.x） | /swagger-ui.html（可视化界面）        | 可交互式查看、调试所有API接口              |
|                        | /swagger-ui/（兼容端点）              | 同上                                      |
|                        | /v2/api-docs（JSON格式元数据）        | 返回所有API的结构化信息（路径、参数、返回值） |
|                        | /swagger-resources（资源列表）        | 返回Swagger配置的资源分组、端点路径        |
| SpringDoc（OpenAPI 3.x） | /swagger-ui/index.html（可视化界面）  | OpenAPI 3.x的可视化界面                   |
|                        | /v3/api-docs（JSON格式元数据）        | 返回OpenAPI 3.x规范的API元数据            |
|                        | /v3/api-docs/swagger-config（配置信息）| Swagger UI的配置参数                      |
#### 1.2 触发条件
- 项目打包部署时未排除Swagger依赖（如springfox-swagger2、springdoc-openapi-starter-webmvc-ui）；
- 未通过配置文件（application.yml/application.properties）禁用Swagger；
- 未通过拦截器/过滤器/网关限制Swagger端点的访问来源；
- 服务器未配置反向代理/防火墙规则屏蔽Swagger端点。

### 场景2：Swagger注解包含敏感业务信息
即使限制了Swagger界面的访问，若Swagger注解中明文写入敏感信息，且元数据接口（如/v2/api-docs）未完全禁用，攻击者仍可通过解析JSON元数据获取敏感内容。
#### 2.1 典型敏感信息类型
- **业务敏感字段**：接口参数/返回值中包含手机号（mobile）、身份证号（idCard）、银行卡号（bankCard）、密码（password）、token、用户隐私数据（如地址、邮箱）等字段，且Swagger注解（@ApiParam、@ApiModelProperty）未脱敏；
- **接口逻辑细节**：@ApiOperation注解中描述了接口的业务逻辑（如“用户密码重置接口，无需验证旧密码”“管理员后台越权查询用户数据接口”）；
- **环境信息**：@Api注解中包含数据库表名、缓存key、第三方接口密钥（如支付接口的appId）、内部服务地址等；
- **版本/技术栈信息**：API元数据中泄露Java框架版本（如Spring Boot 2.6.0）、数据库类型（MySQL/Oracle）、接口认证方式（如JWT密钥过期时间、Basic Auth未加密）。
#### 2.2 示例代码（含敏感信息）
```java
@RestController
@Api(tags = "用户核心接口", description = "包含用户密码重置、身份证信息查询，数据库表：t_user")
@RequestMapping("/user")
public class UserController {

    @PostMapping("/resetPassword")
    @ApiOperation(value = "重置用户密码", notes = "无需验证旧密码，仅需手机号，接口密钥：abc123")
    public Result resetPassword(
            @ApiParam(value = "用户手机号", required = true) @RequestParam String mobile,
            @ApiParam(value = "新密码（明文传输）", required = true) @RequestParam String newPwd) {
        // 业务逻辑
        return Result.success();
    }
}
```
上述代码中，Swagger注解直接暴露了“无需验证旧密码”的逻辑缺陷、数据库表名、接口密钥、明文传输密码等敏感信息。

### 场景3：Swagger配置不当导致范围过大
Swagger支持通过`@EnableSwagger2`（Springfox）/`@OpenAPIDefinition`（SpringDoc）配置扫描包路径，若配置为扫描整个项目（如`basePackage = "com.example"`），会导致：
- 内部管理接口（如/admin/**、/backstage/**）被纳入Swagger文档，暴露给外部；
- 测试用接口（如/test/**、/debug/**）未过滤，泄露测试环境的业务逻辑；
- 第三方集成接口（如对接支付、短信的内部接口）被公开，泄露对接参数和逻辑；
- 甚至包含未上线的草稿接口，泄露未公开的业务规划。

### 场景4：Swagger UI未做认证授权
部分开发人员虽在生产环境保留Swagger，但仅通过“隐藏路径”（如修改Swagger UI路径为/swagger-admin.html）试图规避，未做任何认证（如Basic Auth、Token认证），攻击者可通过目录遍历、fuzz测试发现该路径，进而访问完整文档。
- 典型案例：某项目将Swagger UI路径改为/swagger-123.html，但未配置认证，攻击者通过扫描常见Swagger路径变体（如/swagger、/swagger-ui、/api-docs）发现该端点；
- 更严重的情况：Swagger UI支持直接发送API请求（如调试POST /user/resetPassword），攻击者可直接通过Swagger UI调用接口，结合泄露的参数信息实施攻击。

### 场景5：多环境配置未隔离
Java项目通常区分dev（开发）、test（测试）、prod（生产）环境，但配置文件未做环境隔离：
- 示例：application.yml中未通过`spring.profiles.active`区分环境，Swagger的启用配置（如`swagger.enabled=true`）全局生效，导致生产环境自动开启Swagger；
- 配置错误案例：
  ```yaml
  # 错误配置：全局启用Swagger，未区分环境
  swagger:
    enabled: true
    title: 生产环境API文档
    base-package: com.example
  ```
  正确的隔离配置应通过profile区分，但错误配置会导致生产环境直接启用。

### 场景6：依赖包版本漏洞间接导致泄露
部分老旧Swagger依赖包存在自身的漏洞，导致信息泄露：
- Springfox 2.9.2及以下版本：存在路径遍历漏洞，攻击者可通过构造特殊请求（如/v2/api-docs?group=../../../../etc/passwd）读取服务器本地文件，结合Swagger元数据进一步泄露信息；
- SpringDoc 1.0.0-1.4.0版本：存在配置泄露漏洞，可通过/v3/api-docs/swagger-config获取应用的上下文路径、端口、环境变量等信息；
- 依赖传递漏洞：Swagger依赖的第三方包（如swagger-core、jackson-databind）存在反序列化漏洞，攻击者可通过Swagger端点触发漏洞，进而获取服务器敏感信息。

## 三、泄露内容的类型与危害
### 3.1 泄露内容分类
| 泄露内容类型       | 具体示例                                  |
|--------------------|-------------------------------------------|
| API路径与方法      | /user/resetPassword（POST）、/admin/queryAllUser（GET） |
| 参数信息           | 参数名、是否必填、数据类型、默认值、示例值  |
| 返回值结构         | 包含敏感字段的JSON结构（如{idCard:"110xxxx", mobile:"138xxxx"}） |
| 业务逻辑           | 接口功能、权限校验规则、数据流向、缺陷逻辑  |
| 技术实现细节       | 数据库表名、缓存key、接口密钥、认证方式    |
| 环境配置           | 服务器端口、数据库连接信息、框架版本       |
| 内部接口           | 管理后台、数据统计、日志查询接口           |

### 3.2 危害程度
- **低危**：仅泄露无敏感信息的公开接口文档，无直接安全风险；
- **中危**：泄露业务字段名称、接口逻辑，为攻击者提供攻击方向；
- **高危**：泄露敏感业务接口（如密码重置、资金操作）、认证信息、接口密钥，攻击者可直接利用该信息实施越权、注入、盗刷等攻击；
- **严重**：泄露服务器配置、本地文件路径，结合其他漏洞（如文件读取、反序列化）可导致服务器被入侵。

## 四、影响范围
- **框架范围**：所有基于Spring Boot/Spring MVC集成Swagger 2.x（Springfox）、OpenAPI 3.x（SpringDoc）的Java项目；
- **部署环境**：云原生应用（K8s部署）、传统Tomcat/Jetty部署、微服务架构（Spring Cloud）均可能受影响；
- **业务领域**：金融、电商、政务、医疗等涉及敏感数据的行业，泄露后果更严重。

## 五、典型触发路径（攻击者视角）
1. 攻击者扫描目标域名的常见Swagger端点：如`https://target.com/swagger-ui.html`、`https://target.com/v2/api-docs`；
2. 若端点可访问，直接查看Swagger UI可视化界面，收集所有API接口信息；
3. 若Swagger UI不可访问，访问JSON元数据端点（如/v2/api-docs），解析JSON内容提取敏感信息；
4. 结合泄露的接口信息，构造攻击请求（如利用“无需验证旧密码”的逻辑重置用户密码）；
5. 若发现Swagger配置不当，进一步扫描内部接口、测试接口，扩大攻击面。

## 六、特殊情况：隐式泄露
部分场景下Swagger本身未直接暴露，但间接泄露信息：
- Swagger生成的API文档被搜索引擎收录（如百度、Google索引了/swagger-ui.html），攻击者通过搜索引擎直接获取；
- 项目文档（如Confluence、GitHub）中包含Swagger文档链接，被公开泄露；
- 前端代码（如Vue/React项目）中硬编码了Swagger的/api-docs端点地址，攻击者通过前端源码发现该端点；
- 日志泄露：服务器访问日志中包含/swagger-ui.html的访问记录，攻击者通过泄露的日志发现Swagger存在。



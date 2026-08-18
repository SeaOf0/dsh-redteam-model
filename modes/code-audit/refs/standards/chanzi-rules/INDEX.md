# 规则知识库索引

> 122 条 Java 生态漏洞规则的语义知识正文，按类别分目录存放；cypher 查询本体不在本目录（依赖语义查询引擎，无法离线重放）。
> 使用方式：按类别/规则 ID 用 read 直接读取；与 refs/standards/fortify-kingdom-reference.md
> （定级与分类）及 lang/*/semgrep-rules/（可执行规则）配合。


共 122 条规则。


## cmdi（5 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `any_any_cmdi` | Java 命令注入漏洞 完整解析 | ExecuteShellUtil, ExecuteShellUtils, ProcessBuilder, Runtime, command |
| `other_any_cmdi` | Java 命令注入漏洞 完整解析 | ExecuteShellUtil, ExecuteShellUtils, ProcessBuilder, Runtime, command |
| `readobject_any_cmdi` | Java `readObject` 不安全实现的安全漏洞 | Class, Method, ProcessBuilder, Runtime, command |
| `socket_any_cmdi` | Java 命令注入漏洞 完整解析 | ProcessBuilder, Runtime, command, exec |
| `websocket_any_cmdi` | Java 命令注入漏洞 完整解析 | ProcessBuilder, Runtime, command, exec |

## codei（25 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `any_BeanShell_codei` | Java语言BeanShell RCE（远程代码执行）漏洞全解析 | Interpreter, eval, source |
| `any_ScriptEngine_codei` | Java ScriptEngine 注入漏洞 | Context, ScriptEngine, ScriptEngineFactory, eval, evaluateString |
| `any_el_codei` | Java EL注入漏洞（Expression Language Injection）完整解析 | ExpressionFactory, createValueExpression |
| `any_groovyshell_codei` | Java中GroovyShell代码执行漏洞 完整描述 | GroovyClassLoader, GroovyShell, TemplateEngine, createTemplate, evaluate |
| `any_jshell_codei` | Java JShell 代码执行漏洞 完整描述 | JShell, eval |
| `any_mvel_codei` | MVEL表达式注入漏洞 完整描述 | MVEL, eval |
| `any_ognl_codei` | OGNL表达式注入漏洞（Java） | getValue |
| `any_qlexpress_codei` | Java QLExpress 表达式注入漏洞 | ExpressRunner, execute |
| `any_reflect_codei` | Java 不安全的反射调用漏洞：完整描述与典型场景 | Class, Method, forName, invoke |
| `any_spel_codei` | Java SPEL注入漏洞 | ExpressionParser, SpelExpressionParser, TemplateAwareExpressionParser, parseExpression |
| `other_BeanShell_codei` | Java语言BeanShell RCE（远程代码执行）漏洞 | Interpreter, eval, source |
| `other_ScriptEngine_codei` | Java ScriptEngine 注入漏洞 | Context, ScriptEngine, ScriptEngineFactory, eval, evaluateString |
| `other_el_codei` | Java EL注入漏洞（Expression Language Injection）完整解析 | ExpressionFactory, createValueExpression |
| `other_groovyshell_codei` | Java中GroovyShell代码执行漏洞 完整描述 | GroovyClassLoader, GroovyShell, TemplateEngine, createTemplate, evaluate |
| `other_jshell_codei` | Java JShell 代码执行漏洞 完整描述 | JShell, eval |
| `other_mvel_codei` | MVEL表达式注入漏洞 完整描述 | MVEL, eval |
| `other_ognl_codei` | OGNL表达式注入漏洞（Java） | getValue |
| `other_qlexpress_codei` | Java QLExpress 表达式注入漏洞 | ExpressRunner, execute |
| `other_reflect_codei` | Java 不安全的反射调用漏洞：完整描述与典型场景 | Class, Method, forName, invoke |
| `other_spel_codei` | Java SPEL注入漏洞 | ExpressionParser, SpelExpressionParser, TemplateAwareExpressionParser, parseExpression |
| `pom_jxpath_codei` | Apache Commons JXPath 远程代码执行漏洞（RCE）完整描述 | — |
| `pom_log4j_codei` | Log4j 远程代码执行漏洞（CVE 相关）完整描述 | — |
| `pom_springgateway_codei` | Java Spring Gateway 远程代码执行（RCE）漏洞 | — |
| `pom_struts2_codei` | Java Struts2 远程代码执行（RCE）漏洞 | — |
| `pom_xxljob_codei` | XXL-Job-Core 安全漏洞全量描述（Java 语言） | — |

## cookie（1 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `cookie_response_cookiesecure` | 身份凭据Cookie未设置HttpOnly漏洞 问题描述 | addCookie, setCookie |

## cors（2 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `asterisk_alloworigin_cors` | Java 语言中“允许任意地址CORS”漏洞 | — |
| `origin_alloworigin_cors` | Java 反射型CORS漏洞 | setHeader |

## deser（19 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `any_XMLDecoder_deserialization` | Java XMLDecoder反序列化漏洞 完整描述 | — |
| `any_fastjson_deserialization` | Java Fastjson反序列化漏洞 | parseObject |
| `any_hessian_deserialization` | Java Hessian反序列化漏洞 完整技术描述 | deserialize |
| `any_java_deserialization` | Java反序列化漏洞全解析 | — |
| `any_snakeyaml_deserialization` | Java语言SnakeYAML反序列化漏洞 | Yaml, dump, load |
| `any_xstream_deserialization` | Java XStream 反序列化漏洞完整描述 | XStream, fromXML |
| `other_XMLDecoder_deserialization` | Java XMLDecoder反序列化漏洞 完整描述 | — |
| `other_fastjson_deserialization` | Java Fastjson反序列化漏洞 | parseObject |
| `other_java_deserialization` | Java反序列化漏洞 | — |
| `other_snakeyaml_deserialization` | Java语言SnakeYAML反序列化漏洞 | Yaml, dump, load |
| `other_xstream_deserialization` | Java XStream 反序列化漏洞完整描述 | XStream, fromXML |
| `pom_dubbo_deserialization` | Java Dubbo反序列化漏洞 | — |
| `pom_fastjson_deserialization` | Java Fastjson反序列化漏洞 | — |
| `pom_jacksondatabind_deserialization` | Java Jackson 反序列化漏洞完整描述 | — |
| `pom_shiro_deserialization` | Java Shiro反序列化漏洞 | — |
| `pom_snakeyaml_deserialization` | Java语言SnakeYAML反序列化漏洞 | — |
| `pom_xstream_deserialization` | Java XStream 反序列化漏洞完整描述 | — |
| `socket_java_deserialization` | Java反序列化漏洞 | — |
| `websocket_any_deserialization` | Java反序列化漏洞 | — |

## hpe（4 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `id_jdbc_hpe` | Java 语言水平越权漏洞 | PreparedStatement, Statement, executeQuery |
| `id_jdbctemplate_hpe` | Java 语言水平越权漏洞 | JdbcOperations, JdbcTemplate, query, queryForList, queryForMap |
| `id_mybatis_hpe` | Java 语言水平越权漏洞 | SqlRunner, selectAll, selectBatchIds, selectById, selectOne |
| `id_otherdbquery_hpe` | Java 语言水平越权漏洞 | EntityManager, QueryProducer, Session, createNativeQuery, createQuery |

## infoleak（2 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `exception_any_infoleak` | Java 异常堆栈信息泄露漏洞 完整描述 | HttpServletResponse, Model, PrintWriter, ServletOutputStream, addAttribute |
| `java_swagger_misconfig` | Java语言Swagger信息泄露漏洞 | — |

## jndii（2 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `any_jndi_jndii` | Java Naming and Directory Interface (JNDI) 注入漏洞完整解析 | InitialContext, lookup |
| `other_jndi_jndii` | Java Naming and Directory Interface (JNDI) 注入漏洞完整解析 | InitialContext, lookup |

## ldapi（2 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `any_any_ldapi` | Java语言LDAP注入漏洞全解析 | DirContext, InitialDirContext, search |
| `other_any_ldapi` | Java语言LDAP注入漏洞 | DirContext, InitialDirContext, search |

## misconfig（8 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `any_hash2_weekhash` | Java 弱 Hash 加密算法漏洞：完整描述 | md5Hex, sha1Hex |
| `config_actuator2_misconfig` | Java Spring Boot Actuator 未授权访问漏洞全量描述 | — |
| `config_actuator_misconfig` | Java Spring Boot Actuator 未授权访问漏洞全量描述 | — |
| `config_druid_misconfig` | Java Druid监控页面未授权访问漏洞 完整描述 | — |
| `config_h2_misconfig` | Java 语言 H2 Database Console 未授权访问漏洞 完整描述 | — |
| `java_druid_misconfig` | Java Druid监控页面未授权访问漏洞 完整描述 | StatViewServlet, setEnabled |
| `other_hash2_weekhash` | Java 弱 Hash 加密算法漏洞：完整描述 | md5Hex, sha1Hex |
| `xml_druid_misconfig` | Java Druid监控页面未授权访问漏洞 完整描述 | — |

## secret（9 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `config_secret_hardcode` | Java 密钥硬编码漏洞 完整描述 | — |
| `config_secret_weekpass` | Java应用依赖服务弱口令漏洞全维度描述 | — |
| `java_secret2_hardcode` | Java 密钥硬编码漏洞 完整描述 | — |
| `java_secret2_weekpass` | Java应用依赖服务弱口令漏洞全维度描述 | — |
| `java_secret_hardcode` | Java 密钥硬编码漏洞 完整描述 | getConnection, setAccessKeySecret, setLoginPassword, setPass, setPassword |
| `xml_secret2_hardcode` | Java 密钥硬编码漏洞 完整描述 | — |
| `xml_secret2_weekpass` | Java应用依赖服务弱口令漏洞全维度描述 | — |
| `xml_secret_hardcode` | Java 密钥硬编码漏洞 完整描述 | — |
| `xml_secret_weekpass` | Java应用依赖服务弱口令漏洞全维度描述 | — |

## sqli（9 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `any_jdbc_sqli` | Java JDBC SQL注入漏洞 | Connection, Statement, execute, executeQuery, executeUpdate |
| `any_jdbctemplate_sqli` | Java JdbcTemplate SQL注入漏洞 | JdbcOperations, JdbcTemplate, batchUpdate, execute, query |
| `any_jpa_sqli` | Java JPA SQL注入漏洞 | EntityManager, createNativeQuery |
| `any_mybatis_sqli` | MyBatis SQL注入漏洞完整描述 | — |
| `any_mybatisplus_sqli` | MyBatis-Plus SQL注入漏洞 | EntityWrapper, LambdaQueryWrapper, LambdaUpdateWrapper, QueryWrapper, UpdateWrapper |
| `other_jdbc_sqli` | Java JDBC SQL注入漏洞 | Connection, Statement, execute, executeQuery, executeUpdate |
| `other_jdbctemplate_sqli` | Java JdbcTemplate SQL注入漏洞 | JdbcOperations, JdbcTemplate, batchUpdate, execute, query |
| `other_jpa_sqli` | Java JPA SQL注入漏洞 | EntityManager, createNativeQuery |
| `other_mybatis_sqli` | MyBatis SQL注入漏洞完整描述 | — |

## ssrf（4 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `any_any_ssrf` | Java 语言 SSRF 漏洞全解析 | AbstractHttpClient, AbstractRequestBuilder, AsyncRestTemplate, BasicDataSource, Call |
| `any_socket_ssrf` | Java Socket 类型 SSRF 漏洞解析 | Socket, connect |
| `other_any_ssrf` | Java 语言 SSRF 漏洞 | AbstractHttpClient, AbstractRequestBuilder, AsyncRestTemplate, BasicDataSource, Call |
| `other_socket_ssrf` | Java Socket 类型 SSRF 漏洞解析 | Socket, connect |

## ssti（10 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `any_activiti_ssti` | Java语言Activiti模型注入漏洞 | DeploymentBuilder, ExpressionManager, RepositoryService, RuntimeService, TaskService |
| `any_freemarker_ssti` | Java 语言 FreeMarker 模板注入漏洞（FreeMarker Template Injection, FTI）完整描述 | FreeMarkerTemplateUtils, Template, processTemplate, processTemplateIntoString, putTemplate |
| `any_thymeleaf_ssti` | Java语言Thymeleaf模板注入漏洞 | process, processThrottled |
| `any_velocity_ssti` | Java Velocity模板注入漏洞 完整描述 | evaluate, mergeTemplate, parse |
| `other_activiti_ssti` | Java语言Activiti模型注入漏洞 | RepositoryService, RuntimeService, saveModel, startProcessInstanceByKey |
| `other_freemarker_ssti` | Java 语言 FreeMarker 模板注入漏洞（FreeMarker Template Injection, FTI）完整描述 | putTemplate |
| `other_thymeleaf2_ssti` | springboot Thymeleaf 模板注入漏洞 | — |
| `other_thymeleaf_ssti` | Java语言Thymeleaf模板注入漏洞 | process, processThrottled |
| `other_velocity_ssti` | Java Velocity模板注入漏洞 完整描述 | evaluate, mergeTemplate, parse |
| `spring_thymeleaf_ssti` | springboot Thymeleaf 模板注入漏洞 | — |

## traversal（2 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `any_any_pathtraver` | Java语言目录穿越漏洞全解析 | File, FileInputStream, FileReader, FileSystemResource, FileUtils |
| `other_any_pathtraver` | Java语言目录穿越漏洞 | File, FileInputStream, FileReader, FileSystemResource, FileUtils |

## upload（4 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `any_any_upload` | Java 文件上传漏洞 | BufferedOutputStream, ByteSource, File, FileItem, FileOutputStream |
| `any_oss_upload` | 对象存储（OSS）上传任意文件的安全问题 | BlobClient, BosClient, COSClient, CfsClient, FileClient |
| `jfinal_any_upload` | Java 文件上传漏洞 | BufferedOutputStream, ByteSource, File, FileItem, FileOutputStream |
| `other_oss_upload` | 对象存储（OSS）上传任意文件的安全问题 | BlobClient, COSClient, OSSClient, S3Client, Storage |

## urlredirect（2 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `any_any_urlredirect` | Java 语言 URL 重定向漏洞完整解析 | HttpHeaders, sendRedirect, setLocation |
| `other_any_urlredirect` | Java 语言 URL 重定向漏洞完整解析 | HttpHeaders, sendRedirect, setLocation |

## weekhash（2 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `any_hash_weekhash` | Java 弱 Hash 加密算法漏洞：完整描述 | — |
| `other_hash_weekhash` | Java 弱 Hash 加密算法漏洞：完整描述 | — |

## xss（8 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `any_any_xss` | Java语言中的XSS漏洞 | PrintWriter, format, printf, println |
| `any_freemarker_xss` | Java语言中FreeMarker XSS漏洞完整描述 | FreeMarkerTemplateUtils, Template, process, processTemplate, processTemplateIntoString |
| `any_velocity_xss` | Java Velocity XSS漏洞 完整描述 | Template, merge |
| `jsp_any_xss` | Java JSP XSS漏洞 | PrintWriter, ServletOutputStream, append, format, print |
| `other_any_xss` | Java语言中的XSS漏洞 | PrintWriter, format, printf, println |
| `other_freemarker_xss` | Java语言中FreeMarker XSS漏洞完整描述 | Template, process |
| `other_velocity_xss` | Java Velocity XSS漏洞 完整描述 | Template, merge |
| `spring_templet_xss` | Java Spring MVC 中模版引擎渲染场景下XSS漏洞（仅描述漏洞场景，无修复建议） | Model, ModelAndView, ModelMap, addAttribute, addObject |

## xxe（2 条）

| 规则 ID | 标题 | 关键 sink |
|---|---|---|
| `any_any_xxe` | Java XXE漏洞完整解析 | Digester, DocumentBuilder, DocumentHelper, DocumentProvider, Formatter |
| `other_any_xxe` | Java XXE漏洞完整解析 | Digester, DocumentBuilder, DocumentHelper, DocumentProvider, Formatter |
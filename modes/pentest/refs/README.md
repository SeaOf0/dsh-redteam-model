# pentest 参考手册库（refs/）

> 本目录随 pentest 预设打包分发。所有文件为预设内自包含资源，不依赖任何机器特定路径。
> 定位：手册库——pentest-playbook 是速查卡，这里的文件是深度手册与资产（字典/行业清单/payload 库）；
> 需要细节时用 read 直接读取。
> 路径解析：加载 pentest-playbook 技能时你会得到该技能的 base 目录（SKILL.md 所在目录，
> 即 `skills/pentest-playbook/`）；refs/ 相对 base 目录 = `../../refs/`。
> 覆盖面：Web / API / 移动 App / 小程序 / 组件与中间件 / AI 应用 / 中文资产与行业清单 /
> WAF 对抗 / 口令攻击 / 趋势。共 100 篇。

## 快速路由（按任务类型找目录）

| 任务类型 | 目录 |
|---|---|
| Web 应用渗透（注入/XSS/认证/走私/缓存/文件/逻辑…） | `web/`（37 篇） |
| API 渗透（侦察/BOLA/GraphQL/WebSocket/HTTP2/fuzz…） | `api/`（10 篇）+ `web/web-api-security.md` |
| 移动 App 渗透（Android/iOS/SSL Pinning） | `mobile/`（5 篇） |
| 小程序渗透（微信小程序全流程） | `miniprogram/`（5 篇） |
| 组件/中间件/框架/数据库（fastjson/shiro/中间件/JNDI/未授权服务） | `components/`（8 篇，含默认值审计+修复 diff 盲区方法论） |
| 中文环境资产（国产指纹/默认口令/越权/逻辑/信息泄露/WAF payload/行业清单/工具命令） | `zh/`（24 篇） |
| AI/LLM 应用测试（注入/越狱/RAG 投毒/系统提示词提取/Agent 与 MCP/模型层/AI 基础设施/非预期挖掘技巧） | `ai/`（8 篇） |
| 拿到入口后（初始访问/提权/哈希攻击） | `offensive/`（3 篇） |
| CDN 溯源 | `cdn/`（2 篇） |
| 2025–2026 风向校准 | `trends/`（1 篇） |

## 目录索引

### web/（37 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| web-pentest-comprehensive.md | Web 渗透完整手册：WSTG/PTES/OSSTMM 流程、WAF 绕过五类手法、扫描器结果分析 | 综合流程、扫描结果研判 |
| web-injection-sqli.md | SQL 注入全解（全数据库/盲注/带外/sqlmap/WAF 绕过） | 注入点验证 |
| web-injection-xss.md | XSS 全解（存储/反射/DOM） | XSS 测试 |
| web-injection-ssrf.md | SSRF 全解 | 内网探测/云元数据场景 |
| web-injection-xxe-ssti-nosql.md | XXE / SSTI / NoSQL 注入 | 对应模板/解析器场景 |
| cmdi-command-injection.md | OS 命令注入：shell 元字符全集、盲注/OOB 外带、多语言 payload | 输入可能到达 shell/进程执行/转换器 |
| crlf-injection.md | CRLF 注入：响应头拆分、Location/Set-Cookie/日志注入 | 响应头含用户输入时 |
| http-host-header-attacks.md | Host 头注入与路由滥用：密码重置投毒、缓存投毒、路由 SSRF | 应用信任 Host 生成 URL/路由时 |
| http-parameter-pollution.md | HPP 参数污染：服务器/代理/WAF 解析不一致、绕过与逻辑滥用 | 过滤层与应用层取值分歧时 |
| email-header-injection.md | 邮件头注入与伪造：CRLF、SPF/DKIM/DMARC 绕过 | 表单/重置流程构造 SMTP 时 |
| expression-language-injection.md | 表达式注入：Java EL/SpEL/OGNL/MVEL（Spring/Struts2/Confluence） | Java 表达式求值面 |
| xslt-injection.md | XSLT 注入：处理器指纹、XXE/SSRF、EXSLT 写原语、扩展 RCE | XSLT/样式书可控时 |
| ldap-injection.md | LDAP 注入测试（中文） | 登录/搜索走 LDAP 时 |
| xpath-injection.md | XPath 注入测试（中文） | XML 查询面 |
| path-traversal-lfi.md | 路径穿越与 LFI：下载点/包含/压缩包解压/wrapper | 文件路径可控时 |
| web-file-handling.md | 文件上传/处理漏洞 | 上传点测试 |
| web-deserialization.md | 反序列化攻击 | Java/.NET/PHP 反序列化 |
| web-auth-bypass.md | 认证绕过：JWT 全系、OAuth/OIDC/SAML、MFA、会话管理 | 登录/SSO/API 认证测试 |
| race-condition.md | 竞态与 TOCTOU：单包攻击（HTTP/2）、Turbo Intruder、限购/余额绕过 | 一次性操作/并发滥用 |
| type-juggling.md | PHP 类型混淆（`==` 弱比较/HMAC 绕过） | PHP 鉴权/签名校验 |
| prototype-pollution.md | 原型污染基础：merge/query parser 污染入口 | JS 栈对象合并面 |
| prototype-pollution-advanced.md | 原型污染进阶：服务端 RCE gadget、客户端 gadget、过滤绕过 | 已确认污染要升级利用时 |
| open-redirect.md | 开放重定向：参数/sink 全集 | 跳转参数可控时 |
| web-csrf-cors-clickjacking.md | CSRF / CORS / 点击劫持 | 前端安全面测试 |
| csp-bypass-advanced.md | CSP 绕过：策略弱点、可信端点滥用、nonce 泄露、CSP 挡不住的外带通道 | XSS 被 CSP 挡住时 |
| dangling-markup-injection.md | 悬挂标记注入：无 JS 执行下的 CSRF token/会话数据外带 | HTML 注入可行但 script 被过滤时 |
| csv-formula-injection.md | CSV/表格公式注入（DDE/IMPORT*） | 导出/导出物进表格时 |
| web-request-smuggling.md | HTTP 请求走私全解 | 走私疑点排查 |
| web-cache-attacks.md | Web 缓存投毒与缓存欺骗 | 缓存/CDN 场景 |
| dns-rebinding-attacks.md | DNS rebinding：绕过同源/内网服务访问检查 | SSRF 不可行但浏览器侧可控时 |
| subdomain-takeover.md | 子域接管：悬挂 CNAME/NS/MX 检测与利用 | 资产清理后的悬挂记录 |
| waf-bypass-techniques.md | WAF 绕过方法论（编码/协议层/WAF 特性弱点） | payload 被 WAF 拦截时 |
| waf-product-matrix.md（WAF_PRODUCT_MATRIX.md） | WAF 产品级绕过矩阵：Cloudflare/AWS WAF/ModSecurity/Akamai/Imperva/F5/Sucuri 各「指纹/解析差异/盲区 payload/判据」四段式 | 已识别 WAF 厂商、通用手法失效时 |
| honeypot-detection.md | Web 蜜罐/假 WAF 指纹/canary token 识别与反投喂 | 目标「过于配合」、诱饵内容可疑时 |
| web-logic-vulns.md | 业务逻辑漏洞（支付/权限/流程） | 业务逻辑测试 |
| recon-and-methodology.md | 侦察与方法论：资产映射、端点发现、指纹、测试计划 | 新目标开测第一步 |
| web-api-security.md | API 全景：BOLA/BFLA、GraphQL、Shadow API、gRPC、限流绕过、大规模赋值 | API 测试总览（细节转 api/） |

### api/（10 篇，api-auth 增 client_credentials 弱口令面）

| 文件 | 内容 | 何时读 |
|---|---|---|
| api-recon-and-docs.md | API 侦察与文档审查：端点/Schema/版本/OpenAPI/隐藏文档发现 | API 开测第一步 |
| api-auth-and-jwt-abuse.md | API 认证滥用：Bearer/API Key/声明信任/头伪造/限流边界 | API 认证测试 |
| api-authorization-and-bola.md | BOLA/BFLA 专项：A/B 账号回放、嵌套资源、隐藏字段、方法滥用 | 对象/函数级越权 |
| api-fuzzing.md | API fuzz：RESTler 状态化 fuzz、OpenAPI 驱动生成、字典策略 | API 参数面扩展 |
| graphql-and-hidden-parameters.md | GraphQL 深度滥用：内省/alias 批量绕过限速/persisted query/字段建议/batching/DoS 放大 + 隐藏参数 | GraphQL 或 REST 隐参 |
| websocket-security.md | WebSocket：握手、CSWSH、wsrepl/ws-harness/Burp 工具链 | 实时通道测试 |
| sse-security.md | SSE（Server-Sent Events）：跨源劫持、连接后不校验、事件流注入、重连令牌重放、SSE 走私 | 事件流/实时推送测试 |
| http2-specific-attacks.md | HTTP/2 专项：二进制分帧、HPACK、h2c 升级走私、伪头注入、降级翻译缺陷 | 目标支持 HTTP/2 时 |
| http3-quic-attacks.md | HTTP/3 / QUIC：h3 FIN/EOM desync、QPACK 表投毒、QUIC 走私（CVE-2026-33555）、伪头注入 | 目标支持 HTTP/3（Alt-Svc: h3）时 |
| grpc-security.md | gRPC：protobuf 反序列化、反射泄露、字段走私、metadata/deadline 滥用、gRPC-Web 降级面 | 目标暴露 gRPC/gRPC-Web 时 |

### mobile/（5 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| mobile-pentest-android.md | Android 渗透完整手册（1757 行）：环境、静态/动态、组件导出、WebView、Frida | Android App 测试主手册 |
| mobile-pentest-ios.md | iOS 渗透完整手册（1859 行）：越狱环境、Keychain、运行时操纵 | iOS App 测试主手册 |
| android-pentesting-tricks.md | Android 技巧集：SSL Pinning 绕过、导出组件滥用、Intent 重定向、root 检测绕过、备份提取 | Android 快速姿势 |
| ios-pentesting-tricks.md | iOS 技巧集：Keychain 提取、URL Scheme 劫持、Universal Links、二进制保护分析 | iOS 快速姿势 |
| mobile-ssl-pinning-bypass.md | 移动端 SSL Pinning 绕过：证书/公钥/SPKI 三类 pinning，含 RN/Flutter/Xamarin | 抓包被 pinning 挡住时 |

### miniprogram/（5 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| miniprogram-security-core.md | 小程序安全评估核心手册（3245 行）：CDP+Hook 流量采集、路由/接口资产盘点、IDOR/认证绕过/资金接口红线、加密参数破解、代码保护与硬编码凭据、全 Checklist | 小程序测试主手册（先读） |
| wmp-package-readme.md | 小程序全自动化打包版总览：工具组成与环境 | 了解工具链全貌 |
| e0e1wx-readme.md | 小程序工具链说明 | 同上 |
| e0e1wx-tools.md | 小程序工具清单与用法 | 选工具时 |
| wmpf-debugger.md | WMPFDebugger：PC 端微信小程序框架调试器 | PC 端调试小程序时 |

> 注：miniprogram 手册引用的 MCP 工具名（connection_ops/runtime_ops 等）来自 小程序源工具链，
> 本预设未随附该工具；方法论、Checklist 与手工路径通用。

### components/（8 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| java-framework-vulns.md | Java 框架漏洞：fastjson/shiro/struts2/log4j/spring 系列利用链 | Java 组件版本命中时 |
| middleware-vulns.md | 中间件漏洞：WebLogic/Tomcat/JBoss/WebSphere/nginx 等 | 中间件指纹确认后 |
| database-exploitation.md | 数据库利用：MySQL/MSSQL/Oracle/PostgreSQL/Redis 提权与后利用（授权内） | 拿到数据库口令/注入后 |
| jndi-injection.md | JNDI 注入：Log4j2/Spring/InitialContext.lookup 利用链 | Java JNDI 查询面 |
| unauthorized-access-common-services.md | 常见服务未授权访问：Redis/Rsync/PHP-FPM/AJP(Ghostcat)/Hadoop YARN/H2 等 | 端口命中服务清单时 |
| 容器/K8s 攻击面（2375/10250/etcd/registry、SA token→RBAC、逃逸存在性验证） | components/container-security.md |
| 云凭据后利用（AWS/阿里云等：验真→权限枚举→最小影响证明，第二跳链路） | components/cloud-postexploitation.md |
| component-default-config-audit.md | 组件挖掘方法论：配置默认值审计（黑名单覆盖面缺口）+ 修复 diff 双版本对比（修一半盲区追挖）+ 特殊 IP 语义绕过 + Flow 匿名触发面 + 版本尴尬期速查 | 组件指纹确认后、CVE 追更时 |

### zh/（中文手册与资产，24 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| unauth-access.md | 未授权访问/默认凭据专项 | 国内目标端口面初筛 |
| arbitrary-x-authz.md | 「任意 X」子授权：比 IDOR 更狠的权限维度漏洞 | 越权专项（水平/垂直/维度） |
| logic-flaws.md | 业务逻辑/越权/验证码/支付篡改深度手册（1796 行） | 逻辑漏洞主手册（含验证码对抗） |
| info-disclosure.md | 信息泄露/敏感文件/备份专项 | 敏感文件与泄露面 |
| dos.md | 最小流量证明型 DoS（615 行，100+ 份 H1 高危案例：Tomcat/Node/GitLab/WordPress 等） | 逻辑性资源耗尽 finding（不真打死目标，负面清单照常） |
| waf-bypass-payloads.md | WAF 绕过 payload 大全（6501 行，按场景组织） | 造绕过 payload 时 |
| waf-bypass-cn.md | 国产 WAF 指纹库与针对性绕过：阿里云/腾讯云/长亭雷池/宝塔/天融信/网宿/安全狗/云锁 | 目标为国产生态 WAF 时 |
| dynamic-waf-reverse.md | 动态 JS 混淆型 WAF（瑞数/数美类）对抗：逆向定位→签名还原→补环境重放 | 遇到动态挑战/行为验证类风控时 |
| default-credentials-cn.md | 国产服务/OA/CMS/网络设备默认凭据 | 国内目标登录面 |
| chinese-srcfingerprints.md | 国产组件指纹+路径+高频参数字典（OA/中间件） | 指纹识别与路径 fuzz |
| banking-finance.md | 银行/金融行业渗透 playbook | 金融行业目标 |
| telecom-isp.md | 电信/运营商/ISP 渗透 playbook | 运营商行业目标 |
| tools/tools-password-attacks.md | 口令攻击工具命令（Hydra 等 11 条：在线爆破/字典/规则） | 登录面弱口令测试（配合 default-credentials-cn） |
| tools/tools-web-pentest.md | Web 渗透工具命令（SQLMap 等 16 条 + nuclei 模板编写） | 工具选型与参数 |
| tools/tools-burp-plugin-ecosystem.md | Burp 插件生态清单（403 Bypasser/Hackvertor/IP Rotate/Logger++/JWT Editor 等） | 按测试场景选 Burp 插件 |
| tools/tools-recon.md | 信息收集工具命令（Nmap 等 20 条） | 侦察阶段 |
| tools/tools-exploitation.md | 漏洞利用工具命令（Metasploit 等 11 条，授权内） | 利用阶段 |
| tools/tools-encoding.md | 编码解码工具命令（Base64/URL/Hex/HTML/Unicode/JWT/冷门编码 UTF-7/16/NFKC） | payload 构造与绕过 |
| methodology/00-index.md | 方法论入口 | 读方法论族先看 |
| methodology/01-attack-priority.md | 攻击路径最短原则（黑盒猎手版） | 排测试优先级 |
| methodology/02-bypass-toolkit.md | 通用绕过工具箱（绕过的本质） | 各类绕过思路 |
| methodology/03-evidence-discipline.md | 黑盒证据纪律（与 persona 证据标准同构） | 证据与复现规范 |
| methodology/04-control-gap-hunting.md | 控制缺口（Control Gap）狩猎思维模型 | 越权/逻辑漏洞狩猎 |
| methodology/05-srctimebox-priority.md | SRC 时间盒优先级（22,132 案例统计的高危占比排序） | 时间有限时取舍 |

### ai/（8 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| ai-prompt-injection.md | 提示注入攻击面 | 目标含 LLM 功能时 |
| ai-jailbreak-techniques.md | 越狱技术 | AI 应用红队评估 |
| ai-rag-poisoning.md | RAG 安全：知识库投毒、向量索引污染、间接注入、跨会话泄露 | RAG/知识库型 AI 应用 |
| ai-system-prompt-extraction.md | 系统提示词提取：直接/间接泄露、context bleed、format injection | 提取与验证系统提示词 |
| ai-agent-safety.md | Agent/Multi-Agent 安全评估：工具滥用、间接注入经工具输出、Agent memory 投毒、MCP server 利用、多 agent 协作链（LangChain/AutoGen/CrewAI/MCP 场景） | Agent/MCP 架构目标（MCP 测试主手册） |
| ai-model-security.md | 模型层安全：模型投毒、对抗样本、模型求逆/提取、训练数据攻击、ML 供应链（含深伪检测） | 目标含自训模型/ML 管线时 |
| ai-infra-attack-surface.md | AI 基础设施攻击面：Milvus 认证绕过三洞（sourceid/9091/53100）+ 向量库拖库语义（向量+原文配套、相似度可恢复）、LiteLLM 网关、Langflow、AI 组件指纹与打点顺序 | RAG/AI 底座组件目标 |
| ai-assisted-hunting.md | 非预期挖掘技巧集：报错吐凭证、CDN 桶→真实桶溯源、base 服务业务语义枚举、业务字典构造、动态占位符参数、WAF 绕过推理生成（2026 社区实战提炼） | 挖掘卡壳/常规面打完不收工时对照 |

### offensive/（4 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| initial-access.md | 初始访问技术 | 突破入口构建（授权内） |
| privilege-escalation.md | 权限提升技术 | 拿 shell 后提权 |
| hash-attack-techniques.md | 哈希攻击：长度扩展、MD5/SHA1 碰撞、HMAC 时序、生日攻击 | 签名/哈希校验面与凭据破解 |
| capability-primitive-chaining.md | 能力原语拼图：read/write/exec/ssrf 原语抽象、RCE 六等式、低危→原语映射表、正反向状态空间搜索、突破口清单（功能即原语/跨协议跳跃/凭据复用/解析差异/跨域兑现） | 扫不到单点大洞的僵局；低危组合升链设计 |

### cdn/（2 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| README-fuck-cdn.md | CDN 溯源方案说明 | CDN 隐藏目标（先读这个） |
| fuck-cdn.md | CDN 溯源：找真实 IP 全套方法 | 同上 |

### trends/（1 篇）

| 文件 | 内容 | 何时读 |
|---|---|---|
| trends-2025-2026.md | OWASP Top 10:2025 与 LLM Top 10 2025 变化、agentic 渗透、Burp AI、反方观点；Next.js 中间件绕过类（CVE-2025-29927）与 MCP 安全工具链（MCP-Scan 等）（全部附来源，2026-08 核实） | 开测前校准知识新鲜度 |

## 来源与说明

- **web/ 前 13 篇 + mobile-pentest-android/ios + components 前 3 篇 + ai 前 2 篇 + offensive 前 2 篇**：
  ，
  按原文收录。
- **web/ 其余 22 篇 + api/ 7 篇 + mobile 3 篇技巧类 + components 2 篇 + offensive/hash-attack-techniques**：
  ，按原文收录，仅去掉 SKILL.md 目录壳。
- **zh/ 21 篇**：技能库的中文手册/字典/行业清单/方法论，按原文收录。
- **miniprogram/ 5 篇**：内容整理收录
  及 WMPFDebugger README），仅取文档，不含工具代码。
- **cdn/**：内容整理收录，仅保留 md 文档，截图已省略。
- **trends/**：playbook 自建（自建），条目联网核实并附来源链接。
- **自建补足（8 篇，内容自写）**：
  `web/WAF_PRODUCT_MATRIX.md`、`web/honeypot-detection.md`、`zh/waf-bypass-cn.md`、
  `zh/dynamic-waf-reverse.md`、`api/http3-quic-attacks.md`、`api/sse-security.md`、
  `api/grpc-security.md`、`zh/tools/tools-burp-plugin-ecosystem.md`；另扩写 8 篇既有文件
  （graphql/websocket 对齐、waf-bypass-techniques、waf-bypass-payloads、ssrf、ai-agent-safety、
  tools-web-pentest、web-cache-attacks、web-deserialization、tools-encoding）。外部技术点参考
  审计报告 §7 URL 并注明来源，未整篇搬运。
- 本目录随预设打包分发；第三方来源文件的许可注记见各 README。
- 与 playbook 的关系：速查卡（playbook）→ 深度手册（refs/）→ 证据落盘（任务工作区，见
  ecosystem-cooperation 技能「产物落盘与交接约定」）。

## 路径与链接约定

- 库内文件一律相对路径引用（相对 refs/ 或文件所在目录），**禁止任何本机绝对路径**
  （预设将打包给其他用户使用）。
- 收录文件内部的相对链接（如 `../upload-insecure-files/SKILL.md`）指向兄弟技能，
  在本库内不直接解析；按链接中的技能名在本库对应目录检索同名 md 文件即可（多数兄弟技能已收录）。
- frontmatter（name/description）为源文件自带，保留原样；refs/ 不经技能加载器发现，
  仅由 read 工具按需读取，frontmatter 无副作用。

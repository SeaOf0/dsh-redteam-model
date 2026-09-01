// dsh-attack-atlas taxonomy — AttackAtlas 的类目体系（纯数据层）。
//
// 结构：模式 → { 作战流程阶段, 目标形态, 形态→主类映射, 主类数组(含子项) }。
// 排序即方法论：主类数组顺序 = 矩阵列序（凭据优先→入口→核心挖掘→专项形态）；
// 子项顺序 = 列内自上而下（可利用性/方法论优先级从高到低）。
// 子项 ref = 知识关联（refs/ 相对路径，派单文案引用，测试层校验存在性）。
// 子项可选 forms 数组：声明「仅这些形态适用」；缺省 = 该主类全部适用形态。
// 键规则：格子 key = `<categoryId>/<itemId>`，主类级 key = `<categoryId>`。
// 八专业模式全量就绪；新增模式按同结构追加条目即可。

export const CELL_STATES = ["tested-found", "tested-clear", "na", "budget-stop"];
export const STAGE_STATES = ["active", "done"];
export const ATLAS_MODES = ["pentest", "code-audit", "binary-analysis", "attack-defense", "av-evasion", "incident-response", "cloud-security", "ctf-solver"];

const CORE9 = ["hardcoded", "access", "auth", "config", "injection", "deser", "file", "logic", "component"];

export const TAXONOMIES = {
	pentest: {
		label: "渗透测试",
		stages: [
			{ id: "s0", label: "0 防护画像" },
			{ id: "s1", label: "1 被动信息收集" },
			{ id: "s2", label: "2 入口面盘点" },
			{ id: "s3", label: "3 登陆口专线" },
			{ id: "s4", label: "4 逐面挖掘" },
			{ id: "s5", label: "5 验证与影响证明" },
			{ id: "s6", label: "6 收口" }
		],
		forms: [
			{ id: "web", label: "Web" },
			{ id: "api", label: "API" },
			{ id: "miniprogram", label: "小程序" },
			{ id: "android", label: "Android" },
			{ id: "ios", label: "iOS" },
			{ id: "desktop", label: "桌面" },
			{ id: "component", label: "组件" },
			{ id: "cloud", label: "云" },
			{ id: "ai", label: "AI" }
		],
		stateLabels: { "tested-found": "已验·有发现", "tested-clear": "已验·未命中", na: "不适用（附原因）", "budget-stop": "未验·让位/预算" },
		stateShort: { found: "已验", clear: "未命中", na: "不适用", budget: "让位" },
		formCategories: {
			web: CORE9,
			api: CORE9,
			miniprogram: CORE9.concat("mini"),
			android: CORE9.concat("mobile"),
			ios: CORE9.concat("mobile"),
			desktop: ["hardcoded", "access", "config", "file", "desktop"],
			component: ["hardcoded", "config", "component"],
			cloud: ["hardcoded", "access", "component"],
			ai: ["hardcoded", "injection", "ai"]
		},
		categories: [
			{
				id: "hardcoded", label: "硬编码与密钥泄露", desc: "凭据优先利用——发现即可直接用",
				items: [
					{ id: "fe-creds", label: "前端账号密码明文", ref: "zh/info-disclosure.md" },
					{ id: "fe-keys", label: "前端密钥/AK-SK 明文", ref: "zh/info-disclosure.md" },
					{ id: "cloud-creds", label: "云凭据（AK/SK）泄露", ref: "components/cloud-postexploitation.md" },
					{ id: "appsecret", label: "AppSecret 硬编码", ref: "miniprogram/miniprogram-security-core.md" },
					{ id: "apk-keys", label: "apk/asar 内密钥", ref: "mobile/android-pentesting-tricks.md" },
					{ id: "apikey-derive", label: "API key 推导与权限范围", ref: "ai/ai-infra-attack-surface.md" },
					{ id: "intranet", label: "内网地址/端点泄露", ref: "zh/info-disclosure.md" },
					{ id: "js-comments", label: "JS 敏感注释", ref: "zh/unauth-access.md" }
				]
			},
			{
				id: "access", label: "访问控制", desc: "谁能访问什么的边界",
				items: [
					{ id: "unauth", label: "未授权访问（含 JS 路由分析）", ref: "zh/unauth-access.md" },
					{ id: "horiz", label: "水平越权", ref: "zh/arbitrary-x-authz.md" },
					{ id: "vert", label: "垂直越权", ref: "zh/arbitrary-x-authz.md" },
					{ id: "idor", label: "IDOR", ref: "zh/arbitrary-x-authz.md" },
					{ id: "bola", label: "BOLA", pb: "形态作战线 A（三态对照主战场）", ref: "api/api-authorization-and-bola.md" },
					{ id: "mass-assign", label: "批量赋值", ref: "web/web-api-security.md" },
					{ id: "csrf", label: "CSRF", ref: "web/web-csrf-cors-clickjacking.md" },
					{ id: "cors", label: "CORS", ref: "web/web-csrf-cors-clickjacking.md" },
					{ id: "jsonp", label: "JSONP 劫持", ref: "web/web-api-security.md" },
					{ id: "postmessage", label: "PostMessage 跨窗口缺陷", ref: "web/web-message-postmessage.md" },
					{ id: "websocket", label: "WebSocket 攻击（含跨站劫持 CSWSH）", forms: ["api"], pb: "形态作战线 A4（通道面）", ref: "api/websocket-security.md" },
					{ id: "hidden-params", label: "隐藏参数发现", forms: ["api"], pb: "形态作战线 A4（参数面）", ref: "api/graphql-and-hidden-parameters.md" },
					{ id: "graphql-auth", label: "GraphQL 字段级授权/introspection", forms: ["api"], pb: "形态作战线 A1/A4（文档面与参数面）", ref: "api/graphql-and-hidden-parameters.md" },
					{ id: "redirect", label: "开放重定向", ref: "web/open-redirect.md" }
				]
			},
			{
				id: "auth", label: "会话认证", desc: "身份生命周期的每个环节",
				items: [
					{ id: "login-bypass", label: "登录绕过", ref: "web/web-auth-bypass.md" },
					{ id: "weak-pass", label: "弱口令/默认口令", ref: "zh/default-credentials-cn.md" },
					{ id: "reset", label: "密码找回/重置缺陷", ref: "web/web-auth-bypass.md" },
					{ id: "captcha", label: "验证码缺陷", ref: "web/web-logic-vulns.md" },
					{ id: "fe-crypto", label: "前端加密/签名实现缺陷（→任意用户登录）", ref: "zh/tools/tools-encoding.md" },
					{ id: "jwt", label: "JWT/Token 缺陷", pb: "形态作战线 A2（鉴权模型）", ref: "api/api-auth-and-jwt-abuse.md" },
					{ id: "oauth", label: "OAuth/SSO 缺陷", pb: "形态作战线 A2（鉴权模型）", ref: "api/api-auth-and-jwt-abuse.md" },
					{ id: "session-fix", label: "会话固定/不注销", ref: "web/web-auth-bypass.md" },
					{ id: "user-enum", label: "用户名枚举", ref: "web/web-pentest-comprehensive.md" },
					{ id: "brute", label: "暴力破解面", ref: "zh/tools/tools-password-attacks.md" }
				]
			},
			{
				id: "config", label: "配置与传输", desc: "暴露面与协议层",
				items: [
					{ id: "info-leak", label: "敏感信息泄露（备份/.git/回显/目录列表/过载字段/sourcemap）", ref: "zh/info-disclosure.md" },
					{ id: "subdomain", label: "子域接管", ref: "web/subdomain-takeover.md" },
					{ id: "cache-poison", label: "缓存投毒", ref: "web/web-cache-attacks.md" },
					{ id: "cache-decep", label: "缓存欺骗", ref: "web/web-cache-attacks.md" },
					{ id: "smuggling", label: "HTTP 请求走私（CL.TE/TE.CL/H2/方法走私）", ref: "web/web-request-smuggling.md" },
					{ id: "host-header", label: "Host 头攻击", ref: "web/http-host-header-attacks.md" },
					{ id: "proxy-header", label: "代理头信任缺陷（XFF 伪造）", ref: "web/http-host-header-attacks.md" },
					{ id: "dns-rebinding", label: "DNS rebinding", ref: "web/dns-rebinding-attacks.md" },
					{ id: "plaintext", label: "明文传输/弱 TLS", ref: "web/web-pentest-comprehensive.md" },
					{ id: "headers", label: "安全响应头缺失", ref: "web/web-csrf-cors-clickjacking.md" },
					{ id: "clickjacking", label: "点击劫持", ref: "web/web-csrf-cors-clickjacking.md" },
					{ id: "grpc", label: "gRPC 攻击面", forms: ["api"], ref: "api/grpc-security.md" },
					{ id: "http2", label: "HTTP/2 特有攻击", forms: ["api"], ref: "api/http2-specific-attacks.md" },
					{ id: "http3", label: "HTTP/3（QUIC）攻击面", forms: ["api"], ref: "api/http3-quic-attacks.md" }
				]
			},
			{
				id: "injection", label: "注入", desc: "输入进解释器的全部通道",
				items: [
					{ id: "sqli", label: "SQL 注入", ref: "web/web-injection-sqli.md" },
					{ id: "cmdi", label: "命令执行", ref: "web/cmdi-command-injection.md" },
					{ id: "ssrf", label: "SSRF（含 gopher/dict/file 协议链）", ref: "web/web-injection-ssrf.md" },
					{ id: "ssti", label: "SSTI 模板注入", ref: "web/web-injection-xxe-ssti-nosql.md" },
					{ id: "el", label: "表达式注入（EL/SpEL/OGNL）", ref: "web/expression-language-injection.md" },
					{ id: "jndi", label: "JNDI 注入", ref: "components/jndi-injection.md" },
					{ id: "xxe", label: "XXE", ref: "web/web-injection-xxe-ssti-nosql.md" },
					{ id: "xss", label: "XSS（反射/存储/DOM/mXSS/DOM clobbering）", ref: "web/web-injection-xss.md" },
					{ id: "nosql", label: "NoSQL 注入", ref: "web/web-injection-xxe-ssti-nosql.md" },
					{ id: "graphql-inj", label: "GraphQL 注入变体", forms: ["api"], ref: "api/graphql-and-hidden-parameters.md" },
					{ id: "crlf", label: "CRLF", ref: "web/crlf-injection.md" },
					{ id: "email-header", label: "邮件头注入与伪造", ref: "web/email-header-injection.md" },
					{ id: "proto", label: "原型污染（客户端/Node.js）", ref: "web/prototype-pollution.md" },
					{ id: "xpath", label: "XPath 注入", ref: "web/xpath-injection.md" },
					{ id: "xslt", label: "XSLT 注入", ref: "web/xslt-injection.md" },
					{ id: "csv", label: "CSV 公式注入", ref: "web/csv-formula-injection.md" },
					{ id: "hpp", label: "HTTP 参数污染", ref: "web/http-parameter-pollution.md" },
					{ id: "ldap", label: "LDAP 注入", ref: "web/ldap-injection.md" },
					{ id: "sse-inj", label: "SSE 注入", forms: ["api"], ref: "api/sse-security.md" }
				]
			},
			{
				id: "deser", label: "反序列化", desc: "对象重建链全部入口",
				items: [
					{ id: "java", label: "Java 原生反序列化", ref: "web/web-deserialization.md" },
					{ id: "fastjson", label: "Fastjson", ref: "components/java-framework-vulns.md" },
					{ id: "shiro", label: "Shiro", ref: "web/web-deserialization.md" },
					{ id: "hessian", label: "Hessian", ref: "web/web-deserialization.md" },
					{ id: "json-key", label: "JSON Key 顺序绕过 Setter 校验", ref: "components/java-framework-vulns.md" },
					{ id: "php", label: "PHP（POP 链/phar）", ref: "web/web-deserialization.md" },
					{ id: "pickle", label: "Python pickle", ref: "web/web-deserialization.md" },
					{ id: "dotnet", label: ".NET（ViewState）", ref: "web/web-deserialization.md" }
				]
			},
			{
				id: "file", label: "文件", desc: "文件读写删的全部路径",
				items: [
					{ id: "upload", label: "任意文件上传", ref: "web/web-file-handling.md" },
					{ id: "read", label: "任意文件读取/下载", ref: "web/web-file-handling.md" },
					{ id: "dir", label: "目录遍历", ref: "web/path-traversal-lfi.md" },
					{ id: "path", label: "路径穿越", ref: "web/path-traversal-lfi.md" },
					{ id: "lfi", label: "LFI/RFI", ref: "web/path-traversal-lfi.md" },
					{ id: "zipslip", label: "Zip Slip 解压穿越", ref: "components/java-framework-vulns.md" },
					{ id: "delete", label: "任意文件删除/覆盖", ref: "web/web-file-handling.md" }
				]
			},
			{
				id: "logic", label: "业务逻辑", desc: "规则与状态的设计缺陷",
				items: [
					{ id: "payment", label: "支付/订单逻辑", ref: "web/web-logic-vulns.md" },
					{ id: "state-bypass", label: "状态机绕过", ref: "web/web-logic-vulns.md" },
					{ id: "race", label: "并发竞态", ref: "web/race-condition.md" },
					{ id: "rule-bypass", label: "业务规则绕过", ref: "zh/logic-flaws.md" },
					{ id: "sms-bomb", label: "短信/邮箱轰炸", ref: "zh/logic-flaws.md" },
					{ id: "rate-limit", label: "API 限流缺失", ref: "zh/dos.md" },
					{ id: "abuse", label: "资源滥用", ref: "zh/dos.md" },
					{ id: "type-juggling", label: "类型混淆", ref: "web/type-juggling.md" },
					{ id: "api-fuzz", label: "API fuzzing 滥用", forms: ["api"], ref: "api/api-fuzzing.md" }
				]
			},
			{
				id: "component", label: "组件与 Nday", desc: "指纹→已知漏洞面",
				items: [
					{ id: "cve", label: "已知 CVE 面（指纹→POC 适配）", pb: "形态作战线 B2（Nday 适配）", ref: "components/component-default-config-audit.md" },
					{ id: "framework-nday", label: "框架 Nday", pb: "形态作战线 B（CMS 型分流即走）", ref: "components/java-framework-vulns.md" },
					{ id: "middleware-nday", label: "中间件 Nday", pb: "形态作战线 B1（组件清单）", ref: "components/middleware-vulns.md" },
					{ id: "svc-unauth", label: "常见服务未授权", ref: "components/unauthorized-access-common-services.md" },
					{ id: "db-exploit", label: "数据库利用", ref: "components/database-exploitation.md" },
					{ id: "container", label: "容器面（Docker/K8s）", ref: "components/container-security.md" },
					{ id: "bucket", label: "对象存储桶配置错误（公开/接管）", ref: "components/cloud-postexploitation.md" },
					{ id: "cloud-post", label: "云服务后利用", ref: "components/cloud-postexploitation.md" }
				]
			},
			{
				id: "mini", label: "客户端·小程序", desc: "小程序特有攻击面", forms: ["miniprogram"],
				items: [
					{ id: "appsecret-leak", label: "AppSecret 泄露", ref: "miniprogram/miniprogram-security-core.md" },
					{ id: "cloud-dev", label: "云开发未授权", ref: "miniprogram/miniprogram-security-core.md" },
					{ id: "openid", label: "openid/code2session 越权", ref: "miniprogram/miniprogram-security-core.md" },
					{ id: "webview-h5", label: "webview 内嵌 H5 域", ref: "miniprogram/miniprogram-security-core.md" },
					{ id: "subpackage", label: "分包逻辑", ref: "miniprogram/wmp-package-readme.md" }
				]
			},
			{
				id: "mobile", label: "客户端·移动", desc: "Android/iOS 特有攻击面", forms: ["android", "ios"],
				items: [
					{ id: "components", label: "四大组件暴露", forms: ["android"], ref: "mobile/mobile-pentest-android.md" },
					{ id: "jsbridge", label: "WebView JS bridge", ref: "mobile/mobile-pentest-android.md" },
					{ id: "deeplink", label: "deeplink/URL scheme", ref: "mobile/android-pentesting-tricks.md" },
					{ id: "binder", label: "Binder 服务缺陷", forms: ["android"], ref: "mobile/android-pentesting-tricks.md" },
					{ id: "intent", label: "Intent 劫持/泄露", forms: ["android"], ref: "mobile/android-pentesting-tricks.md" },
					{ id: "hot-update", label: "热更新校验", ref: "mobile/mobile-pentest-android.md" },
					{ id: "storage", label: "本地存储/日志泄露", ref: "mobile/android-pentesting-tricks.md" },
					{ id: "keychain", label: "keychain 明文", forms: ["ios"], ref: "mobile/ios-pentesting-tricks.md" },
					{ id: "ui-spoof", label: "UI 欺骗与钓鱼", ref: "mobile/mobile-pentest-android.md" },
					{ id: "biometric", label: "弱生物识别/应用锁绕过", ref: "mobile/mobile-pentest-android.md" }
				]
			},
			{
				id: "desktop", label: "客户端·桌面", desc: "桌面客户端特有攻击面", forms: ["desktop"],
				items: [
					{ id: "update-sig", label: "更新机制签名校验", ref: "desktop/electron-desktop-security.md" },
					{ id: "protocol", label: "自定义协议处理", ref: "desktop/electron-desktop-security.md" },
					{ id: "dll", label: "DLL 劫持", ref: "desktop/electron-desktop-security.md" },
					{ id: "local-creds", label: "本地凭据泄露", ref: "desktop/electron-desktop-security.md" }
				]
			},
			{
				id: "ai", label: "AI 面", desc: "AI 应用目标作战线（四分型）", forms: ["ai"],
				items: [
					{ id: "ai-profile", label: "四分型画像（对话入口/Agent/AI 基础设施/业务内嵌）+纯文本模型判定（防目标幻觉）", pb: "AI 应用作战线 §0（形态判定）" },
					{ id: "prompt-inj", label: "提示词注入（直接/间接/记忆投毒）", pb: "AI 应用作战线 §1", ref: "ai/ai-prompt-injection.md" },
					{ id: "jailbreak", label: "越狱与 system prompt 泄露", pb: "AI 应用作战线 §1", ref: "ai/ai-jailbreak-techniques.md" },
					{ id: "output-sink", label: "输出下游解析面（越狱→反序列化/SSTI/命令拼接；纯文本模型无此桥）", pb: "AI 应用作战线 §1" },
					{ id: "sys-prompt", label: "系统提示词提取（诱导复述/格式绕过）", pb: "AI 应用作战线 §1", ref: "ai/ai-system-prompt-extraction.md" },
					{ id: "tool-abuse", label: "工具调用滥用（MCP/插件——注入驱动+权限边界）", pb: "AI 应用作战线 §2", ref: "ai/ai-agent-safety.md" },
					{ id: "config-poison", label: "配置投毒（AGENTS.md/skill）", pb: "AI 应用作战线 §2", ref: "ai/ai-agent-safety.md" },
					{ id: "llm-api", label: "LLM API 未授权与密钥泄露（网关/推理服务）", pb: "AI 应用作战线 §3", ref: "ai/ai-infra-attack-surface.md" },
					{ id: "vector-db", label: "向量库未授权（连接/枚举/拖取）", pb: "AI 应用作战线 §3", ref: "ai/ai-infra-attack-surface.md" },
					{ id: "rag", label: "RAG 上下文污染（可写知识源=持久化注入）", pb: "AI 应用作战线 §4", ref: "ai/ai-rag-poisoning.md" },
					{ id: "model-file", label: "模型文件攻击面（GGUF/pickle 反序列化）", pb: "AI 应用作战线 §3", ref: "ai/ai-model-security.md" },
					{ id: "cot-steal", label: "推理内容窃取（CoT 重放）", ref: "ai/ai-model-security.md" },
					{ id: "data-poison", label: "数据投毒", ref: "ai/ai-model-security.md" },
					{ id: "ai-signal", label: "确定性信号适配（OOB 实收/执行回显/原文落盘）——AI 声称不是证据", pb: "AI 应用作战线 §5（证据纪律）" },
					{ id: "ai-budget", label: "预算纪律（≤30 轮/目标）与工具矩阵（Garak/PyRIT/Promptfoo）", pb: "AI 应用作战线 §5" }
				]
			},
			{
				id: "src-line", label: "SRC 挖掘作战线", desc: "任务口径层——挖法不变，叠加提交口径",
				items: [
					{ id: "src-trigger", label: "入口触发（SRC/众测/补天/漏洞盒子/厂商+SRC——模糊时问一次）", pb: "SRC 挖掘线 §1" },
					{ id: "src-scope", label: "范围圈定（平台规则页=授权边界事实源，越 scope=封号）", pb: "SRC 挖掘线 §2" },
					{ id: "src-report", label: "SRC 报告草稿（六字段变体口径：表单字段+简洁复现导向）", pb: "SRC 挖掘线 §4", ref: "zh/src-mining.md" },
					{ id: "src-rating", label: "评级映射（平台当日标准+三问锚点，拿不准给两档）", pb: "SRC 挖掘线 §4", ref: "zh/src-mining.md" },
					{ id: "src-collect", label: "收录纪律（重复核对/低危也报/时效不囤积）", pb: "SRC 挖掘线 §4" },
					{ id: "src-profile", label: "平台档案机制（分型先验+当日规则页，不做规则全文库）", pb: "SRC 挖掘线 §5", ref: "zh/src-mining.md" }
				]
			}
		]
	},
	"attack-defense": {
		label: "攻防评估",
		stages: [
			{ id: "s1", label: "1 侦察" },
			{ id: "s2", label: "2 突破" },
			{ id: "s3", label: "3 横向" },
			{ id: "s4", label: "4 持久化" },
			{ id: "s5", label: "5 报告" }
		],
		forms: [
			{ id: "external", label: "外网" },
			{ id: "intranet", label: "内网" },
			{ id: "domain", label: "域环境" },
			{ id: "ai", label: "AI 应用" }
		],
		formCategories: {
			external: ["recon", "entry-vec", "cred-line", "foothold", "phishing"],
			intranet: ["host-collect", "inet-recon", "svc-line", "passive-cred", "win-chain", "linux-line", "cloud-intranet", "lateral", "privesc", "hv-target", "pivot", "persistence", "trace-mgmt", "defense-verify"],
			domain: ["host-collect", "passive-cred", "win-chain", "lateral", "domain-attack", "hv-target"],
			ai: ["ai-redteam"]
		},
		/** 战果词别名（attack-defense 专属）：成果登记的 type 是「拿到了什么」的结果名词，体系标签是
		 *  「怎么打」的技法词——此表桥接两者，resolveKey 顶层消费，mark/sync/自动点亮全入口同享。 */
		aliases: {
			"入口点": "entry-vec",
			"数据读取成果": "hv-target",
			"凭据·密码本": "cred-line",
			"哈希集": "win-chain",
			"哈希集(hash map)": "win-chain",
			"横向立足点": "lateral",
			"域控成果": "domain-attack",
			"Webshell 部署": "foothold",
			"持久化项": "persistence",
			"内网资产": "host-collect",
			"检测gap": "defense-verify",
			"检测缺口": "defense-verify"
		},
		zones: [
			{ id: "external", label: "外网打点" },
			{ id: "intranet", label: "内网横向" },
			{ id: "wrapup", label: "登记收尾" }
		],
		chain: true,
		stateLabels: { "tested-found": "走通·有战果", "tested-clear": "执行·未走通", na: "不适用（N-A）", "budget-stop": "未尝试·让位/预算" },
		stateShort: { found: "走通", clear: "未走通", na: "不适用", budget: "让位" },
		categories: [
			{
				id: "recon", label: "测绘侦察", desc: "找面——双源合并", zone: "external",
				items: [
					{ id: "hunter", label: "测绘资产搜索（hunter DSL 联动）", pb: "外网打点 §0（hunter 狩猎页联动）" },
					{ id: "passive-intel", label: "被动情报双源合并（证书透明/DNS/历史）", ref: "offensive/initial-access.md" },
					{ id: "shadow-asset", label: "影子资产/边缘服务/预生产环境", ref: "offensive/initial-access.md" },
					{ id: "fingerprint", label: "指纹与入口盘点", pb: "外网打点 §0（复用 pentest 入口面盘点）" },
					{ id: "honeypot-ext", label: "蜜罐甄别（外网侧）", pb: "内网 §0 蜜罐甄别纪律" }
				]
			},
			{
				id: "entry-vec", label: "入口面提级序", desc: "十类序——可直接转化为权限/数据", zone: "external",
				items: [
					{ id: "weak-pass", label: "1 弱口令（登录口/后台/中间件台）", ref: "pentest:zh/default-credentials-cn.md" },
					{ id: "unauth", label: "2 未授权访问（管理台/接口/对象存储）", ref: "pentest:zh/unauth-access.md" },
					{ id: "login-bypass", label: "3 登陆绕过", ref: "pentest:web/web-auth-bypass.md" },
					{ id: "upload", label: "4 任意文件上传（webshell 路径）", ref: "pentest:web/web-file-handling.md" },
					{ id: "file-read", label: "5 任意文件读取/下载（配置/源码/凭据）", ref: "pentest:web/web-file-handling.md" },
					{ id: "cmdi", label: "6 命令执行", ref: "pentest:web/cmdi-command-injection.md" },
					{ id: "deser", label: "7 反序列化", ref: "pentest:web/web-deserialization.md" },
					{ id: "nday", label: "8 框架通用 Nday（指纹命中即试）", ref: "pentest:components/component-default-config-audit.md" },
					{ id: "sqli", label: "9 SQL 注入（读凭据→复用）", ref: "pentest:web/web-injection-sqli.md" },
					{ id: "ssrf", label: "10 SSRF（内网探针/云元数据）", ref: "pentest:web/web-injection-ssrf.md" },
					{ id: "edge-nday", label: "11 边界设备/VPN Nday（防火墙/SSLVPN 类）", ref: "trends/2026-attack-paradigm-detection.md" }
				]
			},
			{
				id: "cred-line", label: "登陆口与凭据线", desc: "无帐密标准动作", zone: "external",
				items: [
					{ id: "js-clues", label: "登录页 JS 四类结构化线索", ref: "pentest:zh/unauth-access.md" },
					{ id: "hardcoded-first", label: "硬编码凭据优先利用", ref: "pentest:zh/info-disclosure.md" },
					{ id: "api-check", label: "API 安全对照（无凭证/低权限）", ref: "pentest:web/web-api-security.md" },
					{ id: "cred-spray", label: "凭据全服务喷（拿到即复用）", pb: "外网打点 §2/§3（凭据立即复用）" }
				]
			},
			{
				id: "foothold", label: "Webshell 立足点", desc: "获取→连接→立足点作业", zone: "external",
				items: [
					{ id: "get-upload", label: "获取与上传（免杀/generate/用户直供兜底）", pb: "外网打点 §2.5（webshell 管理插件）" },
					{ id: "connect", label: "连接与识别（全协议自动识别）", pb: "外网打点 §2.5（全协议连接器）" },
					{ id: "memshell", label: "Java 内存马路线（注入→删引导→任意路径连）", pb: "外网打点 §2.5（内存马登记制）" },
					{ id: "anchor", label: "系统定锚（whoami/网络/进程/权限面）", pb: "外网打点 §2.5（立足点作业）" },
					{ id: "credbook", label: "密码本收集（浏览器/ssh/运维配置）", pb: "外网打点 §2.5（密码本收集）" },
					{ id: "db-direct", label: "数据库配置提取→直连（PDO 出站）", pb: "外网打点 §2.5（数据库直连）" },
					{ id: "c2", label: "C2 回连上传与通道适配", pb: "外网打点 §2.5（C2 回连）" },
					{ id: "evasion-link", label: "免杀衔接（载荷免杀/EDR 绕过→免杀对抗模式）", ref: "offensive/evasion-techniques.md" }
				]
			},
			{
				id: "phishing", label: "社工与钓鱼", desc: "独立人面入口作战线（授权范围内）", zone: "external",
				items: [
					{ id: "osint-soc", label: "情报期：OSINT 分层（IT/财务·HR/高管）", pb: "社工钓鱼线 §1（目标分层定通道）", ref: "offensive/social-engineering.md" },
					{ id: "mail-batch", label: "邮件批量投递（文案分级：广播/部门/AI 个性化）", pb: "社工钓鱼线 §2（发信基础设施三选一）", ref: "offensive/phishing-campaign.md" },
					{ id: "im-phish", label: "IM 钓鱼（企业微信/微信/QQ 投递）", pb: "社工钓鱼线 §2（IM 通道）", ref: "offensive/im-phishing.md" },
					{ id: "spear", label: "鱼叉邮件投递", pb: "社工钓鱼线 §2", ref: "offensive/phishing-campaign.md" },
					{ id: "cred-phish", label: "凭证钓鱼（仿冒登录页）", pb: "社工钓鱼线 §2", ref: "offensive/phishing-campaign.md" },
					{ id: "ai-phish", label: "AI 生成钓鱼（定制化话术/深度伪造）", pb: "社工钓鱼线 §2（2026 演习重点）", ref: "trends/ad-trends-2025-2026.md" },
					{ id: "water-hole", label: "水坑攻击", pb: "社工钓鱼线 §2", ref: "offensive/initial-access.md" },
					{ id: "payload-evasion", label: "载荷期：免杀协作（av-evasion 生态生成）", pb: "社工钓鱼线 §3（载荷哈希+投递批次登记）" },
					{ id: "c2-infra", label: "C2 期：基础设施与上线（域前置/CDN/云函数）", pb: "社工钓鱼线 §4", ref: "offensive/c2-infrastructure.md" }
				]
			},
			{
				id: "ai-redteam", label: "AI 应用红队", desc: "评估范围内才打", zone: "external", forms: ["ai"],
				items: [
					{ id: "prompt-inj", label: "对话入口提示词注入", ref: "ai/ai-prompt-injection.md" },
					{ id: "ai-infra", label: "AI 基础设施未授权（LLM API/网关）", ref: "ai/ai-agent-safety.md" },
					{ id: "agent-abuse", label: "智能体工具/插件滥用", ref: "ai/ai-agent-safety.md" },
					{ id: "rag-poison", label: "RAG/知识库污染", ref: "ai/ai-prompt-injection.md" }
				]
			},
			{
				id: "host-collect", label: "落点收集 SOP", desc: "横向前置——每台必过", zone: "intranet",
				items: [
					{ id: "opsec-base", label: "OS 识别+监控基线探测（Sysmon/EDR）", ref: "zh-intranet/intranet-host-collect.md" },
					{ id: "modules", label: "模块化收集（W1-W21/L1-L14 全量基线）", ref: "zh-intranet/intranet-host-collect.md" },
					{ id: "triggers", label: "深挖触发表（服务三问）", ref: "zh-intranet/intranet-host-collect.md" },
					{ id: "diverge", label: "资产归纳+凭证发散闭环", ref: "zh-intranet/intranet-host-collect.md" },
					{ id: "xlink", label: "敏感信息跨源关联（攻击图 links）", ref: "zh-intranet/intranet-host-collect.md" }
				]
			},
			{
				id: "inet-recon", label: "内网侦察与姿态", desc: "不做全端口扫描", zone: "intranet",
				items: [
					{ id: "port-policy", label: "常见端口带策略（web/数据库带）", ref: "zh-intranet/intranet-recon.md" },
					{ id: "env-judge", label: "环境判定四型分流（工作组/Linux/云/域）", pb: "内网 §0.7（判定特征与并行分流）" },
					{ id: "fscan-gates", label: "fscan 三道闸（姿态/蜜罐/锁定）", ref: "zh-intranet/intranet-recon.md" },
					{ id: "posture", label: "监测姿态卡（效率/OPSEC 分叉）", ref: "zh-intranet/intranet-recon.md" },
					{ id: "honeypot-int", label: "蜜罐/蜜饵甄别（动手前筛）", ref: "zh-intranet/intranet-recon.md" },
					{ id: "seg-prog", label: "网段穷尽递进（C 段→B 段不跳段）", ref: "zh-intranet/intranet-recon.md" }
				]
			},
			{
				id: "svc-line", label: "服务线", desc: "发现即打——弱口令优先", zone: "intranet",
				items: [
					{ id: "svc-weak", label: "服务弱口令（锁定策略探测先行）", ref: "zh-intranet/intranet-lateral.md" },
					{ id: "db-five", label: "数据库线五问（按序回答）", ref: "zh-intranet/intranet-postexp.md" },
					{ id: "framework", label: "常见框架线（无服务器权限时 web 侧）", ref: "zh-intranet/intranet-postexp.md" },
					{ id: "uncommon", label: "非常见系统线", ref: "zh-intranet/intranet-postexp.md" }
				]
			},
			{
				id: "passive-cred", label: "被动凭据线", desc: "找准位置才开打", zone: "intranet",
				items: [
					{ id: "responder", label: "responder 收割 Net-NTLMv2（同广播域）", ref: "offensive/ntlm-relay-coercion.md" },
					{ id: "relay", label: "ntlmrelayx 中继（签名探测先行）", ref: "offensive/ntlm-relay-coercion.md" },
					{ id: "coercer", label: "coercer 强制认证（制造中继流量）", ref: "offensive/ntlm-relay-coercion.md" },
					{ id: "relay-rbcd", label: "无凭据进阶：中继+RBCD 组合（机器账户直取）", pb: "内网 §1.2（零凭据起步）" },
					{ id: "hash-reuse", label: "哈希就地复用（PtH）", ref: "zh-intranet/intranet-credential-theft.md" },
					{ id: "noise", label: "噪声评估（有监测降级/弃用）", ref: "offensive/ntlm-relay-coercion.md" }
				]
			},
			{
				id: "win-chain", label: "Windows 工作组内网", desc: "无域——本地凭据复用起手", zone: "intranet",
				items: [
					{ id: "chain", label: "凭据链按序（SAM→LSASS→DPAPI）", pb: "内网 §2", ref: "zh-intranet/intranet-password-collection.md" },
					{ id: "local-spray", label: "本地账户跨机喷洒（nxc --local-auth）", pb: "内网 §2（工作组重密码通病）" },
					{ id: "harvest4", label: "落点收割四件套（每台必过）", pb: "内网 §2", ref: "zh-intranet/intranet-password-collection.md" },
					{ id: "smb-old", label: "SMB 老系统历史漏洞（用户确认制）", pb: "内网 §2", ref: "offensive/windows-lateral-movement.md" },
					{ id: "dpapi", label: "DPAPI/凭据管理器", ref: "offensive/credential-harvesting.md" }
				]
			},
			{
				id: "linux-line", label: "Linux 内网", desc: "SSH 面起手——密钥与密码本", zone: "intranet",
				items: [
					{ id: "ssh-cred", label: "SSH 弱口令/密钥复用", pb: "内网 §3（起手）", ref: "offensive/linux-lateral-movement.md" },
					{ id: "key-graph", label: "密钥横向（.ssh×known_hosts 求交+agent 滥用）", pb: "内网 §3（密钥横向）" },
					{ id: "hist-cfg", label: "历史命令与配置凭据", ref: "offensive/linux-lateral-movement.md" },
					{ id: "sudo-suid", label: "sudo/suid 提权面", ref: "zh-intranet/intranet-privesc.md" },
					{ id: "cron", label: "计划任务/自启动", ref: "zh-intranet/intranet-privesc.md" },
					{ id: "docker-sock", label: "容器面：docker socket 即 root", pb: "内网 §3（容器面）" },
					{ id: "nfs-root", label: "NFS no_root_squash（挂载即 root）", pb: "内网 §3" }
				]
			},
			{
				id: "cloud-intranet", label: "云环境内网", desc: "凭据三处起手——云 API 扩大生态协作", zone: "intranet",
				items: [
					{ id: "cred-three", label: "云凭据三处（CLI 配置/环境变量/实例角色）", pb: "内网 §4（起手）" },
					{ id: "ak-verify", label: "AK/SK 验证（凭据指纹即取→云 API）", pb: "内网 §4（生态协作 cloud-security）" },
					{ id: "sg-bypass", label: "安全组旁路与内网 LB 管理台", pb: "内网 §4（云内特有面）" },
					{ id: "meta-ssrf", label: "元数据 SSRF（云上价值翻倍）", pb: "内网 §4（衔接外网 SSRF 提级序）" }
				]
			},
			{
				id: "lateral", label: "横向移动执行", desc: "凭据使用型优于新登录", zone: "intranet",
				items: [
					{ id: "pth", label: "PtH/Kerberos 票据使用", ref: "offensive/windows-lateral-movement.md" },
					{ id: "impacket", label: "impacket exec 线", ref: "offensive/lateral-movement.md" },
					{ id: "lowlog", label: "WMI/计划任务低日志通道", ref: "offensive/lateral-movement.md" },
					{ id: "winrm-rdp", label: "evil-winrm/RDP（记录关联 IP）", ref: "offensive/windows-lateral-movement.md" }
				]
			},
			{
				id: "privesc", label: "权限提升", desc: "可行性证明·不破坏", zone: "intranet",
				items: [
					{ id: "linux-privesc", label: "Linux 提权链（suid/内核/服务）", ref: "zh-intranet/intranet-privesc.md" },
					{ id: "win-privesc", label: "Windows 提权链（服务缺陷/组策略）", ref: "offensive/privilege-escalation.md" },
					{ id: "db-privesc", label: "数据库提权", ref: "zh-intranet/intranet-postexp.md" }
				]
			},
			{
				id: "domain-attack", label: "域内内网", desc: "域凭据先起手——域控漏洞后置备选", zone: "intranet", forms: ["domain"],
				items: [
					{ id: "first-order", label: "起手序：域用户凭据先起手（安静/低崩溃风险）", pb: "内网 §5（定序与三条理由）" },
					{ id: "dom-recon", label: "域信息收集（BloodHound 路径+AD 回收站/LAPS）", pb: "内网 §5", ref: "offensive/bloodhound-ad.md" },
					{ id: "gpp-sysvol", label: "SYSVOL GPP 口令（老域白捡面）", pb: "内网 §5", ref: "zh-intranet/intranet-domain-attacks.md" },
					{ id: "kerberoast", label: "Kerberoast/AS-REP 离线破解", pb: "内网 §5", ref: "offensive/ad-kerberos-attacks.md" },
					{ id: "adcs", label: "ADCS 攻击面（ESC1-ESC8）", pb: "内网 §5", ref: "zh-intranet/intranet-adcs.md" },
					{ id: "delegate", label: "委派攻击（非约束/约束/RBCD）", pb: "内网 §5", ref: "offensive/active-directory-security.md" },
					{ id: "shadow-cred", label: "Shadow Credentials（msDS-KeyCredentialLink 写入）", pb: "内网 §5（委派进阶）", ref: "offensive/ad-kerberos-attacks.md" },
					{ id: "dcsync", label: "DCSync（单请求优于批量登录）", pb: "内网 §5", ref: "offensive/ad-kerberos-attacks.md" },
					{ id: "cross-domain", label: "跨域信任横向（集团多域）", pb: "内网 §5（信任方向定打法）", ref: "offensive/active-directory-security.md" },
					{ id: "dc-vuln", label: "域控漏洞线（Zerologon 类——受阻+用户确认后）", pb: "内网 §5（后置备选）" },
					{ id: "acl-abuse", label: "ACL 滥用提权路径", ref: "offensive/ad-acl-abuse.md" }
				]
			},
			{
				id: "hv-target", label: "高价值目标", desc: "发现即提级", zone: "intranet",
				items: [
					{ id: "dc", label: "域控（发现即进域内内网）", pb: "内网 §5（凭据路线先起手）", ref: "zh-intranet/intranet-domain-attacks.md" },
					{ id: "bastion", label: "堡垒机/跳板（凭证汇聚点）", ref: "offensive/bastion-jumpserver.md" },
					{ id: "devops", label: "DevOps 套件（Jenkins/GitLab/Harbor）", pb: "内网 §9", ref: "zh-intranet/intranet-postexp.md" },
					{ id: "wsus-sccm", label: "WSUS/SCCM 分发面（国外热/国内低频——确认制）", pb: "内网 §9" },
					{ id: "mail-oa", label: "邮件/OA/VPN（密码重置枢纽）", pb: "内网 §9", ref: "zh-intranet/intranet-exchange.md" },
					{ id: "sec-console", label: "安防设备/SIEM 控制台（用户确认制）", pb: "内网 §10（用户确认制）" },
					{ id: "netdev", label: "网管设备（路由器/交换机——只读取证优先）", pb: "内网 §10（用户确认制）" },
					{ id: "printer-ldap", label: "打印机 LDAP 泄露域凭据（顺手取证）", pb: "内网 §10" },
					{ id: "idp", label: "统一认证/身份系统（IdP/SSO）", pb: "内网 §9（DevOps 与身份系统高价值线）" },
					{ id: "rmm-byovd", label: "RMM/BYOVD 管理工具滥用", ref: "trends/2026-attack-paradigm-detection.md" }
				]
			},
			{
				id: "pivot", label: "跨段递进与枢纽", desc: "C 段最快→B 段递进·隔离突破", zone: "intranet",
				items: [
					{ id: "c-seg-fast", label: "C 段最快打法序（情报定向>fscan>未授权>Nday>RCE）", pb: "内网 §6（速度优先级）" },
					{ id: "first-blood", label: "一血优先序（数据库>域控>邮箱>文件服务器）", pb: "内网 §6（成果预期）" },
					{ id: "tool-killed", label: "工具被杀分叉（探杀软→脚本→av-evasion 免杀版）", pb: "内网 §6（落工具前想好退路）" },
					{ id: "b-seg", label: "C 段穷尽判据→B 段递进（三无=穷尽不跳段）", pb: "内网 §6" },
					{ id: "chisel", label: "多级 SOCKS 链（chisel 级联）", ref: "offensive/tunneling-pivoting.md" },
					{ id: "socat", label: "socat/proxychains 级联", ref: "zh-intranet/intranet-tunneling.md" },
					{ id: "cross-seg", label: "跨私网段隔离突破（双宿主/跨段服务/三私网块）", pb: "内网 §6（发现面/突破面/通道面）", ref: "offensive/tunneling-pivoting.md" },
					{ id: "hide-tunnel", label: "隧道流量伪装（HTTPS 长连/CDN/域前置）", pb: "内网 §6（与 C2 期共用伪装纪律）", ref: "offensive/tunneling-pivoting.md" }
				]
			},
			{
				id: "persistence", label: "持久化（登记制）", desc: "真实落地·立即登记·不自动清理", zone: "wrapup",
				items: [
					{ id: "verify", label: "可行性验证（落地→生效证据）", ref: "zh-intranet/intranet-persistence.md" },
					{ id: "registry", label: "persistence-registry 登记（含手动排除步骤）", ref: "zh-intranet/intranet-persistence.md" },
					{ id: "gap-map", label: "持久化×检测对应（detection gap）", ref: "zh-intranet/intranet-persistence.md" }
				]
			},
			{
				id: "trace-mgmt", label: "痕迹管理", desc: "清痕与登记一体", zone: "wrapup",
				items: [
					{ id: "four-faces", label: "痕迹四类清理面（横向场景）", pb: "内网 §12" },
					{ id: "order", label: "清痕顺序纪律（顺序不可倒）", pb: "内网 §12" },
					{ id: "targeted", label: "目标侧定向清痕（克制红线）", pb: "内网 §12" },
					{ id: "op-traces", label: "op-traces 本地台账（报告门校验物）", pb: "内网 §12（报告门校验物）" },
					{ id: "residue", label: "残留清单处置（用户确认后执行）", pb: "内网 §12（用户确认后执行）" }
				]
			},
			{
				id: "defense-verify", label: "防御验证与收口", desc: "detection gap·穷尽终止", zone: "wrapup",
				items: [
					{ id: "gap3", label: "detection gap 三终态（检测到/gap/无法评估）", ref: "defense/detection-matrix.md" },
					{ id: "evidence", label: "防御证据请求（演练启动一次性）", pb: "防御证据请求清单节" },
					{ id: "attackmap", label: "ATT&CK 覆盖度表（走过+没走+原因）", ref: "defense/attack-mapping-analysis.md" },
					{ id: "feedback", label: "成果反哺登记（权限/数据实时入账）", pb: "内网 §11（实时登记）" },
					{ id: "exhaust", label: "穷尽终止判定（无新路径/凭据/网段）", pb: "内网 §11（穷尽终止）" },
					{ id: "report-gate", label: "报告门（op-traces 结构校验）", pb: "报告模板节（op-traces 门）" }
				]
			}
		]
	},
	"incident-response": {
		label: "应急溯源",
		stages: [
			{ id: "s1", label: "1 证据保全" },
			{ id: "s2", label: "2 失陷排查" },
			{ id: "s3", label: "3 溯源还原" },
			{ id: "s4", label: "4 定性" },
			{ id: "s5", label: "5 处置建议" },
			{ id: "s6", label: "6 报告" }
		],
		forms: [
			{ id: "windows", label: "Windows" },
			{ id: "linux", label: "Linux" },
			{ id: "cloud", label: "云上" }
		],
		formCategories: {
			windows: ["evidence-save","compromise-check","spread-loop","card-live","card-webshell","card-memshell","card-worm","card-ransom","card-vuln","card-forensics","timeline","chain-rebuild","ioc-enrich","attribution","mem-forensics","disk-forensics","net-forensics","sample-handoff","containment","remediation","report"],
			linux: ["evidence-save","compromise-check","spread-loop","card-live","card-webshell","card-memshell","card-worm","card-ransom","card-vuln","card-forensics","timeline","chain-rebuild","ioc-enrich","attribution","mem-forensics","disk-forensics","net-forensics","sample-handoff","containment","remediation","report"],
			cloud: ["evidence-save","compromise-check","spread-loop","timeline","ioc-enrich","chain-rebuild","cloud-ir","containment","remediation","report"]
		},
		zones: [
			{ id: "preserve", label: "保全排查" },
			{ id: "cards", label: "场景作战卡" },
			{ id: "reconstruct", label: "溯源还原" },
			{ id: "deep", label: "取证深线" },
			{ id: "deliver", label: "处置交付" }
		],
		stateLabels: { "tested-found": "查实·有证据", "tested-clear": "已查·未命中", na: "不适用（附原因）", "budget-stop": "未查·让位/预算" },
		stateShort: { found: "查实", clear: "未命中", na: "不适用", budget: "让位" },
		chain: true,
		chainKinds: {
			attacker: { label: "攻击者", fill: "rgba(255,107,107,.16)", stroke: "#ff6b6b" },
			infra: { label: "C2/基础设施", fill: "rgba(180,140,255,.15)", stroke: "#b48cff" },
			entry: { label: "失陷入口", fill: "rgba(56,212,255,.16)", stroke: "#38d4ff" },
			host: { label: "失陷主机", fill: "rgba(58,157,255,.13)", stroke: "rgba(58,157,255,.65)" },
			cred: { label: "滥用凭据", fill: "rgba(245,197,66,.12)", stroke: "#f5c542" },
			pivot: { label: "跳板/横向", fill: "rgba(124,200,255,.10)", stroke: "#7cc8ff", dash: "5 3" },
			exfil: { label: "外传/扩散", fill: "rgba(255,159,67,.14)", stroke: "#ff9f43" },
			other: { label: "其他", fill: "rgba(93,107,128,.14)", stroke: "rgba(141,153,171,.6)" }
		},
		aliases: {
			// 成果页 type 双轴桥：persona 链节点八词（执行/影响两词 label contains 已正确命中不重复建；
			// 其他=有意无格）+ 自然事件词。横向/失陷/IOC/时间线/数据外传/提权 六词为纠偏——
			// 裸 contains 会错位到勒索卡前兆/云实例/收敛格/报告格/双勒索格/webshell 伴随格。
			"入口点": "card-vuln/exp-anchor",
			"持久化": "compromise-check", "持久化后门": "compromise-check/backdoor",
			"横向": "spread-loop/five-dim", "横向移动": "spread-loop/five-dim",
			"数据外传": "card-forensics/rebuild",
			"处置清理": "remediation/checklist",
			"勒索病毒": "card-ransom", "勒索软件": "card-ransom",
			"挖矿木马": "compromise-check/backdoor", "木马": "compromise-check/backdoor",
			"日志清除": "card-forensics/rebuild", "痕迹清除": "card-forensics/rebuild",
			"暴力破解": "card-live/chain-ser", "弱口令": "card-live/chain-ser",
			"凭据窃取": "spread-loop/five-dim",
			"隧道": "net-forensics/tunnel-detect",
			"提权": "chain-rebuild", "失陷": "compromise-check", "入侵": "compromise-check",
			"IOC": "ioc-enrich", "时间线": "timeline"
		},
		categories: [
			{
				id: "evidence-save", label: "证据保全", desc: "开工先只读取证", zone: "preserve",
				items: [
					{ id: "snap", label: "系统快照（进程/网络/服务/启动项）", ref: "windows/methodology/incident-flow.md" },
					{ id: "logs-export", label: "关键日志导出", ref: "windows/logs/windows-eventid-detection.md" },
					{ id: "file-hash", label: "可疑文件哈希登记", pb: "取证纪律（主观念）" },
					{ id: "mem-image", label: "内存镜像（可行时）", pb: "内存取证线" },
					{ id: "quick-snap", label: "秒级快照（紧急通道前置）", pb: "场景卡章·紧急处置通道" }
				]
			},
			{
				id: "compromise-check", label: "失陷排查", desc: "文件→进程→持久化→网络", zone: "preserve",
				items: [
					{ id: "webshell", label: "webshell 排查", ref: "windows/webshell/webshell-detection.md" },
					{ id: "linux-webshell", label: "Linux webshell 排查", ref: "linux/webshell/webshell-detection.md" },
					{ id: "memshell", label: "内存马排查（无文件痕迹是常态）", ref: "windows/webshell/memory-shell.md" },
					{ id: "win-persist", label: "Windows 持久化点", ref: "windows/persistence/persistence-points.md" },
					{ id: "lx-persist", label: "Linux 持久化点", ref: "linux/persistence/persistence-points.md" },
					{ id: "backdoor", label: "木马/后门/挖矿排查", ref: "linux/malware/mining-ransomware-backdoor.md" },
					{ id: "hunt", label: "日志狩猎（Chainsaw/Hayabusa·Sigma）", ref: "windows/logs/windows-eventid-detection.md" },
					{ id: "hidden-proc", label: "隐藏进程排查", ref: "linux/process/hidden-process.md" },
					{ id: "rootkit", label: "rootkit/so 后门", ref: "linux/rootkit/so-backdoor-rootkit.md" }
				]
			},
			{
				id: "spread-loop", label: "扩线循环", desc: "五维定损驱动·直到收敛", zone: "preserve",
				items: [
					{ id: "five-dim", label: "五维定损（同密码/同构/同管理员/SSH密钥/频繁交互）", pb: "扩线作战流程" },
					{ id: "sec-filter", label: "安全设备侧预筛（对内/对外攻击记录）", pb: "扩线作战流程" },
					{ id: "ledger-new", label: "覆盖台账新行·已查终态防重复", pb: "覆盖台账" },
					{ id: "converge", label: "收敛判定（池空且无新失陷/新 IOC）", pb: "扩线作战流程" }
				]
			},
			{
				id: "card-live", label: "卡1 攻防在线对抗", desc: "攻击者仍在系统内", zone: "cards",
				items: [
					{ id: "active", label: "活跃度判定（C2/隧道/日志增长/新落地）", pb: "卡 1" },
					{ id: "block", label: "立即阻断（紧急通道：断反连/隧道/跳板）", pb: "卡 1" },
					{ id: "chain-ser", label: "逐类串联（扫描→爆破→登陆→EXP→落地→C2）", pb: "卡 1" },
					{ id: "out-confirm", label: "复测攻击者出局闭环", pb: "卡 1" }
				]
			},
			{
				id: "card-webshell", label: "卡2 webshell 应急", desc: "重命名处置保证据", zone: "cards",
				items: [
					{ id: "locate", label: "定位（内容特征/时间窗/访问日志 payload）", ref: "windows/webshell/webshell-detection.md" },
					{ id: "rename", label: "重命名处置（掐连接不删证据）", pb: "卡 2" },
					{ id: "upload-chain", label: "上传→访问→命令执行全程还原", pb: "卡 2" },
					{ id: "accompany", label: "伴随提权/持久化排查", pb: "卡 2" }
				]
			},
			{
				id: "card-memshell", label: "卡3 内存马应急", desc: "无文件痕迹是常态", zone: "cards",
				items: [
					{ id: "jmap", label: "jmap dump 后分析可疑注册", ref: "windows/webshell/memory-shell.md" },
					{ id: "arthas", label: "Arthas 在线检测", ref: "windows/webshell/memory-shell.md" },
					{ id: "restart", label: "重启清除+先堵入口（否则再生）", pb: "卡 3" },
					{ id: "accompany2", label: "伴随落地物/定时任务/反连排查", pb: "卡 3" }
				]
			},
			{
				id: "card-worm", label: "卡4 病毒/蠕虫应急", desc: "隔离优先·断扩散", zone: "cards",
				items: [
					{ id: "isolate", label: "隔离优先（扩散性=立即处置类）", pb: "卡 4" },
					{ id: "ioc-sweep", label: "样本哈希→ioc.txt→全网 IOC 横扫", pb: "卡 4" },
					{ id: "clean-patch", label: "清除+利用漏洞修补（不修补即再感染）", pb: "卡 4" },
					{ id: "rescan", label: "全网复扫确认清零", pb: "卡 4" },
					{ id: "spread-topo", label: "感染链拓扑还原（扩散源/扩散范围）", pb: "卡 4（链路拓扑图工具落地）" }
				]
			},
			{
				id: "card-ransom", label: "卡5 勒索应急", desc: "隔离防继续加密", zone: "cards",
				items: [
					{ id: "isolate2", label: "隔离（动加密进程前先快照）", ref: "windows/malware/ransomware.md" },
					{ id: "time-win", label: "加密时间窗定位（文件 mtime 聚焦）", ref: "windows/malware/ransomware.md" },
					{ id: "family", label: "勒索信家族识别", ref: "windows/malware/ransomware.md" },
					{ id: "decrypt", label: "解密可行性（公开解密器/不建议支付）", ref: "windows/malware/ransomware.md" },
					{ id: "restore", label: "备份还原+验证无再生再接入", ref: "windows/malware/ransomware.md" },
					{ id: "pre-lateral", label: "前置横向失陷还原（五维扩线）", ref: "windows/malware/ransomware.md" },
					{ id: "double-ext", label: "双重勒索（数据外传威胁面）", ref: "windows/malware/ransomware.md" },
					{ id: "crypto-rev", label: "加密器逆向（协同 binary）", pb: "卡 5" }
				]
			},
			{
				id: "card-vuln", label: "卡6 渗透漏洞应急", desc: "漏洞被利用的入口事件", zone: "cards",
				items: [
					{ id: "exp-anchor", label: "EXP 锚点定位（payload 痕迹→组件版本）", pb: "卡 6" },
					{ id: "ev-save", label: "利用证据保全（请求原文/落地物）", pb: "卡 6" },
					{ id: "mitigation", label: "临时缓解（WAF 规则/配置加固）", pb: "卡 6" },
					{ id: "patch", label: "补丁修复", pb: "卡 6" },
					{ id: "retest", label: "复测验证（同款 EXP 证实不再可利用）", pb: "卡 6" }
				]
			},
			{
				id: "card-forensics", label: "卡7 数字取证", desc: "artifacts 重建行为轨迹", zone: "cards",
				items: [
					{ id: "fit", label: "适用判定（痕迹不足/已删/无文件攻击）", pb: "卡 7" },
					{ id: "image", label: "镜像优先/只读挂载/逐项哈希", pb: "卡 7" },
					{ id: "win-arts", label: "Windows artifacts 优先序", ref: "windows/methodology/disk-artifacts.md" },
					{ id: "rebuild", label: "执行/删除/浏览/外带行为重建", ref: "linux/knowledge/disk-artifacts.md" }
				]
			},
			{
				id: "card-mining", label: "卡8 挖矿应急", desc: "快照先行·多家族并存", zone: "cards",
				items: [
					{ id: "detect", label: "入口判定（高占用/矿池端口·Stratum/新增定时项）", pb: "卡 8" },
					{ id: "snapshot-first", label: "先快照再处置（竞品互杀+备胎再生，不裸杀进程）", pb: "卡 8（时敏动作）" },
					{ id: "persist-sweep", label: "持久化面全量清点（crontab/systemd/authorized_keys/预加载）", pb: "卡 8" },
					{ id: "dual-ioc", label: "矿池+C2 双 IOC 面（只记矿池会漏控制通道）", pb: "卡 8" },
					{ id: "multi-family", label: "多家族并存纪律（清一个不算完）", pb: "卡 8（本卡核心）", ref: "linux/malware/mining-ransomware-backdoor.md" },
					{ id: "entry-rebuild", label: "入口还原（挖矿=失陷结果）+五维扩线", pb: "卡 8" },
					{ id: "recheck", label: "复测（资源正常+无反连+观察窗覆盖定时周期）", pb: "卡 8" }
				]
			},
			{
				id: "card-phish", label: "卡9 钓鱼邮件应急", desc: "邮箱失陷与伪造发信分型", zone: "cards",
				items: [
					{ id: "typed", label: "分型：邮箱失陷（改密撤会话）vs 扩散在途（网关召回）", pb: "卡 9（时敏分型）" },
					{ id: "mail-evidence", label: "邮件本体取证（SPF/DKIM/DMARC 判伪造或失陷）", pb: "卡 9", ref: "windows/scenarios/phishing.md" },
					{ id: "spread-face", label: "扩散面：同批收件人逐人排查（谁提交了凭据）", pb: "卡 9" },
					{ id: "mail-persist", label: "邮箱持久化：收件转发规则+OAuth 授权面（必查必清）", pb: "卡 9" },
					{ id: "entry-link", label: "入口还原（宏/凭证钓鱼/AiTM）+生态协作攻防社工钓鱼线", pb: "卡 9" },
					{ id: "recheck", label: "复测（异常登录消失/规则不再新建）", pb: "卡 9" }
				]
			},
			{
				id: "timeline", label: "时间线还原", desc: "时间轴第一产物", zone: "reconstruct",
				items: [
					{ id: "csv", label: "timeline.csv 合并排序（单一事实源）", pb: "扩线作战流程" },
					{ id: "multi", label: "单条日志不构成结论·多源互证", pb: "证据与时间线主线" },
					{ id: "render", label: "attack-timeline 渲染", ref: "windows/logs/timeline-building.md" },
					{ id: "lx-log", label: "Linux 日志分析", ref: "linux/logs/linux-log-analysis.md" }
				]
			},
			{
				id: "chain-rebuild", label: "攻击链还原", desc: "时间线逐节点闭合", zone: "reconstruct",
				items: [
					{ id: "win-chain", label: "Windows 攻击链重建", ref: "windows/attack-chain/attack-chain-reconstruction.md" },
					{ id: "lx-chain", label: "Linux 攻击链重建", ref: "linux/attack-chain/attack-chain-reconstruction.md" },
					{ id: "topo", label: "链路拓扑图登记（redteam_atlas_chain）", pb: "图谱联动" },
					{ id: "live-chain", label: "在线对抗攻击者链路还原", pb: "卡 1" }
				]
			},
			{
				id: "ioc-enrich", label: "IOC 富化", desc: "未富化如实标注", zone: "reconstruct",
				items: [
					{ id: "collect", label: "ioc.txt 单列清单", pb: "扩线作战流程" },
					{ id: "enrich", label: "批量富化（whois/被动DNS/TI 平台）", ref: "knowledge/threat-intel-2026.md" },
					{ id: "family", label: "家族/工具链归因", ref: "knowledge/threat-intel-2026.md" },
					{ id: "honest", label: "未富化不臆造归因", pb: "IOC 富化线" }
				]
			},
			{
				id: "attribution", label: "定性收口", desc: "疑似→取证验证→定性", zone: "reconstruct",
				items: [
					{ id: "tri-state", label: "三态收口（定性/疑似/排除）", pb: "失陷定性" },
					{ id: "ev4", label: "证据四级锚定", pb: "证据与时间线主线" },
					{ id: "ai-fp", label: "AI 辅助开发指纹归因", ref: "knowledge/threat-intel-2026.md" },
					{ id: "no-force", label: "定不实不硬凑结论", pb: "失陷定性" }
				]
			},
			{
				id: "mem-forensics", label: "内存取证", desc: "I1 可行时的编排落地", zone: "deep",
				items: [
					{ id: "vol3", label: "Volatility3 分析", pb: "内存取证线" },
					{ id: "hash-reg", label: "内存镜像外传哈希登记", pb: "内存取证线" },
					{ id: "fileless", label: "无文件攻击定位", ref: "windows/webshell/memory-shell.md" }
				]
			},
			{
				id: "disk-forensics", label: "盘面取证", desc: "artifacts 优先序", zone: "deep",
				items: [
					{ id: "kape", label: "KAPE/MFTECmd/PECmd", ref: "windows/methodology/disk-artifacts.md" },
					{ id: "csv-time", label: "CSV 归并进时间线", pb: "数字取证线" },
					{ id: "lx-arts", label: "Linux 盘面残留", ref: "linux/knowledge/disk-artifacts.md" }
				]
			},
			{
				id: "net-forensics", label: "网络取证", desc: "pcap 与流量还原", zone: "deep",
				items: [
					{ id: "pcap", label: "tshark pcap 分析", pb: "阶段默认通道" },
					{ id: "flow", label: "会话/流量还原", pb: "网络取证线" },
					{ id: "tunnel-detect", label: "隧道流量识别", ref: "linux/cookbook-linux/11-隧道.md" }
				]
			},
			{
				id: "cloud-ir", label: "云上应急", desc: "三型：实例/凭据/云面", zone: "deep",
				items: [
					{ id: "instance", label: "实例失陷型", pb: "云上应急审计线" },
					{ id: "cred-leak", label: "凭据泄露型", pb: "云上应急审计线" },
					{ id: "abuse", label: "云面滥用型", pb: "云上应急审计线" },
					{ id: "indicators", label: "云审计指标", ref: "knowledge/cloud-audit-indicators.md" }
				]
			},
			{
				id: "sample-handoff", label: "样本分析衔接", desc: "协同 binary", zone: "deep",
				items: [
					{ id: "static", label: "静态（YARA/strings/哈希）", pb: "阶段默认通道" },
					{ id: "dynamic", label: "动态协同 binary（隔离沙箱铁则）", pb: "样本动态" },
					{ id: "supply-chain", label: "恶意软件包供应链", ref: "linux/cookbook-linux/10-恶意软件包供应链攻击.md" }
				]
			},
			{
				id: "containment", label: "紧急处置", desc: "紧急通道压缩时延不绕确认", zone: "deliver",
				items: [
					{ id: "urgent", label: "紧急通道（秒快照→上报→阻断）", pb: "场景卡章·紧急处置通道" },
					{ id: "confirm-sys", label: "阻断类确认制（杀进程/断网/封禁/重命名）", pb: "紧急处置通道" },
					{ id: "no-delete", label: "删除固有数据严禁红线", pb: "边界条款" }
				]
			},
			{
				id: "remediation", label: "处置建议", desc: "只出清单·用户确认执行", zone: "deliver",
				items: [
					{ id: "checklist", label: "清理清单", pb: "处置建议" },
					{ id: "harden", label: "加固建议（检测/处置/风险/验证）", pb: "处置建议" },
					{ id: "script", label: "检测排查脚本/YARA 交付", pb: "交付公约" },
					{ id: "confirm-run", label: "用户确认后执行·操作痕迹登记", pb: "处置建议" },
					{ id: "retest2", label: "复测闭环", pb: "复测闭环" }
				]
			},
			{
				id: "report", label: "报告", desc: "时间线第一产物", zone: "deliver",
				items: [
					{ id: "timeline-first", label: "时间线第一产物", pb: "报告模板" },
					{ id: "five-dim-r", label: "五维影响范围评估", pb: "扩线作战流程" },
					{ id: "handover", label: "残留与移交（处置清单移交）", pb: "报告模板" }
				]
			}
		]
	},
	"cloud-security": {
		label: "云安全攻防",
		stages: [
			{ id: "s1", label: "1 测绘" },
			{ id: "s2", label: "2 路径验证" },
			{ id: "s3", label: "3 横向与持久化" },
			{ id: "s4", label: "4 权限链收口" },
			{ id: "s5", label: "5 检测缺口" },
			{ id: "s6", label: "6 环境还原" },
			{ id: "s7", label: "7 报告" }
		],
		forms: [
			{ id: "ssrf", label: "元数据 SSRF" },
			{ id: "leak", label: "泄露 AK/SK" },
			{ id: "container", label: "容器立足" },
			{ id: "cicd", label: "CI/CD" },
			{ id: "k8s", label: "K8s 立足" },
			{ id: "snapshot", label: "快照" }
		],
		formCategories: {
			ssrf: ["entry-disc","cred-verify","perm-recon","loot-order","deep-dig","cred-loop","trust-lateral","persist-cloud","hv-cloud","snapshot-line","detect-gap-cloud","env-restore","feedback-loop","report-cloud"],
			leak: ["entry-disc","cred-verify","perm-recon","loot-order","deep-dig","cred-loop","trust-lateral","persist-cloud","hv-cloud","snapshot-line","detect-gap-cloud","env-restore","feedback-loop","report-cloud"],
			container: ["entry-disc", "cred-verify", "perm-recon", "loot-order", "container", "k8s-line", "trust-lateral", "detect-gap-cloud", "report-cloud"],
			cicd: ["entry-disc", "cred-verify", "perm-recon", "loot-order", "cicd-line", "hv-cloud", "trust-lateral", "report-cloud"],
			k8s: ["entry-disc", "cred-verify", "perm-recon", "loot-order", "k8s-line", "trust-lateral", "report-cloud"],
			snapshot: ["entry-disc", "cred-verify", "perm-recon", "loot-order", "snapshot-line", "deep-dig", "report-cloud"]
		},
		zones: [
			{ id: "entry", label: "入口与凭证" },
			{ id: "engine", label: "战果扩大引擎" },
			{ id: "native", label: "云原生战场" },
			{ id: "close", label: "收口与检测" }
		],
		/** 登记词别名（cloud-security 专属）：结果词（路径类型/AK-SK 族/报告词）与体系技法标签的桥接
		 *  ——同 ad/binary/code-audit 别名机制；12 官方路径类型词全中+破 IAM/OIDC 歧义。 */
		aliases: {
			// 官方 12 路径类型词（playbook 登记指导）
			"凭证泄露利用": "entry-disc",
			"元数据服务": "entry-disc/imds", "元数据接管": "entry-disc/imds",
			"对象存储": "deep-dig/bucket-public", "存储桶": "deep-dig/bucket-public",
			"桶接管": "deep-dig/bucket-public", "对象桶接管": "deep-dig/bucket-public",
			"云数据库": "loot-order/data-face", "RDS": "loot-order/data-face",
			"权限提升": "deep-dig/iam-deep", "IAM 提权": "deep-dig/iam-deep", "IAM 权限提升": "deep-dig/iam-deep",
			"RAM 提权": "deep-dig/iam-deep", "角色提权": "deep-dig/iam-deep", "策略提权": "deep-dig/iam-deep", "权限链": "deep-dig/iam-deep",
			"K8s 集群": "k8s-line", "集群提权": "k8s-line/rbac",
			"CI-CD": "cicd-line",
			"持久化": "persist-cloud", "持久化后门": "persist-cloud",
			// AK/SK 泄露族（此前全变体不中）
			"AK/SK": "entry-disc/hardcoded-first", "AKSK": "entry-disc/hardcoded-first",
			"AK 泄露": "entry-disc/hardcoded-first", "AK泄露": "entry-disc/hardcoded-first",
			"SK 泄露": "entry-disc/hardcoded-first", "密钥泄露": "entry-disc/hardcoded-first",
			"凭据泄露": "entry-disc/hardcoded-first", "AccessKey 泄露": "entry-disc/hardcoded-first",
			"AccessKey": "entry-disc/hardcoded-first", "前端泄露": "entry-disc/hardcoded-first",
			// 接管/信任/收口词
			"子账号接管": "loot-order/ctrl-face", "账号接管": "loot-order/ctrl-face",
			"IAM": "perm-recon",
			"OIDC": "trust-lateral/oidc", "跨云": "trust-lateral",
			"Secret 泄露": "loot-order/secret-face",
			"配置缺陷": "deep-dig", "配置错误": "deep-dig",
			"制品投毒": "cicd-line/artifact", "快照共享": "snapshot-line/snap-copy",
			"准入绕过": "k8s-line/admission", "Lambda": "serverless/fn-perm",
			"STS": "cred-verify/whoami",
			"日志缺失": "detect-gap-cloud/audit-log", "监控缺失": "detect-gap-cloud/baseline",
			"数据外传": "loot-order/exfil"
		},
		stateLabels: { "tested-found": "走通·有战果", "tested-clear": "执行·未走通", na: "不适用（附原因）", "budget-stop": "未尝试·让位/预算" },
		stateShort: { found: "走通", clear: "未走通", na: "不适用", budget: "让位" },
		chain: true,
		chainKinds: {
			entry: { label: "入口凭证", fill: "rgba(56,212,255,.16)", stroke: "#38d4ff" },
			identity: { label: "身份/角色", fill: "rgba(180,140,255,.15)", stroke: "#b48cff" },
			secret: { label: "密钥面", fill: "rgba(245,197,66,.12)", stroke: "#f5c542" },
			resource: { label: "云资源", fill: "rgba(58,157,255,.13)", stroke: "rgba(58,157,255,.65)" },
			pivot: { label: "信任链/横移", fill: "rgba(124,200,255,.10)", stroke: "#7cc8ff", dash: "5 3" },
			orgroot: { label: "组织根/KMS", fill: "rgba(255,143,95,.16)", stroke: "#ff8f5f" },
			other: { label: "其他", fill: "rgba(93,107,128,.14)", stroke: "rgba(141,153,171,.6)" }
		},
		categories: [
			{
				id: "entry-disc", label: "入口与凭证发现", desc: "六源——指纹命中即取", zone: "entry",
				items: [
					{ id: "git-repo", label: "代码仓库与 git 历史（gitleaks/trufflehog）", pb: "§0 六源①" },
					{ id: "cicd-env", label: "CI/CD 环境变量与 secrets manager", pb: "§0 六源②" },
					{ id: "imds", label: "实例元数据（SSRF→IMDS 链）", ref: "knowledge/metadata-service-endpoints.md" },
					{ id: "fe-bundle", label: "前端 bundle/小程序（AKIA/LTAI/AKID 指纹）", pb: "§0 六源④（指纹表在各 vendors 篇）" },
					{ id: "client-cfg", label: "客户端配置（credentials/kubeconfig/服务账号 JWT）", pb: "§0 六源⑤" },
					{ id: "bucket-backup", label: "对象桶内备份与配置文件", pb: "§0 六源⑥" },
					{ id: "hardcoded-first", label: "硬编码凭据优先利用（通则）", pb: "§0 通则" },
					{ id: "hunter-scan", label: "测绘平台补盲（hunter 影子云资产）", pb: "§0 测绘补盲" }
				]
			},
			{
				id: "cred-verify", label: "凭证验证与身份确认", desc: "拿到任何东西的第一步", zone: "entry",
				items: [
					{ id: "whoami", label: "身份确认（GetCallerIdentity 等价只读）", ref: "knowledge/cloud-api-readonly-probing.md" },
					{ id: "account-reg", label: "账号/租户/主体 ARN 登记", pb: "§1" }
				]
			},
			{
				id: "perm-recon", label: "权限侦察", desc: "这个身份能干什么", zone: "entry",
				items: [
					{ id: "policy-enum", label: "策略/角色/组枚举（cloudsplaining 类）", ref: "knowledge/iam-policy-language-cheatsheet.md" },
					{ id: "can-create", label: "可造身份标记（CreateKey/CreateRole）", pb: "§2" },
					{ id: "hv-face", label: "高危面标记（KMS/Secrets/组织管理）", pb: "§2" }
				]
			},
			{
				id: "loot-order", label: "战果提级序", desc: "先拿什么", zone: "engine",
				items: [
					{ id: "identity-face", label: "身份面（能造 key/角色）", pb: "§3" },
					{ id: "ctrl-face", label: "控制面（控制台接管）", ref: "knowledge/metadata-service-endpoints.md" },
					{ id: "secret-face", label: "密钥面（Secrets/SSM/KMS）", pb: "§3" },
					{ id: "data-face", label: "数据面（桶/库/快照）", pb: "§3" },
					{ id: "exfil", label: "数据外传（exfil/回传通道）", pb: "§3" }
				]
			},
			{
				id: "deep-dig", label: "深挖线", desc: "五类战果标准拿法", zone: "engine",
				items: [
					{ id: "iam-deep", label: "身份与提权", ref: "vendors/aws/iam.md" },
					{ id: "ctrl-deep", label: "控制面接管", ref: "vendors/aws/ssrf-metadata.md" },
					{ id: "bucket-public", label: "对象桶公开/接管", ref: "vendors/aws/s3.md" },
					{ id: "bucket-backdoor", label: "桶对象后门植入/云 CLI 执行", ref: "vendors/aliyun/oss.md" },
					{ id: "persist-deep", label: "持久化（全部登记还原账本）", pb: "§4" },
					{ id: "lateral-deep", label: "信任链横移", pb: "§4/§6" }
				]
			},
			{
				id: "cred-loop", label: "凭证循环放大", desc: "新凭证→身份→权限→新面", zone: "engine",
				items: [
					{ id: "new-cred", label: "循环扩大（轮次可见=可审计）", pb: "§5" },
					{ id: "pool", label: "凭证池 creds-cloud.txt（指纹+身份+来源）", pb: "过程纪律" }
				]
			},
			{
				id: "trust-lateral", label: "横向信任链", desc: "枚举可扮演角色", zone: "engine",
				items: [
					{ id: "assume-role", label: "跨账号 AssumeRole 链", pb: "§6" },
					{ id: "svc-role", label: "服务角色绑定", pb: "§6" },
					{ id: "oidc", label: "OIDC 联邦信任", pb: "§6" },
					{ id: "org-member", label: "资源目录成员账号（用户确认制）", pb: "§6/§8" }
				]
			},
			{
				id: "persist-cloud", label: "持久化（登记制）", desc: "环境改动全登记·不自动清理", zone: "engine",
				items: [
					{ id: "backdoor-role", label: "后门角色", pb: "§7" },
					{ id: "new-key", label: "新增 AccessKey", pb: "§7" },
					{ id: "oidc-add", label: "OIDC 信任新增", pb: "§7" },
					{ id: "fn-backdoor", label: "函数后门", ref: "native/serverless/04-function-persistence.md" },
					{ id: "image-poison", label: "镜像投毒", ref: "native/container/02-image-supply-chain.md" }
				]
			},
			{
				id: "hv-cloud", label: "高价值目标", desc: "发现即提级", zone: "engine",
				items: [
					{ id: "kms", label: "KMS/密钥管理（域控级）", pb: "高价值目标对照" },
					{ id: "idp", label: "IdP/OIDC 联邦信任（堡垒机级）", pb: "高价值目标对照" },
					{ id: "org-root", label: "组织根/管理账号（域控 2.0·最敏感）", pb: "高价值目标对照" },
					{ id: "create-key", label: "能造账号的权限（战果无限再生）", pb: "高价值目标对照" },
					{ id: "cicd-hv", label: "CI/CD 平台（流水线凭据直通工作负载）", ref: "native/cicd/01-pipeline-attack-surface.md" }
				]
			},
			{
				id: "snapshot-line", label: "快照战果", desc: "云特有数据线", zone: "engine",
				items: [
					{ id: "snap-copy", label: "RDS/EBS 快照复制/共享", pb: "场景卡·卡 6（快照战果）" },
					{ id: "snap-restore", label: "授权账号自建恢复→数据落袋", pb: "场景卡·卡 6（快照战果）" }
				]
			},
			{
				id: "container", label: "容器立足", desc: "逃逸→节点→云 IAM", zone: "native",
				items: [
					{ id: "escape", label: "容器逃逸路径（内核/配置/漏洞）", pb: "场景卡·卡 3（容器立足）", ref: "native/container/01-container-escape-paths.md" },
					{ id: "hijack-imds", label: "特权容器劫持节点元数据（CAP_NET_RAW/hostNetwork）", ref: "native/container/01-container-escape-paths.md" },
					{ id: "image-supply", label: "镜像供应链", ref: "native/container/02-image-supply-chain.md" },
					{ id: "net-runtime", label: "容器网络与运行时", ref: "native/container/03-container-network-runtime-detection.md" },
					{ id: "node-role", label: "节点角色→云 IAM 绑定", pb: "场景卡·卡 3（衔接卡 1 元数据）" }
				]
			},
			{
				id: "k8s-line", label: "K8s 战场", desc: "RBAC 提权→集群→回云", zone: "native",
				items: [
					{ id: "exposure", label: "集群暴露面测绘", ref: "native/k8s/01-cluster-exposure-mapping.md" },
					{ id: "rbac", label: "RBAC 滥用提权", pb: "场景卡·卡 4（K8s 立足）", ref: "native/k8s/02-rbac-abuse-privesc.md" },
					{ id: "admission", label: "准入/NetworkPolicy 绕过", ref: "native/k8s/03-admission-networkpolicy-bypass.md" },
					{ id: "secret-exp", label: "Secret/配置暴露", ref: "native/k8s/04-secret-config-exposure.md" },
					{ id: "managed", label: "托管 K8s 平台风险", ref: "native/k8s/05-managed-k8s-platform-risks.md" },
					{ id: "iam-bind", label: "集群→云 IAM 绑定回云", pb: "场景卡·卡 4（集群→云）" }
				]
			},
			{
				id: "cicd-line", label: "CI/CD 流水线", desc: "凭据收割→批量负载→投毒", zone: "native",
				items: [
					{ id: "pipeline", label: "流水线攻击面", pb: "场景卡·卡 5（CI/CD）", ref: "native/cicd/01-pipeline-attack-surface.md" },
					{ id: "repo-perm", label: "代码仓库权限滥用", ref: "native/cicd/02-code-repo-permission-abuse.md" },
					{ id: "artifact", label: "制品仓库投毒（登记制）", pb: "场景卡·卡 5（登记制）", ref: "native/cicd/03-artifact-repo-poisoning.md" },
					{ id: "iac", label: "IaC 模板错误配置", ref: "native/cicd/04-iac-template-misconfig.md" },
					{ id: "ai-supply", label: "AI 供应链投毒（2026 新面）", ref: "native/cicd/03-artifact-repo-poisoning.md" }
				]
			},
			{
				id: "serverless", label: "Serverless", desc: "函数权限与环境密钥", zone: "native",
				items: [
					{ id: "fn-perm", label: "函数权限/触发器滥用", pb: "场景卡·卡 7（Serverless 立足）", ref: "native/serverless/01-function-permission-trigger-abuse.md" },
					{ id: "env-secret", label: "环境变量密钥（env 常存 AK/SK）", pb: "场景卡·卡 7", ref: "native/serverless/02-env-secrets.md" },
					{ id: "dep-poison", label: "依赖投毒（持久化+横向）", pb: "场景卡·卡 7（登记制）", ref: "native/serverless/03-supply-chain-dependency-poisoning.md" },
					{ id: "fn-persist", label: "函数持久化（后门函数/触发器）", pb: "场景卡·卡 7（登记 environment-restore）", ref: "native/serverless/04-function-persistence.md" }
				]
			},
			{
				id: "detect-gap-cloud", label: "检测缺口", desc: "云审计/日志/监控缺失面", zone: "close",
				items: [
					{ id: "audit-log", label: "云审计日志体系", ref: "detection/cloud-audit-log-systems.md" },
					{ id: "rule-design", label: "检测规则设计", ref: "detection/cloud-detection-rule-design.md" },
					{ id: "methodology", label: "检测缺口方法论", ref: "detection/cloud-detection-gap-methodology.md" },
					{ id: "baseline", label: "监控告警基线", ref: "detection/cloud-monitoring-alerting-baseline.md" }
				]
			},
			{
				id: "env-restore", label: "环境还原", desc: "C6 同一账本", zone: "close",
				items: [
					{ id: "restore-reg", label: "测试改动逐项还原登记", pb: "C6" },
					{ id: "trace-sem", label: "操作痕迹云版语义（角色/key/webhook/信任）", pb: "过程纪律" },
					{ id: "manual-remove", label: "手动排除步骤", pb: "§7" }
				]
			},
			{
				id: "feedback-loop", label: "反哺与穷尽", desc: "先登记再扩散", zone: "close",
				items: [
					{ id: "feedback", label: "成果实时登记（云攻击路径板式）", pb: "§9" },
					{ id: "exhaust", label: "穷尽终止（无新凭证/信任/权限）", pb: "§9" }
				]
			},
			{
				id: "report-cloud", label: "报告", desc: "attack-paths 五要素", zone: "close",
				items: [
					{ id: "path-csv", label: "attack-paths.csv（entry/identity/permission/resource/impact）", pb: "过程纪律" },
					{ id: "c7", label: "报告产出与门禁", pb: "阶段编排 C7" }
				]
			}
		]
	},
	"binary-analysis": {
		label: "二进制分析",
		stages: [
			{ id: "s1", label: "1 登记分诊" },
			{ id: "s2", label: "2 静态分析" },
			{ id: "s3", label: "3 动态分析" },
			{ id: "s4", label: "4 还原破解" },
			{ id: "s5", label: "5 假设循环覆盖" },
			{ id: "s6", label: "6 IOC 与报告" }
		],
		forms: [
			{ id: "windows", label: "Windows" },
			{ id: "linux", label: "Linux" },
			{ id: "macos", label: "macOS" },
			{ id: "mobile", label: "移动" },
			{ id: "firmware", label: "固件硬件" }
		],
		formCategories: {
			windows: ["sample-reg","triage-route","static-view","dyn-behavior","mem-line","adversarial","unpack-line","obfuscation","crack-line","instrument","ransom-card","platform-card","edr-card","exploit-line","ioc-rule","ledger-collect"],
			linux: ["sample-reg","triage-route","static-view","dyn-behavior","mem-line","adversarial","unpack-line","obfuscation","crack-line","instrument","ransom-card","platform-card","edr-card","exploit-line","ioc-rule","ledger-collect"],
			macos: ["sample-reg","triage-route","static-view","dyn-behavior","mem-line","adversarial","unpack-line","obfuscation","crack-line","instrument","ransom-card","platform-card","edr-card","exploit-line","ioc-rule","ledger-collect"],
			mobile: ["sample-reg","triage-route","static-view","dyn-behavior","adversarial","unpack-line","obfuscation","crack-line","instrument","mobile-card","platform-card","ioc-rule","ledger-collect"],
			firmware: ["sample-reg","triage-route","static-view","unpack-line","obfuscation","crack-line","instrument","firmware-card","platform-card","exploit-line","ioc-rule","ledger-collect"]
		},
		/** 登记词别名（binary-analysis 专属）：产物/判定/形态词（结果名词）与体系技法标签的桥接
		 *  ——同 ad/code-audit 别名机制；type=产物类型词表时自动点亮对应产出线格。 */
		aliases: {
			// 形态/格式词 → 平台特化格（原生样本专属格 pe-native/elf-native）
			"exe": "platform-card/pe-native", "dll": "platform-card/pe-native", "PE": "platform-card/pe-native",
			"so": "platform-card/elf-native", "ELF": "platform-card/elf-native",
			"Mach-O": "platform-card/macos", "go": "platform-card/gorust", "rust": "platform-card/gorust",
			"UPX": "unpack-line/pack-id", "VMP": "unpack-line/pack-id", "加壳": "unpack-line/pack-id",
			// 家族/分诊词
			"家族识别": "triage-route/family", "免杀家族": "triage-route/family", "样本": "triage-route",
			// 分析形态主词
			"静态分析": "static-view", "动态分析": "dyn-behavior", "行为分析": "dyn-behavior", "行为能力": "dyn-behavior", "挖矿": "dyn-behavior",
			// 产物类型十词（persona/playbook 官方词表）
			"脱壳还原二进制": "unpack-line/unpack", "脱壳还原": "unpack-line/unpack",
			"反编译源码": "static-view/pseudo", "提取配置": "obfuscation/downloader", "提取载荷": "obfuscation/downloader",
			"提取密钥(Key)": "crack-line/key", "密钥提取": "crack-line/key", "Key恢复": "crack-line/key",
			"C2 配置": "dyn-behavior/net", "C2提取": "dyn-behavior/net", "C2": "dyn-behavior/net",
			"修复样本": "unpack-line", "脚本工具": "crack-line/algo", "IOC 集": "ioc-rule",
			// 结论类型词
			"恶意定性": "ledger-collect", "算法破解": "crack-line", "后门确认": "dyn-behavior/persist", "后门": "dyn-behavior/persist",
			"诱饵排除": "ledger-collect", "固件后门": "firmware-card/fw", "rootkit": "platform-card/kernel"
		},
		zones: [
			{ id: "triage", label: "分诊与登记" },
			{ id: "dims", label: "分析维度" },
			{ id: "craft", label: "形态与还原" },
			{ id: "cards", label: "场景作战卡" },
			{ id: "deliver", label: "交付与收口" }
		],
		stateLabels: { "tested-found": "已分析·有结论", "tested-clear": "已分析·未见异常", na: "不适用（附原因）", "budget-stop": "未分析·收窄" },
		stateShort: { found: "有结论", clear: "未见异常", na: "不适用", budget: "未分析" },
		categories: [
			{
				id: "sample-reg", label: "样本登记与活体处置", desc: "登记完成前禁止任何分析动作", zone: "triage",
				items: [
					{ id: "reg", label: "sha256/来源/日期登记（B0 硬前置）", pb: "B0 登记" },
					{ id: "provenance", label: "登记产物 provenance.md", pb: "B0 校验物" },
					{ id: "live", label: "活体处置 SOP（隔离前置）", pb: "样本登记与活体处置 SOP" },
					{ id: "re-reg", label: "还原产物重新登记再流转", pb: "B1" }
				]
			},
			{
				id: "triage-route", label: "分诊路由", desc: "快筛后·假设循环前", zone: "triage",
				items: [
					{ id: "family", label: "家族指纹快筛", pb: "家族指纹快筛路由" },
					{ id: "router", label: "三路路由（病毒分析/逆向破解/固件）", pb: "分诊第三路" },
					{ id: "cluster", label: "多样本批次聚类（同事件多文件）", pb: "多样本批次聚类" }
				]
			},
			{
				id: "static-view", label: "静态三视角", desc: "不执行样本得出结论", zone: "dims",
				items: [
					{ id: "asm", label: "汇编视角", ref: "static/reverse-engineering-binary.md" },
					{ id: "pseudo", label: "伪代码视角", ref: "static/reverse-engineering-binary.md" },
					{ id: "callgraph", label: "调用图+字符串", ref: "static/malware-analysis-static.md" },
					{ id: "cross", label: "多视角交叉（≥2 视角一致才算结论）", pb: "分析维度覆盖规则" }
				]
			},
			{
				id: "dyn-behavior", label: "动态行为面", desc: "隔离 VM 内运行时观察", zone: "dims",
				items: [
					{ id: "proc", label: "进程行为", ref: "dynamic/malware-analysis-dynamic.md" },
					{ id: "file", label: "文件行为", ref: "dynamic/malware-analysis-dynamic.md" },
					{ id: "reg", label: "注册表（Windows 样本）", ref: "dynamic/malware-analysis-dynamic.md" },
					{ id: "net", label: "网络行为", ref: "detection/ja3-jarm-fingerprinting.md" },
					{ id: "persist", label: "持久化行为", ref: "behavior/malware-persistence.md" }
				]
			},
			{
				id: "mem-line", label: "内存分析", desc: "运行时内存取证", zone: "dims",
				items: [
					{ id: "memdump", label: "内存分析", ref: "dynamic/malware-analysis-memory.md" },
					{ id: "inject", label: "进程注入识别", ref: "dynamic/macos-process-injection.md" }
				]
			},
			{
				id: "adversarial", label: "对抗性构造", desc: "样本反分析手段", zone: "dims",
				items: [
					{ id: "antidebug", label: "反调试", ref: "methodology/anti-debugging.md" },
					{ id: "antihook", label: "反 hook", pb: "对抗性构造" },
					{ id: "forge", label: "伪造/提示注入对抗", pb: "对抗性构造" },
					{ id: "antivm", label: "反虚拟化检测对抗（双场景）", pb: "反虚拟化检测对抗章" }
				]
			},
			{
				id: "unpack-line", label: "壳识别与脱壳", desc: "识别→脱壳→IAT 修复", zone: "craft",
				items: [
					{ id: "pack-id", label: "壳/混淆识别", pb: "壳/混淆识别与脱壳" },
					{ id: "unpack", label: "脱壳（app 壳/Windows 壳）", pb: "脱壳与还原" },
					{ id: "iat", label: "IAT 修复", pb: "脱壳与还原" },
					{ id: "verify", label: "B1 三验（dex/IAT/可运行）", pb: "B1 还原完整性" }
				]
			},
			{
				id: "obfuscation", label: "混淆对抗", desc: "变体与混淆还原", zone: "craft",
				items: [
					{ id: "deobf", label: "反混淆", ref: "methodology/code-obfuscation-deobfuscation.md" },
					{ id: "diff", label: "二进制比对（同家族变体）", pb: "多样本批次聚类" },
					{ id: "downloader", label: "下载器链解码", ref: "methodology/downloader-chain-decoding.md" }
				]
			},
			{
				id: "crack-line", label: "逆向破解", desc: "key/算法/授权逻辑还原", zone: "craft",
				items: [
					{ id: "strength", label: "授权机制强度评估", pb: "逆向破解决策" },
					{ id: "key", label: "key/算法还原", pb: "主观念②" },
					{ id: "algo", label: "算法模拟复现脚本", pb: "主观念（交付公约）" },
					{ id: "protect", label: "保护机制破解", ref: "methodology/binary-protection.md" }
				]
			},
			{
				id: "instrument", label: "插桩与符号执行", desc: "工具化深挖", zone: "craft",
				items: [
					{ id: "frida", label: "frida 插桩 SOP", ref: "dynamic/frida-script-library.md" },
					{ id: "angr", label: "angr 符号执行", pb: "angr 符号执行分工" },
					{ id: "ai-assist", label: "AI 辅助逆向（2026）", ref: "trends/re-trends-2025-2026.md" }
				]
			},
			{
				id: "ransom-card", label: "勒索样本卡", desc: "行为+解密器", zone: "cards",
				items: [
					{ id: "behavior", label: "勒索行为分析（加密行为还原）", pb: "场景卡·卡 A（勒索样本）", ref: "behavior/reverse-engineering-ransomware.md" },
					{ id: "keygen", label: "解密器还原（密钥管理缺陷→复现→交 IR 卡 5）", pb: "场景卡·卡 A（核心价值）" }
				]
			},
			{
				id: "firmware-card", label: "固件与硬件卡", desc: "分诊第三路落地", zone: "cards",
				items: [
					{ id: "fw", label: "固件分析", ref: "firmware/firmware-analysis.md" },
					{ id: "uefi", label: "UEFI 逆向", ref: "firmware/uefi-reverse.md" },
					{ id: "hw", label: "硬件安全", pb: "固件与硬件作战卡" },
					{ id: "ot", label: "OT/ICS", pb: "固件与硬件作战卡" },
					{ id: "radio", label: "无线/SDR", pb: "固件与硬件作战卡" }
				]
			},
			{
				id: "mobile-card", label: "移动样本卡", desc: "app 壳与脱壳还原", zone: "cards",
				items: [
					{ id: "apk", label: "APK 逆向（权限组件面+家族快筛）", pb: "场景卡·卡 B（移动样本）", ref: "mobile/apk-reverse/SKILL.md" },
					{ id: "dump", label: "脱壳还原（dump apk pack）", pb: "脱壳与还原" },
					{ id: "app-shell", label: "app 壳对抗", pb: "脱壳与还原" }
				]
			},
			{
				id: "platform-card", label: "平台特化卡", desc: "按运行时与语言", zone: "cards",
				items: [
					{ id: "pe-native", label: "Windows PE 原生样本", ref: "static/reverse-engineering-binary.md" },
					{ id: "elf-native", label: "ELF 原生样本（Linux）", ref: "static/reverse-engineering-binary.md" },
					{ id: "dotnet", label: ".NET 样本（审计面挂 code-audit dotnet sink 表）", pb: "场景卡·卡 C（平台特化）", ref: "platform/dotnet-reverse/SKILL.md" },
					{ id: "gorust", label: "Go/Rust 变种（免杀家族常见）", pb: "场景卡·卡 C（变种语言）", ref: "platform/go-rust-reverse/SKILL.md" },
					{ id: "js", label: "JS 样本/混淆", pb: "场景卡·卡 C（变种语言）", ref: "platform/js-reverse/SKILL.md" },
					{ id: "macos", label: "macOS 样本", pb: "场景卡·卡 C（平台特化）", ref: "platform/macos-reverse/SKILL.md" },
					{ id: "protocol", label: "协议逆向（流量↔样本双向）", pb: "场景卡·卡 C（变种语言）", ref: "platform/protocol-reverse/SKILL.md" },
					{ id: "kernel", label: "内核 0day 挖掘", ref: "methodology/kernel-0day-hunting.md" },
					{ id: "browser", label: "浏览器/V8 样本（扩展权限面+供应链）", pb: "场景卡·卡 C（平台特化）", ref: "platform/browser-extension-reverse/SKILL.md" }
				]
			},
			{
				id: "edr-card", label: "EDR 规避样本卡", desc: "反检测样本逆向", zone: "cards",
				items: [
					{ id: "edrre", label: "EDR 规避手法逆向（检测面反推+规则回馈）", pb: "场景卡·卡 D（EDR 规避样本）", ref: "edr-bypass-re/SKILL.md" },
					{ id: "macos-bypass", label: "macOS 安全机制绕过", pb: "场景卡·卡 D（同卡处理）", ref: "macos-security-bypass/SKILL.md" }
				]
			},
			{
				id: "exploit-line", label: "漏洞样本与利用", desc: "崩溃→利用", zone: "cards",
				items: [
					{ id: "crash", label: "崩溃分析（类型/可控性初判+去重）", pb: "漏洞样本线 ①（崩溃分诊）", ref: "exploit-dev/crash-analysis.md" },
					{ id: "fuzz", label: "fuzzing（选型/语料/崩溃批量进分诊）", pb: "漏洞样本线·fuzzing 入口", ref: "exploit-dev/fuzzing.md" },
					{ id: "exploit", label: "利用开发（分析结论+利用条件→按需交接）", pb: "漏洞样本线 ④（按需交接）", ref: "exploit-dev/exploit-development.md" },
					{ id: "pwn", label: "pwn 面（完整战役走 ctf-solver）", pb: "漏洞样本线 ④（按需交接）", ref: "pwn/SKILL.md" }
				]
			},
			{
				id: "ioc-rule", label: "IOC 与检测输出", desc: "可落地规则", zone: "deliver",
				items: [
					{ id: "yara", label: "YARA 规则", ref: "detection/malware-detection-yara.md" },
					{ id: "ja3", label: "JA3/JARM 指纹", ref: "detection/ja3-jarm-fingerprinting.md" },
					{ id: "sigma", label: "Sigma 规则输出", pb: "IOC 与检测规则输出" }
				]
			},
			{
				id: "ledger-collect", label: "覆盖与假设台账", desc: "B2 收口", zone: "deliver",
				items: [
					{ id: "coverage", label: "analysis-coverage.md 维度终态", pb: "分析维度覆盖规则" },
					{ id: "ledger", label: "hypothesis-ledger.md（确认/证伪/未决）", pb: "假设台账终态规则" },
					{ id: "conf", label: "置信度对账（静态推断/动态确认/交叉）", pb: "结论置信度对账" },
					{ id: "report", label: "产物登记与报告", pb: "成果页登记/报告模板" }
				]
			}
		]
	},
	"code-audit": {
		label: "代码审计",
		stages: [
			{ id: "s1", label: "1 形态与 Triage" },
			{ id: "s2", label: "2 静态审计" },
			{ id: "s3", label: "3 动态验证" },
			{ id: "s4", label: "4 确证闭环" },
			{ id: "s5", label: "5 覆盖与对账" },
			{ id: "s6", label: "6 复核与报告" }
		],
		forms: [
			{ id: "web", label: "后端应用" },
			{ id: "mobile", label: "移动端" },
			{ id: "miniprogram", label: "小程序" },
			{ id: "ai", label: "LLM Agent" },
			{ id: "supply", label: "供应链配置" }
		],
		formCategories: {
			web: ["audit-shape","triage-audit","rce-main","sink-core","biz-logic","sink-priority","confirm-loop","scan-recon","diff-audit","review-cross","report-audit","card-config"],
			mobile: ["audit-shape","triage-audit","rce-main","sink-core","sink-priority","card-decompile","confirm-loop","report-audit"],
			miniprogram: ["audit-shape","triage-audit","sink-core","biz-logic","sink-priority","card-decompile","confirm-loop","report-audit"],
			ai: ["audit-shape","triage-audit","rce-main","sink-core","sink-priority","card-llm","confirm-loop","report-audit"],
			supply: ["audit-shape","triage-audit","card-sca","card-config","scan-recon","confirm-loop","report-audit"]
		},
		zones: [
			{ id: "triage", label: "审计前置" },
			{ id: "rce", label: "RCE 主线" },
			{ id: "matrix", label: "覆盖矩阵轴" },
			{ id: "cards", label: "场景审计卡" },
			{ id: "closure", label: "确证与交付" }
		],
		/** 代审登记词别名（code-audit 专属）：playbook 官方 type 词与近义词→格子（值支持 cat/item） */
		aliases: {
			"命令注入": "sink-core/cmd",
			"文件包含": "sink-core/file-rw",
			"硬编码前端绕过": "rce-main/hardcoded-rce",
			"fastjson": "rce-main/deep-deser",
			"shiro": "rce-main/deep-deser",
			"log4j": "rce-main/cve-patterns",
			"struts2": "rce-main/cve-patterns",
			"weblogic": "rce-main/cve-patterns"
		},
		stateLabels: { "tested-found": "已审·有 finding", "tested-clear": "已审·无 finding", na: "N-A（附原因）", "budget-stop": "未完成（预算）" },
		stateShort: { found: "有finding", clear: "无finding", na: "N-A", budget: "未完成" },
		categories: [
			{
				id: "audit-shape", label: "审计形态判定", desc: "第一动作——静/动与开工问询", zone: "triage",
				items: [
					{ id: "shape", label: "静态/动态形态判定", pb: "审计形态判定与开工问询" },
					{ id: "first-ask", label: "开工问询（环境/授权/范围）", pb: "审计形态判定与开工问询" },
					{ id: "lessons", label: "经验召回（lessons.md 续审）", pb: "审计前置识别（Triage）" }
				]
			},
			{
				id: "triage-audit", label: "前置识别", desc: "框架路由与面映射（A1）", zone: "triage",
				items: [
					{ id: "framework", label: "框架专项路由（refs components/ 九篇直达）", pb: "Triage·框架专项路由" },
					{ id: "fw-jeecg", label: "JeecgBoot 专项（积木报表/密钥/Online 面）", ref: "components/jeecg-boot.md" },
					{ id: "fw-ruoyi", label: "若依专项（定时任务 RCE/Shiro key/Druid/排序注入）", ref: "components/ruoyi.md" },
					{ id: "fw-spring", label: "Spring 全家桶专项（actuator/SpEL/Security 配置）", ref: "components/spring-framework.md" },
					{ id: "fw-thinkphp", label: "ThinkPHP 专项（按版本代核 RCE/SQLi/包含链）", ref: "components/thinkphp.md" },
					{ id: "sink-tables", label: "七语言 sink 大表（覆盖矩阵 sink 轴输入）", pb: "审计覆盖规则·sink 类型轴" },
					{ id: "surface-map", label: "面映射（入口清单+sink 面+深度分级）", pb: "Gate A1 面映射" }
				]
			},
			{
				id: "rce-main", label: "RCE 主线聚焦", desc: "七类——利用链成立即高危", zone: "rce",
				items: [
					{ id: "upload-rce", label: "任意文件上传 RCE", pb: "RCE 主线聚焦表" },
					{ id: "unauth-rce", label: "未授权 RCE（危险接口直达）", pb: "RCE 主线聚焦表" },
					{ id: "combo-rce", label: "组合 RCE（多步链串低危）", pb: "RCE 主线聚焦表" },
					{ id: "hardcoded-rce", label: "硬编码凭据利用链（密钥→伪造 token→RCE）", pb: "RCE 主线聚焦表" },
					{ id: "zipslip-rce", label: "zip 自解压/释放 RCE（zip-slip 覆盖）", pb: "RCE 主线聚焦表" },
					{ id: "deep-deser", label: "深度反序列化（嵌套/二次）", ref: "components/fastjson.md" },
					{ id: "overflow-rce", label: "溢出 RCE（C/C++ 系）", ref: "lang/code-audit-c-cpp.md" },
					{ id: "cve-patterns", label: "CVE RCE 模式对齐（2025-2026）", ref: "trends/cve-2025-rce-patterns.md" }
				]
			},
			{
				id: "sink-core", label: "危险 sink 全集", desc: "模块 × sink 类型双轴", zone: "matrix",
				items: [
					{ id: "cmd", label: "命令执行", pb: "sink 大表（refs/lang/ 对应语言手册）" },
					{ id: "sqli", label: "SQL 注入", ref: "README.md" },
					{ id: "deser", label: "反序列化", ref: "README.md" },
					{ id: "file-rw", label: "文件读写", ref: "README.md" },
					{ id: "ssrf", label: "SSRF", ref: "README.md" },
					{ id: "xxe", label: "XXE", ref: "README.md" },
					{ id: "ssti", label: "SSTI/模板", ref: "README.md" },
					{ id: "path", label: "路径穿越", ref: "README.md" },
					{ id: "el", label: "表达式注入", ref: "README.md" },
					{ id: "ldap", label: "LDAP", pb: "sink 大表" },
					{ id: "xpath", label: "XPath", pb: "sink 大表" },
					{ id: "crypto-mis", label: "密码学实现误用", ref: "crypto/crypto-misuse-audit.md" }
				]
			},
			{
				id: "biz-logic", label: "业务逻辑三行", desc: "sink 轴之外每模块另过", zone: "matrix",
				items: [
					{ id: "state-row", label: "状态变更（状态机跳步/回退）", pb: "业务逻辑维度行" },
					{ id: "race-row", label: "并发（双花/超卖/重复领取）", pb: "业务逻辑维度行" },
					{ id: "client-ctrl", label: "客户端可控值（金额/角色/回调）", pb: "业务逻辑维度行" }
				]
			},
			{
				id: "sink-priority", label: "sink 优先与覆盖", desc: "降深度不删格", zone: "matrix",
				items: [
					{ id: "same-sweep", label: "同型命中横扫（放大器纪律）", pb: "危险 sink 优先策略" },
					{ id: "matrix-cov", label: "audit-coverage-matrix.md 双轴终态", ref: "methodology/coverage.md" },
					{ id: "depth", label: "深度分级（快扫/深审/定向）", pb: "深度分级影响深度不影响排除" }
				]
			},
			{
				id: "card-llm", label: "LLM Agent 应用审计卡", desc: "OWASP Agentic Top 10（2026）", zone: "cards",
				items: [
					{ id: "agentic", label: "Agentic Top 10 视角审计", ref: "ai/ai-agent-safety.md" },
					{ id: "mcp-audit", label: "MCP/工具面审计", ref: "ai/ai-mcp-audit.md" },
					{ id: "prompt-sec", label: "提示与注入面", ref: "ai/ai-prompt-injection.md" }
				]
			},
			{
				id: "card-sca", label: "依赖供应链审计卡", desc: "SBOM→版本核对→投毒面", zone: "cards",
				items: [
					{ id: "sbom", label: "SBOM 生成", ref: "sca/devsecops-supply-chain.md" },
					{ id: "osv", label: "osv-scanner 版本核对", ref: "sca/devsecops-supply-chain.md" },
					{ id: "dep-confuse", label: "依赖混淆/投毒", ref: "sca/dependency-confusion.md" },
					{ id: "secrets-scan", label: "密钥泄露扫描（gitleaks）", ref: "sca/devsecops-secrets.md" }
				]
			},
			{
				id: "card-config", label: "配置与部署资产审计卡", desc: "IaC 与部署面", zone: "cards",
				items: [
					{ id: "dockerfile", label: "Dockerfile/镜像", ref: "config/container-security-scanning.md" },
					{ id: "k8s-manifest", label: "K8s manifest", ref: "config/kubernetes-security.md" },
					{ id: "nginx", label: "nginx/网关配置", pb: "工具手册·配置与部署资产审计" },
					{ id: "cloud-cfg", label: "云配置（权限/端口/密钥）", pb: "审计对象范围" }
				]
			},
			{
				id: "card-decompile", label: "反编译产物审计卡", desc: "移动端/小程序", zone: "cards",
				items: [
					{ id: "android", label: "Android 反编译（jadx/apktool）", pb: "移动端反编译审计" },
					{ id: "ios", label: "iOS 反编译（class-dump/OC runtime）", pb: "移动端反编译审计" },
					{ id: "wxapkg", label: "小程序解包审计", pb: "小程序解包代码" },
					{ id: "obf-reduce", label: "混淆识别与还原（不能还原如实降级）", pb: "移动端/小程序反编译审计" }
				]
			},
			{
				id: "confirm-loop", label: "确证闭环（双链）", desc: "A2——两条链一致才进复核", zone: "closure",
				items: [
					{ id: "dual-chain", label: "双链 TRACE（工人链 vs 追踪员链）", pb: "确证闭环流程" },
					{ id: "chain-verdict", label: "双链结论（一致/不一致/未决）", pb: "Gate A2" },
					{ id: "env-dyn", label: "动态验证（EXP 本地复现）", pb: "动态验证与证据留痕" },
					{ id: "evidence", label: "证据留痕（片段/行号/链引用）", ref: "methodology/evidence-first-audit.md" }
				]
			},
			{
				id: "scan-recon", label: "扫描命中对账", desc: "数量守恒（命中 N=终态 N）", zone: "closure",
				items: [
					{ id: "semgrep", label: "semgrep 静态扫描", pb: "工具手册·静态扫描" },
					{ id: "count-conserv", label: "对账数量守恒（scan-reconcile.md）", pb: "A3·扫描命中对账" },
					{ id: "fp", label: "误报排除（不可达/已过滤/框架已防）", pb: "扫描命中对账" }
				]
			},
			{
				id: "diff-audit", label: "Diff 审计", desc: "补丁与变更分支", zone: "closure",
				items: [
					{ id: "diff-mode", label: "Diff 审计分支（变更面聚焦）", pb: "Diff 审计模式" }
				]
			},
			{
				id: "review-cross", label: "交叉复核", desc: "无复核记录的报告条目拒收", zone: "closure",
				items: [
					{ id: "cross", label: "交叉复核规范", pb: "交叉复核规范" },
					{ id: "claude-upg", label: "claude 升级判据（审计差异化）", pb: "claude 升级判据" }
				]
			},
			{
				id: "report-audit", label: "报告与登记", desc: "六字段+SARIF", zone: "closure",
				items: [
					{ id: "finding-reg", label: "成果页登记（审计字段全集）", pb: "成果页登记" },
					{ id: "sarif", label: "SARIF 机器可读导出（CI 集成）", pb: "SARIF 导出" }
				]
			}
		]
	},
	"av-evasion": {
		label: "免杀对抗",
		stages: [
			{ id: "s1", label: "1 现象采集" },
			{ id: "s2", label: "2 诊断归因" },
			{ id: "s3", label: "3 路径与构建" },
			{ id: "s4", label: "4 判定实验" },
			{ id: "s5", label: "5 检测配对" },
			{ id: "s6", label: "6 回馈与交付" }
		],
		forms: [
			{ id: "webshell", label: "webshell" },
			{ id: "binary", label: "可执行" },
			{ id: "c2", label: "C2" },
			{ id: "retool", label: "工具二开" }
		],
		formCategories: {
			webshell: ["detect-loop","lab-loop","counter-table","lab-suites","payload-webshell","engine-matrix","verdict-pair","feedback-detect","deliver-reg","report-av"],
			binary: ["detect-loop","lab-loop","counter-table","lab-suites","payload-bin","engine-matrix","verdict-pair","feedback-detect","deliver-reg","report-av"],
			c2: ["detect-loop","lab-loop","counter-table","lab-suites","payload-c2","engine-matrix","verdict-pair","feedback-detect","deliver-reg","report-av"],
			retool: ["detect-loop","lab-loop","counter-table","lab-suites","payload-retool","engine-matrix","verdict-pair","feedback-detect","deliver-reg","report-av"]
		},
		zones: [
			{ id: "loop", label: "作战循环" },
			{ id: "counter", label: "对抗技术面" },
			{ id: "payload", label: "四类载荷时序" },
			{ id: "verdict", label: "判定与配对" },
			{ id: "deliver", label: "交付与回馈" }
		],
		stateLabels: { "tested-found": "已测·过检", "tested-clear": "已测·被检出", na: "不适用（无环境）", "budget-stop": "未测（附原因）" },
		stateShort: { found: "过检", clear: "被检出", na: "不适用", budget: "未测" },
		categories: [
			{
				id: "detect-loop", label: "过检测作战循环", desc: "问题驱动——被拦→过掉它", zone: "loop",
				items: [
					{ id: "collect", label: "1 被拦现象采集（入口情报）", pb: "过检测循环 §1" },
					{ id: "diagnose", label: "2 拦截面诊断与机制归因", pb: "过检测循环 §2" },
					{ id: "route", label: "3 对抗路径选择（决策表）", pb: "过检测循环 §3" },
					{ id: "iterate", label: "4 构建迭代（变体登记防重复）", pb: "过检测循环 §4" },
					{ id: "deliver", label: "5 过检投递（授权目标）", pb: "过检测循环 §5" },
					{ id: "feedback", label: "6 检测侧回馈", pb: "过检测循环 §6" }
				]
			},
			{
				id: "lab-loop", label: "本地攻防实验循环", desc: "V1-V4 门禁驱动", zone: "loop",
				items: [
					{ id: "v1", label: "V1 实验计划三声明（环境/去向/持久化预案）", pb: "门禁表 V1" },
					{ id: "round", label: "轮次台账（变体改动点显式登记）", pb: "判定与配对完整性规则" },
					{ id: "gates", label: "V1-V4 逐门过（结构+语义）", pb: "门禁表" }
				]
			},
			{
				id: "counter-table", label: "拦截面对抗决策表", desc: "从现象到选路", zone: "counter",
				items: [
					{ id: "static", label: "静态特征（混淆/壳/导入表清洗/借签/分离）", ref: "techniques/ADVANCED_EVASION.md" },
					{ id: "amsi", label: "AMSI（patchless/上下文破坏/替代宿主）", ref: "techniques/AMSI_BYPASS_TECHNIQUES.md" },
					{ id: "etw", label: "ETW（断 provider/syscall/遥测盲区）", ref: "techniques/AMSI_ETW_BYPASS.md" },
					{ id: "mem-scan", label: "内存扫描（reflective 变种/加密驻留/属性规避/call stack 伪造）", ref: "techniques/PROCESS_INJECTION.md" },
					{ id: "behavior", label: "行为序列（拆分跨进程/LOLBINS/间接调用/延时编排）", ref: "techniques/LOLBINS_AND_GTFO.md" },
					{ id: "sandbox", label: "沙箱/云引擎（环境感知/延时/交互依赖/资源门槛）", ref: "techniques/OPSEC_HARDENING.md" },
					{ id: "driver", label: "驱动级检测（BYOVD/内核对抗面）", ref: "trends/av-trends-2025-2026.md" },
					{ id: "runtime-gate", label: "分析准入门禁（运行时密钥/环境绑定）", pb: "决策表·运行时密钥门禁行" }
				]
			},
			{
				id: "lab-suites", label: "实验载荷组", desc: "lab/ 十二组随预设分发", zone: "counter",
				items: [
					{ id: "l01", label: "01 syscall 直调", pb: "lab/01-syscall-direct" },
					{ id: "l02", label: "02 patchless AMSI", pb: "lab/02-amsi-patchless" },
					{ id: "l03", label: "03 ETW patch", pb: "lab/03-etw-patch" },
					{ id: "l04", label: "04 unhook ntdll", pb: "lab/04-unhook-ntdll" },
					{ id: "l05", label: "05 加密加载器", pb: "lab/05-loader-encrypted" },
					{ id: "l06", label: "06 HWBP hook", pb: "lab/06-hwbp-hook" },
					{ id: "l07", label: "07 多语 webshell", pb: "lab/07-webshell-langs" },
					{ id: "l08", label: "08 内存马四型", pb: "lab/08-memory-shells" },
					{ id: "l09", label: "09 C2 profile", pb: "lab/09-c2-profile" },
					{ id: "l10", label: "10 webshell 管理器生态（魔改）", pb: "lab/10-webshell-managers" },
					{ id: "l11", label: "11 运行时密钥门禁", pb: "lab/11-runtime-key-gate" },
					{ id: "l12", label: "12 门禁链", pb: "lab/12-gate-chain" }
				]
			},
			{
				id: "payload-webshell", label: "webshell 免杀时序", desc: "生态决策：魔改 vs 自研", zone: "payload",
				items: [
					{ id: "judge", label: "原始马判型（特征词/加密/大马小马）", pb: "四类时序表" },
					{ id: "eco", label: "通用生态决策（存量魔改/自研+mini-client）", pb: "四类时序表" },
					{ id: "obf", label: "语言特征混淆或改写", pb: "四类时序表" },
					{ id: "memshell", label: "加密通讯马/内存马（无文件态）", ref: "zh/evasion-payloads-cn.md" },
					{ id: "transport", label: "传输层适配（流量特征）", pb: "四类时序表" },
					{ id: "verdict-eng", label: "引擎族判定（lab/10 对照）", pb: "四类时序表" }
				]
			},
			{
				id: "payload-bin", label: "可执行二进制时序", desc: "功能与特征分离", zone: "payload",
				items: [
					{ id: "split", label: "加载器+加密载荷分离", pb: "四类时序表" },
					{ id: "toolchain", label: "编译链（mingw/llvm+混淆 pass）", pb: "编译链与混淆" },
					{ id: "sign", label: "签名链（借签/伪造）", pb: "四类时序表" },
					{ id: "static-v", label: "静态判定 → 动态行为消减", pb: "四类时序表" }
				]
			},
			{
				id: "payload-c2", label: "C2 时序", desc: "流量与行为定制", zone: "payload",
				items: [
					{ id: "traffic", label: "流量特征分析（JA3/UA/心跳）", pb: "四类时序表" },
					{ id: "malleable", label: "malleable/协议伪装（域前置/CDN 中转）", ref: "techniques/C2_ARCHITECTURE.md" },
					{ id: "beacon", label: "Beacon 行为定制（睡眠/抖动/任务拆分）", ref: "techniques/BEACON_DEVELOPMENT.md" },
					{ id: "alive", label: "上线存活观察", pb: "四类时序表" }
				]
			},
			{
				id: "payload-retool", label: "工具二开时序", desc: "特征定位→改造", zone: "payload",
				items: [
					{ id: "locate", label: "原工具特征定位（字符串/导入/资源）", pb: "四类时序表" },
					{ id: "refactor", label: "源码级改造或二进制 patch", pb: "四类时序表" },
					{ id: "syscall-sub", label: "syscall 直调替代被 hook API", pb: "四类时序表" }
				]
			},
			{
				id: "engine-matrix", label: "判定引擎族矩阵", desc: "单引擎判定不下结论", zone: "verdict",
				items: [
					{ id: "base", label: "基础矩阵（Defender 最新+一款商业 EDR）", pb: "本地判定引擎族矩阵" },
					{ id: "extend", label: "沙箱扩展（延时/指纹差异观察）", pb: "本地判定引擎族矩阵" },
					{ id: "same-engine", label: "目标同款引擎（环境可知时优先补齐）", pb: "本地判定引擎族矩阵" }
				]
			},
			{
				id: "verdict-pair", label: "判定与配对完整性", desc: "结论只覆盖已测环境", zone: "verdict",
				items: [
					{ id: "per-env", label: "逐环境登记（检出/未检出/未测附原因）", pb: "判定与配对完整性规则" },
					{ id: "no-extrap", label: "禁止外推「对所有 AV/EDR 有效」", pb: "判定与配对完整性规则" },
					{ id: "mirror", label: "技术↔检测双向镜像表（V3 缺任一不完整）", pb: "判定与配对完整性规则" },
					{ id: "rule-selftest", label: "检测规则自测终态（已自测/初稿标注）", ref: "detection/malware-detection-yara.md" },
					{ id: "signal", label: "判定信号锚定（引擎输出原文行）", pb: "自测 SOP" },
					{ id: "sigma", label: "Sigma 规则产出", ref: "detection/sigma-rule-development.md" }
				]
			},
			{
				id: "tech-stack", label: "2026 技术栈", desc: "知识章节锚点", zone: "verdict",
				items: [
					{ id: "compile", label: "编译链与混淆", pb: "编译链与混淆" },
					{ id: "amsi-etw", label: "AMSI/ETW 机制", pb: "AMSI / ETW 机制" },
					{ id: "edr-tel", label: "EDR 遥测分析", ref: "detection/edr-telemetry-analysis.md" },
					{ id: "byovd", label: "BYOVD 生态（2026）", ref: "trends/av-trends-2025-2026.md" },
					{ id: "ai-av", label: "AI 辅助免杀（2026 新面）", ref: "trends/av-trends-2025-2026.md" }
				]
			},
			{
				id: "feedback-detect", label: "检测侧回馈", desc: "av-evasion → attack-defense 收口", zone: "deliver",
				items: [
					{ id: "rule-cand", label: "规则候选回馈（YARA/Sigma/遥测指标）", pb: "检测侧情报回馈" },
					{ id: "gap-handoff", label: "detection gap 对接（方向固定）", pb: "检测侧情报回馈" }
				]
			},
			{
				id: "deliver-reg", label: "交付物登记", desc: "交付物清单板式", zone: "deliver",
				items: [
					{ id: "kinds", label: "七类交付物（webshell/二进制/加载器/C2 二开/变形脚本/效果记录/规则配对）", pb: "交付物登记" },
					{ id: "pair-deliver", label: "交付即配对（每个免杀产物配检测规则）", pb: "判定与配对完整性规则" }
				]
			},
			{
				id: "report-av", label: "报告与外推检查", desc: "结论范围 ≤ 已测环境", zone: "deliver",
				items: [
					{ id: "v4", label: "V4 外推检查（范围不越已测环境）", pb: "门禁表 V4" },
					{ id: "six-field", label: "六字段报告与量化小结", pb: "报告模板" }
				]
			}
		]
	},
	"ctf-solver": {
		label: "CTF 解题",
		stages: [
			{ id: "s1", label: "1 题面登记" },
			{ id: "s2", label: "2 模块路由解题" },
			{ id: "s3", label: "3 flag 验证台账" },
			{ id: "s4", label: "4 复盘报告" }
		],
		forms: [
			{ id: "jeopardy", label: "Jeopardy" },
			{ id: "awd", label: "AWD" },
			{ id: "koth", label: "KotH" }
		],
		formCategories: {
			jeopardy: ["mod-core","mod-eco","triage-solve","card-jeopardy","strategy","discipline","ledger-writeup"],
			awd: ["mod-core","mod-eco","card-awd","strategy","discipline","ledger-writeup"],
			koth: ["mod-core","mod-eco","card-koth","strategy","discipline","ledger-writeup"]
		},
		aliases: {
			// 成果页 type=题目模块（主线词）→ 格子；web/pwn/supply 等短词 label 归一后无词边界、裸 id 不参与全局解析，靠别名直连
			"web": "mod-core/web", "pwn": "mod-core/pwn", "reverse": "mod-core/reverse", "rev": "mod-core/reverse",
			"crypto": "mod-core/crypto", "misc": "mod-core/misc", "forensics": "mod-core/forensics",
			"ai-ml": "mod-core/ai-ml", "aiml": "mod-core/ai-ml", "osint": "mod-core/osint", "malware": "mod-core/malware",
			"mobile": "mod-eco/mobile", "ad-domain": "mod-eco/ad-domain", "ad": "mod-eco/ad-domain", "域": "mod-eco/ad-domain",
			"cloud": "mod-eco/cloud", "supply": "mod-eco/supply", "supply-chain": "mod-eco/supply", "供应链": "mod-eco/supply"
		},
		zones: [
			{ id: "modules", label: "题型模块" },
			{ id: "formats", label: "赛制作战卡" },
			{ id: "discipline", label: "纪律与台账" }
		],
		stateLabels: { "tested-found": "已解·flag 验证", "tested-clear": "已试·卡点", na: "不适用（无此类题）", "budget-stop": "未开（让位）" },
		stateShort: { found: "已解", clear: "卡点", na: "不适用", budget: "未开" },
		categories: [
			{
				id: "mod-core", label: "核心模块", desc: "内建 refs 知识库入口", zone: "modules",
				items: [
					{ id: "web", label: "web（SQLi/SSTI/SSRF/JWT/OAuth·SAML/走私/原型污染）", ref: "ctf-web/SKILL.md" },
					{ id: "pwn", label: "pwn（ROP/格式化字符串/堆 fsop/内核·容器逃逸）", ref: "ctf-pwn/SKILL.md" },
					{ id: "reverse", label: "reverse（壳/VM/反调试/算法还原）", ref: "ctf-reverse/SKILL.md" },
					{ id: "crypto", label: "crypto（古典→格，攻击模型全谱）", ref: "ctf-crypto/SKILL.md" },
					{ id: "misc", label: "misc（隐写/压缩包/自定义协议）", ref: "ctf-misc/SKILL.md" },
					{ id: "forensics", label: "forensics（磁盘/内存/流量/浏览器·邮箱/时间线）", ref: "ctf-forensics/SKILL.md" },
					{ id: "ai-ml", label: "ai-ml/提示注入（LLM 应用题）", ref: "ctf-ai-ml/SKILL.md" },
					{ id: "osint", label: "osint（情报检索类题）", ref: "ctf-osint/SKILL.md" },
					{ id: "malware", label: "malware（样本题，深析协同 binary）", ref: "ctf-malware/SKILL.md" }
				]
			},
			{
				id: "mod-eco", label: "生态加载模块", desc: "跨模块面就地加载专业模式", zone: "modules",
				items: [
					{ id: "mobile", label: "mobile（APK/IPA/签名/so）", pb: "模块路由表→binary refs mobile/" },
					{ id: "ad-domain", label: "AD/域（Kerberos/证书/Windows 身份）", pb: "模块路由表→attack-defense 域攻 refs" },
					{ id: "cloud", label: "cloud（元数据/K8s/云服务/容器）", pb: "模块路由表→cloud-security refs" },
					{ id: "supply", label: "供应链（制品/CI/依赖）", pb: "模块路由表→cicd refs+code-audit 供应链卡" }
				]
			},
			{
				id: "triage-solve", label: "分诊入口", desc: "题面特征判定", zone: "modules",
				items: [
					{ id: "triage", label: "solve-challenge 分诊（题面特征→模块）", ref: "solve-challenge/SKILL.md" },
					{ id: "feature-judge", label: "题面特征判读（路由表首列）", pb: "模块路由表" }
				]
			},
			{
				id: "card-jeopardy", label: "卡1 Jeopardy 解题赛", desc: "静态题板调度", zone: "formats",
				items: [
					{ id: "board-run", label: "题板调度与动态记分", pb: "卡 1" },
					{ id: "first-blood", label: "首通血量时机", pb: "卡 1" }
				]
			},
			{
				id: "card-awd", label: "卡2 AWD 攻防赛", desc: "三线并行", zone: "formats",
				items: [
					{ id: "atk-line", label: "批量攻击线", pb: "卡 2" },
					{ id: "patch-line", label: "防御 patch 线", pb: "卡 2" },
					{ id: "counter-line", label: "应急反打线", pb: "卡 2" }
				]
			},
			{
				id: "card-koth", label: "卡3 KotH 占点赛", desc: "占点与维持", zone: "formats",
				items: [
					{ id: "hold", label: "占点与维持", pb: "卡 3" },
					{ id: "anti", label: "反制与轮换", pb: "卡 3" }
				]
			},
			{
				id: "card-hybrid", label: "卡4 混合赛制", desc: "双得分形态资源分配", zone: "formats",
				items: [
					{ id: "detect", label: "识别（规则页双得分形态并存）", pb: "卡 4" },
					{ id: "resource", label: "资源分配（分值占比定倾斜+轮次间隔期解题）", pb: "卡 4" },
					{ id: "split-ledger", label: "两线台账分列与时间切换判据", pb: "卡 4" }
				]
			},
			{
				id: "strategy", label: "比赛策略层", desc: "调度与量化", zone: "formats",
				items: [
					{ id: "priority", label: "调度优先级（分值/血量/擅长）", pb: "比赛策略层" },
					{ id: "stuck", label: "卡点 30-45 分钟量化换题", pb: "比赛策略层" },
					{ id: "hint-ev", label: "hint 期望值决策", pb: "比赛策略层" },
					{ id: "submit", label: "提交纪律", pb: "比赛策略层" },
					{ id: "endgame", label: "收官纪律（剩余 15-20% 切换：未提交对账/软题快抢/不开新硬题）", pb: "比赛策略层·收官纪律" }
				]
			},
			{
				id: "discipline", label: "解题纪律", desc: "flag 真实性主线", zone: "discipline",
				items: [
					{ id: "flag-real", label: "flag 真实性（平台回显/本地 check 器）", pb: "flag 真实性主线" },
					{ id: "no-guess", label: "不猜不撞不伪造", pb: "解题纪律" },
					{ id: "sandbox", label: "沙盒内解题（题目环境=授权对象）", pb: "解题纪律" },
					{ id: "brute-last", label: "爆破最后手段·限速", pb: "解题纪律" }
				]
			},
			{
				id: "ledger-writeup", label: "台账与复盘", desc: "两门收口", zone: "discipline",
				items: [
					{ id: "board-gate", label: "board 门（challenge-board.md 题面登记）", pb: "两门门禁" },
					{ id: "flag-gate", label: "flag 门（flag-ledger.md 验证证据）", pb: "两门门禁" },
					{ id: "parallel", label: "多题并行编排", pb: "解题纪律" },
					{ id: "writeup", label: "writeup 检索合规与模板库闭环", ref: "ctf-writeup/SKILL.md" },
					{ id: "auto-submit", label: "平台提交自动化（CTFd 类 API 结果回写台账）", pb: "工具手册·平台提交自动化" }
				]
			}
		]
	},
};

/** 找格子：key 形如 `cat` 或 `cat/item`；返回 { category, item? } 或 undefined。 */
export function locate(taxonomy, key) {
	const [catId, itemId] = String(key).split("/");
	const category = taxonomy.categories?.find((c) => c.id === catId);
	if (!category) return undefined;
	if (itemId === undefined) return { category };
	const item = category.items.find((i) => i.id === itemId);
	return item ? { category, item } : undefined;
}

/** 形态下可见的子项（item.forms 缺省=全部；形态主类映射外的类不出现）。 */
export function itemsInForm(taxonomy, categoryId, formId) {
	const category = taxonomy.categories.find((c) => c.id === categoryId);
	if (!category) return [];
	if (formId && formId !== "all" && category.forms && !category.forms.includes(formId)) return [];
	return category.items.filter((i) => !i.forms || !formId || formId === "all" || i.forms.includes(formId));
}

/** 校验：全局格子 key 唯一、形态 id 合法、ref 路径不越界（存在性由测试层按 refs 根校验）。 */
export function validateTaxonomy() {
	const problems = [];
	for (const [modeId, t] of Object.entries(TAXONOMIES)) {
		if (t.pending) continue;
		const formIds = new Set(t.forms.map((f) => f.id));
		const zoneIds = new Set((t.zones || []).map((z) => z.id));
		const keys = new Set();
		for (const c of t.categories) {
			if (keys.has(c.id)) problems.push(`${modeId}: 主类 id 重复 ${c.id}`);
			keys.add(c.id);
			if (c.forms) for (const f of c.forms) if (!formIds.has(f)) problems.push(`${modeId}/${c.id}: 未知形态 ${f}`);
			if (c.zone !== undefined && !zoneIds.has(c.zone)) problems.push(`${modeId}/${c.id}: 未知战场 ${c.zone}`);
			for (const i of c.items) {
				const key = `${c.id}/${i.id}`;
				if (keys.has(key)) problems.push(`${modeId}: 格子 key 重复 ${key}`);
				keys.add(key);
				if (i.forms) for (const f of i.forms) if (!formIds.has(f)) problems.push(`${modeId}/${key}: 未知形态 ${f}`);
				if (i.ref !== undefined && (typeof i.ref !== "string" || i.ref.includes("..") || i.ref.startsWith("/"))) {
					problems.push(`${modeId}/${key}: ref 路径非法 ${i.ref}`);
				}
			}
		}
		for (const [formId, cats] of Object.entries(t.formCategories)) {
			if (!formIds.has(formId)) problems.push(`${modeId}: formCategories 引用未知形态 ${formId}`);
			for (const c of cats) if (!keys.has(c)) problems.push(`${modeId}/${formId}: 引用未知主类 ${c}`);
		}
	}
	return problems;
}

/** ref 字段全量清单（测试层用它逐个校验 refs/ 文件存在）。 */
export function refPaths(taxonomy) {
	const out = [];
	for (const c of taxonomy.categories || []) {
		for (const i of c.items) if (i.ref) out.push(i.ref);
	}
	return [...new Set(out)];
}

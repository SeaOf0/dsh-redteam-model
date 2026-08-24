// dsh-scanner-tools 工具注册表——声明式 CLI 参数模型（每个工具一个 def，新增工具只加一行数据）：
//   name/summary/params   工具注册面（defineTool 的名称/摘要/参数 schema；workspace 与 extra 由注册循环统一附加）
//   args.flags            命名参数 → CLI flag（值型；含 shell 元字符拒绝；required 可标）
//   args.combined         数值型参数（flag + 数值；def=保守默认；audited=true 显式覆盖进证据留痕；max=保守上限护栏）
//   args.switches         布尔开关（true 才拼入；白名单外开关走 extra 且留痕）
//   positional            位置参数名（append 到 argv 尾部）
//   defaults              保守默认参数（安全第一：连接扫描免 root / 限速 / 非交互 / 最小强度）
//   additional=extra      逃生门参数——显式附加参数，进证据留痕（不静默）
//   tiers                 六节点工具调用阶梯（本机 → MCP → 已装替代 → MCP 备选 → 问装 → 脚本编写）
//   limits                超时与输出预览上限
//   guard.active          true=主动扫描（防盲打：目标须已登记 assets.md / cloud-assets.md）；targetParam=防盲打取哪个参数当目标

const NO_SHELL_META = /[;&|`$><\n]/;

export const TOOL_DEFS = {
	nmap: {
		id: "nmap", bin: "nmap", name: "nmap_portscan", kind: "portscan", positional: "target",
		summary: "Port/service scan (local nmap, conservative: -sT connect scan no-root + -sV, --max-rate 1000 by default; explicit rate override is audit-logged). Requires the target registered in the asset baseline (防盲打).",
		hint: "端口/服务扫描：-sT 连接扫描（免 root）+ -sV 服务版本，默认 --max-rate 1000 保守限速",
		params: {
			target: { type: "string", required: true, description: "Target host/IP (must be registered in the asset baseline)" },
			ports: { type: "string", description: "Port range, e.g. 80,443,1000-2000 (default top 1000)" },
			scripts: { type: "string", description: "NSE script set (caution: heavy; off by default)" },
			rate: { type: "integer", description: "max-rate override (default 1000 conservative; override is audit-logged)" }
		},
		tiers: [
			"本机 nmap（本工具）",
			"MCP 通道：已连接 MCP 内的 nmap/端口扫描类工具（如 kali MCP）",
			"已装可代替工具：masscan 顶端口扫 / rustscan（+ 手动服务指纹）",
			"MCP 备选通道：其他已连接 MCP 内等价探测工具",
			"询问用户是否安装 nmap（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：bash /dev/tcp 端口探测、nc 循环等实现同等探测（登记 tool-plane「脚本代替 nmap」）"
		],
		args: {
			flags: {
				ports: { flag: "-p", type: "string" },
				scripts: { flag: "--script", type: "string" }
			},
			combined: { rate: { flag: "--max-rate", type: "number", def: 1000, max: 10000, audited: true } },
			switches: {}
		},
		defaults: ["-Pn", "-sT", "-sV"],
		limits: { timeoutMs: 300_000, previewChars: 6000 },
		guard: { active: true, targetParam: "target" }
	},
	masscan: {
		id: "masscan", bin: "masscan", name: "masscan_portscan", kind: "portscan", positional: "target",
		summary: "High-speed port scan (local masscan; conservative --rate 1000 by default, hard-capped; requires raw-socket privileges — falls back to nmap -sT without them). Requires the target registered in the asset baseline (防盲打).",
		hint: "高速端口扫（全网段快筛用）：默认 --rate 1000 保守；需 raw socket 权限（sudo），无权限直接降级 nmap -sT",
		params: {
			target: { type: "string", required: true, description: "Target IP/CIDR, e.g. 10.0.0.0/24 (must be registered)" },
			ports: { type: "string", required: true, description: "Ports, e.g. 80,443,8080 or 1-65535" },
			rate: { type: "integer", description: "packets/sec override (default 1000 conservative, hard cap 5000; override is audit-logged)" }
		},
		tiers: [
			"本机 masscan（本工具，需 sudo/raw socket）",
			"MCP 通道：已连接 MCP 内的端口扫描类工具（如 kali MCP nmap/masscan）",
			"已装可代替工具：nmap -sT（免 root，速度慢但同效）/ rustscan",
			"MCP 备选通道：其他已连接 MCP 内等价探测工具",
			"询问用户是否安装 masscan（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：bash /dev/tcp 并行探测脚本（登记 tool-plane「脚本代替 masscan」）"
		],
		args: {
			flags: { ports: { flag: "-p", type: "string", required: true } },
			combined: { rate: { flag: "--rate", type: "number", def: 1000, max: 5000, audited: true } },
			switches: {}
		},
		defaults: [],
		limits: { timeoutMs: 600_000, previewChars: 6000 },
		guard: { active: true, targetParam: "target" }
	},
	subfinder: {
		id: "subfinder", bin: "subfinder", name: "subfinder_enum", kind: "subdomain", positional: null,
		summary: "Passive subdomain enumeration (local subfinder — passive sources only, does not touch the target; no asset registration required). Backfill the asset baseline with results.",
		hint: "被动子域枚举（多被动源聚合，不触达目标）",
		params: {
			domain: { type: "string", required: true, description: "Base domain, e.g. example.com" }
		},
		tiers: [
			"本机 subfinder（本工具）",
			"MCP 通道：已连接 MCP 内的子域枚举类工具",
			"已装可代替工具：amass enum -passive / assetfinder / dig NS+AXFR 探查",
			"MCP 备选通道：其他已连接 MCP 内等价枚举工具",
			"询问用户是否安装 subfinder（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：证书透明日志查询（crt.sh API curl 脚本）等被动枚举（登记 tool-plane「脚本代替 subfinder」）"
		],
		args: {
			flags: { domain: { flag: "-d", type: "string", required: true } },
			combined: {},
			switches: {}
		},
		defaults: ["-silent", "-timeout", "60"],
		limits: { timeoutMs: 300_000, previewChars: 6000 },
		guard: { active: false }
	},
	gau: {
		id: "gau", bin: "gau", name: "gau_urls", kind: "passive-urls", positional: "domain",
		summary: "Passive URL/history collection (local gau — fetches known URLs from public archives; never touches the target). Ideal for the passive-recon stage and JS/API surface building.",
		hint: "被动 URL 历史收集（wayback/otx/commoncrawl 公开档案；入口面盘点与 JS 专线的弹药库）",
		params: {
			domain: { type: "string", required: true, description: "Domain, e.g. example.com" },
			providers: { type: "string", description: "Archive providers, e.g. wayback,otx,commoncrawl" },
			threads: { type: "integer", description: "fetch threads (default 5 conservative, cap 20; override is audit-logged)" }
		},
		tiers: [
			"本机 gau（本工具）",
			"MCP 通道：已连接 MCP 内的 URL 历史类工具",
			"已装可代替工具：waybackurls / hakrawler 被动档",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 gau（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：web.archive.org CDX API curl 脚本（登记 tool-plane「脚本代替 gau」）"
		],
		args: {
			flags: { providers: { flag: "--providers", type: "string" } },
			combined: { threads: { flag: "--threads", type: "number", def: 5, max: 20, audited: true } },
			switches: {}
		},
		defaults: [],
		limits: { timeoutMs: 300_000, previewChars: 6000 },
		guard: { active: false }
	},
	whatweb: {
		id: "whatweb", bin: "whatweb", name: "whatweb_fingerprint", kind: "fingerprint", positional: "target",
		summary: "Light web fingerprint (local whatweb, -a 1 conservative by default; aggression capped at 3). Unregistered targets allowed (like httpx_probe); backfill the asset baseline.",
		hint: "轻量 Web 指纹（默认 -a 1 保守；回填资产基线）",
		params: {
			target: { type: "string", required: true, description: "Target URL/host" },
			aggression: { type: "integer", description: "1-3 (default 1 conservative; 3 = more active, may trigger alerts; override is audit-logged)" }
		},
		tiers: [
			"本机 whatweb（本工具）",
			"MCP 通道：已连接 MCP 内的指纹识别类工具",
			"已装可代替工具：httpx_probe -tech-detect（本插件已封装）/ wappalyzer CLI",
			"MCP 备选通道：其他已连接 MCP 内等价指纹工具",
			"询问用户是否安装 whatweb（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：curl 抓响应头/指纹特征 + 手工比对（登记 tool-plane「脚本代替 whatweb」）"
		],
		args: {
			flags: {},
			combined: { aggression: { flag: "-a", type: "number", def: 1, max: 3, audited: true } },
			switches: {}
		},
		defaults: ["--no-errors", "--color=never"],
		limits: { timeoutMs: 180_000, previewChars: 6000 },
		guard: { active: false }
	},
	wafw00f: {
		id: "wafw00f", bin: "wafw00f", name: "wafw00f_detect", kind: "waf", positional: "target",
		summary: "WAF detection (local wafw00f, -a probes all known WAF signatures). Feeds the protection-profile stage BEFORE any active testing — rate budget and technique selection depend on it. Backfill the protection profile.",
		hint: "WAF 识别：防护画像阶段先判 WAF（速率预算与打法据此定——playbook 防护画像前置 doctrine 的工具落地）",
		params: {
			target: { type: "string", required: true, description: "Target URL/host" }
		},
		tiers: [
			"本机 wafw00f（本工具）",
			"MCP 通道：已连接 MCP 内的 WAF 识别类工具",
			"已装可代替工具：whatweb -a 3（部分识别）/ httpx 安全头侧判 + 手工 payload 探测（最小化）",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 wafw00f（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：发送典型触发 payload 观察拦截页特征（最小次数，登记 tool-plane「脚本代替 wafw00f」）"
		],
		args: {
			flags: {},
			combined: {},
			switches: {}
		},
		defaults: ["-a"],
		limits: { timeoutMs: 120_000, previewChars: 6000 },
		guard: { active: false }
	},
	dirsearch: {
		id: "dirsearch", bin: "dirsearch", name: "dirsearch_dirs", kind: "content-discovery", positional: null,
		summary: "Dir/path discovery (local dirsearch; conservative -t 10 threads by default). Requires the target registered in the asset baseline (防盲打). Rate budget follows the WAF profile.",
		hint: "目录/路径发现（与 ffuf 同域：dirsearch=自带字典上手快，ffuf=可配性更强；速率在 WAF 画像之后定）",
		params: {
			url: { type: "string", required: true, description: "Target base URL (must be registered)" },
			extensions: { type: "string", description: "e.g. php,html,js" },
			wordlist: { type: "string", description: "Custom wordlist path (absolute or SecLists)" },
			threads: { type: "integer", description: "threads (default 10 conservative, cap 30; override is audit-logged)" }
		},
		tiers: [
			"本机 dirsearch（本工具）",
			"MCP 通道：已连接 MCP 内的目录枚举类工具",
			"已装可代替工具：ffuf_fuzz（本插件已封装，-w 自选字典）/ gobuster / wfuzz",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 dirsearch（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：python 字典循环 requests 探测（登记 tool-plane「脚本代替 dirsearch」）"
		],
		args: {
			flags: {
				url: { flag: "-u", type: "string", required: true },
				extensions: { flag: "-e", type: "string" },
				wordlist: { flag: "-w", type: "string" }
			},
			combined: { threads: { flag: "-t", type: "number", def: 10, max: 30, audited: true } },
			switches: { recursive: "-r" }
		},
		defaults: [],
		limits: { timeoutMs: 600_000, previewChars: 6000 },
		guard: { active: true, targetParam: "url" }
	},
	sqlmap: {
		id: "sqlmap", bin: "sqlmap", name: "sqlmap_inject", kind: "sqli", positional: null,
		summary: "SQL injection verification (local sqlmap, always --batch non-interactive; conservative --level 1 --risk 1 --threads 1 by default). Data-minimization discipline: prefer --banner/--dbs/--count escalation; --dump or OS-level actions (--os-shell etc.) only on explicit user request, via the audited extra escape hatch. Requires the target registered in the asset baseline.",
		hint: "注入验证：--batch 非交互、level/risk/threads 默认 1 最小强度；**数据最小化分级**——banner→dbs→count 逐级证明，--dump/--os-shell 仅用户明示后经 extra 留痕执行（playbook 敏感数据最小化纪律）",
		params: {
			url: { type: "string", required: true, description: "Target URL with the injectable parameter, e.g. http://host/page?id=1 (must be registered)" },
			data: { type: "string", description: "POST body (if any)" },
			cookie: { type: "string", description: "Session cookie for authenticated testing" },
			level: { type: "integer", description: "1-3 (default 1; higher = more injection points tested; override is audit-logged)" },
			risk: { type: "integer", description: "1-3 (default 1; 2-3 include OR/time-based which are heavier; override is audit-logged)" },
			threads: { type: "integer", description: "concurrency (default 1 conservative, cap 5; override is audit-logged)" },
			dbs: { type: "boolean", description: "--dbs enumerate databases (escalation step)" },
			tables: { type: "boolean", description: "--tables enumerate tables (with --dbs or -D)" },
			count: { type: "boolean", description: "--counts row counts (minimal-impact proof of depth)" },
			banner: { type: "boolean", description: "--banner DBMS banner (minimal proof)" },
			forms: { type: "boolean", description: "--forms parse & test forms on the page" }
		},
		tiers: [
			"本机 sqlmap（本工具）",
			"MCP 通道：已连接 MCP 内的注入验证类工具",
			"已装可代替工具：nuclei sqli 模板（本插件 nuclei_scan -severity 可筛）+ 手工 payload 验证（sqlmap 定位后手工最小化复现）",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 sqlmap（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：python requests 手工注入验证脚本（时间盲注延迟判据等，登记 tool-plane「脚本代替 sqlmap」）"
		],
		args: {
			flags: {
				url: { flag: "-u", type: "string", required: true },
				data: { flag: "--data", type: "string" },
				cookie: { flag: "--cookie", type: "string" }
			},
			combined: {
				level: { flag: "--level", type: "number", def: 1, max: 3, audited: true },
				risk: { flag: "--risk", type: "number", def: 1, max: 3, audited: true },
				threads: { flag: "--threads", type: "number", def: 1, max: 5, audited: true }
			},
			switches: { dbs: "--dbs", tables: "--tables", count: "--count", banner: "--banner", forms: "--forms" }
		},
		defaults: ["--batch"],
		limits: { timeoutMs: 900_000, previewChars: 6000 },
		guard: { active: true, targetParam: "url" }
	},
	nikto: {
		id: "nikto", bin: "nikto", name: "nikto_scan", kind: "webserver-scan", positional: null,
		summary: "Web-server config/misconfig scan (local nikto, non-interactive; complementary to nuclei: nikto = server config & known issues, nuclei = template vulns). Noisy — expect IDS visibility; rate/discipline note applies. Requires the target registered in the asset baseline.",
		hint: "Web 服务器配置类扫描（与 nuclei 分工：nikto=服务器配置/已知问题，nuclei=模板漏洞；噪声大，授权与速率纪律适用）",
		params: {
			host: { type: "string", required: true, description: "Target URL/host (must be registered)" },
			tuning: { type: "string", description: "Scan tuning, e.g. 1,2,3 (info/file/default) — narrower = less noisy" },
			ssl: { type: "boolean", description: "force SSL" }
		},
		tiers: [
			"本机 nikto（本工具）",
			"MCP 通道：已连接 MCP 内的 Web 扫描类工具",
			"已装可代替工具：nuclei_scan（本插件已封装——模板覆盖大量同域检查，噪声更低）",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 nikto（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：curl 探测已知配置路径/响应头核查脚本（登记 tool-plane「脚本代替 nikto」）"
		],
		args: {
			flags: { host: { flag: "-h", type: "string", required: true }, tuning: { flag: "-Tuning", type: "string" } },
			combined: {},
			switches: { ssl: "-ssl" }
		},
		defaults: ["-nointeractive"],
		limits: { timeoutMs: 900_000, previewChars: 6000 },
		guard: { active: true, targetParam: "host" }
	},
	hydra: {
		id: "hydra", bin: "hydra", name: "hydra_brute", kind: "brute", positional: "target",
		summary: "Login brute-force (local hydra; conservative -t 4 threads by default, stop-on-first-valid). Requires the target registered in the asset baseline; hard-coded-credential-first doctrine applies — brute only after cred reuse/dictionary candidates, with rate discipline and lockout awareness.",
		hint: "登录爆破（默认 -t 4 保守+首中即停）：**硬编码凭据优先**——先走 JS/配置中的已获凭据与字典候选，爆破是后位手段；锁定策略与速率纪律适用",
		params: {
			target: { type: "string", required: true, description: "Target host + service, e.g. '10.0.0.5 ssh' / '10.0.0.5 rdp' / 'http-post-form 填模块串'（组合位置参数）" },
			login: { type: "string", description: "single username (-l)" },
			loginFile: { type: "string", description: "username list file (-L)" },
			passFile: { type: "string", description: "password list file (-P, absolute path)" },
			port: { type: "string", description: "port if non-default (-s)" },
			threads: { type: "integer", description: "parallel tasks (default 4 conservative, cap 16; override is audit-logged)" }
		},
		tiers: [
			"本机 hydra（本工具）",
			"MCP 通道：已连接 MCP 内的爆破类工具（如 kali MCP）",
			"已装可代替工具：medusa / ncrack",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 hydra（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：python 小字典循环 + 锁定感知（失败 N 次即停，登记 tool-plane「脚本代替 hydra」）"
		],
		args: {
			flags: {
				login: { flag: "-l", type: "string" },
				loginFile: { flag: "-L", type: "string" },
				passFile: { flag: "-P", type: "string" },
				port: { flag: "-s", type: "string" }
			},
			combined: { threads: { flag: "-t", type: "number", def: 4, max: 16, audited: true } },
			switches: {}
		},
		defaults: ["-f"],
		limits: { timeoutMs: 900_000, previewChars: 6000 },
		guard: { active: true, targetParam: "target" }
	},
	impacket: {
		id: "impacket", bin: "impacket", bins: ["impacket-{module}", "{module}.py"], name: "impacket_suite", kind: "ad-exec", positional: "target",
		summary: "Impacket AD toolkit (local; module selectable: secretsdump / psexec / wmiexec / smbexec / atexec / GetUserSPNs / GetNPUsers; binary auto-resolves between 'impacket-<module>' and '<module>.py' install layouts). Credential-first doctrine: use obtained creds/hashes, DCSync single-request over bulk logins; lateral-execution modules leave traces — op-trace ledger applies. Requires the target registered in the asset baseline.",
		hint: "AD 重兵器套件：secretsdump 凭据直取（DCSync 单请求优于批量登录）、psexec/wmiexec/smbexec/atexec 横向执行（痕迹管理纪律适用）、GetUserSPNs/GetNPUsers Roasting 线起点；双安装名自动解析",
		params: {
			module: { type: "string", required: true, enum: ["secretsdump", "psexec", "wmiexec", "smbexec", "atexec", "GetUserSPNs", "GetNPUsers"], description: "Impacket module to run" },
			target: { type: "string", required: true, description: "Module target, e.g. 'DOMAIN/user@10.0.0.5'（secretsdump/exec 线）或 'DC.DOMAIN/user -dc-ip 由 dcIp 参数给'（Roasting 线）" },
			hashes: { type: "string", description: "NTLM hash auth ':NTLMHASH' or 'LM:NT'（pass-the-hash）" },
			dcIp: { type: "string", description: "domain controller IP (-dc-ip，Roasting/域线用)" }
		},
		tiers: [
			"本机 impacket（本工具——impacket-<module> / <module>.py 双名自动解析）",
			"MCP 通道：kali MCP（impacket 全家）",
			"已装可代替工具：netexec/crackmapexec（--sam 凭据线）；secretsdump→reg save 三件套离线解",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 impacket（pip 装于工作区 venv，征得批准后——本工具绝不自动安装）",
			"不批准则脚本编写：python impacket 库直接调用（venv 内）或手工协议（登记 tool-plane「脚本代替 impacket」）"
		],
		args: {
			flags: { hashes: { flag: "-hashes", type: "string" }, dcIp: { flag: "-dc-ip", type: "string" } },
			combined: {},
			switches: {}
		},
		defaults: [],
		limits: { timeoutMs: 900_000, previewChars: 6000 },
		guard: { active: true, targetParam: "target" }
	},
	netexec: {
		id: "netexec", bin: "netexec", bins: ["netexec", "nxc"], name: "netexec_scan", kind: "ad-recon", positional: "target", prefixParam: "protocol",
		summary: "Network/AD protocol validation spray (local netexec, the maintained successor lineage; conservative -t 10 threads by default). Protocols: smb / winrm / ldap / ssh / mssql. Credential validation + situational enumeration (--sam/--shares/--users/--sessions/--pass-pol). Requires the target registered in the asset baseline; lockout awareness applies — spray with obtained cred candidates, not bulk.",
		hint: "AD 协议验证喷洒：凭据候选有效性批量验证 + 态势枚举（SAM/共享/会话/密码策略）；**锁定意识**——用已获凭据候选定向验证而非 bulk；与 crackmapexec 同语法互为替代",
		params: {
			protocol: { type: "string", required: true, enum: ["smb", "winrm", "ldap", "ssh", "mssql"], description: "Target protocol" },
			target: { type: "string", required: true, description: "Host or CIDR, e.g. 10.0.0.0/24（must be registered）" },
			user: { type: "string", description: "username (-u)" },
			pass: { type: "string", description: "password (-p)" },
			hashes: { type: "string", description: "NTLM hash auth (--hashes ':NTLMHASH')" },
			threads: { type: "integer", description: "threads (default 10 conservative, cap 50; override is audit-logged)" },
			sam: { type: "boolean", description: "--sam dump SAM hashes (admin required)" },
			shares: { type: "boolean", description: "--shares enumerate shares" },
			users: { type: "boolean", description: "--users enumerate domain users" },
			sessions: { type: "boolean", description: "--sessions active sessions" },
			passPol: { type: "boolean", description: "--pass-pol password policy（锁定阈值侦察——爆破前置）" }
		},
		tiers: [
			"本机 netexec / nxc（本工具）",
			"MCP 通道：kali MCP（netexec/重武器库）",
			"已装可代替工具：crackmapexec（原版同语法）/ evil-winrm（winrm 线）",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 netexec（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：python 定向凭据验证循环 + 锁定感知（登记 tool-plane「脚本代替 netexec」）"
		],
		args: {
			flags: { user: { flag: "-u", type: "string" }, pass: { flag: "-p", type: "string" }, hashes: { flag: "--hashes", type: "string" } },
			combined: { threads: { flag: "-t", type: "number", def: 10, max: 50, audited: true } },
			switches: { sam: "--sam", shares: "--shares", users: "--users", sessions: "--sessions", passPol: "--pass-pol" }
		},
		defaults: [],
		limits: { timeoutMs: 600_000, previewChars: 6000 },
		guard: { active: true, targetParam: "target" }
	},
	crackmapexec: {
		id: "crackmapexec", bin: "crackmapexec", bins: ["crackmapexec", "cme"], name: "crackmapexec_scan", kind: "ad-recon", positional: "target", prefixParam: "protocol",
		summary: "Network/AD protocol validation spray (local CrackMapExec, the original tool; same CLI grammar as its successor netexec; conservative -t 10 threads by default). Protocols: smb / winrm / ldap / ssh / mssql; --sam/--shares/--users/--sessions/--pass-pol enumeration. Requires the target registered in the asset baseline; lockout awareness applies.",
		hint: "AD 协议验证喷洒（原版，与 netexec 同语法互为替代；原版已停更——优先 netexec，本件为已装环境兼容）",
		params: {
			protocol: { type: "string", required: true, enum: ["smb", "winrm", "ldap", "ssh", "mssql"], description: "Target protocol" },
			target: { type: "string", required: true, description: "Host or CIDR（must be registered）" },
			user: { type: "string", description: "username (-u)" },
			pass: { type: "string", description: "password (-p)" },
			hashes: { type: "string", description: "NTLM hash auth (--hashes ':NTLMHASH')" },
			threads: { type: "integer", description: "threads (default 10 conservative, cap 50; override is audit-logged)" },
			sam: { type: "boolean", description: "--sam dump SAM hashes (admin required)" },
			shares: { type: "boolean", description: "--shares enumerate shares" },
			users: { type: "boolean", description: "--users enumerate domain users" },
			sessions: { type: "boolean", description: "--sessions active sessions" },
			passPol: { type: "boolean", description: "--pass-pol password policy（锁定阈值侦察——爆破前置）" }
		},
		tiers: [
			"本机 crackmapexec / cme（本工具）",
			"MCP 通道：kali MCP（重武器库）",
			"已装可代替工具：netexec（维护中的同语法继任者，优先）",
			"MCP 备选通道：其他已连接 MCP 内等价工具",
			"询问用户是否安装 crackmapexec（征得批准后安装——本工具绝不自动安装）",
			"不批准则脚本编写：python 定向凭据验证循环 + 锁定感知（登记 tool-plane「脚本代替 crackmapexec」）"
		],
		args: {
			flags: { user: { flag: "-u", type: "string" }, pass: { flag: "-p", type: "string" }, hashes: { flag: "--hashes", type: "string" } },
			combined: { threads: { flag: "-t", type: "number", def: 10, max: 50, audited: true } },
			switches: { sam: "--sam", shares: "--shares", users: "--users", sessions: "--sessions", passPol: "--pass-pol" }
		},
		defaults: [],
		limits: { timeoutMs: 600_000, previewChars: 6000 },
		guard: { active: true, targetParam: "target" }
	}
};

/** 由 def + 参数构建 argv：默认 → combined（含上限/留痕）→ flags（元字符拒绝）→ switches（布尔白名单）
 *  → positional → extra。返回 { argv, audit }——audit 为留痕行数组（保守默认时为空）。
 *  未知参数直接拒绝并列已知名（workspace/extra/switches 名也计入已知）。 */
export function buildArgs(def, params = {}) {
	const argv = [...def.defaults];
	const audit = [];
	const known = new Set(["workspace", "extra",
		...(def.positional ? [def.positional] : []),
		...(def.prefixParam ? [def.prefixParam] : []),
		...Object.keys(def.args?.flags ?? {}),
		...Object.keys(def.args?.combined ?? {}),
		...Object.keys(def.args?.switches ?? {})]);
	for (const k of Object.keys(params)) {
		if (params[k] === undefined || params[k] === "") continue;
		if (!known.has(k)) throw new Error(`未知参数 ${k}（已知：${[...known].filter((x) => x !== "workspace" && x !== "extra").join("/")}/extra）`);
	}
	for (const [k, spec] of Object.entries(def.args?.combined ?? {})) {
		let v = params[k];
		if (v === undefined || v === "") v = spec.def;
		if (v === undefined) continue;
		const n = Number(v);
		if (!Number.isFinite(n) || n < 0) throw new Error(`参数 ${k} 须为非负数值`);
		if (spec.max !== undefined && n > spec.max) throw new Error(`参数 ${k}=${n} 超保守上限 ${spec.max}`);
		argv.push(spec.flag, String(n));
		if (spec.audited && String(v) !== String(spec.def)) audit.push(`${spec.flag} ${v}（默认 ${spec.def}，显式覆盖留痕）`);
	}
	for (const [k, spec] of Object.entries(def.args?.flags ?? {})) {
		const v = params[k];
		if (v === undefined || v === "") {
			if (spec.required) throw new Error(`参数 ${k} 必填（${spec.desc ?? ""}）`);
			continue;
		}
		const s = String(v);
		if (NO_SHELL_META.test(s)) throw new Error(`参数 ${k} 含 shell 元字符，拒绝`);
		argv.push(spec.flag, s);
	}
	for (const [k, flag] of Object.entries(def.args?.switches ?? {})) {
		if (params[k] === true) argv.push(flag);
	}
	if (def.positional) {
		const t = params[def.positional];
		if (t === undefined || t === "") throw new Error(`参数 ${def.positional} 必填（扫描目标）`);
		if (NO_SHELL_META.test(String(t))) throw new Error(`目标含 shell 元字符，拒绝`);
		argv.push(String(t));
	}
	if (params.extra) {
		const s = String(params.extra);
		if (NO_SHELL_META.test(s)) throw new Error(`extra 含 shell 元字符，拒绝`);
		argv.push(...s.split(/\s+/).filter(Boolean));
		audit.push(`extra: ${s}（显式附加参数留痕）`);
	}
	if (def.prefixParam) {
		const pv = params[def.prefixParam];
		if (pv === undefined || pv === "") throw new Error(`参数 ${def.prefixParam} 必填`);
		argv.unshift(String(pv)); // 协议名打头（nxc smb <target> 语法），目标与选项随其后
	}
	return { argv, audit };
}

/** 六节点阶梯文案（工具描述与缺装提示共用）。 */
export function tiersLine(def) {
	return "工具调用阶梯（缺失逐级降，每级有出口）：\n" + def.tiers.map((t, i) => `  ${i + 1}. ${t}`).join("\n");
}

export { NO_SHELL_META };

# Burp Suite 插件生态清单

_Burp 插件系统清单：按测试场景归类关键插件与用途_

## 分类索引

| 场景 | 关键插件 |
|---|---|
| 隐藏攻击面/参数发现 | Param Miner、Backslash Powered Scanner、JS Link Finder |
| 越权/授权 | Autorize、AuthMatrix、403 Bypasser |
| 编码/加密变换 | Hackvertor、Unicode Normalizer |
| 认证/JWT | JWT Editor、JSON Web Token Attacker |
| 高速 fuzz | Turbo Intruder |
| 请求走私 | HTTP Request Smuggler、Turbo Intruder（smuggling 模板） |
| 流量与日志 | Logger++、Flow、SQLiPy |
| IP 轮换/指纹 | IP Rotate、Burp 上游代理轮换 |
| GraphQL | InQL、GraphQL Raider |
| 其他 | CO2、Active Scan++、Backslash Powered Scanner |

---

## 隐藏攻击面 / 参数发现

### Param Miner  `param-miner`
_发现隐藏参数、缓存投毒 unkeyed 头、隐藏端点_
```
# 在 Burp 里对目标发请求，Param Miner 后台猜隐藏参数/头
# 关注 "Guessed params" / "Guessed headers" 结果
```

### Backslash Powered Scanner  `backslash-powered`
_语义差异扫描（大小写/路径规范化/编码差异），比传统 fuzz 更省请求_
```
# 对路径/参数做系统性的「解析差异」探测，适合找 WAF/代理绕过面
```

### JS Link Finder  `js-link-finder`
_从 JS 文件提取隐藏端点/路径_
```
# 右键 JS 响应 → JS Link Finder → 提取 endpoints
```

---

## 越权 / 授权

### Autorize  `autorize`
_半自动越权检测：用高权限会话结果与低权限会话对比_
```
# 配置低权限 Cookie → 重放高权限请求 → 对比响应差异，标红越权
```

### AuthMatrix  `authmatrix`
_多角色×多端点授权矩阵可视化_
```
# 定义多角色，对每端点逐一标记各角色的访问结果
```

### 403 Bypasser  `403-bypasser`
_403 状态码绕过（路径改写/头注入/方法切换）_
```
# 对 403 的路径自动尝试：;/.//%2e 后缀、X-Original-URL、X-Rewrite-URL、方法覆盖
# 观察哪个变体返回 200/302
```

---

## 编码 / 加密变换

### Hackvertor  `hackvertor`
_嵌套编码/加密标签化 payload 变换（URL/hex/unicode/XOR/…）_
```
# 用 <@auto_encode_0>payload<@/auto_encode_0> 之类标签做多层编码
```

---

## 认证 / JWT

### JWT Editor  `jwt-editor`
_JWT 解码/篡改/重签（alg=none、密钥注入、kid 注入）_
```
# Repeater 里选 JWT → 改 header/payload → 用注入密钥重签
```

### JSON Web Token Attacker  `jwt-attacker`
_JWT 爆破/alg 混淆/none 攻击一键_
```
# 对 JWT 跑 alg=none / 弱密钥字典
```

---

## 高速 fuzz / 走私

### Turbo Intruder  `turbo-intruder`
_单连接高速并发请求（竞态/限购/走私）_
```
# 用 Python 脚本自定义并发，适合 race condition 与单包攻击
```

### HTTP Request Smuggler  `http-request-smuggler`
_CL.TE/TE.CL/TE.TE 走私自动探测_
```
# 选中请求 → Launch Smuggle probe，识别走私类型后生成 PoC
```

---

## 流量与日志

### Logger++  `loggerpp`
_高级流量日志/过滤/导出，比内建 History 更强的检索与高级过滤_
```
# 全局流量记录，按 regex/关键词过滤，导出到文件
```

### Flow  `burp-flow`
_攻击流图（多请求依赖链可视化）_
```
# 关联多请求的 token/跳转，画攻击链路
```

---

## IP 轮换 / 指纹

### IP Rotate  `ip-rotate`
_按请求轮换上游 IP（配合代理池）_
```
# 配置上游代理列表 → 每请求轮换源 IP，规避 IP 信誉封禁
```

> 说明：IP 轮换需合法上游（住宅/移动代理池），与 TLS 指纹（JA3/JA4）配合
> 才有效（见 `../../web/waf-bypass-techniques.md` §3.4）。

---

## GraphQL

### InQL  `inql`
_GraphQL 内省导出与查询生成_
```
# 右键 GraphQL 端点 → InQL → 导出 schema、生成查询模板
```

### GraphQL Raider  `graphql-raider`
_GraphQL 安全测试套件（内省/字段建议/批量）_
```
# 自动跑内省、字段建议、alias 批量等测试
```

---

## 其他

### CO2  `co2`
_杂项工具集（SQLi 编码/权限/Smuggling 辅助）_
```
# 常用 SQLi 编码器、Smuggling 辅助
```

### Active Scan++  `active-scan-plusplus`
_扩展主动扫描（Host 头注入、路径穿越、编码绕过）_
```
# 补充内建 Scanner 未覆盖的注入面
```

---

> 说明：插件按测试场景归类；安装走 BApp Store。payload/命令为通用写法，
> 未虚构插件不存在的参数。与 `tools-web-pentest.md` 的 Burp Suite 基础用法互补。

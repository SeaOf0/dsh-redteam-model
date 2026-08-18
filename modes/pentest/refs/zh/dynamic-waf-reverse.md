# 动态 JS 混淆型 WAF 对抗（瑞数 / 数美类）— 逆向定位 → 签名还原 → 补环境重放

> **AI 加载说明**：本手册覆盖动态验证码 / JS 混淆型 WAF（瑞数 River、数美 Shumei 等「行为验证 +
> 动态请求签名 + 环境指纹」类风控）的对抗链路。核心三步：**逆向定位 → 签名还原 → 浏览器补环境重放**。
> 与 `../../web/waf-bypass-techniques.md`（通用 WAF）分工：那本讲「造 payload 绕过规则」，
> 这本讲「伪造一个合法浏览器把请求发出去」。仅授权目标。

---

## 0. 为什么这类 WAF 不一样

瑞数 / 数美类风控不是「正则匹配 payload」的 WAF，而是**动态挑战（challenge）型**：

- 首次请求返回一段**混淆 JS**，浏览器执行后生成**动态 cookie / 动态 token**（如瑞数的
  `FSSBBIl1UgzbN7N...` 动态 cookie、数美的 `rid`/`device_id`）。
- JS 里收集**环境指纹**（UA、canvas、webgl、屏幕、时区、插件、字体、事件时序），并用
  **VM 保护 / 字符串加密 / 控制流平坦化**混淆。
- 后端校验「cookie 里的签名 = 当前会话 + 环境指纹 + 密钥」的一致性，不通过就持续挑战或 403。

因此绕过不是「换 payload」，而是**把签名算法逆向出来，用可控环境算出合法签名**。

---

## Part A：攻击方法论

### 1. 逆向定位（找到签名生成点）

#### 1.1 观察挑战流程

```
1. 浏览器首次访问 → 302/200 带 <script> 或 meta refresh，Set-Cookie 含 session
2. JS 执行 → 二次请求带上动态 cookie / 参数（rid、t、sign、token）
3. 后端校验通过 → 返回真实页面；否则继续挑战或 403
```

用抓包工具（Burp/Charles）对比「首次响应」与「二次请求」的差异，圈定**动态字段**。

#### 1.2 定位关键 JS

- 首次响应 HTML 里 `eval(` / `document.write` / 动态加载的 `<script src=...>`。
- 关键字：`cookie`、`document.cookie`、`XMLHttpRequest`、`fetch`、`navigator`、
  `window.location`、`Function(`、`setTimeout`。
- 断点建议（Chrome DevTools）：
  - `document.cookie` setter（`Object.defineProperty(document, 'cookie', ...)`）→ 拦截 cookie 写入点。
  - `XMLHttpRequest.prototype.open` / `send` → 拦截二次请求构造点。
  - `navigator.sendBeacon`、`fetch`。

#### 1.3 处理混淆

| 混淆形态 | 应对 |
|---|---|
| 字符串数组 + 索引（`_0x1234`） | 先还原字符串表，再重命名 |
| 控制流平坦化（switch/while-switch dispatcher） | 定位 dispatcher 变量，恢复真实控制流 |
| VM 保护（自定义 bytecode 解释器） | 定位 opcode 表与 handler，逐步还原语义（见 `js-reverse` 技能族） |
| eval 套 eval | 层层 `console.log` 或 Hook `eval`/`Function` 导出明文 |

**工具**：浏览器 DevTools（Snippets 内 Hook）、`jsjiami` 系列解密、AST 工具（babel 自定义插件
做常量折叠/控制流还原）、`frida`（移动端）、`js-reverse-mcp`（签名链路定位）。

### 2. 签名还原（还原算法）

#### 2.1 定位签名函数

在二次请求发出前，`send`/`open` Hook 内打印 URL 与 body，反推签名入参：

```javascript
// Chrome Snippets Hook 示例（授权环境）
(function(){
  const o = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(m,u){
    console.log('OPEN', m, u);
    return o.apply(this, arguments);
  };
  const s = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function(b){
    console.log('SEND', b);
    return s.apply(this, arguments);
  };
})();
```

#### 2.2 追踪数据流

- 从「最终签名值」回溯：它由哪些变量拼成？哪些来自环境指纹、哪些来自时间戳/随机数、哪些来自
  服务端下发的 challenge（如首次响应里的 `token`/`seed`）。
- 常见签名成分：`md5(env_fingerprint + t + seed + key)` 或 `sha256(...)`，或自定义位运算混淆。

#### 2.3 验证还原正确性

- 用同一输入在本地重算，比对是否与浏览器产生的签名一致。
- 若一致 → 可脱离浏览器纯计算；若含环境指纹且指纹参与签名 → 需「补环境」或「同环境重放」。

### 3. 浏览器补环境重放（三种方案）

#### 3.1 方案 A：真浏览器 + 驱动（首选，最省事）

用 Playwright / Puppeteer 驱动**真实无头浏览器**执行挑战 JS，直接拿合法 cookie：

```python
# Playwright 思路（授权环境）
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(headless=False)  # 必要时 headful，避免无头指纹被识别
    ctx = b.new_context(user_agent="<真实UA>")
    page = ctx.new_page()
    page.goto("https://target.example.com/login")
    page.wait_for_timeout(3000)  # 等待挑战 JS 执行完成
    cookies = ctx.cookies()      # 提取含动态签名的 cookie
    # 后续用 requests 携带 cookies 发起攻击请求
```

判据：拿到 cookie 后，requests 重放能拿到真实页面（非挑战页），且 payload 被后端处理。

#### 3.2 方案 B：补环境（脱离浏览器）

当目标是纯 JS 签名（无 DOM 依赖）时，用 `node + jsdom` 或 `vm2`/`quickjs` 补齐
`navigator/window/document/canvas` 等环境后，直接在 Node 里跑原始 JS 得到签名：

```javascript
// 思路（需自行补全环境对象）
const { JSDOM } = require('jsdom');
const dom = new JSDOM('<!DOCTYPE html>', { url: 'https://target.example.com' });
global.window = dom.window;
global.document = dom.window.document;
global.navigator = dom.window.navigator; // 按需 patch UA/platform/canvas 指纹
// 加载原始挑战 JS，调用其签名函数得到 token
```

判据：Node 算出的 token 与浏览器一致，且能被后端接受。

#### 3.3 方案 C：Hook 真浏览器导出算法（RPC 桥）

在真浏览器里 Hook 签名函数，把「输入→输出」暴露给 Python/外部进程（如通过 CDP 或注入 WebSocket）：

- 适合「环境指纹参与签名、但算法可从环境解耦」的场景。
- 判据：外部进程调用桥接拿到合法签名，且可任意构造业务参数。

---

## Part B：检测与防御（风控侧）

### 4. 检测绕过行为的特征

- 同一 cookie/token 被**多 IP / 多 UA / 异常时序**复用 → 重放特征。
- 环境指纹与 UA/头不一致（如 UA 说 Chrome 但 `navigator.plugins` 为空）→ 补环境痕迹。
- 无头浏览器特征（`navigator.webdriver=true`、缺少真实 GPU/字体、canvas 一致性差）。
- 请求时序机械（无鼠标移动/滚动/键入节奏）→ 自动化痕迹。

### 5. 加固建议（风控/WAF 产品侧）

| 措施 | 说明 |
|---|---|
| 签名绑定「环境指纹 + 会话 + 时效」 | 让纯重放失效，必须真环境 |
| 服务端下发 challenge 一次性 | 防 seed 复用重算 |
| 检测无头/自动化特征 | `webdriver`、`headless` UA、webgl 渲染器 |
| 行为时序校验 | 人机节奏，非脚本节奏 |
| 定期轮换混淆与算法 | 提高逆向成本，但非银弹 |

> 方法论参考：js-reverse 技能族（签名链路定位、页面观察取证、运行时采样、本地补环境复现）、
> jsjiami 混淆逆向思路。payload/脚本为通用写法，未整篇搬运外部原文。

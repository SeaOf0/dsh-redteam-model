# Java语言中FreeMarker XSS漏洞完整描述

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`any_freemarker_xss` · 类别：xss · 关键 sink：FreeMarkerTemplateUtils, Template, process, processTemplate, processTemplateIntoString
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


### Java语言中FreeMarker XSS漏洞完整描述
#### 一、漏洞本质
FreeMarker是Java生态中广泛使用的模板引擎，核心功能是将预定义模板与后端数据模型结合，动态生成HTML、XML、JSON等输出内容。FreeMarker的XSS（跨站脚本攻击）漏洞，本质是**模板中未对用户可控的输入数据进行安全且上下文适配的转义处理**，导致攻击者构造的恶意HTML/JavaScript代码被直接嵌入到输出的页面中，浏览器解析执行该恶意代码，进而引发XSS攻击。

该漏洞的核心诱因是FreeMarker默认不启用自动转义机制，且不同输出上下文（HTML、HTML属性、JavaScript、JSON等）对特殊字符的转义规则不同，若开发者未根据上下文做针对性处理，极易触发漏洞。

#### 二、FreeMarker渲染机制与转义基础
FreeMarker通过“插值语法”（`${变量名}`）将数据模型中的变量代入模板，核心转义能力依赖：
1. **自动转义（auto_escape）**：全局/局部配置是否自动对插值内容做HTML转义（FreeMarker 2.3.24+支持`AutoEscapePolicy`，默认值为`NONE`，即不自动转义）；
2. **内建转义函数**：如`?html`（HTML转义）、`?xml`（XML转义）、`?js_string`（JavaScript字符串转义）等，需开发者手动调用；
3. **指令控制**：如`<#autoesc>`/`<#noautoesc>`可局部覆盖自动转义规则。

XSS漏洞的核心触发点，是上述转义机制未被正确使用，导致用户输入的恶意字符（如`<`、`>`、`"`、`'`、`javascript:`等）未被转义，直接输出到页面中。

#### 三、FreeMarker XSS漏洞的典型场景
##### 场景1：未启用自动转义，直接插值用户输入（最常见）
FreeMarker默认关闭自动转义，模板中直接使用`${userInput}`渲染用户可控数据（如用户名、评论、搜索结果、URL参数等）时，恶意输入会被原样输出。

- 模板示例：
  ```html
  <div class="user-comment">${userComment}</div>
  ```
- Java后端传参示例：
  ```java
  Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
  Template template = cfg.getTemplate("comment.ftl");
  Map<String, Object> dataModel = new HashMap<>();
  // 攻击者构造的恶意输入
  dataModel.put("userComment", "<script>alert(document.cookie)</script>");
  // 渲染输出
  template.process(dataModel, new FileWriter("output.html"));
  ```
- 输出结果：
  ```html
  <div class="user-comment"><script>alert(document.cookie)</script></div>
  ```
  浏览器解析时会执行`<script>`标签内的恶意代码，窃取用户Cookie。

##### 场景2：错误使用转义函数（转义不充分/失效）
开发者虽尝试使用转义函数，但因函数选择错误、后续处理破坏转义结果，导致转义失效。

###### 子场景2.1：使用错误的转义函数
不同转义函数的适用场景不同，错用会导致关键字符未被转义：
- 示例：用`?xml`替代`?html`（XML转义不覆盖HTML全部特殊字符）：
  模板：`<div>${userInput?xml}</div>`
  攻击者输入：`&apos;<script>alert(1)</script>`
  - XML转义仅处理`&`、`<`、`>`、`"`、`'`，但`&apos;`在HTML中会被解析为单引号，仍可突破；
  - 输出结果：`<div>&apos;<script>alert(1)</script></div>`，浏览器解析后执行脚本。

###### 子场景2.2：转义后拼接/修改导致失效
对转义后的内容进行字符串替换、拼接等操作，破坏转义结果：
- 模板示例：
  ```html
  <div>${(userInput?html)?replace("&lt;", "<")}</div>
  ```
- 攻击者输入：`<script>alert(1)</script>`
- 过程：`userInput?html`先将`<`转义为`&lt;`，但后续`?replace`又将`&lt;`还原为`<`，最终输出原始恶意脚本。

###### 子场景2.3：仅部分数据转义
用户输入被拆分为多个变量，仅部分转义、部分未转义，攻击者可利用未转义部分注入：
- 模板示例：
  ```html
  <div>${userName?html}: ${userContent}</div>
  ```
- 攻击者控制`userContent`输入恶意脚本，因未转义直接输出触发XSS。

##### 场景3：自动转义配置失效/范围错误
全局配置了自动HTML转义，但局部禁用、配置值错误或模板类型识别错误，导致转义未生效。

###### 子场景3.1：局部禁用自动转义
全局开启`auto_escape=html`，但模板中通过`<#noautoesc>`禁用局部转义：
- 模板示例：
  ```html
  <#autoesc true>
    <div>${safeInput}</div> <!-- 自动转义 -->
  </#autoesc>
  <#noautoesc>
    <div>${unsafeInput}</div> <!-- 禁用转义 -->
  </#noautoesc>
  ```
- 攻击者控制`unsafeInput`输入恶意脚本，直接输出执行。

###### 子场景3.2：自动转义配置值错误
将`auto_escape`配置为`none`（无转义）、`xml`（仅XML转义）等非HTML值，导致HTML上下文转义失效：
- Java配置示例：
  ```java
  cfg.setAutoEscapePolicy(AutoEscapePolicy.NONE); // 全局禁用自动转义
  // 或错误配置为XML转义
  cfg.setAutoEscapePolicy(AutoEscapePolicy.XML);
  ```

###### 子场景3.3：模板类型识别错误
将HTML模板误标记为“纯文本模板”，导致自动转义未触发：
- 示例：FreeMarker的`TemplateLoader`加载模板时，未正确设置模板的`contentType`为`text/html`，导致自动转义规则不生效。

##### 场景4：渲染到HTML属性中（上下文适配不足）
即使启用基础HTML转义，渲染到HTML属性（如`value`、`href`、`onclick`等）时，因属性上下文的特殊字符未被针对性转义，仍可触发XSS。

###### 子场景4.1：属性引号类型不匹配导致转义失效
- 模板示例（属性用单引号）：
  ```html
  <input type="text" value='${userInput?html}'>
  ```
- 攻击者输入：`' onmouseover='alert(1)'`
- 分析：`?html`仅转义双引号（`"`→`&quot;`），不转义单引号（`'`），输出结果为：
  ```html
  <input type="text" value=' ' onmouseover='alert(1)'>
  ```
  鼠标悬浮时触发恶意代码。

###### 子场景4.2：伪协议注入（href/src等属性）
- 模板示例：
  ```html
  <a href="${userUrl?html}">点击跳转</a>
  ```
- 攻击者输入：`javascript:alert(1)`
- 分析：`?html`仅转义`<`/`>`等字符，`javascript:`伪协议未被过滤/转义，输出后点击链接会执行脚本。

##### 场景5：渲染到JavaScript/JSON上下文（跨上下文转义缺失）
`?html`仅适用于HTML上下文，若将用户输入渲染到`<script>`标签内的JavaScript代码、JSON数据中，仅用`?html`转义不足以防范JS注入。

- 模板示例（渲染到JS变量）：
  ```html
  <script>
    var username = "${userInput?html}";
  </script>
  ```
- 攻击者输入：`";alert(1);//`
- 分析：`?html`将`"`转义为`&quot;`，但浏览器解析`<script>`标签时，`&quot;`会被还原为`"`，最终JS代码变为：
  ```javascript
  var username = "";alert(1);//";
  ```
  直接执行`alert(1)`。

##### 场景6：动态生成模板内容（模板拼接导致的XSS）
若允许用户输入作为模板的一部分（如后端动态拼接模板字符串），即使未触发模板注入，也会直接导致XSS。

- Java后端示例：
  ```java
  // 危险：将用户输入直接拼接到模板字符串中
  String dynamicTemplate = "<div class='user-content'>" + userInput + "</div>";
  Template template = new Template("dynamic", new StringReader(dynamicTemplate), cfg);
  template.process(dataModel, writer);
  ```
- 攻击者输入：`<script>alert(1)</script>`，模板本身包含恶意脚本，渲染后直接输出执行。

##### 场景7：自定义宏/指令中的未转义数据
自定义FreeMarker宏（`macro`）或指令时，若宏内部未对接收的参数进行转义，即使调用宏时忘记转义，也会触发XSS。

- 模板示例（自定义宏未转义）：
  ```html
  <#macro renderUserInfo name>
    <span class="username">${name}</span> <!-- 宏内未转义 -->
  </#macro>
  <!-- 调用宏时未手动转义 -->
  <@renderUserInfo name=userInput/>
  ```
- 攻击者控制`userInput`输入恶意脚本，宏内直接渲染导致XSS。

#### 四、漏洞核心危害
FreeMarker XSS漏洞的危害与普通XSS一致，包括但不限于：
1. 窃取用户Cookie、Session ID，劫持用户会话；
2. 篡改页面内容（如插入钓鱼链接、虚假广告）；
3. 执行恶意JS代码，窃取用户浏览器中的敏感信息（如表单数据、本地存储）；
4. 发起CSRF攻击，利用用户权限操作后端功能；
5. 传播恶意代码（如挖矿脚本、木马）。


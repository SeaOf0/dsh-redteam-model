# Java 文件上传漏洞

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`jfinal_any_upload` · 类别：upload · 关键 sink：BufferedOutputStream, ByteSource, File, FileItem, FileOutputStream, FileUploadService, FileUtils, FileWriter, Files, IOUtils, ServletFileUpload, StorageService
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java 文件上传漏洞
文件上传漏洞是Web应用中高频且高危的安全漏洞，核心成因是**服务器未对上传文件的类型、内容、路径等进行严格校验**，导致攻击者可上传恶意文件（如JSP木马、Class文件、恶意脚本等）并执行，进而控制服务器。Java 生态因自身的技术特性（如Servlet规范、容器差异、框架封装等），其文件上传漏洞呈现出多场景、多变种的特点，以下从核心原理、触发条件、典型场景及变种形式展开完整描述。

## 一、核心原理
Java Web 应用处理文件上传的底层逻辑基于 Servlet 规范（如 `javax.servlet.http.Part`、`commons-fileupload` 组件），或通过 Spring MVC、Struts2 等框架封装实现。漏洞的本质是：
1. 服务器未拦截攻击者上传的**恶意可执行文件**；
2. 恶意文件被存储到 Web 容器可访问的目录（如 `WEB-INF/upload`、`static/upload` 等）；
3. 攻击者通过 URL 访问该文件，触发 Java 容器（Tomcat/Jetty/Undertow）对可执行文件的解析执行，最终实现代码执行、服务器控制等攻击。

Java 与其他语言（PHP/ASP）的核心差异：Java 可执行文件类型为 JSP、JSPX、Class、WAR 等，且文件解析依赖容器的 Servlet 引擎规则，而非脚本解释器。

## 二、基础触发条件
要成功利用 Java 文件上传漏洞，需满足以下核心条件：
1. **上传入口未校验**：应用未校验文件的类型、后缀、内容、大小等；
2. **文件可被存储**：恶意文件能被写入服务器磁盘，且存储路径可被预测/访问；
3. **文件可被解析执行**：存储路径属于 Web 容器的“可访问目录”（即该目录在 `web.xml` 或容器配置中未被禁止访问），且容器能解析该文件类型（如 Tomcat 解析 `.jsp` 文件）；
4. **无后续防护**：无 WAF、文件内容扫描、权限控制等二次防护机制。

## 三、Java 文件上传漏洞的典型场景及变种
### 场景1：后缀名绕过（最基础且高频）
应用仅通过**文件后缀名白名单/黑名单**做简单校验，攻击者通过变种后缀绕过校验，核心利用 Java 容器的文件解析规则。

#### 1.1 大小写绕过
- 原理：应用仅校验小写后缀（如只判断是否包含 `.jsp`），但操作系统/容器对文件名大小写不敏感（Windows 完全不敏感，Linux/Tomcat 对 `.JSP` 仍解析）。
- 示例：上传 `shell.JSP`、`shell.JsP`、`shell.JpS`，绕过仅校验 `.jsp` 的逻辑，Tomcat 仍会将其解析为 JSP 文件执行。

#### 1.2 特殊后缀绕过（容器解析特性）
不同 Java 容器对后缀的解析规则存在差异，攻击者利用非标准后缀实现解析：
| 容器       | 可解析的非标准后缀                | 原理                                                                 |
|------------|-----------------------------------|----------------------------------------------------------------------|
| Tomcat     | `.jspx`、`.jspf`、`.jsw`、`.jspx` | Tomcat 默认配置下，`conf/web.xml` 中对 `jsp` 后缀的映射包含这些变种； |
| Tomcat 7+  | `.jspx`（需启用 JSPX 解析）       | JSPX 是 XML 格式的 JSP，容器默认解析；                               |
| Jetty      | `.jsp`、`.jspx`、`.jspn`          | Jetty 的 `webdefault.xml` 配置了这些后缀的 Servlet 映射；            |

- 示例：应用仅拦截 `.jsp`，攻击者上传 `shell.jspx`，Tomcat 解析执行其中的 JSP 代码。

#### 1.3 后缀截断绕过
利用文件路径/名称的截断特性，绕过后缀校验，分为两种情况：
##### 1.3.1 0x00 截断（已逐步失效）
- 原理：早期 Java 版本中，`String` 或文件操作 API 会将 `0x00`（ASCII 空字符）视为字符串结束符，攻击者构造 `shell.jsp%00.jpg`，后端校验时识别为 `.jpg`（合法），实际存储时 `%00` 截断，文件名为 `shell.jsp`。
- 适用场景：JDK 1.7 及以下（JDK 1.8 修复了该漏洞），且服务器为 Windows 系统（Linux 对 `0x00` 处理不同）。

##### 1.3.2 路径截断（目录遍历+后缀混淆）
- 原理：攻击者构造文件名包含路径分隔符，如 `../../webapps/ROOT/shell.jsp.jpg`，后端若仅校验最后一个后缀 `.jpg`，且未过滤路径分隔符，文件会被写入 Tomcat 根目录，实际访问时 `shell.jsp.jpg` 若被容器解析（如 Tomcat 宽松的解析规则），或通过二次漏洞（如解析漏洞）执行。

#### 1.4 伪后缀绕过（利用解析规则）
- 原理：Tomcat 等容器存在“宽松解析”特性，当文件名包含 `;`、`/`、`\` 等符号时，容器会忽略符号后的内容，仅解析前半部分。
- 示例：
  - 上传 `shell.jsp;123.jpg`，Tomcat 解析为 `shell.jsp`；
  - 上传 `shell.jsp/123.jpg`，容器忽略 `/` 后的内容，识别为 `.jsp` 文件。

### 场景2：MIME 类型绕过
应用仅校验 HTTP 请求头中的 `Content-Type`（MIME 类型），未校验实际文件内容，攻击者篡改 `Content-Type` 绕过校验。

#### 2.1 核心原理
Java 处理文件上传时，可通过 `Part.getContentType()` 或 `commons-fileupload` 的 `FileItem.getContentType()` 获取 MIME 类型，若应用仅判断该值是否为 `image/jpeg`、`image/png` 等合法类型，攻击者可通过 Burp 等工具将 `Content-Type` 改为合法值（如 `image/jpeg`），实际上传的是 `shell.jsp` 文件。

#### 2.2 示例
- 正常上传图片的请求头：`Content-Type: image/jpeg`；
- 攻击者修改为：`Content-Type: image/jpeg`，但请求体中是 JSP 木马内容：
  ```jsp
  <%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
  <% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
  ```
- 应用仅校验 `Content-Type`，放行后文件被存储为 `.jsp`，攻击者访问该文件并传入 `cmd` 参数执行系统命令。

### 场景3：文件内容校验绕过
应用对文件内容做了基础校验（如校验文件头），但校验逻辑存在缺陷，攻击者构造“合法文件头+恶意内容”的文件绕过。

#### 3.1 文件头校验绕过
- 原理：Java 应用常通过读取文件前几个字节判断文件类型（如 JPG 文件头为 `FF D8 FF`，PNG 为 `89 50 4E 47`），攻击者在 JSP 木马前添加合法文件头，绕过内容校验。
- 示例：
  构造文件内容：
  ```
  FF D8 FF  // JPG 文件头
  <% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
  ```
  文件名改为 `shell.jpg`，应用校验文件头为 JPG 合法，存储后若文件被重命名为 `.jsp`（或通过后缀绕过），Tomcat 解析时会忽略文件头，执行后续的 JSP 代码。

#### 3.2 校验逻辑缺陷（如仅校验前N字节）
- 原理：应用仅读取文件前 10 字节校验文件头，攻击者在文件前 10 字节写入合法文件头，后续写入恶意 JSP 代码，绕过校验。
- 示例：Java 代码中的校验逻辑：
  ```java
  // 仅校验前3字节是否为JPG头
  byte[] header = new byte[3];
  inputStream.read(header);
  if (!Arrays.equals(header, new byte[]{(byte)0xFF, (byte)0xD8, (byte)0xFF})) {
      throw new Exception("非法文件");
  }
  ```
  攻击者构造文件前 3 字节为 `FF D8 FF`，后续为 JSP 木马，成功绕过。

#### 3.3 压缩包/归档文件绕过
- 原理：应用允许上传 ZIP/WAR/JAR 等归档文件，且未校验归档内容，攻击者将恶意 JSP 文件打包为 ZIP，改后缀为 `.jpg` 上传，后端解压后释放恶意文件到可执行目录。
- 典型案例：
  - 上传 `shell.zip`（内含 `shell.jsp`），改后缀为 `shell.jpg`，后端解压时未过滤内容，`shell.jsp` 被释放到 `WEB-INF/upload`；
  - 上传恶意 WAR 包（符合 Java Web 规范），后端若自动部署 WAR 包，Tomcat 会解压并执行其中的代码。

### 场景4：框架/组件特定漏洞
Java 主流 Web 框架（Spring MVC、Struts2）、文件上传组件（commons-fileupload）存在特定的上传漏洞，攻击者利用组件缺陷绕过校验。

#### 4.1 Spring MVC 文件上传漏洞
- 原理：Spring MVC 配置 `MultipartResolver` 时，若未限制 `maxUploadSize`、`allowedFileExtensions`，或使用了存在缺陷的配置，导致绕过：
  - Spring MVC < 4.3.14：存在 `MultipartFile` 处理缺陷，可通过构造特殊请求绕过文件类型校验；
  - 配置疏漏：未设置 `uploadDir` 为非 Web 可访问目录，导致上传的文件直接存储在 `static` 目录，可被访问执行。

#### 4.2 Struts2 文件上传漏洞
- 原理：Struts2 的 `FileUploadInterceptor` 拦截器可配置允许的文件后缀，但存在以下绕过方式：
  - 拦截器仅校验 `fileName` 参数，未校验实际文件内容；
  - Struts2 部分版本（如 2.3.x）存在拦截器绕过漏洞（S2-045 等），可通过修改请求格式绕过文件类型校验；
  - 利用 `Content-Disposition` 头中的文件名混淆：如 `filename="shell.jsp"\x00.jpg`，拦截器解析错误导致绕过。

#### 4.3 commons-fileupload 组件缺陷
- 原理：Apache Commons FileUpload 组件（Java 最常用的上传组件）在解析请求时，若处理超大文件、特殊编码文件名（如 UTF-7/UTF-8 混合），可能导致文件名解析错误，攻击者利用该错误构造恶意文件名。
- 示例：组件解析 `filename=shell.jsp%20`（空格）时，若后端未去除空格，文件存储为 `shell.jsp `（末尾空格），Windows 系统会自动忽略末尾空格，实际为 `shell.jsp`。

### 场景5：路径遍历+文件覆盖
攻击者通过上传文件覆盖服务器已有文件（如 `WEB-INF/web.xml`、`WEB-INF/classes` 下的 Class 文件），实现代码执行或配置篡改。

#### 5.1 核心原理
Java Web 应用若未过滤文件名中的路径分隔符（`/`、`\`），攻击者构造包含绝对路径/相对路径的文件名，覆盖关键文件：
- 示例1：上传 `../../WEB-INF/web.xml`，覆盖应用的配置文件，篡改 Servlet 映射、权限控制；
- 示例2：上传 `../../WEB-INF/classes/com/example/Controller.class`，覆盖编译后的 Class 文件，实现代码执行（需满足文件权限、Class 未被加载等条件）；
- 示例3：上传 `../../webapps/ROOT/WEB-INF/web.xml`，覆盖 Tomcat 根应用的配置，添加恶意 Servlet 映射。

#### 5.2 关键条件
- 应用有文件写入权限（如 `WEB-INF` 目录可写）；
- 未过滤文件名中的 `../`、`..\` 等路径遍历字符；
- 覆盖的文件未被锁定（如 Tomcat 运行时 `web.xml` 可被覆盖，重启后生效）。

### 场景6：动态文件名/路径导致的漏洞
应用通过用户输入动态生成上传文件的文件名/存储路径，未做严格过滤，导致攻击者控制文件存储位置和名称。

#### 6.1 动态文件名漏洞
- 原理：后端通过 `request.getParameter("fileName")` 获取文件名，直接拼接为存储路径，未过滤特殊字符：
  ```java
  String fileName = request.getParameter("fileName");
  String uploadPath = "D:/web/upload/" + fileName;
  file.transferTo(new File(uploadPath)); // 未过滤fileName中的.jsp、../等
  ```
  攻击者传入 `fileName=shell.jsp`，直接存储为可执行文件；传入 `fileName=../../shell.jsp`，实现路径遍历。

#### 6.2 随机文件名生成缺陷
- 原理：应用通过随机数生成文件名（如 `System.currentTimeMillis()`），但未拼接固定后缀，或随机数可预测：
  - 示例：`String newFileName = System.currentTimeMillis() + "." + ext;`，若 `ext` 由用户控制，攻击者传入 `ext=jsp`，生成 `1717234567890.jsp`；
  - 风险：随机文件名若可预测，攻击者可提前知道文件路径，访问执行。

### 场景7：跨平台/容器差异导致的漏洞
Java 应用部署在不同容器（Tomcat/Jetty/Undertow）、不同操作系统（Windows/Linux）上，因解析规则、文件系统特性差异，导致在某一环境下的“合法校验”在另一环境失效。

#### 7.1 操作系统差异
- Windows：文件名不区分大小写、忽略末尾空格/`.`，支持 `0x00` 截断（低版本JDK）；
  - 示例：上传 `shell.jsp.`（末尾点），Windows 存储为 `shell.jsp`；
- Linux：文件名区分大小写、对 `0x00` 处理为普通字符，路径分隔符为 `/`；
  - 示例：上传 `shell.JSP` 在 Linux+Tomcat 下仍会被解析为 JSP 文件。

#### 7.2 容器差异
- Tomcat：默认解析 `.jsp`、`.jspx`、`.jspf`，支持宽松解析（`;`、`/` 截断）；
- Jetty：解析规则更严格，但对 `.jspx`、`.jhtml` 仍默认解析；
- Undertow：默认仅解析 `.jsp`，但可通过配置扩展，且对路径遍历的防护更弱。

### 场景8：二次解析/间接执行漏洞
攻击者上传的文件本身无法直接解析，但通过服务器的其他特性（如静态资源解析、脚本引擎调用）间接执行。

#### 8.1 JSP 预编译/自动编译漏洞
- 原理：Tomcat 会自动编译 WEB-INF 目录下的 JSP 文件为 Class 文件，若攻击者上传的文件被移动到 `WEB-INF/classes` 目录（如通过路径遍历），即使后缀为 `.class`，也可能被类加载器加载执行。

#### 8.2 脚本引擎执行
- 原理：应用若使用 Java ScriptEngine（如 Nashorn）处理上传的文件内容，攻击者上传包含恶意 JavaScript 代码的文件，引擎执行时调用 Java 代码：
  ```jsp
  <%
  ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
  engine.eval(new FileReader(request.getParameter("file")));
  %>
  ```
  攻击者上传 `shell.js`（内含 `java.lang.Runtime.getRuntime().exec("whoami")`），触发执行。

#### 8.3 模板引擎解析
- 原理：应用使用 FreeMarker、Velocity 等模板引擎，若上传的文件被作为模板解析，攻击者构造模板语法执行 Java 代码：
  - 示例：上传 `shell.ftl`（FreeMarker 模板），内容为 `${Runtime.getRuntime().exec("whoami")}`，若应用解析该模板文件，触发命令执行。

## 四、漏洞利用的后续影响
Java 文件上传漏洞被利用后，攻击者可实现：
1. **代码执行**：通过 JSP 木马执行任意 Java 代码/系统命令；
2. **服务器控制**：上传后门、创建管理员账户、篡改网站内容；
3. **数据泄露**：读取服务器敏感文件（如 `WEB-INF/database.properties`）；
4. **横向渗透**：利用服务器权限访问内网其他主机；
5. **持久化攻击**：通过覆盖 Class 文件、WAR 包部署实现持久化控制。

## 总结
Java 文件上传漏洞的核心是“校验缺失/失效”+“容器解析规则”+“文件系统特性”的叠加，其变种场景覆盖了后缀混淆、MIME 篡改、内容绕过、框架缺陷、路径遍历等多个维度，且因 Java 生态的复杂性（框架、容器、JDK 版本、操作系统），漏洞的表现形式和利用方式远多于其他语言，需结合具体环境分析触发条件。


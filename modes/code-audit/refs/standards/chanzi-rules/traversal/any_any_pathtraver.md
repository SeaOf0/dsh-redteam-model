# Java语言目录穿越漏洞全解析

> 来源：ChanziSAST 规则库语义规则提取（知识整理，含中文漏洞详解）。
> 规则 ID：`any_any_pathtraver` · 类别：traversal · 关键 sink：File, FileInputStream, FileReader, FileSystemResource, FileUtils, Files, HttpServletResponse, IOUtils, RandomAccessFile, Resource, ResourceLoader, Scanner
> 说明：原文为 cypher 语义查询（不可直接挂 semgrep），下方「知识正文」为规则自带的中文漏洞详解，
> 提取时未改写；配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java语言目录穿越漏洞全解析
目录穿越漏洞（也称为路径遍历漏洞）是指攻击者通过构造恶意的路径输入，绕过应用程序的路径访问限制，访问或修改应用程序预期之外的文件/目录（如系统配置文件、敏感业务数据、源码文件等）。Java作为主流后端开发语言，因文件操作逻辑不严谨、输入校验缺失等问题，极易触发该漏洞，其风险覆盖本地文件操作、文件上传/下载、资源加载等核心场景。

#### 一、目录穿越的核心原理
Java中文件操作依赖`java.io.File`、`java.nio.file.Path`等API，这些API接收路径字符串作为输入时，若直接使用用户可控的路径片段（如文件名、目录名）拼接最终路径，攻击者可通过输入`../`（Unix/Linux）或`..\`（Windows）等路径遍历符，向上回溯目录层级，突破应用程序限定的访问根目录（如`/app/data/`），进而访问系统任意目录。

核心逻辑：
假设应用程序限定访问根目录为`/app/upload/`，正常用户输入`file.txt`，拼接路径为`/app/upload/file.txt`；
攻击者输入`../../etc/passwd`，拼接路径变为`/app/upload/../../etc/passwd`，系统解析后等价于`/etc/passwd`，成功访问系统敏感文件。

Java中路径解析的特性加剧了风险：
1. `File`类的`getCanonicalPath()`/`getAbsolutePath()`会自动解析`../`/`..\`为实际路径，但若未先校验解析后的路径是否在合法根目录内，仍会导致穿越；
2. Windows系统下支持多种路径遍历符变种（如`..\`、`../`、`..%5C`、`..%2F`、`....//`等），易绕过简单的字符过滤；
3. Java对文件名的长度、特殊字符（如`\0`、空格）处理不严谨，可能导致过滤逻辑失效。

#### 二、Java中目录穿越的典型场景及案例
目录穿越漏洞的触发场景与文件操作的业务场景强相关，以下是Java中最常见的触发场景及具体案例：

##### 场景1：文件下载功能（高频触发场景）
**业务场景**：应用提供文件下载接口，通过用户输入的文件名拼接下载路径，例如下载用户上传的文件：
```java
// 危险代码：用户输入直接拼接下载路径
@GetMapping("/download")
public ResponseEntity<Resource> downloadFile(@RequestParam("filename") String filename) {
    // 预期下载目录：/app/upload/
    String baseDir = "/app/upload/";
    // 直接拼接用户输入的文件名
    File file = new File(baseDir + filename);
    // 读取文件并返回
    Resource resource = new FileSystemResource(file);
    return ResponseEntity.ok().body(resource);
}
```
**注入攻击**：
- 攻击者请求：`/download?filename=../../etc/passwd`，拼接路径为`/app/upload/../../etc/passwd`，解析后为`/etc/passwd`，下载系统敏感文件；
- Windows系统下攻击：`/download?filename=..\..\Windows\System32\drivers\etc\hosts`，读取hosts文件；
- 编码绕过攻击：`/download?filename=..%2F..%2Fetc%2Fpasswd`（`%2F`是`/`的URL编码），拼接后路径解析仍为`/etc/passwd`；
- 超长路径绕过：`/download?filename=....//....//etc//passwd`（`....//`等价于`../`），绕过仅过滤`../`的逻辑。

##### 场景2：文件上传功能（写入型目录穿越）
**业务场景**：文件上传接口未校验文件名，攻击者构造含路径遍历符的文件名，将文件写入非预期目录：
```java
// 危险代码：上传文件时直接使用原始文件名保存
@PostMapping("/upload")
public String uploadFile(@RequestParam("file") MultipartFile file) {
    // 预期保存目录：/app/upload/
    String baseDir = "/app/upload/";
    // 获取用户上传的原始文件名（攻击者可控）
    String filename = file.getOriginalFilename();
    // 直接拼接保存路径
    File destFile = new File(baseDir + filename);
    // 写入文件
    file.transferTo(destFile);
    return "上传成功";
}
```
**注入攻击**：
- 攻击者上传文件时，将文件名改为`../../shell.jsp`，文件被保存至`/app/upload/../../shell.jsp`（即`/shell.jsp`），若该目录有执行权限，可触发恶意脚本执行；
- 变种攻击：文件名改为`..%5C..%5Cwebapps%5CROOT%5Cbackdoor.jsp`（Windows编码），写入Web应用根目录，实现远程代码执行；
- 截断绕过：文件名改为`../../etc/crontab\0.txt`（含`\0`截断符），若应用未处理空字符，拼接后路径为`/app/upload/../../etc/crontab`（`\0`后的内容被截断），覆盖系统定时任务文件。

##### 场景3：静态资源加载（资源遍历）
**业务场景**：应用加载静态资源（如图片、JS、CSS）时，通过用户输入拼接资源路径：
```java
// 危险代码：加载静态资源时拼接用户输入
@GetMapping("/static")
public ResponseEntity<Resource> loadStaticResource(@RequestParam("path") String path) {
    // 预期资源目录：/app/static/
    String baseDir = "/app/static/";
    File resourceFile = new File(baseDir + path);
    Resource resource = new FileSystemResource(resourceFile);
    return ResponseEntity.ok().body(resource);
}
```
**注入攻击**：
- 攻击者请求：`/static?path=../../src/main/resources/application.yml`，读取应用配置文件（含数据库密码、密钥等）；
- 攻击：`/static?path=../../../../../../proc/self/environ`（Linux），读取进程环境变量，获取敏感信息；
- 嵌套目录穿越：`/static?path=../images/../../conf/db.properties`，绕过仅校验“是否以/images/开头”的逻辑。

##### 场景4：文件读取/删除操作（业务逻辑内的路径遍历）
**业务场景**：应用提供文件读取/删除接口，用于管理业务文件，但未校验路径：
```java
// 危险代码：删除文件时直接使用用户输入的路径
@DeleteMapping("/delete")
public String deleteFile(@RequestParam("filePath") String filePath) {
    // 预期删除目录：/app/data/
    String baseDir = "/app/data/";
    File file = new File(baseDir + filePath);
    if (file.exists()) {
        file.delete();
        return "删除成功";
    }
    return "文件不存在";
}
```
**注入攻击**：
- 攻击者请求：`/delete?filePath=../../app/logs/access.log`，删除应用日志文件，破坏审计记录；
- 攻击：`/delete?filePath=..\..\Windows\Temp\system.ini`（Windows），删除系统配置文件，导致系统异常；
- 递归删除风险：`/delete?filePath=../../../../`，若应用有足够权限，可能触发递归删除系统目录。

##### 场景5：路径过滤不完整导致的绕过
**业务场景**：开发人员尝试过滤路径遍历符，但覆盖不全，导致绕过：
```java
// 不完整的过滤：仅替换../，未处理..\、....//、编码形式等
@GetMapping("/download")
public ResponseEntity<Resource> downloadFile(@RequestParam("filename") String filename) {
    String baseDir = "/app/upload/";
    // 仅过滤../，未处理其他遍历符
    filename = filename.replace("../", "");
    File file = new File(baseDir + filename);
    Resource resource = new FileSystemResource(file);
    return ResponseEntity.ok().body(resource);
}
```
**注入攻击**：
- 攻击者输入：`..\..\etc\passwd`（Windows遍历符），拼接后路径为`/app/upload/..\..\etc\passwd`，解析后仍为`/etc/passwd`；
- 输入：`....//etc/passwd`（`....//`等价于`../`），过滤后变为`..//etc/passwd`，解析后仍可穿越；
- 输入：`..%2F..%2Fetc%2Fpasswd`（URL编码），过滤逻辑未解码，直接拼接后解析为`/etc/passwd`；
- 输入：`..\/..\/etc/passwd`（混合分隔符），过滤后变为`.\/.\/etc/passwd`，解析后仍可穿越。

##### 场景6：基于NIO API的目录穿越（Path类风险）
**业务场景**：使用Java NIO的`Path`类处理路径，但未校验路径归属：
```java
// 危险代码：使用Path拼接路径，但未检查是否在合法目录内
@GetMapping("/read")
public String readFile(@RequestParam("filename") String filename) {
    Path basePath = Paths.get("/app/upload/");
    // 拼接用户输入的文件名
    Path targetPath = basePath.resolve(filename);
    // 直接读取文件
    String content = Files.readString(targetPath);
    return content;
}
```
**注入攻击**：
- `Path.resolve()`方法会自动解析`../`，攻击者输入`../../etc/passwd`，`targetPath`解析为`/etc/passwd`，直接读取；
- 即使使用`basePath.normalize()`，若未校验`normalize()`后的路径是否以`basePath`为前缀，仍会触发穿越：
  ```java
  // 仍有风险：normalize()解析了../，但未校验归属
  Path targetPath = basePath.resolve(filename).normalize();
  Files.readString(targetPath);
  ```

##### 场景7：ClassLoader/资源加载器的目录穿越
**业务场景**：通过类加载器加载外部资源时，用户输入可控路径：
```java
// 危险代码：类加载器加载用户指定的资源
@GetMapping("/loadResource")
public String loadResource(@RequestParam("resourcePath") String resourcePath) {
    ClassLoader classLoader = getClass().getClassLoader();
    InputStream is = classLoader.getResourceAsStream(resourcePath);
    // 读取资源内容
    BufferedReader br = new BufferedReader(new InputStreamReader(is));
    return br.readLine();
}
```
**注入攻击**：
- 攻击者输入：`../../../../etc/passwd`，类加载器可能突破类路径限制，读取系统文件（取决于JVM安全策略）；
- 输入：`../application.yml`，读取应用配置文件，获取数据库连接信息。

#### 三、目录穿越的触发条件
1. **输入可控**：用户可通过请求参数、表单、文件上传等方式控制路径片段（如文件名、目录名）；
2. **路径直接拼接**：应用将用户输入直接拼接至文件路径，未做合法性校验；
3. **过滤逻辑不完整**：仅过滤部分遍历符（如仅过滤`../`，未处理`..\`、编码形式、超长遍历符）；
4. **权限过高**：应用运行的进程拥有过高的文件系统权限（如root/Administrator），可访问/修改系统敏感文件；
5. **未校验路径归属**：未检查解析后的最终路径是否在应用预期的合法根目录范围内。

#### 四、目录穿越的危害等级
- **低危**：访问非敏感的公开文件（如普通日志、静态图片）；
- **中危**：读取敏感配置文件（如数据库密码、JWT密钥、应用配置）；
- **高危**：修改/删除业务数据文件（如用户数据、交易记录）、写入恶意脚本（如JSP后门）；
- **极危**：修改系统配置文件（如`/etc/passwd`、`/etc/sudoers`）、删除系统核心文件，导致系统瘫痪或权限提升。

#### 五、易被忽视的目录穿越场景
1. **相对路径基目录动态变化**：应用的“合法根目录”通过变量动态获取（如从配置文件读取），若变量被篡改，基目录失效；
2. **文件名大小写绕过**：Windows系统路径不区分大小写，攻击者输入`..\`/`..\`的大写形式（`..\`）绕过小写过滤；
3. **符号链接（软链接）利用**：攻击者先上传含软链接的文件（指向`/etc/passwd`），再通过下载接口访问该软链接，间接读取敏感文件；
4. **多字节字符绕过**：输入全角遍历符（如`．．／`），过滤逻辑未处理全角字符，解析后仍等价于`../`；
5. **嵌套路径遍历**：输入`a/../../b`，绕过“路径必须以a/开头”的校验逻辑，最终解析为`/b`。

综上，Java中的目录穿越漏洞本质是“文件路径拼接时未对用户输入做严格校验”，其风险覆盖文件读取、写入、删除、资源加载等全文件操作场景，危害程度取决于应用进程的权限和被访问文件的敏感性，核心触发点是路径遍历符的解析和过滤逻辑的缺失。


# .NET（C#）审计 Sink 大表（按类型）

> 与其他语言表同形态；反序列化深度专项见 `dotnet-deser-audit.md`（ViewState/gadget 链），
> 本表补齐其余类型。

## 1. 命令注入（CMD）

**Sink**：
- `Process.Start(`（文件名/Arguments 拼接）
- `ProcessStartInfo` 对象：`FileName` / `Arguments` 含用户输入（`UseShellExecute=true`
  时 cmd 形态拼接）
- `PowerShell.Invoke(`（脚本串拼接）；`Microsoft.VisualBasic.Interaction.Shell(`

**危险模式**：Arguments 字符串拼接（`&`/`|` 在 cmd 语义下注入）；可执行路径可控。

**强制验证**：`ArgumentList` 参数化；路径白名单。

## 2. SQL 注入（SQL）

**Sink**：
- ADO.NET：`SqlCommand(`（CommandText 拼接）；`DataAdapter` 同型
- Dapper：`Query(` 拼接串（对比匿名对象绑定形态）
- EF Core：`FromSqlRaw(` / `SqlQueryRaw(`（拼接——对比 `FromSqlInterpolated` 参数化）
- `string.Format` / `$"..."` 拼 SQL

**强制验证**：`SqlParameter` 绑定；`FromSqlInterpolated` 形态；标识符白名单。

## 3. 反序列化（DESER）

**Sink**：
- `BinaryFormatter.Deserialize(`（**一等 RCE gadget**——ysoserial.net 全家；.NET 5+ 已标
  过时但存量代码大量在用）
- `SoapFormatter` / `NetDataContractSerializer` / `ObjectStateFormatter`（ViewState 核心）
- Json.NET：`TypeNameHandling` ≠ `None` + 用户 JSON `$type`（gadget 链）
- `JavaScriptSerializer`（`RegisterConverters` 带类型解析器时）
- `XmlSerializer` 预配置类型面（深链见 dotnet-deser-audit）

**危险模式**：不可信字节/JSON/XML 进上述；ViewState 场景 machineKey 硬编码/泄露=
**ViewState 反序列化 RCE**（配置与密钥一起审）。

**强制验证**：Json.NET `TypeNameHandling.None`；BinaryFormatter 移除（`System.Text.Json`
替代）；ViewState 密钥不可预测且不落盘。

## 4. XSLT 与视图（SSTI）

**Sink**：
- `XslCompiledTransform.Load(`（`XsltSettings` 开 `EnableScript`=嵌入 C# 执行）
- `XslTransform.Load(`（老类默认宽松）
- Razor：`RazorEngine.RunCompile(`（模板串含用户输入=代码执行）；ASP.NET 视图名拼接
  （Controller 返回 `View(userInput)` 类路径拼接面）

**强制验证**：XSLT 脚本禁用；模板源固定；视图名白名单。

## 5. XXE（XXE）

**Sink**：
- `XmlDocument.Load/LoadXml(`（`XmlResolver` 非 null 时外部实体解析）
- `XmlReader.Create(` 未显式 `DtdProcessing.Ignore/Prohibit`
- `XmlSerializer.Deserialize(`（预配置 resolver 面）
- `XPathDocument(`（带 resolver）

**强制验证**：`XmlResolver = null`；`DtdProcessing.Prohibit`；.NET 4.5.2+ 默认收紧，
配置被显式放宽的必查。

## 6. SSRF（SSRF）

**Sink**：
- `WebClient.DownloadString/DownloadFile(`（URL 可控）
- `HttpClient.GetAsync/SendAsync(`（URL 含用户输入；`AllowAutoRedirect` 进内网）
- `HttpWebRequest`（老栈同型）；`WebClient` 走 NTLM 自动认证（SSRF→内网认证透传高危害）

**强制验证**：host 白名单；禁自动凭据委托（`UseDefaultCredentials=false`）。

## 7. 文件与路径穿越（FILE）

**Sink**：
- `File.ReadAllText/WriteAllText/Open(`（路径拼接）
- `Path.Combine(base, user)`（`user` 含 `..` 段或绝对路径（`C:\`/`\\`）时 Combine 直接
  采信第二参——**Combine 不是防穿越**）
- `PhysicalFile(` / ASP.NET Core `StaticFile` 中间件（目录配置）
- 解压：`ZipFile.ExtractToDirectory(`（.NET Framework 4.6.1 及更早不校验条目穿越——
  4.6.2+ 收紧，**版本分界必查**）

**强制验证**：`Path.GetFullPath` 后 `StartsWith(base + sep)`；解压逐条目校验（老框架）。

## 8. 加密与密钥（CRYPTO）

**Sink**：
- ViewState `machineKey`（web.config 硬编码——validationKey/decryptionKey 成对泄露=RCE
  前置，与 DESER 节联动）
- `MD5.Create(` / `SHA1.Create(`（口令存储）；`RNGCryptoServiceProvider` 缺失处用
  `Random`（token 弱随机）
- 硬编码连接串密码（connectionStrings 节）

**强制验证**：密钥环境注入；PBKDF2 类口令存储；`RandomNumberGenerator`。

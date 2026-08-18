---
name: dotnet-deser-audit
description: .NET/C# 反序列化审计手册。覆盖 BinaryFormatter/LosFormatter/ObjectStateFormatter(ViewState)/JavaScriptSerializer/Newtonsoft Json.NET 等格式化器的 gadget 链审计方法、ysoserial.net 链清单、ViewState 机器密钥判据；引用 semgrep-oss csharp 规则集。规则降级兜底手册。
---

# .NET 反序列化审计手册（dotnet-deser-audit）

> 定位：C#/.NET 无独立审计总手册（库内暂无），本篇是反序列化主线的规则降级兜底——把
> .NET 反序列化入口、格式化器、gadget 链、ViewState 判据补齐成「入口识别→危险模式→
> 验证方法→修复建议」完整路径。扫描规则直接挂载
> `refs/standards/semgrep-oss/csharp/lang/security/insecure-deserialization/`。

## 0. .NET 反序列化入口总览（危险模式识别）

| 格式化器/入口 | API | 危险点 |
|---------------|-----|--------|
| BinaryFormatter | `new BinaryFormatter().Deserialize(stream)` | 反序列化任意类型 → gadget RCE |
| LosFormatter | `new LosFormatter().Deserialize(stream)` | ViewState/Session 用，等价 BinaryFormatter 能力 |
| ObjectStateFormatter | `Deserialize(stream)` | ViewState 反序列化 |
| SoapFormatter | `Deserialize(stream)` | SOAP 反序列化 |
| NetDataContractSerializer | `Deserialize(stream)` | 允许 CLR 类型信息 |
| JavaScriptSerializer | `new JavaScriptSerializer(...).DeserializeObject` / `Deserialize` | 需 `SimpleTypeResolver` 才危险 |
| Newtonsoft Json.NET | `JsonConvert.DeserializeObject(json, settings)` + `TypeNameHandling` | `TypeNameHandling.Objects/All/Auto` 触发 gadget |
| DataContractSerializer / DataContractJsonSerializer | `ReadObject` | 配合 known types |
| FastJson | `JSON.ToObject` | 任意类型 |
| FsPickler | `FsPickler.CreateBinarySerializer().UnPickle` | 任意类型 |
| XmlSerializer | `Deserialize` | 相对受限（需 known types） |

## 1. ysoserial.net 链清单

> ysoserial.net：<https://github.com/pwntester/ysoserial.net>（基于 ysoserial 的 .NET 版）。
> 用法：`ysoserial.exe -g <Gadget> -f <Formatter> -c "cmd"`；`-g` 列表见 `ysoserial.net -h`。

| Gadget | 依赖 | 触发机制 |
|--------|------|----------|
| TextFormattingRunProperties | System.Windows.Data（WPF） | `ObjectDataProvider` + `Process.Start` |
| TypeConfuseDelegate | 无（.NET Framework 内置） | `Delegate` 类型混淆 → 任意代码 |
| WindowsIdentity | System.IdentityModel | 任意文件读/令牌 |
| ActivitySurrogateSelector | System.Activities | 任意代码 |
| SessionSecurityToken | System.IdentityModel | 序列化会话令牌 |
| DataSet | System.Data | 任意 SQL/文件操作 |
| ObjectDataProvider | System.Windows.Data（WPF） | 方法调用 → 命令执行 |
| ClaimIdentity | System.Security.Claims | 任意写 |
| DynamicMethod | System.Reflection.Emit | 任意代码 |

**审计判据**：.NET 应用存在上述 gadget 依赖（多为 .NET Framework 默认自带）+ 存在
`BinaryFormatter/LosFormatter/Json.NET(TypeNameHandling)` 反序列化入口 → 候选 RCE。

## 2. ViewState 机器密钥判据（未授权 ViewState 反序列化）

### 2.1 原理

- ASP.NET WebForms 的 `__VIEWSTATE` 由 `ObjectStateFormatter`/`LosFormatter` 序列化，
  并以 `machineKey`（`validationKey` + `decryptionKey`）做 MAC 签名/加密。
- **两类高危**：
  1. **`enableViewStateMac=false`**（关闭 MAC）：ViewState 未签名，可直接篡改注入 gadget；
  2. **machineKey 泄露/为默认值**：从源码、公开仓库、`web.config` 泄露的机器密钥，
     攻击者可自行签名/加密恶意 ViewState → 服务端反序列化 → RCE。

### 2.2 源码/配置判据

```xml
<!-- web.config 判据 -->
<!-- ❌ 关闭 MAC -->
<pages enableViewStateMac="false" ... />

<!-- ❌ 默认/硬编码 machineKey（可被伪造 ViewState） -->
<machineKey validationKey="AutoGenerate,IsolateApps" decryptionKey="AutoGenerate,IsolateApps" ... />
<!-- 若 validationKey/decryptionKey 为固定值且泄露 → 高危 -->

<!-- ✅ 安全（自动生成 + 机器级隔离，但多节点需一致） -->
<machineKey validationKey="AutoGenerate,IsolateApps" decryptionKey="AutoGenerate,IsolateApps" validation="SHA1" decryption="AES" />
```

### 2.3 验证方法

```bash
# 1. 探测 ViewState 是否启用 MAC（请求含 __VIEWSTATE）
# 2. 若拿到 machineKey，用 ysoserial.net 生成恶意 ViewState：
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "whoami" \
  --validationkey=... --decryptionkey=... --validationalg=SHA1 --decryptionalg=AES
# 3. 回放 __VIEWSTATE，观察命令是否执行（默认 whoami 级）
```

## 3. semgrep-oss csharp 规则集引用

本预设已内置开源 csharp 反序列化规则（挂载路径）：
```
refs/standards/semgrep-oss/csharp/lang/security/insecure-deserialization/
```
覆盖 BinaryFormatter / LosFormatter / Newtonsoft(Json.NET) / NetDataContractSerializer /
FsPickler / FastJson / JavaScriptSerializer / SoapFormatter 八类格式化器。

```bash
# 直接挂载扫描
semgrep scan --config refs/standards/semgrep-oss/csharp/lang/security/insecure-deserialization/ --json -o dotnet-deser.json <path>
```

## 4. 审计 grep（无规则时通用兜底）

```bash
grep -rn 'BinaryFormatter\|LosFormatter\|ObjectStateFormatter\|SoapFormatter\|NetDataContractSerializer\|JavaScriptSerializer\|TypeNameHandling\|enableViewStateMac\|machineKey\|TypeNameAssemblyFormat\|SerializationBinder' --include='*.cs' --include='*.config' --include='*.aspx' .
```

## 5. 修复建议（按层）

1. **入口层**：禁止 `BinaryFormatter`/`LosFormatter`/`NetDataContractSerializer` 反序列化
   不可信数据；Json.NET 关闭 `TypeNameHandling`（默认 `None` 安全）。
2. **过滤层**：自定义 `SerializationBinder` 做类型白名单（`BinaryFormatter.Binder`）。
3. **ViewState 层**：保持 `enableViewStateMac=true`（默认），machineKey 用自动生成且不外泄；
   多节点部署用固定 key 时走密钥托管（Vault/KMS），不入库。
4. **检测层**：挂载 semgrep-oss csharp 规则集 + grep 兜底。

## 来源

- ysoserial.net：<https://github.com/pwntester/ysoserial.net>
- .NET 反序列化指南（OWASP）：<https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data>
- 内置规则集：`refs/standards/semgrep-oss/csharp/lang/security/insecure-deserialization/`

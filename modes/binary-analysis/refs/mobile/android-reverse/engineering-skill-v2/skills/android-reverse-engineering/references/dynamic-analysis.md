# Dynamic Analysis

Use runtime analysis only after static analysis has narrowed the search space.

## Goals

- Confirm the final request URL, headers, and body
- Capture sign-related inputs and outputs
- Identify the best hook point with the least noise
- Decide whether SSL pinning bypass or native inspection is actually required

## Triage Order

1. Decompile the APK and identify the network stack first
2. Locate request builders, interceptors, callbacks, or adapter layers
3. Hook the narrowest layer that still exposes the final outbound request
4. Escalate to SSL pinning or packet capture only if Java-side hooks are not enough

## What to Look For in JADX

Search for:

- `Retrofit`, `OkHttp`, `Volley`, `Cronet`, `HttpURLConnection`, `TTNet`
- `Interceptor`, `intercept`, `addInterceptor`
- `Callback`, `onResponse`, `onFailure`, `onSuccess`
- `sign`, `token`, `encrypt`, `decrypt`
- `native `, `System.loadLibrary`, `System.load`

Produce a short triage summary before hooking:

- network framework
- request builder class
- interceptor or middleware chain
- likely sign generator
- whether sign logic appears in Java or native

## Hooking Strategy

Prefer these hook points in order:

1. Final request object construction
2. Interceptor methods
3. Request execution entrypoints
4. Sign or token generation methods
5. Native methods only if Java no longer exposes the needed values

For each hook, capture:

- class and method name
- request URL
- HTTP method
- headers
- body or serialized payload
- sign-related input parameters
- sign-related return value

## SSL Pinning Guidance

Do not start by bypassing SSL pinning. First try to observe requests in-process.

Escalate only when:

- the app sends traffic but Java hooks do not expose the final request
- the target values are visible only after TLS is established
- the user explicitly asks for packet capture or certificate bypass

If pinning bypass is required, describe:

- why Java-layer inspection was insufficient
- which library likely performs pinning
- the exact point you intend to patch or hook

## Packet Capture Guidance

Packet capture is a verification tool, not the default first step.

Use it when:

- you need to validate that a reconstructed request matches runtime traffic
- the app uses a custom transport stack
- the user needs evidence of exact on-wire behavior

Pair capture results with code locations. Raw traffic without code context is not enough.

## Frida Artifact Scripts

Ready-to-use Frida scripts for common dynamic analysis tasks. All scripts are in `scripts/`.

### `jni_method_trace.js` — JNI 全量追踪 + OLLVM 字符串解密

**用途**: 追踪指定 SO 的所有 JNI 调用（FindClass、GetMethodID、NewStringUTF、RegisterNatives 等），运行时解密 OLLVM 加密的字符串。

**适用场景**:
- SO 使用了 OLLVM/Ant-Secure-Compiler 字符串加密，静态分析看不到明文字符串
- 需要了解 native 代码调用了哪些 Java 类和方法
- 需要发现 RegisterNatives 注册的所有 JNI 函数及其偏移
- 需要追踪 native → Java 回调的完整调用链

**使用方式**:
```bash
frida -U -f <package_name> -l scripts/jni_method_trace.js --no-pause
```

**变量修改**:

| 变量 | 位置 | 说明 |
|------|------|------|
| `TARGET_SO` | 第 5 行 | 目标 SO 文件名，如 `"libj2j_hdfhttp.so"`；`""` 表示追踪全部 SO |

**输出解读**:
```
[FindClass] java/util/HashMap [libtarget.so+0x19648]    ← 哪个 SO 的哪个偏移调用了 FindClass
[GetMethodID] put sig:(...)Object; [libtarget.so+0xb5b4] ← 获取了哪个方法
[RegisterNatives] com.example.JniHelper (2 methods)       ← 注册了哪些 JNI 函数
  j2jStep1 (Ljava/util/HashMap;...)V
    fn=0xa388 [libtarget.so]
[NewStringUTF] some_decrypted_string                      ← Native 创建的 Java 字符串（解密后）
```

**注意事项**:
- 必须使用 `spawn` 模式（`-f`）才能捕获 SO 加载时的 RegisterNatives
- NewStringUTF 频率极高，如果刷屏可以设置 `TARGET_SO` 过滤
- 此脚本 Hook ART 运行时层，Android 版本差异可能导致符号匹配失败
- Android 14+ 的 ART 符号命名可能不同，需检查输出确认所有 hook 点安装成功

### `hook_artmethod_register.js` — ART 层 RegisterNative 追踪

**用途**: 在 ART 运行时层面 Hook `ArtMethod::RegisterNative`，拦截所有 native 方法注册，精确定位函数入口。

**适用场景**:
- 需要知道每个 native 函数在 SO 中的精确偏移
- RegisterNatives 被 OLLVM 混淆，静态扫描找不到 call site
- 需要建立 native 函数名 → SO 偏移的映射表

**使用方式**:
```bash
# 需要先部署 helper SO（仅首次）
adb push mobile-deploy/libext64.so /data/local/tmp/
adb shell cp /data/local/tmp/libext64.so /data/data/<package_name>/files/
adb shell chmod 755 /data/data/<package_name>/files/libext64.so

# spawn 追踪
frida -U -f <package_name> -l scripts/hook_artmethod_register.js --no-pause
```

**变量修改**:

| 变量 | 位置 | 说明 |
|------|------|------|
| `TARGET_SO` | 第 1 行 | 目标 SO 文件名，如 `"libj2j_hdfhttp.so"`；`""` 表示追踪全部 SO |

**依赖**: 需要 `libext64.so`（或 32 位的 `libext.so`）部署到目标 App 的 files 目录。此 SO 封装了 `ArtMethod::PrettyMethod` 调用，用于将 ArtMethod 指针解码为可读的方法签名。

**输出解读**:
```
[RegisterNative] com.example.JniHelper.j2jStep1(Ljava/util/HashMap;...)V
  SO:   libtarget.so
  fn:   0x7a1239a388
  off:  0xa388
```

**对比 `jni_method_trace.js`**: 本脚本专注于 native 方法注册发现，输出更简洁；`jni_method_trace.js` 覆盖面更广（包含所有 JNI 调用），适合深入分析 native 代码行为。

### `dump_so.js` — 内存 SO Dump

**用途**: 从运行中的进程内存 dump 出指定 SO 文件。很多 App 的 SO 在 APK 中是加密/压缩的，只在运行时 `JNI_OnLoad` 前解密到内存中。

**适用场景**:
- 静态解包拿到的 SO 被加固/加密，IDA 打不开
- 需要运行时解密后的 SO 做完整静态分析

**使用方式**: Frida console 中调用 `dump_so("libtarget.so")`。dump 文件写入 App 的 files 目录，用 `adb pull` 拉取。

```bash
frida -U <package_name> -l scripts/dump_so.js
# console: dump_so("libj2j_hdfhttp.so")
# adb pull /data/data/<pkg>/files/libj2j_hdfhttp.so .
```

**变量**: 无顶层配置变量，`dump_so("so_name")` 传入目标 SO 名即可。

### `ssl_log.js` — BoringSSL TLS 密钥日志

**用途**: Hook BoringSSL 的 `SSL_CTX_set_keylog_callback`，实时输出 TLS 握手密钥（SSLKEYLOGFILE 格式）。不需要安装代理证书，不需要绕过 SSL pinning。

**适用场景**:
- App 做了 SSL pinning，Charles/Burp 看不到明文
- 需要 Wireshark 解密 TLS 流量
- 自研协议栈（如 TTNet、Cronet）不走系统代理

**使用方式**: Frida console 中调用 `startTLSKeyLogger()`。收集到的 key log 可导入 Wireshark 解密 pcap。

```bash
frida -U <package_name> -l scripts/ssl_log.js
# console: startTLSKeyLogger()
```

**变量**: 无。调用 `startTLSKeyLogger()` 即可。

### `hook_encryption_algo.js` — Java 加密算法全量追踪

**用途**: Hook `javax.crypto.Cipher`、`java.security.MessageDigest`、`javax.crypto.Mac`、`java.security.Signature`，自动输出加密/解密/哈希/HMAC/签名操作的算法、密钥、输入、输出。

**适用场景**:
- 需要知道 App 用了什么加密算法（AES/DES/RSA/...）
- 需要拿到加密密钥和 IV
- 追踪签名/HMAC 的输入输出（如 API 签名、Token 生成）

**使用方式**:
```bash
frida -U <package_name> -l scripts/hook_encryption_algo.js
```

**变量**: `N_ENCRYPT_MODE=1` / `N_DECRYPT_MODE=2` — 常量，无需修改。

**输出解读**:
```
[Cipher] AES/CBC/PKCS5Padding ENCRYPT
  key: a1b2c3d4...
  iv:  01020304...
  in:  plaintext data
  out: encrypted bytes
[MessageDigest] MD5
  in:  sorted_params_string
  out: 32-char-hex
```

### `dump_dex.js` — 内存 DEX Dump

**用途**: 从运行中的进程内存 dump 出所有已加载的 DEX 文件。适用于壳保护、动态加载、热修复场景下，磁盘上的 APK 不包含完整代码。

**适用场景**:
- App 使用了加固（360/梆梆/爱加密等），jadx 反编译不完整
- App 动态下载/加载 DEX
- 需要获取运行时实际执行的代码

**使用方式**:
```bash
frida -U <package_name> -l scripts/dump_dex.js --no-pause
```

DEX 文件自动 dump 到 `/data/data/<pkg>/files/` 目录。用 `adb pull` 拉取后用 jadx 打开。

**变量**: 无。启动即自动 dump。

### `keystore_dump.js` — Android Keystore 证书 Dump

**用途**: 在 HTTPS 双向认证场景下，dump 客户端证书为 p12 文件。

**适用场景**:
- App 使用客户端证书做双向 TLS 认证
- 需要提取证书做服务端模拟

**使用方式**:
```bash
frida -U <package_name> -l scripts/keystore_dump.js
```

| 变量 | 位置 | 说明 |
|------|------|------|
| `password` | 第 2 行 | p12 证书的导出密码，默认 `"hooker"` |

### `bypass_root_detect.js` — Root 检测绕过

**用途**: 绕过 App 的 Root 检测，Hook 常见的检测方法（包名检查、二进制文件检查、系统属性检查、su 命令检测）。

**适用场景**:
- App 检测到 root 后拒绝运行/闪退/隐藏功能
- 金融、银行、支付类 App 的通用绕过

**使用方式**:
```bash
frida -U -f <package_name> -l scripts/bypass_root_detect.js --no-pause
```

**变量**: `RootPackages`、`RootBinaries`、`RootProperties` — 已预置常见检测项，一般无需修改。如果 App 有自定义检测逻辑，可在对应数组中追加。

### `bypass_frida_svc_detect.js` — Frida SVC 检测绕过

**用途**: 绕过通过扫描 SVC 指令和内存特征检测 Frida 的机制。Hook `open`/`openat`/`read`/`readlinkat`/`strstr`/`strcmp`/`snprintf` 系统调用，过滤 Frida 相关路径和字符串。

**适用场景**:
- App 检测到 Frida 后自动退出/崩溃
- App 扫描 `/proc/self/maps` 查找 frida 特征
- App 通过 SVC 直接调用绕过 libc hook

**使用方式**:
```bash
frida -U -f <package_name> -l scripts/bypass_frida_svc_detect.js --no-pause
```

**变量**: 无。

## 脚本选型速查

```
要追踪 native 调用链 + 解密 OLLVM 字符串? → jni_method_trace.js
要定位 native 函数在 SO 中的偏移?       → hook_artmethod_register.js
要 dump 运行时解密的 SO 做 IDA 分析?    → dump_so.js
要看明文 HTTPS 流量(无需绕过 pinning)?  → ssl_log.js
要知道 App 用了什么加密/密钥?          → hook_encryption_algo.js
要对付加固/壳保护的 DEX?              → dump_dex.js
要提取客户端证书?                     → keystore_dump.js
要绕过 Root 检测跑 Frida?             → bypass_root_detect.js
要绕过 Frida 自身的检测?              → bypass_frida_svc_detect.js
```

## Output Template

```markdown
## Runtime Finding

- Hook point: `com.example.net.SignInterceptor.intercept`
- Why this point: closest Java layer before outbound request
- URL: `https://example.com/api/...`
- Method: `POST`
- Headers: `x-sign`, `x-t`, `cookie`, ...
- Body shape: `{...}`
- Sign source: Java / native / unknown
- Next step: inspect native method `nativeGetSign(...)`
```

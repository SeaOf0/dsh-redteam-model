# Native Network Playbook

目标：处理 Java 网络栈以外的 Cronet、BoringSSL、native TLS、QUIC 与 Native pinning 取证。

## 先回答

- 当前流量走 Java 栈、JNI 过渡还是纯 Native 栈
- 证书校验、pinset、公钥摘要比对发生在哪一层
- 是否存在 Cronet builder、自定义 verify callback、native pinset 载入
- 抓包失败是因为 Java pinning、Native pinning、QUIC 还是自定义协议

## 高风险信号

- `org.chromium.net`
- `CronetEngine`
- `UrlRequest`
- `libcronet`
- `BoringSSL`
- `SSL_CTX_set_custom_verify`
- `SSL_set_custom_verify`
- `X509_verify_cert`
- `SSL_do_handshake`
- `quic`

## 作业顺序

### 1. 先定 Java 网络边界

先看：

- `OkHttp` / `Retrofit`
- `CronetEngine.Builder`
- WebView、`shouldInterceptRequest`
- JNI 包装的网络 facade

目标是确认：

- Java 是否只负责配置 builder
- 请求真正发起是在 Java 还是 Native

### 2. 再定 Native 实现

优先定位：

- `libcronet`
- 自定义网络 SO
- `BoringSSL` / `OpenSSL` 风格符号
- 请求回调、证书校验回调、pinset 载入点

### 3. Cronet / QUIC 专项

至少排查：

- `CronetEngine.Builder` 配置项
- `UrlRequest` callback / executor
- 是否强制 QUIC、HTTP/3
- 证书验证回调与公钥摘要比对逻辑

如果明文抓不到，不要只怀疑证书锁定，也要怀疑：

- QUIC 走独立栈
- Native 层自定义加密
- 请求根本没经过 Java HTTP client

### 4. Native TLS 专项

优先检查：

- `SSL_CTX_set_custom_verify`
- `SSL_set_custom_verify`
- `X509_verify_cert`
- `SSL_do_handshake`
- `SSL_write`
- `SSL_read`

记录时要写清：

- 命中模块
- 校验函数
- 回调或 pinset 载入点
- 明文抓取点

### 5. 再决定绕过或取证方案

- Java 配置层可控：
  先 Java hook
- 证书校验在 Native callback：
  先 Native hook
- 注入窗口太早或多进程：
  考虑更早 attach 或静态 patch

## mTLS / 客户端证书认证

当服务端要求客户端出示证书时，常规 unpin 只处理服务端校验。

识别信号：
- `SSLContext.init()` 第一个参数非空（`KeyManager[]` 而非 null）— 这是区分 mTLS 和普通 HTTPS 的关键信号
- `KeyManagerFactory.init()` 搭配包含私钥的 `KeyStore` 加载
- `PKCS12` / `.pfx` / `.p12` 证书文件在 assets 或 raw 中
- Native 层 `SSL_CTX_use_certificate_file` / `SSL_CTX_use_PrivateKey`

取证优先级：
1. 找到客户端证书存储位置（KeyStore / assets / raw / Native 加载）
2. 确认证书是随包分发、首次下载还是设备绑定
3. 常规 unpin 不影响 mTLS；如需绕过需单独提取或替换客户端证书

## TLS 流量拦截

### Frida + frida-analykit

使用 Frida hook libssl.so 的密钥导出函数记录 TLS 密钥：

```javascript
// Hook SSL_write / SSL_read 捕获 TLS 明文流量
var sslWrite = Module.findExportByName("libssl.so", "SSL_write");
var sslRead = Module.findExportByName("libssl.so", "SSL_read");

if (sslWrite) {
  Interceptor.attach(sslWrite, {
    onEnter: function (args) {
      this.buf = args[1];
      this.len = args[2].toInt32();
    },
    onLeave: function (retval) {
      var written = retval.toInt32();
      if (written > 0) {
        console.log("[ssl-write] " + hexdump(this.buf, { length: Math.min(written, 256) }));
      }
    }
  });
}

if (sslRead) {
  Interceptor.attach(sslRead, {
    onEnter: function (args) {
      this.buf = args[1];
    },
    onLeave: function (retval) {
      var read = retval.toInt32();
      if (read > 0) {
        console.log("[ssl-read] " + hexdump(this.buf, { length: Math.min(read, 256) }));
      }
    }
  });
}
```

### Keylog Callback（提取 TLS 密钥材料）

```javascript
// Hook SSL_CTX_new 并注入 keylog callback
var SSL_CTX_new = Module.findExportByName("libssl.so", "SSL_CTX_new");
var SSL_CTX_set_keylog_callback = Module.findExportByName("libssl.so", "SSL_CTX_set_keylog_callback");

if (SSL_CTX_new && SSL_CTX_set_keylog_callback) {
  var keylogCallback = new NativeCallback(function (ssl, line) {
    console.log("[keylog] " + line.readUtf8String());
  }, "void", ["pointer", "pointer"]);

  Interceptor.attach(SSL_CTX_new, {
    onLeave: function (retval) {
      if (!retval.isNull()) {
        SSL_CTX_set_keylog_callback(retval, keylogCallback);
        console.log("[keylog] callback installed on SSL_CTX " + retval);
      }
    }
  });
}
```

工作流：
1. 使用 Frida hook `SSL_write`/`SSL_read`
2. 从 SSL 结构中提取 `client_random` 和 `master_secret`
3. 写入 keylog 文件
4. 在 Wireshark 中配置 keylog 文件路径
5. 自动解密 TLS 流量

### 静态 BoringSSL 密钥提取（Flutter/WebView）

Flutter 和 WebView 内置 BoringSSL，无独立 libssl.so：
1. 内存搜索 `CLIENT_RANDOM` 字符串定位密钥材料
2. 或 hook `SSL_CTX_set_info_callback` 拦截握手过程
3. 或 hook `SSL_do_handshake` 在握手完成时提取 master secret

### primp TLS 指纹库

- 用于生成特定 TLS 指纹（JA3/JA4）
- 可模拟 Chrome/Firefox 等浏览器的 TLS 握手特征
- 适用于需要绕过 TLS 指纹检测的场景

### SSL Key Log → Wireshark 完整工作流

1. **Frida hook** 拦截 TLS 密钥材料
2. **写入 keylog** 文件（NSS Key Log Format）
3. **Wireshark** → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename
4. **过滤** `http` 或目标域名查看解密后的明文流量
5. **导出** 请求/响应用于后续分析

### 内核 eBPF TLS 旁路（Frida 被检测时）

目标存在 anti-Frida、或 `SSL_read`/`SSL_write` hook 不稳定（自检、inline hook 触发崩溃）时，可用内核 eBPF/uprobe 类 TLS 抓包工具旁路抓明文，不需要装 CA 证书、不注入目标进程、不修改用户态内存。

**为什么需要**：Frida hook `SSL_write`/`SSL_read` 依赖目标走 libssl 并能被 Interceptor 命中。强检测目标会自检 libssl 或用内联 syscall 绕过；eBPF 在内核态用 uprobe/kprobe 抓 SSL 函数入口/出口，目标用户态完全无感，是 anti-Frida 场景下抓 TLS 明文的可行替代。

工具能力要求：支持 OpenSSL/BoringSSL/GoTLS/GnuTLS 模块，支持 text/pcap(keylog) 模式，在 Android aarch64 5.5+ / eBPF / BTF 内核上运行。开源等价示例：eCapture 类 eBPF TLS 捕获工具（text 模式直接出明文，pcap 模式出 pcapng，keylog 模式出 master key 供 Wireshark 解密）。指定 Android BoringSSL 路径示例：`/apex/com.android.conscrypt/lib64/libssl.so`。

注意：eCapture 负责旁路抓明文；若目标自带证书 pinning 或自定义 TLS 栈，pinning/业务加密仍需结合 Frida 和静态分析定位。详见 `kernel-assisted-re-playbook.md` 的 eBPF 工具选择。

## 协议降级技术

### QUIC → HTTP/2

当目标强制使用 QUIC（HTTP/3）导致无法抓包时：
1. Hook `CronetEngine.Builder` 禁用 QUIC
2. 或在 DNS 层面阻止 QUIC 端口（443/UDP）
3. 或 Hook `UrlRequest.Builder` 限制协议为 HTTP/2

### Cronet → OkHttp

当需要绕过 Native 网络栈时：
1. 确认 Cronet 只用于网络请求，不承载其他功能
2. 通过 Smali patch 将 Cronet 调用替换为 OkHttp
3. 或在 Java 层拦截请求，用 OkHttp 重新发送

## 常见分歧处理

- `TrustManager` 未命中：
  先看 Cronet / Native verify，不得直接判”没有 pinning”
- `SSL_read / SSL_write` 命中了但抓包仍失败：
  检查是否还有应用层二次加密或 protobuf / 自定义 framing
- Java client 和 Native client 同时存在：
  先确认目标请求走哪一层，不要混用证据

## 联动专题

- **framework-runtime**：Flutter 应用（`libapp.so`）和 Unity 应用（`libil2cpp.so`）的网络请求可能走 Cronet 而非 Java OkHttp，需要先识别运行时类型再选择分析路径。参见 `framework-runtime-playbook.md`
- **integrity-pinning**：当 pinning 发生在 Native TLS 层（`SSL_CTX_set_custom_verify`/`X509_verify_cert`）时，绕过策略需要结合本 playbook 的分层定位和 `integrity-pinning-playbook.md` 的伪造策略
- **crypto-protocol**：网络层抓取到明文后，如果发现是自定义加密协议，需要联动 `crypto-protocol-playbook.md` 进行协议还原
- **jni-bridge**：Cronet 等 Native 网络栈通过 JNI 从 Java 层调用到 Native，需要追踪 `org.chromium.net` → `libcronet.so` 的桥接。参见 `jni-bridge-playbook.md`
- **版本适配**：Android 版本影响证书信任策略和 Network Security Config 行为，参见 `android-version-matrix.md`

## 最小交付

- `run/network-stack-notes.md`
- 报告中的网络分层、pinning 命中层、旁路方式和残留风险

## 实战补充：跨 SO 虚表间接调用

网络 SO 与加密 SO 之间可能不通过 PLT/GOT 链接，而是运行时通过 C++ 虚表注册函数指针回调。典型信号：IDA 中 `BLR Xn` 跳转目标来自 `.bss` 的 `LDAR` 加载，注册函数仅 `ADRL + STLR + RET` 三条指令。

分析需掌握：BLR 反向追踪 → STLR 定位注册函数 → vtable 槽位枚举 → ARM64 `std::string` SSO 布局（短字符串 ≤22B 内联，长字符串取堆指针，byte[23] 符号位区分）。

完整识别信号、5 步分析方法、SSO 参数布局和动态验证流程见 `references/technique-extract-2026-05.md` 第 1 节（抖音 libsscronet × libmetasec_ml 案例）。


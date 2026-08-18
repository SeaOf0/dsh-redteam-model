# Frida Java Playbook

目标：用 Java 层 hook 抓到参数、返回值、加载事件和保护触发点。

## 推荐目标

- 认证与签名方法
- `javax.crypto`
- `java.security`
- `okhttp3`
- `RootBeer`
- `TrustManager`
- `DexClassLoader`
- `Method.invoke`

## 核心 API 模式

基本方法 hook 和构造器 hook 参考 `run/frida-java-template.js` baseline。以下场景是 baseline 未覆盖但常见需求：

### 字段读写

```javascript
Java.perform(function () {
  var Cls = Java.use("com.target.ClassName");
  // 读实例字段：先拿到实例
  Java.choose("com.target.ClassName", {
    onMatch: function (instance) {
      console.log("field value: " + instance.fieldName.value);
    },
    onComplete: function () {}
  });
  // 写静态字段
  Cls.staticField.value = "new value";
});
```

### 多 ClassLoader 场景

当目标使用插件化框架或动态加载时，默认 ClassLoader 可能找不到目标类：

```javascript
Java.enumerateClassLoaders({
  onMatch: function (loader) {
    try {
      loader.loadClass("com.target.ClassName");
      Java.classFactory.loader = loader;
      var Cls = Java.use("com.target.ClassName");
      // 在此处 hook
    } catch (e) {}
  },
  onComplete: function () {}
});
```

### 时序问题

- `Java.perform` 在 Frida attach 后的任何时间点调用都是安全的
- 如果目标类还没有加载（如启动期），使用 `Java.classFactory.loader` + 延迟 hook，或改用 spawn 模式
- 主线程操作（UI 相关）需要 `Java.scheduleOnMainThread`

## 记录要求

- hook 点
- 参数样本
- 返回值样本
- 触发时机
- 是否影响程序稳定性

## Stalker 用于 Java 方法追踪

Frida Stalker 可以追踪方法执行的每条指令：

```javascript
Java.perform(function() {
  var target = Java.use("com.target.ClassName");
  target.methodName.implementation = function() {
    var threadId = Process.getCurrentThreadId();
    Stalker.follow(threadId, {
      transform: function(iterator) {
        var instruction;
        while ((instruction = iterator.next()) !== null) {
          // 记录执行的每条指令
          iterator.putCallout(function(context) {
            console.log("PC: " + context.pc);
          });
          iterator.keep();
        }
      }
    });
    var result = this.methodName();
    Stalker.unfollow(threadId);
    return result;
  };
});
```

注意：Stalker 会产生大量输出，仅用于精确定位问题时使用。

## ArtMethod 获取 Native 地址

在 Attach 模式下，RegisterNatives 已执行完毕，可以通过 ArtMethod 直接读取 native 函数地址：

```javascript
Java.perform(function() {
  var clazz = Java.use("com.target.ClassName");
  // 获取方法的 ArtMethod 指针
  var method = clazz.methodName;
  // 通过 Frida 内部 API 获取 entry point
  // 注意：此方法依赖 Frida 版本和 ART 版本
});
```

适用于：
- RegisterNatives 被混淆，无法静态建立映射
- 需要确认 Java 方法对应的 SO 函数地址
- 动态注册后才能确定的目标函数

## Frida 持久化模式

### fripack 嵌入 Gadget

将 Frida gadget 嵌入 APK，无需 Root 即可使用：
1. 解包 APK
2. 将 `libfrida-gadget.so` 放入 `lib/<arch>/`
3. 修改 Smali，在 Application 类中添加 `System.loadLibrary("frida-gadget")`
4. 重新打包、签名、安装
5. Frida gadget 启动后会监听端口等待连接

### frida-as-xposed 方案

将 Frida 作为 Xposed 替代品使用：
1. 修改 `app_process` 在启动时注入 Frida
2. 通过 ZMQ 命令接口控制 hook
3. 可以实现类似 Xposed 的模块化 hook

## Frida + Wireshark TLS 解密

完整流程：
1. 编写 Frida 脚本 hook `SSL_CTX_set_info_callback` 或 `ssl_log_secret`
2. 从 SSL 结构中提取 master secret
3. 写入 NSS Key Log 格式文件
4. 配置 Wireshark 使用 keylog 文件
5. 自动解密 TLS 流量

```javascript
// 提取 TLS 密钥 —— 动态解析偏移，不要硬编码
//
// 关键：SSL 结构体中 client_random 和 master_secret 的偏移随
// BoringSSL/OpenSSL 版本不同而变化，不能硬编码 0x???。
// 正确做法是 hook 导出函数，从函数参数中直接拿到所需数据：
//
// 方法 A（推荐）：hook SSL_CTX_set_info_callback 或自定义 keylog callback
//   BoringSSL 提供了 SSL_CTX_set_info_callback，在 callback 中
//   可以拿到 ssl 指针，再通过 SSL_SESSION_get_master_key 等 API 读取
//
// 方法 B：hook ssl_log_secret（Android 7+ 系统内部函数）
//   部分系统 ROM 内置了 ssl_log_secret，直接输出 keylog 格式
//
// 方法 C：通过导出符号动态定位

// 示例：通过导出函数动态读取 master key（不依赖硬编码偏移）
function hookTLSKeyLog() {
  // BoringSSL 导出符号，直接通过名称定位
  var SSL_SESSION_get_master_key = Module.findExportByName(
    "libssl.so", "SSL_SESSION_get_master_key"
  );
  var SSL_get_session = Module.findExportByName(
    "libssl.so", "SSL_get_session"
  );
  var SSL_get_client_random = Module.findExportByName(
    "libssl.so", "SSL_get_client_random"
  );

  if (!SSL_SESSION_get_master_key || !SSL_get_session) {
    console.log("[-] libssl.so 中未找到所需导出符号");
    console.log("[-] 可能原因：(1) 系统静态链接 BoringSSL；(2) app 自带 SSL 库");
    console.log("[-] 替代方案：hook ssl_log_secret（Android 7+），或扫描 app 自带 .so 的导出表");
    return;
  }

  var SSL_SESSION_get_master_key_fn = new NativeFunction(
    SSL_SESSION_get_master_key, "size_t", ["pointer", "pointer", "size_t"]
  );
  var SSL_get_session_fn = new NativeFunction(
    SSL_get_session, "pointer", ["pointer"]
  );
  var SSL_get_client_random_fn = new NativeFunction(
    SSL_get_client_random, "size_t", ["pointer", "pointer", "size_t"]
  );

  // hook SSL_read 或 SSL_write 触发点来获取 ssl 指针
  var SSL_read = Module.findExportByName("libssl.so", "SSL_read");
  Interceptor.attach(SSL_read, {
    onEnter: function(args) {
      var ssl = args[0];
      var session = SSL_get_session_fn(ssl);
      // 读 client_random
      var randomBuf = Memory.alloc(32);
      SSL_get_client_random_fn(ssl, randomBuf, 32);
      // 读 master_key
      var keyBuf = Memory.alloc(256);
      var keyLen = SSL_SESSION_get_master_key_fn(session, keyBuf, 256);
      // 输出 keylog 格式
      var crHex = Array.from(new Uint8Array(
        Memory.readByteArray(randomBuf, 32)
      )).map(function(b) {
        return ("0" + b.toString(16)).slice(-2);
      }).join("");
      var mkHex = Array.from(new Uint8Array(
        Memory.readByteArray(keyBuf, keyLen)
      )).map(function(b) {
        return ("0" + b.toString(16)).slice(-2);
      }).join("");
      console.log("CLIENT_RANDOM " + crHex + " " + mkHex);
    }
  });
}
```

## 常见偏差

- 忘记写 `overload` 导致 `Error: methodName(): more than one overload`——需要明确指定参数类型
- hook 时目标类尚未加载——改用 spawn 模式或延迟 hook
- 多 ClassLoader 环境下 `Java.use` 找不到类——需要先 `enumerateClassLoaders`
- hook 了但没有触发——检查是否是混淆后的类名，或方法在父类/接口中定义
- Android 14+ 上部分 hook 目标被列入 hidden API 黑名单——需要先执行 hidden API 绕过（参见 `android-version-matrix.md`）

## 联动专题

- **android-version-matrix.md**：ArtMethod 偏移、hidden API 限制、spawn/attach 行为差异影响 Frida Java hook 可靠性，参见 `android-version-matrix.md`
- **art-runtime**：hook 未命中时可能是 ART 编译状态问题（AOT/JIT/解释执行），参见 `art-runtime-playbook.md` 的 hook 未命中诊断流程
- **anti-frida**：如果 Java hook 被 ArtMethod 完整性自检检测到，参见 `anti-frida-playbook.md` 的 L5 层

## 最小交付

- `run/frida-java-template.js`
- 至少一条成功运行的 Java hook 证据


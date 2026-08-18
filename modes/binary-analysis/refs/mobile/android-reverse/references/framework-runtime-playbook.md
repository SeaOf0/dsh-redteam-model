# Framework Runtime Playbook

目标：识别并处理 Flutter、React Native Hermes、Unity IL2CPP 等跨框架 Android 运行时，避免把框架容器误判成普通 Java-only 应用。

## 先回答

- 当前是 Flutter、Hermes / React Native、Unity，还是混合容器
- Java 容器入口与框架入口在哪里衔接
- 关键逻辑落在 Java、AOT SO、JS bundle、IL2CPP 元数据还是远程更新包
- 当前更适合静态提取、内存 dump、hook、符号恢复还是资源重组

## 高风险信号

- `libapp.so`
- `vm_snapshot_data`
- `isolate_snapshot_data`
- `index.android.bundle`
- `libhermes.so`
- `libil2cpp.so`
- `assets/bin/Data`
- `global-metadata.dat`
- CodePush / 热更新资源
- `libgodot_android.so` + `assets/*.gdc` + `assets/*.pck`
- `*.gdextension`

## 运行时识别 SOP

### Flutter

重点看：

- `libflutter.so`
- `libapp.so`
- snapshot / kernel blob
- `FlutterActivity` / `FlutterFragmentActivity` / `FlutterJNI`

优先回答：

- 逻辑在 Dart AOT、snapshot 还是远端更新资源
- 是否需要基于 isolate、method channel、platform channel 取证

### Hermes / React Native

重点看：

- `index.android.bundle`
- `libhermes.so`
- `ReactActivity`
- `JSIModulePackage` / TurboModule / JSI bridge
- CodePush、热更新目录

优先回答：

- 关键逻辑在 bundle、native module 还是 JS-Native bridge
- bundle 是随包静态分发还是启动后动态下发

### Godot

重点看：

- `libgodot_android.so`（引擎主 SO）
- `assets/*.pck` / `assets/assets.sparsepck`（PCK 资源包，可能加密）
- `assets/*.gdc`（GDScript 编译字节码，头部 `GDSC`，版本 101，zstd 压缩）
- `*.gdextension`（GDExtension 配置文件，指向自定义 native SO）
- RTTI 类型：`15PackedSourcePCK`、`21PackedSourceDirectory`、`10PackSource`

PCK 解包 key 来源：`PackedSourcePCK::try_open_pack()` 从全局指针槽读取 32 字节 key，用于 AES-256-CFB 解密 PCK 目录。

GDExtension 机制：通过 `classdb_register_extension_class5` / `classdb_register_extension_class_method` 注册自定义类和方法（如 `Process.input`），核心算法通常在 GDExtension SO 中（如 `libsec2026.so`），而非引擎 SO。

识别后：
1. 解包 PCK（需找到 script_encryption_key）
2. 反编译 .gdc（GDScript 字节码 → token 流 → 反编译）
3. 分析 GDExtension SO（标准 native 逆向）
4. 如果 PCK 加密：hook `try_open_pack` 提取 key，或从引擎 SO 中定位 key 存储偏移

### Unity / IL2CPP

重点看：

- `libunity.so`
- `libil2cpp.so`
- `assets/bin/Data`
- `global-metadata.dat`
- `UnityPlayerActivity`

优先回答：

- 逻辑在 IL2CPP、资源脚本还是远端热更资源
- 是否存在 stripped symbol，需要结合 metadata 恢复

## 作业顺序

### 1. 先定容器边界

- Manifest 中的入口 Activity / Service
- Java 容器类到框架初始化类
- 关键库和资源由谁加载、在哪个时机加载

### 2. 再定真实逻辑落点

不要只因 Java 层很薄就下结论。
至少判断逻辑在：

- Java
- AOT SO
- JS bundle
- IL2CPP metadata
- 远端更新目录

### 3. 处理 stripped / 资源缺失场景

#### Flutter

- `libapp.so` stripped 时，优先靠字符串、channel 名、资源路径、调用边界定锚
- 如果静态符号贫瘠，优先转运行时 channel / 网络 / crypto sink 取证

#### Hermes / RN

- bundle 混淆时，先找 module id、bridge 注册点、native module 名
- 若 bundle 不在包内，优先排查 OTA / 热更目录和下载路径

#### Unity / IL2CPP

- `libil2cpp.so` stripped 时，不要停在“无符号”
- 结合 `global-metadata.dat`、字符串表、类名、方法名和调用边界恢复
- 如果 metadata 被加壳或加密，优先找解密和加载时机

### 4. 选取证策略

- 容器边界清晰、逻辑落在脚本层：
  优先静态提取 + 运行时验证
- 逻辑落在 AOT / IL2CPP：
  优先边界 hook、metadata 恢复、关键函数 dump
- 存在热更新：
  优先确认下载目录、版本切换和真实使用的资源副本

## Flutter 深入

### Snapshot 分析
- `vm_snapshot_data` + `isolate_snapshot_data` 包含 Dart AOT 编译后的对象快照
- `kernel_blob.bin` 包含 Dart Kernel（中间表示）
- 使用 `darter` / `dart_dump` 工具解析 snapshot

### Dart AOT
- `libapp.so` 包含 Dart AOT 编译的机器码（ARM64）
- 符号通常被 stripped，通过 snapshot 中的类名/方法名辅助定位
- Dart 的异步模型（event loop + isolate）影响 hook 策略

### Method Channel
- Flutter 与 Native 通信通过 `MethodChannel`
- Hook `MethodChannel.invokeMethod` 或 `FlutterJNI.handlePlatformMessage` 拦截通信
- 通信数据为标准 JSON 或二进制

### SSL Pinning 绕过
- Flutter 不使用系统 TLS 库，而是使用内置 BoringSSL
- 标准 OkHttp unpin 无效
- 绕过方式：hook `ssl_verify_peer_cert` 或 `SSL_CTX_set_custom_verify`
- 更底层：hook `session_verify_cert_chain`（BoringSSL 内部函数）

## Cocos2d-js 逆向

### xxtea 密钥提取
- Cocos2d-js 使用 xxtea 加密 `.jsc` 文件
- 密钥硬编码在 `libcocos2djs.so` 中
- 搜索字符串常量或 hook xxtea 解密函数获取密钥
- xxtea 特征常量：`0x9E3779B9`（Delta）

### .jsc 批量解密
1. 从 SO 中提取 xxtea 密钥
2. 遍历 assets 目录下的所有 `.jsc` 文件
3. 使用 xxtea 解密，输出为 JavaScript 源码
4. 关键逻辑通常在 `src/` 目录下

## React Native Hermes 分析

### 字节码版本匹配
- Hermes 字节码有版本号，不同版本的 Hermes 生成不兼容的字节码
- 字节码文件头包含 magic（`1F HBC\0`）和版本号
- 需要匹配版本的 hbcdecomp 才能反编译

### 工具链
- **hbcdump**：官方 Hermes 字节码 dump 工具
- **hbctool**：第三方 Hermes 字节码反汇编/汇编工具
- **hasm**：Hermes 汇编器，可用于修改字节码后重新打包
- **hbcdecomp**：Hermes 字节码反编译器（需要匹配版本）

### 分析流程
1. 确认 Hermes 版本
2. 使用 hbctool 反汇编字节码
3. 定位关键方法（搜索字符串引用）
4. 使用 hbcdecomp 反编译（如果版本匹配）
5. 修改后用 hasm 重新打包

## Unity IL2CPP 全流程

### Metadata 解密（3 种场景）
1. **未加密**：`global-metadata.dat` 直接可用
2. **简单加密**：通常在加载时 XOR 或 AES 解密，hook 解密函数
3. **复杂保护**：metadata 被分片存储或使用自定义加密，需要运行时 dump

### Runtime Dump
- `il2cpp_class_from_name` + `il2cpp_method_get_name` 遍历所有类和方法
- 使用 `il2cppdumper` 从 `global-metadata.dat` + `libil2cpp.so` 恢复头文件
- 运行时 dump：Hook `il2cpp_runtime_invoke` 获取方法执行结果

### API 反混淆
- IL2CPP 编译后方法名来自 metadata
- 如果 metadata 被加密，方法名丢失
- 运行时通过 `il2cpp_class_get_methods` 遍历恢复方法名

### IL2CPP + Lua 架构

许多 Unity 游戏使用 IL2CPP + Lua 热更新架构：
1. C# 层只做薄壳，业务逻辑在 Lua 脚本中
2. Lua 脚本可能被加密存储
3. Hook `luaL_loadbufferx` 拦截所有 Lua 脚本加载
4. dump 解密后的 Lua 源码

```javascript
// Hook luaL_loadbufferx 捕获 Lua 脚本
Interceptor.attach(Module.findExportByName("libtolua.so", "luaL_loadbufferx"), {
  onEnter: function(args) {
    var size = args[2].toInt32();
    var source = Memory.readUtf8String(args[1], size);
    send({type: "lua", source: source, size: size});
  }
});
```

### AutoJS 加密 JS 提取
- AutoJS 应用的 JS 脚本可能被加密打包
- Hook `ScriptEngine.execute` 或 `RhinoScriptEngine` 拦截解密后的脚本
- 或在文件系统层面 dump 解密后的脚本文件

## 游戏协议分析模式

### TCP/UDP 捕获
- 游戏通常使用 TCP 长连接或 UDP（实时对战）
- Wireshark/tcpdump 抓包，过滤目标端口
- 注意：游戏流量可能有自定义 framing（长度前缀 + 魔数）

### Magic Bytes 识别
- 搜索协议头部的固定字节模式
- 常见模式：2-4 字节长度前缀 + 1-2 字节消息类型
- 从多个包中对比共同头部模式

### AES 密钥恢复
- 游戏流量加密通常使用 AES
- 密钥来源：硬编码在 SO 中、登录握手协商、固定密钥+动态 IV
- Hook AES 相关函数获取密钥和 IV

### Protobuf 恢复
- 搜索 `.proto` 文件或 `GeneratedMessageLite` 类
- 从 `parseFrom` / `mergeFrom` 方法反推字段结构
- 使用 `protoc --decode_raw` 解析未知 protobuf 数据

## HybridCLR 解释器 Hook

HybridCLR（huatuo）是 Unity 的热更新方案，将 C# 代码以解释器方式执行：

**识别**：
- `libhuatuo.so` 或 `libhybridclr.so`
- `RuntimeApi.LoadMetadataForAOTAssembly` 调用
- `Interpreter.Execute` 入口函数

**Hook 策略**：
- `Interpreter.Execute` 是所有热更新代码的执行入口，参数包含方法元数据和参数列表
- Hook 此入口可拦截所有热更新方法的调用
- 热更新的 DLL 可从 `LoadMetadataForAOTAssembly` 的参数中 dump

## Corona / Puerts 引擎逆向

### Corona Lua
- 使用 Lua 5.1+ 脚本引擎
- Lua 脚本通常编译为字节码（`.lu` 文件）
- Hook `luaL_loadbuffer` 拦截解密后的 Lua 脚本
- `lua_pcall` 拦截 Lua 函数调用

### Puerts JS
- Unity 中的 TypeScript/JavaScript 运行时（基于 V8/QuickJS）
- JS 代码打包为 `.js` 或编译为字节码
- Hook `v8::Script::Run` 或 QuickJS 的 `JS_Eval` 拦截 JS 执行
- 通过 `puerts` 的 `Register` 函数找到 JS→C# 绑定

## Unity Mod 菜单模式

Unity 游戏常见的内存修改模式：

**工具组合**：And64InlineHook（ARM64 inline hook）+ KittyMemory（内存映射）

**典型 Hook 目标**：
- `Player_get_Health` / `Player_get_Gold` 等属性 getter
- `Application_get_isMobilePlatform` 平台检测
- `Time_get_deltaTime` / `Time_get_time` 时间相关（加速/减速）
- `PlayerPrefs_GetInt` / `PlayerPrefs_GetFloat` 存储读取

**检测与反制**：商业游戏通常检测内存修改行为（完整性校验、内存扫描反制）。

## 常见错误

- 把 Flutter / Unity 的 Java 容器代码当主业务逻辑
- 没确认 bundle / metadata 真正来源，就开始硬拆 base.apk
- `libil2cpp.so` stripped 后直接判“无法继续”
- 未确认远端更新资源，就把包内资源当最终真源

## 最小交付

- `run/framework-runtime-notes.md`
- `run/framework-runtime-map.json`
- 报告中的运行时类型、入口边界、关键资源位置与取证策略


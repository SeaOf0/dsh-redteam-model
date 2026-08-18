# Android 版本适配矩阵

逆向分析中受 Android 版本影响的关键差异。本文件不覆盖所有 API 变更，只聚焦逆向实战中的高频卡点。

## 使用方式

当遇到以下场景时参考本文件：
- Frida hook 命中率异常或 crash
- ART 偏移相关操作（ArtMethod 入口点、access_flags）
- Smali patch 后重签名失败
- SELinux 阻止注入或文件访问
- Hidden API 限制导致反射/hook 失败

## ART Runtime / ArtMethod 偏移

ArtMethod 的内存布局在不同 Android 版本间变化显著，直接影响 Frida Java hook 和手动 ArtMethod 操作。

| 字段 | arm64 (Android 8-14+) | 备注 |
|------|----------------------|------|
| `declaring_class_` 偏移 | 0 | GcRoot，4 字节 |
| `access_flags_` 偏移 | 4 | `kAccNative` (0x100) 位用于检测 Frida hook |
| `dex_method_index_` 偏移 | 8 | uint32_t |
| `method_index_` 偏移 | 12 | uint16_t |
| `hotness_count_` 偏移 | 14 | uint16_t |
| **固定字段合计** | **16** | 之后是指针大小字段（需对齐） |
| `data_` (jni_entry_point) 偏移 | 24 | 填充到 8 字节对齐后；**arm32 为 16** |
| `entry_point_from_quick_compiled_code_` 偏移 | 32 | **arm32 为 20** |
| ArtMethod 总大小 | 40 | **arm32 为 24** |

> **不要硬编码偏移**。arm32/arm64 差异大，且厂商 ROM 可能修改布局。上述值为 AOSP 标准构建参考。运行时探测方法见 `hook-injection-playbook.md` 的 ArtMethod 章节和 `frida-java-playbook.md`。

**运行时探测方法**（不要硬编码偏移）：
```javascript
// 通过已知 ArtMethod 地址反推偏移
var open = MethodUtils.getArtMethod(Java.use("java.io.File").exists);
// 读取 entry point 附近的指针，匹配已知的 stub 地址来确认偏移
```

**关键版本事件**：
- Android 12：VDEX 文件格式在标准 AOSP 构建中被弃用（OAT 直接包含 DEX），部分厂商 ROM 和 OTA 后状态仍可能存在 VDEX 文件
- Android 14：部分 ArtMethod 布局调整，需运行时确认

## APK 签名方案

Smali patch 后重签名时，签名方案版本直接影响兼容性。

| 签名方案 | 引入版本 | 当前状态 | Patch 后重签名影响 |
|----------|---------|---------|-------------------|
| v1 (JAR signing) | Android 1.0 | 仍支持 | 最基础，不覆盖 ZIP 条目外的内容 |
| v2 | Android 7.0 | 标准 | 覆盖整个 APK；`apktool` 默认使用 v2 |
| v3 | Android 9.0 | 标准 | **引入 key rotation**——APK 可声明轮转证书。patch 后用原始签名密钥重新签名即可，除非 App 验证 certificate history |
| v3.1 | Android 13 (API 33) | 标准补充 | v3 的 bugfix，支持 SDK 版本 targeted 的 key rotation；无额外 patch 影响 |
| v4 | Android 11 | 可选 | 增量安装支持（仅 `adb install`），不独立使用，与 v2/v3 共存 |

**关键注意**：
- **Android 14 旋转签名密钥**：`apksigner` 新增 `--rotation` 参数。如果目标 App 使用了 key rotation，patch 后需要用最新的签名密钥重签（不是原始密钥）
- **`apksigner` 版本**：始终使用最新版 Android SDK Build Tools 中的 `apksigner`，旧版本不支持 v3.1/v4
- **`zipalign` 顺序**：v2/v3 签名要求 `zipalign` 在 `apksigner` 之前执行（`zipalign → apksigner`），反序会导致签名验证失败

## SELinux 策略对逆向工具的影响

| Android 版本 | SELinux 默认状态 | 对 Frida 注入的影响 | 对文件操作的影响 |
|-------------|-----------------|-------------------|----------------|
| 6.0-7.1 | Enforcing（部分设备） | 需 root 关闭 SELinux 或 `setenforce 0` | `/data/local/tmp` 通常可写 |
| 8.0-9.0 | Enforcing（强制） | Magisk 可绕过；KernelSU/APatch 内核级处理 | `frida-server` 需放在 `/data/local/tmp` |
| 10-11 | Enforcing + 更严格策略 | Zygisk 注入路径受 SELinux 监控 | `/data/local/tmp` 仍可用，但某些 tmp 目录受限 |
| 12-13 | Enforcing + neverallow 扩展 | 需要 DenyList/Shamiko/Unmount 隐藏注入痕迹 | frida-server 可能需要重命名（SELinux 上下文匹配） |
| 14+ | Enforcing + 更多 neverallow | `ptrace` 受限增强；非 debuggable App 更难 attach | 建议使用 `spawn` 模式而非 `attach` |

**常见 SELinux 拒绝排查**：
```bash
# 查看 SELinux 拒绝日志
adb logcat -b events -d | grep avc
# 或
dmesg | grep avc
# 临时关闭（需 root）
adb shell setenforce 0
```

## Hidden API / Non-SDK 接口限制

Android 9+ 限制反射调用非 SDK 接口，影响 Frida hook 和 jadx 中观察到的内部 API 使用。

| Android 版本 | 限制级别 | 对 Frida Java hook 的影响 | 对反射分析的影响 |
|-------------|---------|-------------------------|----------------|
| 8.x 及以下 | 无限制 | 不受影响 | 反射自由使用 |
| 9-10 | 浅灰/深灰名单 | `Java.use` 调用深灰名单 API 可能抛 `NoSuchMethodException` | 可通过元数据绕过（设置 `vm.hidden-api-policy`） |
| 11-12 | 名单扩展 + 更严格 | 更多 API 被限制 | `setHiddenApiExemptions` 仍可绕过 |
| 13 | 黑名单扩大 | 部分 `art::ArtMethod` 访问受限 | 绕过方法仍然有效但可能需要更新偏移 |
| 14+ | 进一步收紧 | 某些 Frida Java hook 目标被列入黑名单 | 需结合 Native hook 绕过 |

**通用绕过方法**（在 Frida 脚本开头调用，完整实现见 `frida-java-playbook.md`）：
```javascript
// 绕过 hidden API 限制（Android 9+）
Java.perform(function() {
  var VMRuntime = Java.use("dalvik.system.VMRuntime");
  var vmRuntime = VMRuntime.getRuntime();
  var setHiddenApiExemptions = VMRuntime.class.getDeclaredMethod(
    "setHiddenApiExemptions", Java.array("java.lang.String", [""]).getClass());
  setHiddenApiExemptions.invoke(vmRuntime, Java.array("java.lang.String", ["L"]));
  // "L" 前缀匹配所有类（所有 Java 类描述符以 L 开头）
});
```

## DEX/OAT/VDEX 文件格式

| Android 版本 | DEX 格式版本 | OAT 行为 | VDEX 行为 | 对 dump/分析的影响 |
|-------------|------------|---------|----------|------------------|
| 7-8 | `dex\n035\0` - `dex\n038\0` | OAT 包含编译后代码 + DEX | 无 VDEX | 直接从 OAT 中提取 DEX |
| 9-10 | `dex\n039\0` | OAT + VDEX 分离 | VDEX 包含未压缩 DEX | 需先从 VDEX 提取 DEX；`vdexExtractor` |
| 11 | `dex\n039\0` | OAT 包含 compact dex | VDEX 可能包含 compact dex | `compact_dex` 格式需要特殊工具处理 |
| 12+ | `dex\n039\0` - `dex\n040\0` | **VDEX 被弃用**，OAT 直接包含 DEX | 不再生成 | DEX 直接从 OAT 或内存中获取 |
| 14+ | 同上 | OAT 格式持续演进 | 不存在 | 内存 dump DEX 是最可靠方案 |

**DEX magic 速查**（Memory.scan 用）：
```
64 65 78 0a 30 33 35 00  (dex\n035\0)
64 65 78 0a 30 33 37 00  (dex\n037\0)
64 65 78 0a 30 33 38 00  (dex\n038\0)
64 65 78 0a 30 33 39 00  (dex\n039\0)
64 65 78 0a 30 34 30 00  (dex\n040\0, 罕见/内部版本，非标准)
```

## Network Security Config

| Android 版本 | 用户 CA 证书信任 | 明文流量 | 对抓包/证书锁定的影响 |
|-------------|----------------|---------|---------------------|
| 6-8 | 默认信任用户证书 | `targetSdk < 28` 时允许明文 | 安装 Charles/Fiddler 证书即可抓 HTTPS |
| 9+ | **默认不信任用户证书**（与明文流量无关） | `targetSdk >= 28` 时 `usesCleartextTraffic=false`，阻止 HTTP 明文 | 需要 `network_security_config.xml` 配置信任用户证书，或系统级证书注入 |
| 11+ | 用户证书安装位置变更（`/data/misc/user/0/cacerts-added/`） | 同上 | 推荐使用 Magisk 模块（`MagiskTrustUserCerts`）将用户证书提升为系统证书 |
| 14+ | 更严格的证书验证 | 同上 | 部分应用即使在 `network_security_config.xml` 中信任用户证书，也可能被 Play Integrity 检测 |

**系统证书注入方法**（需 root）：

**推荐方法（Magisk 模块）**：安装 `MagiskTrustUserCerts` 模块，自动将用户证书提升为系统证书，无需手动操作。支持 Android 9+，兼容 EROFS 和动态分区。

**手动方法**（Magisk 模块不可用时）：
```bash
# 将用户证书提升为系统证书（Android 9+）
# 注意：Android 10+ 的 EROFS/动态分区设备上 mount -o rw,remount /system 可能失败
# 证书哈希名可从 /data/misc/user/0/cacerts-added/ 获取
adb shell su -c "mount -o rw,remount /system"
adb shell su -c "cp /data/misc/user/0/cacerts-added/<hash>.0 /system/etc/security/cacerts/"
adb shell su -c "chmod 644 /system/etc/security/cacerts/<hash>.0"
adb shell su -c "mount -o ro,remount /system"
```

## Scoped Storage（Android 10+）

| Android 版本 | 影响 | 逆向工作中的应对 |
|-------------|------|----------------|
| 10+ (`targetSdk >= 29`) | 应用私有目录 `/sdcard/Android/data/<pkg>/` 不再可通过系统文件管理器或 `adb pull` 自由访问 | 需要 `adb shell run-as <pkg>` （仅 debuggable 应用）或 root 权限访问 |
| 11+ | 更严格的分区存储执行，Media Store 访问需要权限 | dump 文件输出到 `/data/local/tmp/` 而非 `/sdcard/`；使用 `adb pull /data/local/tmp/` 提取 |
| 所有版本 | `adb shell am dumpheap` / `adb shell cmd package compile` 等调试命令对非 debuggable 应用受限 | 需要 root 或 `android:debuggable=true` 的构建 |

**逆向文件输出建议**：
- Frida 脚本中将 dump 文件写入 `/data/local/tmp/`（所有版本通用，需 root）
- 或写入应用私有目录（`/data/data/<pkg>/`），然后 `adb shell run-as <pkg> cat file > /sdcard/file`
- 避免依赖 `/sdcard/` 路径——不同版本权限模型不同

## extractNativeLibs 标志

AndroidManifest 中的 `android:extractNativeLibs` 影响 SO 文件在设备上的存在方式：

| 值 | 行为 | 对逆向的影响 |
|----|------|------------|
| `false`（Android Studio 3.6+ 默认） | SO 直接从 APK 内加载，不提取到磁盘 | `/data/app/<pkg>/lib/` 目录可能为空；`Module.findBaseAddress` 仍有效但手动 SO 提取需解压 APK |
| `true`（传统行为） | SO 提取到 `/data/app/<pkg>/lib/<abi>/` | 可直接 pull SO 文件到本地用 IDA 分析 |

**识别方法**：检查 `AndroidManifest.xml` 的 `<application>` 标签中 `android:extractNativeLibs` 属性。如果值为 `false` 且需要获取 SO 文件，用 `unzip` 从 APK 中直接提取。

## debuggable 要求

| 场景 | 是否需要 debuggable | 需要 debuggable 时的替代方案 |
|------|-------------------|---------------------------|
| Frida attach 到非 debuggable App | 需要 root | 使用 `spawn` 模式（`frida -U -f`）绕过 |
| `run-as <pkg>` | 需要 debuggable | 用 root 权限直接访问 `/data/data/<pkg>/` |
| `adb shell am dumpheap` | 需要 debuggable | 用 Frida `Memory.dump` 替代 |
| JDWP 调试 | 需要 debuggable | 用 Frida Java hook 替代 |
| `adb shell cmd package compile` | 需要 debuggable 或 root | root 下直接执行 |

**绕过 debuggable 检查**：如果 App 运行时检查 `ApplicationInfo.FLAG_DEBUGGABLE`，Hook `getApplicationInfo` 清除 flag。注意这不会启用 JDWP——只欺骗 App 自己的检测。

## 通用建议

- **不要硬编码偏移**：ArtMethod 偏移、系统属性路径等在不同厂商 ROM 上可能有差异。始终先运行时探测，再使用探测结果
- **spawn 优先于 attach**：Android 12+ 的 SELinux 和 hidden API 限制使得 attach 模式越来越不可靠。spawn 模式在进程初始化前注入，绕过大部分启动期检测
- **验证目标 SDK 版本**：从 `AndroidManifest.xml` 的 `targetSdkVersion` 推断适用的限制。`targetSdkVersion >= 28` 意味着 hidden API 限制生效；`>= 30` 意味着包可见性限制
- **本文件是快照**：Android 版本持续演进，遇到新版本时先在对应 SO 中验证偏移和行为的准确性

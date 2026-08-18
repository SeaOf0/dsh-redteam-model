# Anti-Root Playbook

目标：把 anti-root 当作分层检测体系来拆，不把 hook 掉几个 `File.exists` 就当作完整 bypass。

## 先回答三件事

- 命中发生在 `冷启动 / 功能点击后 / 发包前 / 定时后台轮询`
- 检测位于 `Java 层 / JNI 层 / Native syscall / 系统属性 / 远端 attestation`
- 当前失败现象是 `闪退 / 退出 / 禁用功能 / 风控标记 / 服务端拒绝`

## 先收敛失败信号

在开始绕过之前，必须先锁定检测的实际行为。没有失败信号时不要盲 patch。

至少保留一项：

- logcat 中的检测相关日志（搜索 `root`/`su`/`magisk`/`security`/`integrity` 关键词）
- hook 到的检测分支（`File.exists` 返回 true 的调用栈、Native `access` 返回 0 的路径）
- toast / 对话框 / 错误码
- 服务端响应中的风控标记（HTTP 响应头、JSON 中的风险字段）
- **静默检测取证**：对比 root 设备和非 root 设备的网络请求差异，找出携带 root 状态的风控字段

**静默检测发现方法**（无闪退、无提示的"隐形"检测）：

1. **流量对比**：用 mitmproxy 分别在 root 和非 root 设备上抓同一操作的请求，diff 响应
2. **加密前拦截**：在加密函数入口 hook，检查明文输入中是否包含 root 相关字段（`isRooted`/`rootStatus`/`deviceScore` 等）
3. **OkHttp Interceptor 层**：搜索 `Interceptor`/`Interceptor.chain` 追加的 header 或 body 字段
4. **Native 层采集**：搜索 `__system_property_get` 在加密前被调用的序列——如果加密函数调用链中包含属性读取，很可能是在采集设备状态

## 检测面分层矩阵

### L1 Java/App 层（防护等级 A1-A2）

| 检测项 | 检测方式 | 检测签名 | 绕过策略 |
|--------|----------|----------|----------|
| su 二进制 | `File.exists` / `Runtime.exec("which su")` | `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/data/local/bin/su`, `/data/local/xbin/su` | Hook `File.exists` 对 su 路径返回 false；或 Hook `Runtime.exec` 过滤 su 相关命令 |
| Magisk 包名 | `PackageManager.getPackageInfo("com.topjohnwu.magisk")` | `com.topjohnwu.magisk` | Hook `getPackageInfo` 对 Magisk 包名抛 `NameNotFoundException` |
| 旧版管理器包名 | 同上 | `com.noshufou.android.su`, `eu.chainfire.supersu`, `com.koushikdutta.superuser`, `me.weishu.superku` | 同上 |
| 系统属性 | `System.getProperty` / `__system_property_get` | `ro.debuggable=1`, `ro.secure=0`, `ro.build.tags=test-keys` | Hook 属性读取函数返回安全值 |
| 可写系统分区 | 尝试 `mount | grep " /system"` 或写入测试 | `/system` 挂载为 rw | Hook `mount` 或直接不触发 |
| busybox/工具 | `File.exists` / `Runtime.exec("busybox")` | `/system/bin/busify`, `/system/xbin/busybox` | Hook `File.exists` |
| RootBeer 类库 | 集成 RootBeer SDK 的多个检测向量 | `com.scottyab.rootbeer.RootBeer` 类名 | 定位 `isRooted()` 返回值，Hook 返回 false |

### L2 Native/系统属性层（防护等级 A2-A3）

| 检测项 | 检测方式 | 检测签名 | 绕过策略 |
|--------|----------|----------|----------|
| `__system_property_get` | Native 层读取系统属性 | `ro.debuggable`, `ro.secure`, `ro.build.tags`, `ro.boot.vbmeta.verify` | Hook `__system_property_get` 返回安全值 |
| `access`/`stat` | Native 层文件存在性检查 | `/system/bin/su`, `/sbin/.magisk`, `/data/adb/magisk` | Hook `access`/`stat`/`fstat` 对特征路径返回 -1 |
| `/proc/self/mountinfo` | 读取 mount 信息检测 Magisk overlay | `magisk`, `/sbin/.magisk` 挂载点 | Hook `openat` 拦截 mountinfo 路径 |
| `/proc/version` | 内核版本字符串检测 KernelSU 修改 | 包含自定义后缀的内核版本 | Hook `openat` + `read` 过滤内核版本行 |
| SELinux 状态 | `security_getenforce()` 或读取 `/sys/fs/selinux/enforce` | Permissive 模式（enforce=0） | Hook `security_getenforce` 返回 1（Enforcing）；不轻易建议用户关闭 SELinux |
| `ro.boot.verifiedbootstate` | 验证启动状态 | `orange`（unlocked）vs `green`（locked） | Hook 属性读取返回 `green` |

### L3 Magisk/Zygisk 生态检测（防护等级 A3-A4）

| 检测项 | 检测方式 | 检测签名 | 绕过策略 |
|--------|----------|----------|----------|
| `/sbin/.magisk` | 目录存在性（Android 10 及以下） | `/sbin/.magisk/{util, mirror, mirror-ro}` | 启用 DenyList 或 Shamiko 将目标加入隐藏 |
| `/data/adb/magisk/` | Magisk 数据目录 | `magisk64`, `magisk32`, `magiskinit` | 同上；或 Hook `access`/`openat` |
| Zygisk SO 注入 | 扫描 `/proc/self/maps` 中的 Zygisk 模块 | 匿名 mmap 区域中的 ELF，或特定模块路径 | Shamiko 可清除大部分痕迹；A4+ 需配合 maps hook |
| `ro.boot.vbmeta.verify` | dm-verity 验证状态 | `0`（disabled）| Hook 属性返回 `1` |
| Magisk SU 日志 | `/data/adb/magisk.db` 存在性 | `magisk.db` 文件 | DenyList 隐藏 |

### L4 KernelSU / APatch 专项（防护等级 A3-A5）

KernelSU 和 APatch 是 Magisk 之外的主要 root 方案，检测策略与 Magisk 有差异。

| 检测项 | 检测方式 | 检测签名 | 绕过策略 |
|--------|----------|----------|----------|
| KernelSU 包名 | `PackageManager` 查询 | `me.weishu.kernelsu` | Hook `getPackageInfo` 抛 `NameNotFoundException` |
| KernelSU 管理器 | 检测 KSU 管理器 App（用户可自定义包名） | `me.weishu.kernelsu.manager` 或自定义 | 需扫描所有 App 检测 KSU 特征 Activity；Hook 层面拦截查询 |
| `/proc/version` 修改 | KernelSU 修改内核版本字符串 | 版本字符串包含自定义后缀 | KSU 自身提供 `umount` 模式隔离；或 Hook `openat`+`read` 恢复原始版本 |
| KernelSU `ksud` | 检测 KSU 守护进程 | `/data/adb/ksud` 文件 | Hook `access`/`stat`；或 KSU 的 unmount 模式 |
| APatch 包名 | `PackageManager` 查询 | `me.bmax.apatch` | 同 KSU 策略 |
| APatch boot 修改 | 检查 `ro.boot.apatch` 属性或 APatch 特征 | 自定义属性 | Hook 属性读取 |
| APatch KernelPatch 模块 | `/proc/kpatch` 或 `kpatch` syscall | KernelPatch 接口 | APatch 提供隐藏模式；需在 APatch 管理器中开启 |

**KernelSU vs APatch vs Magisk 的绕过策略差异**：

| Root 方案 | 隐藏机制 | 检测难度（对 App 而言） | 推荐绕过方式 |
|-----------|----------|------------------------|-------------|
| Magisk | DenyList + Shamiko | 低-中（特征文档最多） | DenyList + Shamiko + Frida hook 补漏 |
| KernelSU | Unmount 模式 + 隐藏管理器 | 中（特征相对较少） | 启用 unmount + Hook 属性/文件检查 |
| APatch | 隐藏模式 + Shamiko 兼容 | 中-高（较新，特征库不完善） | 启用隐藏 + 与 Magisk 类似的 Hook 补漏 |

### L5 远端 Attestation（防护等级 A4-A7）

| 检测项 | 检测方式 | 检测签名 | 绕过策略 |
|--------|----------|----------|----------|
| SafetyNet Attestation | Google Play Services API（**已废弃**） | `SafetyNet.getClient().attest()` | 新目标不再使用；旧目标可用 Play Integrity 兼容方案 |
| Play Integrity API - BASIC | 应用完整性检查 | `StandardIntegrityTokenProvider` | 对 repackaged APK 无效（签名不匹配）；原版 APK + root 环境可通过 DenyList 绕过 |
| Play Integrity API - DEVICE | 设备完整性 | DEVICE verdict 要求 `boot` 级验证 | Root 设备通常无法通过 DEVICE 级别，除非 bootloader relock |
| Play Integrity API - STRONG | 硬件信任链 | TEE 级密钥证明 | **无法软件绕过**；标记 `not-bypassable-by-software` |
| Key Attestation | Android Keystore 硬件证明 | `KeyGenParameterSpec` 的 `attestation` 扩展 | 检查 `attestation` 中的 `bootLevel`/`locked`/`unlockable`；**软件绕过空间极小** |
| 自建 Attestation | 服务端下发 challenge + 客户端采集设备信息签名 | 非 Google 标准协议 | 分析 Attestation 协议细节（见下方"远端联动"节），逐字段伪造 |

### L6 组合检测（防护等级 A5-A7）

A5+ 场景下 root 检测通常不独立出现，而是与 anti-frida、anti-debug、完整性校验组合：

- **Root + Integrity**：root 检测作为 attestation 字段上报服务端，服务端综合判定
- **Root + Anti-Frida**：root 环境是 Frida 运行的前提，先检测 root 再检测 Frida
- **多阶段检测**：启动时轻量检测（Java 层），关键操作前重量检测（Native + 远端）
- **SVC 级检测**：直接通过 `svc #0` 系统调用检查文件/属性，绕过 libc hook

## 绕过顺序

先完成 SKILL.md 保护绕过专项要求的四个子面枚举（root / frida / integrity / pinning），再按以下技术顺序执行 root 子面：

### 第一步：环境预处理

- 确认 root 方案类型（Magisk / KernelSU / APatch）
- 启用对应的隐藏机制（DenyList / Shamiko / Unmount / APatch 隐藏模式）
- 将目标 App 加入隐藏列表
- **验证隐藏是否生效**：用 RootBeer 等开源工具先测试

### 第二步：Java 层 hook

优先覆盖高频检测 API：

```javascript
Java.perform(function() {
  // 1. File.exists — 最常见的 Java 层检测
  var File = Java.use("java.io.File");
  File.exists.implementation = function() {
    var path = this.getAbsolutePath();
    if (path === "/system/bin/su" || path === "/system/xbin/su" ||
        path === "/sbin/su" || path === "/data/local/bin/su" ||
        path === "/data/local/xbin/su" || path === "/system/app/Superuser.apk" ||
        path === "/system/app/SuperSU.apk" || path === "/data/adb/magisk" ||
        path === "/data/adb/ksud" || path === "/sbin/.magisk") {
      return false;
    }
    return this.exists();
  };

  // 2. PackageManager — 包名查询
  var PM = Java.use("android.app.ApplicationPackageManager");
  PM.getPackageInfo.overload("java.lang.String", "int").implementation = function(name, flags) {
    var suspicious = ["com.topjohnwu.magisk", "com.noshufou.android.su",
                      "eu.chainfire.supersu", "me.weishu.kernelsu",
                      "me.weishu.kernelsu.manager", "me.bmax.apatch",
                      "com.koushikdutta.superuser", "me.weishu.superku",
                      "io.github.vvb2060.magisk" /* Alpha */];
    if (suspicious.indexOf(name) !== -1) {
      throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(name);
    }
    return this.getPackageInfo(name, flags);
  };

  // 注意：Java System.getProperty("ro.debuggable") 在 Android 上始终返回 null
  // （Android 系统属性与 Java 系统属性不同），真正有效的属性读取在 Native 层
  // __system_property_get，见第三步
});
```

### 第三步：Native 层 hook

```javascript
// Native 层属性拦截
var prop_get = Module.findExportByName("libc.so", "__system_property_get");
Interceptor.attach(prop_get, {
  onEnter: function(args) {
    this.name = args[0].readUtf8String();
    this.valueBuf = args[1];
  },
  onLeave: function(retval) {
    if (this.name === "ro.debuggable") {
      this.valueBuf.writeUtf8String("0");
    } else if (this.name === "ro.secure") {
      this.valueBuf.writeUtf8String("1");
    } else if (this.name === "ro.build.tags") {
      this.valueBuf.writeUtf8String("release-keys");
    } else if (this.name === "ro.boot.verifiedbootstate") {
      this.valueBuf.writeUtf8String("green");
    }
  }
});

// 文件存在性拦截（access/stat/fstat）
var errno_ptr = Module.findExportByName("libc.so", "__errno");
function setErrno(val) {
  if (errno_ptr) { errno_ptr().writeS32(val); }
}

var access = Module.findExportByName("libc.so", "access");
Interceptor.attach(access, {
  onEnter: function(args) {
    var path = args[0].readUtf8String();
    if (path && (path.indexOf("/su") !== -1 || path.indexOf("magisk") !== -1 ||
        path.indexOf("supersu") !== -1 || path.indexOf("kernelsu") !== -1 ||
        path.indexOf("apatch") !== -1 || path === "/sbin/.magisk" ||
        path === "/data/adb/magisk" || path === "/data/adb/ksud")) {
      this.block = true;
    }
  },
  onLeave: function(retval) {
    if (this.block) {
      retval.replace(-1);
      setErrno(2); // ENOENT
    }
  }
});

var stat = Module.findExportByName("libc.so", "stat");
if (stat) {
  Interceptor.attach(stat, {
    onEnter: function(args) {
      var path = args[0].readUtf8String();
      if (path && (path.indexOf("/su") !== -1 || path.indexOf("magisk") !== -1 ||
          path.indexOf("kernelsu") !== -1 || path.indexOf("apatch") !== -1 ||
          path === "/sbin/.magisk")) {
        this.block = true;
      }
    },
    onLeave: function(retval) {
      if (this.block) {
        retval.replace(-1);
        setErrno(2);
      }
    }
  });
}

// /proc 文件拦截（mountinfo / version / self/status）
var openat = Module.findExportByName("libc.so", "openat");
Interceptor.attach(openat, {
  onEnter: function(args) {
    var path = args[1].readUtf8String();
    if (path && (path.indexOf("/proc/self/mountinfo") !== -1 ||
        path.indexOf("/proc/version") !== -1 ||
        path.indexOf("/proc/self/status") !== -1)) {
      this.redirectPath = path;
    }
  }
  // 完整实现需要对 read 也做 hook 来过滤内容
  // 简化方案：让 openat 正常通过，在 read 层过滤关键词
  // 完整方案见 anti-frida-playbook.md 的 /proc 文件拦截模板
});
```

**SVC 级检测处理**：当应用直接使用 `svc #0` 系统调用（不经过 libc）时，上述 libc hook 全部无效。识别方式：在 IDA/radare2 中搜索 `svc #0`（ARM64 编码 `0xD4000001`）或 `svc #1`（ARM32）。绕过策略：

1. **二进制 patch**：将 SO 中的 SVC 指令 NOP 掉（ARM64: `NOP` = `0xD503201F`），通过 Frida `Memory.patchCode` 或 IDA Keypatch 执行
2. **内核级拦截**：如果 SVC 使用频繁，需要 `kernel-assisted-re-playbook.md` 中的 eBPF/SVC hook 方案
3. **smali patch**：如果 SVC 检测在 Java 调用的 Native 函数中，可以直接在 Java 层 hook 调用入口返回安全值，绕过整个 Native 检测函数

### 第四步：远端 Attestation 处理

遇到 Play Integrity / Key Attestation 时：

1. **BASIC 级**：通常不影响 root 隐藏（检查的是 App 完整性而非设备 root 状态）
2. **DEVICE 级**：需要分析 verdict 中哪些字段暴露了 root 状态
3. **STRONG 级 / Key Attestation**：标记 `not-bypassable-by-software`，在报告中说明：
   - 哪些检测面已被绕过（Java + Native）
   - 哪些检测面无法绕过（硬件级 Attestation）
   - 对 completionCriteria 的影响（是否阻塞核心交付）
   - 可能的服务端配合方案（如测试环境关闭 Attestation）

### 第五步：静态 smali patch（仅在动态绕过不稳定时）

当动态 hook 不稳定（多进程、时序问题、启动早期检测）时，直接 patch smali：

1. 定位检测方法：搜索 `File.exists`、`Runtime.exec`、`getPackageInfo`、`__system_property_get` 调用
2. 替换返回值：`const/4 v0, 0x0`（false）或 `return-void`
3. 重新打包/签名/安装验证
4. 注意 APK Signature Scheme v3 对 patch 的影响（参见 `smali-patching-playbook.md`）

## 多阶段 anti-root 必须分层交付

A4+ 场景中 root 检测通常分层：

1. **启动前置**：`Application.onCreate` / `ContentProvider` 中执行轻量 Java 检测
2. **功能前置**：关键功能入口执行 Native 层重量检测
3. **发包前置**：请求发出前收集设备状态作为风控字段上报
4. **后台轮询**：定时执行检测（如每 60s）

如果后两层仍存在，应在 `run/anti-root-bypass.js` 中写清分阶段注入点和未解层。

## 多进程架构处理

当 App 使用多进程（常见于国内超级应用）时，root 检测可能不在主进程中运行。

**识别多进程**：在 `AndroidManifest.xml` 中搜索 `android:process=":` 前缀的组件。常见的子进程名：
- `:push`（推送服务）
- `:webview`（独立 WebView 进程）
- `:remote` / `:service`（远程服务）
- `:guard` / `:security`（安全/保护进程——**重点排查**）

**多进程绕过策略**：

1. **DenyList / Shamiko / Unmount**（推荐）：这些机制作用于 Zygote 层面，覆盖所有 fork 出的子进程。确保目标 App 所有进程都在隐藏列表中
2. **Frida 多进程 attach**：`frida -U -n "com.app:push"` attach 到特定子进程。需要为每个子进程单独注入脚本
3. **Frida spawn 模式**：`frida -U -f com.app --no-pause` 会注入到主进程，但子进程需要单独处理
4. **smali patch**（最可靠）：修改 APK 中的检测代码影响所有进程。当动态 hook 无法覆盖所有子进程时使用
5. **ContentProvider 优先排查**：`ContentProvider` 在每个进程中都会被初始化（`onCreate` 在 Application 之前调用），是放置多进程检测的常见位置

**注意**：KernelSU 的 `unmount` 模式在不同子进程中的行为可能不同——某些子进程可能在 unmount 之前就已经完成了检测。需要针对 `:guard`/`:security` 类进程单独验证。

## 组合绕过示例（A3 场景）

A3 级别常见组合：Java 层 RootBeer + Native `__system_property_get` + `/proc/self/mountinfo` 扫描。需要同时覆盖：

```javascript
// 完整 A3 组合绕过脚本框架
// 1. Java 层：File.exists + PackageManager（见第二步代码）
// 2. Native 属性：__system_property_get（见第三步代码）
// 3. Native 文件：access + stat（见第三步代码）
// 4. /proc 文件：openat + read 过滤 mountinfo 中的 magisk 条目

// mountinfo 过滤示例
var read = Module.findExportByName("libc.so", "read");
// 注意：对 read 的 hook 性能影响大，应限定 fd 来源
// 实际实现应追踪 openat 返回的 fd，只对特定 fd 做内容过滤
// 完整模板见 anti-frida-playbook.md 的 /proc 文件拦截模板
```

## 联动专题

- **anti-frida**：root 环境是 Frida 运行的前提，anti-root 绕过后才能进行 Frida hook。如果 root 绕过后 Frida 仍被检测，参见 `anti-frida-playbook.md`
- **anti-emulator**：部分 App 将 root 检测与模拟器检测合并执行，参见 `anti-emulator-debug-playbook.md`
- **integrity**：Play Integrity / Key Attestation 虽然在 root 检测中使用，但其绕过策略更接近完整性校验，详细参见 `integrity-pinning-playbook.md`
- **dex-loader**：壳保护的 App 可能将 root 检测逻辑放在动态加载的 dex 中，参见 `dex-loader-playbook.md` 确认是否需要先脱壳

## 常见偏差

- 只绕过了 Java 层检测但漏掉了 Native 层的 `access("/system/bin/su")`——需要同时覆盖
- 绕过了 `su` 文件检测但没处理 `ro.debuggable` / `ro.secure` 属性检查
- 忽略了 Play Integrity 的存在——即使不直接检测 root，Play Integrity 也会暴露 root 状态
- 使用老旧的 SafetyNet 绕过方案——SafetyNet 已废弃，新目标应关注 Play Integrity
- 只测试了启动时不闪退，但没检查后台定时检测和发包前风控字段
- 忽略了 KernelSU / APatch 与 Magisk 的特征差异——不同 root 方案的检测点和绕过策略不同
- 在 KernelSU 环境下只做了 Magisk 风格的文件隐藏——KernelSU 的 `unmount` 模式是更可靠的首选方案
- A5+ 场景中 root 检测与 anti-frida 联动时，只绕过了 root 检测就认为可以 hook——需要同步处理 anti-frida

## 最小交付

- `run/anti-root-bypass.js`
- 报告中的检测面与绕过状态（按 L1-L6 分层记录）
- A3+ 场景必须包含使用的隐藏方案（DenyList/Shamiko/Unmount/APatch）和验证结果
- A4+ 场景必须说明远端 Attestation 的处理方式和残留风险

## 实战补充：SELinux 查询探测

LSPosed 的 DirtySepolicy 利用 AppZygote + isolatedProcess 在 `app_zygote` 上下文中查询 SELinux 策略，检测额外 sepolicy 规则：

- `SELinux.checkSELinuxAccess(source, target, class, perm)` 查询敏感上下文对（如 `u:r:untrusted_app:s0 → u:r:magisk:s0`）
- `/proc/self/attr/current` 写入目标 context 检查 transition
- 额外 sepolicy 规则使查询结果与纯净环境不同，成为检测信号

**敏感上下文**: `u:r:magisk:s0`, `u:r:ksu:s0`, `u:r:su:s0`, `u:object_r:ksu_file:s0`, `u:object_r:lsposed_file:s0`, `u:object_r:xposed_data:s0`

**内核级对抗**: 通过 KPM（KernelPatch Module）hook `security_compute_av_user` 等内核函数，对 app UID 来源的敏感查询返回 deny。需注意不同内核版本函数参数位置不同。

详细方法见 `references/technique-extract-2026-05.md` 第 6 节。

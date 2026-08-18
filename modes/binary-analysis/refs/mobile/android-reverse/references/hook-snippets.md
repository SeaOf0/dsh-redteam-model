# Hook Snippets 与环境探测模板

首次 Frida 操作前必读本文件。使用顺序：frida-server 预检 → 环境探测 → 选择 baseline 模板 → 注入执行。

## frida-server 预检（Frida 操作前硬步骤）

任何 `frida-ps`、spawn、attach、runner 或 Frida hook 前，必须先确认设备端 frida-server 处于活跃状态。能枚举设备或进程不等于 server 已启动——这是最常见的"Frida 连不上"根因，必须在动作前排除。

```bash
# 确认活跃进程（任一即可）
adb shell ps -A | grep frida
adb shell pidof <frida-server 进程名>
adb shell su -c 'ps -A | grep -i frida'
```

- **未启动**：先在 `/data/local/tmp/` 查找 `frida-server*`，用已有文件启动；找不到才询问用户 frida-server 路径，不要凭空假设路径。
- **版本匹配**：发现宿主 Frida 与设备端 frida-server 版本不匹配时，**只记录风险并建议用户自行更换**；禁止自行 `pip install`、创建/切换 venv、推送替换 frida-server 或改用其它版本——版本切换会引入不可控变量，归因会更困难。
- **无 hook 基线口径**：做"无 hook 基线运行测试"前也要执行本预检。若基线目标是"纯净无 Frida 环境"，发现 frida-server 正在运行时先停掉或重启设备后再测；若目标是"保留 server 但不挂 hook"，必须明确标注口径。

预检结果写入 `run/frida-env-probe.log`。spawn/attach 异常时先按 `anti-frida-playbook.md` 的"spawn/attach 异常诊断闭环"排查设备状态（锁屏/亮屏/解锁 → `adb reboot` 复测），闭环完成前不得归因到版本/端口/脚本/检测链。

## 首次 Frida 环境探测模板

首次在任务中使用 Frida 时（无论 Java 还是 Native hook），必须先用以下模板完成环境探测，而不是手动逐个查找进程/PID。将探测结果保存到 `run/frida-env-probe.log`，后续所有 Frida 操作直接复用探测结果中的 PID 和进程名。

```javascript
// frida-env-probe.js — 一次性环境探测，保存到 run/frida-env-probe.log
// 用法: frida -U -f <package> -l frida-env-probe.js --no-pause  (spawn)
//    或: frida -U <pid> -l frida-env-probe.js                      (attach)

function probeEnv() {
    var result = {};

    // === Phase 1: 基础环境 ===
    result.fridaVersion = Frida.version;
    result.platform = Process.platform;
    result.arch = Process.arch;
    result.pageSize = Process.pageSize;

    // SELinux 状态
    try {
        var selinux = File.readAllText("/sys/fs/selinux/enforce");
        result.selinuxEnforcing = selinux.trim() === "1";
    } catch (e) {
        result.selinuxEnforcing = "unknown (非 root)";
    }

    // === Phase 2: 模块枚举 ===
    result.processes = Process.enumerateModules().map(function(m) {
        return { name: m.name, base: m.base.toString(), size: m.size };
    });

    // 检查任务指定的关键 SO 是否加载（按需替换列表）
    var keySOs = ['libjiagu.so', 'libmtguard.so', 'libshell-super.2019.so',
                  'libapp.so', 'libil2cpp.so'];
    result.loadedModules = {};
    keySOs.forEach(function(name) {
        try { var m = Process.findModuleByName(name); result.loadedModules[name] = m ? { base: m.base.toString(), size: m.size } : null; }
        catch(e) { result.loadedModules[name] = 'error: ' + e; }
    });

    // 可疑匿名映射（Houdini/翻译层/内存 dump 场景）
    var namedCount = result.processes.filter(function(m) { return m.name !== ''; }).length;
    if (namedCount < result.processes.length * 0.5) {
        result.suspiciousAnon = result.processes.filter(function(m) {
            return m.name === '' && m.size > 0x10000;
        }).slice(0, 10);
    }

    // === Phase 3: Java 环境可用性 ===
    result.javaAvailable = Java.available;
    if (Java.available) {
        Java.perform(function() {
            // Android 版本（影响 hook 策略：ART 内联、deopt 需求等）
            var Build = Java.use('android.os.Build$VERSION');
            result.androidSdk = Build.SDK_INT.value;
            result.androidRelease = Build.RELEASE.value;

            // 当前 Application 类名
            try {
                var app = Java.use('android.app.ActivityThread').currentApplication();
                result.applicationClass = app.getClass().getName();
            } catch (e) {
                result.applicationClass = 'unavailable: ' + e;
            }

            // 目标类预检（替换为任务目标类）
            var targetClasses = [
                // "com.target.SignUtil",
                // "com.target.network.RequestBuilder",
            ];
            result.targetClassStatus = {};
            Java.enumerateClassLoaders({
                onMatch: function(loader) {
                    targetClasses.forEach(function(cls) {
                        if (result.targetClassStatus[cls]) return;
                        try {
                            loader.loadClass(cls);
                            result.targetClassStatus[cls] = 'loaded';
                        } catch (e) {
                            // 未在此 loader
                        }
                    });
                },
                onComplete: function() {
                    targetClasses.forEach(function(cls) {
                        if (!result.targetClassStatus[cls]) {
                            result.targetClassStatus[cls] = 'not-loaded';
                        }
                    });
                }
            });
        });
    }

    send(JSON.stringify(result, null, 2));
}
setImmediate(probeEnv);
```

**探测结果决策表**：

| 探测结果 | 建议操作 |
|----------|----------|
| Java 可用 + 目标类已加载 | attach 模式，直接 hook |
| Java 可用 + 目标类未加载 | attach 模式，先触发目标类加载（导航到对应页面）|
| Java 不可用 | spawn 模式 (`-f`)，或目标为纯 native 进程 |
| SELinux enforcing | 需要 `adb shell setenforce 0` 或使用 Magisk |
| SO 未加载 | spawn 模式或使用 dlopen 监听（见下方片段）|
| Android SDK >= 28 | 注意 AOT 编译可能影响 hook 命中，必要时 `adb shell cmd package compile -m speed -f <pkg>` |

**环境探测完成后**，在后续脚本中直接使用探测到的 PID/模块信息，不再重复探测。若进程重启导致 PID 漂移，使用 `adb shell pidof <package>:<process>` 一行命令获取新 PID，不再手动 `ps | grep`。

### SO 加载时序监听

当探测发现目标 SO 未加载时，先注入以下监听脚本，再触发目标操作：

```javascript
var TARGET_SO = "libtarget.so";  // 替换

function hookWhenLoaded(callback) {
    var mod = Module.findBaseAddress(TARGET_SO);
    if (mod) { callback(mod); return; }
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function(args) { this.path = args[0].readUtf8String(); },
        onLeave: function() {
            if (this.path && this.path.indexOf(TARGET_SO) !== -1) {
                callback(Module.findBaseAddress(TARGET_SO));
            }
        }
    });
}

hookWhenLoaded(function(base) {
    console.log("[dlopen] " + TARGET_SO + " loaded at " + base);
    // 在此添加 hook 逻辑
});
```

### 多进程场景进程选择

```javascript
// 在终端执行：frida-ps -Ua | grep <package>
// 常见多进程：主进程 + :pushservice + :webview + : PRIV
// Hook 目标一般在主进程（无冒号前缀）
// 若需 hook 多进程，对每个进程分别注入或使用 frida -U -f <pkg>:<process>
```

默认不要从空白脚本起步，优先直接改 task-local baseline：

- `run/register-natives-trace.js`: `loadLibrary`、`dlopen`、`JNI_OnLoad`、`RegisterNatives`
- `run/register-natives-trace-advanced.js`: 增强版，补 `dlsym`、`RegisterNatives` 回溯、匿名函数指针与高噪声过滤
  常用 preset：`shell_dynamic_registration`、`shell_dynamic_registration_multiprocess`
- `run/class-loader-trace.js`: `DexClassLoader`、`InMemoryDexClassLoader`、`PathClassLoader`
- `run/class-loader-trace-advanced.js`: 增强版，补 `BaseDexClassLoader`、`dexElements`、`findClass/loadClass` 观察
- `run/anti-root-bypass.js`: root 包、二进制、属性、命令探测
- `run/anti-root-bypass-advanced.js`: 增强版，补 native 文件探测、`__system_property_get`、RootBeer 定向处理
- `run/anti-frida-bypass.js`: Frida 关键词、路径、libc 字符串比较与探测路径
- `run/anti-frida-bypass-advanced.js`: 增强版，补端口扫描阻断、更多 proc/path/native 探测面
  常用 preset：`cronet_multiprocess`、`stealth_spawn_child`
- `run/integrity-bypass.js`: 本地签名/安装源/调试态/常见 Integrity facade
- `run/integrity-bypass-advanced.js`: 增强版，补类加载观察、Play Integrity / SafetyNet builder 与 boolean 强制返回位点
  常用 preset：`rootbeer_play_integrity`、`legacy_safetynet`
- `run/cert-pinning-bypass.js`: `SSLContext`、Conscrypt、OkHttp、WebView
- `run/cert-pinning-bypass-advanced.js`: 增强版，补 HttpsURLConnection、Cronet builder 与可选 native verify patch
- `run/frida-java-template.js`: Java 方法与构造器 trace baseline
- `run/frida-java-template-advanced.js`: 增强版，补 byte array 预览、thread/stack 输出、class-load watch、boolean force
- `run/frida-native-template.js`: export/symbol trace baseline
- `run/frida-native-template-advanced.js`: 增强版，补 `dlopen` / `dlsym` 观察与更强 backtrace

若目标是 `A6 / A7`，先配合 `references/a6-a7-failure-pattern-cookbook.md` 选择最像当前症状的 pattern，再改对应 baseline。
若增强版已内置 preset，先切 `ACTIVE_PRESET`，再只改剩余目标特有字段。

## 常用切入点

- `RegisterNatives`: 记录类名、方法名、签名、函数地址、模块偏移
- `DexClassLoader`: 记录 dex path、loader 链、首次命中时机
- `Cipher / MessageDigest / Signature`: 把输入、输出、调用方拆开记录
- `OkHttp / CertificatePinner`: 记录 URL、host、headers、pinning 命中点
- `SSL_write / SSL_read`: 只截短预览，先确认是否已进入 TLS 明文边界


# ART Runtime Playbook

目标：处理 `ART / OAT / odex / inline / quickening / deopt / early instrumentation / multi-process` 场景下的运行时执行偏差。

## 高风险信号

- `oat`
- `odex`
- `quickened`
- `inline cache`
- `zygote`
- `isolatedProcess`
- `remote process`

（注：Android 12+ 已移除 VDEX，编译产物直接包含在 OAT/ODEX 中；面对 Android 12+ 目标时不应再以 VDEX 作为排查入口）

## 必须回答

- 目标逻辑是否受 AOT/JIT、inline、quickening 或 hidden API 限制影响
- 关键逻辑在哪个进程触发，是否存在 `remote`、`isolated` 或守护进程
- 应优先 `spawn`、早期 attach、deopt、延迟 hook 还是静态补丁
- 当前 hook 未命中的原因是时机、进程、编译状态还是逻辑未执行

## spawn vs attach 决策树

| 场景 | 模式 | 命令示例 |
|------|------|----------|
| 冷启动 / 二启 / 首屏网络 / 启动恢复链 / Splash 后首个 Fragment | `spawn` | `frida -U -f com.target -l hook.js` |
| 反篡改/加壳在 Application.onCreate 执行 | `spawn` | `frida -U -f com.target -l hook.js` |
| 需要捕获类加载、JNI_OnLoad | `spawn` | 同上，脚本中在 `Java.perform` 内 hook |
| 目标已运行、hook 点在用户交互后触发 | `attach-name` | `frida -U com.target -l hook.js` |
| 多进程且需精确注入某子进程 | `attach-pid` | `frida -U -p <PID> -l hook.js` |

**判断流程：**
1. 目标逻辑是否在启动阶段（冷启动、二启、首屏网络、Application / ContentProvider / JNI_OnLoad）执行？→ spawn
2. 进程是否已运行且 hook 点可延迟触发？→ attach-name
3. 是否存在多进程且包名相同（如 `:webview`、`:pushservice`）？→ `frida-ps | grep com.target` 列出所有实例，attach-pid 精确命中
4. Android 12+ 注意：VDEX 已移除，OAT 直接包含编译产物；若 spawn 后立即 crash，检查 `android:extractNativeLibs=false` 与 `useEmbeddedDex` 配置

**硬性归因规则**：冷启动/二启问题中，attach 未命中不能直接解释为“逻辑未执行”。必须先记录：spawn 是否执行、目标进程/PID、脚本加载时间、首屏请求或 UI 错误出现时间。缺少这些时间证据时，hook 未命中只能标为 `inconclusive`，并用 `task-record-attempt --kind=probe --status=inconclusive` 落盘。

## deopt 策略

**何时需要 deopt：**
- hook 回调不触发，但 `Java.use` 能找到类 → 方法可能被 AOT 编译为本地代码
- `frida -l hook.js` 无报错但无输出 → inline cache 或 quickening 跳过了解释入口

**强制 deopt（Frida）：**
```javascript
// 方法级 deopt：强制解释执行
Java.deoptimizeEverything();

// 或单方法级（性能更优）
var cls = Java.use("com.target.ClassName");
cls.methodName.implementation = function () { /* ... */ };
```

### Spawn 模式完整脚本模板

```javascript
// spawn-mode-template.js — 配合 frida -U -f com.target -l spawn-mode-template.js
// 用于捕获 Application.onCreate / ContentProvider / JNI_OnLoad 阶段逻辑

Java.perform(function () {
  // 1. 延迟类加载追踪：枚举所有 ClassLoader，定位目标类
  Java.enumerateClassLoaders({
    onMatch: function (loader) {
      try {
        loader.loadClass("com.target.ClassName");
        console.log("[spawn] Found target class in loader: " + loader);
      } catch (e) {
        // 类不在此 loader 中，跳过
      }
    },
    onComplete: function () {
      console.log("[spawn] ClassLoader enumeration complete");
    }
  });

  // 2. 单方法 hook + deopt
  var TargetClass = Java.use("com.target.ClassName");
  TargetClass.criticalMethod.overload("java.lang.String").implementation = function (input) {
    var result = this.criticalMethod(input);
    console.log("[hook] criticalMethod(" + input + ") => " + result);
    return result;
  };

  console.log("[spawn] hooks installed");
});
```

### 多进程 Attach 脚本模板

```javascript
// attach-multi-process.js — 配合 frida -U -p <PID> -l attach-multi-process.js
// 用于精确注入子进程（如 :cronet, :pushservice）

console.log("[attach] process: " + Java.use("android.os.Process").myPid());

Java.perform(function () {
  // 在子进程中追踪 JNI 调用
  var Runtime = Java.use("java.lang.Runtime");
  Runtime.loadLibrary0.overload("java.lang.Class", "java.lang.String").implementation = function (cls, name) {
    console.log("[attach-native] loadLibrary0: " + name);
    return this.loadLibrary0(cls, name);
  };
});
```

**验证 deopt 成功：**
1. hook 回调是否触发 → 最直接证据
2. `Java.deoptimizeEverything()` 后重新触发 → 若命中则确认为 AOT 问题
3. 若 deopt 后仍不命中 → 问题不是编译状态，转向进程/时机排查

**deopt 风险：** 全局 deopt 会导致目标卡顿甚至 ANR，优先单方法 hook；仅在确认 AOT 干扰时使用全局 deopt。

## 多进程处理

**识别多进程：**
```bash
frida-ps -U | grep com.target
# 输出可能包含：
# com.target            (主进程)
# com.target:webview    (WebView isolated)
# com.target:pushservice (推送服务)
```

**isolated process 检测：**
- AndroidManifest.xml 中 `android:process=":xxx"` 声明
- `android:isolatedProcess="true"` → 独立 UID，常规 attach 可能权限不足
- 关键问题：目标逻辑运行在哪个进程？用 `logcat | grep <包名>` 配合日志确认

**多进程协调策略：**
1. 单进程目标 → 直接 attach
2. 主进程 + 子服务进程 → 主进程 spawn，子进程 attach-pid
3. isolated process → 检查是否可通过 ContentProvider/Broadcast 触发逻辑回主进程，避免直接 hook isolated
4. 同包名多实例 → 必须用 PID 区分，不能用包名 attach

## hook 未命中诊断

**四大原因及排查步骤：**

| 原因 | 症状 | 诊断方法 |
|------|------|----------|
| OAT/AOT 编译 | hook 静默无输出 | 执行 `Java.deoptimizeEverything()` 后重试 |
| inline/quickening | 方法能找到但回调不触发 | 单方法 deopt 或检查是否有内联调用点 |
| 错误进程 | 类找不到 / ClassNotFoundException | `frida-ps` 确认 PID，切换到正确进程 |
| 时机过早 | spawn 模式下类未加载 | 在 `Java.enumerateClassLoaders` 中延迟 hook |

**诊断流程：**
1. `Java.use("com.target.Class")` 是否成功？→ 否：类未加载或错误进程
2. `Method.overload(...).implementation = ...` 是否报错？→ 否但无回调：AOT/inline
3. deopt 后是否命中？→ 是：确认 AOT 问题；否：继续下一步
4. 手动触发目标逻辑（点击/操作），观察 logcat 是否有异常 → 排除逻辑未执行
5. 若以上都排除 → 参考 `a6-a7-failure-pattern-cookbook.md` FP-05

## 分析顺序

1. 确认进程模型、入口时机和触发路径
2. 判断是否存在编译产物、inline 或 quickening 风险
3. 选择 `spawn`、多进程 attach、deopt 或延迟 hook 策略
4. 将未命中与命中样本都落入 task-local 证据

## 最小交付

- `run/art-runtime-notes.md`
- 报告包含：进程模型（单/多/isolated）、编译状态（AOT/解释/deopt 结果）、注入时机（spawn/attach/PID）、hook 命中/未命中诊断记录、残留问题

## 联动专题

- **android-version-matrix.md**：ART 内部布局（ArtMethod 偏移、OAT/VDEX 格式、dex2oat 行为）高度依赖 Android 版本。涉及 ArtMethod 操作、OAT 分析或 VDEX 处理前，先确认目标 Android 版本对应的差异，参见 `android-version-matrix.md`
- **hook-injection**：ART hook 的底层实现（ArtMethod `entry_point` 替换、access_flags 修改）的技术细节，参见 `hook-injection-playbook.md`
- **anti-frida**：如果 hook 未命中是因为目标有 anti-frida 检测（而非 ART 编译问题），参见 `anti-frida-playbook.md`
- **dex-loader**：OAT/VDEX 文件分析与壳保护的 DEX dump 相关，参见 `dex-loader-playbook.md`

# Anti-Emulator Debug Playbook

目标：将模拟器检测与调试检测从 Root / Frida 中独立出来。

## 检测面分层

### 第一层：Java 层设备指纹

- `Build.FINGERPRINT` / `Build.MODEL` / `Build.MANUFACTURER`
- `ro.product.*` / `ro.hardware` / `ro.kernel.qemu`
- 传感器列表、电话状态、SIM、基带缺失
- `Build.ANDROID_ID` 异常值、GAID 缺失
- 屏幕分辨率与密度异常
- 电池状态（永充/无变化）、蓝牙/WiFi 扫描结果
- CPU 特性缺失（`/proc/cpuinfo` 不含预期 flags）
- `telephony` / `SubscriptionInfo` 空值

### 第二层：文件系统与硬件

- `/dev/qemu_pipe`、`/dev/goldfish_pipe`、`/dev/socket/qemud`
- `/system/bin/qemu-props`、`init.goldfish.rc`、`init.ranchu.rc`
- `/sys/class/thermal/thermal_zone*` 缺失（模拟器无温控）
- GPU 渲染器字符串含 `Emulator`；`ro.product.board` = `goldfish` / `ranchu` / `vbox86`
- 传感器仅 `accelerometer`，缺 `gyroscope` / `proximity` / `pressure`

### 第三层：特定模拟器指纹

| 模拟器 | 关键特征 |
|--------|----------|
| Bluestacks | `Build.MODEL` 含 `BST`；`/bstfolder` 存在 |
| LDPlayer | `ro.product.model` 含 `LDPlayer`；`/ldinit` 存在 |
| Nox | `ro.product.manufacturer` 含 `nox`；`libNoxStat.so` |
| MuMu | `ro.product.model` 含 `MuMu`；`ro.hardware=vbox86`（旧版）或 `nemu`（MuMu 12+） |

### 第四层：时序检测

- CPU 基准测试：执行固定运算测量耗时，模拟器结果偏离真机阈值
- `System.nanoTime` 两次间隔异常（调试器暂停拉大间隔）

### 调试检测

- `Debug.isDebuggerConnected`
- `android:debuggable` 标志
- `/proc/self/status` TracerPid != 0
- `ptrace(PTRACE_TRACEME)` 自附加占用
- 信号 handler 检测 SIGTRAP / SIGILL（单步执行特征）

## 绕过策略

### 属性伪装

```javascript
Java.perform(() => {
  const SP = Java.use("android.os.SystemProperties");
  SP.get.overload("java.lang.String").implementation = function(key) {
    if (key === "ro.hardware") return "qcom";
    if (key === "ro.kernel.qemu") return "0";
    if (key === "ro.product.model") return "Pixel 6";
    if (key === "ro.product.manufacturer") return "Google";
    return this.get(key);
  };
});
// Native 层同步 hook __system_property_get，返回相同伪装值
```

### 文件系统拦截

```javascript
// Android 文件操作主要通过 openat 系统调用，而非 open
Interceptor.attach(Module.findExportByName(null, "openat"), {
  onEnter(args) {
    const p = args[1].readUtf8String();
    if (p && /qemu|goldfish|nox|bstfolder|ldinit/.test(p))
      args[1] = Memory.allocUtf8String("/dev/null");
  }
});
```

### 调试检测绕过

| 方法 | 绕过 |
|------|------|
| TracerPid 多线程枚举 | hook `/proc/self/task/*/status` 读取，`TracerPid` 行返回 `0` |
| ptrace 自附加 | hook `ptrace`：`PTRACE_TRACEME` 时返回 `-1` 使自附加失败，解除调试器锁定（`onLeave` 中 `retval.replace(-1)`）；或直接 NOP 调用 |
| 时间差检测 | hook `System.nanoTime` / `elapsedRealtimeNanos` 返回单调递增值 |
| 信号 handler | hook `sigaction` 拦截 SIGTRAP/SIGILL 自定义 handler 注册 |

## 绕过顺序

1. 属性伪装 + 文件拦截（消除模拟器指纹）
2. TracerPid 清零 + ptrace 绕过（解除调试检测）
3. 时间与信号绕过（处理深层反调试）
4. 最后才考虑静态 patch

## 替代方案

- **Custom ROM / 云真机**：从根源消除模拟器特征，绕过全部本地检测
- **Play Integrity DEVICE 级别**：部分应用仅检查 Play Integrity verdict，用真实设备 + 代理即可，无需逐项绕过
- **树莓派 / ARM 板**：物理 ARM 设备运行 Android，无模拟器特征

## 最小交付

- `run/anti-emulator-bypass.js` — 属性伪装 + 文件拦截 + TracerPid 清零 + ptrace 绕过
- 报告：检测面清单、触发时机（启动 / 定时 / 关键操作前）、每项绕过状态

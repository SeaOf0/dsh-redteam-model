# Frida Native Playbook

目标：围绕 JNI 桥、关键 RVA、关键导出符号做低侵入 Native 取证。

## 推荐目标

- `JNI_OnLoad`
- `RegisterNatives`
- `Java_*`
- 关键 RVA
- `SSL_write / SSL_read`
- `open / read / access / ptrace / strstr`

## 核心 API 模式

基本导出符号 hook 参考 `run/frida-native-template.js` baseline。以下场景是 baseline 未覆盖但常见需求：

### 偏移地址 hook（stripped symbols）

当 SO 被 strip 后没有导出符号名，使用基址 + 偏移：

```javascript
var mod = Module.findBaseAddress("libtarget.so");
if (mod) {
  var target = mod.add(0x1234);  // RVA from IDA/Ghidra
  Interceptor.attach(target, {
    onEnter: function (args) {
      console.log("hooked at offset 0x1234 arg0=" + args[0]);
    }
  });
}
```

RVA 来源：IDA 默认以 0 为基址时函数地址即 RVA；若 IDA 设定了非零 imagebase（如 0x100000），则 RVA = 函数地址 - imagebase。Ghidra 中 Listing 窗口直接显示的地址通常就是 RVA。

### ARM64 参数读取

ARM64 调用约定下前 8 个参数在 x0-x7 寄存器，返回值在 x0。注意：`args[N]` 是 `NativePointer`，没有类型信息，使用前需要通过 IDA/Ghidra 确认函数签名中各参数的类型和含义：

```javascript
onEnter: function (args) {
  // args[0]-args[7] 对应 x0-x7
  // 读取字符串
  var str = Memory.readCString(args[0]);
  // 读取 buffer
  var buf = Memory.readByteArray(args[0], args[1].toInt32());
  console.log(hexdump(buf, { length: args[1].toInt32() }));
}
```

### 动态库加载观察

```javascript
Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
  onEnter: function (args) { this.path = Memory.readCString(args[0]); },
  onLeave: function () {
    if (this.path && this.path.indexOf("libtarget") !== -1) {
      console.log("target SO loaded: " + this.path);
      // 此时可以 hook SO 内函数
    }
  }
});
```

在 SO 的 `dlopen` 回调中 hook 其内部函数，避免 SO 尚未加载就尝试 hook 的时序问题。

## 记录要求

- 模块名
- 函数地址或导出符号
- 入参样本
- 缓冲区样本
- 返回值

## Stalker 内部原理

Frida Stalker 的工作机制：
- **基本块级 copy-and-instrument**：将原始代码复制到新内存区域，在副本上添加插桩
- **trust_threshold**：控制基本块缓存复用
  - 0 = 不缓存，每次重新编译
  - 高值 = 更积极缓存已编译块
- **执行副本**：实际执行的是复制后的代码，原始代码不被修改
- **检测风险**：内存比较型检测可以发现执行地址不在原始代码段

```javascript
// Stalker 使用示例
Stalker.follow(Process.getCurrentThreadId(), {
  transform: function(iterator) {
    var instruction;
    while ((instruction = iterator.next()) !== null) {
      iterator.putCallout(function(context) {
        // 在每条指令执行前回调
      });
      iterator.keep();
    }
  }
});
```

### Snapshot 对比

使用 Stalker 进行 snapshot 对比检测被修改的代码：
1. 启动前对目标代码区域做 snapshot
2. Stalker 执行后对比 snapshot
3. 找出被运行时修改的位置

## 硬件断点 API（Frida 16.5+）

硬件断点不修改目标代码，适用于高对抗场景：

```javascript
// 设置异常处理器（Frida 16+ 支持）
Process.setExceptionHandler(function(details) {
  if (details.type === 'access-violation' || details.type === 'breakpoint') {
    console.log("HW breakpoint hit at: " + details.address);
    console.log("Context: " + JSON.stringify(details.context));
    return true; // 处理异常，继续执行
  }
  return false;
});
```

注意：`MemoryAccessMonitor` 在 Frida 16+ 已被移除。替代方案：
- 使用 `Process.setExceptionHandler` 捕获硬件断点异常
- 结合 `Memory.scan` 做事后扫描而非实时监控
- 在高对抗场景使用 `Interceptor.replace` 替代 `Interceptor.attach` 减少检测面

优势：
- 不修改任何代码——无 inline hook 痕迹
- 不被简单的代码完整性校验检测
- 适合定位检测点

## Trace-based 检测点发现

### 二分法定位

当不确定哪个函数触发检测时，使用二分法：
1. 注入所有 hook → 正常运行
2. 移除一半 hook → 如果触发检测，问题在移除的一半
3. 继续二分直到定位到具体函数
4. 对该函数进一步分析检测逻辑

### Frida Trace

```javascript
// 使用 Frida 的 trace 功能批量追踪函数调用
// 对可疑模块的所有导出函数设置 trace
var module = Process.findModuleByName("libtarget.so");
module.enumerateExports().forEach(function(exp) {
  if (exp.type === 'function') {
    try {
      Interceptor.attach(exp.address, {
        onEnter: function(args) {
          console.log("CALL: " + exp.name);
        }
      });
    } catch(e) {}
  }
});
```

## 内存扫描模式

用于反检测场景的内存扫描：

```javascript
// 扫描特定模式
var pattern = "frida"; // 搜索特征字符串
Memory.scan(Module.findBaseAddress("libtarget.so"), 
  Process.findModuleByName("libtarget.so").size,
  pattern,
  {
    onMatch: function(address, size) {
      console.log("Found at: " + address);
    },
    onComplete: function() {
      console.log("Scan complete");
    }
  }
);

// 扫描 RWX 页（Frida 特征）
Process.enumerateRanges('rwx').forEach(function(range) {
  console.log("RWX range: " + range.base + " size=" + range.size);
});
```

## Frida 源码编译与去特征

当目标检测 Frida 特征（端口扫描、maps 字符串、线程名等）导致常规 frida-server 无法使用时，需要从源码编译魔改版本。

### 编译方案选择

| 方案 | 仓库 | 适用场景 | 构建复杂度 |
|------|------|---------|-----------|
| rusda (taisuii) | `github.com/taisuii/rusda` | 全特征替换，lief 二进制修补 | 中 — 需 Python lief |
| ajeossida (hackcatml) | `github.com/hackcatml/ajeossida` | 自动化程度高，批量字符串替换 | 低 — 一键脚本 |

### 编译关键步骤（以 rusda 为例）

```bash
git clone --recurse-submodules -b 16.2.1 https://github.com/frida/frida
cd frida
# 需要: Node.js 22, NDK r25c, build-essential, lib32stdc++-9-dev, pip3 install lief
make core-android-arm64
# 验证 patch 生效: make core-android-arm64 | grep Patch
# 产物: build/frida-android-arm64/bin/frida-server
```

ajeossida 方案：先构建一次 vanilla 版本（必须），再运行 `python3 main_ubuntu_android.py`，设置 `CUSTOM_NAME = "fyrrida"`。

### 必须替换的指纹清单

| 原始特征 | 替换目标 | 检测方式 |
|---------|---------|---------|
| `frida` (全局字符串) | 自定义名 (如 `rusda`) | maps/内存扫描 |
| `frida_agent_main` (入口) | `main` | 符号表扫描 |
| `FridaScriptEngine` | 反转字符串 | .rodata 搜索 |
| `GLib-GIO` / `GDBusProxy` / `GumScript` | 反转或自定义 | .rodata 搜索 |
| `gum-js-loop` (线程名) | 自定义名 | `/proc/self/task/*/comm` |
| `gmain` / `gdbus` (线程名) | 自定义名 | pthread_getname_np |
| 默认端口 27042 | 自定义 (如 14725) | 端口扫描 |

部署时使用非默认端口：`./frida-server -l 0.0.0.0:14725`，连接：`frida -H 127.0.0.1:14725 -f <pkg>`

### 常见编译陷阱

- lief patch 脚本必须实际执行——用 `grep Patch` 验证输出
- ajeossida 必须先构建 vanilla，否则 patch 构建失败
- 构建失败时删 `build/` + `deps/` 重来
- `--depth 1` 克隆节省时间和空间

## Unidbg + Capstone + Keystone 离线分析

在无法使用 Frida 的场景下，使用 Unidbg 模拟执行 + 反汇编器离线分析：

1. 在 Unidbg 中加载 SO 并模拟执行目标函数
2. 使用 Unicorn hook 记录执行路径
3. 使用 Capstone 反汇编执行过的指令
4. 使用 Keystone 汇编修改后的指令
5. 在 Unidbg 中验证修改效果

适用于：
- 目标有强反 Frida 检测
- 需要在不连接设备的情况下分析
- 需要精确控制执行环境

## 常见偏差

- hook stripped SO 时使用了符号名而非偏移地址——需要先用 IDA/Ghidra 确认 RVA
- SO 尚未加载就尝试 hook——需要在 `dlopen` 回调中延迟 hook
- 读取 buffer 时没有先检查指针是否为 null——加入 `ptr.isNull()` 检查
- 多线程环境下 hook 输出交错——在 `onEnter` 中记录 `Process.getCurrentThreadId()`

## 最小交付

- `run/frida-native-template.js`
- 至少一条成功运行的 Native hook 证据


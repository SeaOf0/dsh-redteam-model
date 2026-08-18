# Hook Injection Playbook

目标：理解 Hook 和注入的底层原理，选择正确的注入方式，而不是只会调用 Frida API。

## 先回答

- 当前需要 Hook 的是 Java 方法还是 Native 函数
- 目标是否有反注入/反 Hook 检测
- 注入窗口是什么时机（spawn / attach / zygote）
- 需要什么级别的隐蔽性（标准注入 / 无痕注入 / 内核级）

## 高风险信号

- `ptrace` 被拦截
- `dlopen` 被监控
- `/proc/self/maps` 被检查
- Frida 特征被检测（端口、线程名、内存特征）
- SO 完整性校验
- SELinux 强制模式
- 多进程架构（主进程 + 守护进程 + 服务进程）

**升级信号（A6+ 目标）**：当上述信号同时出现 ≥3 项，且用户态工具（Frida/Xposed/Zygisk/Dobby）逐一被系统性拦截（不是配置错误），应停止在用户态纠缠，落 detection-evidence 后升级到 `stealth-hook` topic——详见 [stealth-hook-playbook.md](./stealth-hook-playbook.md) §先回答。

## 注入方法对比

| 方法 | 原理 | 隐蔽性 | 适用场景 |
|---|---|---|---|
| ptrace attach | 调试器附加 | 低 | 通用，但最易被检测 |
| Frida spawn | 进程创建时注入 | 中 | 需要早期 hook 时 |
| Frida attach | 运行中注入 | 中 | 通用场景 |
| Frida Zymbiote | ArtMethod patch | 高 | Frida 17.6+，无 ptrace |
| Zygisk | Zygote 注入 | 高 | Root + Magisk 环境 |
| PLT Hook | GOT 表替换 | 中 | 特定 SO 函数 hook |
| Inline Hook | 指令修改 | 中 | 特定地址 hook |
| LD_PRELOAD | 动态链接器预加载 | 低 | 简单函数替换 |
| Gadget 注入 | 修改 APK 嵌入 Frida | 高 | 无 Root 场景 |

## 操作顺序

### 1. 选择注入方式

决策树：
1. 目标有反 Frida 检测 → 考虑 Zymbiote 或修改版 Frida
2. 需要 Hook 启动早期代码 → spawn 模式
3. 目标是多进程 → Zygisk 或逐进程 attach
4. 无 Root → Gadget 嵌入或 fripack
5. 只需 Hook 特定 SO 函数 → PLT/GOT Hook（Dobby/bhook）

### 2. Java Hook 原理（ArtMethod 修改）

Android ART 运行时中，Java 方法调用通过 ArtMethod 结构体：
- ArtMethod.entry_point_from_jni_：JNI 方法入口
- ArtMethod.entry_point_from_quick_compiled_code_：OAT 编译代码入口
- ArtMethod.data_：方法数据

Hook 流程（8 步）：
1. 找到目标方法的 ArtMethod 指针
2. 将方法设置为 native（修改访问标志）
3. 保存原始 entry_point
4. 创建 bridge 函数（跳板）
5. 设置新的 native entry_point 为 bridge 函数
6. bridge 函数中获取调用参数
7. 调用原始方法获取返回值
8. 返回修改后的结果

Frida 内部实现与此类似，但封装了更多细节（JNI bridge、参数解析、GC 安全等）。

### 3. PLT/GOT Hook 原理

ELF 动态链接中，外部函数调用通过 PLT（过程链接表）跳转到 GOT（全局偏移表）中的地址：
1. 解析 ELF 头获取 PHT（程序头表）
2. 找到 PT_DYNAMIC 段
3. 遍历动态段获取 GOT 表位置
4. 找到目标函数在 GOT 中的条目
5. 保存原始地址
6. 将 GOT 条目修改为 hook 函数地址
7. hook 函数中可选择调用原始函数

工具：
- **Dobby**：支持 ARM/ARM64/x86 的 inline hook 框架
- **bhook**：字节跳动开源的 PLT hook 框架
- **xHook**：爱奇艺开源的 PLT hook 框架

### 4. Inline Hook 原理（ARM64）

ARM64 指令固定 4 字节，hook 需要至少覆盖 4 条指令（16 字节）：

1. **保存原始指令**：备份目标地址处的 4 条指令
2. **写入跳转**：将前 4 条指令替换为跳转到 hook 函数的指令
   - 短跳转：`B` 指令（±128MB 范围）
   - 长跳转：`LDR X16, #8; BR X16; .quad target_addr`（16 字节）
3. **构建 trampoline**：
   - 执行保存的原始指令
   - 跳转回原函数被覆盖指令之后的位置
4. **调用原始函数**：跳转到 trampoline

寄存器保存：
- ARM64 调用约定中 x0-x7 是参数寄存器
- x29 (FP)、x30 (LR) 需要保存
- NEON 寄存器 q0-q7 用于浮点参数
- hook 函数中需要保存/恢复所有可能被修改的寄存器

### 5. Frida Zymbiote 注入（17.6+）

架构变化：
- **不再依赖 ptrace 注入 Zygote**：通过 ArtMethod patching 在目标进程 fork 后修改 Java 方法入口
- **短生命周期 payload**：注入完成后 payload 退出，只留下修改
- 注意：目标进程 attach 后运行脚本时 frida-agent 仍会出现在 `/proc/self/maps`——Zymbiote 解决的是 Zygote 阶段注入检测，不是运行时 maps 隐蔽

使用场景：
- 目标检测传统 Frida 注入特征（详见 `references/anti-frida-playbook.md`）
- 需要高隐蔽性 Java 层 hook
- 需要在 attach 后立即生效

限制：
- 主要针对 Java 层 hook
- Native hook 仍使用传统方式
- 需要最新版 Frida（17.6+）

### 6. Spawn 模式注入实现

Spawn 模式在进程创建时就注入：
1. `frida -U -f com.target.app` 启动应用
2. Frida 通过 `am start` 创建进程
3. 在 `Application.onCreate()` 前注入
4. 可以 hook 所有初始化阶段的代码

适用场景：
- 需要 hook `Application.onCreate()`
- 需要 hook `ContentProvider.onCreate()`
- 需要 hook `JNI_OnLoad`
- 需要 hook 早期反检测

### 7. SO 注入与 Zygisk 模块开发

#### SO 注入

通过 ptrace 或 Zygisk 注入自定义 SO：
1. 编写 SO（包含 `constructor` 或 `JNI_OnLoad`）
2. 通过 ptrace 调用 `dlopen` 加载 SO
3. 或通过 Zygisk 自动注入

#### Zygisk 模块

1. 创建模块目录结构
2. 实现 `zygisk_module_entry` 入口
3. 在 `onLoad` / `onPreload` / `onServerSpecialize` / `onAppSpecialize` 中处理
4. 可以在所有应用启动前注入

### 8. 替代框架

- **Albatross**：指令级 hook，不修改原始指令，通过异常处理机制实现
- **Dobby**：轻量级 inline hook 框架，支持 ARM/ARM64/x86/x64
- **bhook**：字节跳动 PLT hook 框架，高性能
- **And64InlineHook**：ARM64 inline hook 库

### 9. SVC Hook 和 eBPF 拦截

#### SVC Hook
- 拦截系统调用入口（`svc #0` 指令）
- 在内核层面过滤和修改系统调用
- 工具：Abyss、svc_hook、eDBG
- 可以绕过用户态的所有检测

#### eBPF 拦截
- 使用 Linux eBPF 在内核中拦截系统调用
- 需要 Root 权限和内核支持
- 可以在不修改用户态代码的情况下拦截和修改系统调用行为

### 10. 反检测注入策略

1. **特征消除**：修改 Frida 特征（线程名、端口、SO 路径）
2. **注入时机**：在目标检测启动前完成注入
3. **注入方式**：选择不触发检测的注入方式（Zymbiote > Zygisk > ptrace）
4. **持久化**：使用 fripack 嵌入 gadget，避免进程间注入

## Frida 内部架构（理解检测原理的必要知识）

### 三大组件

| 组件 | 语言 | 运行位置 | 职责 |
|------|------|----------|------|
| frida-server | Vala | 设备端守护进程（USB/TCP） | 管理设备连接、进程枚举、agent 注入 |
| frida-agent | Vala/C/JS | 目标进程内 | 执行 JS 脚本、提供 Interceptor/Java/Native API |
| frida-gadget | C | 嵌入 APK 的 .so | 无 Root 场景替代 server，应用启动时自动加载 |

### 注入链路（attach 模式）

```
frida CLI → frida-server (USB) → ptrace attach → /proc/$pid/mem 写入 loader
→ loader dlopen frida-agent.so → agent 启动 V8/QuickJS 运行时
→ 加载用户 JS 脚本 → 执行 hook 注册
```

### Java Hook 底层流程（frida-java-bridge）

`Java.use("class").method.implementation = fn` 的完整调用链：

1. `implementation.set(fn)` — JS 层入口
2. `implement(wrapper)` — 创建 JS→Native 桥接
3. `makeMethodImplementation()` — 构造 NativeCallback 包装 JS hook 函数
4. `handleMethodInvocation()` — 注册到 method mangler
5. `methodMangler.replace(method, newEntry)` — 执行 ArtMethod 替换
6. 目标 ArtMethod 的 `data_` 字段被替换为指向 NativeCallback 的 native entry
7. `access_flags` 被修改为 `kAccNative | kAccFastInterpreterToInterpreterInvoke`
8. 后续所有对该 Java 方法的调用都经过 Frida 的 NativeCallback 桥接

关键检测面：步骤 6-7 修改了 ArtMethod 内存，可被完整性校验发现。

### Native Hook 底层流程（frida-gum Interceptor）

`Interceptor.attach(target, { onEnter, onLeave })` 的完整调用链：

1. `gumjs_interceptor_attach()` — JS→C 绑定入口
2. `gum_interceptor_attach()` — 分配 listener 和 trampoline
3. 替换目标函数入口指令为跳转到 Frida trampoline
4. trampoline 保存寄存器上下文 → 调用 `onEnter` listener → 恢复执行原始指令 → 跳回原函数
5. 原函数返回时经过 `onLeave` trampoline

ARM64 trampoline 格式（Frida 使用 X17 或 X16 作为间接跳转寄存器）：
- 入口跳转：`LDR Xn, [PC, #8]; BR Xn; .quad hook_addr`（16 字节）
- 原始指令被搬迁到 trampoline 的 "slab" 区域

关键检测面：入口 4-16 字节被修改，可被 inline hook 自检发现。

### Zymbiote 注入链路（Frida 17.6+）

```
frida CLI → frida-server → enable_spawn_gating → inject_zymbiote
→ Zygote fork 子进程 → /proc/$pid/mem 写入微型 loader → Java 运行时调用触发（如 setArgV0Native）
→ loader 执行后立即回滚（短生命周期）
→ 后续 attach 时 frida-agent 仍常规注入目标进程
```

与 ptrace 模式的区别：Zymbiote 不 ptrace Zygote，不向 Zygote 注入 agent。但目标进程 attach 后 agent 仍存在。

### Stalker 内部机制

- 基本块级 copy-and-instrument：将原始代码复制到新内存（slab），在副本上添加插桩
- `trust_threshold` 控制缓存：0=不缓存（每次重新编译），高值=积极缓存
- **不修改原始指令**——执行的是副本，但执行地址在 slab 区域
- 可被内存比较型检测发现（PC 寄存器指向的地址不在原始代码段内）

## 常见偏差

- 只会使用 Frida 而不了解底层原理——遇到 Frida 检测就束手无策
- 所有场景都用同一种注入方式——应该根据目标保护等级选择策略
- 忽略 SELinux 对注入的影响——某些注入方式在 SELinux enforcing 下无法工作
- Inline Hook 不处理 PC 相对指令——ARM64 的 ADRP/ADR/LDR literal 需要重定位
- 不考虑多进程架构——主进程注入成功但服务进程未注入

## 最小交付

- `run/hook-injection-notes.md`
- 选择的注入方式及原因
- Hook 点列表和 hook 代码
- 注入成功验证证据

## 联动专题

- **android-version-matrix.md**：ArtMethod 字段偏移、SELinux 策略、hidden API 限制均随 Android 版本变化。涉及 ArtMethod 操作或 ptrace 注入前，先确认版本差异，参见 `android-version-matrix.md`
- **anti-frida**：注入后如果被检测（inline hook 自检、maps 扫描等），参见 `anti-frida-playbook.md` 的 L4-L5 层检测矩阵
- **anti-root**：注入依赖 root 环境，如果 root 被检测导致注入失败，参见 `anti-root-playbook.md`
- **stealth-hook**：用户态注入被 A6+ 目标系统性拦截（CRC 校验 + maps 监控 + ptrace 探测 + ArtMethod 指针漫游）时，升级到内核无痕 hook——参见 `stealth-hook-playbook.md` 与 `stealth-hook-vs-traditional-matrix.md`

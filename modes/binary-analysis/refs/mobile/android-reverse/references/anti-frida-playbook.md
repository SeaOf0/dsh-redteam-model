# Anti-Frida Playbook

目标：把 `anti-frida` 当作分阶段、分层级对抗来拆，不把单点字符串 patch 误判为完整 bypass。

## Frida 不可行时的退出策略

**不要在 Frida 绕过上无限投入**。当遇到以下情况时，应立即切换到替代方案：

**退出条件**（满足任一即触发）：
- A4+ 壳 + 模拟器环境 → 直接退出，改用专用脱壳工具
- 连续 2 次不同 Frida 脚本都因检测被杀（不是脚本 bug）
- 壳的检测层级 >= L4（内存模式/ArtMethod/SVC 级检测）

**替代方案优先级**：
1. **专用脱壳工具**：eBPFDexDumper / BlackDex / FART，不依赖 Frida（参见 `unpack-tool-matrix.md`）
2. **Smali Patch**：直接修改 APK 去除检测逻辑（不依赖运行时 hook）
3. **LSPosed 模块**：基于 Xposed 的 hook 比 Frida 更难被检测
4. **真机环境**：部分检测在模拟器上才触发，真机上可直接绕过
5. **Kernel-assisted**：eBPF / PTE hook / 硬件断点（参见 kernel-assisted-re）

**禁止在 Frida 绕过上超过 3 轮尝试**（A4+ 壳 + 模拟器最多 1 轮）。超限后必须 pivot 到上述替代方案。

## 先回答三件事

- 命中发生在 `attach 前 / 冷启动早期 / 功能点击后 / 发包前`
- 检测位于 `Java / JNI / Native syscall / 远端联动`
- 当前失败现象是 `闪退 / 退出 / 卡死 / 禁用功能 / 服务端风控`

## 常见检测面

### Java / App 层

- 进程名 / 线程名
- 包名、类名、堆栈、异常信息
- `frida` / `gum-js` / `linjector` 字符串
- 文件存在性检查
- 调试状态、类加载异常、反射结果

### Native / libc 层

- `ptrace`
- `open / openat / access / stat / fopen`
- `readlink`
- `/proc/self/maps`
- `/proc/self/status`
- `/proc/self/task/*/comm`
- `strstr / strcmp / memcmp`
- 端口扫描、socket connect、loopback 探测

### 高级组合面

- 多阶段检测：启动先查进程，发包前再查 maps / 端口
- Java 判定 + Native 二次确认
- 完整性 / root / anti-debug 与 anti-frida 联动

## spawn/attach 异常诊断闭环（先于检测绕过）

Frida spawn、spawn-gating、attach 或早期注入出现卡住、`closed`、server 不可用、启动后立刻断开、目标未起或只剩 server 可见时，**必须先按以下顺序排查设备状态**，再判断是否进入检测绕过 SOP。这一步是检测绕过的前置——大量"看似被检测"的失败其实是设备锁屏、frida-server 未起或版本不匹配。

**为什么强调顺序**：在未排除设备状态问题时，把失败归因到 anti-Frida 检测链会误导整个分析方向，叠加的 hook/patch 也会掩盖真正的根因，最终在同一路径上反复失败。

1. **frida-server 活跃确认**：任何 `frida-ps`/spawn/attach 前用 `adb shell ps -A | grep frida`、`adb shell pidof <frida-server 进程名>` 或 `adb shell su -c 'ps -A | grep -i frida'` 确认活跃进程。能枚举设备/进程不等于 server 已启动。
   - 未启动：先在 `/data/local/tmp/` 查找 `frida-server*`，用已有文件启动；找不到才询问用户路径。
   - 版本不匹配：发现宿主 Frida 与设备端 frida-server 版本不匹配时，**只记录风险并建议用户自行更换**；禁止自行 `pip install`、创建/切换 venv、推送替换 frida-server 或改用其它版本（会引入不可控变量）。
2. **锁屏/亮屏/解锁检查**：设备熄屏/锁屏会让 spawn 卡住或目标不启动。先 `adb shell input keyevent KEYCODE_WAKEUP` 唤醒并解锁后用同一最小命令复测。
3. **`adb reboot` 复测**：唤醒解锁后仍异常，`adb reboot`，等设备恢复、确认解锁、重启 frida-server，再用同一最小命令复测。
4. **复测仍失败才进入检测绕过 SOP**：闭环完成前，不得把失败结论写成版本不匹配、端口暴露、脚本错误或目标检测已确认，也不得继续扩大 hook 面。

复测命令、结果和判断写入 `run/frida-env-probe.log` 或 `run/anti-frida-bypass.js` 的头部注释。

## 分阶段 SOP

### 1. 先锁定触发窗口

按下面顺序定位：

1. 冷启动即崩或闪退：
   优先 `spawn`、`Application`、`ContentProvider`、`JNI_OnLoad`
2. 首页正常，点功能后触发：
   先找该功能前的 Java / Native 汇合判定点
3. 本地看似正常，但发包失败：
   检查 anti-frida 是否作为风控字段写入请求或 attestation 链

### 2. 先收敛失败信号

至少保留一项：

- logcat
- hook 到的异常分支
- toast / 对话框 / 错误码
- 服务端拒绝样本

没有失败信号时，不要盲 patch。

### 3. 先做低成本 Java 绕过

优先处理：

- 文件存在性查询
- 可疑字符串搜索
- 调试状态、线程名、类名判断
- 统一布尔判定函数

如果 Java 层只负责分发，立即转 Native。

### 4. Native 层按“检测原语”拆

优先级通常是：

1. `ptrace`
2. `open / openat / access / stat / fopen`
3. `readlink`
4. `strstr / strcmp / memcmp`
5. `connect` 本地端口扫描

记录时至少写清：

- 模块
- 符号或地址
- 入参
- 目标路径 / 字符串 / 端口
- 返回值

### 5. 多阶段 anti-frida 必须分层交付

不要把所有逻辑塞进一个临时脚本后就结束。
至少区分：

- 启动前置绕过
- 功能前置绕过
- 发包前二次校验绕过

如果后两层仍存在，应在 `run/anti-frida-bypass.js` 中写清分阶段注入点和未解层。

## 常见 A5-A7 场景

### maps / 线程名 / 端口组合检测

- 单独 patch `strstr("frida")` 往往不够
- 需要同时覆盖 `/proc` 文件访问、线程枚举和 socket 探测

### JNI 包装后的 Native 检测

- 先回到 Java 调用入口
- 确认是否由 JNI 聚合多个检测结果
- 找“最终 verdict”优先于逐个 syscall patch

### 壳或动态加载后的二次检测

- 首次绕过成功不代表后续 feature dex / SO 没有再检测
- 命中 `DexClassLoader / dlopen` 后，要重新审视注入窗口

## Frida 编译与定制

### 从源码编译

1. 克隆 Frida 仓库并安装依赖
2. 修改特征字符串：将 `frida`、`gum-js`、`linjector` 替换为自定义名称
3. 修改默认端口（27042）为非标准端口
4. 编译生成修改版 frida-server

### 现成修改版

- **rusda**：基于 Frida 源码的魔改补丁集，通过替换特征字符串、符号前缀和线程名来减少检测面
- **fyrlove 魔改版**：看雪社区 fyrlove 维护的 Frida 编译魔改方案，基于 fyrrida-server 绕过特定壳检测
- **fripack**：将 Frida gadget 嵌入 APK，无 Root 使用

### 通用单点修改

最简单的修改——重新命名 Frida agent SO 使特征字符串检测失效：
```javascript
// 在运行 frida-server 前，修改二进制中的特征字符串
// 例如将 "frida" 替换为 "xxxxx"（等长替换保持偏移不变）
// sed -i 's/frida/xxxxx/g' frida-server
// 同时替换 "gum-js-loop" "linjector" 等特征字符串
```

## Zymbiote 注入（Frida 17.6+）

Frida 17.6 引入了新的注入架构，从根本上改变了注入阶段的检测面对抗关系。本节从 anti-frida 视角分析 Zymbiote 的收益、局限和新检测面。Zymbiote 的内部注入链路和技术实现细节见 `hook-injection-playbook.md`。

### 核心架构变化（检测视角）

| 阶段 | 传统 Frida | Zymbiote | 检测影响 |
|------|-----------|----------|----------|
| Zygote 注入 | ptrace attach Zygote → 注入 frida-agent.so | 不 ptrace Zygote，不注入 agent | 消除 Zygote 被污染的检测面 |
| 目标进程注入 | fork 后从 Zygote 继承 frida-agent | fork 后通过 `/proc/$pid/mem` 写入微型 loader | loader 生命周期短（毫秒级），但写入行为仍可被监控 |
| Hook 注册 | frida-agent 常驻进程 | loader 触发 ArtMethod patch 后立即退出 | Zygote 阶段无痕迹，但 ArtMethod 修改本身是新检测面 |
| 运行时 | frida-agent 在 maps 中可见 | attach 后 frida-agent **仍然出现**在 maps 中 | **Zymbiote 不解决运行时 maps 隐蔽问题** |

### Zymbiote 对 7 层检测矩阵的影响

Zymbiote 改变了各层的绕过优先级。以下标注 Zymbiote 单独能解决的层、需要配合的层、和不涉及的层：

| 层 | Zymbiote 单独效果 | 需要配合 | 说明 |
|----|-------------------|----------|------|
| L1 字符串/文件 | **部分解决** | 魔改 Frida | Zygote 阶段无特征，但 attach 后 agent 仍可被 maps 扫描和线程枚举发现 |
| L2 协议指纹 | **显著改善** | 无 | spawn 阶段无端口监听、无 D-Bus/WebSocket 握手；但 attach 后 frida-server 端口仍可被探测 |
| L3 端口绑定 | **显著改善** | 无 | spawn 阶段无独立 frida-server 进程绑定端口 |
| L4 内存模式 | **不解决** | 魔改 Frida + 内存清理 | ArtMethod patch 本身产生 inline hook 签名；attach 后 Stalker/trampoline 仍产生 RWX 页 |
| L5 ArtMethod 完整性 | **加剧问题** | ArtMethod 直写 / 硬件断点 | Zymbiote 通过替换 ArtMethod 的 `entry_point`（函数指针）工作，检测方可遍历关键方法的 `entry_point` 与已知合法地址比较 |
| L6 信号/异常 | **改善** | spawn 时机控制 | 不依赖 ptrace，消除了 TracerPid 检测面 |
| L7 时序侧信道 | **不解决** | 内核级能力 | Zymbiote 的 loader 写入和 ArtMethod patch 仍产生可测量的时序差异 |

### Zymbiote 引入的新检测面

Zymbiote 消除了传统 Frida 的部分检测面，但引入了新的可检测点：

1. **ArtMethod entry_point 替换残留**：Zymbiote 通过替换目标进程 ArtMethod 的 `entry_point`（函数指针）实现 Java hook，不修改 `data_` 或 `access_flags`。检测方可以遍历关键方法的 `entry_point` 字段，与已知合法编译代码地址比较，发现被替换的入口。这与 L5 检测重叠但目标字段不同——标准 Frida Java Hook 修改 `data_`（arm64 偏移 24），Zymbiote 修改 `entry_point`（arm64 偏移 32），两者需要不同的校验策略。

2. **`/proc/$pid/mem` pwrite 痕迹**：Zymbiote 在 fork 后通过 `pwrite()` 系统调用向 `/proc/$pid/mem` 写入 loader（约 920 字节 shellcode），写入位置是 `libstagefright.so` 可执行映射的末尾页。如果检测方安装 `seccomp-BPF` 过滤对 `/proc/self/mem` 的 `pwrite64` 系统调用，或检查 `libstagefright.so` 末尾页的代码完整性，仍可捕获。

3. **`setArgV0Native` 触发点**：Zymbiote 利用 ART 内部的 `setArgV0Native` 作为 loader 执行触发点。部分壳/保护方案会监控此函数是否被外部调用。

4. **attach 阶段不隐蔽**：这是最常见的误解。Zymbiote 只在 spawn/Zygote 阶段隐蔽。目标进程 attach 后注入 frida-agent 运行用户脚本时，agent 仍然出现在 `/proc/self/maps`、线程列表、fd 表中。如果目标在运行时（而非启动时）执行检测，Zymbiote 提供零收益。

5. **Abstract Unix Socket 通信**：Zymbiote 的 loader 通过 abstract Unix socket（名称格式 `/frida-zymbiote-<UUID>`）与 frida-server 通信。检测方可以枚举 `/proc/net/unix` 中的 abstract socket，匹配 `frida` 或 `zymbiote` 关键词。

6. **Boot heap 内存搜索模式**：Zymbiote 搜索 `boot.art`、`boot-framework.art` 和 `dalvik-LinearAlloc` 内存区域定位目标 ArtMethod slot。这种跨区域内存扫描行为本身可以被监控（如通过 `InMemoryDexClassLoader` 的内存保护或 `mprotect` 监控）。

7. **USAP 进程注入**：除了 zygote64/zygote，Zymbiote 也会向 usap32/usap64（Unspecialized APP Process 池进程）注入，扩大了可被监控的进程范围。

### Zymbiote 适用场景决策

```
目标在启动时检测 Frida（Zygote 状态 / maps 扫描 / ptrace）？
├── 是 → Zymbiote 有明确收益
│   ├── 仅 Java hook 需要 → Zymbiote + 魔改 Frida
│   └── 需要 Native hook → Zymbiote 帮助 spawn 阶段，但 attach 后仍需传统绕过
└── 否（目标在运行时检测）→ Zymbiote 收益有限
    ├── maps/线程扫描 → 魔改 Frida + maps hook
    ├── ArtMethod 校验 → 硬件断点 / ArtMethod 直写
    └── 时序侧信道 → 内核级能力
```

### Zymbiote 与魔改 Frida 的组合策略

A4+ 场景下 Zymbiote 和魔改 Frida 应组合使用，各自覆盖不同阶段：

| 阶段 | Zymbiote 负责 | 魔改 Frida 负责 |
|------|--------------|----------------|
| Zygote fork 时 | ArtMethod patch，不污染 Zygote | N/A |
| spawn 到 attach | 无 frida-server 端口、无 agent 进程 | N/A |
| attach 后运行脚本 | N/A | 消除 agent 字符串特征、线程名、memfd 显示名 |
| 运行时 hook | N/A | 消除 trampoline 签名、RWX 页、maps 条目 |

**使用方式**：
```bash
# Zymbiote 在 Frida 17.6+ 的 spawn 模式中自动激活，无需额外参数
# 命令与标准 spawn 模式相同：
frida -U -f com.target -l bypass.js
# 前提：frida-server 17.6+ 且设备已 Root
# Zymbiote 对用户透明——使用 spawn 模式即可自动享受 Zygote 阶段隐蔽性
```

### 常见误区

- **"用了 Zymbiote 就不需要魔改 Frida"**：错误。Zymbiote 只解决 spawn 阶段，attach 后的运行时检测仍需魔改。
- **"Zymbiote 让 Frida 完全隐蔽"**：错误。attach 后 frida-agent 仍出现在 maps、线程、fd 表中。Zymbiote 的隐蔽性仅限于 Zygote 阶段。
- **"Zymbiote 可以绕过 ArtMethod 校验"**：恰恰相反，Zymbiote 通过替换 ArtMethod 的 `entry_point`（arm64 偏移 32）工作，而标准 Frida Java Hook 修改 `data_`（arm64 偏移 24）。两者修改不同字段，但都会被完整性校验发现。检测方需要同时校验两个字段才能全面覆盖。
- **"Zymbiote 不需要 Root"**：错误。Zymbiote 需要 Root 权限操作 `/proc/$pid/mem`。无 Root 场景仍需 Gadget 嵌入。

## libmsaoaidsec.so 5 级递进绕过

某支付宝安全库的 5 层 Anti-Frida 检测：

1. **pthread_create 拦截**：检测线程创建，Hook `pthread_create` 过滤检测线程
2. **clone 系统调用**：绕过 pthread 后检测改用 clone，Hook `clone` 过滤
3. **strstr 字符串匹配**：直接内存搜索 "frida" 字符串，需 patch strstr 或修改 Frida 特征
4. **/proc/status 读取**：读取进程状态检测调试器，Hook `open`/`read` 返回伪造内容
5. **最终方案**：使用修改版 Frida（消除所有字符串特征）

> 逐层绕过策略见上方「7 层检测矩阵」L1-L4 对应行，不要仅依赖本节的简化步骤。

## 硬件断点技术（Frida 16.5+）

不修改代码、不注入指令的断点方式：

```javascript
// 设置异常处理器（Frida 16+ 支持）
Process.setExceptionHandler(function(details) {
  console.log("Hit at: " + details.address + " type=" + details.type);
  return false; // 不处理异常，继续
});

// 使用 Interceptor + replace 实现类似效果
// 在指定地址设置 hook 但不修改原始指令
var target = Module.findBaseAddress("libtarget.so").add(0x1234);
// 通过 Interceptor.attach 的 onEnter 记录而不修改
Interceptor.attach(target, {
  onEnter: function(args) {
    console.log("Called from: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join('\n'));
  }
});
```

注意：Frida 的 `MemoryAccessMonitor` 在 Frida 16+ 已被移除。替代方案：
- 使用 `Process.setExceptionHandler` + 手动设置硬件断点寄存器（需要平台支持）
- 使用 `Interceptor.attach` 的轻量模式（不修改代码段的 `replace` 模式）

优势：
- 不修改目标代码（减少 inline hook 痕迹）
- 不被简单的代码完整性校验检测
- 可用于检测点定位（bisect 方法）

## Stalker 架构

Frida Stalker 的源码级原理：
- 基本块级 copy-and-instrument：将原始代码复制到新内存，添加插桩
- `trust_threshold`：控制基本块缓存复用，0=不缓存，高值=更积极缓存
- 不修改原始指令，但执行的是副本
- 可被内存比较型检测发现（执行地址 != 原始代码段地址）

## 内存级检测与对抗

### 检测方式
- RWX 页扫描：Frida 生成的代码页通常是 RWX
- inline hook 检测：比较函数入口的前几条指令是否被修改
- Zygote 继承状态：从 Zygote fork 的进程可能继承 Frida 状态

### 对抗方式
- 使用硬件断点替代 inline hook
- 在 hook 中恢复原始指令后再执行完整性校验
- 使用 Zymbiote 或修改版 Frida 消除内存特征

## 7 层检测矩阵（A3+ 必查）

A3+ 场景下必须逐层排查以下检测向量。经验证，单层绕过在 A4+ 场景中几乎必然失败——检测方通常组合 3-5 层形成纵深防御。

### L1 字符串/文件扫描（防护等级 A1-A3）

| 检测项 | 检测方式 | 检测签名 | 绕过策略 |
|--------|----------|----------|----------|
| 特征字符串 | `strstr/strcmp` 在内存中搜索 | `"frida"`, `"gum-js"`, `"linjector"`, `"frida-agent"`, `"frida-server"` | 魔改 Frida 二进制中等长替换；或 hook `strstr/strcmp` 返回 NULL |
| maps 扫描 | `openat/read` 读 `/proc/self/maps` | `"frida"`, `"gadget"`, `memfd:` 前缀 | hook `openat` 拦截 maps 路径；或清零 memfd 条目前 4 字节（ELF magic） |
| 线程名枚举 | `openat/read` 读 `/proc/self/task/*/comm` | `"frida-agent"`, `"gum-js-loop"`, `"gmain"`, `"gdbus"`, `"pool-frida"` | 魔改 Frida 重命名线程（`frida→dpCWV`, `gmain→XdJWC`, `gdbus→NFzHZ`） |
| 文件存在性 | `access/fstat` 检查路径 | `/data/local/tmp/frida*`, `/data/local/tmp/re.frida.server/` | hook `access/fstat` 对特征路径返回 -1 |
| 端口扫描 | `socket/connect` 探测 27042 | 27042 默认端口及 20000-65535 范围扫描 | 使用非标准端口；魔改 Frida 使用随机端口 |

### L2 协议指纹识别（防护等级 A3-A4）

| 检测项 | 检测方式 | 检测签名 | 绕过策略 |
|--------|----------|----------|----------|
| D-Bus 握手探测 | 向可疑端口发送 NUL 字节 + AUTH | 目标端口返回 `D-Bus` 协议头（Frida < 15 使用 D-Bus） | 使用 Frida 15+（WebSocket 协议）；魔改去掉 D-Bus 后端 |
| WebSocket 指纹 | 向端口发送 HTTP Upgrade 请求 | `Sec-WebSocket-Accept` 头匹配 Frida 握手响应 | 魔改 Frida 的 WebSocket 握手协议；Zymbiote 在 spawn 阶段无端口监听但 attach 后仍有 |
| memfd 特征 | 扫描 maps 中的 `memfd:` 条目 | `memfd:frida-agent-64.so`（Frida 17+ 通过 memfd_create 加载） | 清零 memfd 映射的前 4 字节（\x7fELF → 0x00000000）；或魔改 memfd 显示名 |

### L3 进程-端口绑定关联（防护等级 A3-A4）

| 检测项 | 检测方式 | 检测签名 | 绕过策略 |
|--------|----------|----------|----------|
| 端口归属验证 | `readlink /proc/net/tcp6` + 查找 socket inode → 查找进程 | 可疑端口属于非应用自身的进程（frida-server PID） | 使用 gadget 嵌入（端口在应用进程内）；Zymbiote spawn 阶段无独立 frida-server 进程但 attach 后仍有 |
| /proc/net 扫描 | `openat/read` 读取 `/proc/net/tcp` / `/proc/net/tcp6` | 匹配 LISTEN 状态的可疑端口条目 | hook `/proc/net/tcp*` 的读取，过滤 frida-server 条目 |

### L4 内存模式检测（防护等级 A4-A5）

| 检测项 | 检测方式 | 检测签名 | 绕过策略 |
|--------|----------|----------|----------|
| ARM64 trampoline 签名 | 扫描代码段中的特定指令模式 | `LDR X17, [PC, #8]; BR X17`（字节序列 `51 00 00 58 20 02 1F D6`，小端序）或 `LDR X16, [PC, #8]; BR X16`（`50 00 00 58 00 02 1F D6`）—— Frida 版本间可能使用 X16(IP0) 或 X17(IP1) | 使用 `Interceptor.replace` 替代 `attach`（不同 trampoline 格式）；或使用硬件断点 |
| RWX 页扫描 | 遍历 `/proc/self/maps` 查找 `rwx` 权限页 | Frida 生成的代码页（Stalker 副本、trampoline）拥有 RWX 权限 | 使用 `trust_threshold=0` 禁用 Stalker 缓存；或在 hook 中恢复页面权限 |
| inline hook 自检 | 比较函数入口字节与预期值 | 函数前 4-16 字节被替换为跳转指令 | 使用硬件断点；或在检测函数中恢复原始字节后再执行校验 |
| PrettyMethod hook 检测 | 检查 `LDR X16,[PC,#8]` 签名 | ArtMethod 替换后 `PrettyMethod` 入口被修改 | 避免直接 hook PrettyMethod；通过 ArtMethod `data_` 字段偏移直接读取 |

### L5 ArtMethod 完整性自检（防护等级 A4-A5）

| 检测项 | 检测方式 | 检测签名 | 绕过策略 |
|--------|----------|----------|----------|
| entry_point 校验 | 运行时比对 ArtMethod `data_` 字段与编译时值 | Frida Java Hook 替换了 `data_` 字段（常见偏移 arm64=24, arm32=20，因 Android 版本和厂商 ROM 而异，需运行时探测确认） | 使用 ArtMethod 直接内存写入替代 Frida Java Hook；或 hook 校验函数返回通过 |
| access_flags 校验 | 检查方法是否被标记为 native | Frida 将目标方法设置为 native（`kAccNative`） | 恢复 `access_flags` 中的 native 位；或使用 `Java.use` 的 `$className` 替代方案 |

### L6 信号/异常探测（防护等级 A4-A6）

| 检测项 | 检测方式 | 检测签名 | 绕过策略 |
|--------|----------|----------|----------|
| SIGTRAP 探测 | 注册自定义 SIGTRAP handler，主动触发断点 | Frida trampoline 触发 SIGTRAP 时，handler 检查触发地址是否在 Frida 的代码区域内 | 魔改 Frida 不使用断点指令；或 hook `sigaction` 返回虚假的 handler 信息 |
| 反调试状态检测 | 检查 `TracerPid`（`/proc/self/status`）或通过 `prctl(PR_SET_DUMPABLE, 0)` 禁止调试器附加 | 非 0 的 TracerPid 值表示调试器附加 | Zymbiote 不依赖 ptrace 注入 Zygote（但 attach 阶段仍需 ptrace）；spawn 模式在检测启动前完成注入 |

### L7 时序侧信道（防护等级 A5-A7）

| 检测项 | 检测方式 | 检测签名 | 绕过策略 |
|--------|----------|----------|----------|
| syscall 时序差 | ARM64 `CNTVCT_EL0` 硬件计数器测量 syscall 执行时间 | 被内核 hook 的 syscall（如 KernelSU hook 的 `faccessat`）执行时间明显更长（~70% 阈值比较） | 无法在用户态绕过——需要内核级能力（使用原始 syscall 路径而非 hook 路径）；或接受该检测面标记为 `DEFERRED` |
| 多次采样统计 | 数千次调用中排序消除调度噪声，绑定最快 CPU 核心（`sched_setaffinity`） | 统计分布而非单次判定，降低误报率 | 同上——内核级对抗；或判定该检测是否影响 completionCriteria 核心目标 |

### 其他已知检测向量（未归入 7 层但需留意）

| 检测项 | 检测方式 | 适用等级 |
|--------|----------|----------|
| `/proc/self/mem` 直接读取 | 绕过 libc hook，直接通过 fd 读取代码页检查 inline hook | A5+ |
| `dl_iterate_phdr` | 枚举已加载共享对象（包括匿名映射），即使 maps 被 hook 也能发现 Frida 内存映射库 | A4+ |
| `seccomp-BPF` 过滤器 | 安装 seccomp 规则阻止注入相关的 syscall（如 `process_vm_writev`、对 `/proc/self/mem` 的 `pwrite64`） | A5+ |
| `logcat` 监控 | Frida 注入过程会产生 logcat 输出，应用可监控特定日志 | A3+ |

### 检测强度与防护等级映射

> 注意：以下映射仅描述各等级的**典型检测组合**，实际检测因目标而异。A3 应用可能包含 L5 级检测，A5 应用可能跳过 L2。**必须逐层验证，不得根据防护等级跳过任何层。**

| 防护等级 | 典型检测组合 | 最低绕过策略 |
|----------|-------------|-------------|
| A1-A2 | L1 部分（字符串/文件） | 标准 Frida + 字符串替换 |
| A3 | L1 + L2 部分 | 魔改 Frida + 端口随机化 |
| A4 | L1-L4 组合（3-4 层） | 深度魔改 Frida + Zymbiote（解决 spawn 阶段） + 内存特征清理 |
| A5 | L1-L5 组合（4-5 层）+ 多阶段 | 魔改 Frida + 硬件断点 + ArtMethod 直写 |
| A6-A7 | L1-L7 组合（5-7 层）+ SVC 级 + 时序侧信道 | 内核级能力（eBPF/SVC hook）+ 魔改 Frida + 硬件断点；部分检测面可能需 DEFERRED |

### 使用方法

1. 根据防护等级确定需要排查的层数范围
2. 逐层验证：每层用对应的"检测签名"列确认是否存在
3. 存在的层执行对应的"绕过策略"
4. 记录结果到 `run/anti-frida-bypass.js` 的分层注释中
5. A5+ 场景中 L7 无法用户态绕过时，标记为 `DEFERRED` 并说明对 completionCriteria 的影响

### 多向量组合绕过示例（A3 场景）

A3 级别常见组合：maps 扫描 + 端口扫描 + 线程名检测。需要同时覆盖三个向量：

```javascript
// 1. Hook openat 防止 maps/状态文件读取
var openat = Module.findExportByName(null, "openat");
Interceptor.attach(openat, {
  onEnter: function(args) {
    var path = args[1].readUtf8String();
    if (path && (path.includes("/proc/self/maps") ||
        path.includes("/proc/self/status") ||
        path.includes("/proc/self/task"))) {
      // 返回 -1 或重定向到安全文件
      this.redirect = true;
    }
  }
});

// 2. Hook connect 防止端口扫描探测
var connect = Module.findExportByName(null, "connect");
Interceptor.attach(connect, {
  onEnter: function(args) {
    var port = args[1].add(2).readU16();
    // 检查是否在探测 Frida 默认端口范围
    if (port >= 27042 && port <= 27050) {
      this.block = true;
    }
  },
  onLeave: function(retval) {
    if (this.block) retval.replace(-1);
  }
});

// 3. 使用魔改 Frida 消除线程名特征（编译时处理）
// 如 rusda: gum-js-loop → russellloop, frida-agent → 自定义名
```

## SVC 级反 Hook 检测

部分高级保护直接通过 SVC 指令（系统调用）进行检测，绕过 libc Hook：
- Hook 目标：`ptrace`、`openat`、`read` 等
- 检测方式：直接执行 `svc #0` 而不经过 libc wrapper
- 绕过方式：内核级拦截（SVC hook、eBPF）或修改 SO 中的 SVC 指令

## Frida 无 Root 持久化

- **fripack**：将 Frida gadget 嵌入 APK 的 lib 目录，应用启动自动加载
- **修改 app_process**：替换系统 app_process，在其中启动 Frida server
- **Gadget 嵌入**：修改 APK，在 Application.onCreate 中 System.loadLibrary("frida-gadget")

## Frida 魔改编译 SOP

A4+ 场景下标准 Frida 几乎不可用。以下是经过验证的魔改关键点清单：

### 必须修改的特征（按优先级）

| 修改点 | 文件/位置 | 原始值 | 修改为 | 检测向量 |
|--------|-----------|--------|--------|----------|
| 协议字符串 | frida-core `.vala` 源文件 | `frida` 相关协议标识 | XOR 十六进制编码 | L1 字符串扫描 |
| 类型名 | `.rodata` 段 | `Frida` 前缀类型名 | 等长字节反转（二进制 patch 脚本） | L1 字符串扫描 |
| 符号前缀 | 所有二进制 | `frida` | 自定义前缀（如 `rusda`） | L1/L4 符号扫描 |
| 线程名 | 源码 | `gum-js-loop` | 自定义名（如 `russellloop`） | L1 线程枚举 |
| 线程名 | 源码 | `frida-agent` | 自定义名 | L1 线程枚举 |
| memfd 显示名 | 源码 | `memfd:frida-agent-64.so` | 自定义名 | L2 memfd 特征 |

### 编译环境要求

- Frida 16.5.x → NDK r25
- Frida 17.6.x → NDK r25（注意：Frida main 分支可能要求更高版本，以发布标签为准）
- Vala 编译器 + Python 构建工具链
- `objcopy` 用于 .rodata 修补

### 快速验证

魔改后验证清单：
1. `strings frida-server | grep -i frida` 应返回 0 结果
2. `/proc/$pid/maps` 中无 `frida` 字样
3. `/proc/$pid/task/*/comm` 中无 `frida`/`gum`/`gmain`/`gdbus` 字样
4. 默认端口 27042 未监听
5. 目标 A4+ App 能正常 attach 不闪退

## 成功判定

至少满足两项：

- 本地不再因 anti-frida 退出或阻断
- 目标功能可继续进入
- 关键请求可正常发起
- 没有新的二次 anti-frida 命中证据

## 联动专题

- **hook-injection**：Zymbiote 的内部注入链路、ArtMethod patching 技术实现和 spawn 架构细节见 `hook-injection-playbook.md`。本 playbook 仅从检测/绕过视角分析 Zymbiote
- **anti-root**：anti-frida 的前提是 root 环境可用。如果 root 被检测导致 Frida 无法运行，先参见 `anti-root-playbook.md`
- **art-runtime**：L5 ArtMethod 完整性校验与 ART 运行时的 ArtMethod 内存布局相关，偏移量随 Android 版本变化。参见 `art-runtime-playbook.md` 和 `android-version-matrix.md`
- **dex-loader**：壳保护的 App 可能将 anti-frida 检测放在动态加载的 dex/SO 中，脱壳后才能完整分析检测链。参见 `dex-loader-playbook.md`

## 最小交付

- `run/anti-frida-bypass.js`
- 报告中的触发时机、检测面、绕过状态、残留风险
- A3+ 场景必须包含 7 层检测矩阵的逐层排查记录

## 实战补充：商业壳多层检测绕过参考

梆梆加固等商业壳的 Frida 检测是系统性纵深防御。实战映射的 L1-L6 层级表（含具体检测手段和绕过策略）见 `references/technique-extract-2026-05.md` 第 2 节。

**关键决策点**：
- **快速绕过**（调试场景）：仅 `Interceptor.replace` 自杀函数 + Hook `android_dlopen_ext` 监控目标 SO 加载时机。省力但可能残留检测
- **完整绕过**（稳定分析场景）：逐层处理。快速绕过 + 工程机白名单信息（`ro.build.user` == 特定 hex 值时跳过所有检测）= 判断是否值得做完整绕过
- `android_dlopen_ext` hook 模板见 `references/technique-extract-2026-05.md` 第 2 节或 `references/hook-snippets.md`


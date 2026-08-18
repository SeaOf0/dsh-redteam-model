# Kernel-Assisted Reverse Engineering Playbook

目标：当用户态工具（Frida、ptrace、Xposed）全部被检测或拦截时，利用内核能力继续逆向分析。本 topic 不覆盖内核开发本身，而是聚焦"应用逆向中何时需要、如何使用内核工具"。

## 先回答

- 当前用户态工具是否已穷尽（Frida 被检测、ptrace 被拦截、inline hook 被自检）
- 目标防护等级是否 >= A5（A5 以下通常不需要内核手段）
- 是否有 Root 权限 + 自定义内核模块支持（KernelSU / APatch / Magisk + 自定义 boot.img）
- 需要的是无痕调试、DEX dump、syscall 监控、还是硬件断点

## 何时升级到内核手段

**升级条件**（满足任一即需考虑）：
1. 用户态所有注入方式被检测（ptrace、Frida、Zygisk 都被拦截）
2. 目标 SO 有完整的 ArtMethod 完整性自检（L5 级检测）
3. 目标进程监控 `/proc/self/maps` 且不允许任何 SO 映射
4. 目标使用 `seccomp-bpf` 限制 syscall（如禁止 `ptrace`、`process_vm_readv`）
5. 需要在进程启动最早期获取数据（如 DEX 解密后的瞬间 dump）

**分流到 stealth-hook**：若目标 ≥ A6 且交付物是"hook 命中 + 修改执行流 + 过反检测"，本 topic 的 eBPF/HWBP 单点能力不够——直接走 [stealth-hook-playbook.md](./stealth-hook-playbook.md)。本 topic 聚焦"取证观察"，stealth-hook 聚焦"无痕 hook 与执行流接管"。

## 用户态 vs 内核手段路线决策

升级条件命中后，进入注入/hook 前还要按**交付目标**选路线，记入 `route-state.json`。内核手段成本高、风险大，不应作为默认——但目标场景不同，最优解也不同。

**为什么按任务类型分流**：内核 HWBP 不触用户态内存、不引发 `.text` CRC，适合取证；但它的能力有限（槽位少、不能跑复杂脚本、不能 replace 大段逻辑），让它去"过检测让 App 跑起来"既不必要也不可行。把两类目标混为一谈会导致选错主力工具。

- **共存型目标**（交付物是"让 App 带 hook 正常运行 / 过检测 / 注入不被发现"）→ 用户态 Frida 路线优先。目标是与检测共存：用 Frida 定位并接管 CRC 校验、反 Frida 检测的执法分支（让校验返回 clean、隐藏 Frida 痕迹：端口/agent 名/线程名/maps/gadget），按"先接管 CRC 校验再注入其余 hook"的顺序推进，必要时用改版 Frida/gadget 降低特征。
  - **此路线下内核硬件断点仅作辅助验证**——用来确认参数、返回值、patch 候选或 syscall 证据，不能替代 Frida 过检测主线。
- **取证型目标**（交付物是 T1-T4 的参数/返回值/算法还原）→ 按检测强度分层：
  1. 目标**无 anti-Frida** → 直接用 Frida（脚本灵活、开发快）。
  2. 目标**有 anti-Frida** → 用内核硬件断点取证（不触用户态内存、不引发 CRC/反 Frida），读寄存器/内存、dump 中间数据。
  3. 内核断点**功能不足**（需复杂脚本逻辑、主动调用函数、replace 大段逻辑、读断点拿不到的上下文）→ 回到 Frida 并先过检测（同共存型做法），再做算法分析。
- 任务类型不明 → 先问用户"要共存还是要取证"；取证型还要确认目标是否存在 anti-Frida，再选路线。

本路线决策与 `so-runtime-evidence-playbook.md` §4（内核 syscall 证据）、`integrity-pinning-playbook.md` 的 Native 自校验专项处置顺序一致。

## 工具选择

| 场景 | 工具 | 原理 | Root 要求 |
|---|---|---|---|
| 无痕调试/trace | edbg (eBPF) | eBPF 程序注入内核，替代 ptrace | Root + eBPF 支持 |
| DEX dump | eBPFDexDumper-rs | eBPF 监控 mmap/write，拦截 DEX 加载 | Root + eBPF 支持 |
| syscall 监控 | SVCMonitor | 内核模块拦截 `svc #0` 指令 | Root + 自定义内核 |
| 硬件断点 Hook | KPM + HWBP | ARM64 硬件断点寄存器，修改进程内存 | Root + 内核模块 |
| 内存页 Hook | PTE hook | 修改页表项权限，触发 page fault | Root + 内核模块 |
| 零侵入 Binder 代理 | AndProxy (seccomp) | seccomp-bpf 拦截 Binder syscall | Root |

## 操作顺序

### 1. eBPF DEX Dump

适用场景：壳保护下的 DEX 脱壳，用户态 dump 被壳自检发现。

**eBPFDexDumper-rs SOP**：
1. 编译 eBPF 程序（Rust + libbpf）
2. 加载 eBPF 程序到内核
3. eBPF 程序 hook `do_mmap` / `do_write` 系统调用
4. 检测到 DEX magic（`dex\n035\0` / `dex\n039\0`）时触发 dump
5. 4 层容错策略：
   - 层 1：拦截 `mmap` 写入，检测 DEX 头
   - 层 2：拦截 `write` 系统调用，检测 DEX 数据
   - 层 3：定期扫描目标进程内存映射
   - 层 4：ART 运行时 DEX 采集 + 字节码回填

**优势**：完全不注入目标进程，不修改 `/proc/self/maps`，不创建新线程。

### 2. eBPF 无痕调试器（edbg）

适用场景：A6/A7 级反调试保护，ptrace 被完全封锁。

**edbg 架构**：
- `edbgserver`：运行在设备上的 eBPF 调试服务
- 通过 eBPF 程序替代 ptrace 的核心功能（读写内存、设置断点、单步执行）
- 断点通过 eBPF uprobe 实现（不修改目标指令）
- 单步通过 eBPF kprobe 监控调度器实现

### 3. 内核硬件断点 Hook

适用场景：需要在特定地址设置断点，但不能修改指令（有完整性自检）。

**ARM64 硬件断点机制**：
- ARM64 通常有 6 个执行断点（`DBGBVR0`-`DBGBVR5` + `DBGBCR`）+ 4 个数据观察点（`DBGWVR0`-`DBGWVR3`）
- 通过内核模块（KPM）设置：写入 `DBGBVR`（目标地址）+ `DBGBCR`（控制寄存器）
- 触发时产生调试异常，内核模块处理并回调到用户态
- **进阶用法**：单槽位状态机跳转（入口↔LR），用一个 BP 同时抓入口参数与返回值——详见 `stealth-hook-playbook.md` §HWBP 状态机

**多核同步**：`smp_call_function` 确保所有 CPU 核心都设置相同的硬件断点。

> **本节的进阶能力（单 BP 抓返回值、Watchpoint 抓内存读写、命中后修改 X0-X7）已被 `stealth-hook` topic 系统化封装**。如果目标 ≥ A6 或需要"无痕 + 主动修改寄存器/返回值"，直接走 [stealth-hook-playbook.md](./stealth-hook-playbook.md)，不必从此处自行拼装。

### 4. PTE Hook（页表 Hook）

适用场景：需要 Hook 函数但不能修改指令，硬件断点数量不够（>6 点）。

**原理（两种实现）**：

| 实现 | 触发机制 | 开销 | 代表方案 |
|---|---|---|---|
| 简单 PTE Hook | PTE 改只读 → 数据写入触发 page fault（数据断流） | TLB 刷新开销大，不适合高频路径 | 早期实验性内核模块 |
| **PTE+UXN+DBI** | PTE 置 UXN bit (bit 54) → 执行触发 Instruction Abort → DBI 重编译跳板 | **一次性重编译，无 TLB 反复刷新** | 可选外部 `xiaojianbang-stealth-hook`（链接见 `tools/vendor-packs/stealth-hook.md`） |

**关键纠正**：本 playbook 早期版本写"PTE Hook 限制：TLB 刷新开销大，不适合高频调用路径"——这只对简单 write-fault PTE Hook 成立。**xiaojianbang PTE+DBI 方案通过克隆页 + 一次性 ARM64 指令重编译（处理 B/BL/B.cond/CBZ/ADR/BLR+PAC）已解决此问题**，可挂在任意高频业务函数上。

> **需要 >6 个 hook 点、替换函数体、或与 LSPlant 集成做 Java 无痕 Hook 时**，直接走 [stealth-hook-playbook.md](./stealth-hook-playbook.md) 的 PTE+DBI 模式，不要在此处手工拼装。

### 5. seccomp-bpf Binder 代理（AndProxy）

适用场景：需要代理 Binder 通信，但不修改目标进程。

**原理**：
1. 使用 `seccomp-bpf` 安装过滤器，拦截 `ioctl` syscall（Binder 基于 ioctl）
2. 过滤器不阻止调用，只通知用户态代理
3. 代理进程读取 Binder 事务数据
4. 可选择修改或转发 Binder 事务

**优势**：零注入、零修改、零内存映射。

### 6. SVC 监控

适用场景：追踪目标进程的系统调用行为（文件访问、网络操作、进程操作）。

**原理**：
1. 内核模块 hook `svc #0` 异常处理
2. 读取系统调用号和参数（从用户态寄存器获取）
3. 记录所有系统调用到 buffer
4. 用户态工具从 buffer 读取日志

## 部署操作

### eBPFDexDumper-rs 编译与使用

```bash
# 前置条件: Root 设备 + 内核 5.4+（确认 eBPF 支持）
adb shell cat /proc/version
adb shell ls /sys/fs/bpf  # 确认 eBPF 文件系统已挂载

# 编译（需要 Rust + libbpf-dev + Android NDK）
git clone https://github.com/AabyssZG/eBPFDexDumper-rs.git
cd eBPFDexDumper-rs
# 交叉编译 ARM64
export NDK_HOME=/path/to/android-ndk
export TARGET=aarch64-linux-android
cargo build --release --target $TARGET

# 推送到设备
adb push target/$TARGET/release/ebpf-dex-dumper /data/local/tmp/
adb shell chmod +x /data/local/tmp/ebpf-dex-dumper

# 执行 dump（指定目标包名）
adb shell su -c "/data/local/tmp/ebpf-dex-dumper -p com.target.package -o /data/local/tmp/dex_output/"

# 拉取 dump 结果
adb pull /data/local/tmp/dex_output/ ./
```

### edbg 编译与使用

```bash
# 前置条件: Root 设备 + 内核 5.10+ + eBPF 支持完整
git clone https://github.com/AabyssZG/edbg.git
cd edbg

# 编译（需要 Rust + libbpf + bpftool）
cargo build --release --target aarch64-linux-android

# 推送到设备
adb push target/aarch64-linux-android/release/edbgserver /data/local/tmp/
adb shell su -c "chmod +x /data/local/tmp/edbgserver"

# 启动调试服务
adb shell su -c "/data/local/tmp/edbgserver --pid $(pidof com.target.package)"

# 从主机连接
# edbg 支持通过 adb forward 转发端口
adb forward tcp:9527 tcp:9527
# 然后使用 edbg 客户端连接
edbg-client --host 127.0.0.1 --port 9527
```

### ARM64 硬件断点设置（内核模块方式）

```bash
# 前置条件: 已编译 KPM 内核模块并推送到设备
# KPM 需要从源码编译匹配当前内核版本
adb push kpm_hwbp.ko /data/local/tmp/
adb shell su -c "insmod /data/local/tmp/kpm_hwbp.ko"

# 设置硬件断点（通过 /proc 或 ioctl 接口）
# 目标地址需要是目标进程空间中的绝对地址
# adb shell su -c "echo 'pid:PID addr:0xHEXADDR type:execute' > /proc/kpm_hwbp"
# 示例：在 libtarget.so +0x1234 处设置执行断点
# 1. 先获取 libtarget.so 在目标进程中的基址
adb shell su -c "cat /proc/$(pidof com.target.package)/maps | grep libtarget.so"
# 2. 基址 + RVA = 绝对地址
# 3. 写入断点配置
adb shell su -c "echo 'pid:$(pidof com.target.package) addr:0xBASE_PLUS_RVA type:execute' > /proc/kpm_hwbp"

# 读取断点触发日志
adb shell su -c "cat /proc/kpm_hwbp"
```

## 常见偏差

- 不先穷尽用户态手段就上内核工具——内核工具成本高、风险大，应作为最后手段
- 不确认设备是否支持 eBPF——5.x 以下内核的 eBPF 支持有限
- 忽略内核模块对系统稳定性的影响——生产设备上需谨慎
- 混淆本 topic 的范围——本 topic 是"应用逆向中使用内核工具"，不是"内核逆向"
- 不考虑 SELinux 影响——内核模块和 eBPF 在 SELinux enforcing 下可能需要额外策略
- 硬件断点不考虑多核——必须 `smp_call_function` 同步所有核心

## 最小交付

- `run/kernel-assisted-re-notes.md`
- 内核工具选择及原因（为什么用户态工具不够用）
- 内核工具部署和执行记录
- 采集到的数据（dump 的 DEX、trace 日志等）

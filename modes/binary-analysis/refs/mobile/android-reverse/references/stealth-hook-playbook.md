# Stealth Hook Playbook

> 本 playbook 覆盖 A6/A7 强对抗场景下的**内核级无痕 Hook**。
> 可选外部工具参考：`tools/vendor-packs/stealth-hook.md` 只登记 GitHub 开源项目链接；本 skill 不内置源码、KPM 或用户态二进制。
> 适用前提：用户态 Frida/Xposed/Dobby 已被系统性检测或拦截，需升级到内核态。

本 topic 与 `kernel-assisted-re`（取证导向：eBPF dump、edbg、AndProxy）和 `hook-injection`（用户态 Hook 原理）形成三层递进：

| Topic | 范围 | 触发时机 |
|---|---|---|
| `hook-injection` | 用户态 Hook 原理（PLT/Inline/Java/ArtMethod） | A0-A4，无系统性反检测 |
| `kernel-assisted-re` | 内核取证（eBPF/edbg/seccomp/SVC 监控） | A5+，目标是 dump/trace 而非共存 |
| `stealth-hook`（本专题） | 内核无痕 Hook（HWBP+PTE+DBI+Ghost Mem） | A6-A7，目标需共存且用户态 Hook 全部失败 |

## 先回答（升级前必答）

进入本专题前必须先在 `run/stealth-hook-notes.md` 落盘以下答案，否则按 `kernel-assisted-re` 路线决策节"过早升级"处理：

1. **用户态工具失败证据**：`ptrace`/Frida/Xposed/Zygisk/Dobby 各自失败的具体检测点是什么？是配置错误还是系统性拦截？落盘 `detection-evidence`
2. **目标防护等级**：是否真为 A6/A7？低于 A6 由 `hook-injection` 处理
3. **任务类型**：**取证型**（T1-T4，抓参数/还原算法）还是**共存型**（让 App 带 hook 正常运行 / 过检测）？此决策影响主力工具选择（见"路线决策"）
4. **设备能力**：ARM64 + Kernel 5.4+ GKI + APatch + KernelPatch 0.13.x + 解锁 BL？四件套缺一不可，缺则降级到 `kernel-assisted-re` 的 eBPF 路线或纯静态
5. **数据需求**：是否需要修改执行流（replace-ret / modify-arg）？还是只需观察（live trace / listen-ret）？

## 路线决策

### 取证型 vs 共存型

- **取证型目标**（T1-T4）：
  - **无 anti-Frida** → 直接 Frida（脚本灵活、开发快），本 topic 仅作辅助
  - **有 anti-Frida** → 主力用本 topic 的 HWBP 模式（不触用户态内存、不引发 CRC/反 Frida），读寄存器/内存、dump 中间数据
  - **HWBP 功能不足**（需复杂脚本逻辑、主动调用、replace 大段逻辑）→ 回到 Frida 并先过检测（按 `anti-frida-playbook.md`），再做算法分析
- **共存型目标**（让 App 带着接管跑）：
  - 用户态 Frida 路线优先（接管 CRC 校验、隐藏 Frida 痕迹），按"先接管 CRC 校验再注入其余 hook"顺序推进
  - 本 topic 的内核 HWBP 仅作辅助验证（确认参数、返回值、patch 候选），**不**作为共存主线
- **任务类型不明** → 先问用户"要共存还是要取证"；取证型还要确认目标是否存在 anti-Frida

### HWBP 模式 vs PTE 模式

| 维度 | HWBP（硬件断点） | PTE Hook（页表 + DBI） |
|---|---|---|
| 槽位上限 | **6 个执行断点 / 4 个数据观察点** | 理论无限（按 4KB 页为单位） |
| 修改内存 | 否 | 否（仅置 UXN 位） |
| 修改页表 | 否 | 是（目标页 PTE 置 UXN） |
| 首次触发开销 | 微秒级（debug trap） | 单次 `do_page_fault`，后续克隆页全速 |
| 适合场景 | ≤6 个目标函数、监听参数/返回值 | >6 个函数、需大段替换执行流、LSPlant 初始化 |
| 反检测叠加 | 自动含 Ptrace Spoof | 自动含 Maps Hide + Ghost Mem |
| 实现复杂度 | 中（KPM 内 handler + 状态机） | 高（KPM + 用户态 DBI 重编译） |

**选择规则**：
- Hook 点 ≤ 6 且只需观察/改参/改返回值 → HWBP
- Hook 点 > 6 或需替换函数体 → PTE Hook
- 需 Java 层无痕 Hook → PTE Hook（喂给魔改 LSPlant，见"LSPlant 集成"节）

## 可选外部 vendor tool pack

本仓库不再保留 `<SKILL_BASE>/tools/stealth-hook/` vendor 副本，也不随 skill 分发任何 KPM、用户态二进制、源码或部署脚本。

唯一登记位置：`tools/vendor-packs/stealth-hook.md`

使用规则：

- 不自动下载、构建、部署外部项目；由用户根据设备、内核版本、授权边界和稳定性风险决定是否尝试。
- 用户未明确选择并提供本地产物前，不得把 KPM 加载、用户态工具推送或 hook 自检列为已完成项。
- 若用户提供本地产物，先在 `run/stealth-hook-notes.md` 记录来源链接、本地路径、版本或 commit（若可得）、SHA256、目标设备与内核假设，再进入设备侧验证。
- 外部项目的具体构建、参数和部署命令以其上游文档为准；本 playbook 只保留路线门禁、证据结构和验收要求。

## 设备能力四件套

```
1. ARM64 架构           adb shell getprop ro.product.cpu.abi      # 必须是 arm64-v8a
2. 内核 5.4+ GKI        adb shell uname -r                        # 5.4 / 5.10 / 5.15 / 6.1
3. APatch 已安装        adb shell su -c 'apatch version'          # 提供模块加载 + su
4. KernelPatch 0.13.x   adb shell su -c 'cat /proc/apatch/version' # kpimg d01+
5. Bootloader 已解锁    fastboot oem device-info（或厂商对应命令）  # unlocked = true
```

任一条不满足 → 退出本 topic，降级到：
- 无 Root / 未解锁 → `kernel-assisted-re` 的 eBPF 路线（仍需 Root，但要求低）；或纯静态分析
- 内核 < 5.4 / 非 GKI → 同上
- Root 但无 APatch（仅 Magisk） → 评估刷 KernelPatch 或换设备；不可降级到 Zygisk（强度不足）

## 七大模块原理（理解检测面与适用边界必备）

> 完整文档见上游 `[原创]Android内核无痕Hook理解和感悟.md`。本节为运行时必读最小集。

### 1. HWBP（Hardware Breakpoint）

ARM64 CPU 内置调试寄存器（`DBGBVR`/`DBGBCR`），写入目标地址后，CPU 执行到此自动 trap 到内核 `bg_hwhook_handler`，无需修改任何用户态内存。

**关键约束**：
- 物理上限 6 个执行断点 + 4 个数据观察点
- **线程级**绑定：必须遍历 `/proc/[pid]/task` 对所有 TID 注册，KPM 内还需 hook `wake_up_new_task` 监听新线程
- 回收必须用 **RCU + 标记清除式异步 GC**，禁止直接 `kfree`（多核并发 UAF 黑屏）

**状态机跳跃（监听返回值）**：单断点在入口↔LR 间跳跃，避免消耗 2 个槽位同时拿到入口参数和返回值。
- 入口命中 → 抓 X0-X7 + 把断点跳到 LR（PAC 剥离）
- LR 命中 → 抓 X0 返回值 + 把断点跳回入口

### 2. PTE Hook + UXN

修改目标内存页的页表项（PTE），置位 UXN（用户态不可执行）。代码内容可读（CRC 通过），但执行即触发 Instruction Abort，陷入 `do_page_fault`。

KPM 在缺页 handler 中查 `offset_map`，把 PC 重定向到用户态 DBI 重编译好的克隆页继续执行。

**并发安全**：原页永远是 UXN 雷区，多线程同时撞网被内核逐个引导到克隆页，无竞态 Crash。

### 3. DBI 指令重编译（用户态）

克隆页不是字节级拷贝。ARM64 是 PIC（位置无关代码），相对寻址必须修正：

| 指令类 | 问题 | DBI 解法 |
|---|---|---|
| `B` / `BL` | ±128MB 范围，跨页拷贝必越界 | Far Redirect：X17 暂存 + LDR 字面量 + BR，1 槽膨胀为 11 槽 |
| `B.cond` / `CBZ` / `TBNZ` | ±1MB 射程，必越界 | 反转条件 + 跳过远跳 + Far Redirect |
| `ADRP` + `ADD` | 基于 PC 的页寻址，克隆后页基址全错 | 提前算出绝对地址，改写为 `LDR Rd, [PC, #8]` + 字面量 |
| `BLR*`（含 PAC） | 强行替换会破坏 PAC 签名致 SIGILL | 清指令第 21 位（BLR→BR 保 PAC 验证但不污染 LR） |

DBI 引擎先跑 `dbi_compute_layout` 算每条指令膨胀后偏移，记入 `offset_map`，再正式拷贝。这是 KPM 缺页 handler 路由的依据。

### 4. Ghost Memory（VMA-less 物理级隐身）

普通 `mmap` 必产生 VMA，暴露在 `/proc/self/maps`。Ghost Mem 三步：

1. 内核 `vzalloc` 分配物理页
2. 用户态随机挑一个未占用的 `target_va`（如 `0x6000000000` 区）
3. `apply_to_page_range` 强行把内核物理 PFN 注入目标进程的 PTE，手工拼装属性位：`0x1 | 0x2 | 0x4 | 0x40 | 0x300 | 0x400 | 0x800`（Valid / Page / Normal / User / Inner Shareable / AF / nG）

结果：CPU 硬件 MMU 认可（属性合法），但 OS 的 `mm_struct` 链表查无此 VMA。`/proc/self/maps` 和 `mincore` 都看不到。Ghost Mem 是存放 DBI 克隆页和 LSPlant 跳板的最强容器。

### 5. Maps Hide

反作弊遍历 `/proc/self/maps` 最终走内核 `seq_file` 的 `show_map`/`show_smap`。KPM 在这些回调的 after 钩子里：
1. 记录 `prev_count`
2. 提取本次新增的一行
3. 命中我们注入的特征名 → 把 `m->count` 拨回 `prev_count`，返回 `SEQ_SKIP`

效果：可疑行在打印缓冲区被时光倒流，反作弊读不到。

### 6. Ptrace Spoof（假账本）

反作弊 ptrace 五步杀：
1. `PTRACE_GETREGSET` 读寄存器
2. 满载占坑测试（写 6 个）
3. 读写一致性校验
4. 越界诱导（写 7 个，正常应 `-ENOSPC`）
5. 主动触发测试

KPM 拦截 `sys_ptrace`，每个线程维护 `struct user_bp_stat` 假账本：
- GET → 返回假账本（地址恒为 0，"干干净净"）
- SET → 写入假账本，不碰真 CPU；`count > max_count` 时返回 `-ENOSPC`（完美模拟）

`perf_event_open` 不需 spoof：我们的 HWBP 精确到具体 TID + 地址，反作弊的测试函数不在覆盖范围内。

### 7. KPM Syscall 桥接

KPM Hook syscall 285（`copy_file_range`，6 args），magic `0x584A42`（"XJB"）校验后路由到 `bg_syscall` 调度中心：
- `BGSYSCALL_HB_HOOK` 等 HWBP 命令
- `BGSYSCALL_HB_DBI_COMMIT` 等 PTE+DBI 命令
- `BGSYSCALL_HD_SO_ADD` 等 Maps Hide 命令

## 外部工具尝试门禁

### 1. 用户选择

先读 `tools/vendor-packs/stealth-hook.md`。只有当用户明确选择尝试该外部项目，并提供或确认会自行准备匹配当前设备的本地产物后，才进入后续设备侧验证。

### 2. 产物登记

在 `run/stealth-hook-notes.md` 记录：

- 外部项目链接
- 用户提供的 KPM / 用户态工具本地路径
- 版本或 commit（若可得）
- SHA256
- 目标设备、Android 版本、内核版本、APatch / KernelPatch 状态

缺少本地产物或设备能力不足时，退出本 topic，回到 `kernel-assisted-re` 或纯静态路线。

### 3. 设备侧验证

设备侧加载、自检和参数使用以外部项目上游文档为准。验证结果只在真实执行并落盘后才可引用；不得把“外部项目理论支持”写成“本任务已验证”。

### 4. 选 hook 点

来自 `hook-injection-playbook.md` 的 PLT/GOT/Inline 候选地址在此都适用。HWBP 直接吃 SO 相对偏移 `--offset`，无需绝对地址换算。

**禁忌**：不要 hook 高频通用函数（`memcpy`/`malloc`/`strlen`/`pthread_*`）。`hit_count` 爆炸 = 选错位置，正常业务函数调用频率很低。

## 操作模式速查

外部项目的具体命令、参数、默认值和限制以上游文档为准；本 playbook 不复刻其命令表，避免 stale SOP 或跨设备误用。

本 topic 只记录模式选择：

| 模式 | 适用条件 | 需要落盘的证据 |
|---|---|---|
| HWBP | ≤6 个 hook 点，只需观察参数 / 返回值或小范围改参 | hook 点、命中次数、寄存器 / 内存快照、未触发反检测证据 |
| PTE+DBI | >6 个 hook 点，或需要替换函数体 / 零字节修改 | 页表 / 克隆页路线说明、命中证据、稳定性风险 |
| LSPlant stealth | Java 层无痕 Hook 且存在 ArtMethod 指针漫游检测 | 指针检测面、Ghost Mem / 跳板策略、残留风险 |

## LSPlant 集成（Java 层无痕 Hook）

LSPlant 默认需要 6 个 inline hook 接口，正好对应 ARM64 6 个 HWBP 槽位。配合 Ghost Mem 可实现 Java 层 100% 无痕：

```cpp
lsplant::InitInfo initInfo{
    // 用 HWBP/PTE Hook 替代常规 inline hook
    .inline_hooker = my_stealth_inline_hooker,
    .inline_unhooker = my_stealth_inline_unhooker,

    // 符号解析（不变）
    .art_symbol_resolver = [...],
    .art_symbol_prefix_resolver = [...],

    // 关键：劫持内存分配，LSPlant 跳板 → Ghost Mem
    .mem_map = [](auto* addr, auto length, auto prot, auto flags, auto fd, auto offset) {
        return call_alloc_hidden_mem(length);  // 越过 OS，无 VMA 记录
    },
    .mem_unmap = [](auto* addr, auto length) {
        return call_free_hidden_mem((unsigned long)addr);
    },
};
```

**ArtMethod 检测面**（指针漫游检测）：防守方扫所有 `ArtMethod.entry_point_from_quick_compiled_code_`，发现指向匿名 `rwx` 内存即报警。LSPlant + Ghost Mem 后，指针指向 Ghost Mem，反作弊查无此 VMA。

**进一步加固**（PTE + UXN 替换法）：完全不动 `ArtMethod` 入口指针，转而对真实机器码入口地址拉起 UXN 电网/PTE Hook。指针"看起来原装"、CRC 完美、调用即陷入内核态被任意操纵。

## 反检测能力对照

| 检测手段 | Frida | Xposed | Dobby | 本框架 |
|---|:---:|:---:|:---:|:---:|
| `.text` CRC 完整性 | ❌ 改字节 | ❌ 改字节 | ❌ 改字节 | ✅ 不修改代码 |
| `/proc/self/maps` 扫匿名 r-x | ❌ 暴露 | ❌ 暴露 | ❌ 暴露 | ✅ Maps Hide + Ghost Mem |
| `ptrace` 读调试寄存器 | N/A | N/A | N/A | ✅ 假账本（5 步杀全失效） |
| `perf_event_open` 枚举 | N/A | N/A | N/A | ✅ 内核态事件用户态不可见 |
| 线程检测（敏感线程名） | ❌ Frida 线程 | ❌ | ✅ | ✅ 无线程 |
| Frida 特征（端口/agent/gadget） | ❌ | ✅ | ✅ | ✅ 无关 |
| `TracerPid` | ❌ | ✅ | ✅ | ✅ 0 |
| ArtMethod 入口指针漫游 | ❌ LSPlant 默认改 | — | — | ✅ Ghost Mem + PTE 不改指针 |
| Stalker PC 在 slab 区 | ❌ | — | — | ✅ PC 在 Ghost Mem（VMA 查不到） |

## 常见偏差

- **过早升级**：A0-A5 任务用本框架属于过度工程。先穷尽 `hook-injection` 用户态手段，落盘失败证据再升级
- **hook 高频通用函数**：`memcpy`/`strlen` 等会 `hit_count` 爆炸，日志刷屏且无法定位业务。hook 目标函数内部的具体地址
- **混淆范围**：本 topic 是"用内核手段做应用层 Hook"，不是内核逆向。内核逆向不在本技能范围
- **忽略 SELinux**：APatch + KPM 在 SELinux enforcing 下通常 OK，但部分厂商定制策略可能拦截 syscall 285 hook 或 `apply_to_page_range`，需 `setenforce 0` 临时验证后再恢复
- **多核 HWBP 不同步**：必须 `smp_call_function` 同步所有核心注册。KPM 内部已处理，但自定义魔改时不要破坏此路径
- **RCU 回收路径**：HWBP 节点回收必须走 RCU 宽限期，禁止直接 `kfree`，否则多核 UAF 黑屏
- **混淆 LSPlant 默认行为与 Ghost Mem 加固**：默认 LSPlant 仍会暴露 ArtMethod 入口指针，必须配合 Ghost Mem 才彻底
- **设备能力四件套缺一不可**：硬件断点要 CPU 支持、PTE Hook 要 GKI 内核、Ghost Mem 要 `apply_to_page_range` 可用，缺一降级

## 联动专题

- `references/kernel-assisted-re-playbook.md`：取证型场景（dump/trace）选 eBPF 路线，本 topic 是共存型或带修改流的升级
- `references/hook-injection-playbook.md`：本 topic 的基础。用户态 Hook 原理（PLT/GOT/Inline/ArtMethod）在这里
- `references/anti-frida-playbook.md`：共存型目标用 Frida 路线时，先在这里过 Frida 检测
- `references/so-runtime-evidence-playbook.md`：磁盘 SO 不可直接分析、`init_array` 闪退等场景与本 topic 的"匿名 RX/memfd"信号重叠
- `references/a6-a7-failure-pattern-cookbook.md`：FP-03（桥接是动态注册）、FP-04（Native pinning）、FP-05（Java hook 不命中）的解决路径之一是升级到本 topic
- `references/integrity-pinning-playbook.md`：Native 自校验需要"零字节修改"接管时进入本 topic

## 最小交付

`run/stealth-hook-notes.md` 必含字段：

- 目标信息（包名、PID、SO 名 + 偏移）
- 升级到本 topic 的依据（用户态失败证据 + 防护定级 + 任务类型 + 设备能力四件套答案）
- 模式选择（HWBP / PTE / LSPlant 集成）及原因
- 外部工具选择记录（若用户实际选择尝试：GitHub 链接、本地产物路径、版本或 commit、SHA256、设备假设）
- 设备侧验证日志（若实际执行：KPM 加载、自检输出；未执行则写明未尝试原因）
- hook 点列表（SO + 偏移 + 用途）与命中证据（X0-X7 + mem dump + hit_count）
- 反检测裁定（对照"反检测能力对照"表逐项确认）
- 风险与残留（是否触发 SELinux、是否需 LSPlant 魔改、是否多进程需逐进程部署）

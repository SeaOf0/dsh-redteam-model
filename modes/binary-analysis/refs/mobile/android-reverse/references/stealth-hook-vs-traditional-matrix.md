# Stealth Hook vs Traditional Hook Matrix

> 本矩阵为 `stealth-hook-playbook.md` 的对比附件。**目的**：在选型时一眼看清各方案在 A6/A7 反作弊环境下的存活面。
> 详细 playbook 路径：`references/stealth-hook-playbook.md`

## 方案层速查

| 方案 | 修改 `.text` | 修改页表 | 需 VMA | 触发机制 | 容量上限 | 隐蔽等级 |
|---|:---:|:---:|:---:|---|:---:|---|
| Frida Interceptor | ✅ 改入口 4-16 字节 | 否 | ✅ slab 区 | 跳板陷阱 | 无限 | 低（CRC + maps 双爆） |
| Xposed LSPosed | ✅ 改 ArtMethod | 否 | ✅ | Java 入口替换 | 无限 | 低（maps 暴露） |
| Dobby Inline | ✅ 改入口指令 | 否 | ✅ 跳板 | 跳板陷阱 | 无限 | 低（同 Frida） |
| LSPlant（默认） | ✅ 改 ArtMethod 入口指针 | 否 | ✅ LSPlant 跳板 | 入口指针替换 | 无限 | 中（指针漫游可查） |
| Frida Stalker | 否（执行 slab 副本） | 否 | ✅ slab 区 | PC 在 slab | 无限 | 低（PC 不在原始段） |
| Frida Zymbiote | 否 | 否 | ✅ attach 后 agent | ArtMethod patch | 无限 | 中（仅 Zygote 阶段隐藏） |
| **stealth-hook / HWBP** | ❌ | ❌ | ❌ | CPU 调试 trap | **6 / 4** | **极高** |
| **stealth-hook / PTE+DBI** | ❌ | ✅（置 UXN） | ❌（Ghost Mem） | `do_page_fault` | 无限 | **极高** |
| **stealth-hook / PTE+DBI + LSPlant** | ❌ | ✅ | ❌（Ghost Mem） | 缺页 + 入口不修改 | 无限 | **最高**（指针漫游也通过） |

## 检测面 × 方案矩阵

| 检测手段 | Frida | Xposed | Dobby | LSPlant 默认 | Zymbiote | **stealth-hook** |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `.text` 字节 CRC | ❌ | ❌ | ❌ | ❌（ArtMethod 入口也 CRC） | ❌ | ✅ |
| `/proc/self/maps` 扫描 r-x | ❌ | ❌ | ❌ | ❌ | 中 | ✅（Maps Hide + Ghost Mem） |
| `ptrace(PTRACE_GETREGSET)` 读调试寄存器 | N/A | N/A | N/A | N/A | N/A | ✅（假账本） |
| 满载占坑（写 6 个 HWBP） | N/A | N/A | N/A | N/A | N/A | ✅（写入假账本不触真 CPU） |
| 读写一致性校验 | N/A | N/A | N/A | N/A | N/A | ✅（始终与假账本交互） |
| 越界诱导（写 7 个应 ENOSPC） | N/A | N/A | N/A | N/A | N/A | ✅（模拟 -ENOSPC） |
| `perf_event_open` 主动触发测试 | N/A | N/A | N/A | N/A | N/A | ✅（HWBP 精确 TID+地址，不命中测试函数） |
| 线程名检测 | ❌ | ❌ | ✅ | ✅ | ✅ | ✅（无线程） |
| Frida 端口扫描（27042/27043） | ❌ | ✅ | ✅ | ✅ | ✅ | ✅（无关） |
| Frida agent 内存特征 | ❌ | ✅ | ✅ | ✅ | 部分 | ✅（无关） |
| `TracerPid != 0` | ❌ | ❌ | ❌ | ❌ | ✅ | ✅（零） |
| ArtMethod 入口指针漫游 | — | — | — | ❌（指向匿名 rwx） | ❌ | ✅（Ghost Mem 查无 VMA） |
| Stalker PC 在 slab 区域 | ❌ | — | — | — | — | ✅（PC 在 Ghost Mem） |
| 调用栈回溯（FP/LR） | ❌ | ❌ | ❌ | ❌ | 部分 | ✅（状态机跳跃不污染 LR） |

## 选型决策树（按反检测强度）

```
A0-A3（无 anti-Frida）
    └─→ Frida（开发快，参见 hook-injection-playbook）

A4-A5（壳 / 动态 Dex / 单层 anti-Frida）
    └─→ Frida + anti-frida-playbook（先过检测）
        或 unpack-tool-matrix（脱壳优先）

A6-A7（多层 anti-Frida + 内存 CRC + maps 扫描 + ptrace 反查 + ArtMethod 指针漫游）
    ├─ 取证型（T1-T4，抓数据即可）
    │   └─ HWBP（≤6 点）或 PTE+DBI（>6 点）
    │       └─ 反作弊 ptrace 检测 → 自动含 Ptrace Spoof
    │
    └─ 共存型（让 App 带接管跑）
        ├─ 优先 Frida + anti-frida（成本最低）
        └─ Frida 死路 → stealth-hook + 魔改 LSPlant（Ghost Mem 跳板）
```

## 性能对比

| 方案 | 首次触发开销 | 后续调用开销 | 多核并发安全 |
|---|---|---|---|
| Frida Interceptor | 微秒（JIT） | 几乎为零 | ✅ |
| Inline Hook | 微秒 | 零 | ⚠️ 改指令瞬间竞态 Crash |
| HWBP | 微秒（debug trap） | 零（状态机跳跃后） | ✅（RCU 回收） |
| PTE+DBI | 单次 `do_page_fault`（毫秒级） | 零（克隆页全速原生执行） | ✅（缺页天然隔离） |

## 工程成本对比

| 方案 | 部署难度 | 维护成本 | 工具成熟度 |
|---|---|---|---|
| Frida | 极低（一行 pip） | 低 | 极高 |
| Xposed/LSPosed | 中（需框架） | 中 | 高 |
| Zygisk 模块 | 中（需 Magisk + 模板） | 中 | 中 |
| eBPF（edbg/AndProxy） | 高（Rust + libbpf + 内核 5.4+） | 高 | 中 |
| **stealth-hook（可选外部项目）** | 高（用户自行评估 GitHub 项目、设备适配与部署风险） | 中高（跨设备 / 跨内核需重新验证） | 中（外部社区项目） |

## 适用边界汇总

| 你的目标 | 推荐方案 |
|---|---|
| 无 anti-Frida，需快速脚本 | Frida |
| Java 层 hook + Magisk 环境 | LSPosed via Zygisk |
| 需 hook 高频函数、跨多进程 | Frida + Zygisk（成本最低） |
| A4-A5 脱壳 | 按 `unpack-tool-matrix.md` |
| A6 反作弊（CRC + maps 扫描） | **stealth-hook / HWBP** |
| A7 反作弊（CRC + maps + ptrace + 指针漫游） | **stealth-hook / PTE+DBI + 魔改 LSPlant** |
| 需 Java 层无痕 + 反作弊 ptrace 五步杀 | **stealth-hook / 全栈** |
| 取证型（dump DEX） | `kernel-assisted-re` eBPF 路线（不属本 topic） |
| 取证型（无痕调试，ptrace 被锁） | `kernel-assisted-re` edbg 路线 |

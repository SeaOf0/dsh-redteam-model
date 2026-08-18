# SO Runtime Evidence Playbook

目标：在 Native SO 分析中，把"磁盘上看到的代码"和"运行期真正执行的代码"对齐。加固方案普遍把真实检测/校验逻辑放在加密段、自解密 constructor、匿名可执行映射或 `memfd` 中——直接分析磁盘 SO 会把 patch 打在诱饵代码上，运行时仍然崩溃。本专题收纳运行期取证的硬约束与最小闭环。

> 本专题是 `native-so`、`kernel-assisted-re`、`integrity-pinning`、`anti-frida` 的协作层：当磁盘 SO 不可直接分析、崩溃落在未知映射、或 inline hook 后立刻自毁时，从这些专题升级到这里。

## 目录

- 先回答
- 触发条件
- §1 SO 可分析性门禁（加密 / 壳化 / 自解密 / 运行时重建）
- §2 运行期 dump/fix 操作
- §3 匿名执行证据门禁（匿名 RX / memfd）
- §4 内核级 syscall 证据
- §5 崩溃 / 闪退 7 步闭环
- §6 与其他专题的协作
- 常见偏差
- 最小交付

## 先回答

进入本专题前先确认：

- 磁盘 SO 是否能被 IDA 正常识别（section/dynamic 表完整、函数数量合理）？
- 运行期 `pc/lr` 是否落在磁盘可解释的代码段？
- 目标是否存在 `.text` 自校验或反 Frida（决定 dump 时机与工具路线，见 `integrity-pinning-playbook.md` Native 自校验节、`anti-frida-playbook.md`）？
- 当前防护定级是否 >= A4（A4 以下通常不需要本专题的完整闭环）？

任务类型先锁定（写入 `route-state.json`）：是**共存型**（让 App 带 hook 正常运行）还是**取证型**（抓参数/还原算法）。这决定工具路线——详见 `kernel-assisted-re-playbook.md` 的"用户态 vs 内核手段路线决策"。本专题的证据采集对两种任务都适用。

## 触发条件

任一即触发：

- 防护定级 >= A4 且目标含 Native SO
- IDA 反编译返回仅导入桩 / 空函数 / 极少量函数
- 崩溃 tombstone / logcat 的 `pc/lr` 落在 `[anon:...]` / `memfd` / 未知映射
- inline hook 或 dump 后立即崩溃（`.text` 自校验信号）
- `signal-gates.md` 命中"IDA 仅识别导入桩"或"BR/BLR 跳入无文件名映射"信号

## §1 SO 可分析性门禁（加密 / 壳化 / 自解密 / 运行时重建）

进入 IDA 语义分析前，必须先判定磁盘 SO 是否处于加密、壳化、自解密或运行时重建状态。命中任一特征即触发运行期 dump/fix（§2），在此之前禁止基于磁盘 SO 下函数语义、检测链、patch 候选或动态验证结论。

**为什么需要这一步**：加固/混淆方案常把真实代码加密存放，运行期由 constructor 或 `JNI_OnLoad` 解密到内存或匿名段执行。磁盘 SO 的 `.text` 可能是空壳、stub 或诱饵；分析它得到的"检测函数""加密常量"与运行期实际执行的代码无关，patch 必然失效。

**命中特征**（观察到任一即判定不可直接分析）：

1. ELF section header / dynamic 段 / 字符串表异常或缺失
2. IDA / objdump 仅识别导入桩（`dlopen`/`dlsym`/`JNI_OnLoad` 等少数导出），无业务函数
3. 已知运行 `pc/lr`（来自 tombstone / Frida / logcat）不落在磁盘 SO 的可解释代码段
4. constructor / `JNI_OnLoad` 含解密循环、ELF 重建、`mmap(MAP_FIXED)` 覆盖自身等代码
5. 运行期出现新的可执行段（匿名 RX、`memfd`，见 §3）
6. 壳 wrapper / 加固入口特征（`unpack-tool-matrix.md` 壳识别总表命中，或 DT_INIT 非业务代码而是解压器）

**判定落盘**：把判定结果、命中特征、证据来源写入 `run/so-runtime-evidence-notes.md` 的"SO 可分析性判定"节，并同步到 `route-state.json`。未判定前不得把 IDA 结论升级为 `delivered`。

## §2 运行期 dump/fix 操作

§1 判定不可直接分析后，必须先 dump 运行期 SO 或真实可执行段，重建为可导入 ELF，经校验后才进 IDA。

**dump 时机选择**（按优先级）：

1. **`soinfo::call_constructors` 命中时**——首选。constructor 执行意味着 SO 已映射、解密已发生但业务逻辑未跑，是抢真实 `.text` 的最佳窗口。
2. **`dlopen` / `android_dlopen_ext` 返回后、`JNI_OnLoad` 前后**——次选。当 constructor 窗口太短或 linker 符号不可用时。
3. **maps 稳定后（进程存活）**——适用于稳定进程。风险是检测逻辑可能已执行完，但仍是有效基线。
4. **匿名段单独 dump**——当关键逻辑落在匿名 RX / `memfd` 时（见 §3），按地址范围单独 dump 并对齐基址。

**工具选择**（按场景，均为能力描述 + 开源等价示例）：

| 场景 | 能力要求 | 开源等价示例 |
|---|---|---|
| 进程稳定、SO 已在 maps、不会立刻死亡 | 库模式 dump（按 pid/package + SO 名，自动按 maps 查范围并 rebuild ELF） | root 下 `dd`/自制脚本读 `/proc/<pid>/mem` + maps；或开源内存 dumper（MemDumper 类）的 library 模式 |
| constructor / dlopen 短窗口、快速闪退、大 SO | Frida 命中 linker constructor 后立即触发 dump 的联动脚本 | Frida Python API hook `soinfo::call_constructors`，命中后立刻调内存 dumper |
| 匿名 RX / 拆段 / `memfd` | 手动地址范围 dump | dumper 的 manual 模式（指定 `--start`/`--end`），或直接按 maps 范围读 `/proc/<pid>/mem` |

**校验**（dump 后必须全部通过才进 IDA）：

```bash
file <dumped.so>
readelf -h <dumped.so>
readelf -d <dumped.so>
```

`readelf -h` 应输出合法 ELF 头；`readelf -d` 应能解析动态段。校验失败只能补 dump 时机/工具证据，**禁止回退到直接分析磁盘 SO**。

**落盘**：dump 产物路径、base / 偏移口径、dump 时机、校验命令与结果写入 `run/so-runtime-evidence-notes.md`。后续 IDA 分析、函数范围、pc/lr 归属、patch 候选**全部以 dump 产物为准**。

## §3 匿名执行证据门禁（匿名 RX / memfd）

dump/fix 完成后、IDA 结论前，必须完成匿名执行证据采集。加固方案常把真实检测/校验逻辑解密到匿名可执行内存执行，dump 出的 `.text` 可能仍是诱饵。

**为什么需要这一步**：现代壳会把关键函数搬到 `[anon:.bss]`、`memfd` 或 `mmap(PROT_EXEC)` 申请的匿名段运行，磁盘和常规 dump 都抓不到。不先核对会让分析停在诱饵层，patch 命中诱饵代码，运行时真实检测仍触发。

**必须采集的 6 项证据**（缺项则停止推进、补采，不得用"证据不足"继续下结论或 patch）：

1. **运行期映射落盘**：拉取 `/proc/<pid>/maps`，标明 pid、进程名、采集时机，保留到 `run/` 或 `artifacts/`。
2. **可执行段枚举**：在 maps 中标出所有 `rwx`、匿名 `r-x`（无文件名或 `[anon:...]`）、`memfd`、可疑 `[anon:.bss]` 段。
3. **可执行映射来源**：用内核 syscall 捕获（§4）或检索 `mmap(PROT_EXEC)` / `mprotect(...PROT_EXEC)` / `memfd_create`。当前日志未覆盖这些 syscall 时，本轮只能补采，不得假定没有匿名 RX。
4. **`pc/lr` 归属**：把 tombstone / Frida / logcat 中关键 `pc/lr/callsite` 与 maps 逐项比对，写明落在目标 SO / 系统库 / 匿名 RX / `memfd` / 未知映射。闪退/kill 的 `pc/lr` 未归属前禁止 patch。
5. **跳入匿名段证据**：检查目标 SO 的 `.init_array` / constructor / `JNI_OnLoad` / dlopen 回调 / 直接 syscall wrapper 附近，是否申请匿名内存并 `BR/BLR`/间接调用到匿名段。
6. **匿名段 dump/fix**：若关键逻辑、崩溃 `pc/lr`、检测调用或间接跳转落在匿名 RX / `memfd`，必须 dump 该匿名段，按基址/对齐 fix 后再进函数范围确认。

**处置**：

- 关键 `pc/lr` 均落在 dump 的目标 SO 或系统库，且 maps / syscall / 跳转检查均未发现逻辑跳入匿名 RX -> 继续以 dump 产物进 IDA，在 notes 写"未见关键逻辑落在匿名 RX，后续以 `<so>` dump 偏移为准"。
- 发现关键逻辑在匿名 RX / `memfd` -> dump 该匿名段并 fix，后续函数范围、检测链、patch 候选、`pc/lr` 归属**必须以匿名段产物为准**。
- 只看过磁盘/dump SO、未落盘 maps、未比对 `pc/lr`、syscall 未覆盖 mmap/mprotect/memfd_create -> 停止分析、补证据；禁止标记风险后继续下结论或 patch。

## §4 内核级 syscall 证据

Frida 的 libc hook 看不到内联 `svc #0` 发起的 direct syscall——这是加固检测的常见盲区（绕过 libc 直接 `svc` 发 `kill`/`exit`/`openat`）。当行为发生但 Frida libc hook 未命中，或需要把崩溃 `pc/lr/sp` 归属到具体映射时，必须用内核侧 syscall 捕获。

**为什么需要这一步**：用户态 hook（Frida Interceptor on libc）依赖目标走 libc 调用。加固 SO 用内联 `svc #0` 直接发系统调用，Frida 完全看不到；同时内核侧能在进程死亡的最后一刻把 `pc/lr` 解析到 `so!offset` 或 `anon:base+offset`，这是事后归属崩溃的唯一可靠手段。

**捕获目标**：

- `kill` / `tgkill` / `exit` / `exit_group`（自杀/终止）
- `SIGSEGV` / `SIGTRAP` / `SIGABRT` / `BRK` 触发上下文
- `faccessat` / `openat` / `readlinkat` / `statx`（root/hook/环境路径探测）
- `mmap` / `mprotect(PROT_EXEC)` / `memfd_create`（匿名可执行段来源，§3 依赖）

**记录字段**：syscall 号、参数、返回值、`pc/lr/sp`、线程 pid/tid，以及 `pc/lr` 归属（SO/系统库/匿名 RX/`memfd`/未知）。

**工具能力要求**：KPM / eBPF 类内核 syscall 捕获模块，支持在进程死亡前解析 `pc/lr -> so!offset` 或 `anon:base+offset`。开源等价示例：APatch/KernelPatch + KPM 形态的 syscall filter；或 eBPF uprobe/kprobe 类监控（详见 `kernel-assisted-re-playbook.md` 的 SVC 监控章节）。

**落盘**：采集命令、目标包名/进程名、filter 配置、输出日志路径、关键 syscall 摘录、与 Frida/logcat 的时间线对应关系，写入 `run/so-runtime-evidence-notes.md`。若证明 direct syscall 命中而 Frida libc hook 未命中，明确记录"这是绕过 libc hook 的 direct syscall"。

## §5 崩溃 / 闪退 7 步闭环

闪退 / 崩溃 / 退出案例进入 SO 静态分析后，必须按以下顺序推进。该顺序是硬约束，不是建议——前置步骤未完成时，后续步骤的分析结论不成立。

**为什么强调顺序**：崩溃根因常藏在加载链最早期（constructor 自解密、`.init_array` 反检测、匿名段跳转）。从崩溃点局部函数往回猜会遗漏入口处的检测，导致 patch 治标不治本，崩溃在同一调度链内迁移。

1. **syscall / pc-lr-sp 定位**：用 §4 捕获 syscall 与 `pc/lr/sp`，确认落点在 SO / 系统库 / 匿名 RX / `memfd` / 未知映射。
2. **SO 可分析性判定 + dump/fix**：按 §1 判定目标 SO 是否加密/壳化/自解密/运行时重建；命中则按 §2 dump/fix，禁止直接分析磁盘 SO。
3. **入口分析**：IDA 导出 dump/fix 产物，先分析 `.init` -> `.init_array`/constructor -> `JNI_OnLoad`/`RegisterNatives`/JNI bridge，记录入口函数范围和关键调用。
4. **匿名执行证据**：完成 §3 的 6 项证据；关键逻辑在匿名段时先 dump/fix 匿名段。
5. **CRC / 完整性校验检查**：按 `integrity-pinning-playbook.md` 的 Native 自校验节，检查自身 `.text` / libc / libart / linker / dex / 签名的 CRC 或逐字节校验，确认失配执法路径。
6. **崩溃函数完整分析**：确认崩溃点所在函数范围（见 `native-so-playbook.md` 的"函数范围确认"节），完整分析该函数、上游调用者、下游关键调用、fatal 分支、返回值/状态码和副作用。
7. **patch 与验证**：步骤 1-6 完成并写入 notes 后，才允许提出 patch 候选或恢复动态验证。动态验证在同一 SO/函数/检测链/调度链内失败累计 3 次后，按 `failure-protocol.md` 的"动态-静态 pivot 专项"回到完整静态闭环。

**普通检测链**（非崩溃场景）的推荐分析顺序见 `native-so-playbook.md`；本节仅约束崩溃/闪退路径。

## §6 与其他专题的协作

- **`native-so`**：函数范围确认、ELF/Linker/GOT-PLT 机制、RegisterNatives 定位、ARM64 调用约定——这些静态分析能力是本专题 dump/fix 后进 IDA 的基础。
- **`kernel-assisted-re`**：§4 的 syscall 捕获、§3 的匿名段证据、共存型 vs 取证型的工具路线决策——内核手段是本专题的证据来源之一。
- **`integrity-pinning`**：§5 步骤 5 的 CRC/完整性校验识别与处置（self-.text/libc/libart）归属那里。
- **`anti-frida`**：dump 时机选择、constructor hook 的 Frida spawn/attach 异常诊断闭环——Frida 是本专题 dump 的常用载体。
- **`dex-loader` / `unpack-tool-matrix`**：DEX 层脱壳决策不属本专题；本专题聚焦 SO 层运行期证据。当目标同时有壳（DEX）和加密 SO 时，先按 unpack-tool-matrix 处理 DEX，再按本专题处理 SO。

## 常见偏差

- **磁盘 SO 可读就直接分析**：IDA 能打开不等于代码是真实执行的；§1 的命中特征任一条出现就要走 dump/fix。
- **dump 出 `.text` 就当作真实代码**：跳过 §3 匿名执行检查会让分析停在诱饵层；必须核对 `pc/lr` 归属和匿名映射。
- **从崩溃点局部函数往回猜**：跳过 §5 步骤 3 的入口分析会遗漏 constructor/`.init_array` 里的早期检测。
- **Frida libc hook 未命中就下"无该行为"结论**：direct syscall（内联 `svc #0`）绕过 libc，必须用 §4 内核侧捕获。
- **把 helper / 容器类误记为检测入口**：入口分析完成后要区分检测函数与辅助函数（字符串解码、日志、加密 helper）。
- **动态失败后继续叠加 hook/patch**：同 SO/函数/调度链内动态失败 3 次必须回静态闭环，不得用叠加变量绕过止损。

## 最小交付

- `run/so-runtime-evidence-notes.md`，包含：
  - SO 可分析性判定（命中特征、证据来源）
  - dump/fix 产物路径、时机、base/偏移口径、校验结果
  - 匿名执行证据 6 项结论（有/无匿名 RX、段地址范围与权限、来源 syscall、`pc/lr` 归属）
  - syscall 证据摘要（关键 syscall、`pc/lr` 归属、与 Frida/logcat 时间线）
  - 崩溃 7 步闭环进度（每步完成状态）
- 至少一条从入口到崩溃点/检测点的调用链证据
- patch 候选（如有）必须标注基于哪个产物（dump SO / 匿名段）的偏移
# x64dbg 调试方法论 + 插件生态 + 脚本系统

> 定位：`x64dbg-reversing/SKILL.md` 是 MCP 命令速查（19 类工具），本篇补**调试方法论 + 插件生态 + 脚本系统**。
> 与 `references/unpacking-oep-iat.md`（脱壳方法论）衔接：本篇讲「断点怎么选/插件怎么配/脚本怎么写」，那篇讲「壳怎么脱、OEP 怎么找、IAT 怎么修」。
> 工具按检测制：x64dbg 属 Windows 侧补充工具集（需 Windows 环境），缺失如实标注。

---

## 1. 断点方法论（软件/硬件/内存断点选择）

### 1.1 三类断点对比

| 类型 | 实现 | 数量/代价 | 适用 |
|---|---|---|---|
| **软件断点**（INT3/0xCC） | 改目标字节为 0xCC | 无限，但改代码（触发自校验） | 常规断点，非自校验样本 |
| **硬件断点**（DR0-DR3） | 调试寄存器 | 仅 4 个，不改代码 | 自校验/只读代码、执行断点、OEP 找法 |
| **内存断点**（PAGE_GUARD） | 改页保护 | 每页 1 个，改页属性 | 盯「谁读写这块内存」 |

选型判据：

```text
- 样本会自校验代码（读自己字节算哈希）→ 不用软件断点，用硬件断点。
- 要断「执行到某地址」→ 硬件执行断点（不改代码）。
- 要断「谁写了某变量/缓冲区」→ 内存写断点。
- 常规 API 断点（GetDlgItemTextA 等）→ 软件断点即可。
```

### 1.2 条件断点

```text
# 命令栏（x64dbg 表达式）
bp 0x401000, eax == 0          # 仅 eax==0 时断下
bpc 0x401000, [esp+4] == 1     # 条件断点（内存/寄存器比较）
# MCP：x64dbg_breakpoints set_condition bp_id=1 condition="EAX != 0"
```

判据：条件命中即断，未命中不打断——用于「循环里第 N 次/某值出现才停」。

### 1.3 日志断点（不中断，记录值）

```text
# 断下时只记录不暂停
bp 0x401000, 0, "log eax={x@eax} esi={s@esi}"
# MCP：x64dbg_breakpoints set_log bp_id=1 log="Value at ESP+4: {d@RSP+4}"
```

判据：日志输出参数/返回值序列，用于「不暂停地 trace 高频调用」。
> 条件/日志断点的 `{x}/{d}/{s}/{@}` 格式说明见 `x64dbg-reversing/SKILL.md`「Breakpoint Conditions」。

---

## 2. 插件生态

### 2.1 xAnalyzer（自动注释）

- 定位：自动给函数调用/参数加注释，快速读懂反汇编。
- 用法：加载插件后，命令 `xanalyzer` 或插件菜单对当前函数运行。
- 输出解读：`call GetProcAddress` 旁自动标注 API 名与参数含义，函数参数被注释。

### 2.2 ScyllaHide / TitanHide（反反调试）

| 插件 | 定位 | 用法 |
|---|---|---|
| ScyllaHide | 用户态隐藏调试器（PEB/NtQuery/时序） | 插件菜单选 Profile（VMProtect/Themida/默认），开启隐藏 |
| TitanHide | 内核驱动隐藏（SSDT/调试对象） | 安装内核驱动，全局隐藏调试器 |

输出解读：隐藏后样本的反调试检测（IsDebuggerPresent/PEB.BeingDebugged/NtQueryInfo）返回「非调试」值。
判据：样本不再「检测到调试即退出」，能进入目标逻辑（与 §1 断点配合）。

### 2.3 Baymax Patch Tools（补丁）

- 定位：把调试期补丁固化为可分发补丁器。
- 用法：调试定位补丁点 → Baymax 生成补丁（异常/内存断点补丁）。
- 输出解读：产出独立补丁工具，客户可离线应用（配合 software-cracking 补丁章）。

### 2.4 Scylla / Snowman

- Scylla：IAT 重建（见 `unpacking-oep-iat.md` §4）。
- Snowman：x64dbg 内反编译插件，快速伪代码（见 tools-dynamic.md x64dbg 节）。

---

## 3. 脚本系统（x64dbg 脚本）

### 3.1 语法要点

```text
- 脚本文件 .txt，一行一条命令；用 Script 面板加载运行。
- 断点：bp / bphws / bpm；执行：run / StepInto / StepOver / stop。
- 变量：$var 赋值（mov $x, eax），比较 cmp + 条件跳转 je/jne。
- 标签：labelname: ；跳转：jmp labelname。
- 日志：log "..."。
```

### 3.2 常用脚本

```text
// 1) 批量下 API 断点 + 记录参数
bp GetDlgItemTextA
bp GetWindowTextA
bp MessageBoxA, 0, "log hwnd={x@[esp+4]} txt={s@[esp+8]}"
run

// 2) 条件循环：运行到 eax 匹配
start:
run
cmp eax, 0x1234
jne start
log "hit eax=0x1234 at {x@eip}"
pause

// 3) 硬件断点找 OEP（配合 unpacking-oep-iat.md §2.1 ESP 定律）
bphws [esp], r, 4      // 对 pushad 后的 ESP0 下硬件读断点
run
StepInto
StepInto
// 单步到 jmp OEP 处，记录 OEP
```

判据：脚本运行后按预期停点/记录，产出可复用的调试步骤（脚本留存并入证据）。

---

## 4. 与 unpacking-oep-iat.md 的衔接指针

```text
- 找 OEP 用「硬件断点 + 内存断点」方法论 → unpacking-oep-iat.md §2（ESP 定律/单步跨节）。
- dump + IAT 修复用 Scylla → unpacking-oep-iat.md §4（Scylla 一键链 + 三法对比）。
- 反调试对抗用 ScyllaHide → 本篇 §2.2 + anti-debugging.md。
- 补丁固化用 Baymax → 本篇 §2.3 + software-cracking 补丁章。
```

---

## 来源与延伸

- x64dbg MCP 命令速查（19 类）：`../SKILL.md`。
- 脱壳方法论（OEP/IAT/B1 判据）：`references/unpacking-oep-iat.md`。
- 反调试技术全解：`methodology/anti-debugging.md`（ScyllaHide/TitanHide 背景）。
- 补丁制作（Baymax/策略）：`methodology/software-cracking/SKILL.md`。
- xAnalyzer：https://github.com/ThunderCls/xAnalyzer ；ScyllaHide：https://github.com/x64dbg/ScyllaHide
- TitanHide：https://github.com/mrexodia/TitanHide ；Baymax：https://github.com/sicaril/Baymax-Patch-toOLS

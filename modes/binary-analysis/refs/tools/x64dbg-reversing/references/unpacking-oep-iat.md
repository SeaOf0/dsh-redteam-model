# Windows 壳脱壳：OEP 寻找方法体系 + IAT 修复各法对比

> 定位：`x64dbg-reversing/SKILL.md` 是 x64dbg-MCP 命令速查（怎么下断点/读内存），本篇是**方法论**——
> 回答「壳在哪、怎么找 OEP、IAT 怎么修、修完怎么判合格」。与本模式 Gate B1「还原完整性三验」直接挂钩。
> 补充工具集按检测制表述：x64dbg/Scylla/ImportREC 属 Windows 侧补充工具，开工 `command -v` 探测（缺失时按 playbook 四级兜底）。

---

## 0. 何时需要本篇

- 样本 `file` 判定为 PE，但节区熵值异常高（>7.0）、入口点不在 `.text` 而在异常节（`.upx0/.vmp0/.aspack`）、导入表仅剩 `LoadLibrary/GetProcAddress` 等 1~3 个 API —— 判定为加壳。
- 目标不是「跑起来看行为」（那是动态分析），而是**还原真实程序**供深入分析与 code-audit：脱壳 → IAT 修复 → 三验。

**整体管线**（与 playbook「脱壳与还原」一致）：
壳识别 → OEP 定位 → 内存 dump → IAT 重建 → 验证可运行性 → 三验通过后交 code-audit。

---

## 1. 壳识别（先分清是哪类，再选 OEP 找法）

| 壳类型 | 特征 | OEP 找法侧重 |
|---|---|---|
| 压缩壳（UPX/ASPack/FSG/MPRESS/nsPack） | 入口 `pushad`/`pushfd`，节区熵高，导入表残缺 | ESP 定律 / pushad-popad 特征（见 §2） |
| 加密/虚拟化壳（VMProtect/Themida） | `.vmp0/.vmp1`、`.themida` 节；VM 入口 `push reg` 全量入栈 + 间接跳转 dispatcher | 内存/硬件断点 + 单步跨节 + handler 识别（见 native-vm-devirt.md） |
| 打包壳（自定义 stub） | 无已知节名，入口为解密器 | 内存断点盯「写入后首次执行」+ 单步 |

识别命令（检测后使用，mac/linux 用 readelf/objdump，Windows 用 x64dbg/DIE）：

```bash
# 节区熵值（python3 + pefile 或直接 binwalk -E）
readelf -S sample.exe | grep -E "\.upx|\.vmp|\.aspack|\.themida"
# 导入表残缺度（只 1~3 个 API 是强信号）
objdump -p sample.exe | sed -n '/DLL Name/,/^$/p'
```

判据：入口点所在节名 + 节区熵 + 导入表条数三者交叉，命中 ≥2 即判「加壳」，登记壳类型进 evidence-index.md。

---

## 2. OEP 定位方法体系

OEP（Original Entry Point）= 壳 stub 解压/解密完成后跳转回的真实程序入口。找 OEP 的本质是**定位「壳结束、真实代码开始」的那次长跳转**。各法按「适用壳类型 + 判据」成体系：

### 2.1 ESP 定律（压缩壳首选）

原理：32 位压缩壳入口普遍以 `pushad`（0x60，把 8 个通用寄存器压栈，ESP 下降 0x20）开头，结束时 `popad`（0x61）+ `jmp OEP`。因此 `pushad` 之后栈顶地址 `ESP0` 就是「壳保存现场」的唯一地址——在 `ESP0` 上放一个**硬件读断点**，当 `popad` 弹栈读到同一地址时断下，再单步数次即到 `jmp OEP`。

步骤（x64dbg 32 位目标用 x32dbg）：

```text
1. 载入样本，停在 EP（入口点），确认首条是 pushad/pushfd。
2. 单步执行 pushad（F7），记录此刻 ESP 值 = ESP0（如 0x0019FF6C）。
3. 命令栏对 ESP0 下硬件断点（读访问）：
   bp [ESP0], r, 4        # 或 GUI：右键堆栈地址 → 断点 → 硬件,访问
   （x64dbg MCP：x64dbg_breakpoints set_hardware address="ESP0" type=read）
4. F9 运行，断下时通常已到 popad 之后 1~2 条。
5. F8 单步，看到 jmp eax / jmp [reg] 跳向远处高地址（如 0x00401000 附近）即 OEP 跳转。
6. 跳转处下软件断点，F7 进入，记录 EIP = OEP。
```

判据：断点命中位置紧跟 `popad/popfd`，其后是「无条件跳向 `.text` 或导入密集区」的长跳转；跳转目标处可见标准程序 prologue（`push ebp; mov ebp,esp` 或 MSVC `sub esp,...`）。

适用壳：UPX、ASPack、FSG、MPRESS、nsPack 及多数「pushad 开头」的压缩壳。
不适用：加密壳/虚拟化壳入口不是标准 pushad（VMProtect 是连续 push 寄存器 + dispatcher），ESP 定律需配合 handler 识别。

### 2.2 pushad-popad 特征法（ESP 定律的变体）

直接搜索字节模式定位「成对的 pushad…popad+jmp」：

```text
x64dbg 搜索字节序列（AOB）：60 ... 61 E9 / 60 ... 61 FF E0
GUI：右键 → 搜索 → 命令 → findpattern
MCP：x64dbg_search pattern="60 ?? ?? ?? 61 E9"
```

原理与 ESP 定律同源，但**先静态定位再断点**，适合入口不是 pushad、但 stub 内部存在 pushad/popad 块的壳。
判据：命中的 `61` 后紧跟 `E9 xxxxxxxx`（近跳）或 `FF E0`（jmp eax）或 `FF 25`（jmp [mem]），跳转目标即 OEP 候选。

### 2.3 内存断点法（写断点盯「解压落点」）

原理：壳 stub 解密/解压后会把真实代码写入目标节区（常是 `.text` 或自解压节），**在目标节区入口设内存写断点**，写完成即意味着真实代码就绪，随后在「写入后首次执行」处断下即 OEP。

```text
1. 观察壳 stub 的目标地址范围（如 jmp 前的 lea/edi 指向 0x00401000）。
2. 对 0x00401000 设内存写断点（F2 → 硬件/内存断点 → 写）。
   MCP：x64dbg_breakpoints set_memory address="0x401000" size=4
3. F9，断在「首次写入 0x00401000」处 —— 此时解密已完成或进行中。
4. 继续 F9 数次或单步，直到执行流进入 0x00401000 区（即从壳代码跳进真实代码）。
5. 入口即 OEP。
```

判据：写断点命中后，执行流「跨节跳转」从壳节进入真实代码节；真实代码区首条为标准 prologue。
适用壳：带自定义解密 stub 的打包壳、以及需要「盯数据落点」的加密壳第一段。

### 2.4 硬件执行断点 + 单步跨节

原理：硬件断点用 DR0-DR3 调试寄存器，不改代码（对抗自校验壳），可设「执行」断点在真实代码节首地址。

```text
1. 静态判定真实代码节（通常 .text 且熵值正常）。
2. 对 .text 节首地址设硬件执行断点（右键 → 断点 → 硬件,执行）。
   MCP：x64dbg_breakpoints set_hardware address="0x401000" type=execute
3. F9，执行流一旦进入 .text 即断下，即 OEP。
```

判据：断点命中时 EIP 落在真实代码节首部，且此前执行位于壳节。
适用壳：配合单步用于「ESP 定律失效」的自定义壳；硬件断点仅 4 个，够用。

### 2.5 单步跟踪法（最后兜底）

原理：无任何结构特征可依时，逐指令单步（F7），记录「跨节长跳转」。可用「单步跨节」思路加速：只在「大跳转/跨节跳转」处停留。

```text
1. 载入停在 EP，打开「跟踪」。
2. F7 单步，重点关注 jmp/call 的目标是否跨节（从一个节跳入另一节）。
3. 一旦看到 jmp 跳向熵值正常的代码区，即 OEP 候选。
4. 下断点验证：跳转目标可被反汇编为合理 prologue。
```

判据：跳转目标节区熵值正常 + 可反汇编出标准函数头 + 后续有 API 调用。
适用壳：所有找不到「pushad/写断点」特征的壳；最慢，作为兜底。
风险：加密壳在 OEP 附近有反调试/自校验，单步可能触发反跟踪（结合 ScyllaHide 隐藏调试器）。

### 2.6 各法适用性速查

| 方法 | 成本 | 适用壳 | 判据 |
|---|---|---|---|
| ESP 定律 | 低 | 压缩壳（UPX/ASPack/FSG/MPRESS/nsPack） | 断点命中 popad 后紧接 jmp OEP |
| pushad-popad 特征 | 低 | 同上（非 EP 的 pushad 块） | 61 后紧跟 E9/FF E0/FF 25 |
| 内存写断点 | 中 | 自定义解密 stub | 写断点命中后跨节进入真实代码 |
| 硬件执行断点 | 中 | 加密壳/自校验壳 | 执行流跨节命中真实代码节首 |
| 单步跟踪 | 高 | 兜底 | 跨节跳转 + prologue 合理 |

---

## 3. 内存 dump

定位到 OEP 后，把进程内存镜像写盘（此时真实代码已解压、但 IAT 可能未修复）。

```text
1. 停在 OEP。
2. x64dbg：Scylla 插件 → Dump（或 OllyDump 思路：右键 → 转储）→ 选择「修正镜像大小」。
   MCP：x64dbg_dumping dump_module base="0x400000"
3. 记录 dump 的 ImageBase（默认 0x00400000，ASLR 样本用实际基址）。
```

判据：dump 文件 `file` 仍识别为 PE；用 pefile 打开能读到节区表；dump 后立即接 §4 IAT 重建（dump 与 fix 需配套，否则 IAT 指针仍是壳解析出的运行时地址）。

---

## 4. IAT 修复各法对比

### 4.1 为什么 dump 后 IAT 要修

壳为了隐蔽，常把导入解析逻辑私有化：dump 出的内存里，IAT（Import Address Table）里的指针可能是「壳自己解析后的运行时地址」或「指向壳 stub 的加密指针」，而非标准导入目录格式。直接运行 dump 会因「导入目录不完整/指针无效」而失败。IAT 重建 = 重新生成标准 PE 导入目录 + 正确填充 API 地址。

### 4.2 IAT 重建算法（手修视角，理解本质）

PE 导入链路：`IMAGE_IMPORT_DESCRIPTOR`（每个 DLL 一条）→ `OriginalFirstThunk`（INT，导入名表）→ `FirstThunk`（IAT，运行时地址）→ `Name`（DLL 名）。

重建步骤（可用 python3 + pefile/lief 脚本兜底实现，playbook 脚本兜底层）：

```text
1. 定位 IAT：找「指向已加载 DLL 代码区的一串指针数组」。特征：连续 dword/qword，
   每个值都落在 kernel32.dll/ntdll.dll/user32.dll 等模块的导出地址范围。
   Scylla 的「IAT Autosearch」就是自动扫描满足此特征的指针数组。
2. 解析 thunk：对每个 IAT 指针，反查它属于哪个 DLL 的哪个导出（按地址→导出名）。
   ordinal 导入（无名字）需按「DLL + ordinal」重建。
3. 重建导入目录：为每个涉及 DLL 生成 IMAGE_IMPORT_DESCRIPTOR，
   写回 INT（名字表）+ IAT（地址表）+ DLL 名，并修正数据目录表第 2 项（导入表）RVA/Size。
4. 重定位：若 dump 基址 ≠ 原 ImageBase，修正所有绝对地址（Scylla 的「Fix Dump」一并处理）。
```

判据（重建成功的最低标准）：每个 thunk 都解析为「已知 DLL 的已知导出名」，无「指向壳节/堆内存」的悬空指针。

### 4.3 三法对比：ImportREC vs Scylla vs 手修

| 维度 | ImportREC（经典，32 位） | Scylla（x64dbg 插件，x86/x64） | 手修（脚本） |
|---|---|---|---|
| 定位 IAT | 手动输入 RVA/Size，或「自动搜索」 | IAT Autosearch 自动扫描 | 自己写 pefile 扫描指针数组 |
| 解析 thunk | Get Imports 解析 | Get Imports（红色=未解析需人工补） | 自写地址→导出反查 |
| 支持 x64 | 否（主要 32 位） | 是 | 是（脚本无位数限制） |
| 处理 anti-dump/擦除 IAT | 弱 | 中（可配合 Get Imports 补漏） | 强（可完全自定义） |
| 重定位 | 需手动 | Fix Dump 一并处理 | 自写重定位表重建 |
| 适用场景 | 老 32 位压缩壳 | 现代壳、x64 样本、Themida/VMProtect 常规段 | 前三者失败时的精确兜底 |

结论：**优先 Scylla（x64dbg 内一键链），ImportREC 作 32 位老样本备选，手修作三验失败时的兜底**。

### 4.4 Scylla 插件用法（x64dbg 内，Themida/VMProtect 通用）

```text
1. 停在 OEP。
2. Plugins → Scylla（或命令 scylla）。
3. OEP 栏填真实 OEP（自动带出当前 EIP，核对）。
4. 点「IAT Autosearch」→ 自动定位 IAT（记下 Size）。
5. 点「Get Imports」→ 解析 thunk；**红色条目 = 未解析，逐条核对/手改**。
6. 点「Dump」→ 转储进程内存为 dump.exe。
7. 点「Fix Dump」→ 选刚生成的 dump.exe，Scylla 写入新导入目录 + 重定位。
8. 运行 dump_fixed.exe 验证。
```

MCP 对应（命令速查在 SKILL.md）：`x64dbg_dumping fix_iat original_iat="<IAT 地址>"` 只是把已定位 IAT 修复，方法论上仍需先 Autosearch/Get Imports 定位。

---

## 5. 常见壳手工脱壳路线（分篇）

### 5.1 UPX（-d 优先，失败走 ESP 定律）

```bash
# 首选：UPX 自带解压（检测到 upx 时）
upx -d sample.exe -o unpacked.exe
# 若被篡改 magic 头（upx 脱壳失败）：
# 手工：ESP 定律（§2.1）→ OEP → dump → Scylla fix
```

判据：`upx -d` 退出码 0 + 输出文件 `file` 为正常 PE + 入口点回到 `.text`；篡改头样本走手工，OEP 判据同 §2.1。

### 5.2 ASPack

```text
入口 pushad → ESP 定律（§2.1）→ OEP（典型 0x0040xxxx）→ dump → Scylla。
特征：节名 .aspack/.adata，EP 前几条为 pushad + call（自解密 stub）。
```

### 5.3 FSG（Fast Small Good）

```text
体积极小、stub 短。入口常是 jmp 直接进解密 stub，可能无标准 pushad。
用 pushad-popad 特征法（§2.2）搜 60…61；或用内存写断点（§2.3）盯解压落点。
判据：跳转目标为导入密集的真实入口。
```

### 5.4 MPRESS

```text
压缩壳，节名 .MPRESS1/.MPRESS2。入口 pushad 特征明显，ESP 定律直接命中。
OEP 后 IAT 常需重建（MPRESS 会重排导入）。
```

### 5.5 nsPack

```text
节名 .nsp0/.nsp1。入口 pushad + 自解密。ESP 定律 + 内存写断点（§2.3）组合。
判据：跨节跳入 .nsp 之外的真实代码区。
```

---

## 6. 与 Gate B1「IAT 有效性三验」的判据衔接

playbook 的 Gate B1 三验 = **dex 校验 / IAT 有效性 / 可运行性**（Windows 样本聚焦后两项）。「IAT 有效性」不是「Scylla 点了 Fix」就算过，必须落到可核验判据：

| 验法 | 判据 | 对应 IAT 恢复质量 |
|---|---|---|
| **IAT 指针域核验** | 每个 IAT thunk 反查落在「对应 DLL 的导出地址空间」，无指向壳节/堆/悬空指针 | Scylla「Get Imports」无红色未解析项；手修后 pefile 遍历 IAT 全部命中导出 |
| **导入目录结构核验** | 数据目录表第 2 项指向合法 `IMAGE_IMPORT_DESCRIPTOR` 链，DLL 名/INT/IAT 三字段齐备 | ImportREC/Scylla 重建后 pefile 能完整枚举 `DIRECTORY_ENTRY_IMPORT` |
| **可运行性核验** | dump_fixed.exe 在隔离环境可加载、入口可执行、依赖 DLL 无缺失 | 运行不报「0xc0000005/0xc0000135（缺 DLL）」；`GetProcAddress` 依赖的函数全部解析 |

**质量对应关系**（各验法验证哪种恢复质量）：

- 「IAT 指针域核验」最严——它直接验证「每个 API 地址是否真实有效」。Scylla Autosearch 若漏掉被壳抹除的 thunk，这一验会红——需手修补齐。
- 「导入目录结构核验」验证「重建的导入目录格式是否合法」——ImportREC 手选范围错误、或 Scylla 未 Fix 时，这一验不过。
- 「可运行性核验」是最终集成验——前两验过但可运行性不过，说明存在未覆盖的导入（如延迟导入 delay-load、或 TLS 回调里的动态解析），需回查。

**三验不过的处置**（persona 硬规则）：还原标「疑似」，禁止在残缺产物上下结论；缺哪一验就在还原验证记录（`artifacts/<sha256>-restore-verify.md`）里注明缺口，逐项回修（优先手修 IAT 补齐指针域）。

---

## 7. 常见失败与对策

| 症状 | 原因 | 对策 |
|---|---|---|
| ESP 定律断点不命中 | 入口非 pushad（加密壳） | 换 §2.3/2.4，识别 handler（native-vm-devirt.md） |
| Scylla Get Imports 大量红色 | IAT 被壳抹除/加密 | 手修：按「IAT 指针域核验」逐个反查导出补名 |
| dump 运行报 0xc0000135 | 导入 DLL 缺失 | 核对导入目录 DLL 名，补齐运行环境 |
| dump 运行报 0xc0000005 | IAT 指针悬空 | 重跑 §6 指针域核验，定位悬空 thunk 手修 |
| 单步触发反跟踪 | 壳带反调试 | ScyllaHide 隐藏调试器（profile 选对应壳） |

---

## 来源与延伸

- x64dbg + Scylla 用法：与 `x64dbg-reversing/SKILL.md`（MCP 命令）配套；ScyllaHide 反调试隐藏见 `methodology/anti-debugging.md`。
- VMProtect/Themida 的 VM 段 devirtualization（非本文件「常规段脱壳」范围）：`methodology/reverse-engineering/references/native-vm-devirt.md`。
- VMProtect 2 脱壳 IAT 修复流程参考：http://www.qwbw.cn/news/101858.。
- 手修 IAT 脚本兜底：playbook 四级兜底「脚本兜底」层（python3 + pefile/lief）。

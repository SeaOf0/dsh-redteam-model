# Deobfuscation Playbook

目标：把混淆从"看不懂的代码"恢复到"可分析的逻辑"，不试图追求完美去混淆，而是让关键路径可读。

## 先回答

- 混淆类型是什么（FLA / BR / SUB / BCF / icall / 自定义 / 组合）
- 混淆保护产品是什么（OLLVM / Hikari / Arkari / Goron / BlackObfuscator / 自定义）
- 关键函数是否可以绕过混淆直接在运行时抓取输入输出
- 是否需要静态还原还是运行时 hook 即可完成目标

## 高风险信号

- 大量 switch-case / if-else 形成分发器（FLA）
- `cmov` / `CSEL` 条件传送被滥用（BR）
- 简单表达式被替换为复杂等价表达式（SUB/MBA）
- 控制流图中出现大量不相关跳转
- 字符串在静态分析中全部为密文
- dexlib2 反编译后方法体出现重复 basic block
- `0x9E3779B9` 常量（xxtea）
- Arkari 风格间接跳转（查表 + 全局数组 DestBBs）
- `BLR Xn` 间接调用 + 函数指针表加密（icall）
- `.bss` 段全局变量不透明谓词（BCF）

## OLLVM 类型识别

### 混淆产品识别

```
SO 层 switch-case 分发器 + .bss 全局变量 → 标准 OLLVM
SO 层 + 间接跳转查表 + 全局数组 DestBBs → Arkari（检查 L0-L3 级别）
SO 层 + BLR Xn 间接调用 + 函数指针表 → Goron / OLLVM icall
SO 层 + 常见于手游 → 优先考虑 Hikari
Dalvik 层 + dexlib2 重复 basic block → BlackObfuscator（不是 SO 层问题）
```

### FLA（控制流平坦化）

特征：
- 一个大型 switch-case 或 if-else 链作为分发器
- 一个状态变量驱动分发
- 原 basic block 保留但执行顺序被打乱
- ARM64 关键指令：`MOV/MOVK` 组合常量，`CSEL` 条件赋值，`B dispatcher`
- MOVK 组合常量是**按位 OR** 不是加法：`MOV W8, #0xA6FB; MOVK W8, #0x7986, LSL#16` → `(0x7986 << 16) | 0xA6FB`

### BR（间接跳转）

ARM64 四种模式：
1. **无条件 BR**：无 CSEL，直接计算地址
2. **单 CSEL**：一个 `CSEL` + `BR Xn`
3. **多 CSEL**：链式 `CSEL` + `BR Xn`
4. **跳转表**：`ADRL + LDRSW + ADD + BR`

识别要点：`CSEL`/`CSET` 指令大量出现，不透明谓词（如 `x * x >= 0`），`CMP + CSEL + LDR + ADD + BR` 序列

### BCF（虚假控制流）

特征：`.bss` 全局变量不透明谓词（如 `y >= 10 && ((x-1)*x & 1) != 0` 恒假），虚假条件分支

### SUB（指令替换）

特征：简单运算→复杂等价表达式（MBA），位运算组合替代 add/sub/xor

### ARM32 差异

- NOP = `0x00 0x00 0xC0 0x46`（Thumb2），ARM64 NOP = `0x1F 0x20 0x03 0xD5`
- 条件标志在 CPSR 而非独立 NZCV 寄存器，Unicorn 中读 CPSR bits[31:28]
- 状态常量 32 位即可，无需 MOVK 组合（ARM32 用 MOVW + MOVT）
- BCF .bss patch 方法相同，但指令级 patch 编码不同（ARM32 无 x86 的 0x8B/0xB8 模式）
- Unidbg 默认 ARM32 环境，需显式 `AndroidEmulatorBuilder.for64Bit()` 指定 ARM64

### 自定义变体

- **Arkari**：4 级加密（字符串加密 + FLA + BCF + SUB），间接跳转使用查表
- **BlackObfuscator**：Dalvik 字节码级混淆，方法体被切片重组
- **Hikari**：OLLVM 移动端移植版，常见于手游 SO
- **Goron**：基于 LLVM 9.0，icall（间接调用）+ indbr（间接分支）特征

## 操作顺序

### 1. 先判断混淆类型和保护等级

- 用 IDA/Ghidra 查看目标函数的控制流图
- FLA：图呈"汉堡包"结构，顶部大分发器 + 平行 block
- BR：基本块间多出大量条件跳转 / CSEL
- BCF：.bss 全局变量 + 不透明谓词条件分支
- SUB：表达式异常复杂但控制流正常
- 组合：同时存在多种特征

### 1b. 自动化还原工具（跨类型）

D-810/deflat 脚本不适配魔改变体时，可用基于 `capstone`/`unicorn`/`keystone-engine` 的自动化还原脚本对 CFF（控制流平坦化）、间接跳转、dispatcher 状态机做整体还原。开源等价示例：OLLVM_Deobfuscator 类工具，输入 SO + 函数起止地址（hex），按 `--type auto|cff|indirect` 输出还原后 SO，再重新导入 IDA 与 `pc/lr/callsite` 交叉验证。

使用约束：

- 先完成"函数范围确认"（见 `native-so-playbook.md`），还原脚本要吃准确的函数起止地址，范围错则还原错。
- 在语义分析、检测链归纳、patch 候选之前先还原——不得只看混淆伪代码局部结论就继续 patch。
- 魔改变体（状态变量宽度变化、寄存器预加载、异常跳转表）需要改工具副本代码适配：**只改项目副本，不改工具原始仓库**，并记录改动文件、算法假设、输入/输出 SO、函数范围、还原前后关键跳转变化与失败边界。
- 还原结果必须重新导入 IDA 或重新导出关键函数文本，与 Frida/内核 syscall/logcat 的 `pc/lr/callsite` 交叉验证，不能单独作为结论。

macOS/Windows 上 `keystone`/`unicorn` 安装失败时，优先用 Linux/WSL 跑还原脚本，再把输出 SO 带回 IDA。

### 2. BCF 还原

工具优先级：
1. **D-810 插件**（首选）：F5 刷新即自动移除不透明谓词
2. **.bss 段只读 patch**（通用性强）：将 .bss 段所有 dword 设为固定常量（如 2）并设只读，IDA 常量传播自动消除虚假分支 → 完整脚本见 `run/bcf-bss-patch-template.py`
3. **指令级 patch**（仅 x86）：将 `mov reg, [mem]` 替换为 `mov reg, 0`（0x8B→0xB8+reg_code），ARM 版本用方法 2 即可

### 3. 字符串加密去混淆

四种方法：
1. **返回值 hook**：直接 hook 字符串解密函数，打印解密后结果
2. **高交叉引用函数识别**：字符串解密函数通常被大量调用，通过 xref 数量定位
3. **JNI trace**：如果字符串在 JNI 层解密，trace JNI 调用序列
4. **内存 dump**：等待应用完全初始化后，dump 解密后的内存镜像

dexlib2 字符串解密（Dalvik 层）：识别调用模式 → 提取加密参数 → 调用解密函数 → 批量替换

### 4. FLA 还原

**标准 vs 非标准区分**：标准 FLA 循环头 ≠ 汇聚块（循环头恰好 2 个前驱：序言+汇聚块），非标准 FLA 循环头地址 == 汇聚块地址。

工具优先级（标准 FLA）：D-810 → IDAPython 状态机 → angr → Unicorn/flare-emu
工具优先级（非标准/魔改 FLA）：angr xdefla(逐块) → Unicorn BFS → Unidbg → flare-emu

**路线 A：纯静态状态机（IDAPython）**— 适用标准 FLA，状态常量可从 MOV/MOVK 提取：

1. 找分发器：函数内被 `B` 引用最多的地址
2. 找状态寄存器：`CMP W8, W9; B.NE dispatcher` 中 CMP 第一个操作数
3. 找 next_state 块：直接赋值 `MOV+MOVK` 或条件赋值 `CSEL`
4. 找 cur_state 块：反向匹配 `CMP+B.NE` 或正向匹配 `CMP+B.EQ`
5. 重建：匹配 next_state==cur_state，patch 真实 block 间的直接跳转

关键 ARM64 模式：CSEL 双后继代表 if-else（真分支+假分支）；真实块末尾是 `B dispatcher`（无条件），junk 块末尾是 `B.cond dispatcher`（条件）→ 完整脚本见 `run/fla-state-machine-template.py`

**路线 B：块关系分析（FlowChart）**— 6 条分类规则：序言→主分发→预分发→真实块→返回块，其余为 junk。入度最高块通常是主分发块。

**路线 C：angr 符号执行**— 逐块处理避免路径爆炸。关键：`CALLLESS` 选项阻止分析函数调用；对 CSEL 块 fork 状态分别探索两条分支 → 完整脚本见 `run/fla-angr-template.py`

**路线 D：模拟执行 trace**— Unicorn / flare-emu / Unidbg 三种方案。核心：在 CSEL 处修改 NZCV 强制选择分支，记录真实 block 转换关系 → 完整脚本见 `run/fla-unicorn-template.py`

ARM64 NZCV 标志位（PSTATE bits [31:28]）：N=bit31, Z=bit30, C=bit29, V=bit28

| 条件码 | 含义 | 强制为真 | 强制为假 |
|--------|------|---------|---------|
| EQ (Z==1) | 等于 | `0x40000000` | `0x00000000` |
| NE (Z==0) | 不等于 | `0x00000000` | `0x40000000` |
| GT (Z==0&&N==V) | 大于 | `0x00000000` | `0x40000000`(Z=1) |
| GE (N==V) | 大于等于 | `0x00000000` | `0x80000000`(N=1,V=0) |
| LT (N!=V) | 小于 | `0x80000000` | `0x00000000` |

### 5. BR 还原

按模式选择工具：
1. **无条件 BR**：静态算目标或 Keypatch → `BR Xn` 改 `B target`
2. **单 CSEL**：分析不透明谓词，确定恒真/恒假 → `CSEL` 改 `B.cond`，`BR` 改 `B`
3. **多 CSEL**：Unidbg 双模拟器分别强制真/假（避免状态污染），算出真实目标 → 完整脚本见 `run/br-patch-template.py`
4. **跳转表**：IDA switch idiom 识别或 Frida trace 批量

Frida 批量 trace 方案：IDAPython 扫描 BR/BLR → 自动生成 Frida hook 脚本 → spawn 模式注入 → 解析日志 → IDAPython 批量 patch → 完整脚本见 `run/br-patch-template.py`

data 段只读 trick（间接调用还原）：IDA 中 `Alt+S` 取消 data 段写入权限，IDA 自动将间接调用优化为直接调用。

工具：Keypatch（手动 patch）/ Unicorn（执行 trace）/ angr pyvex（VEX IR 简化）/ BinaryNinja（HLIL 自动简化）

### 6. SUB 还原

工具优先级：D-810 / IDA 9.2 内建 → GAMBA → Z3

**IDA 9.2 内建**：反编译器对标准 MBA 表达式有较好的内建简化能力，先试 F5 看效果。

**GAMBA**：`pip install git+https://github.com/DenuvoSoftwareSolutions/GAMBA.git`
```bash
python simplify_general.py -b 32 -z 1 "(x + y) - 2 * (x & y)"
# -b BITCOUNT: ARM32=32, ARM64=64, 默认64
# -z 1: 启用 Z3 等价性验证
# -v 3: 穷举验证所有输入组合
```
预处理要点：GAMBA 无法解析 C 指针语法，`*(v16+i)` → `V16_i`，`v12[v9]` → `V12_v9`，先简化赋值表达式再代入。

**Z3**（兜底）：
```python
from z3 import *
x, y = BitVecs('x y', 32)
prove(x ^ y == (x + y) - 2 * (x & y))  # 验证等价
simplified = simplify((x + y) - 2 * (x & y))  # 简化
```

### 7. 自定义 OLLVM 处理

**魔改应对**：

| 魔改手法 | 击败的工具 | 反制方法 |
|----------|----------|---------|
| 真实块与预分发间插入中间块 | D-810, JEB | 放宽识别：中间块的前驱也是真实块 |
| switch → if-else 链 | 标准状态机 | 识别 CMP+B.cond 链替代 switch |
| 随机化 origBB 跳转目标 | 简单后继检查 | 改用模拟执行 trace |
| 多级/嵌套 dispatcher | 单级分析 | 递归分析子分发器 |
| Arkari L0-L3 加密 | 标准 BR 还原 | 按级别解密 |
| 多返回块 | 单出口假设 | 枚举所有 RET 块 |

**产品特定处理**：
- **BlackObfuscator**：dexlib2 分析方法体切片模式，重组原始指令流
- **Arkari**：先处理字符串解密，再用 D-810 + 手动分析处理 FLA/BR
- **Hikari**：标准 OLLVM 工具通常适用
- **D-810 对魔改无效时**：遇到魔改 FLA（switch→if-else、中间块）立即切换 angr/Unicorn，不要反复尝试 D-810

Arkari 间接跳转 4 级加密速查：

| 级别 | 加密公式 | 解密难度 | 特征 |
|------|---------|---------|------|
| L0 | `enc_addr = target + EncKey` | 低 — `SUB target, -EncKey` | 全局数组 `DestBBs[]` |
| L1 | `enc_addr = target + (AddKey ^ XorKey)` | 中 — 单密钥对 | `SUB` + `EOR` 模式 |
| L2 | `enc_addr = target + (AddKey ^ (XorKey * Idx))` | 高 — 每个 block 不同密钥 | 密钥随 `Idx` 变化 |
| L3 | `enc_addr = target + (EncKey1 ^ (realKey(Idx) * Idx))` | 极高 — 双数组 | `DestBBs[]` + `XorKeys[]` |

L3 还原要点：`XorKeys` 存储值经 `NEG → XOR(EncKey1) → NEG`（算术取负）变换，即 `stored = -(-originalKey ^ EncKey1)`。该变换是自逆的，对存储值执行同样三步即恢复 `originalKey`。还原后的 `originalKey` 代入 L2 公式即得真实跳转地址。

### 8. 综合工作流（推荐）

**组合混淆处理顺序（BCF → 字符串 → FLA → BR → SUB）**：
1. BCF 优先：虚假分支的不透明谓词会干扰 FLA 状态变量提取（.bss 全局变量同时被 BCF 和 FLA 使用）
2. 字符串其次：解密后的字符串是后续理解 FLA 真实块语义的高价值锚点
3. FLA 第三：BCF 清除后状态变量提取更干净；字符串解密后可辅助判断真实块功能
4. BR 第四：FLA 恢复真实控制流后，间接跳转的目标更容易定位
5. SUB 最后：纯表达式简化，不影响控制流结构，最后处理即可

如果工具自动还原效果差，转运行时 hook 直接抓输入输出。不要追求完美去混淆——目标是让关键路径可读。

### 9. OLLVM 源码级理解（从被动还原到主动理解）

理解 OLLVM 的 LLVM Pass 实现原理，可以更快定位混淆模式和还原策略，而不是盲目试工具。

#### IndirectBranch Pass（间接跳转）

LLVM Pass 在函数退出时运行：
1. 为每个基本块分配随机 ID（存入 `DestBBs[]` 全局数组）
2. 将 `br label %target` 替换为：`switch(cur_bb_id) { case N: br label %target; }`
3. 对 Arkari 变体：额外加密 case 常量（L0-L3 级别，见 Arkari 速查表）

逆向推论：找到 `DestBBs[]` 数组 → 每个元素是一个基本块的随机 ID → `switch` 的 case 值就是 ID → 反查 ID→原始块映射。

#### BCF Pass（虚假控制流）

LLVM Pass 实现：
1. 对每个基本块，克隆一份副本（false branch）
2. 插入不透明谓词：`if (opaque_predicate) goto original; else goto clone;`
3. `.bss` 全局变量作为不透明谓词的操作数

逆向推论：`.bss` 全局变量就是不透明谓词的变量 → `.bss` 段 patch 就是强制不透明谓词为恒假 → 虚假分支永远不会执行。

#### SUB Pass（指令替换）

标准 OLLVM 的 LLVM Pass 替换方案（`Substitution.cpp` 源码）：

加法替换（4 种随机选择）：
- `addNeg`: `a + b` → `a - (-b)`
- `addDoubleNeg`: `a + b` → `-(-a + (-b))`
- `addRand`: `a + b` → `(a + r) + b - r`（r 为随机值）
- `addRand2`: `a + b` → `(a - r) + b + r`（r 为随机值）

MBA 混淆变体（Hikari 增强 SUB / 独立 MBA 混淆器，**非标准 OLLVM**）：
- `a + b` → `(a ^ b) + 2 * (a & b)`
- `a - b` → `(a ^ ~b) + 2 * (a & ~b) + 1`
- `a ^ b` → `(a | b) & ~(a & b)`

标准 OLLVM SUB 可以通过更简单的代数还原处理；MBA 变体需要 GAMBA/Z3。

逆向推论：识别这些等价模式后，可以反向替换回简单运算，GAMBA/Z3 自动完成这一步。

#### 关键 LLVM Pass 对应还原策略

| LLVM Pass | 混淆效果 | 还原策略 |
|-----------|---------|---------|
| `Flattening` | 控制流平坦化 | 状态机分析 / angr / trace |
| `IndirectBranch` | 间接跳转加密 | 查表解密 / trace 目标 |
| `BogusControlFlow` | 虚假条件分支 | `.bss` patch / D-810 |
| `Substitution` | 表达式替换 | GAMBA / Z3 / IDA 9.2 内建 |
| `ADCEPass`（标准优化） | 混淆后死代码消除，清理无效代码 | 理解这是编译器后处理优化，不是独立混淆 |
| `InstSimplifyPass`（标准优化） | 混淆后指令简化，优化生成代码 | 同上 |

### 10. miasm 符号执行去混淆

miasm 提供基于符号执行的去花指令（junk code removal）能力：

**适用场景**：
- 标准 OLLVM FLA/BR 去混淆工具（D-810、angr）处理不了的魔改混淆
- 需要自动化跟踪函数调用和返回的去混淆

**miasm 符号执行引擎**：
- 核心类：`SymbolicExecutionEngine`（miasm.ir.symbexec）— 纯符号执行
- `DSE`（miasm.analysis.dse）— 动态符号执行（concolic），支持符号+具体混合模式
- 社区扩展（如看雪论坛的 `FuncExecutionEngine`）在 `SymbolicExecutionEngine` 基础上添加了自动跟踪 `BL` 函数调用和返回的能力
- 可以在符号执行过程中对未知函数做具体执行，避免路径爆炸

**SOP**：
1. 将目标函数加载到 miasm 的 JIT 引擎
2. 设置入口参数为符号值
3. 使用 `FuncExecutionEngine` 执行，自动处理函数调用
4. 收集约束，求解真实控制流
5. 输出去混淆后的 IR 或补丁原二进制

**与 angr 对比**：miasm 的函数调用跟踪更精确（angr 的 `CALLLESS` 直接跳过调用），但 miasm 的文档和社区支持不如 angr 丰富。

## 常见偏差

- 试图逐函数完美去混淆——应该只处理关键路径上的函数
- 混淆场景下仍然逐行阅读伪代码——应该先运行时 hook 抓输入输出
- 没有先识别混淆类型就选择工具——不同混淆类型需要不同还原策略
- 忽略字符串解密——解密后字符串是后续分析的高价值锚点
- 在 IDA 中手动恢复 FLA——D-810/angr 可以自动化大部分工作
- 把 Arkari 当标准 OLLVM 处理——Arkari 有额外的间接跳转和字符串加密层
- 不知道 MOVK 是按位 OR——`MOV+MOVK` 组合是 `(high<<16)|low`，不是 `high+low`
- 十进制搜不到试十六进制——ARM64 状态常量 `1825021717` 可能显示为 `0x6CE39C70`
- angr 不用 CALLLESS 直接全函数分析——路径爆炸，必须逐块 + CALLLESS
- D-810 无效时反复尝试——遇到魔改立即切换 angr/Unicorn，不浪费时间

## T4/T5 混淆/加密困难时强制路径

当 `deliverableTier` 为 T4 或 T5，且分析过程中遇到 OLLVM / VMP / 自定义虚拟机 / Native 层加密/签名复杂导致无法直接还原算法时，在搜索轮次用尽后，必须覆盖以下检查点。

**检查点适用规则**：先完成"混淆类型识别"检查点（需要先 `Read` `deobfuscation-playbook.md` 获取识别方法）。根据识别结果，仅执行与识别到的混淆类型相关的检查点：
- 若识别到 FLA（控制流平坦化）→ 必须覆盖：Dispatcher 结构分析 + 锚点反向追踪
- 若识别到 BR（间接跳转）→ 必须覆盖：Dispatcher 结构分析 + 锚点反向追踪
- 若识别到 BCF（虚假控制流）→ 必须覆盖：.bss 全局变量 patch 相关证据
- 若识别到 SUB（指令替换）→ 必须覆盖：表达式简化相关证据
- 若仅字符串加密无控制流混淆 → 不需要覆盖 Dispatcher 结构分析，但仍需覆盖：加密库指纹识别 + 锚点反向追踪
- 所有情况均需覆盖：加密库指纹识别 + 差分分析 + 公开研究搜索（此三项为通用必检）

| 检查点 | 最低操作深度 | 有效证据 | 无效证据 |
|---|---|---|---|
| 混淆类型识别（必检） | 按 playbook "先判断混淆类型"：用 IDA 查看目标函数 CFG，识别 FLA/BR/BCF/SUB/组合 | 混淆类型判定 + CFG 截图或描述 + 具体特征指令地址 | "SO 有混淆"（无类型识别） |
| 加密库指纹识别（通用必检） | 搜索导入符号 + 扫描 `.rodata` 中 S-box / IV 特征（至少 3 个不同偏移） | 命中的特征地址 + 字节内容 + 对应算法名 | "搜索了但没找到" |
| 锚点反向追踪（通用必检） | 从已知锚点（Base64 表、SHA-1 IV、AES S-box）出发，用 xref 追踪至少 2 层调用链 | xref 链中每个函数的地址 + 反编译结果 | 只列了锚点地址没有追踪 |
| Dispatcher 结构分析（FLA/BR 必检） | 对 OLLVM dispatcher 函数：提取 dispatcher 变量 + 列出 >=5 个 case 块目标地址 | 汇编中 CMP/CSEL 指令地址 + 分支目标列表 | "IDA 反编译为空" |
| 差分分析（通用必检） | 对 >=1 组已知输入输出：解码密文结构、对比长度/重复模式、推测加密模式 | 密文 hex dump + 结构分析结论 | "只有 1 组样本无法对比" |
| 公开研究搜索（通用必检） | 按"执行内搜索检查"流程：至少 3 组不同关键词，先社区搜索，无结果再全网搜索 | 搜索结果摘要 + 写入 external-research.md | 1 次搜索失败就放弃 |

相关检查点全部完成后，才允许向用户报告 T4/T5 的当前状态并请求方向指导。报告必须附带每条检查点的证据文件或回复正文中的详细记录。

## Java 层混淆

Java 层混淆工具（DexGuard、Allatori、Stringer、ProGuard/R8 增强模式、商业加固的 Java 层字符串加密）不属于 OLLVM 族，但同样需要去混淆才能有效分析。本节覆盖 Java 层混淆的识别与还原。

### 识别信号

| 信号 | 混淆工具 | 优先级 |
|------|----------|--------|
| 类名/方法名全部为 `a.b.c` 但控制流正常 | ProGuard / R8 | A1，不做去混淆 |
| 字符串常量全部消失，运行时通过反射获取 | DexGuard / Allatori / 自定义 | A2+ |
| try-catch 块大量插入但不影响逻辑 | DexGuard | A2+ |
| 方法调用通过 `Class.forName` + `Method.invoke` 间接调用 | DexGuard / 商业加固 | A2+ |
| 资源文件名混淆（`res/layout/a.xml`） | DexGuard | A2 |
| DEX 文件结构异常（多个 DEX 但代码量不大） | DexGuard 分片 | A2+ |
| 字符串解密方法集中在一个或少数类中 | Allatori / Stringer | A2 |
| `javax.crypto` 调用被包装在自定义工具类中 | 通用 | A2 |

### 操作顺序

1. **确认混淆级别**：如果只是 ProGuard/R8 重命名（A1），不需要去混淆——直接用 jadx 读取即可。只有字符串加密、反射隐藏、控制流混淆才需要本节后续步骤

2. **定位字符串解密方法**：
   - 在 jadx 中搜索 `String.valueOf\|decrypt\|decode` 配合 `byte[]` 参数的方法
   - 搜索 `Class.forName` 调用，识别间接调用模式
   - 若字符串解密方法集中在少数类中（Allatori 典型模式），记录这些类的完全限定名

3. **Allatori 字符串解密还原**：
   - Allatori 通常为每个类生成一个静态解密方法，接受 int/char[] 参数返回 String
   - 用 jadx 找到解密方法，手动分析其逻辑（通常是简单 XOR + 位移）
   - 编写 Python/JS 脚本批量调用解密方法还原所有加密字符串
   - 或用 Frida hook 解密方法，在运行时捕获所有解密结果

4. **DexGuard 反射隐藏还原**：
   - DexGuard 将直接方法调用替换为 `Class.forName(name).getDeclaredMethod(name, paramTypes).invoke(null, args)` 模式
   - 在 jadx 中搜索 `Method.invoke` 和 `Class.forName`，建立间接调用映射表
   - 映射格式：`{ 原始调用位置 → 目标类.方法名 }`
   - 对于 `name` 参数本身也被加密的情况，先执行步骤 2 的字符串解密还原

5. **DexGuard try-catch 混淆清理**：
   - DexGuard 插入的 try-catch 块不会改变执行路径（catch 块为空或仅 re-throw）
   - 识别模式：catch 块为空或只有 `throw e`，且 try 块内的代码在移除 try-catch 后逻辑不变
   - 在 smali 层面移除 `.catch` 指令即可清理（参考 smali-patching-playbook Pattern 5）

6. **DexGuard DEX 分片重组**：
   - DexGuard 可能将一个类的不同方法拆分到不同 DEX 中
   - 用 jadx 打开完整 APK（不是单个 DEX），jadx 会自动合并 multidex
   - 若 jadx 合并后仍有缺失，检查 `classes*.dex` 中是否有额外的 class definition

### 检查点

| 检查点 | 有效证据 |
|--------|----------|
| 混淆工具识别 | 具体工具名 + 识别依据（特征字符串/代码模式） |
| 字符串解密还原 | 至少 3 个解密前后对照示例 |
| 反射调用映射 | 至少 5 个间接调用→原始调用的映射对 |

## 最小交付

- `run/deobfuscation-notes.md`
- 还原后的关键函数伪代码或控制流图
- 使用的工具和参数记录

## 实战补充：NRV2B 自修改代码与 Gap Code

部分商业壳（如爱加密 v4）使用 NRV2B 压缩作为外层 stub，解压后 `mmap(MAP_FIXED)` 覆盖自身映射。这类自修改代码导致 IDA 静态分析只能看到压缩态。

### NRV2B 解压器识别信号

- `DT_INIT` 不是业务代码而是解压器
- `get_bit` 核心循环: `adds w4,w4,w4; cbz w4,reload; ldr w4,[x0],#4; adcs w4,w4,w4; ret`
- 初始哨兵值 `w4 = 0x80000000`
- 连续 4-5 个 uint32 常量作为解压参数表（src base / ASLR ref / page align / output size / data start）

### Gap Code 处理

解压后代码覆盖 vaddr `0x30000-0xD8000`（示例），但原始文件只到 `0x852DC`。IDA 看不到 gap code 区域的关键函数。

**解决**：
1. 运行时从 `/proc/pid/mem` 读取 SO base + gap offset
2. 保存为 `gap_code.bin`
3. IDA "Edit → Segments → Load additional binary" 加载到对应 vaddr

### LLVM Pass 构建知识

理解 OLLVM 混淆器如何通过 LLVM New Pass Manager 构建有助于逆向分析：
- Pass 通过 `add_llvm_pass_plugin` CMake 宏编译为 `.so` 动态库
- 入口函数 `llvmGetPassPluginInfo()`（extern "C" weak symbol）
- `registerPipelineStartEPCallback` 注入 clang 编译管线
- `isRequired() = true` 确保 Pass 不被优化跳过
- `ModuleToFunctionPassAdaptor` 将 Function Pass 适配为 Module Pass

详见 `references/technique-extract-2026-05.md` 第 3、5 节。

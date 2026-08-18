# VMP Analysis Playbook

目标：从 VM 保护的字节码中恢复可读的原始逻辑，而不是试图完整逆向 VM 解释器。

## 先回答

- VMP 类型（Dalvik 字节码 VMP / Native ARM64 VMP / 混合型）
- 保护产品是什么（自定义 / NP / LIAPP / DexProtector / 梆梆 / 某壳）
- 关键逻辑是否可以通过运行时 trace 获取而不需要完整还原字节码
- handler 表是否可以被提取和映射

## 高风险信号

- 方法体被替换为 native 调用（Dalvik VMP）
- `dalvik_bytecode_handler` 或类似分发器符号
- 大量连续的 switch-case / jump table（VM dispatcher）
- 操作码被打乱或加密
- `VMPProtect` / `VMProtect` 字符串
- `libjiagu.so` / `libsecexe.so` / `libprotectClass.so`（壳标识）
- 方法被标记为 native 但实际承载 Dalvik 逻辑

## VMP 类型识别

### Dalvik 字节码 VMP

特征：
- 原 Dalvik 方法被替换为 native 方法
- 自定义 VM 解释器执行原始字节码
- handler 表包含 256 个条目（对应 Dalvik 指令集 0x00-0xFF）
- 操作码映射被打乱

识别方法：
- 在 JADX/JEB 中找到方法声明为 native 但无对应 JNI 实现
- 搜索壳特征字符串和 SO 库
- hook `dalvik.system.DexFile` 或 `ClassLoader` 观察动态加载行为

### Native VMP（ARM64）

特征：
- SO 中的关键函数被 VM 保护
- 自定义寄存器上下文（VM context）
- handler 通过操作码分发
- 原始 ARM64 指令被替换为 VM 字节码

识别方法：
- 控制流图中出现大量重复的 dispatch 结构
- 函数入口保存大量寄存器到 VM context
- 操作码序列与标准 ARM64 指令不对应

## 操作顺序

### 1. 确认 VMP 保护存在

- 在 JADX 中搜索被替换为 native 的方法
- 在 IDA/Ghidra 中搜索 VM dispatcher 模式
- 运行时 hook 目标方法，观察是否进入 VM 解释器
- 确认保护产品类型（影响后续分析策略）

### 2. 提取 Handler 表

#### Dalvik VMP

1. 定位 VM 解释器入口（通常在壳 SO 的 JNI_OnLoad 或 RegisterNatives 映射的函数中）
2. 找到 dispatcher 函数（大型 switch-case 或 jump table）
3. 每个 case 对应一个 handler
4. 记录 handler 数量和操作码映射关系

Handler 表提取：
- 静态分析：在 IDA 中手动标注每个 handler
- 动态 trace：用 Frida Stalker trace 解释器执行，记录 handler 调用序列
- 组合方法：先静态识别 dispatcher 结构，再动态确认映射

### 3. 构建操作码映射

#### 从打乱的 handler 恢复操作码语义

方法 A —— 逐一分析每个 handler：
1. 分析 handler 的行为（移动、算术、跳转、调用等）
2. 将 handler 行为与 Dalvik 指令集对照
3. 建立操作码→语义的映射表

方法 B —— 对比分析：
1. 获取一份未加 VMP 的相同版本的 APK
2. 对比方法执行 trace
3. 从执行差异中推断操作码映射

方法 C —— 自动化工具辅助：
1. 使用 Unicorn Trace + TENET 插件记录 handler 执行
2. 使用 AI 辅助识别 handler 语义模式
3. 使用 frida-stalker 追踪解释器执行流

### 4. 字节码还原

#### 从 VM 字节码恢复 Dalvik 字节码

1. 根据 handler 映射表，将 VM 字节码逐条翻译回 Dalvik 字节码
2. 恢复操作数（寄存器编号、常量、引用等）
3. 验证还原结果（与运行时行为对比）

#### Native VMP 字节码还原

1. 识别 VM context 结构（虚拟寄存器映射）
2. 分析每个 handler 的实际操作
3. 将 VM 字节码翻译回等效的 ARM64 指令或伪代码
4. 恢复函数调用和参数传递

### 5. Trace-based 方法（推荐优先使用）

当静态还原成本过高时，优先使用 trace-based 方法。详细的 trace 采集、切片和分析流程见 `references/trace-analysis-playbook.md`。

#### Frida Stalker Trace
1. 在 VM 解释器入口设置 Stalker
2. 记录所有 handler 调用序列和参数
3. 从 trace 中提取关键逻辑（输入→处理→输出）

#### Unicorn Trace + TENET
1. 将 VM 解释器和字节码加载到 Unicorn
2. 执行并记录完整 trace
3. 导入 IDA + TENET 插件可视化分析
4. 结合静态 handler 分析还原语义

#### Trace-slice 反向切片加速
- 大量 trace 中只有少量指令与目标值相关
- trace-slice（Rust）可在 8 秒内处理 24M 行 / 2.88GB trace，切片到约 5.4%
- 切片后用 VMLifter 语义提升：108K trace → 756 行伪代码 → LLM 识别算法

#### VMP 解释器 Trace 范围确定
1. 用第 11 节的入口启发式定位 VM 入口函数
2. 以 VM 入口函数的起始地址作为 trace 起始点
3. trace 终止点：找到 dispatcher 循环后的第一个 `RET` 或下一个 `STP x29, x30`（新函数序言）
4. 在 Unidbg 中：`emulator.traceCode(vmEntryAddr, vmEntryAddr + estimatedSize)`，estimatedSize 从 IDA 函数边界获取
5. 如果 trace 输出过大，先用模块范围过滤（限定 `libtarget.so`），再用 trace-slice 反向切片

### 6. AI 辅助 Handler 识别

- 将 handler 反编译代码提供给 AI（如 Claude/GPT）
- 提示 AI 识别 handler 对应的操作语义
- AI 特别擅长识别：算术运算、数据移动、比较跳转、方法调用等模式
- 注意：AI 结果需要人工验证，不能直接信任

### 7. 保护产品专项

- **NP（NetEase / 网易）**：handler 表可能有额外加密层，需要先解密再分析
- **LIAPP**：操作码映射可能每次构建不同，需要运行时动态提取
- **DexProtector**：多层保护，VMP 可能与字符串加密、反调试联动
- **梆梆（Bangcle）**：动态加载的 DEX 中的方法可能也被 VMP 保护
- **自定义壳**：通常比商业壳简单，handler 映射可能更规则

### 8. 已知产品 VMP Handler 特征速查

| 产品 | 取指模式 | 分发方式 | 寄存器文件 | 特殊特征 |
|------|---------|---------|-----------|---------|
| libsgmain (支付宝) | handler 外取 opcode，handler 内取 operand | 单级 jump table | 独立 VM_REG 数组，W11/W12/W16 索引 | 规则映射，handler 无额外混淆 |
| libmtguard (美团) | handler 外取 opcode + operand | 二级分发：opcode→Handler_Arithmetic→opcode2→具体 handler | 独立 VM_REG 数组，W11/W12/W13，operand 通过间接链解析 | 间接链操作数解析（0x13A38C→0x13A63C） |
| libdroidguard (Google) | 封装为 `vm_decode_` 函数调用 | 数组查找：`handler_address[decoded_opcode]` | `registers_->reg[index]` 结构体，通过 `vm_decode_`/`vm_set_register` 访问 | **MBA 编码 + OLLVM 双层保护**，需先去混淆 |
| VMProtect (x86) | handler 外取 opcode，handler 内取 operand | R8/R9D 间接跳转 | 基于 RSP 的虚拟栈（非寄存器数组） | 算术操作通过虚拟栈 push/pop，非直接寄存器操作 |

### 9. ARM64 VMP 固定宽度字节码解析模板

多数大厂 VMP 使用 32 位固定宽度字节码，位域分布如下：

```
|31|30-26|25-21|20-16|15-12|11-6|5-0|
| 1|  Xa |  Xn |  Xt |  Xm |imm |vOP|
   5-bit  5-bit  5-bit  4-bit 6-bit 6-bit
```

对应 ARM64 取指-译码汇编模式：
```asm
LDR W12, [X0]                    ; vInsn = *vPC
AND  W10, W12, #0x3F             ; vOpcode = vInsn[5:0]
UBFX W9, W12, #0x15, #5          ; Xn = vInsn[25:21] (src reg)
UBFX W8, W12, #0x10, #5          ; Xt = vInsn[20:16] (dst reg)
LDRSW X3, [jpt_base, X10, LSL#2] ; offset = jumptable[vOpcode]
BR   X3                          ; dispatch
```

VMState 常见结构（0x150 字节）：
```c
struct VMState {          // 偏移
    uint64_t vStack;      // +0x00
    uint64_t vStack1;     // +0x08
    uint64_t vPC;         // +0x18
    uint64_t vX[32];      // +0x20..+0x118 (32 个虚拟寄存器, 8B each)
    uint64_t vFlag;       // +0x130 (0=顺序, 2=指令设置, 3=触发跳转)
    uint64_t vAddrJump;   // +0x138
    uint64_t vAddrReturn; // +0x140
    uint64_t vAddrBase;   // +0x148
};
```

vFlag 延迟分支机制：指令执行时设 vFlag=2，下次取指时变为 3，再下次 PCUpdate 时触发跳转。这是典型的反分析特征。

### 10. AI 辅助 VMP 还原工作流

当 VMP + 白盒密码组合保护时，推荐以下分阶段工作流：

**Phase 1 — Trace 数据采集**（Unidbg 指令级 trace）
- 在 VM 解释器区域开启 trace（百万行级别）
- 在每个 dispatcher 断点处 dump 评估栈的前后状态

**Phase 2 — 操作码语义推断**
- 对每组 (pre_stack, post_stack) 尝试匹配已知运算：

```python
def infer_opcode(pre_stack, post_stack):
    a, b = pre_stack[-2], pre_stack[-1]
    r = post_stack[-1]
    candidates = {'ADD': (a+b)&0xFFFFFFFF, 'XOR': a^b,
                  'LSL': (a<<(b&31))&0xFFFFFFFF, 'SUB': (a-b)&0xFFFFFFFF}
    return [name for name, val in candidates.items() if val == r]
```

关键约束：单组数据不可靠（XOR 和 ADD 在特定输入下结果相同），必须用多组输入交叉验证。

**Phase 3 — 控制流还原**
- 追踪 vPC 回跳识别循环
- 循环次数推断加密参数：如 `3 × 9 × 4 = 108` 次迭代 × 每次含 16 次 GF 乘法 = AES-128

**Phase 4 — 白盒密钥恢复**（如果 VMP 内嵌白盒密码）
- GF(2^8) 乘法识别：8 次循环 + 约化常数 `0x1B` = AES
- S-box 表碰撞恢复：暴力搜索 `delta` 使得 `T1[x] == T2[x ^ delta]` 对所有 x 成立，`delta = 轮密钥差`

### 11. VMP 入口识别启发式

在 SO 中定位 VMP 保护函数的快速规则：

**包装函数特征**（Dalvik VMP 的 native 桩函数）：
- 函数体 ≤ 20 条指令
- 仅包含单次 `BL` 调用（跳转到 VM 解释器）
- 以 `RET` 结尾
- 参数直接传递给 BL 目标（x0-x7 → 解释器入口）

**ARM64 VMP 入口特征**：
- 入口保存 8+ 通用寄存器到 VM context（`STP x19, x20, [x0, #offset]` 模式）
- 大量 `STR/LDR` 到连续内存区域（VM register file）
- 后续进入 dispatcher 循环（`AND w_reg, w_insn, #mask; LDR x_target, [table, x_reg, LSL#3]; BR x_target`）

**IDA 辅助识别**：在 IDA Python 中搜索上述模式可快速定位 VM 入口。

### 12. IDA 打平与 trace-slice 协同

当 VMP dispatcher 使用 OLLVM FLA 打平时，静态分析 dispatcher 需要先打平：

**IDA 打平技术**：
1. 将所有 `BL dispatcher` 替换为 `B dispatcher`（消除调用栈干扰）
2. 合并次级跳转表（多个 handler 共享 dispatcher 副本时）
3. 创建统一的 dispatcher 入口（所有 handler 汇聚到一个分发点）

**与 trace-slice 协同**：
1. 先用 trace 采集真实执行路径（忽略打平的虚假分支）
2. trace-slice 反向切片提取核心路径
3. 在打平后的 IDA 视图中标注 trace 确认的真实分支
4. 避免 分析 OLLVM 布尔方程的虚假路径

### 13. Godot VM 专项

Godot 4.x 的 GDScript 字节码保护模式：

**PCK 资源加密**：
- 加密算法：AES-256-CFB
- 密钥来源：硬编码或运行时计算
- 解密时机：PCK 加载时

**GDScript 字节码混淆**：
- 操作码 XOR 0xB6（单字节异或去混淆）
- CFF（Control Flow Flattening）双变体：每个代码块有两条等价执行路径，运行时选择
- 字符串常量加密

**分析步骤**：
1. 定位 PCK 解密函数（搜索 AES-256-CFB 常数或 `encrypt`/`decrypt`/`script_encryption_key` 相关字符串）
2. Hook `PackedSourcePCK::try_open_pack` 提取 32 字节解密 key：
```javascript
// 在 libgodot_android.so 中定位 try_open_pack
var mod = Process.findModuleByName("libgodot_android.so");
// 搜索 script_encryption_key 或 PackedSourcePCK 符号
var exports = mod.enumerateExports().filter(e => e.name.includes("PackedSourcePCK"));
// 如果符号被 strip，通过字符串引用或 AES 常数交叉引用定位
// hook 解密函数，在 key 被加载时 dump 32 字节
```
3. dump 解密后的 PCK（在解密后 hook 文件读取）
4. 对 GDScript 字节码做 XOR 0xB6 去混淆（仅作用于操作码字节，不是整个文件）
5. 使用 GDScript 反编译工具（godot-decompiler 等，需匹配引擎版本）还原源码
6. CFF 双变体：在 GDScript 解释器入口用 Stalker.follow trace 确认实际执行路径

## 常见偏差

- 试图完整逆向 VM 解释器——应该只关注关键方法的 handler 映射
- 不先确认保护产品类型就开始分析——不同产品策略差异很大
- 忽略运行时 trace 方法——很多时候 trace 就够用了，不需要完整还原字节码
- 在 handler 数量巨大时逐个手动分析——应该先用自动化工具过滤
- 把 VM context 的虚拟寄存器当成物理寄存器分析——需要先理解 context 结构
- 还原后不验证——必须与运行时行为交叉验证

## 最小交付

- `run/vmp-analysis-notes.md`
- handler 映射表（至少覆盖关键路径上的 handler）
- 还原后的关键方法伪代码或字节码
- 使用的 trace 数据和工具记录

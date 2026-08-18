# Native VMProtect / Themida Devirtualization（VM 段去虚拟化）

> 定位：把 native 侧 VMProtect/Themida 的 VM 段 devirtualization 从「概念名词」补成**可执行工作流**。
> `tools-advanced.md` 的 VMProtect/Themida 段给的是「识别特征 + CTF trace 策略」，本篇给「handler 识别 →
> 指令日志 → VTIL 反编译 → 还原判据」的逐步路线，并附 NoVmp/VTIL 用法。
> 对比参照：Android 侧 `vmp-analysis-playbook.md` 反而更深，本篇是 native（x86/x64）侧的对等补齐。

---

## 0. 什么时候需要 devirtualization

- 目标受 VMProtect/Themida 保护，关键代码被虚拟化（非简单压缩壳）。
- 直接静态分析只能看到「VM dispatcher 循环」，看不到真实逻辑。
- 两条路：**完整 devirtualization**（把 VM 字节码还原成 x86/IR，可静态读）vs **定向 trace**（只追踪输入相关操作，够用即止，CTF 常见）。
- 选路判据：需要「全局理解/交付可读还原」→ 完整 devirt；只需「还原校验/比较逻辑」→ 定向 trace。

---

## 1. 识别 VM 段与结构

```bash
strings binary | grep -i "vmp\|vmprotect\|themida"
readelf -S binary | grep -E "\.vmp|\.themida"     # PE 用 objdump -h
# 熵值：VM 段熵高（字节码 + handler 混合）
```

VM 入口特征（识别 dispatcher）：

```text
1. VM 入口：连续 push 寄存器（保存现场，类似 pushad 但非固定 0x60）。
2. Dispatcher：一个大的间接跳转（jmp [reg + offset] / jmp reg），
   每次执行一个 handler 后回到 dispatcher 取下一个 opcode。
3. Handler 表：连续存放 handler 地址的数组，dispatcher 按 opcode 索引跳转。
4. Handler 末尾：统一跳回 dispatcher（形成循环）。
```

判据：找到「dispatcher 循环 + handler 表 + 统一回跳」三要素，即确认 VM 段，进入 handler 识别。

---

## 2. VM handler 识别

```text
1. 定位 handler 表（dispatcher 的索引寄存器 + 基址）。
2. 对每个 handler：
   - 记录其「读取/修改的虚拟机状态」（VM 栈指针/虚拟寄存器/内存）。
   - 识别语义：vAdd/vSub/vMul/vXor/vNot（算术）、vPush/vPop（VM 栈）、
     vLoad/vStore（内存读写）、vJmp/vJcc（控制流）、vRet（VM 退出，恢复真实寄存器）。
3. 建立「opcode → handler → 语义」映射表（VM 字节码反汇编器的基础）。
```

工具：
- **VMPAttack**（IDA 插件）：自动识别 VMProtect handler。
- 手写脚本（capstone 反汇编 dispatcher + handler，按「入口特征 + 回跳」聚类 handler）。

判据：handler 映射表覆盖 dispatcher 所有可达分支，且能解释每条 VM 字节码的语义。

---

## 3. 指令日志（动态 trace）

对受保护样本做指令级 trace，记录 VM 字节码执行序列，用于验证 handler 映射与定向还原：

```text
1. 断在 VM 入口。
2. 指令级跟踪（x64dbg trace / frida Stalker / Intel Pin），
   在 dispatcher 处记录「opcode + 操作数」序列。
3. 输出「VM 指令日志」，与 handler 映射表交叉验证语义。
```

判据：trace 出的 opcode 序列能按映射表逐条还原成语义，且输入/输出流与真实执行一致。

---

## 4. VTIL 反编译（NoVmp 路线）

### 4.1 VTIL（Virtual-machine Translation Intermediate Language）

VTIL 是专为「虚拟机翻译」设计的中间语言（IR），用于把 VM 字节码 lift 成可优化的 IR，再降级回 x86/x64。

### 4.2 NoVmp（VTIL 静态 devirtualizer，VMProtect 3.x）

NoVmp 用 VTIL 静态地把 VMProtect 3.x 的 VM 段还原。

```text
1. 获取 NoVmp（https://github.com/ozerelkerem/NoVmp，需 Windows 构建）。
2. 载入受保护二进制，定位 VMProtect VM 段。
3. NoVmp：识别 handler → 构建 VM 字节码反汇编器 → lift 到 VTIL → 优化简化 → 输出还原代码。
4. 输出还原后的函数（供 IDA/Ghidra 进一步静态分析）。
```

判据：NoVmp 输出能在原二进制对应地址替换 VM 段，且还原代码逻辑与动态 trace 观察一致。

### 4.3 手写 VTIL lift（框架未装时的兜底）

```text
1. 用 §2 的 handler 映射，把 VM 字节码翻译成 VTIL IR（vAdd→VTIL::register 加法 等）。
2. 用 VTIL 的优化 pass（常量折叠/死代码消除/表达式简化）化简。
3. 降级（translate）回 x86/x64，得到可读汇编。
```

---

## 5. 还原判据（什么算「devirtualization 成功」）

| 判据 | 验证方法 |
|---|---|
| **handler 覆盖** | dispatcher 所有分支都有语义映射，无「未知 opcode」 |
| **语义等价** | 还原代码的输入/输出与动态 trace 观察一致（字节级） |
| **可读性** | 还原后能识别原始逻辑（比较/加密/校验），而非仍是 VM 循环 |
| **可重编译**（进阶） | 还原代码重编译后行为等价（DecLLM 思路，见 trends） |

判据不过 = 还原不完整，标「疑似」；禁止在残缺还原上下结论（persona 硬规则）。

---

## 6. 定向 trace（够用即止的降级路线）

完整 devirt 成本高，多数场景只需追踪「输入相关操作」：

```python
# frida hook dispatcher，记录 opcode 序列 + 关键 handler 的操作数（示意）
Interceptor.attach(ptr('0xVM_DISPATCH'), {
    onEnter(args) {
        // 记录 handler index 与 VM 栈顶，用于还原比较/加密逻辑
        console.log('handler:', this.context.rax, 'vmsp:', this.context.rsi);
    }
});
```

适用：还原校验/比较逻辑、确认加密算法、提取内嵌密钥——不必 devirt 全部 VM 段。

---

## 来源与延伸

- NoVmp（ozerelkerem，VTIL 静态 devirtualizer VMProtect 3.x）：https://github.com/ozerelkerem/NoVmp
- VMProtect 2 脱壳流程（VMP2 IAT 修复）：http://www.qwbw.cn/news/101858
- VTIL：https://github.com/vtil-project/VTIL-Core
- VMProtect/Themida 识别与常规段脱壳（非 VM 段）：`tools-advanced.md`（VMProtect/Themida Analysis）、`tools/x64dbg-reversing/references/unpacking-oep-iat.md`。
- Android DEX/ARM64 VMP（对等参照）：`mobile/android-reverse/references/vmp-analysis-playbook.md`。

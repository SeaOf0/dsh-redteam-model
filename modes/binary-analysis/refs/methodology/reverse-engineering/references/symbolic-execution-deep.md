# 符号执行与模拟器深度（angr / unicorn）

> 定位：在 `tools-dynamic.md`（angr 基础 path explore / 符号输入）之上，补**可落地的深度用法**——
> angr 状态操作/约束优化/路径爆炸治理（避免 Trap-Angr）、去混淆与 keygen 实战；unicorn 内存映射/断点/多架构/与 capstone 联动。
> 工具按检测制：`command -v` 探测 angr/unicorn（pip 包），缺失走四级兜底。

---

## 0. 两者分工

| 引擎 | 定位 | 强项 | 局限 |
|---|---|---|---|
| angr | 符号执行 + 约束求解 | 路径探索、约束求解、去混淆辅助 | 路径爆炸、浮点/堆/crypto 弱 |
| unicorn | CPU 模拟器（无 OS 层） | 精确执行、自修改代码、去壳、跨架构 | 无 syscall（需自己 hook），不符号化 |

选路判据：要「解约束找输入」→ angr；要「精确跑一段代码/dump 自解密内存/跨架构模拟」→ unicorn（OS 层用 Qiling，见 tools-dynamic.md）。

---

## 1. angr 状态操作

### 1.1 状态构造

```python
import angr, claripy
proj = angr.Project('./bin', auto_load_libs=False)

# entry_state：从入口（默认符号 stdin）
s0 = proj.factory.entry_state()

# full_init_state：跑完 libc 初始化（符号 argv/env）
s1 = proj.factory.full_init_state()

# blank_state：从任意地址裸起（跳过初始化，手动设寄存器/内存）
s2 = proj.factory.blank_state(addr=0x401200)

# call_state：以「调用某函数」的姿态起（keygen 常用：直接调校验函数）
s3 = proj.factory.call_state(0x401000, arg1, arg2)
```

### 1.2 寄存器/内存符号化（keygen 核心）

```python
# 符号化一段输入缓冲，作为校验函数的参数
buf_addr = 0x600000
buf_len = 16
buf = claripy.BVS('serial', buf_len * 8)
s = proj.factory.blank_state(addr=0x401000)   # 校验函数入口
s.memory.store(buf_addr, buf)                 # 符号缓冲写入内存
s.regs.rdi = buf_addr                         # 传参（x64 第一参）
for i in range(buf_len):
    b = buf.get_byte(i)
    s.solver.add(b >= 0x20, b <= 0x7e)        # 可打印约束
```

### 1.3 约束求解

```python
# 到达目标点后求解符号输入
found = simgr.found[0]
serial = found.solver.eval(buf, cast_to=bytes)
# 多解：eval 多次 / eval_upto
sols = found.solver.eval_upto(buf, 5, cast_to=bytes)
```

判据：`eval` 出的输入喂回真实程序能通过校验 = 约束正确还原了 f（keygen 成功）。

---

## 2. Hook 与约束优化

### 2.1 Hook 函数（避免在库函数里爆炸）

```python
# SimProcedure：替换函数为「摘要」
class AlwaysOne(angr.SimProcedure):
    def run(self):
        return 1
proj.hook_symbol('check_license', AlwaysOne())

# 地址级 hook：跳过 I/O / 反调试
@proj.hook(0x401050, length=5)
def skip(state):
    pass

# 替换库函数（crypto 用 concretize 摘要，避免符号化哈希爆炸）
class SHA256Hook(angr.SimProcedure):
    def run(self, data, length, out):
        concrete = self.state.solver.eval(
            self.state.memory.load(data, self.state.solver.eval(length)), cast_to=bytes)
        import hashlib
        self.state.memory.store(out, hashlib.sha256(concrete).digest())
proj.hook_symbol('SHA256', SHA256Hook())
```

### 2.2 约束简化与求解提速

```python
# 求解前简化约束
s.solver.simplify()
# 对具体值提前 concretize，减少符号爆炸
concrete_val = s.solver.eval(expr)           # 求一个具体值
s.solver.add(expr == concrete_val)           # 固化为具体值继续
```

判据：hook 掉 crypto/I/O/反调试后，符号状态数显著下降，求解返回时间可控。

---

## 3. 路径爆炸治理（避免 Trap-Angr）

angr 最常见翻车点 = 路径爆炸（符号跳转/循环导致状态指数级增长，跑不出结果）。治理手段按优先级：

```python
# 1. 探索技术：DFS + 长度限制（flag-checker 类首选）
simgr = proj.factory.simgr(s)
simgr.use_technique(angr.exploration_techniques.DFS())
simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=500))

# 2. Veritesting：合并符号分支（控制流分支密集时）
simgr.use_technique(angr.exploration_techniques.Veritesting())

# 3. 循环治理：LoopLimiter / concretize 循环变量
simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=10))

# 4. 状态裁剪：只保留到目标的「最有希望」状态（Spiller/thread 数）
simgr.use_technique(angr.exploration_techniques.Spiller())

# 5. ZERO_FILL：未约束内存/寄存器零填充（减少无意义分叉）
s.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
s.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
```

判据：设置治理后 `simgr.explore` 能在超时内返回 found；若仍爆炸，回退「定向 trace + unicorn」组合（§5）。

---

## 4. 去混淆应用

angr 在去混淆上擅长「具体化对抗性检查 + 解不透明谓词」：

```python
# 1. 反 VM/反调试检查具体化：hook 检查函数返回「真机值」
proj.hook_symbol('IsDebuggerPresent', AlwaysZero())   # 返回 0

# 2. 不透明谓词（obfuscated 恒真/恒假分支）：符号执行能证明恒真
#    用 solver 判断条件是否恒真：
cond = s.solver.is_true(branch_condition)   # True/False/None（未知）
#    恒真/恒假 → 直接具体化，剪掉死分支

# 3. movfuscator：mov-only 混淆，符号执行直接解约束
#    （配合 instruction-count 侧信道，见 tools-dynamic.md）
```

判据：去混淆后 CFG 显著简化，死分支被剪除，可读逻辑恢复。

---

## 5. unicorn 深度（模拟器 hook / 去壳 / 跨架构）

### 5.1 内存映射 + 代码装载

```python
from unicorn import *
from unicorn.x86_const import *
mu = Uc(UC_ARCH_X86, UC_MODE_32)
BASE = 0x400000
mu.mem_map(BASE, 0x100000)                     # 映射代码段
mu.mem_map(0x1000000, 0x10000)                 # 映射堆/栈
mu.mem_write(BASE, code_bytes)                 # 写入代码
mu.reg_write(UC_X86_REG_ESP, 0x1000F000)       # 设栈
```

### 5.2 断点 / hook（去壳核心：自修改代码 dump）

```python
# 代码 hook：逐指令反汇编（capstone 联动）
from capstone import Cs
md = Cs(CS_ARCH_X86, CS_MODE_32)
def hook_code(uc, address, size, user_data):
    code = uc.mem_read(address, size)
    for insn in md.disasm(code, address):
        print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")

# 内存 hook：写 hook 抓「解密落点」（dump 自解密代码）
def hook_mem_write(uc, access, address, size, value, user_data):
    if address == 0x401000:
        print(f"[*] write to 0x{address:x} size={size}")   # 解密完成信号
mu.hook_add(UC_HOOK_CODE, hook_code)
mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
```

### 5.3 多架构模拟（IoT/固件）

```python
Uc(UC_ARCH_ARM, UC_MODE_ARM)          # ARM
Uc(UC_ARCH_ARM64, UC_MODE_ARM)        # ARM64
Uc(UC_ARCH_MIPS, UC_MODE_MIPS32)      # MIPS
# 对应 capstone 常量 CS_ARCH_ARM / CS_ARCH_ARM64 / CS_ARCH_MIPS
```

### 5.4 去壳完整链（unicorn 自动脱壳）

```text
1. 装载壳样本到 unicorn，映射内存。
2. hook 内存写：记录「高熵段被写入」的地址（解密落点）。
3. 跑到「写入完成 + 跳转进入」。
4. dump 该段内存 = 脱壳产物。
5. 与静态脱壳（unpacking-oep-iat.md）互证。
```

判据：dump 出的段可反汇编出合理 prologue + API 调用，且与 x64dbg 手工脱壳产物一致。

---

## 6. keygen 实战模板（angr 解约束）

```python
# exp/keygen-angr.py —— 用 angr 对校验函数解出合法序列号
import angr, claripy
proj = angr.Project('./target', auto_load_libs=False)

CHECK_FUNC = 0x401000     # 校验函数入口（返回 0/非0）
buf_addr, buf_len = 0x600000, 16
buf = claripy.BVS('serial', buf_len * 8)
s = proj.factory.blank_state(addr=CHECK_FUNC)
s.memory.store(buf_addr, buf)
s.regs.rdi = buf_addr
for i in range(buf_len):
    b = buf.get_byte(i)
    s.solver.add(b >= 0x20, b <= 0x7e)

simgr = proj.factory.simgr(s)
# 找「返回非0」（校验通过）的路径：对返回地址下条件
simgr.explore(find=0x4010A0, avoid=0x4010B0)   # 成功/失败两个出口
if simgr.found:
    print(simgr.found[0].solver.eval(buf, cast_to=bytes))
```

判据：输出序列号喂回原程序通过校验 = f 被正确还原。

---

## 来源与延伸

- angr / unicorn 基础用法：`tools-dynamic.md`（angr 基础、Qiling、LD_PRELOAD 侧信道）。
- keygen/补丁/网络绕过全链：`../software-cracking/SKILL.md`。
- OLLVM 去混淆工具链（obpo/d810-ng）：`ollvm-deobfuscation.md`。
- Qiling（unicorn 之上的 OS 层）：`tools-dynamic.md` Qiling 节。

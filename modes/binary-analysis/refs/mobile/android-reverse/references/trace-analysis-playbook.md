# Trace Analysis Playbook

目标：通过指令级 trace 采集、切片、污点传播和语义提升，还原被混淆/保护的算法逻辑。

## 先回答

- trace 目标是什么（函数偏移、SO 名称、还是完整调用链）
- 需要哪种粒度的 trace（指令级 / 基本块级 / 函数调用级）
- 目标 SO 是否有反 trace 检测（反 Frida Stalker、反调试等）
- 最终目标是什么（算法还原 / 参数追踪 / 反混淆 / VMP handler 分析）

## 工具选择矩阵

| 工具 | 采集方式 | 粒度 | 反检测能力 | 适用场景 |
|---|---|---|---|---|
| Unidbg trace | Unicorn 后端模拟 | 指令级 | 无需（离线模拟） | 已能在 Unidbg 中跑通的 SO 函数 |
| Frida Stalker | 进程内 copy-and-instrument | 指令/基本块级 | 低（可被 PC 检测） | 需要真机环境、JNI 交互复杂的场景 |
| GumTrace | Frida Gum Stalker 封装 | 指令级 + JNI/ObjC | 低 | 需要同时追踪 JNI 调用和 Native 指令 |
| QTrace | QBDI + shadowhook | 指令级 | 中（无 ptrace） | 目标有反 Frida 检测但允许内存映射 |
| QBDI | 独立 DBI 框架 | 指令级 | 中 | 需要不依赖 Frida 的插桩 |
| eBPF | 内核态 | 系统调用级 | 高（内核级） | 监控 syscall 行为、网络操作 |

## 操作顺序

### 1. 选择采集策略

**离线优先**：如果目标函数能在 Unidbg 中执行，优先使用 Unidbg trace（无检测风险，可控性强）。参见 `unidbg-simulation-playbook.md` 的 Trace 性能优化章节。

**真机备选**：如果目标依赖复杂 JNI 环境、设备状态或网络交互，使用 Frida Stalker 或 QTrace。

**决策树**：
1. Unidbg 能跑通 → Unidbg trace（离线，优化后 5-20x 速度）
2. 需要真机 + 无反 Frida → Frida Stalker / GumTrace
3. 需要真机 + 有反 Frida → QTrace / QBDI
4. 只需 syscall 级追踪 → eBPF

### 2. Trace 采集

#### Unidbg Trace 采集

```java
// 开启 AssemblyCodeDumper（Unicorn 后端路径）
emulator.traceCode(base, base + moduleSize);
// 限定模块范围避免无效输出
// 优化配置见 unidbg-simulation-playbook.md Trace 性能优化章节
```

#### Frida Stalker Trace 采集

```javascript
// 基本块级 trace
var stalker = Stalker.follow(pid, {
    transform: function(iterator) {
        var bb = iterator.next();
        var addr = bb.address;
        iterator.putCallout(function(context) {
            send({type: "bb", addr: addr.toString()});
        });
        var inst;
        while ((inst = iterator.next()) !== null) {
            iterator.keep();
        }
    }
});
```

**注意**：Stalker 不修改原始指令，但执行地址在 slab 区域。目标可通过 `PC % module_base` 检测。

### 3. Trace 预处理

原始 trace 通常包含大量无关指令，需要预处理：

**模块范围过滤**：只保留目标 SO 地址范围内的指令。

**调用/返回配对**：识别 `BL`/`RET` 对，构建调用层级。

**寄存器追踪**：每条指令记录关键寄存器值（x0-x7 参数寄存器、x29 FP、x30 LR）。

### 4. Trace 切片

**反向切片**（从输出回溯输入）：
- 从目标输出（返回值、内存写入）出发
- 沿 def-use 链反向追踪到输入参数
- 过滤无关指令，通常可将 trace 压缩到 5-10%

**trace-slice**（Rust 实现）：
- 处理速度：24M 行 / 2.88GB 约 8 秒
- 支持 ARM64 指令级反向切片
- 输出：影响目标值的指令子集

**正向切片**（从输入追踪输出）：
- 从输入参数出发
- 追踪数据流到最终输出
- 用于参数追踪和污点分析

### 5. 污点分析

**LTV-taint**（DuckDB 存储）：
- 向前污点传播：标记输入字节，追踪其在内存和寄存器中的传播
- 向后污点传播：从输出回溯到输入
- 支持条件污点（只在特定分支条件下传播）

**典型应用**：
- 追踪加密密钥来源（从 Java 层传入 → JNI → Native 加密）
- 定位签名参数的生成路径
- 识别反混淆后的真实控制流

### 6. 语义提升与算法恢复

**VMLifter**（基于 trace 的语义提升）：
- 输入：指令级 trace（如 108K 行）
- 处理：将 ARM64 指令序列提升为高级语义操作
- 输出：压缩后的伪代码（如 756 行）
- 后续：用 LLM（Gemini/GPT）识别算法类型

**算法恢复 SOP**：
1. 采集目标函数的完整 trace
2. 反向切片提取核心计算路径
3. 语义提升压缩指令序列
4. 用 LLM 识别算法模式（hash、encrypt、MAC、KDF 等）
5. 对照标准算法验证（替换常数、查表）
6. Python 复现并与原始输出对比

### 7. 可视化分析

**trace-ui**（Tauri + React）：
- 调用树折叠：展开/收起函数调用层级
- 反向污点追踪面板：点击输出值回溯影响链
- 寄存器面板：逐指令显示寄存器变化（事后分析，非实时调试）
- 内存面板：追踪内存读写操作

### 8. 与其他 Topic 的联动

- **deobfuscation**：OLLVM 反混淆时，先用 trace 确认真实执行路径，再做静态还原。trace 是 `deobfuscation-before-hook` 原则的补充验证手段
- **vmp-analysis**：VMP handler 分析需要 trace 来逐条追踪 VM 字节码执行，识别 opcode 语义
- **unidbg-simulation**：Unidbg trace 是本 topic 的主要采集方式；trace 优化配置见该 playbook
- **crypto-protocol**：算法恢复后需在 crypto-protocol topic 中进行完整协议还原

## 常见偏差

- 采集全量 trace 再分析——应先做切片和过滤，只分析相关路径
- 不限定模块范围——libc/libart 的 trace 占 50%+ 且无分析价值
- 只用 trace 不做语义提升——原始 trace 量大且难以理解，必须压缩
- 不验证恢复的算法——必须用真实输入输出对验证 Python 复现
- 忽略 trace 对性能的影响——Stalker trace 会显著降低目标执行速度（10-100x）
- 混淆 trace 采集和分析——采集在目标环境，分析在本地，不要在目标上做重量级分析

## 最小交付

- `run/trace-analysis-notes.md`
- trace 采集配置（工具、范围、粒度）
- 切片/污点分析结果
- 恢复的算法伪代码或 Python 复现
- 验证：与原始输入输出对比记录

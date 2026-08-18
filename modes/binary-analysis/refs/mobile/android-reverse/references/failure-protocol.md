# 失败处理与停损协议

> 本文件收纳失败处理、止损规则、retrospective 协议、pivot 质量门禁、困难场景强制路径、以及"何时允许向用户报告无法完成"的全部条件。
> SKILL.md 仅保留一句话指针。同一方法连续失败、触发止损、需要 pivot 或准备报告无法完成前必须读取本文件。

## 目录

- 失败处理
- 停损与困难处理
- 时间止损补充
- 单字段止损规则
- pivot 质量门禁
- pivot 假设前置规则
- 重复操作止损
- Retrospective 协议
- 困难场景强制路径
- 何时允许向用户报告"无法完成"

## 失败处理

同一方法（相同工具 + 相同策略）连续 3 次失败后，必须转向完全不同的方法。每次失败都必须用 `task-record-attempt --kind=probe|patch|verify --status=failed|invalid|inconclusive --tool=<tool> --strategy=<strategy> --evidence=<path>` 写入 `route-state.json::approachHistory`；不得只在正文或 report.md 里描述。

转向前检查 `approachHistory`：如果新方法在历史中出现过且结果为 `failed / invalid / inconclusive`，跳过该方法换下一个。

| 条件 | 动作 |
|------|------|
| 同一方法 3 次失败 | 该方法标记 EXHAUSTED，必须转向 |
| 任何 10 次工具调用无进展 | 强制 retrospective |
| approachHistory 出现旋转模式（A→B→C→A） | 跳过已失败方法 |
| approachHistory ≥ 15 条 | 向用户报告低成功率 |

## 停损与困难处理

| 阶段            | 停损条件                              | 动作                                     |
| --------------- | ------------------------------------- | ---------------------------------------- |
| Observe         | 连续 2 轮无法确定防护等级或运行时类型 | 搜索已知特征 → 切换分诊策略或补动态探测 |
| Capture/Rebuild | 连续 2 轮无新增验收证据               | 搜索已知保护/混淆特征 → pivot           |
| Patch           | 连续 3 轮绕过失败且无新检测面发现     | 搜索公开绕过方案 → 切换绕过策略         |
| 整体            | 连续 4 轮无任何阶段进展               | 搜索 → 强制 retrospective               |
| 全局            | 累计 2 次 retrospective 后仍无进展    | 向用户报告并请求方向指导                 |

## 时间止损补充

同一切入点（同一工具链+同一策略）累计超过 8 turn 仍无 completionCriteria 硬证据，必须立即 pivot。累计 12 turn 仅产出"发现了X需进一步分析"类结论，必须强制 retrospective。

## 单字段止损规则

对单个未知字段（如 a2/a5/a9 的某一方面）使用同一分析策略（如穷举熵源、穷举密钥）累计超过 **4 turn** 仍无收敛迹象时，必须执行以下动作之一：

1. **接受当前结论边界**：将"该字段依赖 native 内部不可还原状态"作为结论写入 progress.md，标记为 `provisional` 精度，然后 pivot 到其他字段
2. **升级策略**：从黑盒探测升级到白盒静态分析（如从 Frida hook 升级到 IDA 汇编级追踪）
3. **降级并跳过**：若该字段不是 completionCriteria 的直接阻塞项，标记为 `DEFERRED`，先推进其他更接近交付的字段

判断"是否收敛"的标准：连续 2 轮产出的事实是否在缩小假设空间（如从 6 种可能缩到 2 种），还是只是在同一空间内增加样本。若只是增加样本而不缩小空间，即为不收敛。示例：穷举 a2 来源时，第 1 轮排除 rand、第 2 轮排除 time → 收敛（空间从 5 缩到 3）；第 3 轮和第 4 轮只是换了不同 process 再采样，结论仍为"不确定" → 不收敛。

## pivot 质量门禁

触发 pivot 时，新切入点必须声明 `[pivot] 从 {旧} → 到 {新}`，且满足至少一项：工具链不同 / 分析层次不同 / 目标不同。**额外要求**：pivot 前必须 Read `route-state.json` 的 `approachHistory`，确认新切入点不与任何 `failed / invalid / inconclusive` 记录匹配。若匹配，输出 `[路线检查] pivot 目标匹配历史失败记录，更换方向`，必须重新选择切入点。

## pivot 假设前置规则

每次 pivot 后、执行第一个工具调用之前，必须用 1 句话声明**可证伪假设**：`假设 X，如果成立则应观察到 Y，否则转向 Z`。Z 必须是一个具体不同的分析方向（不同工具/层次/目标），不允许"继续探索"等模糊方向。这防止在同一维度内做无结构的随机探索。示例：`假设 a2 来自 libc random()，如果成立则固定 random 返回值后 a2 应不再变化，否则 pivot 到纯静态 IDA 追踪内部状态机`。若假设在 2 轮内无法被证伪（无明确的"应观察到 Y"），该假设不合格，需重新声明。

## 重复操作止损

连续 3 次因同一环境问题（PID 漂移、进程选择、spawn/attach 切换）失败时，不得继续重试，必须：1. 把环境探测逻辑封装为一个可复用脚本 2. 或 pivot 到不依赖该环境的分析方向（如纯静态分析）。

> Frida spawn/attach 连接异常（卡住/`closed`/server 不可用/启动后断开）必须先按 `anti-frida-playbook.md` 的"spawn/attach 异常诊断闭环"排查设备状态（锁屏/解锁/`adb reboot` 复测），闭环完成前不计入"失败次数"，也不得归因到版本/端口/脚本/检测链。

遇到明确的工具链能力边界（非 OLLVM 混淆类）时，3 轮内主动向用户报告：已尝试 + 边界判断 + 建议下一步。OLLVM 混淆导致的"反编译不可读"不算能力边界——必须先按「分析中信号门禁」（见 `signal-gates.md`）的 FLA/BR/BCF/SUB 手动还原步骤执行至少一轮分析。

## 动态-静态 pivot 专项

与"同一方法 3 次失败"的通用规则并行，Native SO 场景有更具体的止损口径。**有效动态测试**包括：新增/修改 Frida hook、inline patch、返回值替换、syscall/libc hook、spawn/child-gating/runner 覆盖策略、fork/线程/端口/maps 隐藏策略等会改变运行行为的验证轮次。

**触发条件**：同一 SO、同一函数、同一检测链或同一调度链内，有效动态测试失败累计 **3 次**后，禁止继续新增或扩大动态 hook/patch/runner/隐藏等变量。

**触发后必须转入静态闭环**（不得用叠加动态变量绕过止损）：

1. 用内核 syscall 捕获整理 syscall 与 `pc/lr/sp`（见 `so-runtime-evidence-playbook.md` §4）
2. 判定目标 SO 是否加密/壳化/自解密/运行时重建；命中则 dump/fix 运行期 SO（§1-§2）
3. IDA 导出 dump/fix 产物，先分析 `.init`/`.init_array`/constructor/JNI_OnLoad
4. 完成匿名执行证据 6 项（§3），关键逻辑在匿名段时 dump/fix 匿名段
5. 检查 CRC/完整性校验（`integrity-pinning-playbook.md` Native 自校验专项）
6. 确认崩溃点函数范围（`native-so-playbook.md` 函数范围确认），完整分析函数上下游、fatal 分支、状态码

**完成静态闭环后**，可按静态结论**成组调整** patch/hook/runner 覆盖（不是逐次试错）；每组调整都要在 `run/` 产物中说明分析依据、工具、命令、代码改动、检测代码明细、结果与下一步。未完成静态闭环前，只允许做不改变目标行为的证据采集，或 dump/fix、IDA/OLLVM 还原、日志归属整理。

动态测试失败次数、对应 SO/函数/调度链、静态闭环进度必须通过 `task-record-attempt` 落盘到 `route-state.json` 的 `approachHistory`，并同步写入 `run/so-runtime-evidence-notes.md`。

## Retrospective 协议

触发条件：止损表"强制 retrospective"命中 / 12 turn 停滞 / 用户纠正关键假设 / 所有切入点 PARKED/EXHAUSTED / 初始假设被推翻。

**隐式触发条件**（以下场景也必须触发 retrospective 写入，不得仅在正文输出然后跳过）：

- 同一分析策略连续失败 **3 次**（如 3 次不同的 Frida 脚本都因同一环境问题失败、3 次不同 key 解密都未产出可读结果）
- 压缩恢复时 `retrospectiveCount` 为 0 但会话已超过 20 turn → 必须在本次恢复中写入至少 1 条 retrospective

执行步骤：0. 前置落盘（若由用户纠正触发）→ 1. 暂停分析（Read/Write/Edit 除外）→ 2. 回顾 task.json + route-state.json（含 `approachHistory`）→ 3. 识别卡点根因（卡在哪？哪个假设可能错？未利用的线索？哪些方法已标记 EXHAUSTED？）→ 4. 生成 >=2 条实质性不同的新切入点（必须确认不匹配 `approachHistory` 中任何 FAILED 记录）→ 5. 写入 `route-state.json` 的 `retrospectives` 数组（含触发原因、根因分析、新切入点列表、时间戳），更新 `retrospectiveCount`。

**retrospective 写入质量要求**：每条记录的根因分析必须包含"**做了什么、期望什么、实际什么、为什么不可行**"四要素。缺少四要素中任一条的记录不计入 retrospectiveCount。`failedBecause` 必须引用 `approachHistory` 中对应的记录，并包含 `failedPattern`（失败模式分类）。

**四要素最低信息标准**（形式审查）：
- `期望什么`：必须包含具体的目标状态（不是"获取到签名值"而是"调用 sign(body, timestamp) 返回 hex string，长度 32"）
- `实际什么`：必须包含工具返回的错误信息、实际观察到的输出、或与期望的差异描述（不是"未成功"而是"返回空字符串 ''，无 crash log"）
- `为什么不可行`：必须包含具体的阻碍因素（不是"工具限制"而是"IDA decompile 返回 JUMPOUT，FLA dispatcher 包含 47 个 case block，需先完成 FLA 还原才能继续"）

正文输出 `[retrospective] 触发原因: X, 根因: Y, 失败模式: {failedPattern}, 涉及方法: {M1},{M2}, 新方向: Z1, Z2`

## 困难场景强制路径

遇到困难时**不允许直接放弃**，必须按指定路径逐级尝试。

**T4/T5 分流门控**：若 `deliverableTier` 为 T4 或 T5，且困难属于"混淆导致无法追踪调用链"或"Native 层加密/签名复杂"：OLLVM 类 → Read `deobfuscation-playbook.md` 的 "T4/T5 强制路径" 节；VMP 类 → Read `vmp-analysis-playbook.md` + `deobfuscation-playbook.md` 的 "T4/T5 强制路径"。T4/T5 路径穷尽后才允许回退到以下 Frida 兜底。

每条路径第一步都是搜索公开工具/方案：

- **加固/壳无法反编译** → 按 `references/unpack-tool-matrix.md` 选择专用脱壳工具（eBPFDexDumper → BlackDex → FunDex2 → FART/FART+Frida）→ Smali Patch 脱壳 → 最后才考虑纯 Frida dumpclass
- **混淆无法追踪调用链** → 搜索反混淆工具 → OLLVM 类必须 Read deobfuscation-playbook → 字符串锚点 → xref 反向追踪 → Frida 动态追踪
- **反调试/反 Frida 导致 hook 失效** → 根据实际检测层级和注入时序按 `references/unpack-tool-matrix.md` 选择替代路线 → 可定位时做 Smali Patch 去检测 → 只有新证据表明运行时仍可进入时才重试 Frida
- **Native 层加密/签名复杂** → 搜索已知加密实现 → 动态输入输出对比 → 符号定位 → IDA 深入分析。若 IDA 不可用，必须停下来请求用户启动（不得静默降级到 radare2）

**"尝试"的最低标准**：每步必须产出可记录的证据，无证据的尝试不计入"已尝试"。

## 何时允许向用户报告"无法完成"

满足**全部条件**时才允许：1. 至少 3 条实质性不同的切入点（不同工具链/层次/目标）2. 至少 1 次 retrospective 3. 每条切入点有具体失败证据（做了什么、期望什么、实际什么、为什么不可行）4. 当前梯度所有可行路线 EXHAUSTED（必须 Read `route-state.json` 确认所有主要方法均已标记 EXHAUSTED）5. 报告包含每条切入点记录、失败证据、retrospective 结论 6. 2 次 retrospective 后仍无进展可请求协作。不满足就输出"无法完成"视为违规放弃。

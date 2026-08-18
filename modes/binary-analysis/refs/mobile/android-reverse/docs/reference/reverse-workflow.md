<!-- publish: framework -->
# Reverse Workflow

这是 `android-reverse` 的执行协议，不是人类教程。

## 阶段总览

0. `RouteSync`
1. `Observe`
2. `Capture`
3. `Rebuild`
4. `Patch`
5. `PureExtraction`
6. `Port`
7. `Close`

## 阶段切换规则

- 每个阶段结束时，先刷新 `route-state.json`，再回写 `route-plan / clues / progress`，再补 `report.md`
- 每个阶段收尾后都要刷新 `route-state.execution`；若 `execution.status=ready-to-continue`，就在同一轮继续执行 `nextExecutableAction`
- 只要下一阶段前提已经满足，就在同一轮内直接进入下一阶段，不把“阶段总结”当作暂停点
- 恢复已有任务时，`RouteSync` 完成后立刻回到当前活跃阶段执行
- 只有用户协作阻塞、高风险副作用确认、或 `Close` 已完成时，才允许停下等待用户

## Entrypoint Loop

`android-reverse` 默认使用 `Hypothesis -> Probe -> Evaluate -> Pivot -> Retry` 循环，而不是单专题直线推进。这里的 Evaluate 必须落到 `route-state.json`，不能只停在聊天推理。

规则如下：

1. 先列 2 到 5 个候选 `entrypoints`
2. 按成本、信息增益、复用价值排序
3. 同时只激活 1 到 2 个切入点
4. 单次推进先验证最便宜的 probe
5. 每次 probe / patch / verify / 用户优先工具预检后，立即运行 `task-record-attempt`
6. 有效就扩展同一切入点并绑定更多专题
7. 无效就把它 `PARKED / EXHAUSTED`，切到下一条
8. 如果现有切入点全部无效，先做 `retrospective`，再生成新切入点

## Attempt 记录协议

LLM 可以分析，但不能把“我觉得试过了”当作状态事实。每次行动后必须记录：

```bash
node <SKILL_BASE>/tools/task/task-record-attempt.mjs <task-id> \
  --kind=probe|patch|verify|tool \
  --status=success|failed|blocked|invalid|inconclusive \
  --tool=<tool> \
  --strategy=<strategy> \
  --entrypoint=EP-001 \
  --evidence=run/example.log
```

状态解释：

- `success`：产生了可复用证据，并能缩小假设空间
- `failed`：有效尝试但结果否定了假设
- `invalid`：验证环境或 harness 无效，不能用于 patch / 完成依据
- `inconclusive`：结果不能区分假设，不能升格为事实
- `blocked`：外部条件阻塞，可等待用户或记录降级

`task-advance` 只根据结构化状态给下一步。若返回 `needs-tool-preflight / needs-evidence / needs-retrospective / needs-state-repair`，先修该闸门，不继续业务 patch。

## 每轮最小控制包

每轮结束时必须自检并记录到 `route-state.json` 与 `progress.md`：
1. 本轮是否更接近用户最终验收（是/否/具体证据）
2. 当前切入点状态（active/parked/exhausted）
3. 当前最贵的未知项是什么
4. acceptanceGap：距用户目标还差什么
5. 如果下一轮仍不收敛，准备停掉哪条路线
6. **线索刷新**：本轮是否有新确认的发现（算法、密钥、协议结构、调用链闭合）？若有且尚未写入 `clues.md`，必须在输出 progress 前先执行落盘（见 `references/output-gates.md`「突破性发现即时落盘」，SKILL.md 协议路由表已索引）

## 阶段回退协议

允许从高阶段主动回退到低阶段（保留已建立的证据和脚本），回退不等于放弃：
- Capture → Observe：初始分诊不完整
- Rebuild → Capture：证据不足以支撑重建
- Patch → Rebuild：重建不完整导致无法定位 patch 点

回退时必须写出：回退原因、保留内容清单、回退后的第一条 probe。

## 平台化解释

- `Observe`: 以 APK/APKS/AAB、Manifest、壳迹象、运行时类型和主组件为中心做任务分诊
- `Capture`: 用静态分析、Frida、日志、JNI/Native/网络取证建立证据链
- `Rebuild`: 把关键路径重建为最小可验证脚本、hook 模板或复现实验
- `Patch`: 按最小原因修补壳、完整性、Pinning、ClassLoader 或环境阻塞
- `PureExtraction`: 把运行时噪音和纯协议/纯算法边界分开
- `Port`: 把稳定逻辑移植到脚本、夹具或外部宿主并完成一次验收

## Close

`Close` 不是新的逆向阶段，而是交付收口阶段。

标准顺序：

1. `task-close` 先做自动修复
2. 运行 `validation`
3. 执行 cleanup

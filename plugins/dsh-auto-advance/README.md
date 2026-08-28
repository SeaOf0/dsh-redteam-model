# dsh-auto-advance 自动推进器

八专业模式的事件驱动闭环最后一环：执行体返回 → 台账有未收口方向 → followup 推进提醒。

## 做什么

subagent 类工具（原生 `subagent`/`subagent_fork` + `subagent_claude_code`/`subagent_codex` 等
`subagent` 前缀工具）的 result 到达时，若工作区 operation-state 意图台账存在 open 意图，
注入一条推进提醒：

- 先 `operation_progress` 收口本次执行对应的意图（`intent_done` 附产出指位 /
  `intent_blocked` 附原因）；
- 再依锚 `operation_intent` 派下一步，或无下一步时静默收尾（不硬造方向）；
- 派单 prompt 里写了 `i1/i2` 时点名对应意图（以 prompt 提及为准）。

## 三护栏（自主不失控）

| 护栏 | 语义 |
| --- | --- |
| 轮数上限 | 连续自动推进 `maxAutoTurns`（默认 5）轮封顶；真人消息重置计数 |
| opt-in | 仅意图台账存在且有 open 意图时激活（登记即激活，与 scope 同纪律） |
| 自描述注入 | 提醒自带台账态势（收口什么/还剩什么/第几轮/人工随时接管），可审计 |

另有冷却窗 `cooldownMs`（默认 30s）：并行执行体齐返回并作一次推进，不刷屏。

## 边界

- 只注入，不拦截不改写；非八专业模式/无台账会话零干扰。
- followup 源标记 `kind:"user"`（与 attack-atlas 覆盖提醒同款），自注入 id 被排除在
  「真人重置」判定外。
- 注入失败不重试（下一执行体返回自然再试）。

## 配置

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `enable` | `true` | 总开关 |
| `maxAutoTurns` | `5` | 连续自动推进轮数上限 |
| `cooldownMs` | `30000` | 冷却窗（毫秒） |

## 测试

`node test/run.mjs`——决策纯函数全分支/装配接线/三护栏/真人重置/意图点名。

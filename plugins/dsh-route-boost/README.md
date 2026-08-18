# dsh-route-boost

七预设（modes/）的**逐轮治理信封**——「红队完整上线」逐轮注入逻辑的 DSH
原生实现，v0.2 补齐其阶段记忆/证据预判/强制检索三要素后**核心能力对齐并在四维反超**
（结构门禁 18>5 门、组合层物理强制、跨模型双签真实存在、变化才注入的成本模型）。

## 机制（全原生，无 hook hack）

- 注册一个 `ctx.systemPrompt.context()` **动态上下文节**（宿主平面全局层，全模式装配可见）。
- 每步装配时 text 函数现场求值：`agentPresets.composedPreset(agent.ctx)` 取当前模式 →
  用缓存的**最新人类用户输入**（`agent/inbox/inserted` 时刻更新——消灭"本轮装配先于
  user/message 入 session"的一轮滞后；只认 `source.kind === "user"`，与 apiproxy 判真实
  输入同款，机器 user 消息不污染）做阶段推断 → 渲染信封。
- agent-loop 的 `RuntimeContextProjection` 只在**信封文本变化时**投递一条快照 user 消息——
  同阶段零成本，阶段切换自动重新锚定。非安全预设（无路由表）渲染空文本，零干扰。

## 信封内容（默认 ≤1600 字符）

```
[route-boost] mode=<preset>（中文名） phase=<id> <标签>（推断——若与实际任务不符，以实际为准继续）
gates: <本阶段相关门> —— 结构校验调 stage_gate，语义门禁归复核员（independent-review）
review: 关键 finding 双签 = DSH 独立复核 + subagent_claude_code 复核一致；仅确认/挑战二选一
boundary: <模式边界一行：速率/资金红线/登记前置/三声明等>
evidence: <confirmed/partial/unknown>（confirmed=用户已附原始证据材料；partial/unknown=先补证据）
refs: refs/<命中类目>/README.md（指针不灌正文，控上下文成本）——无命中时改为强制检索提示
```

- **阶段粘滞（v0.2）**：无关键词命中的输入沿用上一阶段（裸"继续"不重置），显式关键词覆盖；
- **证据等级预判（v0.2）**：从用户文本推断 confirmed/partial/unknown 注入（沿袭
  evidence-level 的七预设版）；
- **强制检索提示（v0.2）**：refs 无命中时提示"先 web_search 或读本模式 refs/README.md，
  勿凭记忆自答"（其 internet-fallback "never let the model self-answer" 的等价物）。

gate 标题直接 import `dsh-stage-gate` 的 `GATES`（单一事实源；同级目录缺失时降级内置摘要）。

## operation 恢复行

工作区存在 `operation-state.json` 且有未收口准则/待办时，信封第 2 行注入「operation 恢复」：
goal（截断 80）+ 准则 met 进度 + 未收口 id + 待办数 + 最近门判定——中断续作的对齐锚点；
全 met 的终态契约不占信封预算。

## 已知取舍

- **正文级 skill-boost 不做（设计取舍）**：对方每轮灌命中技能前 2000 字，我们只给指针——
  七预设 refs 规模大（500+ 篇），逐轮灌正文会撑爆上下文；模型按指针自取 + persona 纪律。
  翻转开关留 v0.3（includeRefs 已参数化）。
- **会话内模式切换**：DSH 平台约束（仅 blank 会话可选预设），生态规则（子代理+跨模式
  playbook）补偿，本插件不解决。
- **OPSEC 关键词调级**：不补——七预设速率纪律在 persona/playbook 有静态默认，
  运行时调级价值低。

## 验证

- `node test/run.mjs` — 121 项离线单测（路由命中/粘滞/证据/信封渲染/gate 引用存在性/决定性）
- `node ../../../.zcode/chain-probe.mjs` — 七预设作用域真实 `systemPrompt.assemble()` 渲染实证
- `node ../../../.zcode/route-boost-live.mjs` — 真实 AgentLoop 四轮 8 项检查（注入/切换/去重/粘滞/
  证据行/留痕）全部通过
- 真机验收：重启 dsh web 后任一模式会话发首条消息，观察 `[route-boost]` 快照与阶段切换时机

## 安装（本机已装）

web profile `package.json`：dependencies 加 `@dsh-external/dsh-route-boost` link +
`dsh.profile.bundles` 追加同名 bundle，`pnpm install`，**重启 dsh web 生效**。
新环境随 `dsh-redteam-model/deploy/` 一键部署（hostPlane 组）。

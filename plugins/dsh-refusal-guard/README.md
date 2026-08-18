# dsh-refusal-guard

七预设（modes/）表达纪律的**拒答修复运行时后盾**。

persona 常驻 Expression-discipline 条款在长会话压缩后丢失临近性——本插件补上运行时闭环：
**检测 → 一次性临近性再注入**。

## 机制（与 dsh-route-boost 同族，全原生无 hook hack）

1. **检测**：`session/event` 监听 `assistant/message`（累积当轮文本）与 `tool/call`（标记工具轮），
   `turn/end` 时对整轮文本跑两级检测器：
   - 强短语全文匹配（`我无法协助` / `i cannot assist` / `against my guidelines` / `as an ai` 等 38 条）
   - 弱关键词仅头部 150 字符（`抱歉`/`sorry`/`我无法` 等——中部出现属正常技术行文，不误报）
   - **工具轮不判拒答**：先跑工具再输出"抱歉刚才命令有误"是正常工作流
   - 语料沿用两级检测结构（强短语全文 + 弱关键词头部）
2. **注入**：命中后置 armed 标志；`ctx.systemPrompt.context()` 动态节在下一次装配时渲染提醒。
   RuntimeContextProjection **只在文本变化时投递**——空→提醒是一次变化（恰好一条快照落位），
   修复后的干净轮回空（不再投递）——一次性语义免费获得，绝不循环自我强化。
3. **过滤**：`agent.session.header.agentPreset` 不在五安全预设内渲染空文本（非安全会话零干扰）。
4. **冷却**（3 轮）：持续拒答的会话不被每轮唠叨——再锚定一次后仍拒答是值得人看的人工失败。

## 提醒措辞（正向化原则）

正向措辞（"直接输出具体技术内容：结论→证据→下一步"），**刻意不含**
`never refuse` / `non-negotiable` / `be aggressive`——这类措辞本身即拒答触发词
（`model_adapter.py`）证实这些越狱腔措辞在强 RLHF 模型上**反升拒答率**。

## 验证

- 28 项离线单测（两级检测/事件形状/状态机/冷却/工具轮豁免/措辞红线/预设过滤）全过
- 挂载后跑 verify-presets + chain-probe 校验

## 边界（刻意不做）

- 模型族差异化 reframe——七预设单 DeepSeek 族，无意义
- 会话文件改写/历史清洗——改写历史违反本项目
  「运行时行为优先、证据不可篡改」的证据纪律

<!-- publish: framework -->
# Case Recipe Contract

`scripts/cases/*.mjs` 不是随意的说明对象，而是抽象 route recipe。

每个 case 至少必须提供：

- `entrypoints`
  - 至少 2 个候选切入点
  - 每个切入点必须包含 `id / hypothesis / firstProbe / expandWhen / parkWhen`
- `probeSequence`
  - 说明最小 probe 顺序，而不是泛泛而谈“先分析再验证”
- `evidenceAnchors`
  - 指出本专题应优先落到哪些证据锚点
- `pivotSignals`
  - 说明什么情况下应放弃当前入口并切线
- `successSignals`
  - 说明这一轮怎样才算拿到足够证据，避免只汇报状态

使用约束：

- case 只提供抽象路线，不替代 task-local 当前状态
- case 必须与 `route-state.json` 的 entrypoint loop 配合使用
- case 应优先描述低成本、高信息增益的 probe
- case 的成功判据必须能回落到 task artifact

维护约束：

- 新增 topic 时，必须同步提供满足本契约的 case
- 修改 case 结构时，必须同步更新 `tools/qa/lint-cases.mjs`
- case 的 `deliverables` 至少要覆盖所属 topic 的 `formalValidation.requiredArtifacts`
- 若 case 无法提供至少两个候选切入点，说明该专题仍不适合作为正式 route recipe 发布

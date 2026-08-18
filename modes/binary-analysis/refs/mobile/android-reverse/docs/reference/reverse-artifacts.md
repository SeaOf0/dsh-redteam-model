<!-- publish: framework -->
# Reverse Artifacts

正式产物分三层：

- 状态层：`state/route-state.json`、`state/route-plan.md`、`state/clues.md`、`state/progress.md`
- 证据层：`network.jsonl / runtime-evidence.jsonl / static-evidence.jsonl / memory-evidence.jsonl / logcat.jsonl`
- 结论层：`report.md`、`run/*`

原则：

- 状态层不承载原始证据
- 状态层必须能恢复 `tracks + entrypoints + retrospectives`
- 证据层不承载任务编排
- 结论层必须能回指证据层与状态层


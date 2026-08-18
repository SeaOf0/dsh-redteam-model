# Validation Checklist

- 当前阶段与 `route-state.execution.nextPhase` 一致
- 活跃切入点与 `nextExecutableAction` 可相互印证
- 关键 evidence 已写入 task-local
- 命中网络、内存或运行时专题时，`network.jsonl / memory-evidence.jsonl / runtime-evidence.jsonl / logcat.jsonl` 已按需落证
- 若命中 `protection-bypass`，`root / frida / integrity / pinning` 四个子面都已被显式裁定，而不是停留在 `not-started`
- 若命中 `protection-bypass`，对应命中子面的脚本工件已落盘，未命中子面已标记 `not-applicable`
- 报告结论能回指函数、地址、模块、脚本或日志
- 输出满足 `artifacts/tasks/<task-id>/report.md`、`run/fixtures.json`、`state/route-state.json`
- 命中的 topic artifacts 已在报告或 task-local 中留痕
- 若 `protectionTier >= A2` 且累计执行 >= 3 轮，`route-state.json` 的 `search.searchRounds` > 0（搜索已完成且结果已落盘）


# Tool Defaults

- 默认阶段：`Observe`
- 默认切入点上限：`2`
- 默认 probe 最大轮次：`2`
- 默认工作语言：中文
- 默认最小交付：`artifacts/tasks/<task-id>/report.md`、`run/fixtures.json`、`state/route-state.json`

## 阶段转换规则

```
RouteSync → Observe → Capture → Rebuild → Patch → PureExtraction → Port → Close
```

| 当前阶段 | 前进条件 | 回退条件 |
|---------|---------|---------|
| Observe → Capture | 防护等级已确定 + 运行时类型已识别 + entrypoints 已列出 | — |
| Capture → Rebuild | 至少一条切入点的证据已捕获（hook 日志 / 抓包 / 内存 dump） | 初始分诊不完整（如壳未脱、Split 未重组） |
| Rebuild → Patch | 关键路径已重建为最小可验证脚本 / 复现实验 | 证据不足以支撑重建 |
| Patch → PureExtraction | Patch 已验证通过（安装 + 运行 + 目标功能正常） | 重建不完整导致无法定位 patch 点 |
| PureExtraction → Port | 平台噪音已剥离 + 纯算法/逻辑边界已明确 | — |
| Port → Close | 移植后脚本/夹具通过验收 | — |

**同一轮内前进**：只要下一阶段前提已满足，在同一轮内直接进入，不把"阶段总结"当停点。

**回退规则**：允许主动回退（保留已建立的证据和脚本），回退时必须写出：回退原因、保留内容清单、回退后的第一条 probe。


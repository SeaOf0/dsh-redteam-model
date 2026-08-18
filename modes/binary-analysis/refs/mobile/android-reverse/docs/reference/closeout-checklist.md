<!-- publish: framework -->
# Closeout Checklist

## 硬门槛

1. `task.json`、`report.md`、`run/fixtures.json` 存在且可读取。
2. `state/route-state.json` 是状态真源，`route-plan / clues / progress` 与其生成结果一致。
3. 所有必需 `deliverables[]` 均为 `delivered`；部分完成只能停在 `acceptance-ready`、`blocked` 或 `in-progress`。
4. 每个必需 `completionCriteria` 精确为 `met` 且包含可读取的 `evidenceRefs`。
5. 交付物与各自 T1-T5 tier 匹配，未使用被否决的回退路线。
6. T5/本地复现存在新鲜的 `run/verification-result.json`；T3 存在通过的 no-op 基线和回归矩阵。
7. 报告没有把未执行的用户验收、真实短信、登录或深层页面验证写成已确认。

## 自动修复边界

`task-close` 可以重新生成 Markdown 视图和规范报告段，但不能替用户补证据、自动把 criteria 改为 `met`，也不能把 `acceptance-ready` 提升为 `delivered`。关闭后会再次验证最终落盘状态；失败时回滚关闭状态。

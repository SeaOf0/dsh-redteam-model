# 快速开始

## 新任务

1. 阅读 `SKILL.md`
2. 阅读 `docs/reference/reverse-bootstrap.md`
3. 若当前 workspace 没有 history data files，优先执行 `node tools/task/task-start.mjs <task-id>`
4. 如果开局已能判断 topic 或交付约束，可把 `--topic=`、`--topics=`、topic alias flag、`--local-repro`、`--api-call-example`、`--task-input=...` 一起交给 `task-start`
5. 优先使用结构化 `task-input`；它会自动回填 `deliverables / boundaries / attachMode / packageName / hints`，并按线索补 topic pack
6. `task-start` 会在“无历史文件”时转发到 `task-init`；若 workspace 已有 history data files，则默认阻止再建第二个 task-local，除非显式传 `--force-new-task`
7. 执行 `node tools/task/task-sync.mjs <task-id>`，刷新 Markdown 视图、workspace bridge 与首轮 `execution`
8. 执行 `node tools/task/task-advance.mjs <task-id>`，拿到显式的 `execution.status / nextExecutableAction`
9. 从 `Observe` 开始推进，先形成候选 `entrypoints`
10. 在 `Observe` 稳定后确认切入点和证据面已成形
11. 再进入深 `Capture`，并把证据写入 task artifact
12. 若 `task-advance` 给出 `execution.status=ready-to-continue`，不要停在状态汇报，直接执行 `nextExecutableAction`
13. 日常迭代优先执行 `npm run smoke:quick`
14. 发布前执行 `npm test`；它会串行运行结构 QA 与 4 组 smoke 场景

## 继续已有任务

1. 进入现有 `artifacts/tasks/<task-id>/`
2. 执行 `node tools/task/task-sync.mjs <task-id>`
3. 执行 `node tools/task/task-advance.mjs <task-id>`
4. 先查看 `task.json`、`state/route-state.json`、`state/route-plan.md`、`state/clues.md`、`state/progress.md`
5. `task-sync` 本身已经刷新过一轮 `execution`；`task-advance` 负责做显式第二次判定，并在需要时写入 `pauseCategory / pauseReason`
6. 确认 `execution.status / nextExecutableAction` 后直接继续推进，不要停在“已恢复”
7. 如果已有 `Observe` 结果但最近发生 route pivot，可先重新确认切入点和证据面
8. 每一阶段结束都先落盘，再自动进入下一阶段；只有 `pauseCategory=user/risk`、缺样本或 closeout 才暂停
9. 如果任务包含 JNI / Native / Split / Framework runtime 风险，先补读对应 playbook 再做深挖

## 开始前建议补读

- `docs/guides/minimal-usage-manual.md`
- `docs/guides/task-lifecycle.md`


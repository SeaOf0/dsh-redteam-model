# 任务生命周期

一个标准任务应沿着下面的闭环推进：

1. `Init`
   若当前 workspace 没有 history data files，优先使用 `node tools/task/task-start.mjs <task-id>` 创建 task-local
   如果已能预判 topic 或交付约束，可在这里直接带 `--topic=`、`--topics=`、topic alias flag、`--local-repro`、`--api-call-example`、`--task-input=...`
   `task-start` 会在“无历史文件”时转发到 `task-init`；若已有 history data files，则默认阻止再建第二个 task-local，除非显式 `--force-new-task`
2. `Sync`
   使用 `node tools/task/task-sync.mjs <task-id>` 建立状态真源和 Markdown 视图
   如 task-local 中相关脚本仍是模板占位，`task-sync` 还会桥接 workspace 根目录已有的 `run/*` 脚本到 task-local
3. `Advance`
   使用 `node tools/task/task-advance.mjs <task-id>` 刷新 `execution.status / nextExecutableAction`
   如需显式写入暂停语义，可带 `--pause-category=`、`--pause-reason=`；如需程序化消费，可加 `--json`
4. `Observe`
   先识别专题、目标边界、包体结构、运行时类型和关键证据面
   同时列出 2 到 5 个候选切入点并排序
5. `Capture`
   采集静态结果、hook 日志、JNI / Native 证据、网络或存储样本输入输出
   先验证当前活跃切入点的最小 probe
7. `Rebuild`
   在本地重建关键逻辑、协议边界、hook 样本或最小验证脚本
8. `Patch`
   若环境、保护、ClassLoader、Pinning 或运行时边界阻塞验证，按 first divergence 做最小补丁
9. `PureExtraction`
   仅在 local rebuild 稳定后进入纯算法 / 纯协议提取
10. `Port`
   把算法、验证脚本或复现夹具迁移到目标宿主
11. `Close`
    更新 `report.md`，补齐 `verify-once`，再用 `node tools/task/task-close.mjs <task-id>` 收口
    `task-close` 会保留当前项目下的 task-local 数据，执行验证并清理任务产物
    closeout 前还会自动修复 `report.md` 必填段、同步 `route-plan / clues / progress`，并在需要时桥接 workspace 根目录已有脚本

补充约束：
- 每个阶段完成后先写盘，再自动进入下一阶段；不要把阶段总结、状态同步或恢复完成当作停点
- 每次 `task-sync` 后都要看 `execution.status`；若为 `ready-to-continue`，必须继续执行 `nextExecutableAction`
- 只有用户协作阻塞、高风险确认或 closeout 已完成时，才等待用户下一条指令
- `closeout` 完成后，必须把 `route-state / route-plan / progress / report.md` 同步到 `execution.status=completed`，不能遗留 `ready-to-continue -> verify-once`
- `topics` 是能力模块；`entrypoints` 才是当前推进顺序
- 若当前切入点无效，必须显式切换；若当前切入点集全部无效，必须先复盘，再生成新切入点

## 每个任务至少应留下

- `artifacts/tasks/<task-id>/report.md`
- `artifacts/tasks/<task-id>/run/verify-once.mjs`
- `artifacts/tasks/<task-id>/run/fixtures.json`
- 与专题相关的最小脚本、样本和说明


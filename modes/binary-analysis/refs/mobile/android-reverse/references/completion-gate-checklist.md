# 完成门禁 Checklist

只在准备使用“已完成、已成功、已交付、已闭环”等措辞时执行。

1. 读取 `task.json`，确认 objective 仍是用户原话，当前交付没有命中 `disallowedFallbacks` 或 `userRejectedApproaches`。
2. 检查每个必需 `deliverables[]`：只有该交付单元的所有 `criteriaIds` 都有硬证据时，状态才可为 `delivered`。
3. `completionCriteria` 使用精确状态：`pending | met | blocked | rejected`。完成时所有必需条件必须为 `met`；不再接受 `hit/passed/done` 等模糊兼容状态。
4. 检查 `report.md`、`task.json`、`run/fixtures.json` 和专题要求的物理产物。证据引用必须指向存在的文件或日志位置。
5. T5 或本地复现：运行 `node <SKILL_BASE>/tools/task/task-verify.mjs <task>`；验证结果必须与当前 spec 和入口哈希一致，T5 至少包含两组不同输入/输出向量。
6. T3：确认 no-op 重打包/重签/安装/冷启动基线通过；确认 `cold-start`、`core-path`、`signature-integrity` 以及 objective 特定路径的回归证据。若使用卸载，必须有用户同意清数据的记录。
7. 运行 `node <SKILL_BASE>/tools/task/task-close.mjs <task>`。只有命令成功且最终状态复验通过，才允许声明整个任务完成。

只完成部分 deliverable 时，明确列出已交付和待验收部分；不要关闭根任务。

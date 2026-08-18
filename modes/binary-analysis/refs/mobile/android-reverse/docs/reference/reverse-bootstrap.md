<!-- publish: framework -->
# Reverse Bootstrap

这是 `android-reverse` 的 bootstrap 单一真源。`docs/reference/android-reverse-bootstrap.md` 仅是兼容桥接页。

## 新任务

1. 确认任务属于授权 Android 应用逆向，并取得目标路径、用户原始 objective、禁止操作和期望交付。
2. 快速分诊可直接执行；需要动态取证、patch、协议迁移或多轮续跑时，运行 `task-start` 创建 task-local。
3. 读取与当前信号直接相关的一个 playbook。其他参考文件按需读取，不要在取得首个领域证据前遍历全部协议。
4. `protectionTier` 在完成分诊前保持 `null`；专题命中不能代替保护证据。

## 续跑任务

按以下顺序恢复：

1. `task.json`
2. `state/route-state.json`
3. `report.md` 与 `run/fixtures.json`
4. `task-sync`，然后 `task-advance`
5. 若 `execution.status=ready-to-continue`，执行 `nextExecutableAction`

`route-plan.md / clues.md / progress.md` 是生成视图，不是第二状态源。

## 第一条工作回复

完整任务只需说明：用户目标与交付单元、当前阶段、本轮成功证据、下一可执行动作。工具状态只列真实阻塞或用户明确指定的工具；无需展示内部已读文档清单。

## 专项信号

命中 OLLVM/FLA/BR/BCF/SUB 或反编译出现 JUMPOUT 时，读取 `references/signal-gates.md`。A4 本身不等于 OLLVM，也不阻止模块枚举、Java hook 或 JNI 边界定位。

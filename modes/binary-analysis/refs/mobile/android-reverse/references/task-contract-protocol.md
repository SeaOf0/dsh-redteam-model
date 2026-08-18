# 任务契约协议

本文件定义 schema v2 的任务契约、复合交付、兼容迁移和快速分诊边界。契约的目的，是在长会话和上下文压缩后保留用户目标，而不是增加启动仪式。

## Schema v2

非平凡任务至少记录：

- `objective`：用户原话，不改写
- `deliverables[]`：一个或多个交付单元，每项包含 `id / tier / criteriaIds / status / required`
- `completionCriteria[]`：包含 `id / label / status / evidenceRefs`
- `currentDeliverableId`：当前推进的交付单元
- `protectionTier`：初始 `null`，分诊证据充分后才写 A0-A7
- `disallowedFallbacks`、`userRejectedApproaches`：用户否决，只增不减

`deliverableTier` 保留为单交付任务和旧工具的兼容视图。复合任务不得创造 `deliverableTierComposite`；以 `deliverables[]` 为准。

合法状态：

- criteria：`pending | met | blocked | rejected`
- deliverable：`in-progress | blocked | acceptance-ready | delivered | rejected`

`acceptance-ready` 表示 agent 侧验证完成，但仍缺用户操作或真实设备边界验收。不得自动提升为 `delivered`。

## 创建时序

1. 收集 target、objective、边界和期望交付。
2. 需要多轮、动态取证、T2-T5、patch 或协议恢复时，运行 `task-start`；快速分诊可不创建 task-local。
3. 把用户原话、交付单元和可观察验收条件写入 `task.json`。
4. 读取一个与当前信号直接相关的 playbook，开始最小成本观测。

创建契约前允许读取输入文件、Manifest 和做不会改变目标状态的轻量分诊；禁止在目标和安全边界尚不明确时执行安装、卸载、主动流量或 patch。

## 复合交付

自然任务可能同时需要多个梯度，例如“去广告并提供纯 Python 查询实现”。应拆成：

```json
{
  "deliverables": [
    { "id": "remove-ads", "tier": "T3", "criteriaIds": ["c1", "c2"], "status": "in-progress", "required": true },
    { "id": "local-query", "tier": "T5", "criteriaIds": ["c3", "c4"], "status": "in-progress", "required": true }
  ]
}
```

一个交付单元成功不能关闭其他交付单元。只有所有 `required=true` 的单元都是 `delivered`，根任务才能关闭。

## completionCriteria

每条标准必须说明可观察结果和证据位置，不能只写“完成、正常、稳定”。常见目标应排除表面捷径：

| 目标 | 必须排除 |
|---|---|
| 生成/实现 | 重放预捕获值 |
| 还原算法 | 调用原 SO、RPC 或只识别算法名 |
| 纯 Python/Node | 子进程、Frida、ADB、Android 运行时依赖 |
| T3 patch | 只构建、不重签安装启动；只验证一个页面却声称全局生效 |

完成状态必须通过结构化 `status` 写入，不从 label 中搜索 `pass/met/done` 子串。

## 交付梯度约束

- T1：证据链和可回指位置
- T2：可独立运行的 hook 脚本和运行时命中证据
- T3：最小根因 patch、no-op 重签基线、安装启动和任务特定回归矩阵；基础项必须实测，确实不存在的业务面仅凭理由和静态/组件证据标记 `not-applicable`
- T4：协议、字段、算法和来源文档；可使用动态分析辅助
- T5：独立本地实现，禁止最终运行时依赖原 SO、RPC、Frida、ADB、Unidbg/Unicorn/angr/Qiling；使用 `task-verify` 对至少两组不同输入/输出向量验证

这些约束按每个 deliverable 的 tier 应用，而不是按一个全局最高等级覆盖其他交付单元。

## 用户否决

用户明确否决路线时，先将方法族和用户原话追加到 `userRejectedApproaches`，再继续其他方向。用户明确授权重试前，不得复活该路线。隐式技术矛盾应先记录为新证据，不要自动当成用户否决。

## 快速分诊

问题范围窄、无需动态取证或修改目标时，可以完成反编译、关键词搜索和文字结论，不创建完整 route-state。出现以下任一情况后升级为 task-local：

- 需要 Frida、动态 dump、安装、重签或主动流量
- 需要跨 Java/JNI/Native 建链
- 需要多轮 pivot 或会话续跑
- 用户要求 T2-T5 交付

## 旧任务迁移

读取旧任务时只做内存兼容，不自动改写。显式迁移：

```text
node <SKILL_BASE>/tools/task/task-migrate.mjs <task> --to=2 --dry-run
node <SKILL_BASE>/tools/task/task-migrate.mjs <task> --to=2
```

迁移会备份 `task.json.v1.bak`，不会把旧任务自动标记为 delivered；已满足旧标准的任务最多迁移到 `acceptance-ready`，等待重新确认。

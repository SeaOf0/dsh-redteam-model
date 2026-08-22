# dsh-attack-atlas (AttackAtlas)

AttackAtlas——八专业模式的架构体系面板，置于「redteam 成果」标签页左侧。

- 未选专业模式：引导页提示进入八模式；进入后自动切换该模式体系
- 架构矩阵：战场分区 × 战术列 × 子项，形态切换与阶段带按模式定义；列序即方法论序
- 四态点亮（对齐各模式覆盖台账终态，语义随模式本地化）：已测·有发现（金）/ 已测·未命中 / 不适用 N-A（附原因）/ 预算耗尽；未测为暗格
- 攻防 / 应急 / 云三模式带链路拓扑图：攻击链与感染链节点登记后自动成图，重大成果金框标记，支持多入口与「从会话生成（模型登记）」
- 双击子项 / 主类 / 阶段 = 派单进当前会话（自动携带目标锚定与 refs 知识手册）
- 单键子项 = 详情浮层（状态 / 原因 / 关联 finding / 目标溯源 + 人工回写兜底）

模型侧工具：`redteam_coverage_mark`（格子 / 主类终态，多目标带 target 溯源）、`redteam_coverage_stage`（阶段推进）、`redteam_coverage_list`（终态全读）、`redteam_atlas_target`（作战目标登记）、`redteam_atlas_chain`（链路拓扑登记）。存储 `~/.dsh/attack-atlas/atlas.db`，(session, mode) 双键隔离。

测试：`node test/run.mjs`

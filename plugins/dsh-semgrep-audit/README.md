# dsh-semgrep-audit (semgrep 封装)

code-audit 扫描对账闭环的运行时化——本机 semgrep 封装为模型工具（不挂 scanner-tools，代审专属）。

- 工具 `semgrep_scan`：本地 semgrep + 预设离线三层规则集（自动定位 refs/：java 402 条自建 / php / oss 1080 条；layer=custom 指自定路径）
- 纪律内置：检测制（缺装拒绝，三级兜底提示，绝不自动装）；`--metrics=off` 离线；产物落 `artifacts/scans/semgrep-<ts>.json` + evidence-index 回行
- 命中进对账（双写）：`scan-reconcile.md`（人读）+ `scan-reconcile.csv`（机读，表头 `scanner,rule,file,line,verdict,reason`）待处置行——**命中 ≠ 漏洞**，复核+补真实调用链后经 `redteam_finding_register(sourceOrigin=scan-confirmed / scan-false-positive)` 升格，A3 门数量守恒
- 只读：静态扫描不写目标仓；产物只落任务工作区

挂载：preset 平面（code-audit 的 agent.cordis.yml 一行）。测试：`node test/run.mjs`

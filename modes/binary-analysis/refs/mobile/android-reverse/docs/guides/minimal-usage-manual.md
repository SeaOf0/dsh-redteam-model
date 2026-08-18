# 最小使用手册

## 1. 适用场景

当你要处理以下任务时，直接使用 `android-reverse`：

- APK / APKS / AAB / XAPK / DEX / SO / JNI 逆向
- AndroidManifest、组件、权限、资源、资产文件分诊
- Java 调用链、JNI 桥接、Native SO、Frida 动态取证
- Root / Frida / Integrity / Pinning / 模拟器 / 调试检测绕过
- 动态 Dex、壳、Split Delivery、Flutter / Hermes / Unity 运行时分析
- 协议恢复、签名链路、网络栈与本地复现实验
- 继续已有 task-local 并恢复上下文

## 2. 第一次怎么开始

1. 先读 `<SKILL_BASE>/SKILL.md`
2. 再读 `<SKILL_BASE>/docs/reference/reverse-bootstrap.md`
3. 若当前 workspace 没有 history data files，用 `node <SKILL_BASE>/tools/task/task-start.mjs <task-id>` 建任务目录
4. 如果已经知道 topic 或交付约束，可直接把 `--topic=`、`--topics=`、`--local-repro`、`--api-call-example`、`--task-input=...` 交给 `task-start`
5. 若 `task-input` 已包含 `Flutter / Cronet / JNI / split APK / WebView / ContentProvider / emulator / flag` 等线索，`task-init` 会自动补选对应 topic pack
6. `task-start` 在无历史文件时会转发到 `task-init`；若 workspace 已有 history data files，则默认阻止新建第二个 task-local，除非显式传 `--force-new-task`
7. 用 `node <SKILL_BASE>/tools/task/task-sync.mjs <task-id>` 初始化状态视图、workspace bridge 与首轮 `execution`
8. 用 `node <SKILL_BASE>/tools/task/task-advance.mjs <task-id>` 刷新 `execution.status / nextExecutableAction`
9. 从 `Observe` 阶段开始，不要跳过取证直接下结论

补充约定：
- `task-start` / `task-init` / `task-sync` / `task-advance` / `task-close` 统一使用绝对路径调用：`node <SKILL_BASE>/tools/task/<script>.mjs <args>`
- 任务数据始终写入当前项目目录下的 `artifacts/tasks/<task-id>/`（`workspaceRoot = process.cwd()`），不写入 skill 全局目录
- 脚本内部自动从 `<SKILL_BASE>`（基于 `import.meta.url` 定位）读取模板文件
- 可通过 `ANDROID_REVERSE_WORKSPACE_ROOT` 覆盖 workspace 根目录（一般不需要）
- `task-close` 会保留当前项目下的 task-local 数据，执行验证并清理任务产物
- 新任务用 `run/verification.spec.json` 声明本地复现；旧 workspace 的 `run/local-repro-example.js`、`run/api-call-example.js` 仍可桥接用于兼容，但不能单独满足 closeout

## 3. 每次工作至少要做什么

- 明确当前阶段：`Observe / Capture / Rebuild / Patch / PureExtraction / Port`
- 明确本轮产物落点：`artifacts/tasks/<task-id>/`
- 把关键证据写入 artifact，而不是只留在对话里
- 更新 `report.md`
- 在 `Observe` 稳定后、进入深 `Capture` 前确认切入点和证据面已成形
- 每一阶段结束都要先刷新 `route-state.json` 及其 Markdown 视图，再自动推进下一阶段
- 每一轮结束都要刷新 `execution.status / nextExecutableAction`；只有 `pauseCategory=user/risk` 时才允许等待用户
- 续跑任务恢复完成后直接回到活跃阶段执行，不以“等待继续”收尾

## 4. 设备与进程怎么使用

- 默认优先复用同一设备、同一包名、同一 attach 策略
- 若需要登录、激活或触发业务路径，优先在当前设备会话完成后继续复用
- hook、trace、logcat、抓包、验证尽量围绕同一进程模型完成
- 若必须切换设备、用户态环境或进程附着方式，要在报告中写清原因

## 5. 任务结束前要检查什么

- `report.md` 是否已更新
- `run/verify-once.mjs --validate-only` 是否可通过
- 关键脚本、样本、说明是否已落盘
- 如有经验参考，是否记录采纳与否

## 6. 最常用命令

`<SKILL_BASE>` 是 Skill 工具返回的 base directory 路径。所有命令均使用绝对路径调用，任务产物创建在当前项目目录。

```bash
node <SKILL_BASE>/tools/task/task-start.mjs <task-id>
node <SKILL_BASE>/tools/task/task-start.mjs <task-id> --topics=static-triage,jni-bridge,crypto-protocol --local-repro
node <SKILL_BASE>/tools/task/task-start.mjs smoke-demo --task-input=<SKILL_BASE>/references/task-input-examples/login-jni-native-network.json
node <SKILL_BASE>/tools/task/task-init.mjs <task-id> --topic=protocol
node <SKILL_BASE>/tools/task/task-init.mjs <task-id> [--force-new-task]
node <SKILL_BASE>/tools/task/task-sync.mjs <task-id>
node <SKILL_BASE>/tools/task/task-advance.mjs <task-id>
node <SKILL_BASE>/tools/task/task-close.mjs <task-id>
```

若当前工作目录就是 skill 项目目录本身，也可使用 npm scripts：

```bash
npm run task:start -- <task-id>
npm run task:init -- <task-id> --topic=protocol
npm run task:advance -- <task-id> --json
npm run check
npm run smoke:quick
npm run smoke
npm test
```

## 7. Startup Gate

- Before any formal android-reverse work, inspect the current workspace for history data files under `artifacts/tasks/*/`.
- History data files mean any of: `task.json`, `state/route-state.json`, `report.md`, `run/fixtures.json`.
- If none of these history data files exist, you must start with `node <SKILL_BASE>/tools/task/task-start.mjs <task-id> [...]` or directly run `node <SKILL_BASE>/tools/task/task-init.mjs <task-id> [...]`.
- `task-start` 支持把 `task-init` 的初始化参数原样转发下去，例如 `--topic=`、`--topics=`、`--local-repro`、`--api-call-example`、`--task-input=...`
- Only when history data files already exist may you enter the resume flow with `task.json -> route-state.json -> task-sync -> task-advance`.
- If history data files already exist, do not create a second task-local by default; only do so with `node <SKILL_BASE>/tools/task/task-start.mjs <task-id> --force-new-task [...]`.

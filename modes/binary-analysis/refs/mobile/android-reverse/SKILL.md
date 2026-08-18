---
name: android-reverse
description: Android 应用逆向工程工作流技能。用户提到 APK/APKS/AAB/XAPK、DEX、SO/JNI、smali、Frida、IDA/JADX/JEB、脱壳/加固、反编译/重打包、抓包/hook、去广告/VIP、patch/mod、协议或签名还原、设备指纹、反调试/反检测、OLLVM、dex2so/dragoncore/libmetasec，或要求继续既有 Android 逆向任务时必须触发，即使没有点名本技能。覆盖授权 Android 应用的静态分诊、Java/JNI/Native、运行时取证、保护绕过、动态 Dex、Split、Flutter/Hermes/Unity、Native TLS、Storage/IPC、WebView、Smali patch、协议恢复和 Android CTF。不要用于普通 Android 开发、未授权漏洞利用、Android 系统/ROM/TEE 级逆向或 iOS 逆向。
---

# Android Reverse Framework

这是面向真实 Android 应用逆向交付的工作流入口，不是要求每次加载全部资料的知识库。

## 边界

- 只处理用户有权分析的 Android 应用、样本、设备和流量。
- 普通 Android 开发、系统/ROM/TEE 逆向、iOS 逆向和未授权利用不属于本技能。
- 不主动触发真实短信、支付、生产账号流量、数据清除或不可逆安装操作；需要时先说明影响并取得确认。

## 两种工作模式

### 快速分诊

范围窄、只需静态回答且不涉及动态取证或修改目标时，直接完成最小反编译、关键词搜索和证据结论。不要为了一个“有没有壳”问题创建完整状态机。

### 完整任务

出现以下任一情况时创建 task-local：T2-T5 交付、多轮续跑、动态取证、patch/重签、协议迁移、跨 Java/JNI/Native 建链或保护绕过。

```text
node <SKILL_BASE>/tools/task/task-start.mjs <task-id>
```

启动协议见 `docs/reference/reverse-bootstrap.md`，契约字段见 `references/task-contract-protocol.md`。

## 核心原则

### 1. Observe before change

先确定目标、运行环境和第一条可证伪假设，再选择工具。工具可用不等于当前路线正确。

### 2. Artifact before claim

将要支撑根因、patch 或交付的事实，先写入 `run/fixtures.json` 或对应日志，再更新 route-state。聊天里的推断不能自动升级为证据。

### 3. Bridge before deep native

涉及 JNI 时，先建立 `System.loadLibrary → JNI_OnLoad/RegisterNatives → Java↔Native` 映射。没有桥接证据，不把任意 SO 函数语义提升为业务结论。

### 4. Verify before declare

- T2：脚本独立运行并命中目标数据。
- T3：no-op 重签基线通过，业务 patch 通过安装、冷启动和任务特定回归。
- T4：协议字段、算法和来源可回指。
- T5：独立实现对至少两组不同输入/输出向量通过 `task-verify`，最终运行时不依赖原 SO/RPC/Frida/ADB。

### 5. Goal-lock and stop-loss

每个阶段检查当前动作是否推进用户原始 objective。相同工具和策略连续三次失败、连续 tombstone 或没有新增证据时，先 retrospective 再 pivot；不要用细微脚本变体伪装新路线。

## 完整任务强制执行循环

“执行轮”指一个可证伪假设及其直接的 probe、patch 或 verify，不按聊天轮数或工具调用数量计算。完整任务的每个执行轮都按以下顺序推进：

1. 回读 `task.json::objective`、当前 deliverable、相关 criteria 和 `state/route-state.json::execution`，确认本轮动作直接缩短交付路径。
2. 首次运行动态工具、连接设备或执行安装/重签/目标状态变更前，读取 `references/environment-preflight.md`，只检查当前路线和用户指定工具需要的能力；有清数据、真实账号流量或不可逆影响时先取得确认。
3. 在首次领域操作前读取一个直接匹配的 playbook；后续出现新信号时只补读新命中的协议，不遍历全部资料。
4. 写明可证伪假设、预期观察、失败判据和失败后的不同方向，再执行能区分假设的最小动作。
5. 动作结束后先把原始证据写入任务目录。每次 probe、patch、verify 和工具预检，无论 `success / failed / invalid / inconclusive / blocked`，都立即运行 `task-record-attempt`；聊天或 `report.md` 不能替代结构化尝试记录。
6. 运行 `task-advance`。状态为 `ready-to-continue` 时执行 `nextExecutableAction`，不要停在状态复述。
7. 同一工具和策略连续三次失败、动态测试连续失败、tombstone 累积或多轮没有新增验收证据时，读取 `references/failure-protocol.md`，先写 retrospective，再选择与失败历史实质不同的 pivot。
8. 在分诊/环境预检完成、获得改变路线的关键证据或 patch/verify 结果、pivot 前、暂停/上下文交接前更新 `report.md`；报告是阶段摘要，原始证据仍以 `run/` 产物为准。

尝试记录的最小命令形态：

```text
node <SKILL_BASE>/tools/task/task-record-attempt.mjs <task> \
  --kind=<probe|patch|verify|tool> --status=<success|failed|blocked|invalid|inconclusive> \
  --tool=<tool> --strategy=<strategy> --evidence=<task-local-refs> \
  --hypothesis=<falsifiable-hypothesis> --expected=<expected-observation> --actual=<actual-observation>
```

patch 另外记录 candidate、root-cause evidence 和 rollback；只有候选设计、尚未应用时使用 `--proposal`。

需要支撑后续推理的首条关键证据出现时读取 `references/output-gates.md` 的证据落盘规则；准备声明完成时再执行其中的完整完成门禁和 `references/completion-gate-checklist.md`。

## 任务契约

Schema v2 使用：

- `objective`：用户原话
- `deliverables[]`：可同时包含 T3、T5 等多个交付单元
- `completionCriteria[]`：结构化 `id / label / status / evidenceRefs`
- `currentDeliverableId`
- `protectionTier`：分诊前保持 `null`
- `disallowedFallbacks`、`userRejectedApproaches`

criteria 状态只使用 `pending | met | blocked | rejected`；deliverable 使用 `in-progress | blocked | acceptance-ready | delivered | rejected`。一个交付单元成功不能关闭其他交付单元。

旧任务只读兼容；显式迁移：

```text
node <SKILL_BASE>/tools/task/task-migrate.mjs <task> --to=2 --dry-run
node <SKILL_BASE>/tools/task/task-migrate.mjs <task> --to=2
```

## 状态与恢复

`state/route-state.json` 是机器状态真源：保存 entrypoints、attempts、patch candidates、validation runs、stop-loss 和下一动作。

`state/route-plan.md`、`state/clues.md`、`state/progress.md` 是生成视图，不要手工双写。硬证据内容放在 `run/fixtures.json` 或日志，route-state 只记录证据如何改变路线。

续跑顺序：

1. `task.json`
2. `state/route-state.json`
3. `report.md` 与 `run/fixtures.json`
4. `task-sync`
5. `task-advance`
6. 若状态为 `ready-to-continue`，执行 `nextExecutableAction`

## Android 路由门禁

### 防护定级

防护等级是 A0-A7，但 topic 命中不能自动推导等级。先记录壳/动态加载/检测/混淆的具体证据，再写 `protectionTier`。

确认动态 Dex 或壳时，读取 `references/unpack-tool-matrix.md`，按设备、ABI、ROM、进程存活、检测时序和 Anti-Frida 证据选路。A4 只表示复杂保护，不表示 Frida 必然失败。

### OLLVM 与 Frida

出现 FLA/BR/BCF/SUB、dispatcher、JUMPOUT 等可复核信号时，读取 `references/signal-gates.md` 并先静态还原受影响的目标控制流。

门禁只阻止依赖未还原控制流语义的 Native attach/call/patch；模块枚举、maps、Java hook、装载时机和 RegisterNatives 边界取证不因 A4 或 OLLVM 自动禁止。

首次 Frida 运行前读取 `references/hook-snippets.md` 的环境探测模板，确认设备、进程、版本和 spawn/attach 时机。

### T3 Smali patch

读取 `references/smali-patching-playbook.md`。首个业务 patch 前完成：

```text
原 APK → no-op 重打包/重签 → apksigner 验证 → 安装 → 冷启动
```

然后记录：

```text
node <SKILL_BASE>/tools/task/task-baseline.mjs <task> \
  --source=<original.apk> --resigned=<noop.apk> --evidence=<refs> \
  --signature-verified --installed --launched
```

签名不同需要卸载时，先说明会清数据并取得明确同意。业务 patch 按最小根因执行，每个候选都记录 hypothesis、evidence、expected observation 和 rollback。

通用回归至少覆盖 `cold-start / core-path / signature-integrity`，这三项必须实测通过。如果 objective 是“全部去广告”，再覆盖 onboarding、home、query-results、login/SSO、deep navigation、resume；确实不存在的业务面才可标为 `not-applicable`，并附理由及组件/静态证据。未覆盖路径写成待验收，不能宣称全局完成。

### T5 本地迁移

最终产物允许标准库、常见加密/编码/HTTP/数学库，不允许原 SO、RPC、Frida、ADB、Java 子进程、Unidbg/Unicorn/angr/Qiling 作为运行时依赖。

在 `run/verification.spec.json` 声明 Node/Python 入口和断言，显式执行：

```text
node <SKILL_BASE>/tools/task/task-verify.mjs <task>
```

验证器使用结构化 argv、`shell:false`、任务目录约束、产物哈希和输出断言；仅退出码为 0 或 stdout 非空不算验证。

## 专题路由

完整关键词索引见 `references/topic-playbook-index.md`。高频路由：

| 信号 | 读取 |
|---|---|
| JNI/RegisterNatives | `references/jni-bridge-playbook.md` |
| Native SO | `references/native-so-playbook.md` |
| 协议/签名/加密 | `references/crypto-protocol-playbook.md` |
| 动态 Dex/壳 | `references/dex-loader-playbook.md` + `references/unpack-tool-matrix.md` |
| 梆梆企业版/libDexHelper | `references/dex-loader-playbook.md` + `references/unpack-tool-matrix.md` + `references/bangcle-libdexhelper-playbook.md` |
| OLLVM/混淆 | `references/signal-gates.md` + `references/deobfuscation-playbook.md` |
| 运行期自解密 SO/匿名 RX | `references/so-runtime-evidence-playbook.md` |
| Frida Java/Native | `references/frida-java-playbook.md` / `references/frida-native-playbook.md` |
| Flutter/Hermes/Unity | `references/framework-runtime-playbook.md` |
| Cronet/BoringSSL/native TLS | `references/native-network-playbook.md` |
| APKS/AAB/XAPK | `references/split-delivery-playbook.md` |
| WebView/Hybrid | `references/webview-hybrid-playbook.md` |
| Storage/IPC | `references/storage-ipc-playbook.md` |
| Root/Frida/Integrity/Pinning | 对应 anti-* 与 integrity playbook |

## 专题结论边界

- Split：分包重组前，不因 base.apk 缺逻辑下“目标不存在”结论。
- Framework runtime：识别 Flutter/Hermes/Unity 后再选择资源和 Native 路径。
- Native network：Java TrustManager 未命中不能证明没有 pinning。
- ART：先排查进程、时机和编译状态，再解释 hook miss。
- 保护绕过：只对实际目标涉及的 root/frida/integrity/pinning 子面裁定；未验证的子面写明未测。

## 回复与完成

第一条完整任务回复只需说明：目标和交付单元、当前阶段、本轮成功证据、下一可执行动作。工具状态只列真实阻塞或用户指定工具。

正常进度回复不受完成门禁阻止。准备使用“已完成/已交付”时读取 `references/output-gates.md` 和 `references/completion-gate-checklist.md`。

没有真实用户消息证据时，不得写“用户已确认”。agent 侧完成但仍缺真实短信、登录或设备边界验收时，使用 `acceptance-ready`。

## CLI

```text
node <SKILL_BASE>/tools/task/task-init.mjs <task-id> [--task-input=...]
node <SKILL_BASE>/tools/task/task-sync.mjs <task-id>
node <SKILL_BASE>/tools/task/task-record-attempt.mjs <task-id> ...
node <SKILL_BASE>/tools/task/task-advance.mjs <task-id>
node <SKILL_BASE>/tools/task/task-verify.mjs <task-id>
node <SKILL_BASE>/tools/task/task-close.mjs <task-id>
```

## 能力边界与成熟度

<!-- BEGIN GENERATED: topic-maturity-summary -->
- `synthetic-e2e` (`8`): `crypto-protocol`, `dex-loader`, `framework-runtime`, `jni-bridge`, `protection-bypass`, `runtime-hooking`, `split-delivery`, `static-triage`
- `guided` (`10`): `ctf`, `deobfuscation`, `device-fingerprint`, `hook-injection`, `kernel-assisted-re`, `so-runtime-evidence`, `stealth-hook`, `trace-analysis`, `unidbg-simulation`, `vmp-analysis`
- `closed-loop` (`9`): `anti-emulator-debug`, `art-runtime`, `call-flow`, `java-api`, `native-network`, `native-so`, `smali-patching`, `storage-ipc`, `webview-hybrid`
- `reference-only` (`0`): none published yet
<!-- END GENERATED: topic-maturity-summary -->

成熟度表示现有模板和 QA 深度，不等于所有真实 App 都已验证。详细口径见 `docs/reference/capability-matrix.md`。

# Android Reverse Prompts

本文件是 **提示词模板库**，不再重复维护完整运行协议。

固定执行约束、首读顺序、首轮回复契约、专题强制要求，以以下文件为准：

- `SKILL.md`
- `docs/reference/reverse-bootstrap.md`
- `docs/reference/reverse-workflow.md`
- `docs/reference/case-safety-policy.md`

使用方式：

1. 先选一个 **底座模板**（新任务 / 续跑任务）
2. 再追加一个 **场景覆盖层**
3. 如有需要，再追加一个 **注入片段**（首轮回复契约、Baseline 优先、A6/A7 等）

---

## 一、底座模板

### A. 新任务底座

```text
使用 android-reverse framework-first 流程处理一个新的授权 Android 应用逆向任务。

先读：
1. docs/reference/reverse-bootstrap.md
2. docs/reference/reverse-workflow.md
3. docs/reference/case-safety-policy.md

按 SKILL.md 的任务契约锁定规则创建 task-local（artifacts/tasks/<task-id>/task.json），后续证据、结论、进度持续落盘到该目录。

任务输入（每个字段独立成行；用户未提供的字段写"未指定"而非省略）：
- target: <样本路径或说明；含包名/版本/MD5/SHA1 如已知>
- goal: <用户原话目标，不改写不提炼；一句话"想达成什么">
- deliverable: <T1-T5 交付等级 + 可验证完成条件；回答"做成什么样算完成">
- constraints: <授权边界 + 禁止项 + 设备/系统版本 + 时间预算>
- knownClues: <已知入口/符号/地址/算法猜测/样本 IO/前置分析；没有写"无">
```

**字段职责对照**（goal vs deliverable 是常见混淆点）：

| 字段 | 回答 | 反例（不要这样写） |
|---|---|---|
| `goal` | 用户想达成什么 | "还原签名算法" ✅ ／ "写 Python 脚本" ❌（这是 deliverable） |
| `deliverable` | 什么算完成 | "T5 纯 Python，对新输入实时生成有效签名（非重放）" ✅ ／ "还原算法" ❌（这是 goal） |
| `constraints` | 解决空间的硬限制 | "禁止 Frida；仅 v3.2.1；4h 内" ✅ |
| `knownClues` | 已知起点（减少冷启动） | "libfoo.so+0x1234 疑似签名入口；附 5 组 IO 样本" ✅ |

**完整填写示例**：

```text
- target: com.example.app v3.2.1（./samples/app-v3.2.1.apk，SHA1: a1b2c3...）
- goal: 还原 /api/v1/sign 接口的 X-Sign 请求头生成逻辑
- deliverable: T5 纯 Python 实现，对任意 (path, body, timestamp, device_id) 输入实时生成有效 X-Sign（非重放预捕获值）
- constraints: 禁止 Frida（目标强反 Frida）；仅授权版本 v3.2.1；4 小时内
- knownClues: libfoo.so+0x1234 疑似签名入口；Java 层经 com.example.security.SignKit.genSign() 调用；附 5 组 (input, X-Sign) 样本
```

### B. 续跑任务底座

```text
继续执行已有 android-reverse 任务：<task-id>。

先读取并同步（按顺序，前者缺失不阻塞后续）：
1. artifacts/tasks/<task-id>/task.json（**必存**；缺失视为新任务，回到底座 A）
2. artifacts/tasks/<task-id>/state/route-state.json（缺失则记 notes："首跑未持久化路线状态"）
3. artifacts/tasks/<task-id>/state/route-plan.md（缺失则基于 task.json 重建）
4. artifacts/tasks/<task-id>/state/clues.md（缺失视为无线索）
5. artifacts/tasks/<task-id>/state/progress.md（缺失视为无进度记录）
6. artifacts/tasks/<task-id>/report.md（缺失必须在第一轮补齐，参考 SKILL.md "report.md 增量写入规则"）
7. 运行 node tools/task/task-sync.mjs <task-id>
8. 运行 node tools/task/task-advance.mjs <task-id>

恢复完成后不要停在状态汇报，若 `execution.status=ready-to-continue`，则继续执行 `nextExecutableAction`。

**已确认线索约束**：`clues.md` 中 `confidence=verified` 或 `confidence=cross-validated` 的线索在后续分析中视为已知事实。不得将已确认的算法、密钥、协议结构重新标记为"未知"或重新推测。若对已有线索有怀疑，必须先提供反证（新的证据推翻旧结论），再标记为待验证。
```

---

## 二、场景覆盖层

以下片段应追加在底座模板后，不再重复写通用约束。

### 1. 静态分诊 / Manifest / 导出组件

```text
场景覆盖层：
- 补读 references/static-triage-playbook.md
- 目标：输出 entrypoints、导出面、敏感组件、可疑资源和下一步切入点
- 优先交付：run/component-map.md、run/static-triage-notes.md、report.md
```

### 2. Java API / Call Flow

```text
场景覆盖层：
- 补读 references/java-api-playbook.md、references/call-flow-playbook.md
- 目标：恢复 Retrofit / OkHttp / Volley / ViewModel / Repository 的关键调用链
- 优先交付：run/api-map.md、run/call-chain.md、run/fixtures.json
```

### 3. JNI / Native SO

```text
场景覆盖层：
- 补读 references/jni-bridge-playbook.md、references/native-so-playbook.md
- 目标：定位 System.loadLibrary、JNI_OnLoad / RegisterNatives / Java_*，恢复至少一条 Java -> Native 主链
- 优先交付：run/register-natives-trace.js、run/jni-bridge-map.md、run/call-chain.md
```

### 4. Runtime Hook / Frida

```text
场景覆盖层：
- 若重点在 Java 层，补读 references/frida-java-playbook.md
- 若重点在 Native 层，补读 references/frida-native-playbook.md
- 目标：选择最小可验证 hook，优先拿到入参/返回值/明文证据
- 优先交付：run/frida-java-template.js 或 run/frida-native-template.js、report.md
```

### 5. Protection / Pinning / Integrity

```text
场景覆盖层：
- 补读 references/anti-root-playbook.md、references/anti-frida-playbook.md、references/integrity-pinning-playbook.md
- 目标：分别裁定 root / frida / integrity / pinning 四个子面，并定位锁定发生层
- 优先交付：run/anti-root-bypass.js、run/anti-frida-bypass.js、run/integrity-bypass.js、run/cert-pinning-bypass.js、run/network-stack-notes.md
```

### 6. Dex Loader / Split Delivery / Framework Runtime

```text
场景覆盖层：
- 补读 references/dex-loader-playbook.md、references/split-delivery-playbook.md、references/framework-runtime-playbook.md
- 目标：确认逻辑位于 base、feature、动态 Dex 还是框架运行时资源中，并恢复真实入口
- 优先交付：run/dex-loader-dump-notes.md、run/split-delivery-notes.md、run/framework-runtime-notes.md、run/framework-runtime-map.json
```

### 7. Native Network / Cronet / BoringSSL

```text
场景覆盖层：
- 补读 references/native-network-playbook.md、references/art-runtime-playbook.md
- 目标：明确 Java / JNI / Native 网络分层、关键进程与 pinning 命中层
- 优先交付：run/network-stack-notes.md、run/art-runtime-notes.md、run/cert-pinning-bypass.js
```

### 8. WebView / Storage / IPC

```text
场景覆盖层：
- 补读 references/webview-hybrid-playbook.md、references/storage-ipc-playbook.md
- 目标：恢复 WebView JS-Native bridge、本地缓存、Provider / Binder / Intent 数据流
- 优先交付：run/webview-bridge-notes.md、run/storage-ipc-notes.md、run/component-map.md
```

### 9. Smali Patch / Rebuild / Resign

```text
场景覆盖层：
- 补读 references/smali-patching-playbook.md
- 目标：以最小原因 patch 指定阻断点，并记录 rebuild / resign / verify 路径
- 优先交付：run/smali-patch-notes.md、run/verify-once.mjs、report.md
```

### 10. Crypto / Protocol / Signature

```text
场景覆盖层：
- 补读 references/crypto-protocol-playbook.md
- 若涉及 JNI 或 Native，再补 jni-bridge / native-so playbook
- 目标：恢复 HMAC / AES / token / protobuf / 自定义签名的输入、输出、关键常量与最小复现样例
- 优先交付：run/protocol-notes.md、run/fixtures.json、run/solver-template.py 或等价脚本
```

### 11. CTF / Crackme

```text
场景覆盖层：
- 补读 references/ctf-playbook.md
- 目标：恢复校验逻辑、拿到 flag 或给出 solver
- 优先交付：report.md、run/solver-template.py、run/protocol-notes.md 或 run/smali-patch-notes.md
```

### 12. Deobfuscation / OLLVM

```text
场景覆盖层：
- 补读 references/deobfuscation-playbook.md
- 若涉及 SO 层混淆，同步补读 references/native-so-playbook.md
- 目标：识别混淆类型（FLA/BR/SUB/BCF/icall/自定义）和混淆产品（OLLVM/Hikari/Arkari/Goron），恢复关键路径可读性
- 混淆类型识别与工具选择详见 playbook，此处仅强调：先识别再选工具
- 魔改检测：若 D-810 无效，立即按 playbook 魔改应对章节切换路线
- 字符串优先解密——降低后续分析难度
- 优先交付：run/deobfuscation-notes.md、还原后的关键函数伪代码
```

### 13. VMP Analysis

```text
场景覆盖层：
- 补读 references/vmp-analysis-playbook.md
- 若涉及 Dalvik VMP，再补 references/dex-loader-playbook.md
- 目标：识别 VMP 类型、提取 handler 表、恢复关键方法字节码或通过 trace 获取输入输出
- 优先交付：run/vmp-analysis-notes.md、handler 映射表、还原后的关键方法伪代码
```

### 14. Unidbg / Simulation

```text
场景覆盖层：
- 补读 references/unidbg-simulation-playbook.md
- 若涉及 JNI 环境，再补 references/jni-bridge-playbook.md
- 目标：在 PC 上模拟执行 SO 函数，绕过设备依赖获取加密/签名结果
- 优先交付：run/unidbg-simulation-notes.md、Unidbg 调用代码、模拟结果验证
```

### 15. Device Fingerprint / Risk Control

```text
场景覆盖层：
- 补读 references/device-fingerprint-playbook.md
- 若涉及 Native 层采集，再补 references/native-so-playbook.md
- 目标：还原指纹采集维度、风控参数生成逻辑和绕过策略
- 优先交付：run/device-fingerprint-notes.md、指纹采集维度清单、风控参数生成逻辑
```

### 16. Hook / Injection

```text
场景覆盖层：
- 补读 references/hook-injection-playbook.md
- 若涉及 Frida 检测绕过，再补 references/anti-frida-playbook.md
- 目标：选择正确的注入方式和 hook 策略，理解底层原理
- 优先交付：run/hook-injection-notes.md、hook 代码、注入成功验证
```

### 17. Kernel-assisted RE（取证型内核手段）

```text
场景覆盖层：
- 补读 references/kernel-assisted-re-playbook.md
- 触发条件：用户态工具（Frida/ptrace/Xposed）已被系统性拦截；目标 ≥ A5；交付物是取证（参数/返回值/DEX dump）而非"过检测让 App 跑起来"
- 设备前置：Root + 内核 5.4+（eBPF）或 APatch/KernelPatch（KPM）
- 路线分流：取证型优先本 overlay；共存型优先 Frida 过检测，本 overlay 仅辅助
- 优先交付：run/kernel-assisted-re-notes.md、内核工具部署日志、采集到的证据（DEX dump / syscall trace / 寄存器快照）
```

### 18. Stealth Hook（A6+ 内核无痕 hook）

```text
场景覆盖层：
- 补读 references/stealth-hook-playbook.md、references/stealth-hook-vs-traditional-matrix.md
- 触发条件：用户态 Frida/Xposed/Zygisk/Dobby **逐一**被系统性拦截（CRC + maps 监控 + ptrace 探测 + ArtMethod 指针漫游），且交付物是"hook 命中 + 修改执行流 + 过反检测"
- 升级前置：必须先在 hook-injection + anti-frida 路线落 detection-evidence，避免过早升级
- 设备能力四件套（缺一不可）：ARM64 + Kernel 5.4+ GKI + APatch + KernelPatch 0.13.x + 解锁 BL
- 模式分流：观察参数/返回值 → HWBP（≤6 点）；替换执行流或 >6 点 → PTE+DBI；Java 无痕 → LSPlant 魔改 + Ghost Mem
- 优先交付：run/stealth-hook-notes.md（含 userModeFailureEvidence、deviceCapability、modeSelectionReason、hookPoints.hitEvidence、antiDetectionAudit）
```

### 19. SO Runtime Evidence（崩溃 / 加密 SO / 匿名 RX）

```text
场景覆盖层：
- 补读 references/so-runtime-evidence-playbook.md
- 触发信号：磁盘 SO 不可直接分析（加密/壳化/自解密）、运行期闪退 SIGSEGV/SIGTRAP/SIGKILL/BRK、崩溃 PC/LR 落在未知映射、inline hook 后立刻自毁、init_array/constructor 阶段闪退、匿名 RX/memfd/direct syscall
- 目标：先 dump/fix 运行期 SO 再分析；区分"被检测主动自毁"与"hook 副作用崩溃"
- 与 hook-injection 的边界：磁盘 SO 可读且 hook 不闪退 → 走 hook-injection；否则走本 overlay
- 优先交付：run/so-runtime-evidence-notes.md、dump 后的可读 SO、崩溃证据链（PC/LR/backtrace/信号）
```

### 20. Trace Analysis（指令级 trace / 算法恢复）

```text
场景覆盖层：
- 补读 references/trace-analysis-playbook.md
- 触发条件：符号被剥离/混淆、静态伪代码不可读、OLLVM 还原后仍有空白、需要从执行流反推算法
- 工具选择：GumTrace（Frida 内置）/ QTrace / VMLifter / Frida Stalker / Unidbg trace 模式
- 目标：采集指令级 trace → 切片（按调用边界）→ 污点传播 → 语义提升 → 还原伪代码
- 优先交付：run/trace-analysis-notes.md、trace 切片结果、还原后的伪代码或 Python 等价实现
```

---

## 三、注入片段

### 1. 首轮回复契约注入

```text
完整任务首轮工作回复简要包含：
- 用户目标与当前 deliverable
- 当前阶段
- 本轮要取得的成功证据
- 下一可执行动作
工具或环境只列真实阻塞，不展示内部已读文档清单。
```

### 2. Baseline 优先注入

```text
若 task template 中存在对应 run/*.js baseline，先使用默认版本验证切入点。
只有 baseline 已证明切入点成立但信息不足时，才切换到 run/*-advanced.js。
先记录 baseline 命中/未命中证据，再决定是否升级 advanced。
```

### 3. A6 / A7 附加注入

```text
目标疑似 A6 / A7。
在正式深挖前先读 references/a6-a7-failure-pattern-cookbook.md，并排除当前最像的 failure pattern。
先说明保护等级与依据，再开始深挖。
不要一开始就做重型爆破，先列 entrypoints，再做最小 probe。
```

### 4. 本地复现交付注入

```text
本轮需要交付本地复现。
除 report.md 外，还要给出：
- run/run-local.mjs 或等价算法实现
- run/verification.spec.json（结构化 argv、入口和输出断言）
- 执行 task-verify，保存 run/verification-result.json
- T5 至少使用两组不同输入/输出向量；若要求 API 示例，增加 role=api-call 的验证 case
```

---

## 四、推荐拼装方式

- **新 APK 静态分诊**：新任务底座 + 静态分诊 + 首轮回复契约注入
- **JNI + SO + Pinning**：新任务底座 + JNI / Native SO + Native Network + Protection + Baseline 优先注入
- **A6/A7 高对抗**：新任务底座 + Dex Loader / Split / Framework + Native Network + A6/A7 附加注入 + 首轮回复契约注入
- **续跑 task-local**：续跑任务底座 + 对应场景覆盖层 + Baseline 优先注入
- **OLLVM 混淆还原**：新任务底座 + JNI / Native SO + Deobfuscation + Baseline 优先注入
- **VMP / 壳保护**：新任务底座 + JNI / Native SO + VMP Analysis + Dex Loader + Baseline 优先注入
- **协议还原 + Unidbg**：新任务底座 + Crypto / Protocol + JNI / Native SO + Unidbg / Simulation + 本地复现交付注入
- **设备指纹 + 风控**：新任务底座 + Device Fingerprint / Risk + JNI / Native SO + Protection + Baseline 优先注入
- **A6+ stealth hook（用户态全失败）**：新任务底座 + Hook / Injection（先穷尽用户态并落 detection-evidence）+ Stealth Hook（A6+ 升级）+ A6/A7 附加注入 + 首轮回复契约注入
- **崩溃排查 / 加密 SO dump**：新任务底座 + SO Runtime Evidence + JNI / Native SO + Hook / Injection（探针式）+ 首轮回复契约注入
- **内核取证（无痕 DEX dump / syscall trace）**：新任务底座 + Kernel-assisted RE + Dex Loader + A6/A7 附加注入
- **符号剥离 / 算法反推**：新任务底座 + JNI / Native SO + Trace Analysis + Crypto / Protocol + 本地复现交付注入

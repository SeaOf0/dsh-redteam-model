# Upgrade Iteration Log

1. 将 `android-reverse` 从单文件 skill 重构为 framework-first 入口。
2. 建立 `docs/reference` 正式规则层。
3. 建立 `references` 专项参考层。
4. 建立 `scripts/cases` 抽象案例层。
5. 建立 `artifacts/tasks/_TEMPLATE` task-local 模板层。
6. 重写 `SKILL.md`，改为入口式而非内容堆叠式。
7. 引入 `A0-A7` Android 防护分级。
8. 固化 `Intake -> Triage -> Static -> Bridge -> Dynamic -> Bypass -> Rebuild -> Report` 八阶段协议。
9. 将 JNI 桥接分析提升为独立正式维度。
10. 将 Root / Frida / Integrity / Pinning / DexLoader 拆为独立专项。
11. 吸收开源安卓 skill 中的 API 提取、调用链分析、依赖准备等高价值内容。
12. 增加 task.json、report.md、fixtures、verify-once 等最小交付合同。
13. 建立首轮能力矩阵，识别保护绕过、完整性、动态 Dex 三个弱项。
14. 补 `package.json` 与 `tools/qa/*`，把结构检查变成可执行动作。
15. 新增 `repo-conventions.md`、`tool-reference.md`、`tool-defaults.md`、`skill-capability-summary.md`。
16. 将 `integrity` 明确纳入 task template 与 task-local 脚本。
17. 将 `dexLoader` 补强为 `class loader 取证 + dump notes` 双产物。
18. 收紧 `validation-checklist.md`，把 Root / Frida / Integrity / Pinning 分别纳入验收口径。
19. 第二轮能力评估后，所有主能力面已达到 `Strong`，高频高风险专题达到 `Super-Strong`，满足停止迭代条件。
20. 从高级安卓逆向视角复评后，识别出 `WebView/Hybrid`、`Storage/IPC`、`Smali patch`、`Anti-emulator/anti-debug` 四个缺漏能力面。
21. 补 `webview-hybrid-playbook.md` 与 `storage-ipc-playbook.md`，将 hybrid 容器与本地数据/IPC 拉入正式框架。
22. 补 `anti-emulator-debug-playbook.md`，将模拟器与调试检测从 Root/Frida 中独立出来。
23. 补 `smali-patching-playbook.md`，把 patch、重打包、签名、安装验证正式化。
24. 为 `Native SO`、`WebView`、`Storage/IPC`、`Anti-emulator-debug`、`Smali patch` 增加 task-local 产物与抽象 case。
25. 扩展 `task.json`、`report.md`、`output-contract.md`、`validation-checklist.md`，把新增能力纳入正式交付与验收链。
26. 第三轮能力评估后，所有纳入矩阵的能力面均达到 `Strong` 或 `Super-Strong`，停止迭代。
27. 从高级安卓逆向视角第四轮复评，识别出 `Split Delivery`、`Framework Runtime`、`Native Network` 三个此前未纳入矩阵的现代高频场景短板。
28. 重写 `SKILL.md`，修正入口文件编码/可读性问题，并把三类新能力面接入触发条件、专项优先级、质量门槛与强制交付。
29. 新增 `split-delivery-playbook.md`、`framework-runtime-playbook.md`、`native-network-playbook.md`，把 AAB/APKS、Flutter/Hermes/Unity、Cronet/BoringSSL 正式化。
30. 为三类新能力面补 `scripts/cases/*` 抽象 case 与 `artifacts/tasks/_TEMPLATE/run/*` task-local notes。
31. 扩展 `task.json`、`report.md`、`task-input schema`、`tool-reference.md`、`setup-guide.md`、`validation-checklist.md` 与 `check-*` QA 脚本，使新能力面进入正式执行链。
32. 第四轮评估后，`Split Delivery` 达到 `Super-Strong`，`Framework Runtime` 与 `Native Network` 达到 `Strong`；继续进入下一轮复评。
33. 第五轮复评确认最后短板位于 `ART runtime / OAT / VDEX / inline / deopt / early instrumentation`，该层直接影响高保护目标的 hook 命中率和结论稳定性。
34. 新增 `art-runtime-playbook.md`、`android-art-runtime-workflow.mjs` 与 `run/art-runtime-notes.md`，把进程模型、编译状态、attach/deopt 策略纳入正式专项。
35. 扩展 `SKILL.md`、`android-reverse-bootstrap.md`、`reverse-workflow.md`、`tool-defaults.md`、`task-input schema`，使运行时早期注入与多进程排查成为默认协议的一部分。
36. 将 `Framework Runtime` 与 `Native Network` 升级到 `Super-Strong`，因为它们已进入 `task.json`、`report.md`、`output-contract`、`validation-checklist` 与 QA。
37. 第五轮评估后，所有主能力面均达到 `Strong` 或 `Super-Strong`，且无新增主能力短板，停止迭代。
38. 第六轮框架审查确认“能力声明高于 topic 闭环”，因此停止使用泛化的“真实 Android 逆向 90%+”表述，改为按授权 Android 应用逆向口径评估。
39. 新增 `java-api`、`call-flow`、`native-so`、`webview-hybrid`、`storage-ipc`、`native-network`、`art-runtime`、`anti-emulator-debug`、`smali-patching`、`ctf` 等 registry-backed topics，把原先仅存在于 playbook / report / task.json 的高频能力面纳入正式 topic 体系。
40. 修复 `task-init` 未复制 evidence scaffold 的问题，补齐 `timeline/static/runtime/network/memory/logcat` 基础证据文件，确保 task-local 真正可落地。
41. 为新增 `closed-loop` topics 补齐 baseline 经验参考，把经验层闭环纳入正式保证。
42. 更新 `SKILL.md`、`README.md` 与 `skill-capability-summary.md`，明确当前技能定位为 Android 应用逆向框架，并将覆盖结论收敛为“授权应用层多数高频场景”，不再使用泛化的 90%+ 口径。
43. 新增 `check-maturity-evidence`，把 `guided / closed-loop / synthetic-e2e` 的判级规则形式化为可执行审计，并明确“允许保守声明，不允许超前声明”。
44. 第七轮增强先处理 `scripts/cases` 过于抽象的问题，将 case 从“专题说明对象”提升为包含 `entrypoints / probeSequence / evidenceAnchors / pivotSignals / successSignals` 的 route recipe。
45. 收紧 `tools/qa/lint-cases.mjs`，要求每个 case 至少声明两个候选切入点，以及最小 probe、扩展条件、停放条件，避免高对抗场景继续依赖操作者临场重建策略。
46. 第八轮增强聚焦 `split-delivery`，补齐知识门槛、formal validation 与模板 artifact 格式问题，不再只依赖 playbook 指导。
47. 将 `split-delivery` 从 `guided` 提升到 `synthetic-e2e`，并同步 capability summary，使成熟度声明与证据层重新对齐。
48. 第九轮增强收紧 `crypto-protocol`、`dex-loader`、`framework-runtime`、`runtime-hooking` 四个 synthetic topic 的 formal validation，不再允许只改状态位就通过 topic 级验收。
49. 同步修复 `crypto-fixtures.json` 与 `framework-runtime-map.json` 模板中的转义残留，确保 task-local 初始化即生成合法 JSON 工件。
50. 第十轮增强补知识层密度，新增组合经验参考，显式覆盖框架运行时、多进程与 Native 网络栈联动场景。
51. 同步在 `references/high-adversarial-open-source-notes.md` 中为新增组合参考补充开源校准来源。
52. 第十一轮增强补齐维护性文档，新增 `docs/reference/case-recipe-contract.md`，把 `scripts/cases` 的 route recipe 字段从隐式 lint 规则提升为正式契约。
53. 同步在 `SKILL.md`、`README.md`、`scripts/cases/README.md` 与 `reverse-task-index.md` 中挂载 case 契约入口，降低后续维护者的理解成本。
54. 第十二轮复评收紧 maturity 口径，明确 `synthetic-e2e` 只代表仓库级 synthetic task / validation / deliverable 闭环，不再外延成真实目标的高对抗回归承诺。
55. 新增 `check-case-topic-alignment`，把 `scripts/cases/*.mjs -> topic.formalValidation.requiredArtifacts` 的一致性变成可执行 QA，防止 case 与 topic contract 漂移。
56. 同步修复 `framework-runtime` 与 `jni-bridge` case 的 deliverables，使 route recipe、formal validation 与 output contract 重新对齐。
57. 第十三轮增强补齐 `task-init --task-input` 的真实输入映射：支持扁平/结构化双格式，自动回填 `deliverables / boundaries / packageName / attachMode / hints`，并按线索自动补选 topic pack。
58. 新增 `references/task-input-examples/*.json` 场景样例，覆盖 Flutter + JNI + Cronet、Split + Dex + 协议恢复、WebView + Storage + smali patch、Android CTF 四类高频任务。
59. 新增 `tools/qa/check-smoke-scenarios.mjs`、`apply-smoke-scenario.mjs` 与 `smoke-scenarios.mjs`，在临时 workspace 内闭环演练 4 组场景并覆盖全部 18 个 topic。
60. 为发布入口补 `npm run smoke`、`npm test` 与 `npm run release:check`，把”结构一致”升级为”结构 + 生命周期 + closeout”双层回归。
61. 将 `tools/knowledge/compress-similar-experience.mjs` 从 no-op 升级为安全默认的相似度压缩工具，支持 `--json` 分析与 `--apply` 合并归档。
62. 移除 knowledge/experience 系统，清理 knowledgeRefs、knowledge-policy、experience-card 及相关引用。
63. 全面分析 data/ 目录 264 篇社区逆向经验文档，识别出去混淆、VMP 分析、模拟执行、设备指纹、AI 辅助逆向、Hook 框架原理 6 个主要能力缺口。
64. 新增 `references/deobfuscation-playbook.md`，覆盖 OLLVM FLA/BR/SUB 识别与还原、字符串去混淆、自定义变体（Arkari/BlackObfuscator/Hikari）和综合工作流。
65. 新增 `references/vmp-analysis-playbook.md`，覆盖 Dalvik/Native VMP 类型识别、handler 表提取、操作码映射构建、字节码还原和 trace-based 方法。
66. 新增 `references/unidbg-simulation-playbook.md`，覆盖 Unidbg 3 阶段环境补全、Unicorn 指令级模拟、QBDI 无感知插桩和 angr 符号执行。
67. 新增 `references/device-fingerprint-playbook.md`，覆盖指纹采集维度、多源交叉验证、风控参数生成逻辑、Play Integrity/Key Attestation 和绕过策略。
68. 新增 `references/ai-assisted-re-playbook.md`，覆盖 IDA MCP/JADX MCP 工作流、AI 辅助去混淆和算法还原、上下文管理策略。
69. 新增 `references/hook-injection-playbook.md`，覆盖 Java Hook（ArtMethod 8 步）、PLT/GOT Hook、Inline Hook（ARM64）、Zymbiote、Zygisk、SVC Hook/eBPF。
70. 增强 `crypto-protocol-playbook.md`，新增白盒密码学分析（AES/SM4 DFA）、算法识别签名表、CRC/完整性绕过、商业算法模式识别、7 阶段协议还原工作流。
71. 增强 `anti-frida-playbook.md`，新增 Frida 编译定制、Zymbiote 注入、libmsaoaidsec 5 级绕过、硬件断点、Stalker 架构、内存级检测对抗、SVC 级反 Hook、无 Root 持久化。
72. 增强 `native-so-playbook.md`，新增 ELF 深入、Linker 7 步加载、GOT/PLT 机制、SO 自保护、DEX 格式、ARM64 逆向模式、APK 签名验证、RegisterNatives 替代发现。
73. 增强 `native-network-playbook.md`，新增 TLS 流量拦截（frida-analykit）、BoringSSL 密钥提取、primp TLS 指纹、SSL Key Log→Wireshark 工作流、协议降级技术。
74. 增强 `framework-runtime-playbook.md`，新增 Flutter 深入（snapshot/Dart AOT/Method Channel/SSL bypass）、Cocos2d-js（xxtea/.jsc）、Hermes（字节码/工具链）、Unity IL2CPP 全流程、游戏协议分析。
75. 大幅扩展 `ctf-playbook.md`（从 24 行扩展为完整 playbook），新增 9 种题型解题技术、竞赛案例参考、游戏安全模式、Solver 模板。
76. 增强 `frida-java-playbook.md`，新增 Stalker Java 方法追踪、ArtMethod Native 地址获取、Frida 持久化模式、Frida+Wireshark TLS 解密。
77. 增强 `frida-native-playbook.md`，新增 Stalker 内部原理、硬件断点 API、Trace-based 检测点发现、内存扫描模式、Unidbg+Capstone+Keystone 离线分析。
78. 新增 6 个 topic registry：`deobfuscation`、`vmp-analysis`、`unidbg-simulation`、`device-fingerprint`、`ai-assisted-re`、`hook-injection`，均设为 `guided` 成熟度。
79. 更新 SKILL.md 覆盖声明、成熟度摘要、专项优先级和强制交付，纳入 6 个新专题。
80. 更新 PROMPTS.md，新增 6 个场景覆盖层（Deobfuscation/VMP/Unidbg/DeviceFingerprint/AI/Hook）。
81. 更新 capability-matrix.md，新增 6 个专题的表格行和详情节。
82. 框架从 18 个专题扩展到 24 个专题，guided 从 1 个提升到 7 个。


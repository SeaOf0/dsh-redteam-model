# Skill Capability Summary

## Framework

- 已从单文件 skill 升级为 framework-first 仓库
- 已具备入口、阶段协议、产物、专项、矩阵、QA、迭代日志

## Technical Coverage

- 静态分诊
- Split delivery / AAB / APKS
- Framework runtime / Flutter / Hermes / Unity
- ART runtime / OAT / VDEX / inline / deopt / early instrumentation
- Java API 与调用链
- JNI 桥接
- Native SO
- Native network / Cronet / BoringSSL
- WebView / hybrid
- Storage / IPC
- Frida Java / Native
- Root / Frida / Anti-emulator / Anti-debug / Integrity / Pinning
- Dex loader / 脱壳
- Smali patch / rebuild / resign
- 协议与密码
- Android CTF
- Deobfuscation / OLLVM / FLA / BR / SUB
- VMP 分析 / VM interpreter / handler table / opcode mapping
- Unidbg 模拟执行 / 环境补全
- 设备指纹 / 风控参数 / Play Integrity / Key Attestation
- AI 辅助逆向 / IDA MCP / JADX MCP
- Hook 原理 / PLT / GOT / Inline Hook / 注入方式

## Current Assessment

- 覆盖口径调整为“授权 Android 应用逆向”，不再混入系统/ROM/TEE 级议题
- 当前共有 `25` 个 registry-backed topics：`8` 个 `synthetic-e2e`、`9` 个 `closed-loop`、`8` 个 `guided`
- `synthetic-e2e` 的含义收敛为”仓库级 synthetic task / validation / deliverable 闭环”，不再外延成”所有真实样本均已实战回归”
- 应用层高频主线已全部进入 registry、task model、artifact contract 与 QA；其中 `split-delivery` 已补齐知识门槛与 formal validation，不再只停留在 guided 保证
- `closed-loop` 专题已补齐 baseline 经验参考，不再只是 reference 或 report 级接入
- 对授权 Android 应用逆向，可覆盖多数高频应用层场景；`ctf`、`deobfuscation`、`vmp-analysis`、`unidbg-simulation`、`device-fingerprint`、`hook-injection`、`kernel-assisted-re`、`trace-analysis` 八个专题已进入 guided 保证；对 Android 全域逆向仍不做统一闭环承诺


# 交付物索引

## 必检文件（所有任务）

- `artifacts/tasks/<task-id>/report.md`
- `artifacts/tasks/<task-id>/task.json`
- `artifacts/tasks/<task-id>/run/fixtures.json`

## 推荐创建

- `artifacts/tasks/<task-id>/run/verify-once.mjs`（若未创建，完成门禁要求在正文中展示端到端验证证据）

## 按任务类型追加

| 专题 | 追加文件 |
|---|---|
| Java API / 调用链 | `run/api-map.md`、`run/call-chain.md` |
| Frida Java | `run/frida-java-template.js` |
| Frida Native | `run/frida-native-template.js` |
| WebView / Hybrid | `run/webview-bridge-notes.md` |
| Storage / IPC | `run/storage-ipc-notes.md` |
| Split Delivery | `run/split-delivery-notes.md` |
| Framework Runtime | `run/framework-runtime-notes.md` |
| Native Network | `run/network-stack-notes.md` |
| ART Runtime | `run/art-runtime-notes.md` |
| JNI Bridge | `run/register-natives-trace.js` |
| Native SO | `run/native-notes.md` |
| 保护绕过 - Root | `run/anti-root-bypass.js` |
| 保护绕过 - Frida | `run/anti-frida-bypass.js` |
| 保护绕过 - Integrity | `run/integrity-bypass.js` |
| 保护绕过 - Emulator | `run/anti-emulator-bypass.js` |
| 证书锁定 | `run/cert-pinning-bypass.js` |
| Smali Patch | `run/smali-patch-notes.md` |
| 协议还原 | `run/protocol-notes.md` |
| CTF | `run/solver-template.py` |
| Deobfuscation | `run/deobfuscation-notes.md` |
| VMP Analysis | `run/vmp-analysis-notes.md` |
| Unidbg Simulation | `run/unidbg-simulation-notes.md` |
| Device Fingerprint | `run/device-fingerprint-notes.md` |
| Hook Injection | `run/hook-injection-notes.md` |

追加文件缺失可在 `report.md` 中标注 `pending` 但不阻塞完成声明。必检文件缺失则禁止声明完成。

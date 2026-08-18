<!-- publish: framework -->
# Capability Matrix

The canonical topic source now lives under `topics/<topic>/topic.json`.
`docs/reference/topic-route-matrix.json` is a generated registry view for QA, publish, and review.
Declared maturity is audited by `docs/reference/maturity-audit-rules.md` and `tools/qa/check-maturity-evidence.mjs`.

## Maturity Summary

- `synthetic-e2e`: `8` 个专题；已具备 registry-backed synthetic task 骨架、formal validation 与专题产物约束；该级别只代表仓库级 synthetic 闭环，不等同于所有真实目标都已完成实战回归。
- `closed-loop`: `9` 个专题；已具备 registry-backed task model、formal validation 与专题产物约束，但未声明 synthetic task pack 保证。
- `guided`: `10` 个专题；已具备 registry-backed 指导能力，但仍低于 closed-loop 与 synthetic 保证级别。
- `reference-only`: `0` 个专题；已有参考资料，但尚无 registry-backed 的执行契约。

说明：maturity 口径用于描述仓库内的 task model、formal validation、topic pack 与交付保证级别，不直接等价于真实样本覆盖率或高对抗实战回归完备度。

## Topic Table

| Topic | Maturity | Owner | Risk | Route | Required Checks |
|---|---|---|---|---|---|
| `crypto-protocol` | `synthetic-e2e` | `android-reverse-core` | `high` | `crypto-protocol` | `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables` |
| `dex-loader` | `synthetic-e2e` | `android-reverse-core` | `high` | `dex-loader` | `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables` |
| `framework-runtime` | `synthetic-e2e` | `android-reverse-core` | `high` | `framework-runtime` | `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables` |
| `jni-bridge` | `synthetic-e2e` | `android-reverse-core` | `high` | `jni-bridge` | `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables` |
| `protection-bypass` | `synthetic-e2e` | `android-reverse-core` | `high` | `protection-bypass` | `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables` |
| `runtime-hooking` | `synthetic-e2e` | `android-reverse-core` | `high` | `runtime-hooking` | `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables` |
| `split-delivery` | `synthetic-e2e` | `android-reverse-core` | `medium` | `split-delivery` | `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables` |
| `static-triage` | `synthetic-e2e` | `android-reverse-core` | `high` | `static-triage` | `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables` |
| `anti-emulator-debug` | `closed-loop` | `android-reverse-core` | `high` | `anti-emulator-debug` | `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables` |
| `art-runtime` | `closed-loop` | `android-reverse-core` | `high` | `art-runtime` | `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables` |
| `call-flow` | `closed-loop` | `android-reverse-core` | `medium` | `call-flow` | `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables` |
| `java-api` | `closed-loop` | `android-reverse-core` | `medium` | `java-api` | `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables` |
| `native-network` | `closed-loop` | `android-reverse-core` | `high` | `native-network` | `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables` |
| `native-so` | `closed-loop` | `android-reverse-core` | `high` | `native-so` | `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables` |
| `smali-patching` | `closed-loop` | `android-reverse-core` | `medium` | `smali-patching` | `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables` |
| `storage-ipc` | `closed-loop` | `android-reverse-core` | `medium` | `storage-ipc` | `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables` |
| `webview-hybrid` | `closed-loop` | `android-reverse-core` | `medium` | `webview-hybrid` | `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables` |
| `ctf` | `guided` | `android-reverse-core` | `medium` | `ctf` | `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables` |
| `deobfuscation` | `guided` | `android-reverse-core` | `high` | `deobfuscation` | `check:topic-manifests`, `check:capability-coverage`, `check:deliverables`, `check:operating-contracts` |
| `device-fingerprint` | `guided` | `android-reverse-core` | `medium` | `device-fingerprint` | `check:topic-manifests`, `check:capability-coverage`, `check:deliverables`, `check:operating-contracts` |
| `hook-injection` | `guided` | `android-reverse-core` | `high` | `hook-injection` | `check:topic-manifests`, `check:capability-coverage`, `check:deliverables`, `check:operating-contracts` |
| `kernel-assisted-re` | `guided` | `android-reverse-core` | `high` | `kernel-assisted-re` | `check:topic-manifests`, `check:capability-coverage`, `check:deliverables`, `check:operating-contracts` |
| `so-runtime-evidence` | `guided` | `android-reverse-core` | `high` | `so-runtime-evidence` | `check:topic-manifests`, `check:capability-coverage`, `check:deliverables`, `check:operating-contracts` |
| `stealth-hook` | `guided` | `android-reverse-core` | `high` | `stealth-hook` | `check:topic-manifests`, `check:capability-coverage`, `check:deliverables`, `check:operating-contracts` |
| `trace-analysis` | `guided` | `android-reverse-core` | `medium` | `trace-analysis` | `check:topic-manifests`, `check:capability-coverage`, `check:deliverables`, `check:operating-contracts` |
| `unidbg-simulation` | `guided` | `android-reverse-core` | `medium` | `unidbg-simulation` | `check:topic-manifests`, `check:capability-coverage`, `check:deliverables`, `check:operating-contracts` |
| `vmp-analysis` | `guided` | `android-reverse-core` | `high` | `vmp-analysis` | `check:topic-manifests`, `check:capability-coverage`, `check:deliverables`, `check:operating-contracts` |

## Topic Detail

### `crypto-protocol`

- 名称: Crypto / protocol / signature recovery
- 成熟度: `synthetic-e2e`
- 维护方: `android-reverse-core`
- 风险等级: `high`
- 路线轨道: `crypto-protocol`
- 协议文档: `references/crypto-protocol-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/crypto-protocol`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/crypto-protocol.json`
- taskInit: aliases=`protocol`, baseProtectionTier=`A3`, combinationProtectionTiers=none
- 必需 signals: `hmac`, `aes`, `token`, `protobuf`, `signature`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables`
- caseFiles: `android-crypto-protocol-workflow.mjs`
- taskPackFiles: `crypto-fixtures.json`, `protocol-notes.md`

### `dex-loader`

- 名称: Dex loader / shell / dynamic code
- 成熟度: `synthetic-e2e`
- 维护方: `android-reverse-core`
- 风险等级: `high`
- 路线轨道: `dex-loader`
- 协议文档: `references/dex-loader-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/dex-loader`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/dex-loader.json`
- taskInit: aliases=`shell`, baseProtectionTier=`A5`, combinationProtectionTiers=none
- 必需 signals: `dexclassloader`, `inmemorydexclassloader`, `stub application`, `shell`, `libdexhelper`, `bangcle`, `dump`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables`
- caseFiles: `android-dex-loader-workflow.mjs`
- taskPackFiles: `bangcle-libdexhelper-evidence.md`, `class-loader-trace-advanced.js`, `class-loader-trace.js`, `dex-loader-dump-notes.md`

### `framework-runtime`

- 名称: Framework runtime / Flutter / Hermes / Unity
- 成熟度: `synthetic-e2e`
- 维护方: `android-reverse-core`
- 风险等级: `high`
- 路线轨道: `framework-runtime`
- 协议文档: `references/framework-runtime-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/framework-runtime`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/framework-runtime.json`
- taskInit: aliases=`runtime`, baseProtectionTier=`A3`, combinationProtectionTiers=none
- 必需 signals: `flutter`, `libapp.so`, `hermes`, `index.android.bundle`, `unity`, `libil2cpp.so`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables`
- caseFiles: `android-framework-runtime-workflow.mjs`
- taskPackFiles: `framework-runtime-map.json`, `framework-runtime-notes.md`

### `jni-bridge`

- 名称: JNI bridge / RegisterNatives mapping
- 成熟度: `synthetic-e2e`
- 维护方: `android-reverse-core`
- 风险等级: `high`
- 路线轨道: `jni-bridge`
- 协议文档: `references/jni-bridge-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/jni-bridge`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/jni-bridge.json`
- taskInit: aliases=`jni`, baseProtectionTier=`A4`, combinationProtectionTiers=none
- 必需 signals: `jni_onload`, `registernatives`, `system.loadlibrary`, `java_`, `native`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables`
- caseFiles: `android-jni-bridge-workflow.mjs`
- taskPackFiles: `jni-bridge-map.md`, `register-natives-trace-advanced.js`, `register-natives-trace.js`

### `protection-bypass`

- 名称: Protection bypass / root / frida / integrity / pinning
- 成熟度: `synthetic-e2e`
- 维护方: `android-reverse-core`
- 风险等级: `high`
- 路线轨道: `protection-bypass`
- 协议文档: `references/integrity-pinning-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/protection-bypass`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/protection-bypass.json`
- taskInit: aliases=`bypass`, baseProtectionTier=`A3`, combinationProtectionTiers=none
- 必需 signals: `rootbeer`, `frida detection`, `ptrace`, `play integrity`, `safetynet`, `certificatepinner`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables`
- caseFiles: `android-protection-bypass-workflow.mjs`
- taskPackFiles: `anti-frida-bypass-advanced.js`, `anti-frida-bypass.js`, `anti-root-bypass-advanced.js`, `anti-root-bypass.js`, `cert-pinning-bypass-advanced.js`, `cert-pinning-bypass.js`, `integrity-bypass-advanced.js`, `integrity-bypass.js`

### `runtime-hooking`

- 名称: Frida runtime capture / Java + Native
- 成熟度: `synthetic-e2e`
- 维护方: `android-reverse-core`
- 风险等级: `high`
- 路线轨道: `runtime-hooking`
- 协议文档: `references/frida-java-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/runtime-hooking`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/runtime-hooking.json`
- taskInit: aliases=`frida-hook`, baseProtectionTier=`A3`, combinationProtectionTiers=none
- 必需 signals: `frida`, `java.use`, `interceptor`, `hexdump`, `hook`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables`
- caseFiles: `android-runtime-hook-workflow.mjs`
- taskPackFiles: `frida-java-template-advanced.js`, `frida-java-template.js`, `frida-native-template-advanced.js`, `frida-native-template.js`

### `split-delivery`

- 名称: Split delivery / APKS / AAB
- 成熟度: `synthetic-e2e`
- 维护方: `android-reverse-core`
- 风险等级: `medium`
- 路线轨道: `split-delivery`
- 协议文档: `references/split-delivery-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/split-delivery`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/split-delivery.json`
- taskInit: aliases=`split`, baseProtectionTier=`A2`, combinationProtectionTiers=none
- 必需 signals: `apks`, `aab`, `split apk`, `dynamic feature`, `asset pack`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables`
- caseFiles: `android-split-delivery-workflow.mjs`
- taskPackFiles: `split-delivery-notes.md`, `split-layout.json`

### `static-triage`

- 名称: Static triage / manifest / packaging
- 成熟度: `synthetic-e2e`
- 维护方: `android-reverse-core`
- 风险等级: `high`
- 路线轨道: `static-triage`
- 协议文档: `references/static-triage-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/static-triage`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/static-triage.json`
- taskInit: aliases=`apk-triage`, baseProtectionTier=`A0`, combinationProtectionTiers=none
- 必需 signals: `manifest`, `exported`, `permission`, `component`, `asset`, `resource`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables`
- caseFiles: `android-apk-triage-workflow.mjs`
- taskPackFiles: `component-map.md`, `static-triage-notes.md`

### `anti-emulator-debug`

- 名称: Anti-emulator / anti-debug / tracer bypass
- 成熟度: `closed-loop`
- 维护方: `android-reverse-core`
- 风险等级: `high`
- 路线轨道: `anti-emulator-debug`
- 协议文档: `references/anti-emulator-debug-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/anti-emulator-debug`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/anti-emulator-debug.json`
- taskInit: aliases=`anti-debug`, `emulator`, baseProtectionTier=`A3`, combinationProtectionTiers=none
- 必需 signals: `emulator`, `debug`, `tracer`, `ro.kernel.qemu`, `isdebuggerconnected`, `ptrace`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables`
- caseFiles: `android-anti-emulator-debug-workflow.mjs`
- taskPackFiles: `anti-emulator-bypass.js`

### `art-runtime`

- 名称: ART runtime / OAT / VDEX / inline / deopt
- 成熟度: `closed-loop`
- 维护方: `android-reverse-core`
- 风险等级: `high`
- 路线轨道: `art-runtime`
- 协议文档: `references/art-runtime-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/art-runtime`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/art-runtime.json`
- taskInit: aliases=`art`, `deopt`, baseProtectionTier=`A4`, combinationProtectionTiers=none
- 必需 signals: `oat`, `vdex`, `odex`, `inline`, `deopt`, `zygote`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables`
- caseFiles: `android-art-runtime-workflow.mjs`
- taskPackFiles: `art-runtime-notes.md`

### `call-flow`

- 名称: Call flow / Activity / ViewModel / Repository tracing
- 成熟度: `closed-loop`
- 维护方: `android-reverse-core`
- 风险等级: `medium`
- 路线轨道: `call-flow`
- 协议文档: `references/call-flow-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/call-flow`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/call-flow.json`
- taskInit: aliases=`flow`, `viewmodel`, baseProtectionTier=`A1`, combinationProtectionTiers=none
- 必需 signals: `activity`, `fragment`, `viewmodel`, `repository`, `onclick`, `observer`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables`
- caseFiles: `android-call-flow-workflow.mjs`
- taskPackFiles: `call-chain.md`

### `java-api`

- 名称: Java API / client / endpoint extraction
- 成熟度: `closed-loop`
- 维护方: `android-reverse-core`
- 风险等级: `medium`
- 路线轨道: `java-api`
- 协议文档: `references/java-api-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/java-api`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/java-api.json`
- taskInit: aliases=`api`, `endpoint`, baseProtectionTier=`A1`, combinationProtectionTiers=none
- 必需 signals: `retrofit`, `okhttp`, `volley`, `baseurl`, `api`, `endpoint`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables`
- caseFiles: `android-java-api-workflow.mjs`
- taskPackFiles: `api-map.md`

### `native-network`

- 名称: Native network / Cronet / BoringSSL / QUIC
- 成熟度: `closed-loop`
- 维护方: `android-reverse-core`
- 风险等级: `high`
- 路线轨道: `native-network`
- 协议文档: `references/native-network-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/native-network`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/native-network.json`
- taskInit: aliases=`cronet`, `tls`, baseProtectionTier=`A3`, combinationProtectionTiers=none
- 必需 signals: `cronet`, `boringssl`, `ssl_ctx`, `x509`, `quic`, `native tls`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables`
- caseFiles: `android-native-network-workflow.mjs`
- taskPackFiles: `network-stack-notes.md`

### `native-so`

- 名称: Native SO / ELF / symbol / crypto constant analysis
- 成熟度: `closed-loop`
- 维护方: `android-reverse-core`
- 风险等级: `high`
- 路线轨道: `native-so`
- 协议文档: `references/native-so-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/native-so`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/native-so.json`
- taskInit: aliases=`native`, `so`, baseProtectionTier=`A3`, combinationProtectionTiers=none
- 必需 signals: `elf`, `symbol`, `rva`, `so`, `crypto constant`, `syscall`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables`
- caseFiles: `android-native-so-workflow.mjs`
- taskPackFiles: `native-notes.md`

### `smali-patching`

- 名称: Smali patch / rebuild / resign / install verify
- 成熟度: `closed-loop`
- 维护方: `android-reverse-core`
- 风险等级: `medium`
- 路线轨道: `smali-patching`
- 协议文档: `references/smali-patching-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/smali-patching`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/smali-patching.json`
- taskInit: aliases=`smali`, `patch`, baseProtectionTier=`A2`, combinationProtectionTiers=none
- 必需 signals: `smali`, `patch`, `rebuild`, `resign`, `apktool`, `install verify`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables`
- caseFiles: `android-smali-patching-workflow.mjs`
- taskPackFiles: `smali-patch-notes.md`

### `storage-ipc`

- 名称: Storage / IPC / provider / binder evidence
- 成熟度: `closed-loop`
- 维护方: `android-reverse-core`
- 风险等级: `medium`
- 路线轨道: `storage-ipc`
- 协议文档: `references/storage-ipc-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/storage-ipc`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/storage-ipc.json`
- taskInit: aliases=`storage`, `ipc`, baseProtectionTier=`A1`, combinationProtectionTiers=none
- 必需 signals: `sharedpreferences`, `sqlite`, `room`, `mmkv`, `contentprovider`, `binder`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables`
- caseFiles: `android-storage-ipc-workflow.mjs`
- taskPackFiles: `storage-ipc-notes.md`

### `webview-hybrid`

- 名称: WebView / hybrid bridge / JS-Native boundary
- 成熟度: `closed-loop`
- 维护方: `android-reverse-core`
- 风险等级: `medium`
- 路线轨道: `webview-hybrid`
- 协议文档: `references/webview-hybrid-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/webview-hybrid`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/webview-hybrid.json`
- taskInit: aliases=`webview`, `hybrid`, baseProtectionTier=`A2`, combinationProtectionTiers=none
- 必需 signals: `webview`, `addjavascriptinterface`, `evaluatejavascript`, `hybrid`, `webchromeclient`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables`
- caseFiles: `android-webview-hybrid-workflow.mjs`
- taskPackFiles: `webview-bridge-notes.md`

### `ctf`

- 名称: Android CTF / crackme / solver extraction
- 成熟度: `guided`
- 维护方: `android-reverse-core`
- 风险等级: `medium`
- 路线轨道: `ctf`
- 协议文档: `references/ctf-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/ctf`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/ctf.json`
- taskInit: aliases=`crackme`, `flag`, baseProtectionTier=`A2`, combinationProtectionTiers=none
- 必需 signals: `ctf`, `crackme`, `flag`, `solver`, `challenge`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:operating-contracts`, `check:deliverables`
- caseFiles: `android-ctf-workflow.mjs`
- taskPackFiles: `solver-template.py`

### `deobfuscation`

- 名称: OLLVM / FLA / BR / SUB / BCF / deobfuscation
- 成熟度: `guided`
- 维护方: `android-reverse-core`
- 风险等级: `high`
- 路线轨道: `deobfuscation`
- 协议文档: `references/deobfuscation-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/deobfuscation`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/deobfuscation.json`
- taskInit: aliases=`deobf`, `ollvm`, baseProtectionTier=`A4`, combinationProtectionTiers=none
- 必需 signals: `ollvm`, `fla`, `control flow flattening`, `bogus control flow`, `bcf`, `instruction substitution`, `mba`, `dispatcher`, `deobfuscation`, `arkari`, `blackobfuscator`, `hikari`, `goron`, `blr obfuscation`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:deliverables`, `check:operating-contracts`
- caseFiles: `android-deobfuscation-workflow.mjs`
- taskPackFiles: `bcf-bss-patch-template.py`, `br-patch-template.py`, `fla-angr-template.py`, `fla-state-machine-template.py`, `fla-unicorn-template.py`, `fla-state-machine-template.py`, `fla-angr-template.py`, `fla-unicorn-template.py`, `br-patch-template.py`, `bcf-bss-patch-template.py`

### `device-fingerprint`

- 名称: Device fingerprint / risk control / Play Integrity
- 成熟度: `guided`
- 维护方: `android-reverse-core`
- 风险等级: `medium`
- 路线轨道: `device-fingerprint`
- 协议文档: `references/device-fingerprint-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/device-fingerprint`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/device-fingerprint.json`
- taskInit: aliases=`fingerprint`, `risk`, baseProtectionTier=`A3`, combinationProtectionTiers=none
- 必需 signals: `device fingerprint`, `risk control`, `play integrity`, `key attestation`, `safetynet`, `device id`, `android id`, `imei`, `risk engine`, `warlock`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:deliverables`, `check:operating-contracts`
- caseFiles: `android-device-fingerprint-workflow.mjs`
- taskPackFiles: `device-fingerprint-notes.md`, `device-fingerprint-notes.md`

### `hook-injection`

- 名称: Hook framework internals / injection methods
- 成熟度: `guided`
- 维护方: `android-reverse-core`
- 风险等级: `high`
- 路线轨道: `hook-injection`
- 协议文档: `references/hook-injection-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/hook-injection`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/hook-injection.json`
- taskInit: aliases=`hook`, `inject`, baseProtectionTier=`A3`, combinationProtectionTiers=none
- 必需 signals: `hook`, `injection`, `plt hook`, `got hook`, `inline hook`, `artmethod`, `zygisk`, `ptrace`, `frida internals`, `dobby`, `bhook`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:deliverables`, `check:operating-contracts`
- caseFiles: `android-hook-injection-workflow.mjs`
- taskPackFiles: `hook-injection-notes.md`, `hook-injection-notes.md`

### `kernel-assisted-re`

- 名称: Kernel-assisted reverse engineering (eBPF, HWBP, seccomp for app RE)
- 成熟度: `guided`
- 维护方: `android-reverse-core`
- 风险等级: `high`
- 路线轨道: `kernel-assisted-re`
- 协议文档: `references/kernel-assisted-re-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/kernel-assisted-re`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/kernel-assisted-re.json`
- taskInit: aliases=`kernel`, `kre`, baseProtectionTier=`A5`, combinationProtectionTiers=none
- 必需 signals: `ebpf`, `hardware breakpoint`, `hwbp`, `pte hook`, `seccomp`, `svc monitor`, `dex dump kernel`, `edbg`, `kernel module`, `kpm`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:deliverables`, `check:operating-contracts`
- caseFiles: `android-kernel-assisted-re-workflow.mjs`
- taskPackFiles: `kernel-assisted-re-notes.md`, `kernel-assisted-re-notes.md`

### `so-runtime-evidence`

- 名称: SO Runtime Evidence (encrypted/packed SO dump-fix, anonymous RX/memfd execution, crash syscall attribution)
- 成熟度: `guided`
- 维护方: `android-reverse-core`
- 风险等级: `high`
- 路线轨道: `so-runtime-evidence`
- 协议文档: `references/so-runtime-evidence-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/so-runtime-evidence`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/so-runtime-evidence.json`
- taskInit: aliases=`sre`, `so-runtime`, baseProtectionTier=`A4`, combinationProtectionTiers=none
- 必需 signals: `encrypted so`, `packed so`, `self-decrypt`, `runtime rebuild`, `anonymous rx`, `memfd`, `anon exec`, `crash pc lr`, `sigkill`, `sigsegv`, `sigtrap`, `brk`, `direct syscall`, `dump fix`, `call_constructors`, `init_array crash`, `so 闪退`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:deliverables`, `check:operating-contracts`
- caseFiles: `android-so-runtime-evidence-workflow.mjs`
- taskPackFiles: `so-runtime-evidence-notes.md`

### `stealth-hook`

- 名称: Stealth Hook (Kernel-assisted zero-trace hooking via HWBP+PTE+DBI+GhostMem)
- 成熟度: `guided`
- 维护方: `android-reverse-core`
- 风险等级: `high`
- 路线轨道: `stealth-hook`
- 协议文档: `references/stealth-hook-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/stealth-hook`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/stealth-hook.json`
- taskInit: aliases=`stealth`, `shook`, baseProtectionTier=`A6`, combinationProtectionTiers=none
- 必需 signals: `stealth hook`, `无痕 hook`, `kernel hook`, `hwbp`, `hardware breakpoint`, `硬件断点`, `pte hook`, `page table hook`, `uxn`, `dbi`, `dynamic binary instrumentation`, `指令重编译`, `ghost memory`, `幽灵内存`, `vma-less`, `maps hide`, `ptrace spoof`, `kpm`, `kernelpatch`, `apatch`, `xiaojianbang`, `lsplant stealth`, `artmethod stealth`, `anti-cheat bypass`, `crc bypass`, `text crc`, `反作弊`, `frida detected`, `frida 不上`, `ptrace detected`, `a6 hook`, `a7 hook`, `高对抗 hook`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:deliverables`, `check:operating-contracts`
- caseFiles: `android-stealth-hook-workflow.mjs`
- taskPackFiles: `stealth-hook-notes.md`, `stealth-hook-notes.md`

### `trace-analysis`

- 名称: Trace collection, slicing, taint analysis, and algorithm recovery
- 成熟度: `guided`
- 维护方: `android-reverse-core`
- 风险等级: `medium`
- 路线轨道: `trace-analysis`
- 协议文档: `references/trace-analysis-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/trace-analysis`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/trace-analysis.json`
- taskInit: aliases=`trace`, `trc`, baseProtectionTier=`A3`, combinationProtectionTiers=none
- 必需 signals: `trace`, `trace-ui`, `trace-slice`, `taint`, `ltv-taint`, `gumtrace`, `qtrace`, `vmlifter`, `instruction trace`, `execution trace`, `algorithm recovery`, `semantic lift`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:deliverables`, `check:operating-contracts`
- caseFiles: `android-trace-analysis-workflow.mjs`
- taskPackFiles: `trace-analysis-notes.md`, `trace-analysis-notes.md`

### `unidbg-simulation`

- 名称: Unidbg / Unicorn / QBDI / angr simulation
- 成熟度: `guided`
- 维护方: `android-reverse-core`
- 风险等级: `medium`
- 路线轨道: `unidbg-simulation`
- 协议文档: `references/unidbg-simulation-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/unidbg-simulation`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/unidbg-simulation.json`
- taskInit: aliases=`unidbg`, `emu`, baseProtectionTier=`A3`, combinationProtectionTiers=none
- 必需 signals: `unidbg`, `unicorn`, `qbdi`, `angr`, `emulation`, `simulation`, `environment patching`, `jni patch`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:deliverables`, `check:operating-contracts`
- caseFiles: `android-unidbg-simulation-workflow.mjs`
- taskPackFiles: `unidbg-simulation-notes.md`, `unidbg-simulation-notes.md`

### `vmp-analysis`

- 名称: VMP / VM interpreter / opcode restoration
- 成熟度: `guided`
- 维护方: `android-reverse-core`
- 风险等级: `high`
- 路线轨道: `vmp-analysis`
- 协议文档: `references/vmp-analysis-playbook.md`
- taskPackDir: `artifacts/tasks/_TEMPLATE/topic-packs/vmp-analysis`
- taskModelFile: `artifacts/tasks/_TEMPLATE/extensions/vmp-analysis.json`
- taskInit: aliases=`vmp`, `vm`, baseProtectionTier=`A5`, combinationProtectionTiers=none
- 必需 signals: `vmp`, `vm interpreter`, `handler table`, `opcode mapping`, `bytecode restoration`, `dispatcher`, `virtual machine protection`, `dexprotector`, `liapp`
- 必需检查: `check:topic-manifests`, `check:capability-coverage`, `check:deliverables`, `check:operating-contracts`
- caseFiles: `android-vmp-analysis-workflow.mjs`
- taskPackFiles: `vmp-analysis-notes.md`, `vmp-analysis-notes.md`

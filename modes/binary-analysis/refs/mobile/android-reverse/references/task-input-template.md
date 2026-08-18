# 自动化任务输入模板

最少输入字段：

- `target`
- `objective`
- `requirements`
- `boundaries`

推荐补充字段：

- `targetType`
- `targetParts`
- `packageName`
- `apkVersion`
- `abi`
- `androidVersion`
- `deviceMode`
- `attachMode`
- `protectionHints`
- `frameworkHints`
- `networkHints`
- `processHints`
- `entryHints`
- `declaredTools` / `mcpTools`
- `preferredTools`
- `deliverableTier`
- `deliverables`（复合任务的结构化交付单元）
- `completionCriteria`
- `successCriteria`（仅旧输入兼容；新任务不要同时提供）
- `timeBudget`
- `retryPolicy`
- `patchingAllowed`
- `dynamicAllowed`

## 结构化输入

- Schema: `references/schemas/android-reverse-task-input.schema.json`
- Example: `references/schemas/android-reverse-task-input.example.json`
- 场景样例:
  - `references/task-input-examples/login-jni-native-network.json`
  - `references/task-input-examples/split-dex-crypto.json`
  - `references/task-input-examples/webview-storage-smali.json`
  - `references/task-input-examples/ctf-crackme.json`

## 推荐写法

- `target`、`requirements`、`boundaries` 既支持简单字符串，也支持对象形式
- 对象形式更适合自动初始化，因为 `task-init --task-input=...` 会把 `deliverables`、`localReproductionRequested`、`apiCallExampleRequired`、`forbiddenActions`、`frameworkHints`、`networkHints` 等字段直接映射到 task-local
- 用户声明 `mt-mcp` / MT 管理器优先时，写入 `declaredTools` 或 `preferredTools`；`task-init` 会在 `task.json.toolchain` 中记录前台要求，后续不可静默降级
- 当 `task-input` 中出现 `Flutter / Hermes / Unity / Cronet / JNI / CertificatePinner / DexClassLoader / split APK` 等线索时，`task-init` 会自动补选对应 topic pack

## 输入约束

- 允许脱敏值
- 禁止真实 token / key / 证书私钥入库
- 真实样本应留在 task-local 目录


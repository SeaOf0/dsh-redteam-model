# 任务契约详细约束

创建 `task.json` 时按需读取本文件，获取 `deliverableTier` 和 `completionCriteria` 的详细约束。

## deliverableTier 约束内联

创建 `task.json` 时，必须根据 `deliverableTier` 值在 `task.json` 中增加对应的约束字段，确保上下文压缩后仍可从 task.json 恢复：

- `T5`：增加 `"disallowedRuntimeDeps": ["unicorn", "unidbg", "angr", "qiling", "frida", "adb", "java_subprocess"]`，增加 `"allowedCryptoDeps": ["pycryptodome", "cryptography", "crypto-js", "node-forge", "hashlib", "hmac", "base64", "struct"]`
- `T4`：增加 `"requiresProtocolDoc": true`，增加 `"disallowedRuntimeDeps": ["unicorn", "unidbg", "angr", "qiling"]`（T4 允许 Frida 作为分析辅助，但最终交付不应依赖模拟器框架）
- `T3`：增加 `"requiresSmaliPatch": true`
- `T2`：增加 `"requiresRunnableHook": true`，增加 `"disallowedRuntimeDeps": ["unicorn", "unidbg", "angr", "qiling"]`（T2 允许 Frida 本身作为交付依赖，但不允许模拟器框架）

## completionCriteria 有效性

每条标准必须包含可观察的验证方法（如"adb shell am start 后无 crash logcat 输出"）。禁止"完成/ok/pass/正常/稳定/流畅"等主观词。

## completionCriteria 反向约束推导

当 `objective` 包含核心动作动词（生成/还原/提取/解密/签名/加密/计算/破解/实现），对应条目必须显式排除该动作的常见替代捷径。推导方法：对 objective 中的每个核心动词，自问"什么操作从表面看满足目标但实际绕过了核心难点？"，将答案的否定形式写入 completionCriteria。常见捷径对照：

| 核心动词       | 常见替代捷径      | completionCriteria 应排除                 |
| -------------- | ----------------- | ----------------------------------------- |
| 生成/实现      | 重放预捕获值      | "对新输入实时计算（非重放预捕获值）"      |
| 还原           | 调用原始二进制/SO | "独立实现算法（非调用原 SO/非 RPC）"      |
| 还原           | 确认使用了某算法  | "完整还原计算过程（非仅识别算法类型）"    |
| 协议还原       | 修改重放原请求    | "可构造全新请求（非修改原始请求重放）"    |
| 纯 Python 实现 | 依赖外部进程/工具 | "零运行时外部依赖（非子进程调用/非 RPC）" |

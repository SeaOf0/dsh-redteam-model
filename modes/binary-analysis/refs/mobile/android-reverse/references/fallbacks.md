# Fallbacks

## 工具回退

- `jadx` 不可用：使用 `apktool + JEB/JD`，报告标记为 `UNVERIFIED`
- `JEB` 不可用：保留 `jadx + strings + Frida`
- `IDA` 不可用：优先用导出符号、字符串、Frida Native 取证
- `Frida` 不可用：只做静态，但所有运行时结论标记为 `INFERRED`

## 证据回退

- 无法直接拿到返回值：先抓入参与中间值
- 无法直接定位 JNI：先从 `System.loadLibrary` 和字符串反推
- 无法 dump Dex：先记录加载点、解密源、内存窗口和阻断原因

## 时间回退

- 超时前先沉淀已确认事实
- 报告必须写明已检查项、未完成项、下一条最高收益路径

## A6 A7 回退

- `hook 未命中`：先对照 `references/a6-a7-failure-pattern-cookbook.md` 排查进程、时机、loader、bridge、网络分层
- `一次 bypass 后又出现新故障`：不要立即扩大 patch 面，先判断是不是进入了下一条 failure pattern


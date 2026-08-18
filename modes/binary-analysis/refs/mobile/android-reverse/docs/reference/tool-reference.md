# Tool Reference

优先链：

- `JADX/JEB/Apktool` 做静态分诊与资源/Manifest/Smali 观察
- `IDA` 做 SO / JNI / Native 深挖
- `Frida` 做 Java / Native / TLS / ClassLoader 动态取证
- `mt-mcp` 做用户显式指定的 MT 管理器交互、文件观察、smali/资源辅助操作；使用前必须确认 MT 管理器在手机顶层前台
- `adb / bundletool / logcat` 做安装、split、运行时验证

统一要求：

- 先 triage，再决定静态、动态还是 patch
- 先证据，后结论
- 先最小 probe，再扩展工具链
- 动态任务优先从 `artifacts/tasks/_TEMPLATE/run/*.js` baseline 改起
- 用户声明某 MCP 工具优先时，先验证并落 `task.json.toolchain`；不可静默改走其它工具
- `A6 / A7` 任务先用 `references/a6-a7-failure-pattern-cookbook.md` 排除高频假阴性
- 默认版脚本用于低噪声切入，`*-advanced.js` 用于高对抗扩面与二次验证


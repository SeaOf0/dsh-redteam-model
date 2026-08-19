# 02 patchless AMSI（上下文破坏）

- 运行：PowerShell 5.x（-ExecutionPolicy Bypass；本地实验机）
- 技术侧：反射置 amsiInitFailed → AMSI 走初始化失败降级路径（不 patch 任何字节，
  对抗针对 AmsiScanBuffer 补丁的完整性校验）。PS7/新版 PowerShell 需换字段路线
  （NOTES 变体登记）。
- 检测侧配对：AmsiUtils 反射访问遥测（.NET 反射敏感 API 监控）；amsiInitFailed
  状态一致性校验（ETW Microsoft-Antimalware-Service 会话事件缺失）。
- 判定表（本地实测后填）：| 引擎 | 结果 | 原文行 |

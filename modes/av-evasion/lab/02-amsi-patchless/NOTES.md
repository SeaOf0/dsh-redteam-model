# 02 patchless AMSI（上下文破坏）

- 运行：PowerShell 5.x / 7.x（-ExecutionPolicy Bypass；本地实验机）
- 技术侧（三条路线按序尝试，任一路线成功即静默后续扫描）：
  - **R1 .NET 反射路线（PS5+PS7 通用）**：置 amsiInitFailed → AMSI 走初始化失败降级路径。
    PS5 用限定程序集名解析 AmsiUtils；PS7 按程序集名在当前加载域检索同类型
    （`AppDomain.GetAssemblies() | ? FullName -match 'System.Management.Automation'`，
    避开版本/公钥差异）——**不 patch 任何字节**。
  - **R2 Win32 数据补丁路线（patchless 核心）**：AmsiScanBuffer 前导 64 字节窗口内定位
    `lea rcx,[rip+disp32]` → 反算 AmsiContext 变量地址 → 置 NULL（8 字节零写）→ 回读验证。
    patch 的是**上下文指针数据**而非代码字节，对抗针对 AmsiScanBuffer 的补丁完整性校验。
  - **R3 观察项**：两路线均未命中时记录 PS 版本/amsi.dll 前导，供判定（如实现不变式）。
- 检测侧配对：AmsiUtils 反射访问遥测（.NET 反射敏感 API 监控）；amsiInitFailed
  状态一致性校验（ETW Microsoft-Antimalware-Service 会话事件缺失）；AmsiContext 指针
  空值校验（扫描前对 context 成员做非空断言）。
- 判定表（本地实测后填）：| 引擎 | 结果 | 原文行 |
- 变体登记：R1（PS5/PS7 字段路线）与 R2（Win32 数据补丁）为互补形态；
  内存 patch 类（改 AmsiScanBuffer 字节）不在本实验范围（见 refs/techniques/
  AMSI_BYPASS_TECHNIQUES.md，完整性校验对抗面差异）。
- 验证记录：2026-08-20 ps1 语法检查未执行（本机无 pwsh，如实标注）；运行验证待
  Windows PowerShell 判定环境。

# 03 ETW 压制

- 构建：`x86_64-w64-mingw32-gcc -mwindows -o etw-patch.exe etw_patch.c`
- 用法：`etw-patch.exe [mode]`（默认 mode 0）
  - mode 0：EtwEventWrite 首字节置 ret——本进程 ETW 事件静默（最小改动面）
  - mode 1：EtwEventWrite + EtwEventWriteFull 双入口置 ret
  - mode 2：NtTraceEvent stub 置 ret——最深层入口（syscall 层），覆盖面最大但
    ntdll 完整性校验检出概率最高
  - mode 3：provider 选择性静默——EtwEventWrite 入口 5 字节 jmp 钩子 → 转接块比对
    `EVENT_DESCRIPTOR+0x10` 的 ProviderId.Data1：命中返回 0（该 provider 静默），
    未命中**还原原函数前导 14 字节后跳回原入口**（防钩子重入、可重复安装、
    其余遥测保留——隐蔽性高于全量静默）
- 技术侧：只影响自身进程；mode 0/1 为单字节/双入口补丁，mode 3 为带还原的 inline 钩子。
- 检测侧配对：EtwEventWrite 入口完整性校验（EDR 自检/probe 遥测）；事件流突然静默
  （进程存活但 ETW 零事件=自身遥测缺失告警）；内存属性变更监控（VirtualProtect 敏感
  调用）；mode 3 的 jmp 入口与异常控制流（CFG）。
- 判定表（本地实测后填）：| 引擎 | 结果 | 原文行 |
- 变体登记：mode 0/1/2（深度递增的 ret 补丁）+ mode 3（选择性钩子）；
  「断 EtwpEventRegister 回调」未落地（见 refs/techniques/AMSI_ETW_BYPASS.md）。
  Windows 判定环境。

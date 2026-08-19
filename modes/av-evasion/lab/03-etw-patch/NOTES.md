# 03 ETW 压制

- 构建：`x86_64-w64-mingw32-gcc -mwindows -o etw-patch.exe etw_patch.c`
- 技术侧：进程内 EtwEventWrite 首字节置 ret——本进程 ETW 遥测静默（只影响自身进程）。
- 变体：整段 nopping、provider GUID patch、断 EtwpEventRegister 回调（配对补充）。
- 检测侧配对：EtwEventWrite 入口完整性校验（EDR 自检/probe 遥测）；事件流突然静默
  （进程存活但 ETW 零事件=自身遥测缺失告警）；内存属性变更监控。
- 判定表：| 引擎 | 结果 | 原文行 |

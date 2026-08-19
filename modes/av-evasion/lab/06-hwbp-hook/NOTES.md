# 06 硬件断点拦截

- 构建：`x86_64-w64-mingw32-gcc -mwindows -o hwbp.exe hwbp.c`
- 技术侧：Dr 寄存器对目标函数下执行断点 + VEH 在断点处短路（改返回值/参数）——
  全程不改代码字节，对抗 AmsiScanBuffer/EtwEventWrite 补丁完整性校验。
- 变体：多断点（AMSI+ETW 同挂）、断点后单步续执行改参数路线、x32 调用约定适配。
- 检测侧配对：Dr 寄存器非零遥测（SetThreadContext CONTEXT_DEBUG_REGISTERS 敏感操作）；
  VEH 注册监控；单步异常频次；ETW-TI 断点上下文可见性。
- 判定表：| 引擎 | 结果 | 原文行 |

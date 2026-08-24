# 06 硬件断点拦截

- 构建：`x86_64-w64-mingw32-gcc -mwindows -o hwbp.exe hwbp.c`
- 用法：`hwbp.exe [mode]`
  - mode 0（默认）：**短路式 + 多断点**——Dr0=AmsiScanBuffer、Dr1=EtwEventWrite 同挂，
    命中即 Rax=0（+置 AMSI_RESULT_CLEAN）并 RIP 直跳返回地址，不进入被拦函数
  - mode 1：**改参续行式**——Dr0 命中把 r8（length）清零 → 摘断点位 + TF 单步 →
    SINGLE_STEP 里重挂断点位、清 TF → 函数照常执行完毕（扫描长度 0 → 无扫描返回 S_OK）
- 技术侧：全程不改代码字节，对抗 AmsiScanBuffer/EtwEventWrite 补丁完整性校验。
  **硬件断点关键语义**：断点命中时指令**未执行**——短路式必须手动推进 RIP；
  续行式必须先摘点再放行，否则同地址死循环；Dr 断点与 TF 单步都投递
  EXCEPTION_SINGLE_STEP，VEH 内先按 Rip 区分命中目标，Dr6 清位防判定残留。
- 变体（未落地）：x32 调用约定适配（Dr0-3 与栈参布局差异，需 i686 编译链）。
- 检测侧配对：Dr 寄存器非零遥测（SetThreadContext CONTEXT_DEBUG_REGISTERS 敏感操作）；
  VEH 注册监控；单步异常频次；ETW-TI 断点上下文可见性。
- 判定表（本地实测后填）：| 引擎 | 结果 | 原文行 |
- 构建验证记录：2026-08-20 mingw 14.0.0 编译通过（PE32+ GUI x86-64）；运行验证待
  Windows 判定环境。

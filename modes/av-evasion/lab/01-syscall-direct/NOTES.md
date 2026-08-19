# 01 直接系统调用

- 构建：`x86_64-w64-mingw32-gcc -mwindows -o syscall-demo.exe main.c`
- 技术侧：读 ntdll 导出函数体内 SSN → 自建 stub 直接 syscall——绕过 EDR 对 ntdll 的
  inline hook（调用不经过被 hook 的函数入口）。
- 检测侧配对：syscall 指令地址不在 ntdll 映射内（源异常遥测）；栈回溯缺 ntdll 帧；
  ETW-TI（Thread Intelligence）可标记非镜像 syscall 来源。
- 判定表（本地实测后填）：| 引擎 | 结果 | 原文行 |
- 变体登记：SSN 读取方式（函数体偏移 vs 导出表遍历）、stub 位置（栈 vs 堆）。

## indirect 变体（indirect.c）

- 构建：`x86_64-w64-mingw32-gcc -mwindows -o indirect-demo.exe indirect.c`
- 与 direct 互补：**syscall 指令在 ntdll 内执行**（跳转 gadget `syscall;ret`），调用栈显示
  合法 ntdll 返回地址——对抗"syscall 指令地址不在 ntdll 映射内"的遥测。
- **Halo's Gate**：目标函数被 hook 时从邻近存步按 32 字节步进推算 SSN（hook 通常只改
  头几字节，邻居完好）；再进一步 Tartarus' Gate（邻近也被 hook 时正反向交错扫描）。
- 进阶组合：.text code cave 存桩（零额外可执行分配）+ stub 用后 SecureZeroMemory 清零。
- 检测侧配对：非入口跳入 ntdll 中段的异常控制流（CFG/ETW-TI）；gadget 地址统计
  （固定偏移被指纹）；栈上可执行内存遥测。
- 判定表：| 引擎 | 结果 | 原文行 |

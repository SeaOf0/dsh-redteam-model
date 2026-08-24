# 01 直接系统调用

- 构建：`x86_64-w64-mingw32-gcc -c -x assembler -o syscall.o syscall.asm && x86_64-w64-mingw32-gcc -mwindows -o syscall-demo.exe main.c syscall.o`
  （build.sh 01 case 已含此链）
- 技术侧：**SSN 运行时解析**——syscall.asm 的 GetSSN 走 PEB→Ldr→InMemoryOrderModuleList
  （两跳取 ntdll，第一项是 exe）→ PE 导出表按名线性匹配 → name 下标→ordinal→函数 RVA→
  校验 `4C 8B D1 B8` 前导后读 SSN。全程零 GetModuleHandle/GetProcAddress 调用。
  自建 stub 直接 syscall——绕过 EDR 对 ntdll 的 inline hook（调用不经过被 hook 的函数入口）。
- 形态对照（main.c 两形态）：
  - **A：.text 静态 stub**（DoDirectSyscall，syscall.asm 内）——syscall 指令在本模块 .text；
  - **B：堆上动态 stub**（heap_stub_call，RW 组桩 → RX 执行 → RX→RW → SecureZeroMemory
    清零 → 释放）——对照「stub 位置（栈 vs 堆 vs 镜像 .text）」变体。
- 检测侧配对：syscall 指令地址不在 ntdll 映射内（源异常遥测）；栈回溯缺 ntdll 帧；
  ETW-TI（Thread Intelligence）可标记非镜像 syscall 来源。
- 判定表（本地实测后填）：| 引擎 | 结果 | 原文行 |
- 变体登记：SSN 读取方式（函数体偏移 vs 导出表遍历——本实现=导出表遍历）、
  stub 位置（栈 vs 堆 vs .text——本实现=堆+.text 两形态对照）。
- 构建验证记录：2026-08-20 mingw 14.0.0（GNU as 2.46）汇编+链接通过
  （PE32+ GUI x86-64）；运行验证待 Windows 判定环境（lab 纪律：结论覆盖=实测环境面）。

## indirect 变体（indirect.c）

- 构建：`x86_64-w64-mingw32-gcc -mwindows -o indirect-demo.exe indirect.c`
- 与 direct 互补：**syscall 指令在 ntdll 内执行**（跳转 gadget `syscall;ret`），对抗
  "syscall 指令地址不在 ntdll 映射内"的遥测。
- **SSN 解析三级**：①目标函数体直接读（未 hook）→ ②Halo's Gate（被 hook 时从邻近存根
  按 32 字节步进推算）→ ③Tartarus' Gate（邻近也被 hook 时正反向交错扫描；②③合并在
  ssn_of，±512 字节窗口，SSN 结果做范围校验防误判）。
- **gadget 定位**：PE 头解析取 ntdll .text 段（IMAGE_SCN_MEM_EXECUTE），段内扫描
  `0F 05 C3`——不再依赖"某函数入口偏移 0x12"的脆弱假设。
- **桩形态**：VirtualAlloc RW 组桩（mov r10,rcx / mov eax,SSN / jmp [rip+0]→gadget，23B）
  → RX → 执行 → RX→RW → SecureZeroMemory → 释放（堆桩而非栈桩——避免栈可执行遥测）。
- 进阶组合（未落地，见 refs/techniques/ADVANCED_EVASION.md）：.text code cave 存桩
  （零额外可执行分配）。
- 检测侧配对：非入口跳入 ntdll 中段的异常控制流（CFG/ETW-TI）；gadget 地址统计
  （固定偏移被指纹）；进程私有可执行内存遥测。
- 判定表：| 引擎 | 结果 | 原文行 |
- 构建验证记录：2026-08-20 mingw 14.0.0 编译通过（PE32+ GUI x86-64）；运行验证待
  Windows 判定环境。

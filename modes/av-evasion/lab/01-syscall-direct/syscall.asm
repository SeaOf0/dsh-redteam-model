; SSN 动态解析 stub：运行时从 ntdll 导出表读系统调用号，避开硬编码版本耦合
section .text
global GetSSN, DoDirectSyscall
extern printf

GetSSN:
    ; rcx = ntdll!Nt 函数名哈希（简易 djb2 预计算）；返回 eax = SSN
    ; 遍历 ntdll 导出表按名匹配（demo：调用方传函数名指针，此处线性查找）
    mov rax, [gs:0x60]          ; PEB
    mov rax, [rax+0x18]         ; PEB->Ldr
    mov rax, [rax+0x20]         ; InMemoryOrderModuleList
    mov rax, [rax]              ; ntdll（第二项）
    mov rax, [rax+0x20]         ; DllBase
    mov rdx, [rax+0x3C]         ; e_lfanew
    add rdx, rax
    mov edx, [rdx+0x88]         ; ExportRVA
    add rdx, rax
    mov r10d, [rdx+0x14]        ; NumberOfNames
    mov r8,  [rdx+0x20]         ; AddressOfNames
    add r8,  rax
    mov r9,  rcx                ; 目标名
.loop:
    dec r10d
    js .fail
    mov rcx, [r8 + r10*4]
    add rcx, rax
    mov rsi, r9
    mov rdi, rcx
    mov r11, 0
.cmp:
    mov al, [rsi+r11]
    mov bl, [rdi+r11]
    cmp al, bl
    jne .loop
    test al, al
    jz .found
    inc r11
    jmp .cmp
.found:
    mov r8, [rdx+0x24]          ; AddressOfNameOrdinals
    mov cx,  [r8 + r10*2]
    mov r8, [rdx+0x1C]          ; AddressOfFunctions
    mov eax, [r8 + rcx*4]
    add rax, rax_loop_dummy     ; (占位：实际 = ntdll base + RVA)
    ret
.fail:
    xor eax, eax
    ret

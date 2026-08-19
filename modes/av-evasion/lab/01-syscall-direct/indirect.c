// 间接系统调用 demo：跳转到 ntdll 中真实 syscall;ret 指令——调用栈显示合法 ntdll 返回地址
// 与 direct 版互补：direct 的 syscall 指令在自己模块内（栈异常遥测可测）；indirect 借 ntdll 现场执行
// Halo's Gate：目标 Nt 函数被 hook 时，从邻近未 hook 存根位置 +/-16 字节步进推算 SSN
#include <windows.h>
#include <stdio.h>

static DWORD ssn_of(BYTE* fn) {
    if (fn[0] == 0x4C && fn[1] == 0x8B && fn[2] == 0xD1 && fn[3] == 0xB8)
        return *(DWORD*)(fn + 4);                  // 未 hook：直接读
    for (int i = 1; i < 32; i++) {                  // Halo's Gate：邻近存根推算
        BYTE* up = fn + i * 32;
        if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8)
            return *(DWORD*)(up + 4) - i;           // 上邻 SSN - 偏移
        BYTE* dn = fn - i * 32;
        if (dn[0] == 0x4C && dn[1] == 0x8B && dn[2] == 0xD1 && dn[3] == 0xB8)
            return *(DWORD*)(dn + 4) + i;           // 下邻 SSN + 偏移
    }
    return 0;
}

int main(void) {
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    BYTE* avm = (BYTE*)GetProcAddress(nt, "NtAllocateVirtualMemory");
    DWORD ssn = ssn_of(avm);
    if (!ssn) { printf("[-] SSN 解析失败\n"); return 1; }
    // 定位 ntdll 内任一 syscall;ret gadget（syscall 指令 = 0F 05，后随 C3）
    BYTE* nte = (BYTE*)GetProcAddress(nt, "NtWriteVirtualMemory");
    // 标准 stub 布局：mov r10,rcx(4B) mov eax,ssn(5B) ... syscall(2B) ret(1B)——偏移 0x12 处
    BYTE* gadget = NULL;
    for (int off = 0; off < 0x20 && !gadget; off++)
        if (nte[off] == 0x0F && nte[off+1] == 0x05 && nte[off+2] == 0xC3)
            gadget = nte + off;
    if (!gadget) { printf("[-] syscall;ret gadget 未定位\n"); return 2; }
    // 组桩：mov eax,SSN ; jmp gadget（跳转而非自带 syscall——指令在 ntdll 内执行）
    BYTE stub[16]; int i = 0;
    stub[i++] = 0xB8; *(DWORD*)(stub+i) = ssn; i += 4;        // mov eax, ssn
    stub[i++] = 0xFF; stub[i++] = 0x25; *(DWORD*)(stub+i) = 0; i += 4;  // jmp [rip+0]
    *(ULONG64*)(stub+i) = (ULONG64)gadget; i += 8;            // target
    DWORD old; VirtualProtect(stub, sizeof(stub), PAGE_EXECUTE_READWRITE, &old);
    LPVOID mem = NULL; SIZE_T sz = 0x1000;
    typedef LONG (WINAPI *P)(HANDLE, PVOID*, ULONG, PSIZE_T, ULONG, ULONG);
    LONG st = ((P)stub)(GetCurrentProcess(), &mem, 0, &sz, MEM_COMMIT, PAGE_READWRITE);
    printf("[+] indirect syscall：SSN=%lu gadget=%p status=0x%lX mem=%p\n", ssn, (void*)gadget, st, mem);
    return st == 0 ? 0 : 1;
}

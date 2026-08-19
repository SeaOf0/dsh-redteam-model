// 直接系统调用 demo：以 NtAllocateVirtualMemory 为例，绕过 ntdll 用户态 inline hook
// 判定配对见 NOTES.md。构建：x86_64-w64-mingw32-gcc（-masm 不需要，asm 单独汇编）
#include <windows.h>
#include <stdio.h>

// demo 版：直接读 ntdll!NtAllocateVirtualMemory 函数体第 5 字节取 SSN（mov eax, SSN）
// 这是 HellsGate 系的极简形态：不 hook 不 patch，只读再自建 stub
typedef LONG (WINAPI *pNtAVM)(HANDLE, PVOID*, ULONG, PSIZE_T, ULONG, ULONG);
typedef LONG (WINAPI *pStub)(HANDLE, PVOID*, ULONG, PSIZE_T, ULONG, ULONG);

#pragma pack(push, 1)
typedef struct { WORD mov_eax; DWORD ssn; WORD syscall_ret; } STUB;
#pragma pack(pop)

int main(void) {
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    pNtAVM fn = (pNtAVM)GetProcAddress(nt, "NtAllocateVirtualMemory");
    BYTE* p = (BYTE*)fn;
    // 标准 syscall 序列：mov r10,rcx; mov eax,<SSN>
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
        DWORD ssn = *(DWORD*)(p + 4);
        STUB stub = { 0xB8, ssn, 0x0F05C3 };  // mov eax,ssn; syscall; ret
        LPVOID mem = NULL; SIZE_T sz = 0x1000;
        LONG st = ((pStub)&stub)(GetCurrentProcess(), &mem, 0, &sz, MEM_COMMIT, PAGE_READWRITE);
        printf("[+] SSN=%lu status=0x%lX mem=%p（直接 syscall 分配成功）\n", ssn, st, mem);
        return st == 0 ? 0 : 1;
    }
    printf("[-] 未识别 syscall 序列（hook 或版本差异）\n");
    return 2;
}

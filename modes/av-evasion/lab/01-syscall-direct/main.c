// 直接系统调用（direct syscall）完整实现：SSN 运行时解析 + 双 stub 形态对照
//
// 形态 A（.text 静态 stub）：GetSSN/DoDirectSyscall 由 syscall.asm 提供——
//   导出表遍历读 SSN（零 GetProcAddress 依赖），syscall 指令在本模块 .text 内。
// 形态 B（堆上动态 stub）：同一 SSN 手工组桩到 RW→RX 的私有内存，
//   用完 SecureZeroMemory 清零——对照「stub 位置（栈 vs 堆 vs 镜像 .text）」变体。
// 判定配对见 NOTES.md。构建：
//   x86_64-w64-mingw32-gcc -c -o syscall.o syscall.asm
//   x86_64-w64-mingw32-gcc -mwindows -o syscall-demo.exe main.c syscall.o
#include <windows.h>
#include <stdio.h>

/* syscall.asm 提供（Windows x64 调用约定） */
DWORD GetSSN(const char* name);
LONG  DoDirectSyscall(DWORD ssn, ULONG64 args[6]);

typedef LONG (WINAPI *pNtAVM)(HANDLE, PVOID*, ULONG, PSIZE_T, ULONG, ULONG);

/* 形态 B：堆 stub 组桩（mov r10,rcx; mov eax,SSN; syscall; ret = 12 字节） */
static LONG heap_stub_call(DWORD ssn, HANDLE proc, PVOID* base, PSIZE_T size, ULONG at, ULONG prot) {
    BYTE code[12];
    code[0] = 0x4C; code[1] = 0x8B; code[2] = 0xD1;          /* mov r10, rcx   */
    code[3] = 0xB8; *(DWORD*)(code + 4) = ssn;               /* mov eax, SSN   */
    code[8] = 0x0F; code[9] = 0x05;                          /* syscall        */
    code[10] = 0xC3;                                         /* ret            */
    BYTE* stub = (BYTE*)VirtualAlloc(NULL, sizeof(code), MEM_COMMIT, PAGE_READWRITE);
    if (!stub) return -1;
    memcpy(stub, code, sizeof(code));
    DWORD old;
    VirtualProtect(stub, sizeof(code), PAGE_EXECUTE_READ, &old);   /* RW → RX */
    LONG st = ((pNtAVM)stub)(proc, base, 0, size, at, prot);
    VirtualProtect(stub, sizeof(code), PAGE_READWRITE, &old);      /* RX → RW */
    SecureZeroMemory(stub, sizeof(code));                          /* 用后清零   */
    VirtualFree(stub, 0, MEM_RELEASE);
    return st;
}

int main(void) {
    /* ── 形态 A：.text 内 asm stub（导出表遍历解析 SSN）── */
    DWORD ssn = GetSSN("NtAllocateVirtualMemory");
    printf("[A] GetSSN(NtAllocateVirtualMemory) = %lu\n", ssn);
    if (ssn) {
        LPVOID mem = NULL; SIZE_T sz = 0x1000;
        ULONG64 args[6] = { (ULONG64)GetCurrentProcess(), (ULONG64)&mem, 0,
                            (ULONG64)&sz, MEM_COMMIT, PAGE_READWRITE };
        LONG st = DoDirectSyscall(ssn, args);
        printf("[A] direct syscall（.text stub）status=0x%lX mem=%p\n", st, mem);
    }

    /* ── 形态 B：堆上动态 stub（同一 SSN，对照 stub 位置变体）── */
    if (ssn) {
        LPVOID mem = NULL; SIZE_T sz = 0x1000;
        LONG st = heap_stub_call(ssn, GetCurrentProcess(), &mem, &sz, MEM_COMMIT, PAGE_READWRITE);
        printf("[B] direct syscall（heap stub，用后清零）status=0x%lX mem=%p\n", st, mem);
    }

    /* SSN 解析失败 = 目标函数被 hook 或版本差异：走 Halo's Gate 兜底（见 indirect.c）
     * 或退回 04 先去 hook 再正常调用。 */
    if (!ssn) { printf("[-] SSN 解析失败（函数体前导非标准 stub）——按 NOTES 换 indirect/04 路线\n"); return 2; }
    return 0;
}

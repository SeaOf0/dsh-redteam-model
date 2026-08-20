/* 运行时密钥门禁原理演示（教学实现，零恶意功能）
 *
 * 行为：启动先做纯内存密钥判定（argv[1] 或环境变量 RUN_KEY 的 FNV-1a 哈希与内嵌
 * 期望值比对）——匹配才解密内嵌演示配置并打印；不匹配静默 return 0（无输出、
 * 无文件、无网络）。观察失败路径的系统调用特征是本实验的核心产出。
 *
 * 构建：cc gate.c -o gate  （跨平台纯 C，无平台 API）
 * 正确解锁：RUN_KEY=demo-key-2026 ./gate   或   ./gate demo-key-2026
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* 真实形态中期望密钥哈希是内嵌常量（随符号/字面量混淆层保护），不出现密钥明文；
 * 本演示为可读性用现算对照等价表达 */

static uint64_t fnv1a(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    while (*s) { h ^= (unsigned char)*s++; h *= 1099511628211ULL; }
    return h;
}

/* 内嵌演示配置（单字节 XOR 加密；真实形态中是 C2 地址/回连参数等敏感数据） */
static const unsigned char enc_conf[] = {
    0x39,0x35,0x34,0x3c,0x33,0x3d,0x5a,0x1e,0x1f,0x17,0x15,0x40,0x5a,0x0a,0x08,0x15,
    0x1c,0x13,0x16,0x1f,0x47,0x1e,0x1f,0x17,0x15,0x57,0x19,0x48,0x06,0x09,0x16,0x1f,
    0x1f,0x0a,0x47,0x4b,0x42,0x09,0x06,0x10,0x13,0x0e,0x0e,0x1f,0x08,0x47,0x49,0x09,
    0x06,0x11,0x1f,0x03,0x57,0x1d,0x1b,0x0e,0x1f,0x47,0x0a,0x1b,0x09,0x09,0x1f,0x1e,
    0x70
};
static const unsigned char CONF_KEY = 0x7a;

static void print_conf(void) {
    char buf[sizeof enc_conf + 1];
    for (size_t i = 0; i < sizeof enc_conf; i++) buf[i] = enc_conf[i] ^ CONF_KEY;
    buf[sizeof enc_conf] = '\0';
    printf("%s", buf);
}

int main(int argc, char **argv) {
    /* —— 门禁：纯内存判定，全程零文件/网络/硬件探测系统调用 —— */
    const char *k = NULL;
    if (argc > 1) k = argv[1];
    else { const char *e = getenv("RUN_KEY"); if (e) k = e; }

    /* 密钥不匹配 → 静默干净退场（不报错、不落盘、零后续行为） */
    if (!k || fnv1a(k) != fnv1a("demo-key-2026")) return 0;

    /* —— 门禁通过：此刻敏感配置才进入内存并解密 —— */
    print_conf();
    return 0;
}

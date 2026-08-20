/* 组合前置链演示：反沙箱时钟对表 → 运行时密钥门禁 → 配置解密挂载点（教学骨架，零恶意功能）
 *
 * 链序按实战样本观测还原：先环境门（沙箱里连密钥判定的存在都不暴露）后身份门。
 * 任一门失败 → 静默 exit 0（不报错/不落盘/零后续行为），累积"过干净"形态。
 *
 * 构建：cc gate_chain.c -o gate_chain -lpthread
 *   正常解锁：RUN_KEY=demo-key-2026 ./gate_chain （先过 ~2s 时钟对表）
 *   模拟快进沙箱（自验拒绝路径）：cc -DDEMO_SIM_FASTFORWARD ... ——睡眠线程"被提速"→门禁触发
 * 真实形态对接位：payload_mount() 处对接 lab/05 加载器的解密执行段（载荷自备）。
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#define DEMO_SLEEP_SEC 2        /* 演示用短窗；真实形态为数十秒级 */
#define CLOCK_TOL_MS  200       /* 两时钟流逝偏差容限 */

static uint64_t fnv1a(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    while (*s) { h ^= (unsigned char)*s++; h *= 1099511628211ULL; }
    return h;
}

/* ── 门一：反沙箱——时钟对表 ───────────────────────────────
 * 双时钟交叉验证：睡眠线程真实睡 N 秒，主线程核对 CLOCK_MONOTONIC 与
 * CLOCK_REALTIME 的流逝是否都与 N 一致且互相一致。沙箱"快进睡眠/篡改时间"
 * 会让二者出现不可调和的偏差（单点篡改必然顾此失彼）。 */
static void *sleeper(void *arg) {
#ifdef DEMO_SIM_FASTFORWARD
    /* 模拟被提速的沙箱：声称睡了 N 秒，实际只睡 N/10 —— 双时钟对不上 */
    struct timespec ts = { DEMO_SLEEP_SEC / 10, 0 };
    nanosleep(&ts, NULL);
#else
    struct timespec ts = { DEMO_SLEEP_SEC, 0 };
    nanosleep(&ts, NULL);
#endif
    return arg;
}

static int gate_clock(void) {
    struct timespec m0, r0, m1, r1;
    clock_gettime(CLOCK_MONOTONIC, &m0);
    clock_gettime(CLOCK_REALTIME, &r0);
    pthread_t th; pthread_create(&th, NULL, sleeper, NULL);
    pthread_join(th, NULL);
    clock_gettime(CLOCK_MONOTONIC, &m1);
    clock_gettime(CLOCK_REALTIME, &r1);
    long mono_ms = (m1.tv_sec - m0.tv_sec) * 1000L + (m1.tv_nsec - m0.tv_nsec) / 1000000L;
    long real_ms = (r1.tv_sec - r0.tv_sec) * 1000L + (r1.tv_nsec - r0.tv_nsec) / 1000000L;
    long want_ms = DEMO_SLEEP_SEC * 1000L;
    if (labs(mono_ms - want_ms) > CLOCK_TOL_MS) return 0;   /* 睡眠被跳过/缩水 */
    if (labs(real_ms - want_ms) > CLOCK_TOL_MS) return 0;
    if (labs(mono_ms - real_ms) > CLOCK_TOL_MS) return 0;   /* 双时钟互斥 → 单点篡改 */
    return 1;
}

/* ── 门二：运行时密钥门禁（纯内存，零系统调用） ─────────────── */
static int gate_key(int argc, char **argv) {
    const char *k = NULL;
    if (argc > 1) k = argv[1];
    else { const char *e = getenv("RUN_KEY"); if (e) k = e; }
    /* 真实形态为内嵌哈希常量（随混淆层保护），演示用现算对照等价表达 */
    return k && fnv1a(k) == fnv1a("demo-key-2026");
}

/* ── 挂载点：两门全过才走到这里——此刻敏感数据才进入内存 ─────────
 * 演示载荷=打印解密配置；真实形态此处对接 lab/05 的解密执行段。 */
static const unsigned char enc_conf[] = {
    0x39,0x35,0x34,0x3c,0x33,0x3d,0x5a,0x1e,0x1f,0x17,0x15,0x40,0x5a,0x0a,0x08,0x15,
    0x1c,0x13,0x16,0x1f,0x47,0x1e,0x1f,0x17,0x15,0x57,0x19,0x48,0x06,0x09,0x16,0x1f,
    0x1f,0x0a,0x47,0x4b,0x42,0x09,0x06,0x10,0x13,0x0e,0x0e,0x1f,0x08,0x47,0x49,0x09,
    0x06,0x11,0x1f,0x03,0x57,0x1d,0x1b,0x0e,0x1f,0x47,0x0a,0x1b,0x09,0x09,0x1f,0x1e,
    0x70
};
static const unsigned char CONF_KEY = 0x7a;

static void payload_mount(void) {
    char buf[sizeof enc_conf + 1];
    for (size_t i = 0; i < sizeof enc_conf; i++) buf[i] = enc_conf[i] ^ CONF_KEY;
    buf[sizeof enc_conf] = '\0';
    printf("%s", buf);
}

int main(int argc, char **argv) {
    if (!gate_clock()) return 0;   /* 环境门失败：静默退场，密钥判定未发生 */
    if (!gate_key(argc, argv)) return 0; /* 身份门失败：解密从未发生 */
    payload_mount();
    return 0;
}

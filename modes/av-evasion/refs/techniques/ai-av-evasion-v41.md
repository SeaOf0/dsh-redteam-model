---
name: ai-av-evasion-optimized
description: 使用AI生成免杀Loader和处理Shellcode，结合IPv4混淆、XOR加密、Module Stomping等免杀技术绕过主流杀软检测
version: 4.1
date: 2026-07-07
status: Module Stomping版
---

# AI免杀技术套件 — Module Stomping 版

## 功能描述

本Skill提供完整的免杀解决方案，包括Shellcode处理和Loader编写，利用AI生成高免杀效果的恶意代码载体，绕过主流杀软和EDR检测。

**核心能力：**
- ✅ **Module Stomping**：加载合法微软签名DLL，覆写其 `.text` 段作为执行内存
- ✅ **WriteProcessMemory 写入**：内核态完成保护属性修改，无显式 VirtualProtect 权限翻转
- ✅ **HeapAlloc 解密缓冲**：使用堆分配而非 VirtualAlloc，行为与正常应用一致
- ✅ **直接函数指针调用**：无 CreateFiber（避免 PAGE_GUARD），无回调API
- ✅ **零系统指纹**：不调用 GetUserNameW / GetComputerName 等信息收集API
- ✅ **零反VM检测**：不查CPU核数、内存大小、VM进程、时间加速
- ✅ **零ETW操作**：不碰 EtwEventWrite（Patch本身也是行为特征）
- ✅ **手动IPv4解析**：不用 sscanf，减少 CRT 导入特征
- ✅ **调用栈干净**：执行地址位于微软签名DLL内，栈回溯显示合法模块
- ✅ **SecureZeroMemory**：堆解密后立即擦除明文
- ✅ **IPv4地址混淆**：将Shellcode伪装成IPv4地址数组
- ✅ **XOR动态解密**：自定义密钥，加密后数据与随机数据不可区分
- ✅ **DLL分离加载**：Loader不含敏感数据，静态免杀更优
- ✅ **无窗口静默**：-mwindows 编译为GUI程序

## 使用场景

当需要：
- 生成免杀的恶意代码载体（CTF比赛/授权渗透测试）
- 处理Shellcode以逃避检测
- 编写具有反检测能力的Loader
- 进行授权的安全测试和渗透评估

## 核心技术

### 1. Shellcode处理流程

#### 步骤1: Shellcode Patch
- **同义指令替换**：扫描已知等价指令模式进行替换（如 `test rax,rax` → `or rax,rax`），不改变指令长度和语义，仅改变字节特征
- **保守策略**：只替换同长度的等价指令，避免破坏相对跳转偏移
- **无匹配警告**：若未匹配到任何已知模式，输出提示信息

**脚本：scripts/shellcode-patch.py**

#### 步骤2: Shellcode加密
- **XOR加密**：使用自定义密钥对Shellcode进行异或加密
- **密钥长度自适应**：支持任意长度密钥（不可为空）
- **零特征**：加密后数据与随机数据不可区分

**脚本：scripts/shellcode-encrypt.py**

#### 步骤3: Shellcode混淆（IPv4方案）
- **编码伪装**：将Shellcode伪装成IPv4地址数组
- **无字节序问题**：直接按字节顺序转换
- **高熵隐藏**：数百个IP地址，静态扫描呈现为网络配置数据

**脚本：scripts/shellcode-obfuscate-ipv4.py**

### 2. Loader架构

#### 2.1 Module Stomping 原理

```
本方案:  LoadLibrary(签名DLL) → 解析PE找.text
         → WriteProcessMemory(Shellcode→DLL.text) → FlushInstructionCache
         → 直接函数指针调用执行
         ↓ 隐匿: DLL内存有合法文件映射 + 微软签名
         ↓ WriteProcessMemory 在内核态完成保护属性修改, 无显式 VirtualProtect
```

#### 2.2 执行流程

```
main()
  │
  ├─[1] LoadLibraryA("helper.dll")    ← 加载Payload DLL
  ├─[2] GetPayloadData/Size/Key()    ← 获取IPv4数组+密钥
  │
  ├─[3] HeapAlloc(GetProcessHeap())  ← 堆分配 (非VirtualAlloc)
  ├─[4] deobfuscate_ipv4()           ← 手动IPv4解析 (无sscanf)
  ├─[5] xor_decrypt()                ← XOR解密
  ├─[6] FreeLibrary(payload_dll)     ← 释放DLL
  │
  ├─[7] LoadLibraryA("msimg32.dll")  ← 加载合法签名DLL
  ├─[8] FindTextSection(hMod)        ← 解析PE找.text段
  │
  ├─[9] WriteProcessMemory(.text)    ← 内核态写入 (无显式VirtualProtect)
  ├─[10] FlushInstructionCache()     ← 刷新指令缓存
  │
  ├─[11] SecureZeroMemory(decBuf)    ← 擦除堆中明文
  ├─[12] HeapFree(decBuf)            ← 释放堆
  │
  └─[13] 函数指针调用(.text)          ← 直接调用执行 (无Fiber, 无回调)
```

#### 2.3 关键特性

| 维度 | 实现方式 |
|------|----------|
| 执行内存来源 | 签名DLL的 .text 段（Module Stomping） |
| 代码写入方式 | WriteProcessMemory（内核态修改保护属性，无显式 VirtualProtect） |
| 解密缓冲区 | HeapAlloc（堆分配） |
| 执行方式 | 直接函数指针调用（无 Fiber，无回调） |
| 系统信息查询 | 零查询 |
| IPv4解析 | 手动解析（零CRT导入） |
| 执行地址栈回溯 | msimg32.dll!text（合法模块） |
| 导入DLL | 仅 KERNEL32 + msvcrt |
| 内存清理 | SecureZeroMemory + HeapFree |

#### 2.4 DLL回退链

Loader在加载签名DLL时按顺序尝试，确保可用性：

```
msimg32.dll  →  dcomp.dll  →  dwmapi.dll
```

每个DLL加载后检查 `.text` 段大小是否足够容纳Shellcode，不足则释放后尝试下一个。

### 3. 编译

```bash
# 步骤1: 编译Payload DLL
gcc -shared -o helper.dll payload_dll.c -s

# 步骤2: 编译Loader（零额外依赖）
gcc -mwindows -o loader_v4.exe loader_v4.c -s
```

| 参数 | 说明 |
|------|------|
| `-shared` | 编译为 DLL |
| `-mwindows` | GUI 程序，无控制台窗口 |
| `-s` | 去除符号表，减小体积 |

**零额外链接库**：不需要 `-lpsapi`，不依赖任何额外静态库。

## 使用指南

### 完整流水线

```bash
# === Phase 1-3: Shellcode处理 ===
cd scripts/
python shellcode-patch.py shellcode_raw.bin
python shellcode-encrypt.py shellcode_patched.bin "X9kLm3qR7vW2"
python shellcode-obfuscate-ipv4.py shellcode_encrypted.bin

# === Phase 4: 生成Payload DLL ===
# 将 shellcode_obfuscated_ipv4.c 中的IPv4数组复制到 payload_dll.c
# 确认密钥一致
gcc -shared -o helper.dll payload_dll.c -s

# === Phase 5: 编译Loader ===
gcc -mwindows -o loader_v4.exe loader_v4.c -s

# === 部署 ===
# loader_v4.exe + helper.dll 同目录
```

## 文件清单

### Shellcode处理脚本
- `scripts/shellcode-patch.py` — Shellcode字节特征修改工具
- `scripts/shellcode-encrypt.py` — Shellcode XOR加密工具
- `scripts/shellcode-obfuscate-ipv4.py` — IPv4地址混淆工具

### Loader模板
- `scripts/loader_v4.c` — Module Stomping版Loader
- `scripts/payload_dll.c` — Payload DLL模板

## 注意事项

1. **合法性**：本工具仅用于授权的安全测试、CTF比赛和渗透评估
2. **DLL命名**：避免使用 `payload.dll`、`shellcode.dll` 等敏感名称
3. **密钥管理**：建议使用高强度随机密钥，密钥不可为空
4. **时效性**：免杀技术会随杀软更新失效，需定期更新策略
5. **测试验证**：每次使用前应在目标环境等效的测试环境中验证
6. **Module Stomping**：若 `msimg32.dll` 不可用，Loader自动回退到其他DLL

---

**最后更新：2026-07-07**
**当前版本：v4.1 — Module Stomping版**
**测试环境：Windows 10/11 Pro x64**

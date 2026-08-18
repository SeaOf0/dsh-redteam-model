---
name: ai-av-evasion-optimized
description: 使用AI生成免杀Loader和处理Shellcode，结合IPv4混淆、XOR加密、Module Stomping等免杀技术绕过主流杀软检测
version: 4.0
date: 2026-06-26
status: 已升级 — Module Stomping版
---

# AI免杀技术套件 v4.0 — Module Stomping 版

## 功能描述

本Skill提供完整的免杀解决方案，包括Shellcode处理和Loader编写，利用AI生成高免杀效果的恶意代码载体，绕过主流杀软和EDR检测。

**v4.0 核心升级（针对行为分析检出）：**
- ✅ **Module Stomping**：零 VirtualAlloc 执行内存 — 加载合法微软签名DLL，覆写其 `.text` 段
- ✅ **HeapAlloc 替代 VirtualAlloc**：解密缓冲区使用堆分配，看起来像正常应用行为
- ✅ **零系统指纹**：移除所有 GetUserNameW / GetComputerName 等调用
- ✅ **零反VM检测**：不查CPU核数、内存大小、VM进程、时间加速
- ✅ **零ETW操作**：不碰 EtwEventWrite（Patch本身也是行为特征）
- ✅ **手动IPv4解析**：不用 sscanf，减少 CRT 导入特征
- ✅ **Fiber + 回调双路径**：CreateFiber 主线 + EnumSystemLocalesW 备用
- ✅ **调用栈干净**：执行地址位于微软签名DLL内，栈回溯显示合法模块
- ✅ **SecureZeroMemory**：堆解密后立即擦除明文

**v3.0 → v4.0 检出对比：**

| 被检出的行为 (v3.0) | v4.0 对策 |
|---------------------|-----------|
| VirtualAlloc(RW) + VirtualProtect(RX) → 匿名内存被标记 | Module Stomping：VirtualProtect 作用于签名DLL内存 |
| GetUserNameW → "收集系统指纹" | 完全移除，零系统信息查询 |
| Dropper.389 签名 | HeapAlloc + 签名DLL覆写，彻底改变行为链 |
| 枚举UI语言列表 | 改用 EnumSystemLocalesW（更冷门） |

**v2.x 保留功能：**
- ✅ IPv4地址混淆
- ✅ XOR动态解密
- ✅ DLL分离加载（静态免杀）
- ✅ 无窗口静默运行

## 使用场景

当需要：
- 生成免杀的恶意代码载体（CTF比赛/授权渗透测试）
- 处理Shellcode以逃避检测
- 编写具有反检测能力的Loader
- 进行授权的安全测试和渗透评估

## 核心技术

### 1. Shellcode处理流程

#### 步骤1: Shellcode Patch
- **同义指令替换**：识别并替换汇编指令，如`mov rax,0` → `xor rax,rax`
- **花指令注入**：添加无意义的指令和跳转，破坏特征码
- **指令重排**：调整指令顺序，保持功能不变但改变特征

**脚本：scripts/shellcode-patch.py**

#### 步骤2: Shellcode加密
- **XOR加密**：使用自定义密钥对Shellcode进行异或加密
- **密钥长度自适应**：支持任意长度密钥
- **零特征**：加密后数据与随机数据不可区分

**脚本：scripts/shellcode-encrypt.py**

#### 步骤3: Shellcode混淆（IPv4方案）
- **编码伪装**：将Shellcode伪装成IPv4地址数组
- **无字节序问题**：直接按字节顺序转换
- **高熵隐藏**：347+ IP地址，静态扫描呈现为网络配置数据

**脚本：scripts/shellcode-obfuscate-ipv4.py**

### 2. Loader v4.0 架构

#### 2.1 Module Stomping 原理

```
传统方案:  VirtualAlloc(匿名RW) → 写Shellcode → VirtualProtect(RX) → 执行
           ↓ 被检出: 匿名内存 + 权限翻转 = 行为特征

v4.0方案:  LoadLibrary(签名DLL) → 解析PE找.text → VirtualProtect(RW)
           → memcpy(Shellcode→DLL.text) → VirtualProtect(RX) → 执行
           ↓ 隐匿: DLL内存有合法文件映射 + 微软签名
```

#### 2.2 执行流程

```
main()
  │
  ├─[1] LoadLibraryA("helper.dll")    ← 加载Payload DLL
  ├─[2] GetPayloadData/Size/Key()    ← 获取IPv4数组+密钥
  │
  ├─[3] HeapAlloc(GetProcessHeap())  ← 堆分配 (非VirtualAlloc!)
  ├─[4] deobfuscate_ipv4()           ← 手动IPv4解析 (无sscanf)
  ├─[5] xor_decrypt()               ← XOR解密
  ├─[6] FreeLibrary(payload_dll)    ← 释放DLL
  │
  ├─[7] LoadLibraryA("msimg32.dll") ← 加载合法签名DLL
  ├─[8] FindTextSection(hMod)       ← 解析PE找.text段
  │
  ├─[9] VirtualProtect(.text, RW)   ← DLL .text改为可写
  ├─[10] memcpy(.text, shellcode)   ← 覆写.text为shellcode
  ├─[11] VirtualProtect(.text, RX)  ← 翻转为可执行 (作用于签名DLL内存!)
  │
  ├─[12] SecureZeroMemory(decBuf)   ← 擦除堆中明文
  ├─[13] HeapFree(decBuf)           ← 释放堆
  │
  ├─[14] CreateFiber(.text)         ← Fiber执行 (主路径)
  └─[15] EnumSystemLocalesW(.text)  ← 回调执行 (备用路径)
```

#### 2.3 关键优势

| 维度 | v3.0 | v4.0 |
|------|------|------|
| 执行内存来源 | VirtualAlloc 匿名页 | 签名DLL的 .text 段 |
| 解密缓冲区 | VirtualAlloc | HeapAlloc (堆) |
| VirtualProtect作用域 | 匿名内存 → 被标记 | 签名DLL内存 → 正常 |
| 系统信息查询 | GetUserNameW (被检出) | 零查询 |
| IPv4解析 | sscanf (msvcrt导入) | 手动解析 (零导入) |
| 执行地址栈回溯 | 匿名内存 → 可疑 | msimg32.dll!text → 合法 |
| 导入DLL数 | 3 (ADVAPI32/KERNEL32/msvcrt) | 2 (KERNEL32/msvcrt) |

### 3. 编译

#### v4.0 Loader编译（Module Stomping）⭐ 推荐

```bash
# 步骤1: 编译Payload DLL
gcc -shared -o helper.dll payload_dll.c -s

# 步骤2: 编译v4.0 Loader（零额外依赖）
gcc -mwindows -o loader_v4.exe loader_v4.c -s
```

#### 各版本编译参数对比

| 项目 | v2.x | v3.0 | v4.0 |
|------|------|------|------|
| 链接库 | `-lpsapi` | 无 | 无 |
| 关键导入 | NtCreateThreadEx | EnumUILanguagesW | CreateFiber |
| 敏感DLL | psapi.dll | ADVAPI32.dll | 仅KERNEL32+msvcrt |
| 文件大小 | ~19KB | ~18KB | ~18KB |

### 4. 行为特征对比（三代演进）

| 行为 | v2.x | v3.0 | v4.0 |
|------|------|------|------|
| 执行内存 | VirtualAlloc RWX | VirtualAlloc RW→RX 匿名 | **Module Stomping** (签名DLL .text) |
| 解密缓冲 | VirtualAlloc | VirtualAlloc | **HeapAlloc** (正常堆) |
| 反VM检测 | 6层显式 | 零显式 | 零显式 |
| 系统指纹 | 无 | GetUserNameW (被检出!) | **零查询** |
| 线程创建 | NtCreateThreadEx | EnumUILanguagesW | **CreateFiber** + EnumSystemLocalesW |
| ETW | 无 | Patch EtwEventWrite | 无 (Patch本身也是特征) |
| 内存清理 | VirtualFree | SecureZeroMemory+VirtualFree | **SecureZeroMemory+HeapFree** |
| IPv4解析 | sscanf | sscanf | **手动解析** |
| 调用栈 | 匿名内存 | 匿名内存 | **msimg32.dll!text** |
| 导入DLL数 | 4 | 3 | **2** |

## 使用指南

### 完整流水线

```bash
# === Phase 1-3: Shellcode处理 (不变) ===
cd scripts/
python shellcode-patch.py shellcode_raw.bin
python shellcode-encrypt.py shellcode_patched.bin "X9kLm3qR7vW2"
python shellcode-obfuscate-ipv4.py shellcode_encrypted.bin

# === Phase 4: 生成Payload DLL ===
# 将 shellcode_obfuscated_ipv4.c 中的IPv4数组复制到 payload_dll.c
# 确认密钥一致
gcc -shared -o helper.dll payload_dll.c -s

# === Phase 5: 编译v3.0 Loader ===
gcc -mwindows -o loader_v3.exe loader_v3.c -s

# === 部署 ===
# loader_v3.exe + helper.dll 同目录
```

## 文件清单

### Shellcode处理脚本（不变）
- `scripts/shellcode-patch.py`
- `scripts/shellcode-encrypt.py`
- `scripts/shellcode-obfuscate-ipv4.py`

### Loader模板
- `scripts/loader_v4.c` - **v4.0 Module Stomping版（推荐）**
- `scripts/loader_v3.c` - v3.0 行为隐匿版（备用）
- `scripts/loader_dll.c` - v2.x DLL分离版（备用）
- `scripts/loader_full.c` - v2.x 数据内嵌版（备用）
- `scripts/payload_dll.c` - Payload DLL模板

## 注意事项

1. **合法性**：本工具仅用于授权的安全测试、CTF比赛和渗透评估
2. **回调限制**：`EnumUILanguagesW` 回调方式要求Shellcode不依赖 `lpReserved` 参数
3. **DLL命名**：避免使用 `payload.dll`、`shellcode.dll` 等敏感名称
4. **时效性**：免杀技术会随杀软更新失效，需定期更新策略
5. **测试验证**：每次使用前应在目标环境等效的测试环境中验证

## 行为隐匿原则总结

```
v2.x 策略: 主动检测沙箱 → 检测到了就退出
         ↓ 问题：检测行为本身就是恶意特征

v3.0 策略: 不检测，不判断，不退出
          + 看起来像正常程序（GetUserNameW / LoadLibrary userenv.dll）
          + 内存操作与正常JIT编译器无异（RW → RX）
          + 使用冷门但合法的API执行代码（EnumUILanguagesW / Fiber）
          + 阻断遥测上报（Patch EtwEventWrite）
          = 行为链上无可疑特征点
```

## 版本历史

**v4.0 (2026-06-26) — Module Stomping版**
- 🔴 移除：VirtualAlloc 执行内存（替换为 Module Stomping 签名DLL覆写）
- 🔴 移除：VirtualAlloc 解密缓冲（替换为 HeapAlloc 堆分配）
- 🔴 移除：GetUserNameW 等系统指纹查询（被检出为"收集系统指纹"）
- 🔴 移除：ETW Patch（Patch行为本身也是检测特征）
- 🔴 移除：sscanf 依赖（替换为手动IPv4解析）
- 🟢 新增：Module Stomping — 覆写 msimg32.dll .text 段
- 🟢 新增：PE头解析（FindTextSection — 定位签名DLL代码段）
- 🟢 新增：HeapAlloc/HeapFree — 正常堆操作替代 VirtualAlloc
- 🟢 新增：EnumSystemLocalesW 备用执行路径
- 🟢 新增：ADVAPI32.dll 依赖完全移除

**v3.0 (2026-06-26) — 行为隐匿版**
- RW→RX 分阶段内存 + 零反VM + ETW绕过 + 回调执行
- ⚠️ 被检出：VirtualProtect匿名内存 + GetUserNameW系统指纹

**v2.1 (2026-04-05)**
- DLL分离加载方案 + 时间延迟检测

**v2.0 (2026-04-04)**
- IPv4混淆替代UUID + 6层反沙箱 + Syscall绕过Hook

**v1.0 (原始)**
- UUID混淆 + 基础反沙箱

---

**最后更新：2026-06-26**
**当前版本：v4.0 — Module Stomping版**
**测试环境：Windows 10/11 Pro x64**

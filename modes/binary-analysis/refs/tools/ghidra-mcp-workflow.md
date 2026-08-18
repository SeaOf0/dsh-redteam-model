# Ghidra headless 脚本 + MCP 联动工作流

> 定位：`ghidra-reverse/references/ghidra-cheatsheet.md` 是快捷键速查（12 行），本篇补**headless 批量分析 + 脚本开发 + MCP 接入**。
> 与 `trends/re-trends-2025-2026.md` 的「agent-on-top-of-decompiler」衔接：Ghidra 产出伪代码，AI 经 MCP 在其上解释/命名/导航。
> 工具按检测制：Ghidra 属补充工具集（官方 zip + JDK），`command -v` 探测 `analyzeHeadless`，缺失走四级兜底。

---

## 1. Ghidra headless（analyzeHeadless）

### 1.1 批量导入 + 自动分析

```bash
# 单文件导入（建项目）
analyzeHeadless <project_dir> <project_name> -import target.exe -overwrite

# 目录批量导入（多样本）
analyzeHeadless <project_dir> <project_name> -import samples/ -overwrite

# 完全 headless（分析完即删项目，不留 GUI 工程）
analyzeHeadless <project_dir> <project_name> \
  -import target.exe -postScript MyScript.java -scriptPath scripts/ -deleteProject
```

参数要点：`-overwrite`（覆盖同名校验）、`-process`（对已导入文件跑脚本）、`-postScript`（分析后脚本）、`-scriptPath`（自定义脚本目录）、`-deleteProject`（用完删项目）。

输出解读：分析完成后目标在 `<project_dir>/<project_name>.gpr` 与 `<project_dir>/<project_name>.rep/`，可被 GUI 打开或继续脚本处理。

### 1.2 常用 headless 场景

```text
1. 批量家族识别：对 N 个样本 headless 分析，脚本 dump 字符串/导入做聚类。
2. 批量反编译：postScript 遍历函数调 DecompInterface，输出伪代码到文件。
3. 脚本化签名/常量扫描：FindCrypt 类逻辑用脚本扫常量，命中即标记。
```

判据：headless 批处理产出结构化结果（函数表/字符串/伪代码 dump），无 GUI 干预。

---

## 2. Ghidra 脚本开发（Jython / Java）

### 2.1 脚本位置与运行

```text
- 内置脚本：<ghidra>/Ghidra/Features/.../ghidra_scripts/
- 自定义脚本放 -scriptPath 目录；脚本头 @category 分类。
- GUI：Window → Script Manager 运行；headless：-postScript 运行。
```

### 2.2 常用 API（Jython，与 Java API 一致）

```python
# @category Analysis
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType

fm = currentProgram.getFunctionManager()
st = currentProgram.getSymbolTable()
lst = currentProgram.getListing()

# 遍历函数（含未命名）
for func in fm.getFunctions(True):
    print(hex(func.getEntryPoint().getOffset()), func.getName())

# 交叉引用：谁引用了地址 0x401000
from ghidra.program.model.symbol import RefType
rm = currentProgram.getReferenceManager()
for ref in rm.getReferencesTo(toAddr(0x401000)):
    print("xref from", ref.getFromAddress())

# 改名（符号恢复：sub_xxx → 语义名）
st.createLabel(toAddr(0x401000), "decrypt_payload", SourceType.USER_DEFINED)

# 注释
lst.setComment(toAddr(0x401000), lst.EOL_COMMENT, "XOR 解密循环")

# 反编译（DecompInterface）
from ghidra.app.decompiler import DecompInterface
decomp = DecompInterface()
decomp.openProgram(currentProgram)
res = decomp.decompileFunction(fm.getFunctionAt(toAddr(0x401000)), 60, monitor)
print(res.getDecompiledFunction().getC())
```

输出解读：脚本批量改名/注释后，反编译伪代码可读性显著提升；xref 输出还原调用关系。

---

## 3. Ghidra MCP server 接入

### 3.1 项目与接入

| 项目 | 定位 | 来源 |
|---|---|---|
| **GhidraMCP（LaurieWired）** | Ghidra 的 MCP server，LLM 驱动 Ghidra（反编译/列表函数/改名/xref） | https://github.com/LaurieWired/GhidraMCP |
| **ReVa（cyberkaida）** | Ghidra MCP（Reverse Engineering Assistant），AI 操作 Ghidra 分析 | https://github.com/cyberkaida/reverse-engineering-assistant |
| **re-mcp（stl3）** | headless IDA + Ghidra 的 MCP（无 GUI 批量） | https://github.com/stl3/re-mcp |

接入要点（DSH 视角）：

```text
1. Ghidra 侧装 MCP 插件/扩展，起 MCP server（stdio/http）。
2. DSH 的 MCP 加载配置注册，工具平面检测到 mcp__<server>__<tool>。
3. 按 playbook「MCP 兜底」层使用（附录 C）。
```

### 3.2 AI 辅助逆向工作流（agent-on-top-of-decompiler）

```text
1. Ghidra 反编译目标函数 → 伪代码。
2. MCP 把伪代码/符号/xref 交给 AI agent。
3. agent 做：解释逻辑 → 命名函数 → 导航 xref → 标注发现。
4. 落地：AI 命名/判断是「待验证假设」，落字节级证据（persona 硬规则）。
```

判据：MCP 往返返回结构化反编译/符号结果，AI 结论与静态/动态证据互证后才采信。

---

## 4. headless + MCP 组合（批量场景）

```text
- 批量样本 → analyzeHeadless 自动分析 + 脚本 dump 初筛结果 → 可疑样本再用 MCP 让 AI 深挖。
- 大文件/无 GUI 环境 → re-mcp 走 headless IDA+Ghidra，无需图形界面。
```

---

## 来源与延伸

- Ghidra 快捷键速查：`ghidra-reverse/references/ghidra-cheatsheet.md`、`ghidra-reverse/SKILL.md`。
- IDA MCP 工具速查（对等参照）：`ida-reverse/references/ida-mcp-cheatsheet.md`。
- IDA/Ghidra MCP + AI 生态：`tools/ida-plugin-ecosystem.md`、`trends/re-trends-2025-2026.md`。
- 符号恢复（脚本批量改名配合）：`methodology/reverse-engineering/references/symbol-recovery.md`。
- GhidraMCP：https://github.com/LaurieWired/GhidraMCP ；ReVa：https://github.com/cyberkaida/reverse-engineering-assistant

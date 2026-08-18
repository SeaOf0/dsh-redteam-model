# Evasion Research & Knowledge Base — 免杀技术研究与知识库构建

> 来源：整合自 Evasion-SubAgents 项目的 `research` skill + 知识库管理方法论。
> 适用：用 GitHub CLI 系统化搜索 evasion/loader/C2 技术，分析代码模式，去重后保存到本地知识库。

## Authorization Context

AUTHORIZED USE CASE: Defensive Security Research / 已授权红队评估 / 安全产品能力测试。

## 1. 工作流总览

```
Step 1: GitHub 搜索（广 → 窄）
Step 2: 仓库分析（读 README、看 commit、看 stars）
Step 3: 模式提取（按 7 类分类）
Step 4: 去重检查
Step 5: 知识库存储
Step 6: 输出摘要
```

## 2. Step 1：GitHub 搜索

### 用 `gh` CLI（不要用 web 搜索，无法批量）

```bash
# 搜仓库（先广后窄）
gh search repos "shellcode loader language:C stars:>20" --limit 20
gh search repos "AMSI bypass" --limit 15
gh search repos "direct syscall" --language c --limit 15

# 搜代码片段
gh search code "VirtualAlloc PAGE_EXECUTE_READWRITE" --language c --limit 30
gh search code "NtAllocateVirtualMemory" --language rust --limit 20
gh search code "EnumWindows callback shellcode" --limit 20
```

### 关键词矩阵

| 方向 | 关键词 |
|------|--------|
| Loader | shellcode loader / shellcode runner / injector |
| Syscall | direct syscall / indirect syscall / Hell's Gate / Halo's Gate / Tartarus' Gate |
| API 隐蔽 | API hashing / dynamic resolve / PEB walk |
| 反调试 | anti-debug / anti-VM / sandbox detect |
| AMSI/ETW | AMSI bypass / ETW bypass / amsiContext |
| Unhooking | ntdll unhook / known DLLs / MapViewOfFile |
| 字符串 | string obfuscation / stack strings / compile-time encrypt |

## 3. Step 2：仓库分析

```bash
# 查看仓库元信息
gh repo view owner/repo

# 列文件结构
gh api repos/owner/repo/contents

# 直接读关键文件
gh api repos/owner/repo/contents/main.c --jq '.content' | base64 -d
gh api repos/owner/repo/contents/loader.go --jq '.content' | base64 -d
```

### 仓库价值判断

| 指标 | 评估 |
|------|------|
| ⭐ Stars > 100 | 通常意味着技术成熟 |
| 📅 6 个月内有 commit | 仍可用 |
| 🛡 已被 AV 厂商针对性检测 | 价值降低（除非做二开） |
| 📚 有详细文档 | 易分析、易整合 |
| 🧪 有测试 PoC | 验证可信 |

## 4. Step 3：模式提取与分类

提取后按 7 大类分类（与 `loader-engineering.md` 一致）：

| Category | Keywords |
|----------|----------|
| **Memory Allocation** | VirtualAlloc, HeapCreate, NtAllocateVirtualMemory, MappedFile |
| **Code Execution** | CreateThread, EnumWindows, APC, Fiber, callback |
| **API Obfuscation** | API hashing, PEB walk, GetProcAddress, dynamic resolve |
| **String Obfuscation** | XOR, AES, stack strings, compile-time encryption |
| **Anti-Analysis** | IsDebuggerPresent, CheckRemoteDebugger, anti-VM, sandbox |
| **Syscall** | direct syscall, indirect syscall, SSN, Hell's Gate |
| **AMSI/ETW** | amsi.dll patch, EtwEventWrite patch |

## 5. Step 4：去重检查

**关键**：避免知识库膨胀。每次添加前必须去重。

### 去重决策表

| 情况 | 动作 |
|------|------|
| 名字完全相同 | **SKIP**（重复） |
| 同技术不同名 | **SKIP**（重复） |
| 同目标不同实现 | **ADD**（都有用） |
| 不同目标相似 API | **ADD**（不同用途） |
| 同来源同方法 | **SKIP** |
| 同来源不同方法 | **ADD**（变体） |

```bash
# 调用 dedup-check
python lib/knowledge_manager.py dedup-check \
  --name "Direct Syscall via Hell's Gate" \
  --type "execution_evasion" \
  --description "..." \
  --apis "NtAllocateVirtualMemory"
# 输出 SKIP / ADD
```

## 6. Step 5：知识库存储

### 知识库结构

```
knowledge-base/
├── evasion_techniques.json     # 172 项 evasion 技术
│   └── techniques: [{ id, name, type, description, complexity, source, apis, code_template }]
├── loader_techniques.json      # loader 组件库
│   ├── techniques: []          # 已生成的组合
│   └── component_library:      # 85 个组件
│       ├── storage_methods (15)
│       ├── memory_allocators (14)
│       ├── data_copiers (9)
│       └── executors (47)
└── scenarios.json              # 25 个验证场景
```

### 添加 evasion 技术

```bash
python lib/knowledge_manager.py add-evasion \
  --name "API Hashing via PEB Walk" \
  --type "api_obfuscation" \
  --description "通过 PEB → InLoadOrderModuleList 遍历获取 ntdll，hash 比较定位 API" \
  --code-template "// code here" \
  --apis "LdrLoadDll, RtlInitUnicodeString" \
  --complexity "medium"
```

### 添加 loader 组件

```bash
# 新的 allocator
python lib/knowledge_manager.py add-loader-technique \
  --storage embedded \
  --allocator "NtAllocateVirtualMemoryEx" \
  --copier memcpy \
  --executor callback
```

### 添加场景

```bash
python lib/knowledge_manager.py add-scenario \
  --name "Loader 026" \
  --storage embedded \
  --allocator HeapCreate \
  --copier RtlMoveMemory \
  --executor callback \
  --status validated
```

## 7. Step 6：输出摘要

每次 research 完成后给出：

1. **Techniques Found**：列表 + 简述
2. **Complexity Assessment**：simple / medium / complex
3. **Knowledge Base Status**：NEW / DUPLICATE / VARIATION
4. **References**：GitHub URL 列表

## 8. Bash 命令规范

### ❌ 错误用法

```bash
# 输出重定向会拖慢审批
gh search repos "query" 2>/dev/null

# cd 组合命令不便携
cd "/some/path" && python lib/knowledge_manager.py add-evasion
```

### ✅ 正确用法

```bash
# 不重定向
gh search repos "shellcode loader"

# 用相对路径
python lib/knowledge_manager.py add-evasion --name "..."
```

## 9. 持续维护

### 月度更新

```bash
# 看最近 30 天 stars > 10 的新仓库
gh search repos "shellcode loader created:>2026-05-14 stars:>10" --limit 30

# 找新技术变体
gh search code "indirect syscall" --language c --limit 50
```

### 知识库版本控制

`evasion_techniques.json` 含 `version` 和 `last_updated` 字段。每次更新后 bump version，写入更新日志。

## 10. 关键规则

1. **永远检查重复**再添加（用 dedup-check）
2. **保存所有发现**到知识库（即使当前用不上）
3. **每个技术必须有 code_template**（不能只描述）
4. **来源 URL 必须记录**（追溯可信度）
5. **不要用 `>/dev/null` 或 `cd &&`** 组合命令
6. **避免下载整个仓库** — 用 `gh api` 直接读关键文件

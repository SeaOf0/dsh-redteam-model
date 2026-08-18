# C2 Source-Level Evasion — C2 框架源码级免杀

> 来源：整合自 Evasion-SubAgents 项目的 `c2_evasion` skill。
> 适用：分析开源 C2 框架（Havoc / Sliver / Covenant / Mythic 等）的源码，识别 YARA/Sigma/Snort 检测规则，修改源码规避。

## Authorization Context

AUTHORIZED USE CASE: Defensive Security Research / 已授权红队评估 / 安全产品能力测试。

## 1. 工作流总览

```
Phase 1: 识别 C2 组件
    └─ 找 implant/beacon/agent 目录
Phase 2: 检测规则搜集
    └─ 搜 YARA / Sigma / Snort / Suricata 规则
Phase 3: 逐规则分析
    ├─ 解析所有 pattern（$s1, $a1, hex pattern）
    └─ 找到每个 pattern 对应的源码位置
Phase 3.5: Hex 模式分析
    └─ 函数序言 / 配置结构 / 编译特征
Phase 3.6: 二进制资产分析
    └─ shellcode / resource / 配置文件
Phase 3.7: 字符串主动搜索
    └─ 提前发现可能触发的敏感字符串
Phase 4: 源码修改
    └─ 按"编译器 flags → 源码改动 → 函数重命名"优先级
Phase 5: 验证
    └─ 所有 pattern 应不再匹配
Phase 6: 文档化
    └─ 输出 modifications_summary.md
```

## 2. 优先级框架（关键）

| 优先级 | 组件 | 动作 |
|--------|------|------|
| 1（最高）| Implant / Beacon / Agent | 修改（编译进 victim 的部分） |
| 2 | 网络暴露（server 端口/协议特征） | 修改 |
| 3 | Server 内部字符串 | 跳过（不出现在 victim 侧） |

## 3. Phase 1：识别 C2 组件

```bash
# 探查目录结构
ls -la <c2_root>
find <c2_root> -name "*.c" -o -name "*.go" -o -name "*.rs" -o -name "*.py"

# 常见 implant 目录命名
# agent/ beacon/ implant/ client/ src_beacon/ src_gopher/
```

## 4. Phase 2：检测规则搜集

### YARA 规则

```bash
# Awesome YARA
git clone https://github.com/InQuest/awesome-yara

# 搜索针对目标 C2 的规则
grep -rn "rule.*havoc\|rule.*sliver\|rule.*cobaltstrike" awesome-yara/

# YARAHQ 等
git clone https://github.com/Yara-Rules/rules.git
```

### Sigma 规则

```bash
# SigmaHQ
git clone https://github.com/SigmaHQ/sigma.git

# 搜索 C2 行为规则
grep -rn "title.*Havoc\|title.*Sliver" sigma/
```

### 网络规则（Snort/Suricata）

```bash
# ET Open Pro
grep -i "havoc\|sliver\|cobalt" emerging-all.rules
```

## 5. Phase 3：逐规则分析（CRITICAL）

**每一条 YARA/Sigma 规则都必须有 evasion 计划，不能跳过。**

### 决策矩阵

| Pattern 类型 | 编译器 flag 够吗 | 源码改动 | 两者都需要 |
|-------------|-----------------|----------|-----------|
| 函数序言（function prologue）| ✅ 通常够 | ✅ 备选 | 罕见 |
| 字符串字节 | ❌ 无效 | ✅ 必须 | N/A |
| API 调用序列 | ⚠️ 可能 | ✅ 必须 | 有时 |
| 配置结构体 | ❌ 无效 | ✅ 必须 | N/A |

### 优先级排序

1. **优先级 1**：编译器 flags（成本最低，影响最大）
2. **优先级 2**：构建配置修改
3. **优先级 3**：源码修改
4. **优先级 4**：函数/结构体重构

## 6. Phase 4：源码修改模式

### 字符串混淆

```c
// Before
char* header = "BeaconOutput";

// After
char header[] = { 0x07, 0x02, ..., 0x00 };  // XOR encrypted
// 运行时 decrypt
```

### 函数重命名（Go 项目常见）

```go
// Before
func taskProcess(...) { }

// After
func cmdProc(...) { }
```

### Makefile 优化（消除编译器特征）

```makefile
CFLAGS += -O2 -fno-stack-protector -fno-ident -fomit-frame-pointer
LDFLAGS += -Wl,--build-id=none -Wl,--gc-sections -Wl,-s
```

### Go 项目特殊处理（消除 Go 运行时特征）

```bash
# garble（Go 混淆器）
garble -litter build -o agent.exe ./cmd/agent

# 修改 Go 编译参数
go build -ldflags="-s -w -buildid=" -trimpath ./cmd/agent
```

### Rust 项目

```toml
# Cargo.toml
[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

## 7. Phase 5：验证

```bash
# 验证敏感 pattern 已全部消除
grep -rn "BeaconOutput" <c2_root>  # 应无输出
grep -rn "taskProcess" <c2_root>   # 应无输出

# 用 yara 实际扫描二进制
yara -r rules/havoc.yar output/agent.exe
```

## 8. Phase 6：文档化

输出 `rules/<c2_name>/modifications_summary.md`：

```markdown
# C2 Evasion Report

## C2 Framework: <name>
## Rules Analyzed: X YARA, Y Sigma, Z Network

## Binary Assets Analyzed
| Asset | Type | Risk | Action |
|-------|------|------|--------|
| shellcode.bin | Raw | HIGH | Encrypted |

## Hex Pattern Analysis
| Pattern | Type | Evasion Method | Status |
|---------|------|----------------|--------|
| { 48 83 EC 58 } | Prologue | Reduced locals | Evaded |

## String Modifications
| Pattern | File | Modification | Status |
|---------|------|--------------|--------|
| "BeaconOutput" | http.go:78 | XOR encrypt | Evaded |

## Detection Risk: Low/Medium/High
```

## 9. 输出目录结构

```
./rules/<c2_name>/
├── yara/                    # 搜集到的 YARA 规则
├── sigma/                   # 搜集到的 Sigma 规则
├── network/                 # 网络规则
├── rule_analysis/           # 逐规则分析
│   └── <rule_name>.md
├── binary_assets/           # 二进制资产分析
│   └── analysis.md
├── hex_analysis.md          # hex 模式分析
└── modifications_summary.md # 最终报告
```

## 10. 关键规则

1. **绝不跳过任何规则** — 每条 YARA/Sigma 都要有分析
2. **永远先尝试编译器 flags** — 成本最低
3. **只修改用户指定目录**内的代码
4. **必须分析 hex 模式**（不只看字符串）
5. **必须检查 Makefile/build.go/Cargo.toml**
6. **必须检查二进制资产**（shellcode/resource/配置文件）
7. **绝不测试/运行**修改后的二进制
8. **所有改动都要记录原因**

## 11. 常见 C2 框架关键检测点（参考）

| C2 框架 | 常见检测点 | evasion 方向 |
|---------|----------|--------------|
| Cobalt Strike | Beacon 配置结构、`ReflectiveLoader` 字符串、内置 default cert | 配置加密、字符串混淆、自定义 loader |
| Havoc | agent 函数命名、built-in sleep jitter 特征 | garble 混淆、函数重命名 |
| Sliver | Go runtime 特征、implant 配置结构 | garble -litter、trimpath |
| Mythic | agent 模板特征、payload format | 自定义 agent 模板 |
| Covenant | .NET 反射特征、内置 ASCII art | 编译模式、字符串混淆 |

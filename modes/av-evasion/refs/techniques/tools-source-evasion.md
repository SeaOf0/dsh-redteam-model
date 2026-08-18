# Tools Source-Level Evasion — 渗透工具源码级免杀

> 来源：整合自 Evasion-SubAgents 项目的 `tools_evasion` skill。
> 适用：分析开源渗透测试工具（fscan/nuclei/nmap NSE/mimikatz/sliver 等），识别 YARA/Sigma 检测规则，修改源码规避。
> 区别于 `c2-source-evasion.md`：本 leaf 针对**单次运行的工具**，C2 是**长期驻留的 agent**。

## Authorization Context

AUTHORIZED USE CASE: Defensive Security Research / 已授权红队评估 / 安全产品能力测试。

## 1. 工作流总览

```
Phase 1: 工具理解
    ├─ 读 README / docs
    ├─ 分析源码结构
    ├─ 识别核心功能
    └─ 判定工具用途与典型使用场景
        ↓
Phase 2: 开源情报收集
    ├─ 判断是否开源
    ├─ 提取关键词（工具名、作者、特色功能）
    └─ GitHub 搜针对该工具的规则
        ↓
Phase 3: 行为分析
    ├─ 提取核心行为模式
    └─ 搜基于行为的规则
        ↓
Phase 4: 规则归档
    └─ 保存到 rules/{tool_name}/
        ↓
Phase 5: 逐规则分析
    ├─ 解析每条规则 pattern
    ├─ 在源码中定位 pattern 来源
    └─ 制定 evasion 策略
        ↓
Phase 6: 源码修改
    └─ 确保功能保留
        ↓
Phase 7: 验证 + 总结
```

## 2. Phase 1：工具理解

### Step 1.1：读文档

```bash
ls -la <tool_path>
cat <tool_path>/README.md
cat <tool_path>/docs/*.md
```

### Step 1.2：分析源码结构

```bash
# 识别编程语言
find <tool_path> -name "*.go" -o -name "*.c" -o -name "*.py" -o -name "*.rs" -o -name "*.cs"

# 检查构建文件
ls <tool_path>/Makefile <tool_path>/CMakeLists.txt <tool_path>/go.mod <tool_path>/Cargo.toml <tool_path>/*.csproj

# 列主目录
ls -la <tool_path>/
```

### Step 1.3：识别核心功能

```bash
# Go：找 main 包
find <tool_path> -name "main.go"

# Python：找入口
find <tool_path> -name "__main__.py" -o -name "main.py"

# C/C++：找 main 函数
grep -rn "int main" <tool_path>
```

## 3. Phase 2：开源情报收集

### 提取关键词

| 来源 | 关键词类型 |
|------|-----------|
| README | 工具名、功能描述、特色技术 |
| 作者主页 | 作者名、组织 |
| 二进制 | 内置 ASCII art、版本字符串 |
| 命令参数 | `-h` `--help` 输出中的常量 |

### GitHub 搜检测规则

```bash
# 搜工具名相关的 YARA 规则
gh search code "rule.*<tool_name>" --extension yar

# 搜 Sigma 规则
gh search code "title.*<tool_name>" --extension yml

# 搜 Suricata/Snort 规则
gh search code "<tool_name>" --extension rules
```

## 4. Phase 3：行为分析

### 提取行为模式

| 行为类别 | 检测特征 |
|---------|---------|
| **网络扫描** | 高频 TCP SYN、特定端口序列 |
| **登录爆破** | 多次失败登录、特定 UA |
| **密码转储** | lsass.exe 句柄、reg save 操作 |
| **横向移动** | WMI/SMB 远程执行模式 |
| **凭据传递** | Pass-the-Hash 的特定 LogonProcessName |

### 搜行为规则

```bash
# SigmaHQ 行为规则
grep -rn "title.*<tool_name>" sigma/

# ELK 检测规则
gh search code "<tool_name>" --extension json
```

## 5. Phase 4：规则归档

```
rules/{tool_name}/
├── yara/
│   ├── tool_signature.yar
│   └── behavior_pattern.yar
├── sigma/
│   └── process_creation.yml
├── network/
│   └── snort.rules
└── detection_summary.md
```

## 6. Phase 5：逐规则分析（CRITICAL）

对每条规则：

1. **解析所有 pattern** — `$s1, $a1, hex pattern, condition`
2. **定位 pattern 源头** — 在源码哪里生成的
3. **制定 evasion 策略**（按优先级）：
   - **P1**：编译器 flags（`-O2 -fno-ident -Wl,--build-id=none`）
   - **P2**：构建配置（`go build -ldflags="-s -w -trimpath"`）
   - **P3**：源码字符串混淆
   - **P4**：函数/变量重命名

### 决策矩阵

| Pattern 类型 | 编译器 flag | 源码改动 |
|-------------|------------|----------|
| 函数序言 | ✅ 通常够 | ✅ 备选 |
| 字符串字面量 | ❌ 无效 | ✅ 必须 |
| API 调用序列 | ⚠️ 部分 | ✅ 通常需要 |
| 命令行参数 | ❌ 无效 | ✅ 必须（重命名 flag） |
| 默认 UA | ❌ 无效 | ✅ 必须 |

## 7. Phase 6：源码修改模式

### 字符串混淆（消除工具名）

```go
// Before
const ToolName = "fscan"
fmt.Printf("[*] %s v%s\n", ToolName, version)

// After
var toolName = []byte{0x66, 0x73, 0x63, 0x61, 0x6e}  // "fscan" XOR'd
// 运行时解密
```

### 命令行 flag 重命名

```go
// Before
flag.String("target", "", "target IP/CIDR")

// After
flag.String("t", "", "t")
```

### Go 编译参数

```bash
go build -ldflags="-s -w -trimpath -X main.version=" -o tool.exe
# -s -w: 去除符号表和 DWARF
# -trimpath: 去除本地路径
# -X: 覆盖版本字符串

# 进阶：garble 混淆
garble -litter build -o tool.exe
```

### Rust 编译参数

```toml
# Cargo.toml
[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

### Python（py2exe/PyInstaller）

```bash
# PyInstaller 编译时排除 signatures
pyinstaller --onefile --noconfirm --clean \
    --exclude-module pyinstaller \
    --add-data "icon.ico;." \
    tool.py

# 重命名 entry point 文件，避免 PyInstaller 默认特征
```

## 8. Phase 7：验证 + 总结

### 验证

```bash
# 字符串检查
strings tool.exe | grep -i "<tool_name>"  # 应无输出

# YARA 扫描
yara -r rules/<tool_name>.yar tool.exe

# 行为测试（在隔离环境）
strace -f -e trace=network ./tool.exe 2>&1 | head -20
```

### 总结报告

```markdown
# Tools Evasion Report: <tool_name>

## Source Version: <commit_hash>
## Rules Analyzed: X YARA, Y Sigma

## Modifications Summary
| Pattern | File | Modification | Status |
|---------|------|--------------|--------|
| "fscan" string | main.go:42 | XOR encrypt | Evaded |
| Version banner | banner.go:10 | Removed | Evaded |
| Default UA | http.go:88 | Random UA | Evaded |

## Unevadable Items
| Pattern | Reason |
|---------|--------|
| API call sequence | Functionality required |

## Detection Risk: Low/Medium/High
```

## 9. 工具类别参考

| 工具类别 | 代表 | 主要检测点 |
|---------|------|-----------|
| **网络扫描** | nmap / masscan / zmap | 端口序列、TCP fingerprint |
| **Web 扫描** | nuclei / xray / goby | UA、payload 模板特征 |
| **综合扫描** | fscan / kscan / laser | 字符串 banner、内置 PoC |
| **凭据工具** | mimikatz / sharphound / rubeus | lsass 访问、命令参数 |
| **C2 / 横向** | smbexec / wmiexec / atexec | 命令执行模式、临时文件 |
| **代理 / 隧道** | frp / nps / reGeorg | 协议特征、心跳模式 |

## 10. 关键规则

1. **绝不跳过任何规则** — 每条都要分析
2. **永远先尝试编译器 flags**
3. **保留工具核心功能** — evasion 不能破坏功能
4. **行为类规则**优先考虑"使用合法工具替代"而非改源码（如用 `impacket-wmiexec` 替代自实现）
5. **绝不测试/运行**修改后的二进制（编译成功即可）
6. **Python 工具**优先 PyInstaller 配置而非源码大改

# Android CTF Playbook

目标：在限定时间内高效解题，优先找最短路径而非完整逆向。

## 先回答

- 题目类型（Java crackme / JNI crackme / 多层验证 / VM / OLLVM / 白盒 / 其他）
- flag 格式和校验方式（本地比较 / 远端验证 / 多阶段）
- 是否存在简单编码/异或可以快速绕过
- 逆向难度是否超出时间预算

## 适用场景

- Java crackme
- JNI crackme
- 多层校验
- 字符串解密
- VM/解释器
- OLLVM 混淆
- 白盒密码
- 游戏安全赛题

## 五分钟分诊

1. 搜索 `FLAG{` / `CTF{` / `flag{` / `Key{`（明文 flag）
2. 找主界面或输入入口 Activity
3. 搜索 `check` / `verify` / `isValid` / `validate` / `equals`
4. 判断是否进入 Native（`System.loadLibrary` / `native` 方法）
5. 判断是否存在简单编码或异或（Base64、XOR、简单替换）
6. 检查 `assets` / `res/raw` 中是否有加密数据或隐藏文件

## CTF 题型与解题技术

### Java Crackme

常见验证模式：
- **字符串比较**：`equals()` 或 `compareTo()` 直接比较，反编译即可看到 flag
- **编码转换**：Base64、Hex、URL 编码，解码即得 flag
- **简单加密**：XOR、凯撒密码、简单替换，密钥通常硬编码
- **反调试**：`android.os.Debug.isDebuggerConnected()`，直接 patch 返回 false

解题步骤：
1. 反编译 APK（JADX/JEB）
2. 定位验证方法（搜索入口 Activity → onClick → check/verify）
3. 阅读验证逻辑
4. 如果是简单比较——直接提取 flag
5. 如果涉及计算——理解算法后逆推

### JNI Crackme

常见模式：
- **Native 验证**：Java 层调用 native 方法，验证在 SO 中
- **符号分析**：搜索 `Java_com_*` 导出符号
- **RegisterNatives**：动态注册，需要分析 JNI_OnLoad 找到映射关系

解题步骤：
1. 确认 native 方法名和所在 SO
2. IDA/Ghidra 打开 SO
3. 搜索导出符号或分析 JNI_OnLoad
4. 反编译验证函数
5. 理解算法并逆推 flag

### 多层验证链

特征：
- 多个检查函数串联
- 存在 honeypot 分支（假 flag）
- 动态计算函数地址（运行时才确定调用目标）

解题步骤：
1. 完整追踪所有检查分支
2. 区分真正检查和 honeypot（通常 honeypot 路径更短/更简单）
3. 如果地址动态计算——Frida hook 获取运行时地址
4. 逐层解决，记录每层的中间值

### 自定义 VM / 解释器

特征：
- 方法体被替换为自定义字节码
- 存在 VM 解释器分发器
- 操作码可能被映射或加密

解题策略：
1. 定位 VM 解释器入口
2. 识别 handler 表和操作码映射
3. 提取 VM 字节码
4. 逐条翻译或使用 trace-based 方法
5. 详细方法参考 `references/vmp-analysis-playbook.md`

### OLLVM 混淆题目

常见于较高难度的 JNI crackme：
- FLA：控制流平坦化，使用 D-810 还原
- BR：虚假控制流，Keypatch patch
- 字符串加密：hook 解密函数获取明文

特殊技巧：
- 线程创建 hook：某些 OLLVM 题目在子线程中做验证
- init_array 中的字符串解密：在 `JNI_OnLoad` 前就已经解密

### 白盒密码题目

解题方法：
1. 识别白盒实现（大量查找表）
2. 使用 DFA 差分故障攻击
3. 在 Unidbg 中注入故障，收集正确/错误密文对
4. 使用 phoenixAES 自动恢复密钥
5. 详细方法参考 `references/crypto-protocol-playbook.md` 白盒密码学分析

### xxtea 识别

- 特征常量 `0x9E3779B9`（黄金比例衍生 Delta）
- 搜索这个常量即可确认是否使用 xxtea
- 密钥通常硬编码在 SO 中

### Godot 引擎 CTF

特殊场景：
- 自解密 SO：运行时解密自身代码
- GDExtension：C++ 扩展模块
- 可能使用修改版 ChaCha20 加密
- 需要 hook 解密函数获取明文

Godot 资源解密（PCK 加密场景）：
- PCK 解包 key 在 `PackedSourcePCK::try_open_pack()` 中通过全局指针槽读取
- key 为 32 字节，用于 AES-256-CFB 解密 PCK 目录
- `.gdc` 文件结构：头部 `GDSC` + 版本号 + zstd 压缩的 GDScriptTokenizerBuffer

### VM + 多算法组合 CTF（高难度）

典型结构：自定义 VM 解释器内嵌多种加密算法，需要逐层还原。

解题流程（以腾讯竞赛2026决赛为例）：
1. **VM 结构识别**：32 位固定宽度字节码，4 个 32 位状态字（Feistel 结构），jump table 分发
2. **第一层 — Feistel 加密**：8 轮 Feistel 网络，在 VM 内实现。轮函数特征：左右交换 + F 函数。直接从 VM handler 映射还原
3. **第二层 — 自定义 AES**：AES-128-CBC 变种（S-box / MixColumns 系数可能被修改）。识别方法：GF(2^8) 乘法循环 + 约化常数 `0x1B`
4. **第三层 — TEA 变种**：28 轮 TEA（标准 TEA 为 32 轮），delta 可能修改。特征常量 `0x9E3779B9` 或其变种
5. **密钥恢复**：白盒场景下用 DFA（参考 crypto-protocol-playbook），非白盒场景直接从 VM 字节码提取常量

关键技巧：
- VM 内循环次数 × 单次迭代操作数 = 加密参数推断（如 3×9×4 次迭代 + 16 次 GF 乘法 = AES-128）
- 多算法串联时，从最后执行的算法开始逆推（密文 → 最后一层明文 = 倒数第二层密文）
- 自定义 S-box：与标准 S-box 逐字节对比，确认是否修改

### init_array 运行时字符串修改

某些题目通过 `.init_array` 在 SO 加载时修改全局字符串：
1. 分析 `.init_array` 中的函数
2. 这些函数可能在运行时将加密字符串解密到全局变量
3. 静态分析看到的加密字符串不是最终值
4. 需要运行时 hook 或在 SO 加载后 dump 内存

## 竞赛案例参考

### 52pojie 2025

典型题型：
- Java crackme + 简单编码
- JNI crackme + OLLVM
- 多层验证 + honeypot
- 自定义 VM

### 腾讯游戏安全大赛 2025/2026

典型题型：
- Unity IL2CPP + Lua 热更新
- 游戏协议分析 + protobuf
- 反调试 + 反 Frida + 完整性校验
- 移动游戏安全综合挑战

**2026 趋势**：
- Godot 4.5 引擎成为新考点（PCK 加密 + GDScript VMP + GDExtension 隐藏 + ChaCha20 魔改常量）
- 多层安全组合：自解密 SO + PCK 加密 + GDExtension 隐藏 + xor_enc + 变种 ChaCha20
- APK 重打包作弊版检测（签名校验 + 资源完整性）
- AI 辅助解题趋势（ida-mcp + LLM 直接分析 SO）

## AI 辅助 CTF 解题

**工具组合**：
- `ida-mcp` / `ida-agent-bridge`：将 IDA 分析能力暴露给 LLM，支持反编译、重命名、交叉引用等操作
- LLM（Claude/GPT/Gemini）：接收反编译代码，识别算法模式、建议还原策略

**适用场景**：
- 快速识别加密算法（从常数和结构推断 AES/ChaCha20/TEA 等）
- OLLVM handler 语义识别（将反编译代码发给 LLM 识别操作语义）
- 白盒密码分析辅助（识别 S-box 结构和查表模式）

**局限**：
- LLM 无法直接运行代码或验证结果——必须配合实际执行验证
- 复杂混淆（多层 VMP + 白盒）仍需人工主导，AI 辅助理解局部语义
- 不能盲信 LLM 的算法识别——必须用标准算法对照验证

**SOP**：
1. 分诊阶段：用 LLM 快速识别代码模式（加密/哈希/编码/VM）
2. 定位阶段：用 ida-mcp 获取关键函数的反编译代码
3. 理解阶段：将代码发给 LLM 识别算法和关键参数
4. 验证阶段：编写 solver 脚本验证 LLM 的分析结论

## 游戏安全常见模式

### 速度修改
- Hook 时间相关函数（`System.nanoTime`、`getTickCount`）
- 修改时间增量实现加速/减速

### 内存搜索
- 搜索已知数值（分数、金币、血量）
- 使用 GG Modifier 等工具
- DWord / Float / Double 类型匹配

### 协议操控
- 中间人修改游戏协议
- 重放攻击（需要处理 nonce/时间戳）
- 修改 protobuf 字段值

## Solver 模板扩展

### Java Crackme Solver

```python
# 通用 Java crackme 解题模板
# 1. 反编译获取验证逻辑
# 2. 提取加密参数和密钥
# 3. 逆推 flag

import base64

def solve_xor_cipher(ciphertext, key):
    return bytes([c ^ key[i % len(key)] for i, c in enumerate(ciphertext)])

def solve_simple_substitution(ciphertext, mapping):
    return ''.join(mapping.get(c, c) for c in ciphertext)
```

### JNI Crackme Solver

```python
# JNI crackme 解题模板
# 1. 用 Frida hook native 验证函数
# 2. 获取输入输出对
# 3. 逆推 flag

# frida -U -f com.ctf.app -l solver.js
```

```javascript
// solver.js
Java.perform(function() {
  var Checker = Java.use("com.ctf.app.Checker");
  Checker.check.implementation = function(input) {
    var result = this.check(input);
    console.log("Input: " + input + " Result: " + result);
    return result;
  };
});
```

## 常见偏差

- 不做五分钟分诊就开始深入逆向——可能存在明文 flag
- 把 honeypot 分支当成真正验证——需要区分真假检查
- OLLVM 场景下逐行读伪代码——应该用工具自动还原
- 多层验证只解了第一层就提交——需要完整追踪所有检查
- 忽略 init_array 中的运行时修改——静态分析结果可能不是最终值
- 游戏安全题只关注内存修改——可能需要协议层分析

## 最小交付

- `run/solver-template.py`（或 `.js`）
- 报告中的 flag、解题路径与验证逻辑
- 关键发现记录（混淆类型、验证方式、绕过方法）

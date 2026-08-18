---
name: packer
description: Shellcode 免杀加载器一键打包工具。当用户需要将 .bin shellcode 打包成免杀 Windows 可执行文件时触发。只要用户提到 shellcode、免杀、packer、打包、Cobalt Strike、shellcode loader、加载器、注入、bypass AV、生成 exe、.bin 文件、360、QVM、天擎、360安全卫士、鲲鹏沙箱 等关键词就应该使用此 skill。
---

# Packer - Shellcode 免杀加载器一键打包

## 概述

本 skill 采用"入口文档 + 参考文档"结构。`SKILL.md` 只保留主流程与关键约束，详细实现、验证、排障下沉到 `references/`。

**首次使用建议先阅读：** `references/layout.md` → `references/techniques.md` → `references/gostager.md`

完整阅读路径见：`references/overview.md`

## 资源索引

- `tools/sgn.exe`、`tools/keystone.dll`：外部二进制工具（版本见 `tools/README.md`）
- `scripts/encrypt.go`、`scripts/encrypt_ipv4.go`、`scripts/parse_stager.py`：辅助脚本
- `scripts/build_qvm.py`：QVM 专项构建脚本（UUID编码 + Go源码生成 + 编译 + Overlay注水 + PE修复）
- `scripts/verify_pre.py`、`scripts/verify_pe.py`：编译前/后验证脚本
- `assets/versioninfo.json`：静态资源模板
- `references/overview.md`：文档导航与阅读路径
- `references/layout.md`：目录职责约定
- `references/techniques.md`：注入技术与 `SyscallN` 参数表
- `references/defense-modules.md`：防御模块实现模式
- `references/encryption.md`：加解密逻辑参考
- `references/randomization.md`：随机化规范
- `references/gostager.md`：Go stager 详细流程
- `references/verification.md`：编译前/编译后验证
- `references/troubleshooting.md`：故障排查总表（含体积分诊表）
- `references/qvm-bypass.md`：**360 QVM 专项免杀**（UUID + Fiber + IAT欺骗 + Overlay注水 + PE元数据修复）

## 全局约束

1. 命令中的 Python 统一写作 `<python命令>`，先通过环境检查确定是 `python3` 还是 `python`。
2. Windows 环境默认输出目录使用项目内 `result/`，不使用 `/tmp/`。
3. `gostager` 分支中下游字段以 `scripts/parse_stager.py` 输出 JSON 为唯一来源。
4. `sgn.exe` 属于二进制工具，放 `tools/`；源码脚本放 `scripts/`（见 `references/layout.md`）。
5. **每次编译前必须清理上次运行残留的生成文件**（`result/*.go`、`result/*.exe`、`result/.eout.txt` 等），确保本次编译不受上次遗留文件干扰。上次产物在两次生成之间保留，方便排查失败原因。清理方式见 `references/verification.md`。
6. **Go 编译必须使用 `-trimpath -ldflags="-s -w -H windowsgui"`**。`-s` 去符号表、`-w` 去调试信息、`-H windowsgui` 隐藏控制台。跨平台命令写法见 `references/gostager.md`。

## 主流程

### Step 0: 环境检查

- 检测 Python（bash: `python3 --version || python --version` / CMD: `python --version`）
- 记录统一命令占位：`<python命令>`
- 检测 Go、依赖与 Windows 路径约束

### Step 1: 确认输入参数

- `.bin` 路径、输出目录（默认 `result/`）、可选模块与 SGN 开关
- **体积分诊：** 用 `<python命令> -c "import os;print(os.path.getsize('<file>'))"` 获取文件体积，按阈值分流。分诊表见 `references/troubleshooting.md`。
- 用户可通过 `--mode gostager` 或 `--mode createthread` 显式指定，跳过体积判断。

### Step 2: 分流执行

**编译前清理** → 见 `references/verification.md`

**⚠️ 当用户提到 360 / QVM / 天擎 / 360安全卫士 时，切换到 QVM 专项技术栈：**
→ 执行 `<python命令> <skill_dir>/scripts/build_qvm.py <shellcode.bin>` 完成全自动构建。UUID 编码 → Fiber + IAT欺骗 → 编译 → Overlay注水 → PE元数据修复。详见 `references/qvm-bypass.md`。

**分支 A — gostager：** 运行 `scripts/parse_stager.py` 解析 CS stager → HTTP 下载 beacon DLL + 反射加载（跳板技术）。详见 `references/gostager.md`。

**分支 B — 嵌入式模式：** 加密 → 动态生成源码 → 编译前验证 → 编译 → 编译后验证。详见 `references/techniques.md`、`references/encryption.md`、`references/verification.md`。

### Step 3: 报告结果

输出：产物路径/大小、使用模式、模块状态、关键参数摘要。

## 故障排查入口

当出现"不上线"或行为异常时，按统一排障链路诊断。体积判断仅作启发式，优先以解析成功与实测结果分流。

详见：`references/troubleshooting.md`

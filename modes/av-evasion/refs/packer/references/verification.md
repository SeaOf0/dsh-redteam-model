# 验证流程

本文件描述编译前验证和编译后 PE 验证的全部检查项。验证脚本位于 `scripts/verify_pre.py` 和 `scripts/verify_pe.py`。

**模式差异速查：**

| 验证项 | 嵌入式模式 | gostager (CS) |
|--------|-----------|---------------|
| AES 解密验证 | 需要 | 不需要 |
| SGN 编码检查 | 可选 | 不需要 |
| XOR 编码验证 | 需要 | 需要 |
| 加密产物检查 | `.eout.txt` | 不适用 |
| PE 敏感字符串 | 全部应隐藏 | Go runtime 部分泄露正常 |
| 源码模式检查 | 需要 | CS HTTP + 反射加载模式 |

---

## 一、编译前验证

在编译前，对加密产物和生成的 Go 源码执行 6 项强制检查，全部通过才能进入编译。

**适用范围：** 嵌入式模式。gostager 模式无需 AES 解密验证，直接检查 Go 源码即可。

### 执行命令

```bash
<python命令> <skill_dir>/scripts/verify_pre.py <output_dir> <go_source.go>
```

### 检查项说明

| 序号 | 检查项 | 失败处理 |
|------|--------|----------|
| 1 | 解密大小是否在合理范围 (100 ~ 100000 bytes) | 检查 `encrypt.go` 的输出，确认文件路径和内容 |
| 2 | 解密后内容是否为有效 PE / shellcode | 如首字节异常，检查加密流程是否完整 |
| 3 | Go 源码是否包含关键模式 (syscall/LoadLibrary/GetProcAddress/SyscallN 等) | 补全缺失的代码模式 |
| 4 | 是否出现禁止模式 (golang.org/x/sys/windows / LazyDLL / NtProtectVirtualMemory / 明文 API 名) | 移除问题代码 |
| 5 | SyscallN 调用参数数量是否超过 6 | 对照 `references/techniques.md` 修正 |
| 6 | XOR 编码是否能正确还原为合法字符串 | 用 Python 脚本重新计算，禁止手动修正 |

---

## 二、编译后 PE 验证

编译完成后，验证产物文件基本有效性和导入表/字符串泄露情况。

### 执行命令

```bash
<python命令> <skill_dir>/scripts/verify_pe.py result/<exe_name>.exe
```

### 检查项说明

| 序号 | 检查项 | 失败处理 |
|------|--------|----------|
| 1 | 文件头为 `MZ`（有效 PE） | 检查编译是否正常完成 |
| 2 | 文件大小合理 | 过小可能编译失败，过大排查资源嵌入 |
| 3 | Go runtime 泄露 | `kernel32.dll`/`VirtualAlloc`/`CreateThread`/`WaitForSingleObject` 出现在明文属正常（Go `syscall` 包内部硬编码） |
| 4 | 用户隐藏 API 泄露 | `ntdll.dll`/`RtlMoveMemory`/`VirtualProtect`/`GlobalMemoryStatusEx` 等不应出现在明文，出现则检查 XOR 编码 |

---

## 三、编译前清理

每次编译前清理 `result/` 中上次运行残留的生成文件。

```bash
# bash (Git Bash / WSL)
rm -f result/.eout.txt result/*.go result/*.exe
```
```cmd
:: Windows CMD
del /q result\.eout.txt result\*.go result\*.exe 2>nul
```
跨平台通用：
```bash
<python命令> -c "import glob,os;[os.remove(f) for p in ('result/*.go','result/*.exe','result/.eout*') for f in glob.glob(p)]"
```

---

## 四、失败处理约定

- 验证失败先修复代码/产物，再重新验证，不跳过任何步骤直接编译或交付。
- 解密大小不合理 → 检查 `result/.eout.txt` 的生成路径。
- XOR 编码错误 → 用 Python 脚本重新计算并验证，禁止手动修正。
- 参数数量错误 → 对照 `references/techniques.md` 中每个 API 的 SyscallN 参数数量表修正。
- 禁止模式被检测到 → 移除对应的 import 或 API 调用。

验证通过后才可进入编译或交付。

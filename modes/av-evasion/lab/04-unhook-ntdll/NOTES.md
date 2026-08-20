# 04 ntdll 去重映射去 hook

- 构建：`x86_64-w64-mingw32-gcc -mwindows -o unhook.exe unhook.c`
- 用法：`unhook.exe [mode] [函数名]`
  - mode 0（默认）：磁盘 device 路径 SEC_IMAGE 映射 → 全量恢复所有可执行段
  - mode 1：**\KnownDlls\ntdll.dll 段对象**（NtOpenSection + NtMapViewOfSection，
    零磁盘文件 I/O——绕文件访问监控）
  - mode 2：LoadLibraryExA(..., DONT_RESOLVE_DLL_REFERENCES) 新副本 → 从新映射恢复
  - mode 3：**单函数恢复**（[函数名] 必填，覆盖目标函数头 32 字节；Nt* syscall stub
    实测 0x12-0x18 字节——超出 32 字节的函数按 32B 记，如实标注）
- 技术侧：干净 ntdll .text 覆盖进程内被 hook 版本——恢复后的 API 调用不再触发 EDR
  用户态 hook（常与 01 直接 syscall 互补：先去 hook 再正常调用）。
  **覆盖前后哈希对账**：每段恢复打印 FNV-1a before/after，before==after 即"未被 hook"，
  恢复效果可证伪可复核。
- 检测侧配对：跨镜像 .text 写入（对只读节的 VirtualProtect+memcpy 组合遥测）；
  ntdll .text 哈希/完整性周期校验；Hook 自愈（EDR 重新 patch）检测面；
  NtOpenSection 已知段对象访问监控（mode 1）。
- 判定表（本地实测后填）：| 引擎 | 结果 | 原文行 |
  Windows 判定环境。

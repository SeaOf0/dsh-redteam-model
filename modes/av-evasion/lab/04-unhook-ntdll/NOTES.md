# 04 ntdll 去重映射去 hook

- 构建：`x86_64-w64-mingw32-gcc -mwindows -o unhook.exe unhook.c`
- 技术侧：磁盘/段对象的干净 ntdll .text 覆盖进程内被 hook 版本——恢复后的 API 调用
  不再触发 EDR 用户态 hook（常与 01 直接 syscall 互补：先去 hook 再正常调用）。
- 变体：\KnownDlls\ntdll.dll 段对象映射（绕文件监控）、LoadLibraryExA 副本加载、
  仅恢复目标函数。
- 检测侧配对：跨镜像 .text 写入（对只读节的 VirtualProtect+memcpy 组合遥测）；
  ntdll .text 哈希/完整性周期校验；Hook 自愈（EDR 重新 patch）检测面。
- 判定表：| 引擎 | 结果 | 原文行 |

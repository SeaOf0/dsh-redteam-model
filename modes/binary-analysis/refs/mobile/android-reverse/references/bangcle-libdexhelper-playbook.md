# Bangcle libDexHelper Playbook

目标：把 `libDexHelper.so` / `libDexHelper-x86.so` 这类梆梆企业壳样本，从“看到壳特征”推进到可复验的外层 SO 解密、内层 ELF 验证和运行时 DEX 回流。

## 适用范围

命中任一信号时读取本文件：

- APK 中存在 `libDexHelper.so`、`libDexHelper-x86.so` 或同族 SO。
- 壳识别指向梆梆企业版，且外层 SO 只有少量可解释函数/符号。
- `.init_array` / constructor / `JNI_OnLoad` 附近存在解密、`mmap`、`mprotect`、重定位或动态 DEX 加载迹象。

`libDexHelper` 是“自解密 native 容器 + 运行时 DEX 释放/加载”的强线索，不代表固定偏移、固定密钥、固定 Frida 版本或固定工具链。

## 证据产物

选中本路线时，在 task-local 中填写 `run/bangcle-libdexhelper-evidence.md` 或结构化 `run/unpack-evidence.json`。同时更新：

- `dexLoader.shellFamily = "bangcle-libdexhelper"`
- `dexLoader.unpackStrategy`
- `dexLoader.shellEvidenceRefs`
- `dexLoader.elfUnpackEvidenceRefs`
- `dexLoader.innerElfRefs`
- `dexLoader.dexValidationRefs`

没有这些证据时，只能说“命中 libDexHelper 壳线索”，不能宣称已脱壳或真实逻辑完整可见。

## 阶段 1：确认样本和安全取证

记录外层 SO 的来源、ABI、大小、SHA256、包名、设备/ROM、进程名和采集方式。Root 取文件时优先使用任务目录和只读复制；不要把 `chmod 777` 写成标准步骤。需要卸载、清数据、重签安装或触发真实账号流量时，先取得明确授权。

## 阶段 2：解析外层 ELF

优先用 Program Header Table 和 Dynamic Segment，不依赖 Section Header Table。

必须区分：

- `EI_CLASS`: ELF32 / ELF64
- `EI_DATA`: endian
- `PT_LOAD`: VA 到 file offset 映射
- `PT_DYNAMIC`: `DT_INIT_ARRAY`、`DT_INIT_ARRAYSZ`、`DT_RELA`、`DT_RELASZ`、`DT_REL`、`DT_RELSZ`

ELF64 头字段不要按 ELF32 读取：`e_entry` 在 `0x18` 为 8 字节，`e_phoff` 在 `0x20` 为 8 字节，`e_shoff` 在 `0x28` 为 8 字节。

可用 `scripts/inspect-elf-init-array.py <libDexHelper.so>` 生成 PHT、`PT_DYNAMIC`、`.init_array` 与 relocation 摘要；脚本输出是取证材料，不替代 IDA/Ghidra 的调用链和数据流证明。

## 阶段 3：定位 init_array 和重定位

`.init_array` 入口只是候选，不是自动结论。用重定位、调用链和运行时行为共同证明它是否为壳入口。

AArch64 常见重定位类型：

- `0x401 = R_AARCH64_GLOB_DAT`
- `0x403 = R_AARCH64_RELATIVE`

如果 IDA/Ghidra 的 image base 与文件偏移不同，先完成 VA 到 file offset 映射，再解释动态表和重定位目标。

## 阶段 4：恢复解密链

从候选入口向下追踪数据流，而不是从地址常量开始：

- 密钥材料读取位置：文件尾、动态段、自定义段、assets、包名/签名派生。
- 解密操作：RC4/RC4-like、XOR、AES/SM4、压缩/解压、分段拼接。
- 内存操作：`mmap`、`memcpy`、`mprotect`、`dlopen`、自定义 relocation。
- 输出边界：payload 起止偏移、长度、hash 和中间状态 hash。

单样本中出现的 `0x8000` payload、`0x19` XOR key、`0x104E3D` key material 这类数值只能作为该样本的观测值。写进报告时必须说明来源和推导，不能作为 Bangcle 默认常量。

## 阶段 5：验证内层 ELF

保存内层 SO 后至少验证：

- ELF magic、class、endian、machine。
- `e_phoff`、`e_phnum`、`PT_LOAD` 范围在文件内。
- `PT_DYNAMIC` 可解析，导入/导出或 relocation 与平台一致。
- 文件 hash、大小、payload 范围和外层输入 hash 可回指。
- IDA/Ghidra 函数数量变化只能作为辅助现象，不能作为成功证据。

若内层不是完整 ELF，按“内存片段/二阶段载荷/压缩块”处理，转 `so-runtime-evidence-playbook.md` 或继续数据流恢复。

## 阶段 6：运行时 DEX 回流

DEX dump 是独立阶段，不与外层 SO 解密混为一条成功结论。

Frida、Florida、frida-dexdump 或其它工具版本不固定；记录实际版本、设备、ABI、spawn/attach 时机、进程存活和 anti-Frida 证据即可。A4 表示复杂度，不表示 Frida 必然失败。出现高层 anti-Frida、早期自毁或连续同策略失败时，按 `unpack-tool-matrix.md` pivot 到 eBPF/FART/BlackDex/Smali Patch/Root 直读等路线。

## 阶段 7：DEX 修复和验证

DEX header hash 归一化顺序：

1. SHA-1 写入 `0x0c..0x1f`，输入为 `data[0x20:]`。
2. Adler32 写入 `0x08..0x0b`，输入为 `data[0x0c:]`。

Header hash 修复不等于结构修复。继续验证：

- `file_size` 与真实文件长度一致。
- `map_off`、`string_ids`、`type_ids`、`class_defs` 范围在文件内。
- multi-dex 数量和命名可追踪。
- 业务类、Manifest 入口、调用链和目标功能能互相印证。

只找到一个 Activity 或 WebView 类，不能证明 dump 完整。

可用 `scripts/normalize-dex-header.py dumped.dex -o dumped.normalized.dex` 做 header hash 归一化。该脚本会拒绝明显结构不一致的 DEX；拒绝结果应作为继续修复或重新 dump 的证据，而不是忽略。

## 最小交付

- `run/bangcle-libdexhelper-evidence.md` 或 `run/unpack-evidence.json`
- 外层 SO hash、ABI、壳特征和采集来源
- `.init_array` / relocation / 解密链证据
- 内层 ELF 文件、hash 和验证结果
- DEX dump 工具/时机/版本能力记录
- DEX header/结构/语义验证结果
- 未解决风险和下一步 pivot

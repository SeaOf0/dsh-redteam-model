# Native SO Playbook

目标：围绕目标逻辑深挖 SO，而不是泛扫所有函数。

## 工具选择

| 场景 | 工具 | 原因 |
|---|---|---|
| 通用 SO 分析 | IDA Pro | 业界标准，ARM/ARM64 反汇编和反编译质量最高 |
| 无 IDA 许可证 | Ghidra | 免费，ARM/ARM64 支持完善，反编译质量接近 IDA |
| 快速字符串/符号扫描 | `strings` + `nm` / `readelf` | 不需要打开重量级工具即可确认导出符号和字符串 |
| 加密常量定位 | `strings` + grep + IDA/Ghidra xref | 从常量锚点反推调用链 |

Ghidra 与 IDA 的关键差异：
- Ghidra 无许可证限制，可通过 Ghidra Headless Analyzer 命令行反编译 SO，或用 Ghidra Bridge 在 Python 中远程调用
- IDA 可通过 MCP 工具（`ida-pro-mcp`）由 Claude 直接执行反编译、搜索符号、读取 xref 等操作
- 两者均支持脚本（IDA Python / Ghidra Python），可用于批量常量搜索和函数识别

`.so` 分析强制使用 IDA。当本轮需要 IDA 且 `PATH`、项目目录、已有记录和常见安装路径都未命中时，**必须做宿主机全盘搜索**（Windows 枚举盘符搜 `ida64.exe`/`ida.exe`/`idat64.exe`/`idat.exe`；Linux/macOS 用 `find`/`mdfind`/`locate` 搜 `ida64`/`ida`/`idat64`/`idat`），命令、范围、候选、结果落盘；全盘仍找不到才询问用户路径。只有用户明确表示没有 IDA 或无法提供路径后，才允许换用 Ghidra/radare2/objdump，并记录用户答复和替代原因。

## 函数范围确认

分析任何 SO 函数前必须先确认 IDA 识别的函数范围，这是静态结论可信的前提。

**为什么强调**：IDA 的自动函数识别在 stripped SO、OLLVM dispatcher、thunk、异常处理块边界常出错——把相邻函数误合并、把 dispatcher 截断、漏掉尾部 `ret/br` 或 fatal 分支。在错误范围上读伪代码会得到与运行时不符的结论，patch 也会打错位置。

确认清单：

- IDA 识别的起始地址、结束地址、基本块边界是否合理
- 已知 `pc/lr/callsite`（来自 tombstone / Frida / logcat / 内核 syscall 捕获）都落在正确函数范围内
- 入口、跳转表、dispatcher、真实 basic block、尾部 `ret/br`、异常/fatal 分支没有被截断
- 相邻函数、thunk、异常处理块、OLLVM dispatcher 没有被误合并到当前函数

范围异常时，先在 IDA 中修正函数起止范围、重建函数并重新导出，再进入检测链分析。范围确认结果（含人工判断依据）写入 `run/native-notes.md`。未确认函数范围前，不得给出伪代码结论或 patch 候选。批量修正可用 IDAPython 脚本按 JSON 应用已确认的起止范围并输出校验报告（`--dry-run` 只校验不修改）。

## IDA 结构化导出

当 IDA MCP 不可用、或需要批量导出供离线分析时，用 IDAPython 脚本把一个模块的反编译、反汇编 fallback、字符串、导入导出、xref 和函数调用关系一次性导出为 AI 可读文本，输出到 `artifacts/ida-export/<module>/`（或 `run/` 下约定的目录）。

**为什么需要**：单函数 MCP 调用适合精确定位，但跨函数追踪调用链、搜全部加密常量、批量识别 dispatcher 时，逐个 MCP 调用既慢又容易漏；结构化导出一次抓全，离线 grep/交叉引用更高效，也便于在 IDA 不可用时交接给其他工具。

可用开源等价示例：开源 IDA 导出插件（如 INP.py 类"Export for AI"插件，支持批处理 `-S` 调用），或自写 IDAPython 脚本。导出目录路径、来源 SO、偏移口径、函数范围修正状态、是否已做 OLLVM 还原必须落盘到 `run/native-notes.md`；重导出同一版本前先检查现有 `artifacts/ida-export/`，避免重复劳动，重导出时保留旧目录或加时间/版本后缀。

## 优先观察

- 导出符号
- `JNI_OnLoad`
- 字符串与常量表
- 加密常量、S-box、域名、路径
- `open / read / ptrace / syscall / strstr`

## SO 混淆识别

当 SO 出现以下特征时，进入控制流混淆场景，直接反编译结果不可信：

- 大量 `switch-case` 或 `if-else` 嵌套形成分发器（控制流平坦化，OLLVM/Hikari 风格）
- `Cmp` 指令操作数为不透明谓词（如 `x * x >= 0`）
- 基本块之间大量不相关跳转，无局部变量传递
- `cmov` / 条件传送被滥用

应对策略：
1. 先不深挖语义，优先恢复桥接映射（`RegisterNatives` → 函数指针 → 模块基址）
2. 用 Frida 在运行时直接抓函数入参和返回值，绕过静态混淆
3. 识别加密常量和字符串引用作为锚点，从锚点反推业务函数
4. IDA 脚本辅助去平坦化仅在有明确收益时使用，不作为默认步骤

## ELF 深入

### 程序头表（PHT）是加载真相

- PHT（Program Header Table）决定 SO 在内存中的布局
- SHT（Section Header Table）是可选的，strip 后可能被删除
- 分析 SO 加载行为时优先看 PHT 中的 `PT_LOAD`、`PT_DYNAMIC`、`PT_GNU_RELRO`

### GOT[0..2] 固定锚点

- `GOT[0]`：`.dynamic` 段的地址
- `GOT[1]`：linker 的 `struct link_map` 地址
- `GOT[2]`：linker 的 `_dl_runtime_resolve` 函数地址
- 这三个条目在分析 GOT/PLT 机制时是关键参考

### PT_GNU_RELRO

- 标记哪些内存区域在加载完成后设为只读
- GOT 的只读部分在 RELRO 完成后不可写——影响 GOT hook 的可行性
- Full RELRO：整个 GOT 在加载时解析并设为只读，此时 PLT Hook 失效

## Android Linker 加载流程

`find_libraries` 的 7 步加载过程：

1. **读取 ELF 头**：验证魔数、架构、字节序
2. **映射 PT_LOAD 段**：按 PHT 将文件内容映射到内存
3. **处理 PT_DYNAMIC**：解析动态段，获取依赖库列表、重定位表等
4. **加载依赖库**：递归加载所有 NEEDED 库
5. **重定位**：处理 `R_ARM_RELATIVE`、`R_ARM_GLOB_DAT` 等重定位类型
6. **GOT/PLT 初始化**：填充 GOT 表中的函数地址
7. **调用构造函数**：按顺序调用 `.init_array` 中的函数

Hook 时机：
- `.init_array` 函数在 SO 加载完成后立即执行——适合作为早期 hook 点
- 如果目标在 `.init_array` 中做反检测，需要在 `JNI_OnLoad` 之前处理

## GOT/PLT 机制

### 调用流程
1. 代码调用外部函数 → 跳转到 PLT 条目
2. PLT 条目跳转到 GOT 中存储的地址
3. 首次调用：GOT 指向 PLT 的下一条指令（延迟绑定），触发 linker 解析
4. 后续调用：GOT 已更新为真实函数地址

### Hook 影响
- **PLT Hook（GOT 修改）**：修改 GOT 表中的地址，所有通过 PLT 的调用都被拦截
- **Full RELRO 保护**：GOT 在加载时全部解析并设为只读，PLT Hook 失效
- **Inline Hook**：直接修改函数入口指令，不依赖 GOT/PLT，绕过 RELRO

## SO 自保护机制

- **GNU Hash**：符号哈希加速查找，也增加了手动分析难度
- **自定义段**：在 ELF 中添加自定义 section 存储加密数据或校验信息
- **CRC/Hash 校验**：运行时计算 SO 内存镜像的 Hash，与存储值比较
- **反调试**：`.init_array` 中的函数在 `JNI_OnLoad` 之前执行，可以做早期检测

## DEX 文件格式

### 关键结构
- **LEB128**：可变长度编码，广泛用于 DEX 中的大小和偏移字段
- **class_data_item**：类的方法和字段列表，使用 LEB128 编码
- **checksum**：Adler32 校验和，位于文件头 0x08 位置
- **signature**：SHA-1 哈希，位于文件头 0x0C 位置

### 修改 DEX 后重算校验
1. 修改 DEX 内容
2. 重新计算 SHA-1（从 0x20 到文件末尾），写入 0x0C
3. 重新计算 Adler32（从 0x0C 到文件末尾，包含刚写入的 SHA-1），写入 0x08
4. 不重算校验会导致安装失败或运行时校验失败

## ARM64 逆向模式

### 调用约定
- 参数：x0-x7（前 8 个参数）
- 返回值：x0（浮点用 s0/d0/q0）
- 栈帧：x29(FP)/x30(LR)，SP 16 字节对齐
- 被调用者保存：x19-x28, x29(FP), x30(LR)

### 系统调用接口
- 触发：`svc #0` 指令
- 系统调用号：x8 寄存器
- 参数：x0-x5
- 返回值：x0

### Arkari 间接跳转
- Arkari 使用查表替换直接跳转目标
- 跳转表地址通常在 `.rodata` 或自定义段中
- 需要先定位跳转表才能恢复控制流

## APK 签名验证机制

### 三层验证
1. **Java 层**：`PackageManager.getPackageInfo()` 获取签名信息，`Signature` 类比对
2. **Native 层**：SO 中直接读取 ZIP 条目，计算 Hash 与签名比较
3. **Binder 层**：通过 `PackageManagerService` 获取签名，防止客户端伪造

### 绕过要点
- Java 层：Hook `getPackageInfo` 返回指定签名
- Native 层：需要找到验证函数并 patch
- Binder 层：通常需要同时处理 Java 和 Native

## RegisterNatives 替代发现

当 `RegisterNatives` 被混淆或动态生成时，通过 ArtMethod 直接读取 native 入口。

注意：以下偏移仅在 Android 8-10 (ARM64) 上验证过，Android 11+ ArtMethod layout 有变化，需要根据具体版本调整：

```javascript
// 在 Frida attach 后（RegisterNatives 已执行）
// 方法 1：通过 Frida 内部 API（需要特定 Frida 版本支持）
Java.perform(function() {
  var clazz = Java.use("com.target.ClassName");
  // 使用 Java.cast 获取方法的 ArtMethod 地址
  // 注意：直接读取 ArtMethod 偏移依赖 Android 版本
  // Android 8-10 ARM64: entry_point_from_jni_ 偏移 0x18
  // Android 11+ 偏移可能不同，需要从 AOSP 源码确认
});

// 方法 2：通过 Module.findExportByName 确认（更可靠）
// 在 RegisterNatives 执行后，直接搜索 SO 中被注册的地址
Interceptor.attach(Module.findExportByName("libtarget.so", "JNI_OnLoad"), {
  onLeave: function() {
    // RegisterNatives 已完成，此时 hook 目标 native 方法
    // 通过 Java.use + Interceptor.attach 目标方法获取执行地址
  }
});
```

## 常见偏差

- 在未完成 JNI 桥接映射前就深入分析单个 SO 函数——应先建立 Java→Native 最小链路
- 只看导出符号不看 stripped 函数——大量业务逻辑在非导出函数中，需要通过 RVA 定位
- 混淆场景下试图逐函数阅读伪代码——应改用运行时 hook 直接抓输入输出
- 忽略 SO 中的字符串常量——加密算法名、URL、错误信息是高价值锚点

## 结论约束

- 单靠伪代码不得直接下运行时结论
- 高风险结论需要 Frida 或双工具交叉验证

## 最小交付

- `run/native-notes.md`（SO 分析笔记，含以下内容）
- 关键函数地址清单：`{ 函数名/RVA | 调用方 | 功能推测 | 验证状态 }`
- 至少一条从 JNI 入口到关键计算输出的调用链
- 加密常量定位结果（如有）
- 交叉验证证据（IDA 静态 + Frida 动态 / jadx Java 层 + IDA Native 层）

# 分析信号门禁

> 本文件收纳 IDA/Ghidra/JADX 分析过程中各类信号的强制处理规则，包括 `disassemble_function` vs `decompile_function` 首选规则、信号门禁大表、Frida 解锁门禁。
> SKILL.md 仅保留一句话指针。首次对 SO 执行 IDA 分析、或 JADX 发现框架/壳/网络特征时必须读取本文件。

## 目录

- disassemble_function vs decompile_function 首选规则
- 分析中信号门禁
- 混淆还原后续动作
- Frida 解锁门禁
- Playbook 检查点

## disassemble_function vs decompile_function 首选规则

对 SO 函数首次调用 `disassemble_function` 或 `decompile_function` 前，先评估是否存在混淆线索（用户输入含混淆关键词、专题路由已命中、已发现字符串加密/.bss 不透明谓词、前序函数 decompile 返回 JUMPOUT）。若存在任何一条，首次调用必须是 `disassemble_function`，不得先用 `decompile_function` "试探"再回头确认——混淆下的 decompile 输出可能看似合理实则错误（FLA dispatcher 被误解析、BCF 死代码膨胀），会误导后续分析判断。`decompile_function` 仅在以下情况使用：① 确认无混淆 ② 已完成 BCF 等去混淆 patch 后验证还原效果 ③ SUB 还原中获取复杂表达式（控制流结构完整，仅表达式被替换）。radare2 环境下始终优先 `disassemble_function`（其反编译器对混淆代码不可靠）。

## 分析中信号门禁

IDA/Ghidra/JADX 返回以下任一结果时，**在输出任何分析结论或下一步动作之前**，必须先执行对应操作列中的步骤：

| 信号                                             | 必须执行的操作                                                                                                                                                                               |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 函数反编译为空 / JUMPOUT / 大段不可读            | ① 用 IDA `disassemble_function` 查看汇编 ② 识别 FLA（switch-case 分发器 + 状态变量）、BR（CSEL 链 + BR Xn）、BCF（.bss 不透明谓词）、SUB（复杂等价表达式）中的哪一种 ③ 输出混淆类型判定 |
| SO 字符串搜索返回空结果                          | ① 在 `.rodata` 搜索 crypto 常量（AES S-box 0x63、SHA-1 IV 0x67452301 等）② 若也无结果，判定字符串加密，用 xref 从已知 API（memcpy/strlen）反向追踪解密函数 ③ 输出字符串加密判定         |
| switch-case 分发器 / CSEL 链 /`.bss` 全局变量  | 同"函数反编译为空"的 ①②③                                                                                                                                                                  |
| VM interpreter / handler table / opcode dispatch | Read `vmp-analysis-playbook.md`                                                                                                                                                            |
| JADX 发现 `InMemoryDexClassLoader` / `DexClassLoader` | ① Read `dex-loader-playbook.md` ② 记录 dex 加载时机和来源 ③ 判断是否需要动态 dump                                                                                                    |
| JADX 发现 `Cronet` / `BoringSSL` / native TLS import | ① Read `native-network-playbook.md` ② 执行 Java/Native 网络栈分层 ③ 确认 pinning 层级                                                                                              |
| JADX 发现 `libapp.so` / `FlutterFragment` / `FlutterActivity` | ① Read `framework-runtime-playbook.md` ② 确认 Flutter 运行时类型 ③ 定位 Dart AOT snapshot                                                                                            |
| JADX 发现 `libil2cpp.so` / `Il2Cpp` class import | ① Read `framework-runtime-playbook.md` Unity IL2CPP 章节 ② 确认 metadata 加密状态 ③ 定位 global-metadata.dat                                                                           |
| JADX 发现 `WebView.addJavascriptInterface` / `@JavascriptInterface` | ① Read `webview-hybrid-playbook.md` ② 映射 JS-Native 桥接方法名 ③ 评估桥接安全面                                                                                                    |
| JADX 发现 `MMKV` / `SQLCipher` / `EncryptedSharedPreferences` | ① Read `storage-ipc-playbook.md` ② 定位加密存储密钥来源 ③ 评估敏感数据存储安全性                                                                                                    |
| JADX 发现 `SafetyNet` / `PlayIntegrity` / `KeyAttestation` | ① Read `anti-root-playbook.md` 硬件级检测章节 ② 确认验证级别（BASIC/DEVICE/STRONG）③ 评估绕过可行性                                                                                  |
| JADX 发现 `Method.invoke` + `Class.forName` 密集使用 | ① Read `deobfuscation-playbook.md` Java 层混淆章节 ② 识别混淆工具（DexGuard/Allatori）③ 建立间接调用映射                                                                              |
| JADX 发现壳特征 SO（`libjiagu` / `libshell` / `libexec` / `libsecexe` / `libtosprotection` / `libnesec` / `libchaosvmp` / `libbaiduprotect` / `libsgmain` / `libkwscmm` / `libx3g` / `libvirbox` / `libcmvmp` / `libpairipcore` / `OPPOProtect` / `libxloader` / `libDexHelper` / `libegis` / 任何 `unpack-tool-matrix.md` 壳识别总表中的 SO） | ① Read `references/unpack-tool-matrix.md` 壳识别总表 ② 匹配壳类型和难度 ③ 按环境、ABI、进程存活、检测时序和 Anti-Frida 证据选型 ④ 记录到 `route-state.json` 的 `unpackStrategy`；若命中 `libDexHelper`，再 Read `references/bangcle-libdexhelper-playbook.md` 并记录 `dexLoader.shellFamily=bangcle-libdexhelper` |
| IDA 发现 `BLR Xn` 跳转到从 `.bss` 全局变量原子加载的地址（`LDAR`），且该全局变量无同 SO 内的写入 caller | ① 识别跨 SO 虚表间接调用模式 ② 搜索 `STLR`/`STR` 写入找到注册函数 ③ xref 追踪到 vtable ④ Read `references/technique-extract-2026-05.md` 第 1 节 ⑤ Hook 注册函数打印 backtrace 验证跨 SO 链路 |
| IDA 发现 NRV2B 解压器特征（`adds w4,w4,w4; cbz w4,reload; ldr w4,[x0],#4; adcs w4,w4,w4` + `mmap(MAP_FIXED)` 覆盖自身）| ① 识别双层打包/自修改代码 ② 运行时 dump gap code 区域 ③ 用 IDA "load additional binary" 补充缺失代码 ④ Read `references/technique-extract-2026-05.md` 第 3 节 |
| IDA 在加密/签名函数中发现 MD5 四魔数（`0x67452301` / `0xefcdab89` / `0x98badcfe` / `0x10325476`）附近有 `malloc(0x21)` | ① 按 MD5 验证：hook 输入喂 `hashlib.md5` 比对 hex ② 确认是否魔改（比对标准 MD5 输出）③ Read `references/technique-extract-2026-05.md` 第 4 节算法识别快速判定表 |
| IDA 仅识别导入桩 / 极少量函数、section/dynamic/字符串表异常、已知运行 `pc/lr` 不落在磁盘 SO 可解释代码段、constructor/`JNI_OnLoad` 含解密或 `mmap(MAP_FIXED)` 覆盖自身、DT_INIT 非业务代码而是解压器 | ① 判定磁盘 SO 加密/壳化/自解密/运行时重建 ② Read `references/so-runtime-evidence-playbook.md` §1 ③ dump/fix 运行期 SO 前禁止基于磁盘 SO 下函数语义/检测链/patch 结论 |
| IDA 发现 `BR/BLR Xn` 跳入无文件名映射、`.init_array`/constructor/JNI_OnLoad 申请匿名内存并 `mprotect(PROT_EXEC)`、或 maps 中存在 `rwx`/匿名 `r-x`/`memfd`/可疑 `[anon:.bss]` | ① 判定匿名 RX/memfd 执行 ② Read `references/so-runtime-evidence-playbook.md` §3 ③ 完成匿名执行 6 项证据前禁止 patch；关键逻辑在匿名段时 dump/fix 匿名段后以其为准 |
| 崩溃 tombstone/logcat/Frida 的 `pc/lr/sp` 落在 `[anon:...]` / `memfd` / 未知映射，或出现 `SIGKILL`/`SIGSEGV`/`SIGTRAP`/`BRK`/低地址自毁/`abort`/`exit_group` | ① 用内核 syscall 捕获归属 `pc/lr/sp`（Frida libc hook 看不到内联 `svc #0` direct syscall）② Read `references/so-runtime-evidence-playbook.md` §4-§5 ③ 按 7 步闭环推进，前置步骤未完成禁止动态验证或 patch |
| 字符串出现 `libc.so`/`libart.so`/自身 SO 名/`/proc/self/maps`/`/proc/%d/maps`/`linker`，附近有 `openat`+`read`/`mmap` 文件、`memcmp`/CRC/adler/hash 循环、或失配跳 `__stack_chk_fail`/`MOV SP,#0; BR Xn`/`rt_tgsigqueueinfo` | ① 判定 Native 自校验（self-.text/libc/libart/linker）② Read `references/integrity-pinning-playbook.md` 的"Native 自校验专项"节 ③ 干掉检测代码本身，不要逐字节还原被校验内容 |

## 混淆还原后续动作

**执行上述操作并输出混淆类型判定后**，Read `references/deobfuscation-playbook.md` 对应章节获取还原方法（FLA/BR/BCF/SUB 各自的工具优先级和操作步骤）。还原工具不限于 MCP 内置功能——可通过 Bash 执行 Python 脚本（`python script.py`）处理 MCP 获取的数据，或编写 IDAPython 脚本直接分析。**综合工作流推荐顺序：BCF → 字符串 → FLA → BR → SUB**，详见 playbook 第 8 节。

**完成还原分析并写入 `run/deobfuscation-notes.md` 后**，允许选择 Frida 作为补充验证手段。**`deobfuscation-notes.md` 必须包含至少一条具体的分析结果（case→运算映射、跳转目标、patch 地址、化简结果），不得为空文件或纯占位内容。**

## Frida 解锁门禁

只有目标函数出现可复核的 OLLVM/FLA/BR/BCF/SUB 信号时，才启用 `Deobfuscation-before-hook`。`protectionTier=A4`、存在 JNI 或动态 Dex 本身不等于 OLLVM。

门禁阻止的是依赖混淆后目标控制流语义的操作，例如：

- 对未还原的 dispatcher/basic block 地址执行 `Interceptor.attach/replace`
- 用 `NativeFunction` 直接调用尚未确认真实入口和 ABI 的混淆函数
- 根据未还原的伪代码返回值设计 patch 或业务结论

下列观察操作不受此门禁限制，因为它们用于建立边界而不是解释混淆控制流：

- `Process/Module` 枚举、导出符号查询、maps 和装载时机记录
- Java 层 Frida hook
- `System.loadLibrary`、`JNI_OnLoad`、`RegisterNatives` 边界取证
- 读取已知数据区并保存原始证据

对受门禁限制的目标 hook，先写入包含具体地址、case 映射、跳转目标或化简结果的 `run/deobfuscation-notes.md`。空文件或仅写“存在 OLLVM”不能解锁。

## Playbook 检查点

混淆/VMP 信号的检测规则和强制操作步骤见上文「分析中信号门禁」节。完成信号门禁中的基本操作后，如需更深入的还原方法（D-810 配置、IDAPython deflat 脚本、angr 符号执行），再 Read `references/deobfuscation-playbook.md` 的对应章节。

正文输出：`[playbook检查点] 检测到: X, 混淆类型: Y, 还原方法: Z, 已写入 deobfuscation-notes.md`

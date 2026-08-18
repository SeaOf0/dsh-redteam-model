---
name: reverse-engineering-binary
description: >
  Complete binary reverse engineering covering x86/x64/ARM analysis with IDA Pro and Ghidra,
  anti-reverse-engineering techniques and bypass, VM/bytecode analysis, protocol RE,
  binary protection removal, symbol recovery, and automated analysis scripting.
  Part A covers anti-RE techniques used by malware authors;
  Part B covers RE methodology, tool usage, and automation.
domain: cybersecurity
subdomain: reverse-engineering
tags: [reverse-engineering, ida-pro, ghidra, anti-debugging, anti-reversing, binary-analysis, vm-analysis, protocol-reverse, protection-bypass, decompilation]
version: 2.0.0
---

# 二进制逆向工程 — 完整攻防手册

## 适用场景

- 分析未知恶意软件、壳程序或专有二进制文件
- 理解 C2 协议实现与加密算法
- 绕过软件保护机制进行安全研究
- VM/字节码保护的逆向与脱壳
- 网络协议逆向与解析器开发
- 符号恢复与调试信息重建

**不适用**：移动应用逆向（见 reverse-engineering-mobile）、勒索软件专用分析（见 reverse-engineering-ransomware）

## 前置条件

- IDA Pro 7.x/8.x（含 Hex-Rays）或 Ghidra 10.x+
- x64dbg/WinDbg（动态调试）
- Python 3.x（自动化脚本）
- 了解 x86/x64/ARM 汇编
- 了解 PE/ELF 文件格式

---

## Part A：攻击者视角 — 反逆向与保护技术

### 1. 反调试技术

恶意软件使用多层反调试检测分析环境。以下是完整技术矩阵：

#### 1.1 API 级检测

```c
// === IsDebuggerPresent — 最基础检测 ===
if (IsDebuggerPresent()) {
    ExitProcess(0);  // malware exits
}
// 绕过：x64dbg 命令
//   SetCommandLine IsDebuggerPresent: ret 0

// === CheckRemoteDebuggerPresent — 远程调试检测 ===
BOOL bDebugged = FALSE;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebugged);
if (bDebugged) { /* detected */ }
// 绕过：hook NtQueryInformationProcess 返回 STATUS_PORT_NOT_SET

// === NtQueryInformationProcess — 多参数检测 ===
// ProcessDebugPort (7)
DWORD_PTR debugPort = 0;
NtQueryInformationProcess(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
if (debugPort != 0) { /* debugger present */ }

// ProcessDebugObjectHandle (30)
HANDLE debugObject = NULL;
NtQueryInformationProcess(GetCurrentProcess(), 30, &debugObject, sizeof(HANDLE), NULL);
if (debugObject != NULL) { /* debugger present */ }

// ProcessDebugFlags (31)
DWORD debugFlags = 0;
NtQueryInformationProcess(GetCurrentProcess(), 31, &debugFlags, sizeof(DWORD), NULL);
if (debugFlags == 0) { /* debugger present */ }
```

#### 1.2 PEB 结构检测

```asm
; === PEB.BeingDebugged (x64) ===
mov rax, gs:[60h]       ; TEB -> PEB
cmp byte ptr [rax+2], 0 ; PEB.BeingDebugged
jne debugger_detected

; === PEB.NtGlobalFlag ===
mov rax, gs:[60h]
cmp dword ptr [rax+68h], 0  ; NtGlobalFlag (x64 offset 0x68)
; 0x70 = FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
jne debugger_detected

; === 堆标志检测 ===
; PEB.ProcessHeap -> ForceFlags/Flags
mov rax, gs:[60h]           ; PEB
mov rcx, [rax+30h]          ; ProcessHeap
cmp dword ptr [rcx+44h], 2  ; Flags (normal=2 for HEAP_GROWABLE)
cmp dword ptr [rcx+48h], 0  ; ForceFlags (normal=0)
jne debugger_detected
```

#### 1.3 时序与异常检测

```c
// === RDTSC 时序检测 ===
DWORD t1 = __rdtsc();
// ... small code block ...
DWORD t2 = __rdtsc();
if ((t2 - t1) > 0x1000000) { /* debug delay detected */ }

// === INT 2D 检测（仅 NT） ===
__asm {
    int 2dh    // triggers if debugger present, skipped otherwise
    nop        // debugger skips this NOP
}

// === INT 3 断点检测 ===
// 扫描代码段查找 0xCC 字节
for (DWORD i = funcStart; i < funcEnd; i++) {
    if (*(BYTE*)i == 0xCC) { /* breakpoint detected */ }
}

// === CloseHandle 异常检测 ===
// 向无效句柄调用 CloseHandle，调试器会捕获异常
__try {
    CloseHandle((HANDLE)0xDEADBEEF);
} __except (EXCEPTION_EXECUTE_HANDLER) {
    // 没有调试器时进入此处
    isDebugged = FALSE;
}
// 有调试器时异常被调试器拦截，不进入 __except
```

#### 1.4 线程与进程检测

```c
// === 父进程检测 ===
DWORD parentPid = GetParentProcessId();
// 正常情况下父进程应该是 explorer.exe
if (!IsExplorerParent(parentPid)) { /* launched from debugger */ }

// === 硬件断点检测 ===
CONTEXT ctx = {};
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(GetCurrentThread(), &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
    /* hardware breakpoints set */
}

// === 调试端口检测 ===
// 通过 NtQuerySystemInformation 枚举所有调试端口
// SystemKernelDebuggerInformation (0x23)
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN DebuggerEnabled;
    BOOLEAN DebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION;
```

#### 1.5 反附加技术

```c
// === 线程枚举反调试 ===
// 创建多个监控线程检测调试器
DWORD WINAPI AntiDebugThread(LPVOID param) {
    while (TRUE) {
        if (IsDebuggerPresent() || CheckRemoteDebuggerPresent(...))
            TerminateProcess(GetCurrentProcess(), 0);
        Sleep(100);
    }
}
// 创建多个监控线程
for (int i = 0; i < 5; i++)
    CreateThread(NULL, 0, AntiDebugThread, NULL, 0, NULL);

// === 占用调试端口 ===
// 创建进程间互斥体或命名管道阻止调试器附加
```

### 2. 反逆向工程技术

#### 2.1 代码混淆

```
// === 控制流平坦化 (Control Flow Flattening) ===
// 原始代码:
//   if (x > 0) { foo(); } else { bar(); }
//
// 混淆后:
//   switch(state) {
//     case 0: v = x > 0; state = v ? 1 : 2; break;
//     case 1: foo(); state = 3; break;
//     case 2: bar(); state = 3; break;
//     case 3: /* continue */
//   }
//
// 识别特征：单个大 switch + 状态变量 + 类似 BASIC 块分布

// === MBA 混淆 (Mixed Boolean-Arithmetic) ===
// 将简单运算替换为等价复杂表达式
// a + b  =>  (a ^ b) + 2*(a & b)
// a - b  =>  (a ^ ~b) + 2*(~a & b) + 1
// a ^ b  =>  (a | b) - (a & b)
// 去混淆：使用 SAT/SMT 求解器或模式匹配简化

// === 不透明谓词 (Opaque Predicates) ===
// 插入永真/永假条件制造虚假分支
// 永真: (x*x) >= 0        (永真，但分析器需证明)
// 永真: (2*x+1) & 1 == 1  (奇数最低位总为1)
// 永假: (x*x) < 0         (不可能)
```

#### 2.2 字符串加密

```c
// === 栈字符串构造 ===
// 不在 .rdata 中存储字符串，运行时在栈上构造
char str[8];
str[0] = 'h'; str[1] = 't'; str[2] = 't'; str[3] = 'p';
str[4] = ':'; str[5] = '/'; str[6] = '/'; str[7] = '\0';

// === XOR 循环解密 ===
char enc[] = {0x05, 0x11, 0x1e, 0x1e, 0x14, 0x3d, 0x2c, 0x1e, 0x1b};
char key = 0x41;
for (int i = 0; i < sizeof(enc); i++)
    enc[i] ^= key;  // 解密后为 "http://a"

// === 自定义加密函数 ===
// 使用 AES/RC4/SM4 等加密字符串，运行时调用解密函数
// 识别：解密函数通常接受 (buffer*, length) 参数
// 自动化：IDAPython 脚本遍历所有调用点，执行解密并注释结果
```

#### 2.3 API 哈希与反汇编对抗

```
// === API 哈希导入 ===
// 不使用 IAT，通过哈希值动态解析 API
// 常见于 shellcode 和打包恶意软件
DWORD hash = 0x726774C;  // hash("LoadLibraryA")
// 遍历 PEB -> 模块链表 -> 导出表 -> 计算哈希匹配
// 识别工具：APIHashScan 插件、flare-ida shellcode_hashes

// === 反汇编技术 ===
// 1. 流氓字节：在有效指令后插入垃圾字节干扰线性反汇编
//    jmp short +2  /  db 0xE8 (垃圾)  /  real_code
// 2. 重叠指令：不同起始点解析出不同指令
//    x86: EB FF C0 = jmp -1 / inc eax (重叠解析)

// === 符号剥离与 RTTI 移除 ===
// C++ 二进制移除 RTTI 信息阻止类名恢复
// 移除 .pdata 异常目录增加分析难度
// 混淆跳转表：switch-case 使用间接计算而非标准跳转表
```

### 3. 二进制保护机制

#### 3.1 壳程序 (Packers)

```
=== UPX ===
特征：区段名 UPX0/UPX1/UPX2，高熵值
标准脱壳：upx -d target.exe
修改头脱壳：修改 UPX 区段名/ep 后 upx -d 失败
  -> 手动：在 OEP 设置断点，运行到解压完成，dump + 重建 IAT

=== Themida/WinLicense ===
特征：.themida 区段，多层反调试+虚拟化+代码加密
分析流程：
  1. 定位虚拟机入口（jmp 到 VM dispatcher）
  2. 识别 VM context 结构
  3. 跟踪 handler 分发
  4. 记录字节码并映射语义

=== VMProtect ===
特征：.vmp0/.vmp1 区段，选择性代码虚拟化
分析流程：
  1. 定位被保护函数边界
  2. 在 VM 入口设断点
  3. 跟踪 VM opcode 执行
  4. 使用 VMProtect Unpacker 插件辅助

=== Enigma Protector ===
特征：.enigma1/.enigma2 区段
反调试：IsDebuggerPresent + NtQueryInformationProcess + 时间检测
脱壳：寻找 OEP -> dump -> Scylla 重建 IAT

=== ASProtect ===
特征：.aspack 区段，经常修改 PE 头
分析：使用 stripper 工具或手动定位 stub 代码
```

#### 3.2 代码虚拟化

```
=== VMProtect VM ===
- 寄存器虚拟化：将 x86 寄存器映射到 VM 寄存器数组
- 栈虚拟化：使用独立的 VM 栈替代 x86 栈
- Handler 数量：通常 30-60 个 handler
- 每个 handler 执行一个虚拟操作（加、减、移位等）

=== Code Virtualizer ===
- 更复杂的 VM 结构
- 随机化 handler 顺序（每次编译不同）
- 使用混淆的 handler 实现

=== 通用 VM 分析方法 ===
1. 定位 VM dispatcher（循环分发 handler）
2. 识别 VM context 结构（虚拟寄存器、PC、栈指针）
3. 提取 handler 表
4. 为每个 handler 编写语义描述
5. 编写字节码反汇编器
```

#### 3.3 其他保护机制

```c
// === 反篡改/完整性校验 ===
// 计算代码段校验和，运行时验证
DWORD checksum = CRC32(codeSection, codeSize);
if (checksum != expectedChecksum) { /* tampered */ }
// 绕过：nop 掉校验比较指令

// === 控制流防护 (CFG) ===
// Windows 10+ DEP 增强，验证间接调用目标
// __guard_dispatch_icall_fptr 指向 CFG 检查函数
// 绕过：覆盖 __guard_check_icall_fptr 为直接跳转

// === DLL 注入防护 ===
// 仅加载签名 DLL (SetDllDirectory + LoadLibraryEx)
// 绕过：DLL 劫持、内存手动映射
```

### 4. VM/字节码保护设计

```
=== 自定义 VM 架构 ===
组件：
  - VM Entry：保存宿主寄存器，初始化 VM context
  - VM Dispatcher：读取 opcode，查表跳转 handler
  - Handler Table：每个 handler 实现一条虚拟指令
  - VM Exit：恢复宿主寄存器

=== 字节码编码 ===
- Opcode 混淆：使用变换表替代直接 opcode
- 操作数加密：XOR/ADD 变换操作数
- 变长指令：不同指令不同长度增加解析难度

=== 栈式 VM vs 寄存器式 VM ===
栈式（如 JVM）：
  - 操作数通过栈传递
  - 指令短但数量多
  - 逆向需跟踪栈状态

寄存器式（如 Dalvik）：
  - 显式寄存器操作数
  - 指令长但数量少
  - 更接近真实 CPU

=== VM 检测启发式 ===
- 大型 switch/case 结构（>30 分支）
- 循环中的间接跳转（handler dispatch）
- 连续内存区域作为 context
- 大量 push/pop 到固定偏移
```

---

## Part B：防御者/分析师视角 — 逆向工程工作流

### 5. 逆向工程方法论

#### 5.1 系统化分析流程

```
步骤 1: 文件识别与画像
  ├── file 命令确定文件类型
  ├── 位数 (32/64)、架构 (x86/ARM)、格式 (PE/ELF/Mach-O)
  ├── imphash/ssdeep/TLSH 计算用于样本关联
  └── 熵值分析检测加壳

步骤 2: 静态概览
  ├── 字符串提取 (strings -a -el target.exe)
  ├── 导入表分析 (Imported DLLs + API functions)
  ├── 导出表分析
  ├── 资源提取 (Resource Hacker / wxResearch)
  └── 区段信息（名称、熵值、权限）

步骤 3: 入口点分析
  ├── 定位 OEP (Original Entry Point)
  ├── 跟踪 CRT 初始化到 main()/WinMain()
  ├── 识别编译器特征（MSVC/GCC/Clang stubs）
  └── TLS callback 检测（可能在 OEP 之前执行）

步骤 4: 函数识别与命名
  ├── 自动分析识别的函数
  ├── 库函数识别（FLIRT/Lumina）
  ├── 基于交叉引用和调用约定命名自定义函数
  └── 识别 C++ 虚函数表

步骤 5: 深度分析
  ├── 交叉引用分析（数据流+控制流）
  ├── 加密算法识别（FindCrypt/IDA Signsrch）
  ├── 网络函数调用链追踪
  └── 配置数据结构提取

步骤 6: 输出
  ├── C2 地址/域名列表
  ├── 加密密钥与算法
  ├── 配置结构定义
  └── 行为总结与 IOC
```

#### 5.2 关键分析技巧

```
=== main() 定位 ===
MSVC x64:   __scrt_common_main_seh -> 跟踪到用户 main()
GCC x64:     __libc_start_main(main_ptr, ...) -> 第一个参数
Clang x64:   类似 GCC
ARM:         __libc_init_array -> 跟踪 .init_array 段

=== C++ 虚函数表恢复 ===
1. 搜索 RTTI typeinfo 结构（若有）
2. 定位 vtable 指针（构造函数中赋值）
3. 跟踪 vtable 中的函数指针
4. 基于使用上下文命名虚函数

=== 算法识别 ===
常量快速识别：
  0x67452301 / 0xEFCDAB89     -> MD5
  0x6A09E667 / 0xBB67AE85     -> SHA-256
  0x9E3779B9                  -> TEA/XTEA
  0x61707865 / 0x3320646E     -> ChaCha20
  0x01234567 / 0x89ABCDEF     -> Blowfish
```

### 6. IDA Pro 工作流

#### 6.1 数据库创建与初始分析

```
=== 加载配置 ===
1. File -> Open -> 选择目标文件
2. Processor type: 自动检测或手动选择（ARM/MIPS 等）
3. Loading segment/offset: 默认即可
4. 勾选 "Create RAM segment"（ARM 固件需要）

=== 初始分析设置 ===
Options -> General -> Analysis:
  - 启用 "Rename tail bytes"
  - 启用 "Create function tails"
  - 设置栈指针追踪

=== 手动分析命令 ===
- Make Code (C):     将字节转为代码
- Make Data (D):     将字节转为数据
- Make Function (P): 创建函数
- Undefine (U):      取消定义
- Set Type (Y):      设置变量/函数类型
```

#### 6.2 类型重建

```c
// === 结构体创建 ===
// View -> Open Subviews -> Local Types
// Insert 键创建新结构体
struct _ConfigBlock {
    /* +0x00 */ DWORD magic;           // 0xDEADBEEF
    /* +0x04 */ DWORD size;
    /* +0x08 */ char server_ip[64];
    /* +0x48 */ WORD server_port;
    /* +0x4A */ WORD interval;
    /* +0x4C */ BYTE encryption_key[32];
    /* +0x6C */ DWORD campaign_id;
};

// 在反编译窗口中应用类型
// 右键变量 -> Set Type -> 输入 struct name *
// 或快捷键 Y
```

#### 6.3 IDAPython 自动化脚本

```python
# === 自动函数重命名（基于字符串引用）===
import idautils
import idc
import ida_bytes

def rename_funcs_by_strings():
    """根据函数引用的字符串自动重命名函数"""
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        if func_name.startswith("sub_"):
            for xref in idautils.XrefsTo(func_ea):
                # 检查调用者函数中的字符串引用
                caller = idc.get_func_name(xref.frm)
                if not caller:
                    continue
                func_start = idc.get_func_attr(xref.frm, idc.FUNCATTR_START)
                func_end = idc.get_func_attr(xref.frm, idc.FUNCATTR_END)
                for head in idautils.Heads(func_start, func_end):
                    for str_xref in idautils.DataRefsFrom(head):
                        s = idc.get_strlit_contents(str_xref)
                        if s and len(s) > 3:
                            new_name = "parse_" + s[:20].decode('utf-8', errors='replace')
                            new_name = ''.join(c if c.isalnum() else '_' for c in new_name)
                            idc.set_name(func_ea, new_name, idc.SN_CHECK)
                            print(f"Renamed {func_name} -> {new_name}")
                            break

# rename_funcs_by_strings()

# === 字符串 XOR 解密自动化 ===
def decrypt_xor_strings(xor_key=0x41):
    """查找并解密 XOR 加密的字符串"""
    for seg in idautils.Segments():
        seg_start = idc.get_segm_start(seg)
        seg_end = idc.get_segm_end(seg)
        for head in idautils.Heads(seg_start, seg_end):
            if idc.is_code(idc.get_full_flags(head)):
                # 查找 XOR 指令
                mnem = idc.print_insn_mnem(head)
                if mnem == "xor":
                    op1 = idc.get_operand_value(head, 0)
                    op2 = idc.get_operand_value(head, 1)
                    if op1 != 0 and op2 != 0 and op1 == op2:
                        continue  # xor reg, reg (清零)
                    # 查找使用该 XOR key 解密的字符串
                    for data_ref in idautils.DataRefsFrom(head):
                        decrypted = []
                        for i in range(64):
                            b = ida_bytes.get_byte(data_ref + i)
                            if b == 0:
                                break
                            decrypted.append(chr(b ^ xor_key))
                        if decrypted:
                            result = ''.join(decrypted)
                            idc.set_cmt(data_ref, f"Decrypted: {result}", 0)
                            print(f"  0x{data_ref:X}: {result}")

# decrypt_xor_strings()

# === C2 地址提取 ===
def extract_c2_addresses():
    """提取二进制中的 C2 地址和端口"""
    import re
    c2_list = []
    for s in idautils.Strings():
        addr = s.ea
        content = str(s)
        # IP 地址模式
        ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content)
        if ip_match:
            for xref in idautils.DataRefsTo(addr):
                func = idaapi.get_func(xref)
                if func:
                    c2_list.append({
                        'address': ip_match.group(),
                        'string_ea': hex(addr),
                        'ref_func': idc.get_func_name(func.start_ea)
                    })
        # URL 模式
        url_match = re.search(r'https?://[^\s\x00"]+', content)
        if url_match:
            for xref in idautils.DataRefsTo(addr):
                func = idaapi.get_func(xref)
                if func:
                    c2_list.append({
                        'url': url_match.group(),
                        'string_ea': hex(addr),
                        'ref_func': idc.get_func_name(func.start_ea)
                    })
    return c2_list

# for c2 in extract_c2_addresses(): print(c2)

# === YARA 签名生成 ===
def generate_yara_from_func(func_ea, rule_name="malware_func"):
    """从函数字节码生成 YARA 规则"""
    func_end = idc.find_func_end(func_ea)
    if func_end == idc.BADADDR:
        return None
    byte_str = ""
    offset = 0
    while func_ea + offset < func_end:
        b = ida_bytes.get_byte(func_ea + offset)
        mnem = idc.print_insn_mnem(func_ea + offset)
        insn_len = idc.get_item_size(func_ea + offset)
        if mnem and insn_len > 1:
            byte_str += f"{b:02X} "
            for i in range(1, insn_len):
                byte_str += "?? "
            offset += insn_len
        else:
            byte_str += f"{b:02X} "
            offset += 1
    rule = f"""rule {rule_name} {{
    meta:
        description = "Generated from function at 0x{func_ea:X}"
        author = "IDA Auto-Generated"
    strings:
        $s1 = {{ {byte_str.strip()} }}
    condition:
        $s1
}}"""
    return rule

# print(generate_yara_from_func(0x401000))
```

#### 6.4 IDA 插件生态

```
=== 必装插件 ===
FindCrypt:     加密常量识别（AES/DES/RC4/RSA）
Keypatch:      汇编级 patch 编辑器
LazyIDA:       快捷操作集合（复制数据、跳转等）
IDACython:     完整 Python3 脚本支持
shellcode_hashes: shellcode API 哈希解析
fixrewolf:     Go 二进制类型恢复

=== FLIRT 签名匹配 ===
1. File -> Load file -> FLIRT signature file
2. 常用签名：vc32rtf (MSVC), gcc сигнатуры (GCC)
3. 自动标记库函数为已识别

=== 远程调试 ===
1. 目标机器运行 linux_server64 / win32_remote.exe
2. Debugger -> Select remote debugger
3. 配置 IP:端口 -> Attach to process

=== 批量分析模式 ===
ida64 -B target.exe                    # 批量分析生成 .idb
ida64 -S"script.py" target.exe         # 运行脚本后退出
ida64 -A -S"analysis.py" target.exe    # 自动分析模式
```

### 7. Ghidra 工作流

#### 7.1 项目创建与分析

```
=== 导入与分析 ===
1. File -> New Project -> 创建非共享项目
2. 拖入目标文件 -> Import 对话框
3. 分析选项：
   - 勾选 "Decompiler Parameter ID"
   - 勾选 "Reference"
   - 取消 "Emulate"（除非需要）
   - ARM 目标: 勾选 "ARM"
   - MIPS 目标: 勾选 "MIPS"

=== 反编译器使用 ===
- Window -> Decompile: 打开反编译窗口
- 右键变量 -> Rename: 重命名
- 右键变量 -> Retype Variable: 修改类型
- Edit -> Function -> Edit Function: 修改函数签名
- Search -> For Strings: 字符串搜索
```

#### 7.2 Ghidra 脚本（Java）

```java
// === 自动函数重命名脚本 (Ghidra Java) ===
// @category Binary Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class RenameFunctionsByStrings extends GhidraScript {
    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        DataIterator dataIter = listing.getDefinedData(true);

        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                String str = data.getDefaultValueRepresentation();
                if (str.length() < 4) continue;
                Reference[] refs = getReferencesTo(data.getAddress());
                for (Reference ref : refs) {
                    Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                    if (func != null && func.getName().startsWith("FUN_")) {
                        String cleanName = "parse_" + str.substring(0, Math.min(20, str.length()));
                        cleanName = cleanName.replaceAll("[^a-zA-Z0-9_]", "_");
                        func.setName(cleanName, SourceType.USER_DEFINED);
                        println("Renamed " + func.getEntryPoint() + " -> " + cleanName);
                    }
                }
            }
        }
    }
}

// === 配置结构提取脚本 ===
// @category Binary Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class ExtractConfigStruct extends GhidraScript {
    @Override
    public void run() throws Exception {
        StructureDataType config = new StructureDataType("ConfigBlock", 0);
        config.add(DWordDataType.dataType, 4, "magic", "Magic value 0xDEADBEEF");
        config.add(DWordDataType.dataType, 4, "size", "Config block size");
        config.add(StringDataType.dataType, 64, "server_ip", "C2 server IP");
        config.add(WordDataType.dataType, 2, "server_port", "C2 port");
        config.add(WordDataType.dataType, 2, "interval", "Beacon interval");
        config.add(new ArrayDataType(ByteDataType.dataType, 32, 1), 32,
                   "encryption_key", "AES-256 key");
        config.add(DWordDataType.dataType, 4, "campaign_id", "Campaign ID");

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        dtm.addDataType(config, DataTypeConflictHandler.DEFAULT_HANDLER);
        println("Created ConfigBlock structure");
    }
}
```

#### 7.3 Ghidra 高级功能

```
=== 版本追踪 (Version Tracking) ===
1. File -> New Tool -> Version Tracking
2. 添加源程序和目标程序
3. 创建 VT Session
4. 自动匹配：签名匹配 + 函数体匹配
5. 手动确认匹配结果

=== Headless 分析 ===
analyzeHeadless /project/path ProjectName \
    -import target.exe \
    -postScript analysis.py \
    -deleteProject \
    -scriptPath /path/to/scripts

=== Ghidra 扩展 ===
Ghidrallinator:  Go 二进制类型恢复
Ghidra2Docker:   容器化分析环境
SVD-Loader:      ARM SVD 外设寄存器加载
```

### 8. VM/字节码逆向

#### 8.1 VM 入口/出口识别

```
=== VM 入口特征 ===
x86/x64:
  pusha/pushad 或 push rax,rcx,rdx...  (保存所有寄存器)
  sub rsp, N                            (分配 VM context 空间)
  mov [rsp+offset], reg                 (初始化虚拟寄存器)
  lea reg, [handler_table]              (加载 handler 表地址)
  jmp dispatcher                        (跳转到分发器)

ARM:
  push {r0-r12, lr}                     (保存寄存器)
  sub sp, sp, #N                        (分配 VM context)
  str r0, [sp, #offset]                 (初始化虚拟寄存器)
  ldr pc, handler_table                 (跳转到分发器)

=== VM Dispatcher 特征 ===
  movzx reg, byte ptr [VM_PC]          (读取 opcode)
  mov reg2, [handler_table + reg*size] (查表获取 handler 地址)
  jmp reg2                              (跳转到 handler)
  ; 或 switch-case 结构

=== VM Exit 特征 ===
  popa/popad 或 pop rax,rcx,rdx...    (恢复寄存器)
  add rsp, N                            (释放 VM context)
  ret 或 jmp original_code              (返回宿主代码)
```

#### 8.2 Handler 分析与指令集映射

```
=== Handler 分析方法 ===
1. 在 dispatcher 设断点
2. 记录每个 handler 的 opcode 编号
3. 分析每个 handler 的语义（实际 CPU 操作）
4. 建立映射表：

Opcode | Handler Address | Semantic
-------|-----------------|--------
0x01   | 0x40A120        | vADD (vreg[op1] += vreg[op2])
0x02   | 0x40A1F0        | vSUB (vreg[op1] -= vreg[op2])
0x03   | 0x40A300        | vMOV (vreg[op1] = vreg[op2])
0x10   | 0x40A410        | vPUSH (vstack[++vsp] = vreg[op1])
0x11   | 0x40A520        | vPOP  (vreg[op1] = vstack[vsp--])
0x20   | 0x40A630        | vJMP  (vPC = vreg[op1])
0xFF   | 0x40A740        | vEXIT (restore host context)

=== 自动化 Handler 记录 ===
x64dbg 脚本：在 dispatcher 设条件日志断点
  条件: 1
  日志: "OPCODE: {byte:[VM_PC]}, HANDLER: {p:[handler_table + byte:[VM_PC]*4]}"

=== 工具辅助 ===
VMHunt:   基于 Trace 的 VM 分析（Intel PIN）
VMAttack: IDA 插件，自动化 VM handler 识别
VMStrip:  基于符号执行的字节码提升
```

### 9. 网络协议逆向

#### 9.1 协议分析流程

```
步骤 1: 流量捕获与关联
  ├── 同时运行样本 + Wireshark 捕获
  ├── 记录每个网络操作的时间戳
  └── 在 IDA/Ghidra 中定位 send/recv/WSASend/WSARecv 调用

步骤 2: 协议结构识别
  ├── 比较多个请求/响应的相同部分（固定头部）
  ├── 识别长度字段（通常在偏移 +2 或 +4）
  ├── 识别命令/操作码字段（通常在偏移 +0 或 +1）
  └── 检测 magic bytes（协议标识符）

步骤 3: 加密/编码检测
  ├── 高熵数据段 = 可能加密
  ├── Base64 特征字符集 (A-Za-z0-9+/=)
  ├── XOR 加密：已知明文攻击（如 HTTP 头部）
  └── 定位加密函数（send 前的最后变换）

步骤 4: 协议状态机重建
  ├── 记录操作码序列
  ├── 识别请求-响应对
  ├── 建立状态转换图
  └── 文档化协议规范

步骤 5: 自定义解析器
  ├── 基于 Scapy 构建协议层
  ├── 或 Python struct 模块手动解析
  └── 集成到分析管道
```

#### 9.2 IDA/Ghidra 网络函数分析

```python
# === IDAPython: 网络函数调用链追踪 ===
import idautils
import idc

NETWORK_APIS = [
    'send', 'recv', 'sendto', 'recvfrom',
    'WSASend', 'WSARecv', 'WSASendTo', 'WSARecvFrom',
    'connect', 'WSAConnect', 'InternetOpenA', 'HttpSendRequestA',
    'WinHttpSendRequest', 'WinHttpWriteData'
]

def trace_network_calls():
    """追踪所有网络 API 调用及其调用链"""
    for ea, name in idautils.Names():
        if name in NETWORK_APIS:
            print(f"\n=== API: {name} @ 0x{ea:X} ===")
            for xref in idautils.CodeRefsTo(ea, 0):
                func = idaapi.get_func(xref)
                caller = idc.get_func_name(func.start_ea) if func else "unknown"
                print(f"  Called from {caller} @ 0x{xref:X}")
                for head in idautils.Heads(func.start_ea, xref):
                    mnem = idc.print_insn_mnem(head)
                    if mnem == 'lea' or mnem == 'mov':
                        pass  # 检查缓冲区参数

# trace_network_calls()
```

#### 9.3 自定义协议解析器

```python
# === Scapy 自定义协议层 ===
from scapy.all import *

class MalwareProto(Packet):
    name = "MalwareC2"
    fields_desc = [
        ByteField("magic", 0xDE),
        ByteField("version", 1),
        ShortField("length", None),
        ByteEnumField("cmd", 0, {
            0x01: "HEARTBEAT",
            0x02: "CMD_EXEC",
            0x03: "FILE_UPLOAD",
            0x04: "FILE_DOWNLOAD",
            0x05: "SCREENSHOT",
            0x10: "SHUTDOWN"
        }),
        ByteField("flags", 0),
        IntField("seq_num", 0),
        StrField("payload", "", remain=True)
    ]

    def post_build(self, pkt, pay):
        if self.length is None:
            self.length = len(pkt) + len(pay)
            pkt = struct.pack("<H", self.length) + pkt[2:]
        return pkt + pay

bind_layers(TCP, MalwareProto, dport=4444)
```

### 10. 二进制保护绕过

#### 10.1 UPX 脱壳

```bash
# === 标准 UPX 脱壳 ===
upx -d target.exe -o unpacked.exe

# === 修改头 UPX（upx -d 失败时）===
# 方法 1: 修复 UPX 头部魔数
# 在 HEX 编辑器中搜索 UPX! 魔数，修复被修改的字节
# 然后重新运行 upx -d

# 方法 2: 手动脱壳
# 1. 在 x64dbg 中加载
# 2. 在 VirtualAlloc 设断点（UPX 在此解压）
# 3. 运行到断点后，单步到 ret
# 4. 此时 EIP/RIP 指向 OEP
# 5. 使用 Scylla dump 进程
```

#### 10.2 通用脱壳方法

```
=== ESP/字节模式法（通用）===
1. 在入口点记录 ESP 值
2. 在 ESP 地址设硬件写入断点
3. 运行程序 -- 壳解压完成后恢复 ESP
4. 断点触发 = 接近 OEP
5. 单步执行直到看到正常程序代码

=== 断点返回法 (Break-on-Return) ===
1. 在入口点设断点
2. 分析入口代码找到第一个 call/jmp
3. 跟踪到壳的主解压循环
4. 在解压循环后的 ret 设断点
5. 运行到 ret = 到达 OEP

=== OEP 识别特征 ===
- MSVC:  push ebp / mov ebp, esp / sub esp, N
- GCC:   push rbp / mov rbp, rsp / sub rsp, N
- 大量 mov/movabs 指令（全局变量初始化）
- 调用 __security_init_cookie (MSVC)
- 调用 CRT init 函数

=== 导入表重建 (Scylla) ===
1. 在 OEP 暂停
2. 打开 Scylla -> 附加进程
3. IAT Autosearch -> 自动定位 IAT
4. Get Imports -> 扫描导入
5. Fix Dump -> 选择 dump 文件修复
6. 验证：用 CFF Explorer / PE Studio 检查导入表
```

#### 10.3 VMProtect 分析工作流

```
1. 识别被保护函数（区段 .vmp0/.vmp1）
2. 在 VM 入口设断点：
   - 查找 pusha/pushad 序列
   - 或 sub esp, large_number + 寄存器保存
3. 跟踪 VM dispatcher：
   - 记录 opcode 读取位置
   - 识别 handler 分发机制
4. 逐个 handler 分析语义
5. 编写字节码反汇编器
6. 重建原始控制流

工具辅助：
- VMPDump 插件
- VMProtect Devirtualizer (BlackHat 工具)
- TENet - Trace-based analysis
```

### 11. 符号恢复与调试

#### 11.1 PDB 符号恢复

```
=== 本地 PDB 匹配 ===
1. File -> Load file -> PDB file
2. IDA 自动匹配函数地址与符号名
3. 类型信息自动导入

=== 符号服务器 ===
# Microsoft 公共符号服务器
srv*C:\Symbols*https://msdl.microsoft.com/download/symbols

# IDA 配置：Options -> Debug -> Symbol path
# 或使用 symchk 工具下载
symchk /if target.exe /s srv*C:\Symbols*https://msdl.microsoft.com/download/symbols

=== PDB 重建（无原始 PDB 时）===
# 使用 IDAPython 根据函数特征恢复符号
# 1. FLIRT 签名匹配已知库函数
# 2. Lumina 服务器查询
# 3. 手动分析重命名
```

#### 11.2 RTTI 类重建

```python
# === IDAPython RTTI 恢复脚本 ===
import idautils, idc, ida_bytes

def find_rtti_structures():
    """搜索 RTTI type_info 结构"""
    for seg in idautils.Segments():
        seg_name = idc.get_segm_name(seg)
        if '.rdata' not in seg_name:
            continue
        ea = idc.get_segm_start(seg)
        seg_end = idc.get_segm_end(seg)
        while ea < seg_end:
            vtbl_ptr = ida_bytes.get_qword(ea)
            if vtbl_ptr != 0:
                name_ea = ea + 8  # x64
                name_bytes = ida_bytes.get_strlit_contents(name_ea, -1, 0)
                if name_bytes:
                    class_name = name_bytes.decode('utf-8', errors='replace')
                    if class_name.startswith('.?AV'):
                        print(f"  RTTI @ 0x{ea:X}: {class_name}")
            ea += 8

# find_rtti_structures()
```

#### 11.3 Go/Rust 符号恢复

```
=== Go 二进制符号恢复 ===
# Go 二进制通常包含完整符号信息（即使 stripped）
# 符号格式：main.someFunction, runtime.gcBgMarkWorker

# 方法 1: go_parser (IDAPython)
# https://github.com/0xjiayu/go_parser
# 自动恢复 Go 函数名、类型、字符串

# 方法 2: Ghidra Go 脚本
# 分析 pclntab (PC-Line Table) 恢复函数名
# Go 1.16+: pclntab 位于 .gopclntab 段

# 方法 3: 手动定位 pclntab
# 搜索 magic: 0xFFFFFFF1 (Go 1.16+) 或 0xFFFFFFF0 (Go 1.2-1.15)
# 解析函数名表

=== Rust 符号恢复 ===
# Rust 符号格式（需 demangle）：
# _ZN4core6option15Option$LT$T$GT$6unwrap17habc123E
# 使用 rustfilt 工具 demangle:
rustfilt < symbols.txt > demangled.txt

# IDA 中的 Rust 类型恢复：
# 1. 搜索 "rust_panic" 字符串定位运行时
# 2. 查找 Drop trait 实现识别析构函数
# 3. 使用 Ghidra Rust 分析器扩展
```

### 12. 自动化分析脚本

#### 12.1 x64dbg 反调试绕过脚本

```
// === x64dbg 脚本：批量绕过反调试 ===
// 将以下脚本保存为 antidebug.txt，在 x64dbg 命令行执行

// 绕过 IsDebuggerPresent
bp IsDebuggerPresent
loop1:
    run
    log "IsDebuggerPresent called from {p}"
    r eax = 0
    run
    cmp eip, IsDebuggerPresent
    jne loop1

// 绕过 CheckRemoteDebuggerPresent
bp CheckRemoteDebuggerPresent
loop2:
    run
    log "CheckRemoteDebuggerPresent called"
    // 设置 *pbDebuggerPresent = FALSE
    mov [arg2], 0
    r eax = 1
    run
    cmp eip, CheckRemoteDebuggerPresent
    jne loop2
```

#### 12.2 IDAPython 配置提取脚本

```python
# === 恶意软件配置提取器 ===
import idautils
import idc
import ida_bytes
import re

def extract_malware_config():
    """提取恶意软件配置数据（C2、密钥、URL等）"""
    config = {'urls': [], 'ips': [], 'keys': [], 'mutex': [], 'registry': []}

    for s in idautils.Strings():
        content = str(s)
        addr = s.ea

        # URL 提取
        if content.startswith('http://') or content.startswith('https://'):
            config['urls'].append({'value': content, 'addr': hex(addr)})

        # IP 地址提取
        ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', content)
        if ip:
            config['ips'].append({'value': content, 'addr': hex(addr)})

        # 注册表键提取
        if 'SOFTWARE\\' in content or 'HKEY_' in content or '\\CurrentVersion\\' in content:
            config['registry'].append({'value': content, 'addr': hex(addr)})

        # 互斥体提取
        if 'Global\\' in content or 'Local\\' in content:
            config['mutex'].append({'value': content, 'addr': hex(addr)})

        # 可能的加密密钥（Base64 或长随机字符串）
        if len(content) == 44 and content.endswith('=='):
            config['keys'].append({'value': content, 'addr': hex(addr), 'type': 'base64_32byte'})

    return config

# === 输出配置 ===
# cfg = extract_malware_config()
# for category, items in cfg.items():
#     print(f"\n=== {category.upper()} ===")
#     for item in items:
#         print(f"  {item}")
```

#### 12.3 Ghidra Python 配置提取

```python
# === Ghidra Jython 配置提取脚本 ===
# @category Malware Analysis
from ghidra.program.model.symbol import SourceType

def extract_config_ghidra():
    listing = currentProgram.getListing()
    dataIterator = listing.getDefinedData(True)
    config = {'urls': [], 'ips': [], 'strings': []}

    while dataIterator.hasNext():
        data = dataIterator.next()
        if data.hasStringValue():
            val = data.getDefaultValueRepresentation().strip('"')
            addr = data.getAddress()

            if val.startswith("http"):
                config['urls'].append({'value': val, 'addr': str(addr)})
            if "." in val and len(val.split(".")) == 4:
                config['ips'].append({'value': val, 'addr': str(addr)})
            if len(val) > 8:
                config['strings'].append({'value': val, 'addr': str(addr)})

    return config

# cfg = extract_config_ghidra()
# for k, v in cfg.items():
#     if v:
#         print("\n=== %s ===" % k.upper())
#         for item in v:
#             print("  %s @ %s" % (item['value'], item['addr']))
```

---

## 速查表

### 反调试技术检测与绕过矩阵

| 技术 | API/方法 | 检测原理 | 绕过方法 | IDA/x64dbg 命令 |
|------|----------|----------|----------|-----------------|
| IsDebuggerPresent | kernel32 | PEB.BeingDebugged | patch 返回 0 | `r eax=0` after bp |
| CheckRemoteDebugger | kernel32 | NtQueryInfoProcess | hook NtQuery | ScyllaHide 插件 |
| NtQueryInfoProcess(Port) | ntdll | ProcessDebugPort=7 | 返回 STATUS_PORT_NOT_SET | conditional bp + log |
| NtQueryInfoProcess(Object) | ntdll | ProcessDebugObjectHandle=30 | 返回 NULL handle | hook 返回值 |
| PEB.BeingDebugged | 直接读取 | gs:[60h]+2 != 0 | patch PEB 字节为 0 | `eb peb_addr+2 0` |
| PEB.NtGlobalFlag | 直接读取 | gs:[60h]+68h == 0x70 | patch 为 0 | `ed peb_addr+68 0` |
| Heap Flags | 直接读取 | ForceFlags!=0 | patch 为正常值 | `ed heap+44 2; ed heap+48 0` |
| RDTSC 时序 | rdtsc 指令 | 差值过大 | hook rdtsc 返回固定值 | ScyllaHide |
| INT 2D | int 2dh | 调试器单步跳过 NOP | 在 int 2D 后设 bp | 手动跳过 |
| 硬件断点检测 | GetThreadContext | DR0-DR3 != 0 | 清除调试寄存器 | `dr0=0;dr1=0;dr2=0;dr3=0` |
| 父进程检测 | CreateToolhelp32 | 非 explorer.exe | 从 explorer 启动 | CreateProcess from explorer |
| Toolhelp 枚举 | Process32First/Next | 查找调试器进程名 | 重命名 x64dbg.exe | 修改进程名 |

### 二进制保护特征对照表

| 保护器 | 区段特征 | 熵值 | 反调试 | 脱壳方法 |
|--------|----------|------|--------|----------|
| UPX | UPX0/UPX1/UPX2 | <7.0 | 无 | `upx -d` 或手动 OEP+dump |
| Themida | .themida | >7.5 | 多层(API+时序+线程) | VM 分析 + trace |
| VMProtect | .vmp0/.vmp1 | >7.0 | API+VM检测 | Handler 分析 + 反VM |
| Enigma | .enigma1/.enigma2 | >7.5 | API+完整性 | OEP 断点 + Scylla |
| ASProtect | .aspack | >7.0 | API检测 | ESP 法 + IAT 重建 |
| MPRESS | .MPRESS1/.MPRESS2 | ~7.0 | 少量 | OEP 断点 + dump |
| Armadillo | 无特殊区段 | 变化 | 多层+驱动级 | 内存 dump + 重建 |
| Obsidium | .obsidium | >7.0 | API+VM | 定位解密 + dump |
| PELock | 无特殊区段 | >6.5 | API+完整性 | 断点返回法 |

### IDAPython 常用脚本速查

| 任务 | API | 示例 |
|------|-----|------|
| 重命名函数 | `idc.set_name(ea, name)` | `idc.set_name(0x401000, "parse_config", idc.SN_CHECK)` |
| 获取函数名 | `idc.get_func_name(ea)` | `name = idc.get_func_name(0x401000)` |
| 遍历函数 | `idautils.Functions()` | `for ea in idautils.Functions(): print(hex(ea))` |
| 交叉引用到 | `idautils.XrefsTo(ea)` | `for x in idautils.XrefsTo(0x401000): print(hex(x.frm))` |
| 交叉引用从 | `idautils.DataRefsFrom(ea)` | `for r in idautils.DataRefsFrom(ea): print(hex(r))` |
| 读字节 | `ida_bytes.get_byte(ea)` | `b = ida_bytes.get_byte(0x401000)` |
| 写字节 | `ida_bytes.patch_byte(ea, val)` | `ida_bytes.patch_byte(0x401000, 0x90)` |
| 设置注释 | `idc.set_cmt(ea, text, 0)` | `idc.set_cmt(0x401000, "C2 server", 0)` |
| 遍历字符串 | `idautils.Strings()` | `for s in idautils.Strings(): print(str(s))` |
| 获取段信息 | `idaapi.get_segm_by_name(name)` | `seg = idaapi.get_segm_by_name(".text")` |
| 创建结构体 | `ida_struct.add_struc()` | `sid = idc.add_struc(-1, "ConfigBlock", 0)` |

### Ghidra 脚本速查

| 任务 | Java API | 示例 |
|------|----------|------|
| 重命名函数 | `func.setName(name, src)` | `func.setName("parse_config", SourceType.USER_DEFINED)` |
| 获取函数 | `getFunctionAt(addr)` | `func = getFunctionAt(toAddr(0x401000))` |
| 遍历函数 | `funcMgr.getFunctions(true)` | `for f in funcMgr.getFunctions(True): print(f)` |
| 交叉引用 | `getReferencesTo(addr)` | `refs = getReferencesTo(addr)` |
| 读字节 | `getByte(addr)` | `b = getByte(toAddr(0x401000))` |
| 设置注释 | `setPlateComment(addr, text)` | `setPlateComment(toAddr(0x401000), "C2 server")` |
| 创建数据类型 | `StructureDataType(name, size)` | `s = StructureDataType("Config", 0)` |
| 字符串搜索 | `getString(addr)` | `s = getString(toAddr(0x401000))` |
| 输出日志 | `println(text)` | `println("Found C2: " + url)` |
| 获取当前程序 | `currentProgram` | `listing = currentProgram.getListing()` |

### 协议逆向步骤决策树

```
开始协议逆向
│
├─ 是否有流量样本？
│   ├─ 否 → 运行样本 + Wireshark 捕获
│   └─ 是 ↓
│
├─ 流量是否加密/编码？
│   ├─ 是 → 在二进制中定位解密函数
│   │       ├─ 搜索 send/recv 调用链
│   │       ├─ 在 send 前设断点查看明文
│   │       └─ 提取加密密钥和算法
│   └─ 否 ↓
│
├─ 是否有固定头部？
│   ├─ 是 → 提取 magic + version + length 字段
│   └─ 否 → 使用差分分析多个包识别固定/变化部分
│       ↓
│
├─ 识别操作码字段
│   ├─ 比较不同类型包的第一个字节差异
│   ├─ 映射操作码到功能（HEARTBEAT/CMD/UPLOAD等）
│   └─ 在二进制中验证：搜索 switch(opcode) 结构
│       ↓
│
├─ 重建状态机
│   ├─ 记录操作码序列和依赖关系
│   ├─ 识别请求-响应对
│   └─ 绘制状态转换图
│       ↓
│
└─ 编写解析器
    ├─ Scapy 协议层
    ├─ Python struct 模块
    └─ 集成到分析工具
```

---

## MITRE ATT&CK 映射

| 战术 | 技术 ID | 技术名称 | 关联 |
|------|---------|----------|------|
| Defense Evasion | T1027.002 | Obfuscated Files - Software Packing | 加壳规避分析 |
| Defense Evasion | T1027.007 | Dynamic API Resolution | API 哈希导入 |
| Defense Evasion | T1027.009 | Embedded Payloads | 嵌入式 payload 提取 |
| Defense Evasion | T1140 | Deobfuscate/Decode Files | 运行时解密 |
| Defense Evasion | T1560.001 | Archive via Custom Method | 自定义编码/加密 |
| Defense Evasion | T1027.001 | Binary Padding | 填充干扰签名 |
| Discovery | T1082 | System Information Discovery | 恶意软件侦察逻辑 |
| Discovery | T1057 | Process Discovery | 反调试中的进程枚举 |
| Command & Control | T1071 | Application Layer Protocol | C2 协议分析 |
| Command & Control | T1573 | Encrypted Channel | C2 加密通信 |
| Command & Control | T1095 | Non-Application Layer Protocol | 自定义 TCP/UDP 协议 |

---

## 前置条件清单

- [ ] IDA Pro 7.x+ 含 Hex-Rays（或 Ghidra 10.x+）
- [ ] x64dbg + ScyllaHide 插件（动态调试 + 反反调试）
- [ ] Python 3.x 环境（自动化脚本）
- [ ] Wireshark（协议逆向）
- [ ] YARA 工具（签名生成与验证）
- [ ] 了解 PE/ELF 文件格式
- [ ] 了解 x86/x64/ARM 汇编指令集
- [ ] 熟悉 Windows API（进程、内存、网络）

---

## Part C：2025-2026 前沿补充

> 联网复核增补。主要来源：Hex-Rays 官方博客、NSA Ghidra 发布、GitHub 生态、Springer/arXiv 论文、奇安信/看雪/FreeBuf 中文社区。

### C.1 AI/LLM 辅助逆向工程

2025-2026 年最显著的行业变化是大语言模型（LLM）与逆向工程工具的深度融合。

#### C.1.1 MCP 桥接 IDA Pro / Ghidra

Model Context Protocol（MCP）使 LLM Agent 能直接操控反编译器，实现自动化分析闭环。

```
=== ida-pro-mcp（mrexodia）===
GitHub: https://github.com/mrexodia/ida-pro-mcp
要求：IDA Pro 8.3+（推荐 v9），Python 3.11+
功能：
  - 函数反编译 + 重命名 + 类型标注（LLM 驱动）
  - 交叉引用查询 + 调用图生成
  - 字符串解密 + 配置提取
  - YARA 签名生成
兼容：Claude、Cursor、VS Code Copilot 等任意 MCP 客户端

=== GhidraMCP（LaurieWired）===
GitHub: https://github.com/LaurieWired/GhidraMCP
功能：类似 ida-pro-mcp，基于 Ghidra 的自动化逆向
特点：无需 IDA 许可证，完全开源
更新：2025-06 持续维护

=== IDAssist（Hex-Rays 官方插件库）===
链接：https://plugins.hex-rays.com/symgraph/IDAssist/IDAssist
功能：LLM 分析集成到 IDA 界面内部
```

#### C.1.2 Hex-Rays 2026 产品方向

```
官方博客：https://hex-rays.com/blog/2026-product-direction-priorities
关键信号：
  - 将提供 LLM-friendly API（领域驱动的人机两用接口）
  - 新 RE 工具将以 IDA 插件形式发布
  - 深度技术分析能力增强
  - 性能优化（大文件/固件分析）

影响：官方开始拥抱 AI 辅助 RE，MCP 集成将从社区走向官方支持
```

#### C.1.3 奇安信 ReCopilot

```
链接：https://tqgpt.qianxin.com/recopilot/
定位：智能逆向工程助手
能力：
  - 结合 LLM 与 RE 专业知识
  - 自动函数识别与命名建议
  - 恶意软件行为总结
  - 配置数据自动提取
```

#### C.1.4 LLM 辅助 RE 实战模式

```python
# === IDA + DeepSeek/Claude 逆向分析工作流 ===
# 1. 通过 ida-pro-mcp 连接 LLM
# 2. 发送反编译伪代码给 LLM
# 3. LLM 返回：函数用途推断、变量命名建议、漏洞发现
# 4. 自动应用重命名和注释

# 典型 Prompt 模板：
# "分析以下反编译代码，识别：
#  1. 函数用途（一句话）
#  2. 关键变量命名建议
#  3. 潜在安全漏洞
#  4. 加密算法识别（如有）
#  代码：[粘贴反编译输出]"

# Cisco Talos 研究证实 LLM 可作为 RE 侧翼助手
# 参考：https://blog.talosintelligence.com/using-llm-as-a-reverse-engineering-sidekick/
```

### C.2 工具生态重大更新

#### C.2.1 Ghidra 11.3-11.4（2025-2026）

```
=== Ghidra 11.3（2025-02 发布）===
关键新特性：
  1. JIT 加速 P-Code 模拟器
     - 大幅提升动态分析性能
     - 支持 P-Code 级别断点和单步
     - 用途：恶意软件行为模拟、VM handler 跟踪

  2. 内置 Python 3 支持（基于 Pyhidra）
     - 不再需要 Jython
     - 完整 Python 3 生态可用（numpy、requests 等）

  3. 内核级调试
     - 支持内核模块调试
     - 驱动逆向分析增强

  4. VS Code 集成
     - Ghidra 脚本开发环境改进

  5. 新函数图布局
     - 更清晰的控制流可视化

=== Ghidra 11.4.x（2025-2026）===
关键增强：
  1. 符号传播器改进（SymbolicPropogator）
     - 记录分析前后的 pre/post 值
     - P-Code 级分析精度提升

  2. 持续的 JIT 模拟器性能优化
```

#### C.2.2 Binary Ninja 5.3 Jotunheim（2026-04）

```
官方：https://binary.ninja/2026/04/13/binary-ninja-5.3-jotunheim.html
核心特性：
  1. 跨反编译器互操作性
     - 与 Ghidra 和 IDA 数据交换增强
     - 符号、类型、注释可在工具间迁移
     - 导入/导出 IDA 数据库和 Ghidra 项目

  2. NDS32 架构反编译支持
     - AndesCore NDS32 处理器
     - 嵌入式/IoT 固件分析

  3. 新平台和调试器特性
```

#### C.2.3 工具选择决策树（2025-2026 更新）

```
选择逆向工具
│
├─ 预算充足 + 专业场景？
│   └─ 是 → IDA Pro 9.x + Hex-Rays
│       ├── 最佳 FLIRT/Lumina 签名库
│       ├── MCP 生态最成熟（ida-pro-mcp）
│       └─ 2026 官方 LLM API 支持
│
├─ 免费开源 + 学术/研究？
│   └─ 是 → Ghidra 11.3+
│       ├── JIT P-Code 模拟器
│       ├── 内置 Python 3
│       ├── GhidraMCP（开源 AI 辅助）
│       └── 版本追踪功能
│
├─ API 优先 + 自动化管线？
│   └─ 是 → Binary Ninja 5.3
│       ├── Python API 最友好
│       ├── 跨反编译器互操作
│       └── 批量分析首选
│
└─ 轻量级 + CTF/快速分析？
    └─ 是 → Radare2/rizin + r2ghidra
        ├── 命令行高效
        └── r2ghidra 反编译集成
```

### C.3 VM/字节码脱虚拟化前沿

#### C.3.1 LLVM-IR 提升方法

```
=== 核心思路 ===
将 VM 字节码提升（lift）到 LLVM 中间表示（IR），
然后利用 LLVM 优化 pass 恢复原始代码语义。

=== 两条路径 ===
路径 1：静态提升（Static Lifting）
  - 将 VM 视为 White-Box，逆向其内部结构
  - 提取 handler 表 + 字节码
  - 将每个 handler 转译为 LLVM-IR
  - 运行 LLVM 优化 pass（常量折叠、死代码消除、控制流简化）
  参考：hackyboiz 2025 研究
  链接：https://hackyboiz.github.io/2025/09/11/banda/LLVM_based_VMP/en/

路径 2：动态追踪（Dynamic Tracing）
  - 使用 Triton/Intel PIN 执行追踪
  - 记录每条 VM 指令的实际效果
  - 将 trace 提升到 LLVM-IR
  - 优点：不依赖 VM 结构逆向
  参考：JonathanSalwan/VMProtect-devirtualization
  链接：https://github.com/JonathanSalwan/VMProtect-devirtualization
```

#### C.3.2 实战工具与方法

```python
# === VMProtect 脱虚拟化工作流（2025-2026 最新）===
# 基于 Triton 符号执行引擎

# 步骤 1：识别被保护函数边界
# - 通过 .vmp0/.vmp1 区段定位
# - 或通过运行时断点

# 步骤 2：符号执行追踪
from triton import TritonContext, ARCH

ctx = TritonContext(ARCH.X86_64)
# 设置符号化输入
# 运行 VM 执行 trace

# 步骤 3：LLVM-IR 提升
# 将 Triton 的符号表达式转换为 LLVM-IR
# 使用 JonathanSalwan 的框架或自定义 lifter

# 步骤 4：LLVM 优化
# opt -O2 lifted.ll -o optimized.ll
# 应用：常量传播、死代码消除、控制流平坦化还原

# 步骤 5：重新编译
# llc optimized.ll -o recovered.s
# 或 clang optimized.ll -o recovered_function
```

#### C.3.3 Themida 静态脱虚拟化（2026 突破）

```
来源：Back Engineering Labs（2026-09）
链接：https://back.engineering/blog/09/05/2026/
关键贡献：
  - 实现了 CodeVirtualizer/Themida 保护的静态脱虚拟化
  - 技术方法广泛适用于其他虚拟化保护器（包括 VMProtect）
  - 不依赖运行时追踪，纯静态分析
  - 核心步骤：
    1. VM 结构自动识别
    2. Handler 语义提取
    3. 字节码到 LLVM-IR 映射
    4. 优化恢复原始代码
```

#### C.3.4 学术前沿：Tigress 混淆静态检测

```
论文：arXiv 2601.12916（2026-01）
标题：Static Detection of Core Structures in Tigress Virtualization-Based Obfuscation
贡献：
  - 纯静态分析方法识别虚拟化混淆的核心结构
  - 无需执行追踪
  - 可应用于自动化脱虚拟化工具链
```

### C.4 eBPF 辅助二进制分析

#### C.4.1 eBPF 作为逆向工程工具

```
=== SSL 流量拦截（无需代理）===
场景：目标使用 BoringSSL 静态链接（如 Claude Code Bun 二进制 213MB stripped）
方法：
  1. 使用 eBPF uprobe 挂钩 SSL_read/SSL_write
  2. 在内核层拦截加密前的明文
  3. 无需修改二进制或配置代理
工具链：
  - bpftrace：快速原型
  - BCC（BPF Compiler Collection）：完整工具
  - 自定义 eBPF 程序：精确控制

# bpftrace 示例：挂钩 SSL_write 提取明文
uprobe:/path/to/binary:SSL_write
{
    printf("SSL_write: %s\n", str(arg2));
}

参考：https://medium.com/@yunwei356/reverse-engineering-claude-codes-ssl-traffic-with-ebpf-1dde03bcc7ef
```

#### C.4.2 eBPF 恶意软件分析

```
=== LinkPro eBPF Rootkit 分析（Synacktiv）===
链接：https://synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis
特点：
  - 使用 eBPF 程序实现反向连接后门
  - 通过 eBPF 监听 C2 命令（无需用户态守护进程）
  - 分析方法：反编译 eBPF 字节码 + 行为追踪

=== eBPF 字节码逆向基础 ===
Mercari 工程博客提供了 eBPF 逆向入门指南：
https://engineering.mercari.com/en/blog/entry/20240228-an-introduction-to-reverse-engineering-for-ebpf-bytecode
核心概念：
  - eBPF 程序结构（BPF 指令集）
  - Map 数据结构分析
  - Helper 函数调用识别
  - 使用 llvm-objdump 反汇编 eBPF 字节码
```

### C.5 中文社区精华参考

| 来源 | 主题 | 链接 |
|------|------|------|
| 看雪论坛 | AI 时代逆向工作者如何用好 LLM | [bbs.kanxue.com/thread-289245](https://bbs.kanxue.com/thread-289245.htm) |
| 奇安信 | ReCopilot 智能逆向助手 | [tqgpt.qianxin.com/recopilot](https://tqgpt.qianxin.com/recopilot/) |
| GitHub | ai-reverse-toolkit 逆向 AI Skills 工具集 | [github.com/zhizhuodemao/ai-reverse-toolkit](https://github.com/zhizhuodemao/ai-reverse-toolkit) |
| 腾讯云 | 生成式 AI 加速逆向：XLoader 分析 | [cloud.tencent.com/developer/article/2601167](https://cloud.tencent.com/developer/article/2601167) |
| 吾爱破解 | AI 逆向通用思路 | [52pojie.cn/thread-2093760](https://www.52pojie.cn/thread-2093760-1-1.html) |
| 博客园 | IDA Pro MCP 配置及实战 | [cnblogs.com/zhangyuzhuhe/p/19489356](https://www.cnblogs.com/zhangyuzhe/p/19489356) |
| 二进制磨剑 | 2025 年度总结（60+ 篇 IDA/内核/Frida/AI 安全） | [gm7.org/archives/24610](https://www.gm7.org/archives/24610) |
| 火绒安全 | AI 大模型协助二进制安全分析 | [huorong.cn/document/info/classroom/1887](https://www.huorong.cn/document/info/classroom/1887) |
| Elastic | LLM 驱动逆向 vs 迭代 LLM 混淆 | [elastic.co/security-labs/llm-reversing-vs-llm-obfuscation](https://www.elastic.co/cn/security-labs/llm-reversing-vs-llm-obfuscation) |
| Virus Bulletin | 自动检测/绕过反调试（IDA/Ghidra） | [virusbulletin.com/conference/vb2024](https://www.virusbulletin.com/conference/vb2024/abstracts/automatically-detect-and-support-against-anti-debug-idaghidra-streamline-debugging-process/) |

### C.6 防御升级路线图

| 优先级 | 领域 | 建议 |
|--------|------|------|
| **P0** | AI 辅助 RE 集成 | 部署 ida-pro-mcp 或 GhidraMCP，将 LLM 纳入标准分析流水线 |
| **P0** | VM 脱虚拟化 | 掌握 LLVM-IR 提升方法，关注 JonathanSalwan/Triton 生态 |
| **P1** | Ghidra 升级 | 升级至 11.3+，利用 JIT P-Code 模拟器和 Python 3 支持 |
| **P1** | eBPF 分析能力 | 建立 eBPF 字节码逆向能力，应对新型 eBPF rootkit 威胁 |
| **P2** | 跨工具互操作 | 利用 Binary Ninja 5.3 的 IDA/Ghidra 数据交换能力 |
| **P2** | 自动化反调试绕过 | 参考 VB2024 论文，集成自动化反调试检测与绕过脚本 |
| **P3** | Hex-Rays 2026 API | 关注官方 LLM-friendly API 发布，提前准备集成方案 |

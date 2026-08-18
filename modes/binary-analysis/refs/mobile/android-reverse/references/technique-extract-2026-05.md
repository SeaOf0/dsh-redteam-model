# Technique Extract: 2026-05 Real-World Case Studies

从近期实战案例中提炼的方法论与关键信号，供各 playbook 引用。按专题分类。

---

## 1. 跨 SO 虚表间接调用（Cross-SO Vtable Indirect Call）

**来源**: 抖音 libsscronet × libmetasec_ml 跨 SO 加密调用

### 信号模式

IDA 中看到以下组合时，应考虑跨 SO 虚表调用：

- `BLR Xn` 跳转到从 `.bss` 全局变量加载的地址
- `.bss` 变量使用 `LDAR`（Load-Acquire）读取
- 注册函数使用 `STLR`（Store-Release）写入，只有 3 条指令
- 调用方 SO 内无注册函数的直接 caller（xref 为空）

### 分析方法论

1. **定位函数指针存储位置**: 从 `BLR Xn` 反向追踪寄存器来源，定位 `.bss` 全局变量
2. **定位注册端**: 搜索对同一全局变量的 `STLR`/`STR` 写入，找到注册函数
3. **虚表定位**: 注册函数通常位于 C++ vtable 中，通过 xref 追踪到对象构造函数（`Engine_Create` 类函数）
4. **vtable 槽位映射**: 读取 vtable 基地址，按 8 字节步进枚举所有槽位，找到注册函数对应的索引
5. **动态验证**: Hook 注册函数（`Interceptor.attach`），打印 backtrace 确认跨 SO 调用链

### std::string SSO 布局（ARM64 libc++）

分析参数构造时需要识别 SSO：

```
短字符串 (≤22字节): [0..21] = data, [23] = length (MSB=0)
长字符串 (>22字节): [0..7] = heap_ptr, [8..15] = size, [16..23] = capacity|0x80 (MSB=1)
判断: 读取 byte[23] 符号位, <0 → 长字符串取堆指针, >=0 → 短字符串用栈地址
```

汇编对应: `LDURSB W8, [X29,#offset]; CSEL Xdst, Xheap, Xstack, LT`

### 内存序模式

`STLR`（Release）+ `LDAR`（Acquire）配对保证 happens-before，不需要锁。ARM64 零额外开销。

### 适用场景

- `native-network` 专题中遇到 Cronet/自定义网络栈
- JNI 桥接中 SO 间通过回调/函数指针通信
- 加密 SO 与网络 SO 解耦架构分析

---

## 2. 多层 Frida 检测绕过分层方法论

**来源**: 梆梆加固反 Frida 检测绕过

### 检测层级模型（L1-L6 实战映射）

| 层级 | 检测手段 | 本案对应 | 绕过策略 |
|------|---------|---------|---------|
| L1 | 进程名/线程名字符串匹配 | `gum js loop`/`gdbus`/`gmain` in `/proc/self/task/tid/status` | 字符替换（`buf.writeU8(0x78)`） |
| L2 | 内存映射文件扫描 | `/proc/self/maps` 中 memfd + ELF magic 头检测 | 字符串替换（`memfd`→`mamfd`） |
| L3 | 端口扫描 | 扫描 27000-30000 / 24000-26999 / 20000-23999 端口区间 | Hook 端口判断函数返回 0 |
| L4 | 进程自杀机制 | 检测异常后调用 `kill(getpid(), SIGKILL)` | `Interceptor.replace` 自杀函数 |
| L5 | 工程机白名单 | `ro.build.user` == 特定 hex 值时跳过所有检测 | 信息收集（不做绕过，用于理解逻辑） |
| L6 | 辅助检测 | Xposed/Root/模拟器/ptrace 多维度交叉验证 | 视具体检测逐个绕过 |

### 快速绕过 vs 完整绕过

- **快速绕过**: 仅 `Interceptor.replace` 进程自杀函数，适用于调试场景
- **完整绕过**: 逐层处理所有检测，适用于需要稳定 attach 的分析场景
- **决策依据**: 快速绕过 + 工程机白名单信息 = 判断是否值得做完整绕过

### 模块加载监控模板

Hook `android_dlopen_ext` 监控目标 SO 加载时机，在 `onLeave` 中获取 module base 后挂载 bypass：

```javascript
Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter(args) { this.path = args[0].readUtf8String(); },
    onLeave(retval) {
        if (this.path && this.path.indexOf("libTarget.so") !== -1) {
            var module = Process.findModuleByName("libTarget.so");
            if (module) hook_target(module.base);
        }
    }
});
```

---

## 3. NRV2B 双层打包识别与离线解密

**来源**: 爱加密 v4 加固逆向

### NRV2B 打包识别信号

- `DT_INIT` 不是常规业务代码，而是解压器
- 解压参数表为连续 4-5 个 uint32 常量
- `get_bit` 核心循环: `adds w4, w4, w4; cbz w4, reload; ret` + `ldr w4, [x0], #4; adcs w4, w4, w4; ret`
- 初始哨兵值 `w4 = 0x80000000`
- 解压后用 `mmap(MAP_FIXED)` 覆盖自身映射

### Gap Code 问题

内层代码占 vaddr `0x30000-0xD8000`，但原始文件只有 `0x00000-0x852DC`，之后是压缩态。IDA 静态分析看不到 gap code 区域。

**解决方法**: 运行时从 `/proc/pid/mem` 读取 SO base + gap offset 处的数据，保存后用 IDA "load additional binary" 加载到对应 vaddr。

### 离线解密管道验证方法论

**关键教训**: 管道顺序搞错 = 全错。必须先通过 IDA 逐函数追踪确认调用链，不能靠猜测。

验证步骤：
1. 确认管道每一步的输入输出边界
2. 确认步骤之间的调用关系（谁调谁，在哪个函数内部）
3. 用中间产物验证每一步是否正确（如去混淆后应出现已知字符串）

### DEX 格式不变量密钥恢复

当密钥空间有限（如 S-box key_byte 只有 256 种）且已知明文片段（如 DEX magic `dex\n`）时：

1. 暴力枚举所有可能密钥
2. 对已知明文位置验证解密结果
3. 唯一解确认密钥

当 XOR 密钥作用于 DEX 结构区域时，利用 DEX 格式不变量：

- `map_list.size` 高 3 字节必为 0
- `map_item[0].type` 必为 `0x0000`（HEADER_ITEM）
- `map_item[1].type` 必为 `0x0001`（STRING_ID_ITEM）
- `map_item[0].unused` 必为 0

每个不变量唯一确定一个 XOR key 字节，无需枚举。交叉验证: 解密后检查链式 offset 是否连续正确。

### Root 直读内存替代 Frida

Frida 注入失败时的替代方案：

1. 正常启动 App，等待解密完成（约 20 秒）
2. `grep 'dalvik-DEX' /proc/pid/maps` 找到 `[anon:dalvik-DEX data]` 区段
3. `dd` 读取对应内存区域
4. 扫描 `dex\n` magic 提取 DEX

---

## 4. OLLVM 混淆下算法识别与调用链追踪

**来源**: 某招聘APP sig/sp 分析

### RegisterNatives Hook 锁定 JNI 入口

SO 做了 OLLVM 混淆时，静态看不到清楚的 JNI 导出名。解决方案：

Hook `libart.so` 中 `art::JNI::RegisterNatives`（排除 `CheckJNI` 版本），解析 `JNINativeMethod` 数组：

- `methods_ptr[i*3*ptrSize + 0]` = 方法名
- `methods_ptr[i*3*ptrSize + ptrSize]` = 签名
- `methods_ptr[i*3*ptrSize + 2*ptrSize]` = 函数指针

根据函数指针反查所属 SO 和偏移，建立 Java 方法名 → SO 偏移的映射。

### 算法识别快速判定（OLLVM 场景补充）

基础算法识别签名表见 `crypto-protocol-playbook.md`。以下为 OLLVM 混淆下的补充判断信号：

| 信号组合 | 判定 | 验证方法 |
|---------|------|---------|
| MD5 4 魔数 + `malloc(0x21)` + 返回 32 hex | MD5（任意两条即验证） | hook 输入喂 `hashlib.md5` |
| "先算最坏长度再写压缩"两步式 | LZ4 | `lz4.block.compress(input, store_size=False)` |
| 初始化 0-255 序列 + swap loop | RC4（不受 FLA 影响） | `Crypto.Cipher.ARC4` |
| `malloc(0x21)` 但无 MD5 魔数 | 可能是自定义 hash | 需进一步分析 |

**关键洞察**: RC4 的 KSA 是线性循环，不受 FLA 控制流平坦化影响，在混淆代码中反而更容易识别。

### Hook 驱动流水线顺序确定

遇到长 native 链（7+ 子函数）时：

1. Hook 主函数入口和出口
2. Hook 所有子函数入口，按时间戳排序
3. 建立调用顺序链
4. 按顺序逐段分析每个子函数的参数和返回值

### 固定串提取模式

从混淆 SO 中提取固定密钥串：

1. Hook 主函数确认拼接关系（输入 = A + 固定串 + B）
2. IDA 定位 `.bss` 全局变量（`qword_xxxxx`）
3. 多次 hook 验证该变量值不变 → 确认为硬编码固定串

---

## 5. LLVM Pass 编写与混淆器理解

**来源**: LLVM New Pass Manager 编写和使用

### 理解混淆器构建原理

了解 LLVM Pass 编写有助于逆向分析混淆代码：

- **FLA（控制流平坦化）**: 注册为 Function Pass，通过 `registerPipelineStartEPCallback` 注入
- **BCF（虚假控制流）**: 在函数入口插入不透明谓词分支
- **SUB（指令替换）**: 将简单运算替换为等价复杂表达式
- **字符串加密**: 编码/加密全局字符串常量，运行时解密

### Pass 插件加载机制

- 入口函数 `llvmGetPassPluginInfo()`（extern "C" weak symbol）
- 通过 `dlsym` 动态查找加载
- 注册回调 `registerPipelineParsingCallback` 支持 `-passes=name` 调用
- `isRequired() = true` 确保 Pass 不被优化跳过

---

## 6. SELinux 查询探测与 Root 检测

**来源**: Android Root 环境隐藏

### DirtySepolicy 检测原理

利用 AppZygote + isolatedProcess 在 `app_zygote` 上下文中查询 SELinux 策略：

- `isolatedProcess=true` + `useAppZygote=true` → 私有 Zygote
- `zygotePreloadName` 指向检测代码
- 调用 `SELinux.checkSELinuxAccess(source, target, class, perm)` 查询
- 额外 sepolicy 规则会使查询结果与纯净环境不同

### 敏感查询上下文列表

```
u:r:magisk:s0, u:r:ksu:s0, u:r:su:s0, u:r:adbroot:s0
u:object_r:ksu_file:s0, u:object_r:lsposed_file:s0, u:object_r:xposed_data:s0
```

### 内核级对抗

通过 KPM（KernelPatch Module）hook `security_compute_av_user` 等内核函数，对 app UID 来源的敏感查询返回 deny。

---

## 引用索引

| 技术 | 适用 playbook | 引用方式 |
|------|-------------|---------|
| 跨 SO 虚表调用 | native-network, jni-bridge | 新增信号模式 |
| 多层 Frida 检测绕过 | anti-frida | 补充实战层级映射 |
| NRV2B 打包识别 | deobfuscation, unpack-tool-matrix | 新增识别信号 |
| DEX 不变量密钥恢复 | crypto-protocol | 新增密钥恢复方法 |
| RegisterNatives Hook | jni-bridge | 补充动态定位方法 |
| 算法识别快速判定 | crypto-protocol | 补充快速判定表 |
| Root 直读内存 | dex-loader | 补充替代方案 |
| Gap Code 处理 | deobfuscation | 新增 IDA 分析补充步骤 |
| LLVM Pass 理解 | deobfuscation | 背景知识参考 |
| SELinux 探测 | anti-root | 补充检测层级 |

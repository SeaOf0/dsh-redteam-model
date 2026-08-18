# Unidbg Simulation Playbook

目标：在 PC 上模拟执行 Android SO 函数，绕过设备依赖和运行时保护，直接获取加密/签名结果。

## 先回答

- 需要模拟的是哪个 SO、哪个函数、参数是什么
- 目标函数是否依赖 JNI 回调、文件访问、系统调用
- 当前更适合 Unidbg（完整模拟）、Unicorn（指令级模拟）、QBDI（无感知插桩）、还是 angr（符号执行）
- 是否有真实设备上的输入输出对可用于验证

## 工具选择

| 场景 | 工具 | 原因 |
|---|---|---|
| 调用 SO 加密/签名函数 | Unidbg | JNI 环境完善，可直接调用 Java_* 和导出函数 |
| 指令级 trace / 反混淆 | Unicorn | 灵活的指令模拟，支持自定义 hook |
| 不触发检测的插桩 | QBDI | 无 ptrace，无注入痕迹 |
| 路径探索 / 约束求解 | angr | 符号执行，自动探索分支 |
| 快速函数调用验证 | Frida + 设备 | 无需搭建模拟环境 |

## 操作顺序

### 1. 确定模拟目标

- 目标 SO 路径和函数签名
- 函数参数类型和含义
- 预期输出格式
- 是否需要初始化流程（JNI_OnLoad 等）

### 2. Unidbg 环境搭建

#### 基础框架

```java
// 创建模拟器（ARM64 或 ARM）
AndroidEmulator emulator = new AndroidEmulatorBuilder().build();
Memory memory = emulator.getMemory();
memory.setLibraryResolver(new AndroidResolver(23));

// 创建虚拟机
VM vm = emulator.createDalvikVM();
vm.setVerbose(true);

// 加载 SO
DalvikModule dm = vm.loadLibrary(new File("libtarget.so"), false);
```

#### 3 阶段环境补全

**阶段 1：JNI 调用补全**
- 识别 SO 中的 JNI 回调（FindClass、GetMethodID、CallStaticVoidMethod 等）
- 为每个 JNI 调用提供实现或 stub
- 常见需要补全的 JNI 调用：获取 Context、SharedPreferences、PackageManager 信息

**阶段 2：文件访问补全**
- SO 可能读取 `/proc/self/maps`、`/system/build.prop`、应用私有目录等
- 使用 `emulator.getFileSystem()` 或自定义 `IOResolver` 处理
- 常见模式：
  - `SimpleFileIO`：简单文件映射
  - `ByteArrayFileIO`：内存中虚拟文件

**阶段 3：系统调用补全**
- `ioctl`、`prctl`、`ptrace` 等可能触发异常
- 使用 `emulator.getSyscallDispatcher()` 注册自定义处理器
- 常见需要处理的 syscall：`ptrace`（返回成功）、`prctl`（忽略）、特定 `ioctl`

#### JNI 补环境代码模式

覆写 `AbstractJni` 的核心方法，按 `signature` 分支补环境：

```java
// 静态方法（最大量补环境入口）
@Override
public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass,
    String signature, VaList vaList) {
    switch (signature) {
        case "com/xingin/tiny/internal/t->b(I[Ljava/lang/Object;)Ljava/lang/Object;": {
            int i = vaList.getIntArg(0);
            switch (i) {
                case 1004337890:
                    return new StringObject(vm, "/data/user/0/com.target.pkg");
                // ... 按 int 值分支补不同功能
            }
        }
    }
    return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
}

// 字段获取
@Override public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> obj, String sig) {
    switch (sig) {
        case "android/content/pm/PackageInfo->packageName:Ljava/lang/String;":
            return new StringObject(vm, "com.target.pkg");
        case "android/content/pm/ApplicationInfo->dataDir:Ljava/lang/String;":
            return new StringObject(vm, "/data/user/0/com.target.pkg");
    }
    return super.getObjectField(vm, obj, sig);
}

// 实例方法
@Override public int callIntMethodV(BaseVM vm, DvmObject<?> obj, String sig, VaList vaList) {
    switch (sig) {
        case "android/telephony/TelephonyManager->getPhoneType()I": return 1; // PHONE_TYPE_GSM
    }
    return super.callIntMethodV(vm, obj, sig, vaList);
}

// SVC 注册（Native 层 JNI 函数指针）
Pointer _FromReflectedMethod = svcMemory.registerSvc(new Arm64Svc() {
    @Override public long handle(Emulator<?> emulator) {
        return emulator.getContext().getPointerArg(1).toIntPeer();
    }
});
```

常见必补项速查：
- `PackageInfo`: packageName, versionName, firstInstallTime, applicationInfo
- `ApplicationInfo`: targetSdkVersion, dataDir, nativeLibraryDir, flags
- `Context.getSystemService`: "phone"/"wifi"/"audio"/"batterymanager"
- `TelephonyManager`: getSimState/getSimOperator/getNetworkCountryIso/getPhoneType
- `Settings$System/Secure/Global.getInt`
- `WifiManager.isWifiEnabled`, `AudioManager.getStreamVolume/getStreamMaxVolume`

#### 常见缺失符号处理

```java
// 补全未实现的符号
emulator.getMemory().addModuleListener((name, base, size) -> {
    // 检查并补全缺失符号
});

// 常见需要 patch 的场景
vm.resolveClass("android/content/Context");
vm.resolveClass("android/app/Activity");
```

### 3. 调用目标函数

#### 调用 JNI 导出函数

```java
// 方法 1：通过符号名直接调用
dm.callJNI_OnLoad(emulator);

// 方法 2：通过 RegisterNatives 映射的函数
Number result = dm.callFunction(emulator, "Java_com_target_ClassName_method",
    arg1, arg2);
```

#### 调用非导出函数（通过偏移）

```java
// 获取模块基址
Module module = memory.findModule("libtarget.so");
long base = module.base;

// 通过偏移调用
Number result = emulator.eFunc(base + 0x1234,
    emulator.getMemory().malloc(100, false),
    42);
```

### 4. 签名算法模拟完整流程

1. 搭建 Unidbg 环境并加载目标 SO
2. 处理 JNI_OnLoad（可能包含 RegisterNatives 和初始化）
3. 补全所有 JNI 回调和文件访问
4. 调用签名函数，传入参数
5. 提取签名结果
6. 与真实设备结果对比验证

### 5. Unicorn 指令级模拟

适用场景：
- OLLVM 反混淆：trace 真实执行路径
- VMP handler 分析：逐条模拟 VM 字节码
- 算法还原：trace 加密函数的完整执行过程

```python
from unicorn import *
from unicorn.arm64_const import *

# 创建 ARM64 模拟器
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# 映射内存并加载代码
mu.mem_map(base, size)
mu.mem_write(base, code_bytes)

# 设置寄存器和栈
mu.reg_write(UC_ARM64_REG_SP, sp_addr)

# 添加 hook
def hook_code(mu, address, size, user_data):
    # 记录执行的每条指令
    pass

mu.hook_add(UC_HOOK_CODE, hook_code)
mu.emu_start(entry, end_addr)
```

### 6. QBDI 无感知插桩

适用场景：
- 目标有反调试/反 Frida 检测，常规插桩被检测
- 需要在不注入的情况下收集指令级 trace

基本用法：
1. 编译 QBDI 并在目标设备上部署
2. 通过 QBDI 的 VM（Virtual Machine）加载目标 SO
3. 使用 `QBDI_addInstrumentedModule` 限定插桩范围
4. 通过 `QBDI_addCB` 注册指令级回调记录执行流
5. 与 Unidbg 组合使用时：先用 Unidbg 补全环境，再用 QBDI 做指令级 trace

注意：QBDI 在 Android 上的部署需要交叉编译或使用预编译版本，配置成本高于 Frida。

### 7. angr 符号执行

适用场景：
- 探索多分支路径
- 约束求解（如需要满足特定条件的输入）
- 自动化反混淆路径恢复

```python
import angr

proj = angr.Project('libtarget.so', auto_load_libs=False)
state = proj.factory.call_state(func_addr, arg1, arg2)
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=target_addr, avoid=avoid_addr)
```

## JNI 环境补全速查

| JNI 调用 | 常见用途 | 补全方式 |
|---|---|---|
| `FindClass` | 获取 Java 类 | `vm.resolveClass()` |
| `GetMethodID` | 获取方法 ID | 返回模拟 ID |
| `GetStaticMethodID` | 获取静态方法 ID | 返回模拟 ID |
| `CallStaticVoidMethod` | 调用静态方法 | 打桩或空实现 |
| `GetStringUTFChars` | 获取字符串 | 从参数中提取 |
| `NewStringUTF` | 创建字符串 | 直接构造 |
| `GetFieldID` / `GetBooleanField` | 读取字段 | 返回默认值或 mock 值 |

## Trace 性能优化

默认 `AssemblyCodeDumper`（Unicorn 后端路径）对复杂 SO（libmetasec_ml、libsgmain 等）的 trace 速度通常只有 100-500 行/秒。以下优化可将速度提升至 2,000-10,000 行/秒（约 5-20x，实际加速取决于 SO 复杂度和指令密度）。

### Capstone 反汇编缓存

Capstone `cs.disasm()` 是 trace 最大单点开销——同一指令会被反复反汇编。

**L1 缓存**（直接映射数组）：
- 以 `(address & mask)` 为索引，直接映射到预分配数组
- 命中时 O(1)，未命中时调用 Capstone 并写入缓存
- 适合 SO 代码段地址空间（通常 < 16MB，8M 条目足够）
- SMC（自修改代码）场景：检测到写入代码页时需失效对应缓存行

**L2 缓存**（LRU HashMap，补充）：
- 以 `(bytes_hash, address)` 为 key，1M 条目 LRU HashMap
- 处理 L1 冲突导致的未命中

效果：Capstone 调用减少 90%+。

### GC 压力缓解

默认实现大量使用 `ByteBuffer`、`String.format`、`StringBuilder`，导致频繁 GC 停顿。

替换方案：
- `ByteBuffer` → 原始 `byte[]` + 位操作（`& 0xFF`、`<<`、`>>>`）
- `String.format("%02x", b)` → 预计算 `HEX_ARRAY[0xFF & b]` 静态查找表
- `StringBuilder` → 预分配 8MB `StringBuilder`，满时才 flush

效果：GC 停顿减少 80%+。

### 异步 I/O

默认每行 trace 触发一次同步写文件。

改进：
- trace 行写入 `LinkedBlockingQueue<String>`（无界队列）
- 专用 `LoggerThread` 批量写入文件
- 队列极端满时丢弃 trace 行而非阻塞模拟线程

效果：I/O 等待接近 0。

### 模拟器后端与范围控制

- **Dynarmic 后端选择**：Unidbg 使用 Dynarmic 后端；对 ARM64 SO 使用 `AndroidEmulatorBuilder.for64Bit()` 让 Dynarmic 以 ARM64 模式运行，获得更好的兼容性
- **模块范围过滤**：trace 时限定 `module.name == "libtarget.so"`，避免 trace 到 libc/libart 等无关代码，减少 50%+ 的无效输出
- **JIT 预热**：首次调用函数会触发 Dynarmic JIT 编译，耗时较长；正式 trace 前先用dummy 参数调用一次目标函数完成预热

### Trace 结果结构化

高速 trace 产出的大量数据需要结构化解析：
- `TraceCallParser`：解析 JNI 调用（`CallStaticObjectMethodV`）、libc 调用（`memcpy`、`strlen`）、系统调用（`svc #0`）
- 输出结构化 JSON 而非纯文本，便于 trace-ui、taint 分析等工具消费

## 常见故障排除

### UPX 壳 SO 加载崩溃

**症状**：加载 UPX 壳 SO 时 `munmap` 抛出 `IllegalStateException`。

**根因**：UPX 的 `do_xmap` 用一次 `mmap` 分配所有段，但 `munmap` 跨越不同权限区域（`.text` r-x 和 `.data` rw-），Unidbg `AbstractLoader.java munmap()` 检测到权限不匹配抛异常。

**修复**：修改 `AbstractLoader.java` 的 `munmap()` 方法，将权限不匹配和空区域的异常改为 `log.warn()`。

### arc4random 确定性输出

**症状**：`arc4random()` 每次返回相同值。

**根因链路**（NDK r21+ bionic libc）：
1. bionic `arc4random` 内部使用 ChaCha20 PRNG
2. 真机通过 `getrandom` syscall（ARM64 `__NR_getrandom` 278）获取种子
3. Unidbg 中 libc 先 `open /dev/urandom`，但 `fstat` 返回的 `st_mode` 缺少 `S_IFCHR` (0x2000) 位，导致 `raise(SIGKILL)`
4. Unidbg 拦截 `tgkill` syscall 返回 0，进程继续
5. ChaCha20 用固定密钥加密零输入 → 确定性输出

**注意**：不同 NDK 版本的 bionic 实现不同，NDK r25+ 的 `arc4random` 可能走不同路径（直接 `getrandom` 而非先 `open`），需根据实际 NDK 版本确认。

**应对**：
- 固定值可接受（如 trace 分析）→ 不处理
- 需要随机化 → hook `arc4random` 返回自定义序列
- 需要真实随机 → 模拟 `/dev/urandom` 的 `fstat` 返回正确设备类型 `0x2000`

## 常见偏差

- 不先处理 JNI_OnLoad 就直接调用目标函数——很多 SO 在 JNI_OnLoad 中做初始化和 RegisterNatives
- 忽略文件访问错误——SO 可能因为读不到文件而走异常分支
- 补全 JNI 环境时返回值类型不匹配——需要对照 IDA/Ghidra 确认类型
- 模拟结果与真实设备不一致——需要逐层排查 JNI 回调、文件、syscall 的差异
- 用 Unidbg 跑复杂 UI 逻辑——Unidbg 只适合纯逻辑函数，不适合 UI/Activity 依赖
- 不验证就信任模拟结果——至少需要一组真实输入输出对做对照

## 最小交付

- `run/unidbg-simulation-notes.md`
- Unidbg Java 调用代码（至少包含环境搭建和目标函数调用）
- 模拟结果与真实设备结果对照
- 缺失符号和 patch 记录
- trace 优化配置（如使用缓存/异步 I/O，记录配置参数和实测速度）

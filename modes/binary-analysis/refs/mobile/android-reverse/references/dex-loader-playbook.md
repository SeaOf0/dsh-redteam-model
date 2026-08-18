# Dex Loader Playbook

目标：确认动态 Dex、壳、内存加载和解密路径。

## 高风险信号

- `attachBaseContext`
- `DexClassLoader`
- `PathClassLoader`
- `InMemoryDexClassLoader`
- `BaseDexClassLoader`
- `assets/` 高熵 blob
- 很小的 `classes.dex`

## 壳家族识别

通过静态特征初步识别壳类型，不同壳的 dump 策略不同：

| 特征 | 壳类型 |
|---|---|
| `libjiagu.so` 或 `libjiagu_art.so` 或 `libjiagu_64.so` + `com.stub.StubApp` | 360 加固 |
| `com.qihoo.util` 包 + 上述 SO 之一 | 360 加固（新版） |
| `libsecexe.so` / `libsecmain.so` | 梆梆加固 |
| `libDexHelper.so` / `libDexHelper-x86.so` | 梆梆（企业版/libDexHelper） |
| `libijiami.so` | 爱加密 |
| `libshella` / `libtup` / `libshell-super`（文件名含这些前缀） + `com.tencent.StubShell` | 腾讯乐固 |
| `libbaiduprotect.so` | 百度加固 |
| `libkwscmm.so` / `libkwsfixer.so` | 梆梆（企业版） |
| `assets/libsheji.so` / `com.secneo.apkwrapper` | 梆梆（旧版） |
| Application 类名在 `com.stub` / `com.secneo` / `com.shell` 包下 | 通用壳特征 |
| `classes.dex` 只有壳入口 + `assets/` 有大文件 | 通用壳特征 |

识别壳类型不是目的，目的是决定 dump 策略：是等 `DexClassLoader` 调用后 dump，还是在 `InMemoryDexClassLoader` 加载时直接从内存读。

### 壳脱壳要点速查

| 壳 | 脱壳关键时机 | 核心脱壳方法 | 修复要求 |
|---|---|---|---|
| 腾讯一代 (libshella) | `mprotect` 恢复 `r-x` 权限时 | dump 运行时映射的真实 ELF；定位 `.init.array` 的 XOR 解密循环 dump 解密后段 | 手搓修复 ehdr/phdr/dynamic，`SoFixer32` 修复导入表 |
| 企业壳 (第三代抽取) | `InMemoryDexClassLoader` 加载后 | 搜索 magic `BBbb.dgc` → 读取映射表 (每 0x18 字节一组) → 将 code_off 按 uleb128 写回 | SM4-ECB 解密前 0x20000 字节 (key=硬编码⊕包名前16字节) + zstd 解压 |
| 梆梆 (libSecShell) | `init_array` 第一个函数调用前 | hook `__dl___ZL10call_array...`，在 `init_proc` 填充导入表前 dump | dump 后导入表为绝对地址，需 `DebugSymbol.fromAddress` 解析符号名回填 extern 表 |
| 梆梆企业版 (libDexHelper) | 外层 SO `.init_array` / constructor 解密链 | 解析 PHT/PT_DYNAMIC/重定位，恢复壳入口和解密管道，验证内层 ELF 后再做 DEX 回流 | 见 `references/bangcle-libdexhelper-playbook.md`；禁止把单样本偏移/密钥当通用规则 |

第三代抽取型壳还原模式：
- code_item 中 `code_off` 指向置空区，真实 code 藏在 DEX 末尾
- 映射表结构：每组 0x18 字节（code_offset 4B + code_size 4B + ... + write_back_offset 4B）
- 还原：读映射表，将 code_off 按 uleb128 编码写回正确偏移

## 分析顺序

1. **静态定位**：找加载器类（Application 子类 / `attachBaseContext`）、blob 来源（assets / raw / jni / 网络下载）、壳特征
2. **脱壳工具选型**：按 `references/unpack-tool-matrix.md` 的决策流程记录环境、ABI、进程存活、检测时序和 Anti-Frida 证据。A4+ 表示复杂度，不自动证明 Frida 失败；观察到高层 Anti-Frida、早期自毁或连续同策略失败时，优先 pivot 到 eBPFDexDumper / BlackDex / FART / Smali Patch / Root 直读等路线。
3. **Hook 加载链**（仅在工具选型允许或需要补充验证时）：先 hook `DexClassLoader` / `InMemoryDexClassLoader` / `PathClassLoader` 构造器，记录 dex 路径和加载时机
4. **Dump 真实 Dex**：baseline 脚本（`run/class-loader-trace.js`）只记录加载路径和时机，不做 dex 内容 dump。获取真实 dex 需要额外操作：
   - `DexClassLoader` 场景：在 hook 回调中读取 dex 文件路径并复制到 task-local
   - `InMemoryDexClassLoader` 场景（Android 8+）：dex 不落盘，直接从内存 buffer 加载。需要修改脚本从 `ByteBuffer` 参数中读取字节并写入文件，且 buffer 可能是一次性的，必须在构造器调用时立即 dump
4. **回到静态分析**：用 jadx/fernflower 分析 dump 出的真实 dex

## Memory Dump 技术

当 hook 无法直接获取 dex 路径时，需要从进程内存中 dump：

1. **Frida Memory.scan**：扫描 dex magic (`dex\n035\0`、`dex\n037\0`、`dex\n038\0`、`dex\n039\0`、Android 11+ 的 `dex\n040\0`) 定位内存中的 dex
2. **`/proc/<pid>/mem` 读取**：从 maps 中找到 `dex` 相关映射区域，直接读取
3. **`DexFile` 类遍历**：通过 `DalvikSystemDexFile` 或反射获取已加载的 dex cookie，再用 `openDexFile` 获取路径

## InMemoryDexClassLoader dump 方法

`InMemoryDexClassLoader`（Android 8+）直接从内存 `ByteBuffer` 加载 dex，不落盘，需要特殊 dump 策略。

### 方法 1：Frida hook 构造器捕获 ByteBuffer

```javascript
Java.perform(function() {
  var InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
  InMemoryDexClassLoader.$init.overload("java.nio.ByteBuffer", "java.lang.ClassLoader")
    .implementation = function(buf, parent) {
      // ByteBuffer 在构造器调用时可读，必须立即 dump
      // buf.array() 仅适用于 heap ByteBuffer；direct buffer 需要逐字节读取
      var len = buf.remaining();
      var arr = Java.array('byte', len);
      buf.get(arr);
      console.log("[+] InMemoryDexClassLoader ByteBuffer size: " + len);
      // 检查 dex magic
      var magic = String.fromCharCode(arr[0], arr[1], arr[2], arr[3]);
      console.log("[+] magic: " + magic);
      // 写入文件
      var fos = Java.use("java.io.FileOutputStream").$new("/data/local/tmp/dumped_" + Date.now() + ".dex");
      fos.write(arr);
      fos.close();
      console.log("[+] dex dumped");
      this.$init(buf, parent);
    };
});
```

注意：`ByteBuffer` 可能是一次性的（`isDirect` 或 position 会被消费），在构造器入口 dump 最安全，不要等到构造器返回后再读。

### 方法 2：内存扫描 DEX magic

当 hook 时机不确定或 ByteBuffer 已被释放时，直接扫描进程内存：

```javascript
// 扫描 dex magic：64 65 78 0a (dex\n)
var pattern = "64 65 78 0a";
Process.enumerateRanges("r--").forEach(function(range) {
  Memory.scan(range.base, range.size, pattern, {
    onMatch: function(address) {
      // 读取 dex header 获取文件大小（readU32 直接读取小端 uint32）
      var dexSize = address.add(0x20).readU32();
      if (dexSize > 0x70 && dexSize < 50 * 1024 * 1024) {  // 合理范围
        console.log("[+] DEX at " + address + " size: " + dexSize);
        var buf = Memory.readByteArray(address, Math.min(dexSize, range.size - address.sub(range.base).toInt32()));
        // 写入文件
        var f = new File("/data/local/tmp/memscan_" + address + ".dex", "wb");
        f.write(buf);
        f.close();
      }
    },
    onComplete: function() {}
  });
});
```

### dump 时机指导

- **最早时机**：`InMemoryDexClassLoader` 构造器入口 —— ByteBuffer 尚未被消费，数据完整
- **安全窗口**：构造器返回后、`loadClass` 首次调用前 —— ART 内部已持有 dex 副本，但 ByteBuffer 可能已释放
- **兜底方案**：在目标类被使用前（如按钮点击前），用内存扫描方法 2 补 dump
- **不要**：在 `Application.onCreate` 之前 dump —— dex 可能还未解密到内存

## 常见偏差

- 把壳入口的 `classes.dex` 当作全部代码——必须 dump 真实 dex 后再做分析
- dump 时机过早（dex 尚未解密）或过晚（dex 已被释放）——需要在解密后、类加载前的窗口 dump
- 只 dump 了一份 dex 但目标有多阶段解密——需要持续监控 `DexClassLoader` 调用
- `InMemoryDexClassLoader` 场景下找不到文件路径——因为根本没有文件，需要直接从 buffer dump
- 脱壳成功后直接开始业务分析，忽略了壳同时包含 anti-frida/anti-debug 检测——A4+ 场景中壳脱除后应同步检查 `anti-frida-playbook.md`

## 联动专题

- **脱壳工具决策**：所有脱壳策略选型参见 `references/unpack-tool-matrix.md`（壳识别总表 + 工具库 + 决策流程 + 模拟器专项策略）。A4+ 需要证据化选路，不因等级自动判定 Frida 成败
- **梆梆企业版/libDexHelper**：命中 `libDexHelper.so` / `libDexHelper-x86.so` 时读取 `references/bangcle-libdexhelper-playbook.md`，把 `dexLoader.shellFamily` 记为 `bangcle-libdexhelper` 并落 `run/bangcle-libdexhelper-evidence.md`
- **anti-frida**：A4+ 壳常伴随 anti-frida 检测，但是否影响当前路线必须由进程存活、注入时机和检测证据判断。脱壳成功只是第一步；如果实际 Frida hook 仍被检测，参见 `anti-frida-playbook.md` 的退出与 pivot 规则
- **anti-root**：部分壳在 Native 层同时执行 root 检测。参见 `anti-root-playbook.md`
- **native-network**：壳可能将网络请求（包括 pinning）放在动态加载的 dex/SO 中。参见 `native-network-playbook.md`
- **framework-runtime**：Flutter/Unity 应用的"壳"可能是框架级保护（如 DEX 加密 + libapp.so 加密），需要联动分析。参见 `framework-runtime-playbook.md`
- **jni-bridge**：壳的核心逻辑通常在 Native SO 中通过 `RegisterNatives` 注册 JNI 方法，需要建立 Java→Native 桥接映射。参见 `jni-bridge-playbook.md`
- **版本适配**：不同 Android 版本的 DEX/OAT/VDEX 格式差异影响 dump 策略，参见 `android-version-matrix.md`

## 最小交付

- `run/class-loader-trace.js`
- `run/dex-loader-dump-notes.md`
- `run/bangcle-libdexhelper-evidence.md`（仅 `dexLoader.shellFamily=bangcle-libdexhelper` 时要求）
- 报告中的加载器、dump 状态、再分析状态

## 实战补充：Root 直读内存替代 Frida

Frida 注入失败（如 A4+ 壳在 `JNI_OnLoad` 极早期触发检测，spawn 模式来不及 bypass）时的替代方案：

1. 正常启动 App，等待解密完成（约 20 秒）
2. `adb shell su -c "grep 'dalvik-DEX' /proc/$(pidof pkg)/maps"` 找到 `[anon:dalvik-DEX data]` 区段
3. `dd` 读取对应内存区域
4. 扫描 `dex\n` magic 提取 DEX

**注意**：拿到的 DEX 含运行时页对齐填充，大小不精确。如需精确 DEX，应继续分析壳的解密管道实现离线还原。

## 实战补充：NRV2B 双层打包识别

爱加密 v4 等壳使用 NRV2B 解压器作为外层 stub，解压内层代码后 `mmap(MAP_FIXED)` 覆盖自身。识别信号：

- `DT_INIT` 不是业务代码而是解压器
- `get_bit` 核心循环: `adds w4,w4,w4; cbz w4,reload; ldr w4,[x0],#4; adcs w4,w4,w4; ret`
- 初始哨兵 `w4 = 0x80000000`

**Gap Code 问题**：解压后代码覆盖 vaddr `0x30000-0xD8000`，但原始文件只到 `0x852DC`。IDA 静态看不到 gap code 区域（解压后的关键函数都在这里）。

**解决**：运行时从 `/proc/pid/mem` 读取 SO base + gap offset 处数据 → 保存 → IDA "load additional binary" 加载到对应 vaddr。

详细案例见 `references/technique-extract-2026-05.md` 第 3 节。

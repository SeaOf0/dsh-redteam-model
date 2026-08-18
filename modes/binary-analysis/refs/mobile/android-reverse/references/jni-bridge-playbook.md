# JNI Bridge Playbook

目标：先恢复 `Java -> Native` 的真实桥接，再解释 SO 语义。
对 `A4-A7` 目标，桥接恢复不是可选优化，而是主线任务。

## 先回答

- 哪个类、哪个时机触发了 `loadLibrary`
- 桥接是 `Java_*` 导出、`RegisterNatives` 动态注册，还是二者混合
- 关键函数是直接被 Java 调，还是先经过 wrapper / dispatcher / table lookup
- 目标 SO 是否 stripped、是否有壳或延迟加载

## 必查入口

- `System.loadLibrary`
- `System.load`
- `JNI_OnLoad`
- `RegisterNatives`
- `Java_*` 导出符号
- `dlopen / dlsym`

## 作业顺序

### 1. 先定 Java 边界

- 搜索 native 方法声明
- 记录类名、方法名、签名、返回值
- 回溯谁调用它，以及是在启动期、功能点击还是发包前触发

### 2. 再定装载边界

- 找 `loadLibrary` 实际发生在哪个类、哪个生命周期
- 如果没静态命中，检查反射封装、壳 Application、Split / 动态特性模块
- 记录库名、加载顺序、ABI 与进程

### 3. 优先恢复桥接表

恢复优先级：

1. 直接导出 `Java_*`
2. `JNI_OnLoad`
3. `RegisterNatives`
4. 间接注册封装、函数指针表、wrapper 宏

### 4. A5-A7 下的 stripped / 混淆处理

遇到 stripped symbol 或动态注册混淆时，优先：

- 找 `JNINativeMethod` 数组特征
- 找方法名 / 签名字串与其交叉引用
- 找 `RegisterNatives` 调用点附近的类引用、表长度和函数指针数组
- 动态 hook `RegisterNatives`、`dlopen`、`dlsym`，直接打印：
  `className / methodName / signature / fnPtr / moduleBase`

如果 still missing：

- 先确认是否还有二次 `dlopen`
- 再确认是否由壳、解密器或 `DexClassLoader` 延迟释放真正 SO

### 5. 至少建一条最短闭环

最低要求不是“找到一个 Native 函数”，而是建立：

`Java entry -> native symbol/RVA -> effect/output`

`effect/output` 可以是：

- 返回值
- 网络参数
- 签名结果
- 文件 / 数据库存取
- 再回调 Java 的结果

### 6. 再决定是否深挖 Native

只有桥接关系成立后，才进入：

- 算法语义恢复
- 协议参数恢复
- Native patch
- 纯算法提取

## 常见分歧处理

- Java 层有 native 声明，SO 里没有对应导出：
  优先怀疑动态注册，不要直接判“代码缺失”
- `RegisterNatives` 命中了，但函数地址落在匿名内存或晚加载模块：
  优先补 `dlopen / dlsym / class loader` 取证
- 只看到单个可疑加密函数：
  没有桥接链前，不得直接给业务语义

## Frida RegisterNatives Hook 脚本

在 `JNI_OnLoad` 执行后、native 方法被首次调用前，拦截 `RegisterNatives` 拿到完整桥接表：

```javascript
// run/register-natives-trace.js
// 用法: frida -U -f <package> -l register-natives-trace.js --no-pause

var modules = {};

function ensureModule(name) {
  if (!modules[name]) {
    var mod = Process.findModuleByName(name);
    modules[name] = mod ? { base: mod.base, size: mod.size, name: mod.name } : null;
  }
  return modules[name];
}

// 判断地址是否属于某个已加载 SO
function findModuleForAddr(addr) {
  var hits = Process.enumerateModules().filter(function(m) {
    return addr.compare(m.base) >= 0 && addr.compare(m.base.add(m.size)) < 0;
  });
  return hits.length > 0 ? hits[0] : null;
}

// Hook RegisterNatives
Java.perform(function() {
  var JNIEnv = Java.vm.getEnv();
  var envPtr = JNIEnv.handle;

  // JNIEnv->RegisterNatives 是虚函数表第 215 项（索引从 0 开始）
  // 偏移 = 215 * sizeof(void*) = 1720 (ARM64) / 860 (ARM32)
  var pointerSize = Process.pointerSize;
  var registerNativesOffset = 215 * pointerSize;
  var registerNativesPtr = envPtr.readPointer().add(registerNativesOffset).readPointer();

  console.log("[*] RegisterNatives at: " + registerNativesPtr);

  Interceptor.attach(registerNativesPtr, {
    onEnter: function(args) {
      // args[0] = JNIEnv*, args[1] = jclass, args[2] = JNINativeMethod*, args[3] = nMethods
      var methods = args[2];
      var nMethods = args[3].toInt32();

      // 通过反射获取类名
      var jclazz = Java.use("java.lang.Class");
      var jobj = Java.cast(args[1], jclazz);

      console.log("\n[RegisterNatives] class=" + jobj.getName() + " nMethods=" + nMethods);

      for (var i = 0; i < nMethods; i++) {
        var entry = methods.add(i * 3 * pointerSize);
        var namePtr = entry.readPointer();
        var sigPtr = entry.add(pointerSize).readPointer();
        var fnPtr = entry.add(2 * pointerSize).readPointer();

        var name = namePtr.readCString();
        var sig = sigPtr.readCString();
        var mod = findModuleForAddr(fnPtr);

        console.log("  [" + i + "] " + name + sig);
        console.log("       fnPtr=" + fnPtr +
          (mod ? " (" + mod.name + " +" + fnPtr.sub(mod.base) + ")" : " (unknown module)"));
      }
    }
  });

  console.log("[*] RegisterNatives hook installed. Trigger target functionality to capture mappings.");
});
```

### 动态注册混淆场景处理

当 `RegisterNatives` 调用被壳或混淆器包裹时，直接 hook 可能不触发。此时使用以下策略：

**策略 1 — JNI_OnLoad 出口延迟 hook**

```javascript
// 在 JNI_OnLoad 返回后再枚举 native 方法入口
Interceptor.attach(Module.findExportByName("libtarget.so", "JNI_OnLoad"), {
  onLeave: function(retval) {
    Java.perform(function() {
      var cls = Java.use("com.target.ClassName");
      var methods = cls.class.getDeclaredMethods();
      methods.forEach(function(m) {
        if (m.toString().indexOf("native ") !== -1) {
          console.log("[JNI_OnLoad exit] " + m.toString());
        }
      });
    });
  }
});
```

**策略 2 — 二次 dlopen 监控**

壳可能在首次 `JNI_OnLoad` 中延迟加载真实 SO。hook `android_dlopen_ext` 捕获后续加载：

```javascript
Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
  onEnter: function(args) {
    this.path = args[0].readCString();
  },
  onLeave: function(retval) {
    if (this.path && this.path.indexOf("target") !== -1) {
      console.log("[dlopen] " + this.path + " loaded at " + retval);
      // 在此处重新安装 RegisterNatives hook
    }
  }
});
```

## IDA Python: JNINativeMethod 数组识别

在 IDA 中扫描 SO 的 `.rodata` / `.data` 段，识别 `JNINativeMethod` 结构数组特征（连续的 3 指针序列：char* name, char* signature, void* fnPtr）。

```python
# ida_jni_bridge_scan.py
# 在 IDA Python 中执行，扫描 JNINativeMethod 数组
import idautils
import idc
import ida_bytes
import ida_segment

def is_readable_ptr(addr):
    """检查地址是否指向可读内存"""
    return ida_bytes.is_mapped(addr) and ida_bytes.is_loaded(addr)

def read_cstring_safe(addr, max_len=256):
    """安全读取 C 字符串"""
    s = ""
    for i in range(max_len):
        b = ida_bytes.get_byte(addr + i)
        if b == 0:
            break
        if 0x20 <= b <= 0x7e:
            s += chr(b)
        else:
            return None  # 非 ASCII，可能不是方法名
    return s if len(s) >= 2 else None

def scan_jni_native_methods():
    """扫描所有数据段，查找 JNINativeMethod 数组"""
    results = []
    ptr_size = 8  # ARM64，ARM32 改为 4

    for seg_ea in idautils.Segments():
        seg_name = idc.get_segm_name(seg_ea)
        if seg_name not in (".rodata", ".data", ".data.rel.ro", ".bss"):
            continue

        seg_end = idc.get_segm_end(seg_ea)
        ea = seg_ea

        while ea < seg_end - 3 * ptr_size:
            p1 = ida_bytes.get_qword(ea) if ptr_size == 8 else ida_bytes.get_dword(ea)
            p2 = ida_bytes.get_qword(ea + ptr_size) if ptr_size == 8 else ida_bytes.get_dword(ea + ptr_size)
            p3 = ida_bytes.get_qword(ea + 2 * ptr_size) if ptr_size == 8 else ida_bytes.get_dword(ea + 2 * ptr_size)

            # JNINativeMethod: {char* name, char* sig, void* fnPtr}
            # name 应该是指向可读字符串的指针
            # sig 应该是以 '(' 开头的 JNI 签名字符串
            # fnPtr 应该指向代码段（函数地址）
            if (is_readable_ptr(p1) and is_readable_ptr(p2) and
                p3 != 0):

                name = read_cstring_safe(p1)
                sig = read_cstring_safe(p2)

                if (name and sig and
                    sig.startswith("(") and
                    ")" in sig and
                    2 <= len(name) <= 80):
                    results.append({
                        "array_addr": ea,
                        "name": name,
                        "sig": sig,
                        "fnPtr": hex(p3),
                        "segment": seg_name
                    })
                    ea += 3 * ptr_size  # 跳到下一个条目
                    continue

            ea += ptr_size

    return results

# 执行扫描
found = scan_jni_native_methods()
print(f"\n[*] Found {len(found)} JNINativeMethod entries:\n")
for entry in found:
    print(f"  0x{entry['array_addr']:X}: {entry['name']}{entry['sig']} -> {entry['fnPtr']} [{entry['segment']}]")

if found:
    print(f"\n[+] Tip: Cross-reference fnPtr addresses to find the actual native implementations")
    print(f"[+] Tip: Search for the array base address (first entry) in code to find RegisterNatives call")
```

### IDA 手动定位流程

当自动扫描无结果时（stripped / 加密字符串），使用手动方法：

1. **定位 `RegisterNatives` 调用**：在 IDA 中搜索 `RegisterNatives` 的交叉引用（从 import 表）
2. **识别函数指针数组**：`RegisterNatives` 的第 3 个参数是 `JNINativeMethod*`，回溯该参数来源
3. **识别表长度**：第 4 个参数 `nMethods` 通常是立即数，可确认数组大小
4. **逐条提取**：数组中每 3 个指针分别是 name / sig / fnPtr

## 最小交付

- `run/register-natives-trace.js`
- `run/jni-bridge-map.md`（格式如下）
- 报告中的桥接映射、装载时机和至少一条 Java -> Native -> 输出链

### jni-bridge-map.md 模板

```markdown
# JNI Bridge Map

## SO 装载信息
- 库名:
- 加载类:
- 加载时机:
- ABI:
- JNI_OnLoad 地址:

## 桥接表

| Java 类 | Java 方法 | JNI 签名 | Native 函数 | SO + RVA | 注册方式 |
|---------|----------|---------|------------|----------|---------|
| com.xxx.Yyy | doSign | (Ljava/lang/String;J)[B | sub_1234 | libtarget.so +0x1234 | RegisterNatives |

## 最短闭环
1. Java 入口: `com.xxx.Yyy.doSign(body, timestamp)`
2. Native 实现: `libtarget.so sub_1234` (RVA 0x1234)
3. 输出: 返回 byte[] 签名结果
4. 验证: [hook 日志 / 交叉验证方法]
```

## 实战补充：OLLVM 场景下 libart.so 符号搜索

上方第 92 行的 RegisterNatives Hook 脚本通过 `JNIEnv` 虚函数表第 215 项定位。当 SO 做了 OLLVM 混淆时，还可以直接搜索 `libart.so` 导出符号：

- 在 `Module.enumerateSymbolsSync("libart.so")` 中搜索含 `art` + `JNI` + `RegisterNatives` 且**不含** `CheckJNI` 的符号
- `args[1]` = jclass，通过 `jniEnv.getClassName()` 转可读类名
- `args[2]` → `JNINativeMethod` 数组，每元素 3 个指针：name / sig / fnPtr
- `Process.findModuleByAddress(fnPtr)` 反查所属 SO 和偏移

此方法与上方脚本互补：虚函数表方式更通用，符号搜索方式在特定 ROM 上更可靠。


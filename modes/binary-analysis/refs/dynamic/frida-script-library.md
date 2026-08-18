# Frida 脚本库集中索引（按用途分类）

> 定位：把分散在各篇的 frida 脚本（tools-dynamic.md、frida-cookbook、frida-bypass-kit、frida-objection-deep、android-reverse 脚本集）
> 收拢为**按用途分类的实战脚本库**——每类给可执行骨架 + 适用场景 + 判据。
> 本篇是「索引 + 模板」，深度用法（Objection/Gadget 部署/SSL 多层绕过）见 `mobile/mobile-reverse/references/frida-objection-deep.md`；
> 反检测套件见 `mobile/apk-reverse/references/frida-bypass-kit.md`。
> 工具按检测制：`command -v frida frida-trace` 探测，缺失走四级兜底。

---

## 0. 通用骨架

```javascript
// 所有脚本共享的起手：attach 还是 spawn 决定时机
// spawn 模式（从进程启动就 hook，适合早期反调试/初始化）：
//   frida -f ./target -l hook.js --no-pause
// attach 模式（进程已跑，适合网络/文件 API）：
//   frida -p <pid> -l hook.js
```

判据：脚本加载无报错、目标进程运行、`console.log` 输出命中预期调用。

---

## 1. 基础模板族（进程/模块/导出表定位）

```javascript
// 枚举已加载模块（找目标 so/dylib/exe 基址）
Process.enumerateModules().forEach(function(m) {
    console.log(m.name, m.base, m.size, m.path);
});

// 枚举某模块导出（定位函数地址）
var mod = Process.getModuleByName("libnative.so");
mod.enumerateExports().forEach(function(e) {
    console.log(e.type, e.name, e.address);
});

// 解析符号地址（找非导出内部函数用偏移）
var base = Module.getBaseAddress("libnative.so");
var target = base.add(0x1234);   // 用 IDA/Ghidra 静态偏移 + 基址
console.log("target:", target);
```

适用场景：开工确认目标模块/函数地址、把静态偏移转运行时地址。
判据：模块/导出枚举输出与静态分析一致；`target` 地址可下断点。

---

## 2. API 追踪（Interceptor.attach 模板）

```javascript
// 通用 attach 模板：记录参数 + 返回值 + 调用栈
function trace(exportName) {
    var addr = Module.findExportByName(null, exportName);
    if (!addr) { console.log("[!] not found:", exportName); return; }
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.arg0 = args[0]; this.arg1 = args[1];
            console.log(">>> " + exportName + "(" + args[0] + ", " + args[1] + ")");
            // 调用栈（定位谁调的）
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join("\n"));
        },
        onLeave: function(retval) {
            console.log("<<< " + exportName + " => " + retval);
        }
    });
}
["read", "write", "recv", "send", "CreateFileW", "RegOpenKeyExW"].forEach(trace);
```

参数/返回值格式化要点：

```javascript
// 字符串参数
var s = Memory.readUtf8String(args[0]);
var w = args[0].readUtf16String();          // 宽字符串
// 指针 + 长度缓冲
var buf = Memory.readByteArray(args[0], args[1].toInt32());
// 返回值十六进制
console.log("ret = 0x" + retval.toString(16));
```

适用场景：追踪网络/文件/注册表 API，还原「谁在什么时机读写什么」。
判据：trace 输出能还原 API 调用序列 + 关键参数（C2 地址/文件路径/注册表键）。

---

## 3. 反调试绕过（ptrace/时间/环境检测 hook）

```javascript
// 3.1 ptrace(PTRACE_TRACEME) 检测绕过（Linux/Android native）
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter: function(args) { this.req = args[0].toInt32(); },
    onLeave: function(retval) {
        if (this.req === 0 /* PTRACE_TRACEME */) {
            retval.replace(0);
            console.log("[*] ptrace(TRACEME) bypassed");
        }
    }
});

// 3.2 时间检测绕过（clock_gettime / gettimeofday 固定返回）
Interceptor.attach(Module.findExportByName(null, "clock_gettime"), {
    onLeave: function(retval) {
        // 固定 tv_sec/tv_nsec，规避「执行过慢=被调试」的时序检测
        var ts = this.context.rsi;          // x86_64 第二参
        Memory.writeU64(ts, 0); Memory.writeU64(ts.add(8), 0);
    }
});

// 3.3 环境/调试器检测绕过（Android isDebuggerConnected + /proc 检测）
Java.perform(function() {
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() { return false; };
    // 绕过常见 root/调试文件检测
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var p = this.getAbsolutePath();
        if (p.indexOf("frida") >= 0 || p.indexOf("su") >= 0) return false;
        return this.exists();
    };
});
```

适用场景：样本带反调试/反 hook/反 root 时，先消除检测再追真实逻辑。
判据：hook 后样本不再「检测到调试即退出」，能进入目标代码路径（与静态结论互证）。

---

## 4. SSL unpinning（Android/iOS 通用模板）

```javascript
// 4.1 iOS/macOS 通用：hook SecTrustEvaluate 放行证书校验
var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
    Memory.writeU32(result, 4);      // kSecTrustResultUnspecified（信任）
    return 0;                        // errSecSuccess
}, 'int', ['pointer', 'pointer']));

// 4.2 Android OkHttp CertificatePinner 绕过
Java.perform(function() {
    try {
        var Pinner = Java.use("okhttp3.CertificatePinner");
        Pinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
    } catch (e) {}
    // 4.3 通用：接管 TrustManager 返回空信任链
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    // 具体实现类按目标 SSL 栈（Conscrypt/OpenSSL）选择，见 frida-objection-deep.md
});
```

适用场景：样本做证书固定（pinning），需解密其 HTTPS 流量做协议还原。
判据：hook 后 mitmproxy/代理能抓到明文 HTTPS 请求（说明证书校验被放行）。
> 多层绕过（OkHttp/TrustManager/WebView/NetworkSecurityConfig）完整脚本见 `frida-objection-deep.md`。

---

## 5. 内存操作（读/写/扫描/补丁模板）

```javascript
// 5.1 读内存
var addr = ptr("0x7ff000001000");
console.log(hexdump(addr, { length: 64 }));         // 十六进制 dump
console.log(Memory.readUtf8String(addr));           // 读字符串

// 5.2 写内存（改全局标志/密钥）
Memory.writeU8(ptr("0x..."), 0x1);
Memory.writeUtf8String(ptr("0x..."), "patched");

// 5.3 扫描模式（找 flag{ / 关键字节）
Process.enumerateRanges('r--').forEach(function(range) {
    Memory.scan(range.base, range.size, "66 6c 61 67 7b", {  // "flag{"
        onMatch: function(address, size) {
            console.log("[!] found at", address, Memory.readUtf8String(address, 64));
        }, onComplete: function() {}
    });
});

// 5.4 补丁（NOP 一段代码 / 改写跳转）
var base = Module.getBaseAddress("target.exe");
Memory.patchCode(base.add(0x1234), 2, function(code) {
    var writer = new X86Writer(code, { pc: base.add(0x1234) });
    writer.putNop(); writer.putNop();       // 两条 NOP
    writer.flush();
});
```

适用场景：动态改标志跳过检测、扫描内存找密钥/flag、补丁去掉检查分支。
判据：补丁后行为改变（检测被跳过/密钥被读出），且改动地址与静态偏移一致。

---

## 6. native 层 hook（so/dylib 函数 hook + RPC 导出）

```javascript
// 6.1 hook so/dylib 内部函数（按偏移，非导出也可）
var base = Module.findBaseAddress("libnative.so");
Interceptor.attach(base.add(0x1A2C), {
    onEnter: function(args) {
        // 记录参数 + 返回地址
        console.log("native_fn called, ret=", this.context.lr || this.context.rip);
    }
});

// 6.2 RPC 导出：把 hook 能力暴露给外部 Python 调用
rpc.exports = {
    // Python 侧：script.exports_sync.setflag(0x1234, 1)
    setflag: function(addr, val) {
        Memory.writeU32(ptr(addr), val);
        return "ok";
    },
    // Python 侧：script.exports_sync.dump(addr, len)
    dump: function(addr, len) {
        return Array.from(new Uint8Array(Memory.readByteArray(ptr(addr), len)))
            .map(function(b) { return b.toString(16).padStart(2, '0'); }).join(' ');
    }
};
```

Python 侧驱动：

```python
import frida
session = frida.attach("target")            # 或 frida.spawn + resume
script = session.create_script(open("hook.js").read())
script.load()
print(script.exports_sync.dump(0x7ff000001000, 32))   # 调 JS 侧 RPC
```

适用场景：native 层加密/校验逻辑需要「外部批量驱动」时，用 RPC 把 hook 能力导出给 Python 脚本循环调用（如逐字节爆破/批量 dump）。
判据：RPC 调用返回预期数据，Python 能批量驱动 hook 完成自动化。

---

## 7. 脚本选型速查

| 需求 | 用哪类 | 相关深度篇 |
|---|---|---|
| 找目标函数/模块地址 | §1 基础模板 | tools-dynamic.md（Frida 基础） |
| 还原 API 调用序列 | §2 API 追踪 | tools-dynamic.md |
| 反调试/反 hook 对抗 | §3 反调试绕过 | anti-debugging.md、frida-bypass-kit.md |
| 解密 HTTPS 流量 | §4 SSL unpinning | frida-objection-deep.md |
| 动态改标志/找密钥 | §5 内存操作 | tools-dynamic.md（Memory.patchCode） |
| native 批量自动化 | §6 native + RPC | android-reverse/references/frida-native-playbook.md |

---

## 来源与延伸

- 深度用法（Objection/Gadget/SSL 多层）：`mobile/mobile-reverse/references/frida-objection-deep.md`。
- 反检测套件：`mobile/apk-reverse/references/frida-bypass-kit.md`、`frida-cookbook.md`。
- Android native/JNI hook：`mobile/android-reverse/references/frida-native-playbook.md`、`frida-java-playbook.md`。
- 动态分析总纲（Frida/angr/lldb 分工）：`methodology/reverse-engineering/references/tools-dynamic.md`。

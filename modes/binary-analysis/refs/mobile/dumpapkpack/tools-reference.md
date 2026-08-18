# 工具和环境参考

## 必备工具

| 工具 | 用途 | 安装 |
|------|------|------|
| **adb** | Android 设备通信 | Android SDK Platform-Tools |
| **jadx** / **jadx-gui** | DEX 反编译 | `apt install jadx` / `brew install jadx` |
| **Python 3** | 脚本执行 (DEX 提取等) | 系统自带 |
| **unzip** | APK 解包 | 系统自带 |

## 可选工具

| 工具 | 用途 | 安装 | 备注 |
|------|------|------|------|
| **frida** (frida-tools) | 动态 hook / dump | `pip install frida-tools` | 标准和隐蔽注入均需要客户端 |
| **frida-dexdump** | Frida DEX dump 工具 | `pip install frida-dexdump` | 走标准 ClassLoader 的壳有效 |
| **apktool** | APK 解包/重打包 | `brew install apktool` / `apt install apktool` | 可选，unzip 通常够用 |
| **BlackDex64** | 一键脱壳 | [GitHub](https://github.com/CodingGay/BlackDex) | 部分壳可用 |
| **keytool** | 生成 debug 签名密钥 | JDK 自带 | 重打包时需要 |
| **apksigner** | APK 签名 | Android SDK Build-Tools | 重打包时需要 |
| **zipalign** | APK 对齐优化 | Android SDK Build-Tools | 重打包时需要 |

## 隐蔽注入相关

本方案中的「隐蔽注入」是一个通用概念，指通过 Zygisk / Xposed 等框架在进程级别注入 Frida Gadget，
而非运行独立的 frida-server 进程。

### 关键特征（不绑定具体工具）

| 特征 | 说明 |
|------|------|
| 注入层级 | Zygisk 层（进程 fork 时注入） |
| 运行形态 | 无独立进程，Gadget SO 随目标进程加载 |
| 端口 | 自定义（从配置文件读取） |
| 连接方式 | `frida -H 127.0.0.1:<port> -n Gadget` |
| 隐蔽性 | 无进程名特征，无固定端口，maps 中 SO 名称可混淆 |

### 发现隐蔽注入能力

```bash
# 1. 检查 Zygisk / Magisk 模块
adb shell "su -c 'ls /data/adb/modules/'" 2>/dev/null

# 2. 搜索 Gadget SO 和配置文件（通用探测）
adb shell "su -c 'find /data/adb/modules/ -type f \( -name \"libgadget.so\" -o -name \"libgadget.config.so\" -o -name \"*.config.so\" \)'" 2>/dev/null

# 3. 提取端口
adb shell "su -c 'find /data/adb/modules/ -name \"*.config.so\" -exec cat {} \;'" 2>/dev/null \
  | grep -oP '"port":\s*\K\d+'

# 4. 查找目标 App 注入配置（注入框架的管理配置）
#    位置因框架而异，通常在框架 App 的 files/ 目录下
#    通用搜索: 查找包含目标包名的 JSON 配置文件
adb shell "su -c 'find /data/data/ -name \"config.json\" -exec grep -l <target_pkg> {} \;'" 2>/dev/null
```

### 配置目标 App 注入

```bash
# 通用流程（不绑定具体框架）:
# 1. 读取当前配置
adb shell "su -c 'cat <config_path>'" > /tmp/inject_config.json

# 2. 本地修改: 添加目标包名, inject: true, delay: 800
# ⚠️ 必须通过本地文件 adb push 推送，不要在 shell 中 echo
#    原因: shell 引号转义会丢失 JSON 格式

# 3. 推送
adb push /tmp/inject_config.json /data/local/tmp/inject_config.json
adb shell "su -c 'cp /data/local/tmp/inject_config.json <config_path>'"

# 4. 修复权限（匹配原文件 owner）
adb shell "su -c 'chown <owner>:<group> <config_path>'"
adb shell "su -c 'chmod 600 <config_path>'"

# 5. 验证
adb shell "su -c 'cat <config_path>'"
```

### 连接和 dump

```bash
# 端口转发
adb forward tcp:$STEALTH_PORT tcp:$STEALTH_PORT

# 验证连接
frida -H 127.0.0.1:$STEALTH_PORT -n Gadget \
  -e "console.log('OK, PID=' + Process.id)"

# dump DEX
mkdir -p ./output/dex/  # ⚠️ 必须预先创建
frida-dexdump -H 127.0.0.1:$STEALTH_PORT -n Gadget -o ./output/dex/
```

## 模拟器配置

### 推荐: Android Studio AVD

| 参数 | 推荐值 | 说明 |
|------|--------|------|
| 设备 | Pixel 6 Pro | 足够大的屏幕 |
| 系统镜像 | API 27 (Android 8.1) | 较好的兼容性 |
| 镜像类型 | **google_apis** (非 PlayStore) | 可直接 `adb root` |
| RAM | 2048 MB+ | 保证 App 运行流畅 |
| 内部存储 | 2048 MB+ | 安装 App 和 dump 产物 |
| GPU 加速 | 开启 | 提升模拟器性能 |

```bash
# 启动模拟器
emulator -avd Pixel_6_Pro_API_27 -no-snapshot-load

# 获取 Root
adb root

# 验证
adb shell id
# 预期: uid=0(root) gid=0(root)
```

### 注意事项

- **不要使用 PlayStore 镜像** — 无法直接 adb root
- API 27-30 兼容性较好，避免使用最新 API 版本
- frida-server 在某些 API 版本的模拟器上可能无法正常 attach（API 27 已知有问题）

## 目录约定

```
<project_root>/
├── SKILL.md                ← 主 skill 文件
├── README.md               ← 说明文档
├── packer-360jiagu.md      ← 360加固脱壳方案
├── packer-ijiami.md        ← 爱加密脱壳方案
├── packer-template.md      ← 新壳方案模板
├── tools-reference.md      ← 本文件
└── scripts/                ← 辅助脚本
    └── extract_dex.py          DEX 从内存 dump 中提取
```

## 常用命令速查

```bash
# 检查设备连接
adb devices

# 安装/卸载 APK
adb install <file.apk>
adb uninstall <package>

# 启动 App
adb shell am start -n <package>/.MainActivity

# 获取 PID
adb shell pidof <package>

# 查看内存映射
adb shell "cat /proc/<PID>/maps"

# Root 权限操作
adb root                    # 模拟器
adb shell "su -c <cmd>"     # Root 真机

# 拉取文件
adb pull /remote/path/ ./local/path/

# 推送文件
adb push ./local/file /remote/path/

# 查看 logcat
adb logcat | grep -i "frida\|crash\|fatal"
```

## DEX 格式参考

| 偏移 | 大小 | 字段 | 有效值 |
|------|------|------|--------|
| 0x00 | 8 bytes | magic | `64 65 78 0a 30 33 35 00` ("dex\n035\0") |
| 0x20 | 4 bytes | file_size | 文件总大小 (little-endian) |
| 0x24 | 4 bytes | header_size | `70 00 00 00` (112 bytes) |
| 0x28 | 4 bytes | endian_tag | `12 34 56 78` (little-endian) |
| 0x38 | 4 bytes | class_defs_size | 类定义数量 |

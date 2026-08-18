# 环境准备指南

推荐工具：

- `JDK 17+`
- `jadx`
- `apktool`
- `bundletool`
- `apkanalyzer`
- `adb`
- `frida` + `frida-server`
- `IDA Pro`
- `JEB`

## 自动化安装

使用脚本自动检查和安装依赖：

```bash
bash scripts/check-deps.sh                       # 检查依赖
bash scripts/install-dep.sh <java|jadx|fernflower|apktool|adb>  # 安装单个
```

Windows 用户使用 `.ps1` 版本。详见 `scripts/` 目录。

## 各平台详细安装

### Java JDK 17+

jadx 和 Fernflower 均需要 Java 17+。

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install openjdk-17-jdk

# Fedora
sudo dnf install java-17-openjdk-devel

# Arch Linux
sudo pacman -S jdk17-openjdk

# macOS (Homebrew)
brew install openjdk@17
# macOS 安装后需添加到 shell profile：
# export PATH="$HOMEBREW_PREFIX/opt/openjdk@17/bin:$PATH"
```

验证：`java -version` 应显示 17.x 或更高。

### jadx

```bash
# 选项 1: GitHub Releases（推荐）
# 从 https://github.com/skylot/jadx/releases 下载 jadx-*.zip
unzip jadx-*.zip -d ~/jadx
export PATH="$HOME/jadx/bin:$PATH"

# 选项 2: Homebrew (macOS / Linux)
brew install jadx

# 选项 3: 从源码构建
git clone https://github.com/skylot/jadx.git && cd jadx && ./gradlew dist
# 产物在 build/jadx/bin/
```

验证：`jadx --version`

### Vineflower / Fernflower（可选，推荐）

Vineflower 是 Fernflower 的活跃 fork，对现代 Java/Kotlin 支持更好，优先使用。

```bash
# 选项 1: Vineflower GitHub Releases（推荐）
# 从 https://github.com/Vineflower/vineflower/releases 下载 vineflower-*.jar
mkdir -p ~/vineflower && mv vineflower-*.jar ~/vineflower/vineflower.jar
export FERNFLOWER_JAR_PATH="$HOME/vineflower/vineflower.jar"

# 选项 2: 从源码构建 Fernflower
git clone https://github.com/JetBrains/fernflower.git && cd fernflower && ./gradlew jar
export FERNFLOWER_JAR_PATH="$(pwd)/build/libs/fernflower.jar"

# 选项 3: Homebrew (Vineflower)
brew install vineflower
```

验证：`java -jar "$FERNFLOWER_JAR_PATH" --version`

> Fernflower 仅处理 JVM 字节码（JAR/class）。APK/DEX 需先用 dex2jar 转换。

### dex2jar（可选，Fernflower 处理 APK 时需要）

```bash
# GitHub Releases — 从 https://github.com/ThexXTURBOXx/dex2jar/releases 下载
unzip dex-tools-*.zip -d ~/dex2jar
export PATH="$HOME/dex2jar:$PATH"

# Homebrew
brew install dex2jar
```

验证：`d2j-dex2jar --help`

### 可选工具

```bash
# apktool
sudo apt install apktool          # Ubuntu/Debian
brew install apktool              # macOS
# 手动安装: https://apktool.org/docs/install

# adb
sudo apt install adb              # Ubuntu/Debian
brew install android-platform-tools  # macOS

# 从设备拉取 APK
adb shell pm list packages | grep <keyword>
adb shell pm path com.example.app
adb pull /data/app/com.example.app-xxxx/base.apk ./app.apk
```

## 详细工具指南

| 工具 | 参考文档 |
|---|---|
| jadx | `references/jadx-usage.md` |
| Fernflower / Vineflower | `references/fernflower-usage.md` |
| 引擎选择策略 | `references/engine-selection.md` |

## Windows 中文编码

Windows PowerShell 默认编码不是 UTF-8，读取中文 Markdown、实验记录、中文日志时必须显式 UTF-8，**首次读取就指定**，不要先用默认编码读再向用户汇报"乱码后重读"：

```powershell
# 读中文文件
Get-Content -LiteralPath .\docs\experiment.md -Encoding UTF8 -Raw
Get-Content -LiteralPath .\logs\some.log -Encoding UTF8 -Tail 80
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# 脚本处理优先用 Python 显式编码
python -c "from pathlib import Path; print(Path('docs/experiment.md').read_text(encoding='utf-8', errors='replace'))"
```

读 Skill 自身或 `references/*.md` 时同样使用 `-Encoding UTF8`。Linux/macOS 无此问题。

## 最低检查

- `adb devices`
- `jadx --version`
- `java -version`
- `frida --version`
- `bundletool version`

## 故障排除

| 问题 | 解决方案 |
|---|---|
| `jadx: command not found` | 确认 jadx `bin/` 目录在 `$PATH` 中 |
| `Error: Could not find or load main class` | Java 缺失或版本过低 — 用 `java -version` 确认 17+ |
| jadx 大 APK 内存不足 | 增大堆：`jadx -Xmx4g -d output app.apk` 或设置 `JAVA_OPTS="-Xmx4g"` |
| 反编译代码大量 `// Error` | 使用 `--show-bad-code` 输出部分结果，或对混淆目标使用 `--deobf` |
| Fernflower 在某个方法上挂起 | 使用 `-mpm=60` 设置单方法 60 秒超时 |
| Fernflower JAR 未找到 | 设置 `FERNFLOWER_JAR_PATH` 环境变量为 JAR 完整路径 |
| dex2jar 报 `ZipException` | APK 可能有非标准 ZIP 结构 — 改用 jadx 直接处理 |

## Android 动态分析最低要求

- 明确设备是实体机还是模拟器
- 明确是否 root
- 确认 `frida-server` 与客户端版本一致
- 明确 attach 模式：`spawn / attach-name / attach-pid`
- 需要抓启动期逻辑时，先确认是否涉及多进程与 `isolated process`

## 经验规则

- 首轮静态分诊不依赖设备
- `AAB / APKS / split` 任务先完成模块重组再做结论
- 运行时证据不足时再上 Frida
- 高对抗任务优先从 `run/*.js` baseline 改起，不要从空白脚本起步
- `A6 / A7` 默认顺序是：先默认版 `run/*.js` 验证切入点，再切 `run/*-advanced.js` 扩高对抗探测面
- 遇到 Flutter/Hermes/Unity 先识别运行时再选工具链
- 遇到抓包失败先分清 Java 与 Native 网络栈再谈 pinning
- 遇到 hook 未命中先排查进程、时机、ART 编译状态
- 需要 Native 行为结论时，优先先做 Bridge 再做 Native hook
- `A6 / A7` 任务默认补读 `references/a6-a7-failure-pattern-cookbook.md`


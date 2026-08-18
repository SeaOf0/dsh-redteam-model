# Fernflower / Vineflower 使用参考

## 何时使用 Fernflower

| 场景 | 推荐引擎 | 原因 |
|---|---|---|
| 通用反编译 | jadx | 最好的默认选择 |
| jadx 输出有问题 | fernflower | 不同反编译后端可能更好 |
| Lambda / 内部类 | fernflower | 有时处理更准确 |
| Kotlin 协程 | vineflower | 对 Kotlin 支持更好 |
| 需要交叉验证 | both | 两个引擎互补 |

**建议**：Vineflower 是 Fernflower 的活跃 fork，修复了大量 bug，对现代 Java/Kotlin 支持更好。优先使用 Vineflower。

## 基本用法

```bash
# Fernflower / Vineflower
fernflower [options] <input.jar> <output-dir>
vineflower [options] <input.jar> <output-dir>
```

## 关键选项

| 选项 | 默认 | 说明 |
|---|---|---|
| `-dgs=1` | 0 | 生成调试信息（方法签名等） |
| `-ren=1` | 0 | 重命名混淆标识符 |
| `-mpm=60` | 45 | 最大处理方法数（增大可处理更复杂方法） |
| `-hdc=0` | 1 | 不分解复杂表达式 |
| `-asc=1` | 0 | 编码为 ASCII |
| `-udv=1` | 0 | 使用调试变量名 |
| `-log=TRACE` | WARN | 详细日志 |

### 推荐预设

```bash
# 标准分析
vineflower -dgs=1 -ren=1 input.jar output/

# 高对抗目标
vineflower -dgs=1 -ren=1 -mpm=90 -hdc=0 input.jar output/

# 调试模式
vineflower -dgs=1 -ren=1 -log=TRACE input.jar output/
```

## APK 工作流

Fernflower 不直接支持 APK/DEX 输入，需要 dex2jar 中间步骤：

```bash
# 1. APK → JAR
d2j-dex2jar.sh target.apk -o target.jar

# 2. JAR → Java 源码
vineflower -dgs=1 -ren=1 target.jar output/
```

或使用自动化脚本：

```bash
bash scripts/decompile.sh target.apk -o output/ --engine fernflower
```

## 支持的输入格式

| 格式 | 直接支持 | 需要预处理 |
|---|---|---|
| `.jar` | 是 | — |
| `.class` | 是 | — |
| `.apk` | 否 | dex2jar → .jar |
| `.dex` | 否 | dex2jar → .jar |
| `.aar` | 否 | unzip + dex2jar |

## Vineflower vs Fernflower 对比

| 特性 | Fernflower | Vineflower |
|---|---|---|
| 维护状态 | 已停更 | 活跃维护 |
| Kotlin 支持 | 基础 | 增强 |
| Java 17+ | 部分 | 完整 |
| Lambda 处理 | 基础 | 改进 |
| Pattern Matching | 不支持 | 支持 |
| Records | 不支持 | 支持 |
| 输出质量 | 一般 | 较高 |

## 常见问题

### OutOfMemoryError

```bash
# 增大 JVM 堆内存
java -Xmx4g -jar vineflower.jar -dgs=1 input.jar output/
```

### 超时处理

使用 `decompile.sh` / `.ps1` 中的 `FERNFLOWER_TIMEOUT_SECONDS` 环境变量：

```bash
export FERNFLOWER_TIMEOUT_SECONDS=600  # 10 分钟
bash scripts/decompile.sh target.apk --engine fernflower
```

### 部分成功

Fernflower 遇到无法反编译的方法会跳过并记录日志。输出可能不完整但已有的部分仍然有用。与 jadx 输出交叉对比可覆盖更多代码。

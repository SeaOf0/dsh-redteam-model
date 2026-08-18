# dumpapkpack — APK 加壳识别与脱壳方案路由器

## 概述

`dumpapkpack` 是一个面向红队安全研究的 APK 脱壳自动化 skill。它不是单一脱壳工具，而是一个 **策略路由器**：根据壳类型、运行环境能力和壳防御强度，自动选择最优脱壳方案并执行。

## 核心设计

```
输入 APK
   │
   ▼
[1] 壳识别 ─── 解包 + 特征指纹匹配
   │
   ▼
[2] 环境探测 ─── Root / 模拟器 / 标准Frida / 隐蔽注入 / BlackDex
   │
   ▼
[3] 壳防御评估 ─── 反Frida能力 / 反调试能力 / DEX加载路径隐蔽性
   │
   ▼
[4] 策略路由 ─── 壳类型 × 环境能力 × 防御等级 → 最优方案
   │
   ▼
[5] 执行脱壳 ─── 引用 packer-*.md 中的具体方案
   │
   ▼
[6] 验证产物 ─── DEX magic + endian tag + class 数量
   │
   ▼
[7] 反编译输出 ─── jadx → src/
```

## 关键特性

### 区分「标准 Frida」和「隐蔽注入」

这是本 skill 与简单脱壳脚本的核心区别：

| | 标准 Frida (frida-server) | 隐蔽注入 |
|---|---|---|
| 运行形态 | 独立进程 | 注入到目标进程，无独立进程 |
| 默认端口 | 27042（固定） | 自定义（从配置读取） |
| 壳检测风险 | **高** — 进程名、端口、SO 特征均可被扫到 | **低** — Zygisk 层注入，无进程特征 |
| 适用壳类型 | 无 Frida 检测的壳 | **有 Frida 检测的壳** |

路由决策时自动根据壳的反 Frida 能力选择：
- 壳无/弱 Frida 检测 → 标准 Frida dump
- 壳有 Frida 检测但 DEX 走标准 ClassLoader → 隐蔽注入 + frida-dexdump
- 壳有强反 Frida 且 DEX 路径隐蔽 → dd 直读 /proc/PID/mem

### 壳防御等级评估

每个壳方案文档（`packer-*.md`）中包含标准化的防御评估表，涵盖：

| 维度 | 影响 |
|------|------|
| frida-server 进程检测 | 决定标准 Frida 是否可用 |
| frida-agent SO 特征检测 | 决定隐蔽注入是否会被检测 |
| 签名校验阻断 | 决定是否需要原始签名才能脱壳 |
| DEX 加载路径隐蔽 | 决定 frida-dexdump 是否有效 |

## 支持的加固方案

| 加固方案 | 防御等级 | 脱壳状态 | 文档 |
|----------|----------|----------|------|
| 360加固保 VIP (libjgcrqc) | HIGH | ✅ 已验证 | [packer-360jiagu.md](packer-360jiagu.md) |
| 360加固保 (libjgcch) | HIGH+ | ⏳ 待突破 | [packer-360jiagu.md](packer-360jiagu.md) |
| 爱加密 V3+ | MEDIUM | ✅ 已验证 | [packer-ijiami.md](packer-ijiami.md) |
| 梆梆加固 | 待评估 | 待添加 | packer-bangcle.md |
| 腾讯乐固 | 待评估 | 待添加 | packer-legu.md |
| 网易易盾 | 待评估 | 待添加 | packer-yidun.md |

## 文件结构

```
dumpapkpack/
├── README.md               ← 本文件
├── SKILL.md                ← 主 skill 文件（工作流 + 环境探测 + 策略路由）
├── packer-360jiagu.md      ← 360加固保脱壳方案（含防御评估）
├── packer-ijiami.md        ← 爱加密 V3+ 脱壳方案（含防御评估）
├── packer-template.md      ← 新壳方案模板（含防御评估模板）
└── tools-reference.md      ← 工具和环境参考
```

## 使用方式

### 1. 壳识别

```bash
# 解包 APK
unzip -o <input.apk> -d /tmp/apk_check > /dev/null 2>&1

# 运行识别
find /tmp/apk_check/assets/ \( -name "ijiami.dat" -o -name "libjgcrqc*" -o -name "libjgcch*" \)
strings /tmp/apk_check/classes.dex | grep -iE "stub|shell|jiagu|ijiami|ijm|dataencryption"
```

### 2. 环境探测

```bash
# Root
adb shell "su -c id"

# 标准 Frida
adb shell "ps -ef | grep frida-server"

# 隐蔽注入
adb shell "su -c 'find /data/adb/modules/ -name \"*.config.so\" -exec cat {} \;'"
```

### 3. 选择方案并执行

根据 SKILL.md 中的路由矩阵，读取对应的 `packer-*.md`，按步骤执行。

## 扩展新的壳方案

1. 复制 `packer-template.md` 为 `packer-<name>.md`
2. 填写壳特征指纹
3. **填写反 Frida / 反调试能力评估表**（关键步骤）
4. 编写脱壳方案
5. 在 `SKILL.md` 的「支持的加固方案」表格中添加一行
6. 在 `SKILL.md` 的「识别特征表」中添加识别条目

## 环境要求

| 要求 | 说明 |
|------|------|
| adb | Android 设备通信 |
| jadx | DEX 反编译 |
| Python 3 | 辅助脚本 |
| Root 设备或模拟器 | 大部分方案需要 Root |
| frida + frida-dexdump | Frida dump 方案需要 |
| 隐蔽注入框架 | 有 Frida 检测的壳需要 |

## 实战记录

### 爱加密 V3+ — com.lphtsccft (涨乐财富通)

- **方案**: 隐蔽注入 (ZygiskGadget) + frida-dexdump
- **设备**: Root 真机 / Android 15 (SDK 35) / arm64-v8a
- **产物**: 82 个 DEX / 122 MB / 7,240 个 Java 文件
- **耗时**: ~15 min（含环境配置）

### 360加固保 VIP — party_cnooc-3.0.8.apk

- **方案**: Root + JIT 内存直读 (dd)
- **设备**: Android 模拟器 / API 27
- **产物**: 3 个 DEX / ~20 MB / 662 个 Java 文件
- **耗时**: ~20 min

## License

MIT

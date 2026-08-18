---
name: dumpapkpack
description: >
  APK 加壳保护识别与脱壳方案路由器。支持 360加固保、爱加密、梆梆加固、
  腾讯乐固、网易易盾等主流加固方案。根据壳特征指纹自动识别加固类型，
  探测运行环境（Root / 模拟器 / Frida 注入能力 / 隐蔽注入能力），
  综合壳的反 Frida / 反调试能力，选择最优脱壳策略。
  涵盖 Root 内存直读、标准 Frida dump、隐蔽注入 dump、BlackDex 一键脱壳、
  FART 定制 ROM 等多种方法。
license: MIT
compatibility: macOS/Linux, requires adb + jadx
allowed-tools: Bash Read Write Edit Glob Grep Agent
metadata:
  user-invocable: "false"
---

# APK Packer Unpacker (dumpapkpack)

本 skill 是一个脱壳方案路由器：识别壳类型 → 探测环境 → 评估壳防御能力 → 选择策略 → 执行脱壳。

## 工作流程

```
输入 APK
   │
   ▼
[1] 壳识别 (解包 + 特征指纹匹配)
   │
   ▼
[2] 环境探测 (adb / root / 模拟器 / 标准Frida / 隐蔽注入 / BlackDex)
   │
   ▼
[3] 壳防御评估 (反Frida能力 / 反调试能力 / 签名校验强度)
   │
   ▼
[4] 策略路由 (壳类型 × 环境能力 × 壳防御能力 → 最优方案)
   │
   ▼
[5] 执行脱壳 (引用 packer-*.md 中的具体方案)
   │
   ▼
[6] 验证产物 (DEX magic + endian tag + class 数量)
   │
   ▼
[7] 反编译输出 (jadx → src/)
```

---

## 1. 壳识别

解包 APK，检查特征指纹：

### 识别特征表

| 特征文件 / 特征 | 壳类型 | 详情文件 |
|----------------|--------|----------|
| `assets/libjgcrqc*.so` 存在 | 360加固保 | [packer-360jiagu.md](packer-360jiagu.md) |
| DEX 头部 magic `qh\x00\x01` | 360加固保 VIP | [packer-360jiagu.md](packer-360jiagu.md) |
| `AndroidManifest` Application 为 `com.stub.StubApp` 或反包名路径 | 360加固保 | [packer-360jiagu.md](packer-360jiagu.md) |
| `assets/ijiami.dat` 存在 | 爱加密 V3+ | [packer-ijiami.md](packer-ijiami.md) |
| `assets/ijm_lib/*/libexec.so` + `libexecmain.so` | 爱加密 V3+ | [packer-ijiami.md](packer-ijiami.md) |
| `com.ijm.dataencryption.DETool` 在 classes.dex 中 | 爱加密 V3+ | [packer-ijiami.md](packer-ijiami.md) |
| `s.h.e.l.l.A` 壳入口类 | 爱加密 V3+ | [packer-ijiami.md](packer-ijiami.md) |
| `assets/libijiami*.so` | 爱加密 (旧版) | [packer-ijiami.md](packer-ijiami.md) |
| `lib/jiagu/*.so` 或 `assets/libjiagu*.so` | 梆梆加固 | packer-bangcle.md (待添加) |
| `lib/libshell-super.*.so` | 腾讯乐固 | packer-legu.md (待添加) |
| `assets/libtprt.so` | 网易易盾 | packer-yidun.md (待添加) |
| `assets/libsecmain.so` | 腾讯御安全 | packer-tencent.md (待添加) |
| `assets/libkwscmm.so` | 几维安全 | packer-kiwisec.md (待添加) |
| `assets/libsgmain.so` | 阿里聚安全 | packer-ali.md (待添加) |
| 无明显壳特征 | 可能无壳或未知壳 | 按无壳处理 |

### 识别步骤

```bash
# 解包
unzip -o <input.apk> -d /tmp/apk_check > /dev/null 2>&1

# 检查特征文件
find /tmp/apk_check/assets/ -name "*.so" -o -name "*.dat" -o -name "*.jar" | head -20
find /tmp/apk_check/lib/ -name "*.so" | head -20

# 检查 DEX 头部
xxd -l 8 /tmp/apk_check/classes.dex

# 检查壳入口类
strings /tmp/apk_check/classes.dex | grep -iE "stub|shell|jiagu|ijiami|ijm|bangcle|secneo|dataencryption"

# 检查 AndroidManifest Application 类（需 apktool 或 aapt 解码二进制 XML）
strings /tmp/apk_check/AndroidManifest.xml | head -60

# 动态识别（安装后）
adb shell dumpsys package <pkg> | grep -E "primaryCpuAbi|versionName"
adb shell "su -c 'ls /data/app/*/<pkg>*/'"
```

如果无法通过静态特征识别，尝试动态识别：
- 安装 App 后检查 `/data/app/*/lib/` 下的 SO 文件名
- 运行时 `cat /proc/PID/maps` 查看加载的 SO

---

## 2. 环境探测

按以下顺序检测运行环境能力，**重点区分标准 Frida 和隐蔽注入**：

```bash
# 1. adb 连接
adb devices

# 2. Root 权限
adb shell "su -c id" 2>/dev/null || adb shell "id"  # emulator root = uid 0

# 3. 模拟器检测
adb shell "getprop ro.hardware | grep -q goldfish\|ranchu"

# 4. 标准 Frida（frida-server 独立进程）
adb shell "ps -ef | grep frida-server" 2>/dev/null
frida-ps -U 2>/dev/null | head -5

# 5. 隐蔽注入能力检测（重要）
#    检测设备上是否存在隐蔽注入框架，不绑定具体工具名称
#    判据：Zygisk/Xposed 类模块中包含 gadget SO
adb shell "su -c 'ls /data/adb/modules/'" 2>/dev/null
#    扫描所有模块目录，查找包含 gadget 配置文件的模块
adb shell "su -c 'find /data/adb/modules/ -name \"*.config.so\" -o -name \"libgadget.so\"'" 2>/dev/null
#    从找到的配置中提取监听端口
adb shell "su -c 'find /data/adb/modules/ -name \"*.config.so\" -exec cat {} \;'" 2>/dev/null

# 6. BlackDex 安装
adb shell "pm list packages | grep blackdex\|niunaijun" 2>/dev/null
```

### 环境能力矩阵

| 能力 | 标志 | 影响可选方案 | 隐蔽性 |
|------|------|------------|--------|
| `HAS_ROOT` | `su -c id` 返回 uid 0 | 内存直读、frida-server 部署 | — |
| `IS_EMULATOR` | `ro.hardware` 含 goldfish/ranchu | 可直接 `adb root` | — |
| `HAS_FRIDA_SERVER` | frida-server 进程存在 | frida attach / frida-dexdump | ❌ **可被壳检测** |
| `HAS_STEALTH_INJECT` | 隐蔽注入框架存在（无独立进程，Zygisk 层注入） | 隐蔽 dump / frida-dexdump | ✅ **难以被壳检测** |
| `HAS_BLACKDEX` | BlackDex 包名存在 | 一键脱壳 | ⚠️ 部分壳可检测 |

### 标准 Frida vs 隐蔽注入

这是策略路由的关键区分维度：

| 维度 | 标准 Frida (frida-server) | 隐蔽注入 |
|------|--------------------------|----------|
| 运行形态 | 独立进程，有进程名 | 注入到 Zygisk/目标进程，无独立进程 |
| 默认端口 | 27042（固定） | 自定义（从配置读取） |
| 连接方式 | `frida -U` 或 `frida -H :27042` | `frida -H 127.0.0.1:<port> -n Gadget` |
| 壳检测风险 | **高** — 进程名、端口、maps 中 SO 特征均可被扫到 | **低** — Zygisk 层注入，无进程特征 |
| 适用场景 | 壳无 Frida 检测或检测较弱 | 壳有 Frida 检测（爱加密、梆梆等） |
| 局限性 | 无 | 不影响 DEX 加载路径（360 JIT 类仍需 dd 直读） |

### 隐蔽注入能力发现

```bash
# 步骤 1: 列出所有 Zygisk/Xposed 类模块
adb shell "su -c 'ls /data/adb/modules/'" 2>/dev/null

# 步骤 2: 在模块目录中搜索 gadget 特征（通用探测，不绑定具体名称）
#    gadget SO: 通常命名为 libgadget.so 或类似
#    配置文件: 通常包含 interaction/type/listen/port 等字段
adb shell "su -c 'find /data/adb/modules/ -type f \( -name \"libgadget.so\" -o -name \"libgadget.config.so\" \)'" 2>/dev/null

# 步骤 3: 提取端口
#    从配置文件中提取监听端口
STEALTH_PORT=$(adb shell "su -c 'find /data/adb/modules/ -name \"*.config.so\" -exec cat {} \;'" \
  2>/dev/null | grep -oP '"port":\s*\K\d+' | head -1)
echo "Stealth inject port: $STEALTH_PORT"

# 步骤 4: 验证可用性
adb forward tcp:$STEALTH_PORT tcp:$STEALTH_PORT
frida -H 127.0.0.1:$STEALTH_PORT -n Gadget -e "Process.id" 2>&1 | head -10
```

---

## 3. 壳防御评估

在选定脱壳方案前，需要评估目标壳的反调试/反 Frida 能力。
每个 `packer-*.md` 中都包含该壳的防御能力评估表。

### 评估维度

| 维度 | 说明 | 影响方案选择 |
|------|------|------------|
| **frida-server 进程检测** | 扫描 `/proc/*/cmdline` 或 `ps` 匹配 frida 关键字 | 有 → 标准 Frida 不可用 |
| **默认端口检测** | `connect()` 探测 27042 | 有 → 标准 Frida 不可用 |
| **frida-agent SO 特征检测** | 扫描 `/proc/self/maps` 匹配 frida 相关 SO | 有 → 隐蔽注入也可能被检测 |
| **ptrace 反调试** | `ptrace(PTRACE_TRACEME)` 自锁 | 有 → 需提前注入 |
| **签名校验阻断** | JNI_OnLoad 中校验 APK 签名，失败则不解密 DEX | 有 → 无法重打包；需内存 dump |
| **DEX 加载路径隐蔽** | DEX 不走标准 ClassLoader，直接灌入 JIT rwxp 内存 | 有 → frida-dexdump 无效，必须 dd 直读 |
| **检测后的行为** | 崩溃 / 拒绝解密 / 静默降级 | 决定 dump 时机 |

### 防御等级分类

| 等级 | 特征 | 可用方案 |
|------|------|----------|
| `NONE` | 无 Frida 检测 | 所有方案可用 |
| `LOW` | 仅检测 frida-server 进程/端口 | 隐蔽注入可用 |
| `MEDIUM` | 检测 frida SO 特征 + 进程 | 隐蔽注入可用（需 SO 重命名） |
| `HIGH` | 强签名校验 + 反调试 + DEX 路径隐蔽 | 仅 dd 直读 / FART |

---

## 4. 策略路由

根据 **壳类型 × 环境能力 × 壳防御等级**，选择最优脱壳方案。

### 路由矩阵

```
                    │  DEFENSE_NONE/LOW  │  DEFENSE_MEDIUM     │  DEFENSE_HIGH
                    │  (壳无/弱反Frida)  │  (壳有Frida检测)     │  (强反Frida+隐蔽DEX)
────────────────────┼────────────────────┼─────────────────────┼──────────────────────
HAS_FRIDA_SERVER    │  frida-dexdump     │  ❌ 会被检测         │  ❌ 会被检测
(标准 Frida)        │  直接 dump         │                     │
────────────────────┼────────────────────┼─────────────────────┼──────────────────────
HAS_STEALTH_INJECT  │  frida-dexdump     │  frida-dexdump      │  ⚠️ 可注入但
(隐蔽注入)          │  直接 dump         │  ✅ 可绕过检测       │  DEX 不走 ClassLoader
                    │                    │                     │  dd 直读仍是最优
────────────────────┼────────────────────┼─────────────────────┼──────────────────────
HAS_ROOT only       │  dd / frida-dexdump│  dd 直读            │  dd 直读
(无 Frida)          │                    │                     │
────────────────────┼────────────────────┼─────────────────────┼──────────────────────
NO_ROOT             │  BlackDex          │  BlackDex (碰运气)  │  ❌ 基本无解
                    │  Gadget 重打包注入  │  Gadget 重打包注入  │
```

### 通用方案优先级（按壳防御等级分路）

#### 壳防御等级 = NONE / LOW（无 Frida 检测或仅弱检测）

1. **frida-dexdump**（标准或隐蔽注入均可）
2. **BlackDex**（零配置，碰运气）
3. **Root + dd 直读**（最可靠，需 Root）
4. **FART / 定制 ROM**（最后手段）

#### 壳防御等级 = MEDIUM（有 Frida 检测，DEX 走标准 ClassLoader）

1. **隐蔽注入 + frida-dexdump**（绕过 Frida 检测，走标准 ClassLoader dump）
2. **Root + dd 直读**（不依赖 Frida，不受检测影响）
3. **BlackDex**（碰运气）
4. **FART / 定制 ROM**（最后手段）

#### 壳防御等级 = HIGH（强反 Frida + DEX 路径隐蔽）

1. **Root + dd 直读 /proc/PID/mem**（唯一可靠方法）
2. **FART / 定制 ROM**（最后手段）

### 壳特定路由

每个 `packer-*.md` 文件定义了：
1. 该壳的防御等级和具体检测手段
2. 该壳的方案优先级矩阵
3. 每个方案的详细步骤

路由时先读取对应的 `packer-*.md`，按其方案优先级与环境能力取交集，选最高优先级可用方案。

---

## 5. 执行脱壳

选定方案后，参考对应 `packer-*.md` 中的详细步骤执行。

### 通用步骤框架

1. 准备环境（安装工具、配置注入框架）
2. 安装目标 APK（如需）
3. 执行脱壳操作
4. 拉取产物到本地
5. 验证 DEX 有效性
6. jadx 反编译

### 方案 A: 标准 Frida dump

适用条件：`HAS_FRIDA_SERVER` 且壳防御 ≤ LOW

```bash
# 启动 App
adb shell am start -n <pkg>/<activity>
sleep 3

# dump
frida-dexdump -U -n <app_name> -o ./output/dex/

# 或手动 attach
frida -U <pkg> -l dump_script.js
```

### 方案 B: 隐蔽注入 dump

适用条件：`HAS_STEALTH_INJECT` 且壳防御 ≤ MEDIUM 且 DEX 走标准 ClassLoader

```bash
# 1. 发现隐蔽注入端口
STEALTH_PORT=$(adb shell "su -c 'find /data/adb/modules/ -name \"*.config.so\" -exec cat {} \;'" \
  2>/dev/null | grep -oP '"port":\s*\K\d+' | head -1)

# 2. 配置目标 App（通过注入框架的管理配置，具体方式因框架而异）
#    通用原则：设置目标包名，启用注入，设置适当延迟（建议 500-1000ms）

# 3. 端口转发
adb forward tcp:$STEALTH_PORT tcp:$STEALTH_PORT

# 4. 强停 → 启动目标 App（注入框架会暂停 App 等待连接）
adb shell am force-stop <pkg>
sleep 1
adb shell am start -n <pkg>/<activity>
sleep 4  # 等待注入完成

# 5. 验证连接
frida -H 127.0.0.1:$STEALTH_PORT -n Gadget -e "console.log('connected, pid=' + Process.id)"

# 6. dump
mkdir -p ./output/dex/
frida-dexdump -H 127.0.0.1:$STEALTH_PORT -n Gadget -o ./output/dex/

# ⚠️ 注意：输出目录必须预先创建 (mkdir -p)，否则 frida-dexdump 会 FileNotFoundError
# ⚠️ 注意：配置文件通过 adb push 推送，不要在 shell 中 echo（引号转义会丢）
```

### 方案 C: Root 内存直读

适用条件：`HAS_ROOT`，所有防御等级均可用

```bash
# 启动 App
adb shell am start -n <pkg>/<activity>
sleep 3

# 获取 PID
PID=$(adb shell pidof <pkg>)

# 扫描内存区域（根据壳类型选择扫描目标）
# 方式 1: 扫描 rwxp 匿名区域（适用于 360 等 JIT 加载类壳）
adb shell "cat /proc/$PID/maps" | grep "rwxp" | grep "00000000"
# 方式 2: 扫描 r-xp 区域（适用于标准 ClassLoader 加载类壳）
adb shell "cat /proc/$PID/maps" | grep "r-xp" | grep "dex"

# Dump 目标区域
START=0x<start_addr>
END=0x<end_addr>
SIZE=$((END - START))
adb shell "dd if=/proc/$PID/mem bs=4096 skip=$((START/4096)) count=$((SIZE/4096)) 2>/dev/null | gzip" > /tmp/mem_dump.gz
gunzip -f /tmp/mem_dump.gz

# 从 dump 中提取 DEX（使用 Python 脚本）
python3 extract_dex.py /tmp/mem_dump ./output/dex/
```

### 方案 D: BlackDex

适用条件：任何环境，但成功率因壳而异

```bash
# 安装 BlackDex（如未安装）
adb install BlackDex64.apk

# 打开 BlackDex → 点击目标 App → 等待脱壳
# 拉取产物
adb pull /sdcard/Android/data/top.niunaijun.blackbox/BlackDex/ ./output/blackdex/
```

---

## 6. 产物验证

### DEX 有效性检查

```bash
# Magic bytes (offset 0x00): 64 65 78 0a  ("dex\n")
# Endian tag (offset 0x28): 12 34 56 78
# File size  (offset 0x20): 应与实际文件大小一致

xxd -l 0x30 <file.dex>

# 快速批量验证
for f in ./output/dex/*.dex; do
  python3 -c "
import struct, sys
with open(sys.argv[1], 'rb') as f:
    magic = f.read(8)
    f.seek(0x20)
    size = struct.unpack('<I', f.read(4))[0]
    f.seek(0x28)
    endian = f.read(4)
    ok = magic[:4] == b'dex\n' and endian == b'\x12\x34\x56\x78'
    f.seek(0, 2)
    real_size = f.tell()
    print(f'{sys.argv[1]}: valid={ok} header_size={size} real_size={real_size} match={size==real_size}')
" "$f"
done
```

### 壳 stub 判定

壳 stub DEX 通常只有少量类（< 20），主要是加载器类。
真实业务 DEX 通常包含数百到数千个类。用 jadx 加载后检查 class 数量。

### 完整性验证清单

```
□ DEX magic bytes: 64 65 78 0a ("dex\n") at offset 0x00
□ Endian tag: 12 34 56 78 at offset 0x28
□ Header size 字段与实际文件大小一致
□ 非 shell stub: class 数量 > 100
□ jadx 反编译无大量错误
□ 包含目标包名的业务类 (grep 目标包名)
□ 产物总大小合理（通常 > 10MB，壳 stub 通常 < 1MB）
```

---

## 7. 反编译输出

```bash
# jadx 反编译
jadx --no-res -d ./output/src/ ./output/dex/*.dex

# 或交互式查看
jadx-gui ./output/dex/*.dex
```

---

## 支持的加固方案

| 加固方案 | 防御等级 | 详情文件 | 状态 |
|----------|----------|----------|------|
| 360加固保 VIP (libjgcrqc) | HIGH | [packer-360jiagu.md](packer-360jiagu.md) | 已验证 |
| 360加固保 (libjgcch) | HIGH+ | [packer-360jiagu.md](packer-360jiagu.md) | 待突破 |
| 爱加密 V3+ | MEDIUM | [packer-ijiami.md](packer-ijiami.md) | 已验证 |
| 梆梆加固 | 待评估 | packer-bangcle.md | 待添加 |
| 腾讯乐固 | 待评估 | packer-legu.md | 待添加 |
| 网易易盾 | 待评估 | packer-yidun.md | 待添加 |
| 新壳类型 | — | [packer-template.md](packer-template.md) | 复制模板 |

---

## 工具和环境

详见 [tools-reference.md](tools-reference.md)。

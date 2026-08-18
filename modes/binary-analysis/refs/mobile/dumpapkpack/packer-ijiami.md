# 爱加密 (ijiami) V3+ 脱壳方案

## 壳特征指纹

### V3+ 版（已验证可脱）

| 特征 | 值 |
|------|-----|
| 加密 DEX 载荷 | `assets/ijiami.dat`（通常 10-30 MB，加密后的真实 DEX） |
| Native 解密引擎 | `assets/ijm_lib/{armeabi,arm64-v8a}/libexec.so` + `libexecmain.so` |
| 完整性校验 | `assets/signed.bin`（签名校验，16 bytes） |
| 反调试标志 | `assets/af.bin`（反调试标记，16 bytes） |
| Java 层入口类 | `com.ijm.dataencryption.DETool` |
| 壳 stub 入口 | `s.h.e.l.l.A`（AppComponentFactory 子类） |
| 原始 Application | 通常为 `com.<pkg>.xxxApplication`（记录在 `s.h.e.l.l.A.orignAppName` 中） |
| 壳 stub DEX | `classes.dex` 体积极小（通常 < 400 KB） |
| DEX magic | 壳 stub 为标准 `dex\n035`；加密载荷 `ijiami.dat` 为非标准格式 |
| 壳 SO 行为 | `attachBaseContext()` 阶段加载 `libexec.so`，解密 `ijiami.dat` 后通过标准 ClassLoader 加载 DEX |
| DEX 加载方式 | **走标准 DexFile.openDexFile / ClassLoader 路径** |
| **脱壳难度** | **低-中** — 隐蔽注入 + frida-dexdump 即可 |

### 旧版（libijiami）

| 特征 | 值 |
|------|-----|
| SO 文件名 | `assets/libijiami*.so` |
| 脱壳难度 | 低 — 标准 Frida dump 通常即可 |

### 识别命令

```bash
# 1. 加密载荷
find /tmp/apk_check/assets/ -name "ijiami.dat"

# 2. 解密引擎
find /tmp/apk_check/assets/ -path "*/ijm_lib/*" -name "libexec*.so"

# 3. 辅助文件
ls -la /tmp/apk_check/assets/signed.bin /tmp/apk_check/assets/af.bin 2>/dev/null

# 4. 壳入口类
strings /tmp/apk_check/classes.dex | grep -iE "ijiami|ijm|dataencryption|s\.h\.e\.l\.l"

# 5. classes.dex 体积（< 400KB = 壳 stub）
ls -lh /tmp/apk_check/classes.dex

# 6. 完整特征匹配（一条命令）
find /tmp/apk_check/assets/ \( -name "ijiami.dat" -o -path "*/ijm_lib/*" \) \
  && echo "[!] ijiami V3+ detected" \
  || echo "[-] not ijiami V3+"
```

### 确认判定（需命中 ≥ 3 项）

1. ✅ `assets/ijiami.dat` 存在
2. ✅ `assets/ijm_lib/{arch}/libexec.so` 存在
3. ✅ `assets/ijm_lib/{arch}/libexecmain.so` 存在
4. ✅ `com.ijm.dataencryption.DETool` 在 classes.dex 中
5. ✅ `classes.dex` 体积 < 400 KB
6. ✅ `assets/signed.bin` 和 `assets/af.bin` 存在

---

## 反 Frida / 反调试能力评估

| 检测项 | 是否有 | 检测手段 | 影响 |
|--------|--------|----------|------|
| frida-server 进程扫描 | ✅ | 扫描进程列表匹配 frida 关键字 | 标准 Frida 会被检测 |
| 默认端口 27042 检测 | ✅ | 端口探测 | 标准 Frida 会被检测 |
| frida-agent SO 特征检测 | ⚠️ 部分 | 扫描 `/proc/self/maps` | 隐蔽注入中 SO 重命名后可绕过 |
| ptrace 反调试 | ✅ | 反调试保护 | 需在 App 启动前注入 |
| 签名校验阻断加载 | ❌ | 无 APK 签名校验阻断 | 不影响脱壳 |
| DEX 加载路径隐蔽 | ❌ | **走标准 ClassLoader** | ✅ frida-dexdump 有效 |

### 防御等级: **MEDIUM**

- 标准 Frida（frida-server）: ❌ 会被检测
- 隐蔽注入（Zygisk 层注入）: ✅ 可绕过
- DEX 加载走标准路径: ✅ frida-dexdump 可 dump

### 检测后的行为

- 检测到 Frida 时通常**静默降级或崩溃**，不会拒绝解密 DEX
- 但如果 App 闪退，需要在壳解密完成后、App 检测之前完成 dump

---

## 方案优先级矩阵

| 优先级 | 方案 | 环境要求 | 成功率 | 耗时 |
|--------|------|----------|--------|------|
| **1** | 隐蔽注入 + frida-dexdump | Root + 隐蔽注入框架 | 95% | 10-15 min |
| 2 | Root + dd 直读 + DEX 提取 | Root | 85% | 20-30 min |
| 3 | 标准 Frida + frida-dexdump | Root + frida-server（无 Frida 检测的旧版） | 60% | 10 min |
| 4 | BlackDex | 无 Root | 30% | 5 min |

**有隐蔽注入框架时优先方案 1。无隐蔽注入但有 Root 时走方案 2。**

---

## 方案 1: 隐蔽注入 + frida-dexdump（已验证成功 ✅）

### 原理

爱加密 V3+ 的壳在 `attachBaseContext()` 阶段通过 native 引擎解密 `ijiami.dat`，
解密后的 DEX 通过**标准 ClassLoader** 加载到内存。
隐蔽注入框架在 Zygisk 层注入 Frida Gadget，App 启动时 Gadget 自动加载并暂停 App 等待连接，
绕过爱加密的 Frida 进程/端口检测。
连接后使用 `frida-dexdump` 扫描进程内存中的 `dex\n` magic header，直接 dump 已解密的 DEX。

### 环境要求

- Root 设备（已 Root 真机或模拟器）
- 隐蔽注入框架（Zygisk 模块形式的 Frida Gadget 注入器）
- adb 可用
- 本地有 Python 3、frida、frida-dexdump、jadx

### 步骤

#### 1. 发现隐蔽注入端口

```bash
# 扫描所有注入模块的配置文件，提取监听端口
STEALTH_PORT=$(adb shell "su -c 'find /data/adb/modules/ -name \"*.config.so\" -exec cat {} \;'" \
  2>/dev/null | grep -oP '"port":\s*\K\d+' | head -1)
echo "Stealth inject port: $STEALTH_PORT"

# 如果找不到配置，尝试常见端口: 14725, 27043, 8888 等
```

#### 2. 配置目标 App 注入

```bash
# 通过注入框架的管理接口设置目标包名
# 通用方法：找到注入框架的目标配置文件，添加目标包名并启用注入
# 配置必须通过本地文件 adb push 推送（不要在 shell 中 echo，引号转义会丢）

# 示例（通用流程，具体配置格式因框架而异）:
# 1. 读取当前配置
adb shell "su -c 'cat <config_path>'" > /tmp/inject_config.json
# 2. 本地修改：添加目标包名，设置 inject: true，delay: 800
# 3. 推送回去
adb push /tmp/inject_config.json /data/local/tmp/inject_config.json
adb shell "su -c 'cp /data/local/tmp/inject_config.json <config_path>'"
adb shell "su -c 'chown <owner>:<group> <config_path>'"
adb shell "su -c 'chmod 600 <config_path>'"
```

#### 3. 端口转发

```bash
adb forward tcp:$STEALTH_PORT tcp:$STEALTH_PORT
```

#### 4. 启动 App（注入框架会暂停 App 等待连接）

```bash
# 查找正确的启动 Activity
adb shell cmd package resolve-activity --brief -c android.intent.category.LAUNCHER <pkg>

# 强停后启动
adb shell am force-stop <pkg>
sleep 1
adb shell am start -n <pkg>/<activity>
sleep 4  # 等待 Gadget 注入完成

# 此时 App 被 Gadget 暂停，等待 Frida 连接
```

#### 5. 验证连接

```bash
frida -H 127.0.0.1:$STEALTH_PORT -n Gadget \
  -e "console.log('[+] Connected, PID=' + Process.id); Java.available && console.log('[+] Java VM available')"
# 预期输出:
# [+] Connected, PID=XXXX
# [+] Java VM available
```

#### 6. Dump DEX

```bash
# ⚠️ 输出目录必须预先创建！
mkdir -p ./output/dex/

frida-dexdump -H 127.0.0.1:$STEALTH_PORT -n Gadget -o ./output/dex/
# 预期输出:
# INFO:frida-dexdump:[*] Successful found XX dex, used X time.
# INFO:frida-dexdump:[*] All done...
```

#### 7. 验证产物

```bash
echo "Total DEX: $(ls ./output/dex/*.dex | wc -l)"
echo "Total size: $(du -sh ./output/dex/)"

# 验证 DEX magic
xxd ./output/dex/classes.dex | head -2
# 预期: 6465 780a 3033 3500 ("dex\n035")

# 批量验证
for f in ./output/dex/*.dex; do
  python3 -c "
import struct, sys
with open(sys.argv[1], 'rb') as f:
    magic = f.read(4)
    f.seek(0x20)
    size = struct.unpack('<I', f.read(4))[0]
    f.seek(0x28)
    endian = f.read(4)
    ok = magic == b'dex\n' and endian == b'\x12\x34\x56\x78'
    f.seek(0, 2)
    print(f'{sys.argv[1]}: valid={ok} size={size}')
" "$f"
done
```

#### 8. 反编译

```bash
jadx --no-res -d ./output/src/ ./output/dex/
```

### 已知限制

- **frida-dexdump 输出目录必须预先 `mkdir -p`**，否则全部 FileNotFoundError
- **配置文件不能通过 shell echo 写入**，引号转义会丢失，必须 `adb push` 本地文件
- **隐蔽注入有延迟**，设置 `delay: 800` 左右确保壳 SO 加载后再注入
- **部分小体积 DEX**（< 1KB）可能是壳残留或系统 stub，通过 class 数量过滤
- **竞态条件**：如果 App 的 Frida 检测比 Gadget 注入更早触发，可能需要调大 delay

### 实战数据 (com.lphtsccft / 涨乐财富通)

| 产物 | 值 |
|------|-----|
| APK 大小 | 161 MB |
| Dump DEX 数量 | 82 个 |
| Dump 总大小 | 122 MB |
| 最大单 DEX | 12 MB (核心业务) |
| jadx 反编译 | 7,240 个 Java 文件 / 73 MB |
| 反编译错误 | 35 个 |
| 壳 stub DEX | 359 KB (仅含 `s.h.e.l.l.*` 类) |
| 业务模块 | 234 个 ARouter 路由（交易、行情、开户等） |

---

## 方案 2: Root + dd 直读（备选）

### 原理

爱加密解密后的 DEX 在进程内存中可以通过标准方式读取。
使用 `dd` 直接读取 `/proc/PID/mem` 中的 DEX 区域。

### 步骤

```bash
# 启动 App，等待壳完成解密
adb shell am start -n <pkg>/<activity>
sleep 5

# 获取 PID
PID=$(adb shell pidof <pkg>)

# 扫描 DEX 所在内存区域
adb shell "cat /proc/$PID/maps" | grep -E "dex|classes" | head -20

# Dump 包含 DEX 的内存区域
# (具体地址需根据 maps 输出确定)
START=0x<addr>
END=0x<addr>
SIZE=$((END - START))
adb shell "dd if=/proc/$PID/mem bs=4096 skip=$((START/4096)) count=$((SIZE/4096)) 2>/dev/null | gzip" > /tmp/mem_dump.gz
gunzip -f /tmp/mem_dump.gz

# 从 dump 中提取 DEX
python3 extract_dex.py /tmp/mem_dump ./output/dex/
```

### 已知限制

- 需要手动分析 `/proc/PID/maps` 确定目标区域
- 竞态条件：dump 时进程可能正在修改内存
- 不如方案 1 精确（方案 1 直接搜 DEX magic）

---

## 方案 3: BlackDex（快速尝试）

1. 安装 BlackDex
2. 打开 BlackDex → 点击目标 App → 脱壳
3. 拉取: `adb pull /sdcard/Android/data/top.niunaijun.blackbox/BlackDex/ ./output/blackdex/`

### 已知限制

- 爱加密 V3+ 版本 BlackDex 成功率约 30%
- 如果成功，产物直接可用

---

## DEX 验证清单

```
□ DEX magic bytes: 64 65 78 0a ("dex\n") at offset 0x00
□ Endian tag: 12 34 56 78 at offset 0x28
□ Header size 字段与实际文件大小一致
□ 非 shell stub: class 数量 > 100
□ jadx 反编译无大量错误
□ 包含目标包名的业务类 (grep "com.lphtsccft" 等)
□ 产物总大小 > 10MB（壳 stub 通常 < 1MB）
□ DEX 数量 > 10（大型 App 通常有数十个 DEX）
```

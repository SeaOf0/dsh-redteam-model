# 360加固保 VIP 脱壳方案

## 壳特征指纹

### 变体 A: libjgcrqc (VIP 版，已验证可脱)

| 特征 | 值 |
|------|-----|
| SO 文件名 | `assets/libjgcrqc_64.so` (arm64) 或 `assets/libjgcrqc.so` (arm) |
| 加密 DEX magic | `qh\x00\x01` (非标准 `dex\n`) |
| Application 类 | `com.stub.StubApp` 或反包名路径 (如 `coonc.nixiq.tifhcir.moc`) |
| smali 特征 | `StubApp.smali`, `QHClassLoader` 相关类 |
| 壳 SO 行为 | `attachBaseContext()` 中加载 SO，SO 校验签名后解密 DEX |
| DEX 加载方式 | 通过 native ART API 加载到 JIT `rwxp` 匿名内存区域 |
| 运行时签名校验 | 有，但仅在 JNI_OnLoad 入口检查，JIT 内存中 DEX 可直接 dump |
| **脱壳难度** | **低** — Root + dd dump rwxp 内存即可 |

### 变体 B: libjgcch (签名校验强化版，待突破)

| 特征 | 值 |
|------|-----|
| SO 文件名 | `assets/libjgcch_64.so` / `assets/libjgcch_a64.so` |
| 加密载荷 | `assets/libjgcch_enc.so` (可达 28MB+) |
| SO 大小 | ~1MB (stripped, 0 exports) |
| SO 关键字符串 | `getPackageInfo`, `signatures`, `jSHAL`, `JIAGU_HASH_FILE_NAME`, `libijmDataEncryption` |
| 运行时路径 | `/data/data/<pkg>/.jiagu/libjgcch_64.so` |
| JNI_OnLoad | 存在但不在动态符号表中 (0 exports)，dlsym 仍可找到 |
| 运行时签名校验 | **强化** — JNI_OnLoad 中通过 JNI 回调 getPackageInfo 获取签名，计算 SHA-1 与内嵌哈希比对，失败返回 JNI_ERR，**不解密 DEX** |
| DEX 加载方式 | 签名校验通过后才解密，失败则 app 存活但无业务 DEX |
| **脱壳难度** | **高** — 必须绕过签名校验才能触发 DEX 解密 |
| **已知限制** | 无原始签名密钥时，JIT 内存直读无效（DEX 未释放）；隐蔽注入受限（0 exports）；标准 Frida attach 同样受限 |

#### 已尝试但失败的方法
- Frida spawn + hook dlopen → 检测到 SO 加载但 0 exports，无法 replace JNI_OnLoad
- 隐蔽注入 + Java 层签名 hook → Java VM 尚未初始化时 SO 已加载
- JIT rwxp 内存 dump → SO 未解密 DEX，rwxp 区域无 DEX magic

### 识别命令

```bash
# SO 特征
find /tmp/apk_check/assets/ -name "libjgcrqc*"
find /tmp/apk_check/assets/ -name "libjgcch*"

# DEX 头部
xxd -l 8 /tmp/apk_check/classes.dex
# 360 VIP: 71 68 00 01 (qh\x00\x01)
# 普通版: 可能仍是 64 65 78 0a (dex\n) 但被加密

# Application 类
strings /tmp/apk_check/AndroidManifest.xml | grep -iE "stub|jiagu"
```

---

## 反 Frida / 反调试能力评估

### 变体 A: libjgcrqc

| 检测项 | 是否有 | 检测手段 | 影响 |
|--------|--------|----------|------|
| frida-server 进程扫描 | ✅ | 扫描进程列表 | 标准 Frida 会被检测 |
| 默认端口 27042 检测 | ✅ | 端口探测 | 标准 Frida 会被检测 |
| frida-agent SO 特征检测 | ❌ | 无 | 隐蔽注入可用 |
| ptrace 反调试 | ⚠️ | 有限 | 需提前注入 |
| 签名校验阻断加载 | ❌ | 仅入口检查 | 不影响 dump |
| DEX 加载路径隐蔽 | ✅ **关键** | native ART API → JIT rwxp | **frida-dexdump 无效** |

**防御等级: HIGH**（DEX 路径隐蔽是核心障碍，而非 Frida 检测）

### 变体 B: libjgcch

| 检测项 | 是否有 | 检测手段 | 影响 |
|--------|--------|----------|------|
| frida-server 进程扫描 | ✅ | 扫描进程列表 | 标准 Frida 会被检测 |
| frida-agent SO 特征检测 | ✅ | 扫描 maps | 隐蔽注入也可能被检测 |
| 签名校验阻断 | ✅ **关键** | JNI_OnLoad 中 SHA-1 校验 | **签名不匹配则不解密 DEX** |
| DEX 加载路径隐蔽 | ✅ | 同变体 A | frida-dexdump 无效 |

**防御等级: HIGH+**（签名校验阻断 + DEX 路径隐蔽双重障碍）

### 推荐脱壳环境

| 环境 | 变体 A (libjgcrqc) | 变体 B (libjgcch) |
|------|-------------------|-------------------|
| 标准 Frida (frida-server) | ❌ 会被检测 + DEX 不走 ClassLoader | ❌ 会被检测 + DEX 不走 ClassLoader |
| 隐蔽注入 | ⚠️ 可注入但 frida-dexdump 无效 | ❌ 0 exports + 签名校验阻断 |
| dd 直读 /proc/mem | ✅ **唯一可靠方法** | ⚠️ 签名不匹配则 DEX 不释放 |

---

## 方案优先级矩阵

| 优先级 | 方案 | 环境要求 | 成功率 | 耗时 |
|--------|------|----------|--------|------|
| **1** | Root + JIT 内存直读 | Root (模拟器/真机) | 95% (变体A) | 10-20 min |
| 2 | 隐蔽注入 + 内存直读 | Root + 隐蔽注入 | 60% | 20-30 min |
| 3 | BlackDex | 无 Root | 20% | 5 min |

**变体 A 优先方案 1。变体 B 目前无可靠方案，需要进一步研究。**

---

## 方案 1: Root + JIT 内存直读（已验证成功 ✅）

### 原理

360加固保 VIP 的壳 SO 在 `attachBaseContext()` 阶段通过 native ART API 解密 DEX，
解密后的 DEX 直接加载到 **JIT 代码区域**（`rwxp` 匿名内存页），
不走标准 `DexFile.openDexFile` → `ClassCastException` 路径。
因此 Frida 的 `OpenCommon`/`OpenMemory` hook 和 ClassLoader 枚举都无法发现这些 DEX。
**隐蔽注入也无法改变这一点** — 问题不在 Frida 检测，而在 DEX 加载路径。
唯一可靠的方法是直接 dump JIT 内存区域并从中提取 DEX。

### 环境要求

- Android 模拟器 (API 27, `google_apis` 镜像，**不要用 PlayStore 镜像**)
  - 推荐: Pixel 6 Pro, API 27, google_apis
- 或 Root 真机
- adb 可用
- 本地有 Python 3 和 jadx

### 步骤

#### 1. 启动模拟器并安装 APK

```bash
# 启动模拟器 (从 Android Studio 或命令行)
emulator -avd Pixel_6_Pro_API_27 -no-snapshot-load

# 等待启动完成
adb wait-for-device
adb root  # 模拟器可以直接 adb root

# 安装目标 APK
adb install <target.apk>
```

#### 2. 启动 App 并获取 PID

```bash
# 启动 App
adb shell am start -n <package>/.MainActivity

# 获取 PID
PID=$(adb shell pidof <package>)
echo "PID: $PID"
```

#### 3. 扫描 JIT 内存区域

360加固加载的 DEX 在 `rwxp` 匿名区域中。查找这类区域：

```bash
# 查看 /proc/PID/maps，找 rwxp 匿名区域
adb shell "cat /proc/$PID/maps" | grep "rwxp" | grep "00000000" | head -20

# 重点关注较大的 rwxp 区域（通常 > 1MB）
# 示例输出:
# 7a44846000-7a45c00000 rwxp 00000000 00:00 0     [anon:.bss]
```

#### 4. Dump JIT 内存区域

```bash
# 对每个可疑的 rwxp 大区域执行 dump
# 格式: dd if=/proc/PID/mem bs=4096 skip=START/4096 count=SIZE/4096

# 示例: dump 0x7a44846000-0x7a45c00000 (约 23MB)
START=0x7a44846000
END=0x7a45c00000
SIZE=$((END - START))

adb shell "dd if=/proc/$PID/mem bs=4096 skip=$((START/4096)) count=$((SIZE/4096)) 2>/dev/null | gzip" > /tmp/jit_dump.gz

# 解压
gunzip -f /tmp/jit_dump.gz
```

**注意**: dump 操作有竞态条件 — 进程内存可能在扫描和 dump 之间发生变化。
如果 dump 后搜索不到 DEX magic，需要重新扫描并立即 dump。

#### 5. 搜索并提取 DEX

用 Python 脚本从 dump 中搜索 DEX magic 并提取完整 DEX 文件：

```python
#!/usr/bin/env python3
"""extract_dex.py - 从内存 dump 中提取 DEX 文件"""
import struct, sys, os

def extract_dex(dump_path, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    with open(dump_path, 'rb') as f:
        data = f.read()

    count = 0
    offset = 0
    while offset < len(data) - 0x70:
        # DEX magic: 64 65 78 0a
        if data[offset:offset+4] == b'dex\n':
            # 读取 DEX header 中的文件大小
            dex_size = struct.unpack('<I', data[offset+0x20:offset+0x24])[0]
            endian_tag = struct.unpack('<I', data[offset+0x28:offset+0x2c])[0]

            # 验证
            if endian_tag == 0x12345678 and 4096 <= dex_size <= 50*1024*1024:
                # 确保有足够数据
                available = min(dex_size, len(data) - offset)
                dex_data = data[offset:offset+available]

                filename = f"dump_{count}_{dex_size}.dex"
                filepath = os.path.join(output_dir, filename)
                with open(filepath, 'wb') as out:
                    out.write(dex_data)

                print(f"[+] {filename}: {dex_size} bytes @ offset 0x{offset:x}")
                count += 1
                offset += dex_size  # 跳过已处理的 DEX
                continue
        offset += 1

    print(f"\nTotal DEX extracted: {count}")
    return count

if __name__ == '__main__':
    dump_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else './dex_output'
    extract_dex(dump_path, output_dir)
```

```bash
python3 extract_dex.py /tmp/jit_dump ./output/dex/
```

#### 6. 验证 DEX

```bash
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
    real = f.tell()
    print(f'{sys.argv[1]}: valid={ok} header_size={size} real_size={real} classes~{size//200}')
" "$f"
done
```

有效 DEX 判断:
- `valid=True` (magic + endian tag 正确)
- `header_size` 与 `real_size` 接近或一致
- `classes` 数量 > 100（壳 stub 通常 < 20 个类）

#### 7. 反编译

```bash
jadx --no-res -d ./output/src/ ./output/dex/*.dex

# 或交互式查看
jadx-gui ./output/dex/*.dex
```

### 已知限制

- **竞态条件**: `/proc/PID/mem` 内容是实时的，扫描和 dump 之间内存可能变化
- **Frida 兼容性**: API 27 模拟器上 frida-server 可能无法 attach（已知问题），所以用 dd 直读
- **DEX 不完整**: 如果 dump 时进程还在写入，可能截断。多次 dump 取并集
- **壳 stub 排除**: 同时会 dump 到壳自身的 stub DEX（通常很小，5-10 个类），通过大小过滤即可
- **隐蔽注入无法替代 dd**: 问题不在 Frida 检测，而在 DEX 不走 ClassLoader

### 实战数据 (party_cnooc-3.0.8.apk)

| 产物 | 大小 | 内容 |
|------|------|------|
| classes1.dex | 6,867,984 bytes | 业务代码 (com.richfit.*, 5946 classes) |
| classes2.dex | 7,448,076 bytes | 第三方库 (RxJava, 6105 classes) |
| classes3.dex | 6,363,120 bytes | AndroidX/Support (5461 classes) |
| 反编译输出 | 662 Java files | com/richfit/partycnooc/, com/richfit/qixin/ 等 |

---

## 方案 2: 隐蔽注入 + 内存直读（备选）

### 原理

使用隐蔽注入框架在 App 启动时注入，尝试通过 Frida 的 `Memory.scan` 直接扫描进程内存中的 DEX。
绕过了 frida-server 进程检测，但 DEX 仍在 JIT rwxp 区域中，需要自定义 dump 脚本。

### 已知限制

- **frida-dexdump 无效**：因为 DEX 不走 ClassLoader，frida-dexdump 的 ClassLoader 枚举找不到 DEX
- 需要手动编写 Frida 脚本扫描 rwxp 区域
- 变体 B 的 0 exports 限制了 hook 能力
- 成功率不如 dd 直读

---

## 方案 3: BlackDex（快速尝试）

### 步骤

1. 安装 BlackDex64
2. 安装目标 APK
3. 打开 BlackDex → 点击目标 App → 脱壳
4. 拉取: `adb pull /sdcard/Android/data/top.niunaijun.blackbox/BlackDex/ ./output/blackdex/`

### 已知限制

- 360加固保 VIP 版本通常**脱壳失败**（DEX 仍为加密状态）
- 普通版 360加固成功率较高
- 如果 BlackDex 成功，产物直接可用，无需其他方案

---

## DEX 验证清单

```
□ DEX magic bytes: 64 65 78 0a ("dex\n") at offset 0x00
□ Endian tag: 12 34 56 78 at offset 0x28
□ Header size 字段与实际文件大小一致
□ 非 shell stub: class 数量 > 100
□ jadx 反编译无大量错误
□ 包含目标包名的业务类
```

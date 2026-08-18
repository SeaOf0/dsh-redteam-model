# Smali Patching Playbook

目标：在需要验证假设时，支持最小 smali patch、重打包、重签名和安装验证。

## 适用场景

- 快速验证布尔分支
- 绕过本地校验
- 验证登录或购买路径
- 还原被简单混淆的控制流

## 必须记录

- `patchCandidateId`
- patch 点
- patch 原因与根因证据引用
- 预期观察（patch 生效时应出现什么变化）
- rollback 方案
- rebuild 状态
- resign 状态（含签名方案选择）
- install verify 状态

## 候选隔离门禁

T3 patch 不是“试一刀看看”。每个候选先通过 `task-record-attempt --kind=patch --proposal` 写入结构化状态；实际应用业务 patch 时去掉 `--proposal`，此时 no-op 基线门禁生效。候选至少包含：

- `--candidate=PATCH-xxx`
- `--strategy=<单一策略名>`
- `--hypothesis=<为什么这个点是最小根因>`
- `--expected=<验证时应观察到的具体变化>`
- `--evidence=<fixtures/log/smali 地址等 task-local 证据>`
- `--rollback=<如何回退到上一个候选或 base apk>`

同一个 candidate 只验证一个假设。若同一症状连续两个 patch candidate 失败且没有新增根因证据，进入 evidence-only 模式：只允许静态定位、hook 取证、日志归因、验证环境修复，不允许继续业务 patch。

**no-op 签名基线**：任何需要重签安装的任务，首个业务 patch 前先构建一个 no-op re-sign baseline（不改业务逻辑，只重打包/重签/安装/启动）。通过后用 `task-baseline` 记录原始/重签 APK 哈希、签名验证、安装、冷启动和证据。构建成功本身不算基线；基线失败时先解决打包、签名、安装或环境问题。

## 完整 Rebuild SOP

### 步骤 1：反编译

```bash
apktool d target.apk -o target_dir -f
# -f 强制覆盖已存在的输出目录
# 若需要保留原始文件时间戳加 -c
```

### 步骤 2：定位 patch 目标

```bash
# 方法 A：jadx 定位 → baksmali patch
# 先用 jadx 打开 APK，找到目标类和方法，记录类名
# 然后在 apktool 输出目录中找到对应 smali 文件

# 方法 B：直接搜索 smali
grep -r "isVip\|isRooted\|checkLicense" target_dir/smali*/ -l
```

### 步骤 3：执行 patch

按下方"常见 patch 模式"修改 smali 文件。每次 patch 只改一个最小原因点。

### 步骤 4：重打包

```bash
apktool b target_dir -o patched.apk
```

**常见 rebuild 失败排查**：

| 错误信息 | 原因 | 修复 |
|----------|------|------|
| `brut.androlib.AndrolibException: brut.common.BrutException: could not exec` | aapt 未找到 | 安装 Android SDK build-tools 或设置 `APPT` 环境变量 |
| `error: invalid resource directory name` | 资源文件名含非法字符 | 检查 `res/` 下是否有非标准子目录 |
| `rebuild 闪退但无错误输出` | nine-patch 图片损坏 | `find res/ -name '*.9.png'` 检查是否被意外修改 |
| `duplicate resources` | 库资源冲突 | 检查 `apktool.yml` 中的 `doNotCompress` 配置 |

### 步骤 5：对齐

```bash
zipalign -f 4 patched.apk patched-aligned.apk
# zipalign 必须在签名之前执行
# -f 强制覆盖已存在的输出
```

### 步骤 6：签名

```bash
# 生成自签名 key（首次）
keytool -genkey -v -keystore debug.keystore -alias debug -keyalg RSA -keysize 2048 -validity 10000

# 签名
apksigner sign --ks debug.keystore --ks-key-alias debug --out final.apk patched-aligned.apk

# 验证签名
apksigner verify -v final.apk
```

### 步骤 7：安装验证

```bash
# 同签名时先尝试覆盖安装
adb install -r final.apk

# 自签名与已安装版本签名不同时，卸载会清除应用数据。
# 先备份需要保留的数据并取得用户明确同意，再执行：
adb uninstall com.target.package
adb install final.apk

# 验证：检查是否正常启动、patch 点是否生效
adb shell am start -n com.target.package/.MainActivity
adb logcat -s "AndroidRuntime" "System.err" | head -50
```

## 签名方案约束

Android 使用 V1/V2/V3/V3.1 签名方案，选择不当会导致安装失败：

- V1（JAR signing）：基于 ZIP 条目摘要，兼容性最好但保护最弱
- V2（Android 7+）：基于 APK 整体摘要，保护完整 APK；`targetSdk >= 30` 时用 `jarsigner` 只签 V1 可能安装失败
- V3（Android 9+）：支持密钥轮转，有 proof-of-rotation 限制
- V3.1（Android 15+）：扩展密钥轮转链
- 用 `apktool` 重打包后，再用 `apksigner` 签名（`apktool` 不负责签名）
- `apksigner` 默认根据 `minSdkVersion` 选择所有可用方案，通常不需要手动指定
- 验证：`apksigner verify -v <apk>` 确认实际使用的签名方案

## 常见 patch 模式

### Pattern 1：布尔翻转

将 `false` 改为 `true`（或反过来），适用于 `isVip()`、`isDebug()` 等分支：

```smali
# --- before ---
const/4 v0, 0x0          # false
if-eqz v0, :cond_bypass

# --- after ---
const/4 v0, 0x1          # true
if-eqz v0, :cond_bypass
```

核心：`const/4 v0, 0x0` → `const/4 v0, 0x1`，只改一个立即数。

### Pattern 2：条件分支翻转

将 `if-eqz` 改为 `if-nez`（或反过来），直接翻转跳转方向：

```smali
# --- before ---
if-eqz v0, :cond_is_rooted

# --- after ---
if-nez v0, :cond_is_rooted
```

核心：`eqz` ↔ `nez`，`eq` ↔ `ne`，`lt` ↔ `ge`，`gt` ↔ `le`。跳转目标不变，只换比较方向。

### Pattern 3：方法返回值覆写

替换整个方法体，让方法直接返回固定值：

```smali
# --- before（原方法体可能很长）---
.method public isLicenseValid()Z
    .registers 2
    # ... 大量逻辑 ...
    return v0
.end method

# --- after ---
.method public isLicenseValid()Z
    .registers 1
    const/4 v0, 0x1
    return v0
.end method
```

核心：保留 `.method` 和 `.end method`，方法体只留 `const/4` + `return`。注意 `.registers` 要 >= 实际使用的寄存器数。

### Pattern 4：Source smali 控制流跳过

当检测逻辑不是简单布尔分支，而是连续多条检测语句时，在 source smali 中用标签和 `goto` 跳过：

```smali
# --- before ---
invoke-virtual {p0}, Lcom/target/RootChecker;->checkSu()Z
move-result v0
if-nez v0, :cond_safe
invoke-virtual {p0}, Lcom/target/RootChecker;->exitApp()V

# --- after（用 goto 替代整个检测块）---
goto :cond_safe
# 原检测代码保留但不会执行
```

核心：source smali 会重新汇编，不需要按原始指令字节长度填充 NOP。只有直接修改已编译 DEX 的原位二进制 patch，才需要处理 code unit 长度、分支偏移和填充；不要把两种方法混用。

### Pattern 5：try-catch 移除（反反调试）

部分应用通过 try-catch 包裹检测逻辑，捕获修改后抛出的异常来触发额外检测：

```smali
# --- before ---
:try_start
invoke-virtual {p0}, Lcom/target/SecurityChecker;->verify()V
:try_end
.catch Ljava/lang/Exception; {:try_start .. :try_end} :catch_0

# --- after（移除 catch handler）---
invoke-virtual {p0}, Lcom/target/SecurityChecker;->verify()V
# 删除 .catch 指令，让异常正常传播
```

## Multidex 定位策略

当目标方法数超过 65536 时，APK 使用 multidex。patch 前必须确认目标类在哪个 dex 中：

```bash
# 方法 A：查看 apktool 输出目录结构
ls target_dir/smali*/com/target/ClassName.smali
# smali/ = classes.dex, smali_classes2/ = classes2.dex, 以此类推

# 方法 B：baksmali 直接反编译特定 dex
unzip -o target.apk classes*.dex
baksmali d classes2.dex -o smali_out/

# patch 后用 smali 回编译
smali a smali_out/ -o classes2.dex

# 手动替换 dex 进 APK（需要重新对齐和签名）
cp classes2.dex target_dir/
cd target_dir && zip -0 ../patched.apk classes2.dex
```

**注意**：重新写入 DEX 时 ZIP 工具会为新内容计算 CRC32；`-0` 表示 store/不压缩，不表示保留旧 CRC。替换后用 `unzip -t`、`zipinfo` 和 `apksigner verify` 检查条目、对齐和签名。

## Patch 后完整性校验应对

A3+ 级应用常在运行时校验自身完整性（CRC/MD5/SHA），检测 smali patch 后的 DEX 修改。应对策略：

### 检测机制识别

```bash
# 在 jadx 中搜索以下模式定位完整性校验
# 1. 读取自身 APK/DEX 文件并计算哈希
grep -r "getMessageDigest\|CRC32\|DigestUtils" target_dir/smali*/ -l
# 2. 比较 APK 签名与运行时签名
grep -r "PackageManager\|GET_SIGNATURES\|signatures" target_dir/smali*/ -l
# 3. 检查 classes.dex 文件大小
grep -r "classes.dex\|getFileLength\|length()" target_dir/smali*/ -l
```

### 应对方案

| 校验类型 | 应对 | 说明 |
|----------|------|------|
| DEX CRC32/MD5 | patch 校验函数返回 true | 定位校验方法，用 Pattern 3 覆写返回值 |
| APK 签名比对 | patch SignatureVerifier | 运行时签名必然与原始签名不同，覆写比对方法 |
| DEX 文件大小 | 重新建立重打包基线或处理校验逻辑 | source smali 回编译可能改变指令布局、索引和 DEX 大小，不能假设等长 |
| zip entry 校验 | patch 校验逻辑 | 校验特定 ZIP entry 的 CRC/内容 |

**关键**：完整性校验和业务逻辑 patch 可能在不同 dex 中。先定位校验逻辑，再决定 patch 顺序。

## 签名流程注意

- **zipalign 必须在 apksigner 之前执行**：顺序是 `apktool build` → `zipalign` → `apksigner sign`。如果 zipalign 在签名之后运行，V2/V3 签名会失效
- **V2/V3 签名在 apktool rebuild 后需要重新签名**：apktool 解包再重打包会破坏 V2/V3 签名块（META-INF 之外的部分），所以必须用 `apksigner` 重新签名，不能只依赖 V1
- **multidex patching 目标选择**：`classes.dex` 是主 dex，`classes2.dex`、`classes3.dex` 等是补充。用 `baksmali` 反编译特定 dex 时要指定正确文件（`baksmali d classes2.dex -o smali_classes2`），patch 前先用 `dexdump` 或 jadx 确认目标类在哪个 dex 中

## 最小交付

- `run/smali-patch-notes.md`
- 报告中的 patch 与安装验证结果

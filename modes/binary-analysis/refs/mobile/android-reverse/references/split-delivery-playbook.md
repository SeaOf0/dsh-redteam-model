# Split Delivery Playbook

目标：处理 `AAB / APKS / XAPK / split APK / dynamic feature / asset pack` 场景下的重组、安装和逻辑定位。

## 高风险信号

- `base.apk` 很小但资源多
- `split_config.*.apk`
- `config.arm64_v8a`
- `feature_*.apk`
- `BundleConfig.pb`
- `asset pack`
- `split_compat`
- `SplitInstallManager`
- `PlayCoreLibrary`

## 必须回答

- 基础包、配置分包、动态特性模块分别有哪些
- 目标逻辑位于 `base`、feature module、asset pack 还是下载后落地文件
- ABI / density / language split 是否影响复现与安装
- 安装路径应走 `bundletool`、`pm install-multiple` 还是拆包后重新组合

## 格式识别

| 文件/目录 | 格式 | 处理方式 |
|---|---|---|
| `*.aab` | Android App Bundle | `bundletool` 处理 |
| `*.apks` | bundletool 输出的 split 集合 | `bundletool install-apks` 或解压 |
| `*.xapk` | APKPure 等第三方分发格式 | 解压后 `pm install-multiple` |
| `base.apk` + `split_config.*.apk` | 已拆分的 split APK 集 | `pm install-multiple` |
| `*.apk` 单文件 | 普通 APK 或已合并 | 正常分析 |

## 关键命令

### bundletool：AAB → split APK

```bash
# 从 AAB 生成 APKS（需要签名）
bundletool build-apks --bundle=app.aab --output=app.apks --ks=debug.keystore --ks-pass=pass:android

# 从 AAB 生成单个 APK（合并所有 split，便于静态分析）
bundletool build-apks --bundle=app.aab --output=app.apks --mode=universal --ks=debug.keystore --ks-pass=pass:android

# 解压 APKS 查看 split 列表
bundletool extract-apks --apks=app.apks --output-dir=splits/
# 或直接解压（APKS 本质是 zip）
unzip app.apks -d splits/

# 查看设备规格（用于生成定向 APKS）
bundletool get-device-spec --output=device-spec.json

# 按设备规格生成匹配的 APKS
bundletool build-apks --bundle=app.aab --output=app.apks --device-spec=device-spec.json

# 安装 APKS 到设备
bundletool install-apks --apks=app.apks
```

### pm install-multiple：安装 split APK

```bash
# 安装一组 split APK（必须包含 base.apk）
adb install-multiple base.apk split_config.arm64_v8a.apk split_config.hdpi.apk split_config.zh.apk
```

高级场景需要 session API（分步 push + write + commit），此处不展开。

### aapt2 / apksigner

```bash
aapt2 dump badging base.apk                    # 包名、split 名称、权限等
aapt2 dump permissions base.apk                 # 权限列表
aapt2 dump resources base.apk                   # 资源 ID 表

apksigner sign --ks debug.keystore --ks-pass pass:android --out signed.apk modified.apk
apksigner verify --verbose base.apk
```

## 分析顺序

1. **枚举**：解压 APKS/XAPK，列出所有 split、feature、asset pack 和元数据（`toc.pb` / `BundleConfig.pb` / `manifest.json`）
2. **分类**：区分 config split（ABI/density/language）、feature module（`<dist:module>`）、asset pack（`assets/<pack-name>/`）
3. **定位目标**：根据包名和功能描述，判断目标逻辑在哪个模块
4. **选择安装策略**：`bundletool install-apks`、`pm install-multiple` 或 `--mode=universal` 合并
5. **进入分析**：对目标模块做静态/动态分析

## 目标逻辑定位

### 判断目标在哪个 split

- **搜索类名/方法名**：用 jadx 打开 `base.apk`，如果目标类不存在或只有 stub，检查 feature module 的 APK
- **搜索资源 ID**：通过 `aapt2 dump resources` 找资源所在 split
- **检查 AndroidManifest.xml**：`<dist:module>` 标签中的 `dist:title` 和 `dist:instant` 属性标识动态特性模块
- **查看 `toc.pb`**：bundletool 生成的 APKS 内含 `toc.pb`，记录每个 split 的类型和 targeting

### XAPK 处理

XAPK 本质是 zip，含 `manifest.json` + 多个 APK。`unzip` 解压后读 `manifest.json` 查看 split 列表，再用 `adb install-multiple *.apk` 安装。

### 动态特性模块（Dynamic Feature Module）

- 通过 Google Play Core Library 的 `SplitInstallManager` 按需下载
- 代码中的信号：`SplitInstallManager.startInstall()`、`SplitInstallStateUpdatedListener`
- 静态分析时需要单独用 jadx 打开 feature APK
- 运行时可通过 `adb shell pm path <package>` 确认已安装的 split 路径
- 动态特性模块可能在首次使用时才下载，需模拟触发下载或手动安装

### Asset Pack

- `deliveryType`：`install-time`（随 base 安装）、`fast-follow`（安装后立即下载）、`on-demand`（使用时下载）
- `install-time` 的 asset pack 在 base APK 的 `assets/` 下可找到
- `fast-follow` 和 `on-demand` 需要通过 Play Core API 触发下载
- 逆向时检查 `AssetPackManager` / `AssetPackStates` 相关调用

## 常见偏差

- 只分析 `base.apk` 忽略 feature split，遗漏目标逻辑
- 用 jadx 打开单个 split 而非 base，导致类引用缺失——应优先用 `--mode=universal` 合并
- XAPK 直接当 APK 分析——需先解压再处理
- 忘记安装对应 ABI 的 config split 导致 `pm install` 失败
- 动态特性模块未安装就做运行时分析，找不到类

## 最小交付

- `run/split-delivery-notes.md`
- 报告中的模块清单、安装策略和逻辑归属
- 如有动态特性模块，记录触发条件和下载方式

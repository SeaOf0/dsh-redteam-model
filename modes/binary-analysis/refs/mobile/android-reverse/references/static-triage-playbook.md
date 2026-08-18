# Static Triage Playbook

目标：用最少时间确认 APK 的主入口、攻击面、保护面和 Native 参与度。

## 必查清单

- `AndroidManifest.xml`
- `classes*.dex`
- `lib/<abi>/*.so`
- `assets/`
- `res/xml/`
- `strings.xml`

## 关键观察点

- 权限与导出组件
- `Application` 和 launcher `Activity`
- `Service` / `Receiver` / `Provider`
- `usesCleartextTraffic`
- `networkSecurityConfig`
- `System.loadLibrary`
- `DexClassLoader` / `PathClassLoader`
- `TrustManager` / `CertificatePinner`
- `RootBeer` / `su` / `frida`
- `targetSdkVersion` / `minSdkVersion`（影响 ART 行为、签名方案、权限模型）

## 框架与架构信号

- `FlutterActivity` / `FlutterFragmentActivity` / `libapp.so` → Flutter 容器，Java 层很薄
- `ReactActivity` / `libhermes.so` / `index.android.bundle` → React Native 容器
- `UnityPlayerActivity` / `libil2cpp.so` → Unity IL2CPP 容器
- `@Composable` / `Composer` → Jetpack Compose UI，不走传统 View 体系
- `@Inject` / `@Module` / `DaggerXxxComponent` / `Hilt_` → DI 框架，实例化被间接层隐藏
- `Continuation` / `invokeSuspend` / `BuildersKt` → Kotlin 协程，调用链为状态机

## Split / 动态交付检测

未检查 split 就在 `base.apk` 中下"目标不存在"结论，是高频分析错误（见 `a6-a7-failure-pattern-cookbook.md` FP-06）。

- 输入文件扩展名是否为 `.apks` / `.aab` / `.xapk` → 直接走 `split-delivery-playbook.md`
- `base.apk` 中是否缺少目标逻辑 → 检查是否有 `split_config.*.apk`（ABI/density/language split）或动态特性模块
- `AndroidManifest` 中 `android:isFeatureSplit="true"` 或 `<dist:module dist:instant="true">` → split 拆分确认
- `assets/` 中 `.obb` / `.pak` / 大型资源包 → 可能是 asset pack 或运行时下载
- split 重组前不得因 `base.apk` 缺逻辑就下"目标不存在"结论

## 防护等级初判

分诊阶段应根据以下信号给出初始 A 级判定，后续可修正：

- `A0`：无 ProGuard/R8，类名方法名可读，无 native SO
- `A1`：a.b.c 短类名 + R8 full mode 信号（`getClass` / lambda group / merged adapter）
- `A2`：字符串加密（运行时解密函数）、反射调用隐藏、简单 JNI native
- `A2+`：Allatori / DexGuard 控制流平坦化 + 不透明谓词，建议按 A3 流程起步
- `A3`：Root / Frida / Pinning / Integrity 单层保护信号（见关键观察点）
- `A4`：DexClassLoader / 壳特征 SO（见 `dex-loader-playbook.md` 壳识别表）/ `jni` 目录存在且含核心逻辑
- `A5`：多 SO + 多 Dex + Java-Native 强耦合
- `A6`：壳 + 动态加载 + 多层保护组合
- `A7`：复杂混合保护，需要静态与运行时联动拆解

## 分诊后路由

分诊完成后，根据结果路由到对应工作流：

- 反编译引擎选择 → `references/engine-selection.md`
- 框架容器确认 → `references/framework-runtime-playbook.md`
- 壳/加固确认 → `references/dex-loader-playbook.md`
- 保护绕过需求 → 按防护等级读对应 bypass playbook
- 无特殊信号 → 走标准 Java API / 调用链分析流程


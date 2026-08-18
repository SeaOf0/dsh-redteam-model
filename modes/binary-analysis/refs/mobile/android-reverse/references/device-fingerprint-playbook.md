# Device Fingerprint Playbook

目标：还原设备指纹采集维度、风控参数生成逻辑和绕过策略，而不是只罗列 SDK 名。

## 先回答

- 指纹采集 SDK 是什么（RiskEngine / Warlock / Overt / MSA / 自研）
- 采集了哪些维度（设备信息、传感器、网络、行为、环境）
- 风控参数在哪个环节生成（Java / JNI / Native / 组合）
- 是否存在多源交叉验证机制
- Play Integrity / Key Attestation 是否被使用

## 高风险信号

- `RiskEngine` / `Warlock` / `Overt` / `MSA` SDK
- `getDeviceId` / `getAndroidId` / `getImei` / `getSerial`
- `Build.*`（型号、厂商、系统版本等）
- `SensorManager` / `Accelerometer` / `Gyroscope`
- `WifiInfo` / `BSSID` / `SSID` / `MAC`
- `Settings.Secure.ANDROID_ID`
- `SafetyNet` / `Play Integrity` / `KeyAttestation`
- `/proc/cpuinfo` / `/sys/devices/soc0/`（Native 读取）
- 风控参数字段名如 `x-device-id` / `device_fp` / `risk_info`

## 操作顺序

### 1. 定位指纹 SDK 和采集入口

1. 从 Manifest 和依赖中识别指纹 SDK
2. 搜索 SDK 初始化入口（`init` / `setup` / `start`）
3. 追踪 SDK 调用链到具体采集方法
4. 确认数据是在 Java 层采集还是通过 JNI 委托给 Native

### 2. 分析采集维度

#### 设备基础信息
- `Build.MODEL` / `Build.MANUFACTURER` / `Build.BRAND`
- `Build.DISPLAY` / `Build.FINGERPRINT`
- `Settings.Secure.ANDROID_ID`
- `TelephonyManager.getDeviceId()` / `getSubscriberId()`
- `Build.SERIAL`

#### 网络信息
- `WifiInfo.getMacAddress()` / `getBSSID()` / `getSSID()`
- `NetworkInterface.getHardwareAddress()`
- IP 地址（本地 + 外网）
- VPN 检测

#### 传感器数据
- `SensorManager` 注册的传感器列表
- 加速度计 / 陀螺仪 / 指纹传感器
- 传感器数据作为活体检测或模拟器判断依据

#### 存储与安装信息
- 已安装应用列表
- 存储空间信息
- 应用签名信息

#### 环境检测
- Root 检测
- 模拟器检测
- Hook 框架检测
- 多开/分身检测
- VPN / 代理检测

### 3. 多源交叉验证分析

许多高级风控 SDK 使用多源读取同一信息的策略：
- Android ID：4 种读取路径
  1. `Settings.Secure.getString(resolver, "android_id")`
  2. `ContentResolver.query(Uri.parse("content://settings/secure"))`
  3. Native 层直接读取 `/data/system/users/0/settings_ssaid.xml`
  4. 反射调用 `SystemProperties.get("persist.device_config.ssaid.*)")`
- 如果 4 条路径返回不一致，判定为篡改

分析要点：
- 确认 SDK 读取同一信息的所有路径
- 如果修改了某个值，需要同步修改所有读取路径
- 最可靠的方式是在 Native 层 hook 最底层的读取系统调用

### 4. 风控参数生成逻辑还原

完整链路：
1. **入口定位**：找到风控参数在 HTTP 请求中的字段名
2. **Java 层追踪**：从网络请求拦截器回溯到参数生成方法
3. **JNI 入口**：确认是否通过 JNI 调用 Native 生成
4. **Native 逻辑**：在 SO 中分析生成算法
5. **参数拼接**：确认所有维度的数据如何组合和签名

### 5. Play Integrity / Key Attestation 分析

#### Play Integrity API

5 个判定字段：
- `deviceRecognitionVerdict`：设备完整性
- `appRecognitionVerdict`：应用完整性
- `requestHash`：请求绑定
- `accountRecognitionVerdict`：账户完整性（可选）
- `environmentDetails`：环境信息

分析步骤：
1. 找到 `IntegrityManager.requestIntegrityToken()` 调用
2. 确认 nonce 生成逻辑
3. 追踪 token 验证流程（本地验证 / 服务端验证）
4. 确认 verdict 字段的使用方式

#### Key Attestation

分析要点：
- 硬件根信任链验证
- 证书链中的 attestation 扩展字段
- `attestationChallenge` 绑定
- 安全硬件级别（StrongBox / TEE / None）

### 6. 绕过策略（按场景）

#### 属性伪造
- Hook `Build.*` 字段返回指定值
- Hook `Settings.Secure` 修改 Android ID
- Hook `TelephonyManager` 修改设备标识
- 注意多源交叉验证问题

#### 虚拟设备
- 使用 VirtualXposed / VMOS 等虚拟环境
- 注意虚拟环境本身可能被检测

#### 自定义 ROM
- 修改系统属性（需要 Root + 刷机）
- 最彻底但成本最高

#### Native 层统一拦截
- Hook `/proc` 文件读取返回指定内容
- Hook `__system_property_get` 统一修改系统属性
- 这是最可靠的方式，可以同时覆盖 Java 和 Native 的读取

### 7. KernelSU 时间侧信道检测

- KernelSU 通过时间差异检测某些操作
- 需要在 hook 中保持时间一致性
- 使用 Frida 的 `Interceptor.replace` 替代 `Interceptor.attach` 可以减少时间差异

## 高级检测模型：RiskEngine 实例

某些 SDK（如 RiskEngine）采用多层检测框架，按层级评分：

| 层级 | 检测内容 | 典型检测项 |
|------|---------|-----------|
| L1 进程环境 | 进程注入痕迹 | `/proc/self/maps` 中可疑 SO、线程名匹配 |
| L2 网络协议 | D-Bus 端口探测 | 向可疑端口发送 NUL+AUTH 探测 Frida 握手 |
| L3 进程-端口绑定 | 端口归属验证 | 验证监听端口属于哪个进程 |
| L4 内存模式 | ARM64 trampoline 检测 | 函数入口 `LDR X16/X17, [PC,#8]; BR X16/X17` 签名 |
| L5 ArtMethod 完整性 | 方法入口自检 | 运行时比对 `data_` 字段是否被替换 |
| L6 信号/异常探测 | SIGTRAP 检测 | Frida trampoline 触发调试异常，检测自定义 handler |

每层独立评分，汇总为风险等级。绕过需要逐层排查（详见 `references/anti-frida-playbook.md` 7 层检测矩阵）。

## SDK 指纹 JSON 结构分析

某些 SDK 将采集数据打包为 JSON/Protobuf blob，字段使用混淆 key 名：

**分析步骤**：
1. 在 SDK 初始化函数中找到 JSON 构建/序列化入口
2. Hook `JSONObject.put` / `JSONArray.put` 记录所有写入的 key-value 对
3. 对混淆 key 名（如 `a1b2`、`x_param`），通过写入时机和值类型反推含义
4. 常见模式：~50+ key 的 JSON 中，device info 占 15+、environment check 占 10+、sensor data 占 5+、network info 占 8+

**字段反推技巧**：
- `String` 值包含 MAC 地址格式 → 网络相关字段
- `int` 值为 0/1 → 环境检测布尔值（root/hook/emulator）
- `float[]` 值 → 传感器数据
- `long` 值接近时间戳 → 时间相关字段

## 常见偏差

- 只 Hook Java 层的 API——高级 SDK 同时从 Native 层读取，Java hook 不够
- 修改单一维度而忽略交叉验证——需要所有读取路径返回一致
- 忽略环境检测维度——指纹 SDK 通常同时做 Root/模拟器/Hook 检测
- 不验证 Play Integrity 判定结果——需要确认服务端如何使用 verdict
- 把风控参数当成简单设备 ID——实际可能是多维度数据的签名摘要
- 忽略时间维度——某些 SDK 使用采集时间差作为活体/行为检测

## 最小交付

- `run/device-fingerprint-notes.md`
- 指纹采集维度清单
- 风控参数生成逻辑描述
- Play Integrity / Key Attestation 使用情况（如适用）
- 绕过方案和验证结果

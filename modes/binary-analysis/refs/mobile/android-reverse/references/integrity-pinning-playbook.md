# Integrity And Pinning Playbook

这是 `protection-bypass` 路线中处理 `integrity / pinning` 的主手册。
`root` 与 `frida` 子面仍分别参考：

- `references/anti-root-playbook.md`
- `references/anti-frida-playbook.md`

## 先做子面裁定

进入 `protection-bypass` 后，不要只写“在做 bypass”。
必须先把四个子面显式裁定为 `命中 / 阻塞 / not-applicable`：

- `root`
- `frida`
- `integrity`
- `pinning`

`integrity` 与 `pinning` 至少要回答：

- 是本地校验、远端校验，还是两者组合
- 触发时机在启动期、登录后、敏感功能点击后还是发包前
- 返回值需要伪造真值、缓存值、空值还是旁路整个调用链

## 常见命中点

### Integrity

- Play Integrity API
- SafetyNet
- `Signature.verify`
- `PackageManager.getPackageInfo`
- `getSigningInfo`
- 包签名、自校验、DEX / SO hash 校验
- 设备状态、安装来源、调试状态、模拟器状态的组合判定

### Pinning

- `TrustManager`
- `HostnameVerifier`
- `CertificatePinner`
- `network_security_config`
- WebView 自定义证书校验
- Cronet / BoringSSL / Native pinning

## 作业顺序

1. 先定触发窗口
   记录是在 `Application / ContentProvider` 启动早期、首页初始化、登录态恢复、功能点击还是网络请求前触发。
2. 先分本地失败还是远端拒绝
   如果本地已经崩溃、toast、闪退或功能按钮灰化，优先看本地校验。
   如果本地通过但服务端返回 `device risk / integrity failed / cert rejected`，优先看令牌或网络栈。
3. 先找聚合判定点
   不要一上来散点 hook。
   优先找“最终布尔结论”“错误码分发”“是否继续发包”的汇合点。
4. 再拆到子校验
   只有聚合点信息不足时，才继续下钻到签名比对、证书链校验、令牌组装或 Native verify callback。

## Integrity 专项 SOP

### 1. 识别校验类型

- 本地签名 / 包信息校验
- 本地设备状态校验
- 调 Google / 厂商服务拿 attestation token
- 本地取 token，服务端判 token

### 2. 先抓边界，再决定伪造点

至少明确：

- token / verdict 在哪里生成
- verdict 在哪里第一次被消费
- 失败后阻断的是 UI、业务流程还是网络请求

### 3. 常用切入点

- Java 层：
  `PackageManager`、`SigningInfo`、`MessageDigest`、`Signature.verify`
- GMS / 三方 SDK 封装层：
  token provider、task callback、result parser
- Native 层：
  自校验 hash、签名摘要、环境特征聚合函数

### 4. 判定伪造策略

- `返回真值`：
  适合最终布尔或枚举结论点稳定的场景
- `返回缓存值`：
  适合 app 对字段结构和签名格式校验较严的场景
- `旁路上游调用链`：
  适合 token 请求容易触发二次风控或耗时明显的场景

### 5. 常见分歧

- 本地 hook 通过但服务端仍拒绝：
  检查是否还有第二条网络上报链或 Native token 组装链
- 替换布尔值后 app 继续崩：
  说明后续还校验对象字段、时间窗或 token 完整性
- 只在冷启动命中：
  需要更早注入，优先 `spawn` 或前置类加载点

## Native 自校验专项（self-.text / libc / libart / linker）

加固与反作弊 SO 普遍对**自身 `.text`、`libc.so`、`libart.so`**（有时含 `linker`/`linker64`、dex、APK 签名）做 CRC / hash / 逐字节比对。这是 inline hook、GOT patch、dump 修改后立刻崩溃的常见根因，也是 `so-runtime-evidence` 专题 §5 崩溃闭环步骤 5 的检查对象。

**为什么单独成节**：APK / 签名 / Play Integrity 校验在 Java 层或远端，可用返回真值/缓存值绕过；Native 自校验直接读 `/proc/self/maps` 定位自身或系统库的可执行段做字节级比对，hook 它的"返回值"常常不是单一布尔而是一个中央执法出口，需要不同的识别与处置思路。

### 识别特征

观察到以下任一即判定存在 Native 自校验：

- 读 `/proc/self/maps`、`/proc/%d/maps` 定位目标库的 `r-x` 段
- `openat` 目标 `.so` 文件 + `read` / `mmap`，再与内存内容逐字节比对（文件 vs 内存）
- 内存内容与保存的校验常量做 `memcmp` / CRC / adler / hash 循环（内存 vs 常量）
- 字符串里出现 `libc.so`、`libart.so`、自身 SO 名、`/proc/self/maps`、`/proc/%d/maps`、`linker`
- 校验失配后跳异常控制流：`__stack_chk_fail`、零值函数指针表间接调用、`MOV SP,#0; BR Xn` 清栈跳非法地址、`rt_tgsigqueueinfo` 自发 SIGSEGV

### 处置顺序

1. **干掉检测代码本身**（首选），不要去逐字节还原被校验内容。定位 CRC 校验函数与中央执法/kill 出口，让校验函数直接返回"未篡改"或让执法分支不执行。
2. **工具路线按任务类型选**（详见 `kernel-assisted-re-playbook.md` 的"用户态 vs 内核手段路线决策"）：
   - 共存型任务（让 App 带 hook 跑起来）：用 Frida 接管 CRC 校验函数或执法出口
   - 取证型任务（抓参数/还原算法）：有 anti-Frida 时优先内核 HWBP（不触用户态内存、不引发 CRC），HWBP 不支持再回 Frida 过检测
3. **不改被校验 `.text` 的替代手段**（当必须保留 `.text` 原样时）：
   - 内核硬件断点在校验函数入口 replace-ret，让函数体不执行
   - 改全局开关/状态变量（数据段，不在 CRC 覆盖范围）
   - 内核拦截 `kill`/`tgkill`/`exit_group` syscall（只截执法，不碰校验）
   - 双映射/影子页（`mremap`/`userfaultfd`），让校验读到原始字节而执行流走 patch 后的副本

### 环境陷阱

ART 被全局插桩的环境（如定制 ROM 对 `libart` 做 `RegisterNative` hook）下，对 `libart`/`libc` 的 CRC 会因系统侧改动而失配，导致**未注入任何工具也崩溃**。此时崩溃与 Frida/hook 无关，必须先干掉对应 CRC 检测函数，而不是归因于注入工具。

### 落盘

`run/integrity-bypass.js` 或 `run/so-runtime-evidence-notes.md` 必须写明：任务类型与所选工具路线、校验了哪几个目标（自身/libc/libart/linker/dex/签名）、CRC 函数偏移、校验方式（文件 vs 内存 / 内存 vs 常量）、失配自毁形式、采用的绕过手段。

## Pinning 专项 SOP

### 1. 先分层

必须明确 pinning 在：

- Java 层
- `JNI` 过渡层
- 纯 Native TLS 层

### 2. Java 层优先检查

- `CertificatePinner`
- `TrustManager` / `HostnameVerifier`
- 自定义证书摘要、公钥 hash、SPKI 比对
- WebView 客户端回调

### 3. Java 未命中时立即转 Native 栈

重点检查：

- Cronet builder 与 callback
- `SSL_CTX_set_custom_verify`
- `SSL_set_custom_verify`
- `X509_verify_cert`
- pinset 载入点、公钥摘要表、证书 DER 常量

### 4. 绕过策略选择

- Java hook：
  适合 OkHttp / Retrofit / 普通 WebView
- Native hook：
  适合 Cronet / BoringSSL / 自定义 TLS
- 静态 patch：
  适合回调稳定、运行时注入窗口极窄或多进程早期校验

## 常见错误

- 只看到 `TrustManager` 未命中，就下“没有 pinning”结论
- 只 patch 单个异常分支，就宣称完整绕过
- 不区分本地 verdict 与服务端 verdict
- 不记录失败样本，导致后续无法判断是否还有第二层校验

## 最小交付

- `run/integrity-bypass.js`
- `run/cert-pinning-bypass.js`
- 报告中的触发点、命中层、旁路方式、残留问题


# 脱壳工具决策矩阵与壳全景库

本文件是 SKILL 遇到 A4+ 壳时的脱壳策略唯一真源。所有涉及"脱壳"的决策必须先查本文件，
不得在缺少环境、进程存活、检测时序和 Anti-Frida 证据时默认跳到 Frida hook。

## 一、壳全景识别库

### 壳识别总表

通过静态特征（SO文件名 + Application类名 + assets文件）快速匹配壳类型：

| 壳 | 关键 SO | Application 类 | 难度 |
|---|---|---|---|
| **360加固保** | `libjiagu.so` `libjiagu_64.so` `libjiagu_art.so` `libjgdtc*.so` | `com.stub.StubApp` | 3/5(免费) 4/5(企业) |
| **腾讯乐固** | `libshella*.so` `libtup.so` `libshell.so` | `com.tencent.StubShell.TxAppEntry` | 3/5(旧版) 4/5(VMP) |
| **腾讯御安全** | `libtosprotection.*.so` `libshell-super.*.so` | `MyWrapperProxyApplication` | 4/5 |
| **腾讯手游加固** | `libtprt.so` | — | 3/5 |
| **梆梆(免费)** | `libsecexe.so` `libsecmain.so` `libSecShell*.so` | `com.secshell.secData.ApplicationWrapper` | 2/5 |
| **梆梆(企业)** | `libDexHelper.so` `libDexHelper-x86.so` | 同上 | 4/5 |
| **爱加密(标准)** | `libexec.so` `libexecmain.so` | `s.h.e.l.l.S` | 2/5 |
| **爱加密(v3)** | `libexecv3.so` | 同上 | 3/5 |
| **爱加密(企业/v5)** | `libijmDataEncryption.so` | 同上 | 4/5 |
| **娜迦(标准)** | `libchaosvmp.so` `lib*dog.so` | — | 3/5 |
| **娜迦(企业)** | `libedog.so` | — | 4/5 |
| **娜迦(2022+)** | `libxloader.so` | — | 3/5 |
| **百度加固** | `libbaiduprotect*.so` | — | 2/5 |
| **阿里/聚安全** | `libsgmain.so` `libmobisec.so` `libzuma.so` `libdemolish.so` | — | 2/5 |
| **网易易盾** | `libnesec.so` | — | 4/5 |
| **几维安全** | `libkwscmm.so` `libkdp.so` `libKwProtectSDK.so` | `com.Kiwisec.KiwiSecApplication` | 3/5 |
| **顶象科技** | `libx3g.so` | `cn.securitystack.stee.AppStub` | 4/5 |
| **深盾Virbox** | `libvirbox32.so` `libvirbox64.so` | — | 4/5 |
| **通付盾** | `libegis.so` `libNSaferOnly.so` | — | 2/5 |
| **中国移动/魔固云** | `libcmvmp.so` `libmogosecurity.so` | `com.mogosec.AppMgr` | 3/5 |
| **蛮犀安全** | `libdSafeShell.so` `libmxacc.so` | — | 3/5 |
| **珊瑚灵御** | `libreincp.so` `libreincp_x86.so` | `com.coral.util.StubApplication` | 2/5 |
| **海云安** | `libitsec.so` | `c.b.c.b` | 2/5 |
| **CFCA** | `libbasec.so` `libsecenh*.so` | — | 2/5 |
| **启明星辰** | `libvenSec.so` `libvenustech.so` | — | 2/5 |
| **网秦** | `libnqshield.so` | — | 2/5 |
| **OPPO加固** | `OPPOProtect*.so` | — | 3/5 |
| **Google Pairipcore** | `libpairipcore.so` | — | 3/5 |
| **AppGuard(韩国)** | `libloader.so` | — | 3/5 |
| **G-Presto** | `libATG_*.so` | — | 3/5 |
| **LIAPP(韩国)** | (无SO) `assets/LIAPP.ini` | — | 3/5 |
| **DexGuard** | (无独立SO，构建时保护) | — | 3/5 |
| **Promon SHIELD** | (私有SO) | — | 4/5 |
| **Arxan/Verimatrix** | (私有SO) | — | 4/5 |
| **Appdome** | (私有SO) | — | 3/5 |
| **盛大(旧)** | `libapssec.so` | — | 1/5 |
| **瑞星(旧)** | `librsprotect.so` | — | 1/5 |
| **APKProtect** | `libAPKProtect.so` | — | 1/5 |
| **apktoolplus** | `libapktoolplus_jiagu.so` | `com.linchaolong.apktoolplus.jiagu.ProxyApplication` | 1/5 |

#### ByteDance 系 dex2so / dragoncore（非传统壳，独立类别）

**重要**：这一类**不在上表的"壳"框架内**。它不是运行时脱壳场景，而是**编译期 Java→Native 转换**，但表现极其类似"方法体消失"。常见于 TikTok / 抖音 / 头条 / 番茄免费小说 / 红果免费短剧 等字节系全产品线。

| 标识 | 值 |
|---|---|
| 关键 SO | `libdragoncore.so`（也叫 dragoncore / Covode） |
| 加载入口 | `DragonStub.loadLibrary` / `DragonJ2C` 注解 |
| smali 表现 | 大量 Java 方法标记为 `native`，但 dex 内**无对应 JNI 实现** |
| JNI 注册 | `RegisterNatives` 在 `JNI_OnLoad` 内批量注册 |
| Frida 表现 | 多个不相关 Java 方法在 native 层**共享同一地址**（如 `0x722c512510`），Frida hook 报 "unable to intercept function" |

**识别信号**（任一即命中）：
1. smali 中 `public native boolean isVip()` 等业务方法标记为 `native`
2. 存在 `libdragoncore.so` 或 stack trace 出现 `DragonStub` / `NoSuchMethodError ... DragonStub.loadLibrary`
3. Frida hook 多个 Java 方法时返回相同地址
4. dump 出来的 dex 方法体只是 JNI bridge

**处理规则（硬约束）**：
- ✗ **严禁删除 smali 的 `native` 关键字**：`libdragoncore.so` 的 `RegisterNatives` 有完整性校验，删 `native` 触发 JNI pending exception → SIGABRT，Java try/catch **抓不到**
- ✓ **改 Java 实现层**：把目标方法重写为非 native 的 dummy 实现（如 `isAnyVip()Z → const/4 v0, 0x1; return v0`）
- ✓ **Frida hook 必须避开共享地址**：改 hook 调用方（Java 入口）而非 native 实现
- ✓ **配合 Native 分析**：`libdragoncore.so` 应通过 IDA-MCP 反编译 `JNI_OnLoad` / `RegisterNatives` 入口，得到 Java 方法 ↔ native 函数指针映射

**为什么单列**：实测中 agent 把它误判为 A1（"无壳"），跳过 IDA 分析，导致 18 处盲改 smali 失败；后续从 stack trace `DragonStub.loadLibrary` 才反向发现这一保护。把这层信息前置到识别表头，避免重蹈。

辅助识别工具：
- **APKiD**：开源壳识别工具，规则匹配
- **ApkCheckPack**：最全面的壳签名库（40+厂商，170+规则），`github.com/moyuwa/ApkCheckPack`

### 壳防护能力矩阵

| 壳 | DEX加密 | 方法抽取 | VMP | Anti-Frida | Anti-Debug | Anti-模拟器 | SO保护 |
|---|---|---|---|---|---|---|---|
| 360(企业) | Y | Y | Y | **L1-L6** | Y | Y | Y |
| 腾讯乐固(VMP) | Y | Y | Y | **L1-L5** | Y | Y | Y |
| 腾讯御安全 | Y | Y | Y | **L1-L6** | Y | Y | Y |
| 梆梆(企业) | Y | Y | Y | **L1-L5** | Y | Y | Y |
| 爱加密(企业) | Y | Y | Y | **L1-L6** | Y | Y | Y |
| 娜迦(企业) | Y | Y | Y | **L1-L5** | Y | Y | Y |
| 网易易盾 | Y | Y | Y | **L1-L6** | Y | Y | Y |
| 顶象科技 | Y | Y | Y | **L1-L5** | Y | Y | Y |
| 深盾Virbox | Y | Y | Y | **L1-L5** | Y | Y | Y |
| 几维安全 | Y | Y | Y(专业版) | **L1-L4** | Y | Y | Y |
| 中国移动 | Y | Y | Y | **L1-L4** | Y | Y | — |
| 360(免费) | Y | Y | N | L1-L3 | Y | Y | — |
| 梆梆(免费) | Y | Y | N | L1-L3 | Y | Y | — |
| 百度 | Y | Y | N | L1 | 基本 | 基本 | — |
| 阿里 | Y | Y | N | L1 | 基本 | 基本 | — |

> L1-L6 参考 anti-frida-playbook.md 的检测矩阵。表内厂商等级是选路先验，不替代当前 APK 的进程存活、检测时机和注入结果证据。观察到 L4+ 信号时，纯 Frida 不应作为默认脱壳路线。

## 二、脱壳工具库

### 工具按隐蔽性分级

> **执行须知**：下表中标记"模型可执行"的工具可以通过 adb/frida 等 MCP 工具直接操作。
> 标记"需用户安装"的工具是 APK 形式，模型只能生成命令，需要用户在设备上操作。
> 标记"需用户准备"的工具需要用户提前配置环境（刷机/安装框架）。

| 隐蔽性 | 工具 | 原理 | Root | Android | 适用于 | 执行方式 |
|---|---|---|---|---|---|---|
| **极高（内核级）** | **eBPFDexDumper-rs** | eBPF/uProbe 捕获 ART DEX；仍需按壳适配探针 | Y | 13-17 ARM64（项目声明） | 连续 DEX/CodeItem 可在 ART 边界观察的目标 | 需 eBPF 内核；默认 `--clean-oat` 有破坏性，uprobe 可能被检测 |
| **极高（内核级）** | **eBPFDexDumper** | eBPF/uProbe 捕获 ART DEX | Y | 官方只明确测试 Android 13 Pixel 6 ARM64 | 其他 ROM/Android 版本需调整偏移并重建 | 需 eBPF 内核；默认清理 oat，执行前优先 `--no-clean-oat` |
| **高（ART ROM）** | **FART** | 修改 ART 源码主动调用所有方法并 dump CodeItem | Y(刷机) | 6-12(官方) | 第1-3代壳 | 需用户准备（需刷 FART ROM） |
| **高（FART+无ROM）** | **FART+Frida(CYRUS-STUDIO)** | 通过 Frida 注入 FART 逻辑，配置文件驱动定向 dump | Y | 5-13 | 第1-3代壳 | 模型可执行（Frida MCP） |
| **高（ART ROM）** | **Youpk** | 类似 FART 但模块化，被壳厂商关注较少 | Y(刷机) | ≤10 | 第1-3代壳 | 需用户准备（需刷机） |
| **中（免Root）** | **BlackDex** | 独立虚拟化进程加载目标 APK，dump DEX | N | 5-12（项目声明） | 第1-3代壳的部分场景 | **需用户安装 APK；项目明确不处理目标的环境检测** |
| **中（免Root）** | **newBlackDex** | BlackDex 分支，增加 ArmPro 静态解密 | N | 5-13 | 第1-2代壳 | **需用户安装 APK** |

**BlackDex 交互模式**：BlackDex 无命令行触发接口。如果 BlackDex 已安装且是推荐工具：输出"请在 BlackDex 中选择 [目标应用名] → 点击脱壳"，然后执行 `adb shell ls /sdcard/BlackDex/` 或 BlackDex 提示的输出路径，等待用户操作后检查脱壳结果。
| **中（Root）** | **Udex2024** | Android 14 原生 DEX dump，独立应用 | Y | 14 | 第1-2代壳 | **需用户安装 APK** |
| **中（Xposed）** | **FunDex2** | LSPosed 模块 hook loadDex | Y(LSPosed) | 5-13 | 第1-2代壳 | 需用户准备（需 LSPosed） |
| **低（Frida依赖）** | **FRIDA-DEXDump** | Frida 内存扫描 DEX magic | Y | 取决于 Frida/ROM/ABI | 进程稳定且无高层 Anti-Frida 证据的目标 | 可执行，但先做一次环境与存活诊断 |
| **静态** | **Smali Patch** | 反编译→修改壳代码→注入 dump 逻辑→重打包 | N | 取决于 apktool、签名和目标 ABI | 可定位且可重打包的检测/加载路径 | 必须先过 no-op 重签基线，不保证覆盖所有壳 |
| **静态** | **BadUnboxing** | 自动分析 APK 生成定制脱壳器 | N | N/A | Java 层壳 | 模型可执行（桌面工具） |
| **静态** | **vdexExtractor** | 从设备拉取 .vdex 文件静态提取 DEX | Y | 8+ | AOT 编译的 DEX | 模型可执行（adb pull + 工具） |
| **运行时内存直读** | **dd + grep** | Root 权限读取 `/proc/pid/mem`，不注入 SO | Y | 取决于 SELinux/ptrace_scope/进程权限 | 进程存活且可读内存映射的目标 | 先验证权限和映射，不能从 Android 版本推断可用 |

**来源核验（lastVerified: 2026-07-10）**：

- eBPFDexDumper-rs: `https://github.com/chinleez/eBPFDexDumper-rs`（Android 13-17 ARM64/root/eBPF；默认 `--clean-oat`；uprobe 可能留下可检测痕迹）
- eBPFDexDumper: `https://github.com/LLeavesG/eBPFDexDumper`（官方明确测试 Android 13 Pixel 6 ARM64/root；其他版本可能需调整）
- BlackDex: `https://github.com/CodingGay/BlackDex`（项目声明 Android 5-12；明确不处理目标的环境检测）
- Frida Android: `https://frida.re/docs/android/`（支持真机和模拟器路径；x86 测试较少，不等于不可用）

执行前重新核对官方 README/release。版本支持、破坏性默认和可检测性比“推荐排名”优先级更高。

### 特殊方案：爱加密 v4 离线解密

爱加密 v4 的加密管道为 `ijiami.dat → deflate → 外层 XOR → 缓存文件 → S-box → XOR → 索引表 → 9 个 DEX`。

关键特征：
- `assets/ijiami.dat`（高熵载荷）+ `assets/ijiami.ajm`（magic: `indl01`）
- `libexec.so` 含 `SecLLVM compiler` 字符串
- 外层 XOR 密钥由包名 MD5 推导，S-box key 只有 256 种
- 可利用 DEX 格式不变量恢复 XOR 密钥（详见 `technique-extract-2026-05.md` 第 3 节）
- DEX checksum 修复：SHA-1 必须在 Adler32 之前计算

### 特殊方案：梆梆企业版 libDexHelper 静态解密

`libDexHelper.so` / `libDexHelper-x86.so` 命中时，不把单一工具或固定偏移作为默认路线。先读取 `references/bangcle-libdexhelper-playbook.md`，按外层 ELF 动态段、`.init_array`、重定位、解密调用链、内层 ELF 验证和 DEX 回流推进。

关键约束：
- `0x8000` payload、`0x19` XOR key、`0x104E3D` key material 等只可作为单样本观测值，必须记录来源和推导。
- AArch64 relocation 中 `0x401=R_AARCH64_GLOB_DAT`、`0x403=R_AARCH64_RELATIVE`，不要反写。
- ELF64 头字段按 64 位宽度读取，不能沿用 ELF32 偏移。
- Frida/frida-dexdump/Florida 版本不固定；以当前设备、ABI、进程存活和 Anti-Frida 证据决定是否可做诊断性尝试。

### 工具活跃度

| 工具 | 最后更新 | 状态 |
|---|---|---|
| eBPFDexDumper-rs | 2026-05 官方 release | Android 13-17 ARM64/root/eBPF；默认 clean-oat，uprobe 可能可检测 |
| eBPFDexDumper | 2025-12 仓库信息 | 官方测试 Android 13 Pixel 6 ARM64；其他版本需适配 |
| FART+Frida(CYRUS-STUDIO) | 2025 活跃 | 活跃，推荐替代刷机 |
| FRIDA-DEXDump | 按当前仓库/安装环境核验 | Frida 依赖工具；记录实际版本、ROM、ABI、spawn/attach 时机和进程存活 |
| Udex2024 | 2024 | 活跃（Android 14） |
| FunDex2 | 2024 | 活跃（LSPosed） |
| newBlackDex | 2024.8 | 低活跃 |
| BlackDex | 2022-01 最新 release | 可作旧系统候选；不处理环境检测，不能仅按版本宣称可用 |
| FDex2 | 已废弃 | 使用 FunDex2 替代 |

## 三、脱壳决策流程

> **前置条件**：执行决策树前必须先完成环境探测（见下方门禁 0），确认 eBPF/FART/LSPosed 可用性。

### 检测时序判定（脱壳工具选型前必执行）

壳的检测/退出逻辑在哪一层执行？这直接决定哪种工具能成功。
**注意**：是否采用 Frida 由当前样本的 Anti-Frida 证据、注入时机、ROM/ABI 和进程存活共同决定。A4 只是保护复杂度，不是“Frida 必然失败”的证据。

| 检测时序 | 判定信号 | 可用工具 |
|---------|---------|---------|
| init_array | SO 导入 exit/_exit/kill 但无 Java 层 exit 调用；logcat 中 System.exit 出现在 Application 创建前 | BlackDex / Smali Patch SO（A1-A3 壳可尝试 Gadget 注入） |
| JNI_OnLoad | SO 有 JNI_OnLoad + exit 字符串；Java 层 attachBaseContext 后进程死亡 | BlackDex / Smali Patch（A1-A3 壳可尝试 Gadget 注入） |
| Java 层 | smali 中可见 System.exit / Process.kill；启动后几秒死 | BlackDex / Smali Patch（A1-A3 壳可尝试 Frida spawn） |

**判定方法**：
1. IDA 分析 SO → 检查 init_array 函数是否包含 exit/kill 相关导入
2. logcat 检查 → System.exit 出现在哪个时机
3. **允许一次诊断性运行时尝试**（仅检查进程存活时间、崩溃时机和工具能力）。A4+ 也不因等级自动失败，但一旦观察到高层 Anti-Frida、早期自毁或同策略连续失败，立即转向

如果确认退出逻辑位于早于常规注入的 `init_array`，跳过普通 spawn/attach 脱壳；只有具备更早注入方式且能解释时序时才重新评估。

识别壳类型后，按以下决策树选择脱壳策略：

```
是否已确认动态 DEX/壳，且需要运行时获取真实 DEX？
│
├── 是 → 运行环境？
│   │
│   ├── 真机(Root+Magisk)
│   │   ├── **先确认 App 进程存活**（A4+ 壳可能检测 Root/Magisk 杀进程）
│   │   ├── 有兼容 eBPF 内核/ARM64/ART 布局 → eBPFDexDumper-rs（候选，先禁用破坏性 clean-oat）
│   │   ├── 有 FART ROM → FART（第3代抽取壳）
│   │   ├── 有 LSPosed → FART+Frida(CYRUS-STUDIO)（无需刷机）
│   │   └── 都没有 → BlackDex → FunDex2 → Smali Patch → 建议刷 FART ROM
│   │
│   ├── 真机(无Root)
│   │   ├── BlackDex / newBlackDex（首选）
│   │   └── Smali Patch
│   │
│   └── 模拟器
│       ├── 先检查 App 进程是否存活（`adb shell ps | grep <包名>`）
│       │   ├── 进程存活且稳定 → Root 直读 /proc/pid/mem dump（无需注入）
│       │   └── 进程不存在或秒退 → 壳已检测到模拟器杀进程，**不可直接 dump**
│       │       ├── Smali Patch 去模拟器检测 + 重打包（必做前置）
│       │       ├── 去检测后 BlackDex 脱壳
│       │       └── 去 detection 后 mem dump
│       └── 以上都失败 → 建议用户切换到真机（真机可使用 eBPF/FART 等内核级工具）
│
│   > 模拟器先核对 ABI、ROM 和进程存活。Frida 官方支持模拟器路径，但 x86 测试较少；目标存在反模拟器/Anti-Frida 证据时再降级。
│   > 直接 mem dump 的前提是进程存活且 `/proc/pid/mem` 可读；不满足时先处理检测或换环境。
│   > BlackDex 标记为"需用户安装 APK"，无法通过 adb 自动触发脱壳——失败时应请用户手动操作或直接进入 Smali Patch，不得跳到 Frida。
│
└── 否(A1-A3) → Frida 可行
    └── FRIDA-DEXDump / Frida hook dump（标准流程）
```

> **注意**：观察到 Anti-Frida >= L3、早期自毁或连续两次被检测失败时，不再尝试纯 Frida。没有这些证据时，可做一次诊断性尝试确认存活和时序，但不能因 `A4` 标签无限重试。

### 关键决策门禁

**门禁 0：环境探测（执行决策树前必须先完成）**

决策树中的"有 eBPF 内核支持""有 FART ROM""有 LSPosed"等条件，模型无法自动判断。
必须通过以下方式确认：
- **设备环境探测**（优先于上述检查）：记录设备模式、ABI、Android/ROM、Root、进程存活和用户声明。模拟器不自动等于 Frida 禁用；先检查 Frida/ABI 兼容和目标检测证据
- **adb shell** 执行 `cat /proc/config.gz | gunzip | grep CONFIG_BPF` 或 `ls /data/fart` 或 `pm list packages | grep lsposed` 来检查
- 若 adb 不可用或检查失败，**停下来问用户**："你的环境是否安装了 LSPosed / FART ROM / 是否知道内核是否支持 eBPF？"
- 用户说"都没有"或"不确定"→ 按回退路径（BlackDex → Smali Patch）执行

**门禁 1：有高层 Anti-Frida/早期自毁证据时禁止纯 Frida 优先**

当壳类型匹配上表"防护能力矩阵"中 Anti-Frida >= L3 的壳时，
禁止将纯 Frida 脱壳（FRIDA-DEXDump / Frida hook dump）作为首选。必须先尝试上表中的高隐蔽性工具。
FART+Frida(CYRUS-STUDIO) 不受此限制——它以 Frida 为注入通道但核心逻辑是 ART 层主动调用，在真机+LSPosed 下可正常使用。

**门禁 2：模拟器环境降级**

模拟器环境下先检查目标 ABI、ROM 能力和进程存活，再对运行时方案降级。x86 Frida 并非绝对不可用，但官方测试较少；eBPF/FART 等能力也取决于具体镜像，不能仅从“模拟器”标签推断。
**注意**：BlackDex 是 GUI 工具，模型无法通过 adb 触发脱壳操作。BlackDex "失败"（无法自动化）时，应请用户手动操作或直接进入 Smali Patch，不得将此视为"BlackDex 不可用"而跳到其他方案。

**门禁 3：Frida 尝试次数硬限制**

此限制仅适用于"纯 Frida 脱壳"（FRIDA-DEXDump / Frida hook dump），不适用于 FART+Frida(CYRUS-STUDIO)。
已观察到 Anti-Frida >= L3 或早期自毁：普通纯 Frida 脱壳 0 次，除非新的注入时序证据改变判断。
尚无 Anti-Frida 证据且环境兼容：允许 1 次诊断和最多 1 次有实质差异的修正尝试，随后 pivot。
低保护目标同样遵守“同策略连续失败不重复”的止损规则，不设置无限次数。

## 四、模拟器环境专项策略

### 模拟器检测根因

壳在模拟器中检测强度远超真机，因为：
1. Native 层 `init_array` 检测可能早于常规 Frida 注入；一旦当前样本确认该时序，真机和模拟器上的普通 spawn/attach 都应降级
2. Build.HARDWARE=qemu/goldfish/ranchu 无法通过 Java hook 修复（Native 层直接读）
3. x86 模拟器运行 ARM 应用时架构不匹配，壳可直接检测 CPU 特性
4. 即使 Frida spawn 模式，壳的 init_array 在 JNI_OnLoad 前就执行了检测
5. **模拟器常见劣势**：许多镜像缺少兼容 eBPF/FART 能力；x86 Frida 测试较少，硬件指纹也更容易触发检测。具体能力必须实测

**现代模拟器属性伪造**：MuMu/夜神/雷电/云手机等可伪造 `ro.hardware` 为真实硬件型号（如 `Redmi`），`ro.kernel.qemu` 也可为空。仅靠属性检查不够——必须结合 ADB 连接元数据（设备名含 `emulator`、地址为 `127.0.0.1`）和用户声明综合判定。属性检查能命中的已知厂商：夜神（`nox`）、雷电老版本（`chendu`）、BlueStacks（`bluestacks`）；MuMu/雷电新版本/MuVision 等需依赖步骤 1 的 ADB 元数据信号。

### 模拟器推荐策略

| 策略 | 操作 | 适用壳 | 前置条件 |
|---|---|---|---|
| **Smali Patch 去检测（候选）** | 反编译 APK → 定位壳检测代码 → patch 返回值 → 重打包签名安装 | 检测路径可定位且可重打包的目标 | no-op 重签基线 |
| **进程存活检查** | `adb shell ps \| grep <包名>`，确认进程存活且稳定 >10 秒 | — | **所有环境所有方案的前置** |
| **Root 直读 /proc/pid/mem** | 直接读进程内存 dump DEX/SO，无需注入 SO | 权限与映射允许的目标 | 进程存活 + Root + SELinux/ptrace 允许 |
| **BlackDex 虚拟化** | 安装 BlackDex → 选择目标 → 自动 dump | L1-L2 壳（去检测后可覆盖 L3+） | 进程存活 |
| **Smali Patch + 专用工具** | 先 patch 去检测，再用 BlackDex/DexDump 脱壳 | L3+ 壳 | — |
| **切换真机** | 以上都失败时，建议用户使用 Root 真机（优势：可使用 eBPF/FART 等内核级工具，非 Frida） | 最终兜底 | — |

### 模拟器 Root 直读内存脱壳

**前置条件**（必须按顺序检查，不得跳过）：
1. 模拟器有 Root（大多数模拟器默认 Root）
2. **App 进程存活且稳定**：`adb shell ps | grep <包名>` 返回 PID，且等待 10 秒后再次检查进程仍在
3. 若进程不存在或秒退：壳已检测到模拟器并杀进程，**此方案不可用**，必须先 Smali Patch 去模拟器检测

存在高层 Anti-Frida 或早期自毁证据时，纯 Frida 在真机和模拟器上都应降级。模拟器是否具备 eBPF/FART 等能力取决于具体镜像；进程存活和 `/proc/pid/mem` 权限验证通过后，直读才是候选。

步骤：
1. 正常启动 App（`adb shell am start -n <包名>/<主 Activity>`）
2. **等待 5-10 秒后检查进程**：`adb shell ps | grep <包名>` → 若无结果或进程已死，**终止此 SOP**，转 Smali Patch 去检测
3. 若进程存活，再等待 5 秒确认进程稳定（不秒退），然后获取 PID
4. `adb shell su -c "cat /proc/<PID>/maps | grep dalvik-DEX"` 找到 `[anon:dalvik-DEX data]` 区段
5. `adb shell su -c "dd if=/proc/<PID>/mem bs=1 skip=<十进制起始地址> count=<大小> of=/sdcard/dump.dex"` 读取
6. `adb pull /sdcard/dump.dex` 拉取到本地
7. 验证：本地执行 `python -c "print(open('dump.dex','rb').read(4))"` 输出以 `dex` 开头即正确

**也可用于 SO dump**：`grep '\.so' /proc/<PID>/maps` 找到目标 SO 基地址，同样用 dd 读取。

**竞速 dump（进程存活但会延迟崩溃时）**：若 App 启动后存活 3-10 秒然后崩溃（壳延迟检测），可写脚本在启动后立即轮询 PID 并 dump。但这属于特殊情况——**多数 A4+ 壳在模拟器上进程根本活不了或存活极短，不应假设竞速 dump 可行**。

### Smali Patch 去检测 SOP

1. **apktool d target.apk** 反编译
2. **定位检测点**：
   - Java 层：搜索 `Build.HARDWARE` `ro.hardware` `qemu` `goldfish` `ranchu`
   - Application 子类：检查 `attachBaseContext` `onCreate`
   - ContentProvider：检查 `onCreate`
   - 壳入口类（如 `s.h.e.l.l.N`）：检查架构判断方法（如 `x()` 返回 ARM/ARM64）
3. **Patch 策略**：
   - 布尔判断 → `const/4 v0, 0x0`（return false）
   - 字符串比较 → patch `equals` 返回 false
   - 架构检测 → 修改返回值为 ARM64 对应值
   - `System.exit` / `Process.killProcess` → 替换为空操作
   - Native 层检测 → IDA 分析壳 SO，patch 检测函数入口为 `ret`
4. **重打包签名**：`apktool b` → 签名 → 安装 → 验证不闪退

## 五、壳特定脱壳要点

### 360加固
- **免费版**：BlackDex / FunDex2 通常可直接脱壳
- **企业版(VMP)**：需要 eBPFDexDumper / FART ROM / FART+Frida
- **第三代抽取型**：搜索 magic `BBbb.dgc` → 映射表每 0x18 字节一组 → code_off 按 uleb128 写回
- **脱壳 SO**：SM4-ECB 解密前 0x20000 字节 (key=硬编码⊕包名前16字节) + zstd 解压

### 爱加密
- **标准版**：BlackDex 通常可直接脱壳
- **企业版**：需要 eBPFDexDumper / FART / Smali Patch
- **模拟器闪退**：Native 层检测 Build.HARDWARE + /proc/cpuinfo，优先 Smali Patch
- **关键时机**：`s.h.e.l.l.N.al()` native 方法创建 ClassLoader 时 DEX 解密完成

### 梆梆
- **免费版**：FDex2 / BlackDex
- **企业版**：eBPFDexDumper / FART + 真机
- **libDexHelper.so**：优先读取 `references/bangcle-libdexhelper-playbook.md`，先做外层 SO 静态解密和内层 ELF 验证，再回流 DEX
- **init_array hook**：dump 时机在 `init_proc` 填充导入表前
- **hook libc / read/write/mmap**：观察到这些高层检测或早期自毁证据时跳过纯 Frida；未观察到时只允许按能力探测做有限诊断

### 腾讯乐固
- **标准版**：BlackDex / FDex2 / FunDex2
- **VMP版**：eBPFDexDumper / FART
- **脱壳时机**：`mprotect` 恢复 `r-x` 权限时 dump 真实 ELF

### 腾讯御安全
- **强保护样本候选**：优先评估 eBPFDexDumper / FART 与兼容真机
- **Frida**：当前样本观察到多层 Anti-Frida 或早期自毁时跳过普通注入

### 网易易盾
- **强保护样本候选**：优先评估 eBPFDexDumper / FART + 兼容真机
- **VMP 保护**：多层指令转换，静态分析为主
- **Java2C**：部分方法被转为本机代码，脱壳后仍需 IDA 分析

### 娜迦
- **标准版(lib*dog.so)**：BlackDex / FunDex2
- **企业版(libedog.so)**：eBPFDexDumper / FART
- **新版(libxloader.so)**：检测较新，优先 eBPFDexDumper

### 阿里/聚安全
- **整体**：BlackDex / FRIDA-DEXDump 通常即可
- **class_data_item 分离**：可能需要 FART 主动调用来还原方法体

### 百度加固
- **整体**：BlackDex / FRIDA-DEXDump / FunDex2

### 国际壳(DexGuard/Promon/Arxan)
- **DexGuard**：反混淆为主（参见 deobfuscation-playbook.md），脱壳相对容易
- **Promon/Arxan**：优先评估 eBPFDexDumper / FART + 真机；观察到高层 Anti-Frida 或早期自毁证据时跳过纯 Frida

### 未知壳
1. 先尝试 BlackDex（免 Root，兼容性最好）
2. 失败 → eBPFDexDumper（内核级，最高隐蔽性）
3. 失败 → Smali Patch（完全静态操作）
4. 失败 → FART ROM / 建议用户换环境
5. 以上都失败且已确认壳 Anti-Frida <= L2 + 真机环境 → FRIDA-DEXDump（最后手段）

## 六、纯 Frida 脱壳可行性判定

> 本节中"Frida"均指纯 Frida 脱壳（FRIDA-DEXDump / Frida hook dump），不含 FART+Frida(CYRUS-STUDIO)。

在脱壳场景下，纯 Frida 只有满足以下条件时才作为优先候选：

1. 壳的 Anti-Frida <= L2（仅字符串/文件/端口检测，无内存模式/ArtMethod/SVC 检测）
2. Frida、ROM 与目标 ABI 已通过最小环境探测（真机或兼容模拟器均可）
3. 进程在诊断注入后稳定，且 DEX 在可扫描的连续内存区域出现

以下情况默认跳过纯 Frida，除非出现能改变时序判断的新证据：
- 当前样本已观察到 Anti-Frida >= L3、早期自毁或注入即杀进程
- 当前 ROM/ABI 的 Frida 最小探测本身失败
- 已连续 2 次纯 Frida 脱壳失败（不是脚本 bug 而是被检测杀进程）

## 七、升级路径

专用工具失败后按环境和观测证据升级。A4 不自动删除 FRIDA-DEXDump 候选；有高层 Anti-Frida/早期自毁证据时才跳过。

```
A1-A3: BlackDex → FunDex2 → FRIDA-DEXDump → eBPFDexDumper → FART+Frida → Smali Patch
强动态壳: 按 eBPF/ART/虚拟化/静态 patch/内存直读的实际环境能力排序；有高层 Anti-Frida 证据时跳过纯 Frida
```

每步失败必须记录到 `route-state.json` 的 `approachHistory`，包含工具名、失败现象。
同一步骤最多重试 1 次（不同参数），不得在单一工具上超过 2 次尝试。

## 八、Gadget 注入关键陷阱

> **适用范围**：本方案依赖 Frida 运行时，受实际 Anti-Frida 信号和加载时序约束。A4 不是自动否决条件；若目标已观察到 Frida runtime 检测，Gadget 通常不能解决该检测，应跳过。

适用场景：壳检测在 init_array 或 JNI_OnLoad，Frida spawn/attach 无法在其之前注入。通过将 frida-gadget.so 注入 APK，使其在壳 SO 加载前执行。

### 关键陷阱

1. **禁止 DEX 二进制 patch**：不要在 DEX 中插入或覆盖字节码——这会破坏所有内部偏移（try-catch 区域、debug info、字符串表）。必须用 apktool 的 smali 编译路径：`apktool d → 修改 smali → apktool b`
2. **资源编译失败**：apktool 报错时，先删除壳产生的无效资源声明（如 `res/values/raws.xml` 中的无效条目 + `public.xml` 中对应的引用），再用 `--use-aapt2` 重试
3. **版本匹配**：frida-gadget.so 版本必须与设备端 frida 版本一致
4. **AndroidManifest**：需要 `android:extractNativeLibs="true"`（否则 SO 不会解压到磁盘）
5. **注入位置**：在壳的 native 加载类（如 `N.<clinit>`）的 `System.load` 之前添加 `System.loadLibrary("frida-gadget")`

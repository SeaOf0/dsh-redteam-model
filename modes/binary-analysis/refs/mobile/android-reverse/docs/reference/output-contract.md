<!-- publish: framework -->
# Output Contract

> **维护契约**：本文件是各 topic `outputNeedles` 的注册表。每个 topic 在 `topics/<key>/topic.json` 中声明的 `outputNeedles` 字符串必须全部出现在本文件中——`tools/qa/check-capability-coverage.mjs` 会强制校验。新增或修改 topic 的 `outputNeedles` 时必须同步本文件，否则 `npm run check:capability-coverage` 失败。

- `report.md` 文件名保持不变，但标题、正文、项目符号说明、阶段结论都必须使用中文
- 不输出英文版或中英双语版 `report.md`
- 只有代码、文件名、命令名、协议字段名、接口字段名可保留原文

正式输出至少必须包含：

- 当前阶段
- 自动续跑决策
- 目标边界
- 防护等级
- 当前活跃路线
- 本轮切入点
- 关键证据
- 主要结论
- 验收结果
- `UNKNOWNS`
- task artifact 路径
- `artifacts/tasks/<task-id>/report.md`
- `run/fixtures.json`
- 经验参考
- 是否实际采纳
- 采纳后影响了哪条路线

默认最少交付只覆盖通用任务闭环。
本地复现不限制文件名或语言；在 `run/verification.spec.json` 声明 Node/Python 入口、argv 和输出断言，并用 `task-verify` 生成与当前入口哈希一致的结果。仅退出码为 0 或 stdout 非空不能作为交付证据。

如果包含 JNI / Native 桥接，还必须补充：

- `System.loadLibrary / JNI_OnLoad / RegisterNatives` 边界
- 至少一条 Java -> Native -> 输出链
- `run/register-natives-trace.js`
- `run/jni-bridge-map.md`

如果包含 Protection bypass，还必须补充：

- Root / Frida / Integrity / Pinning 四个检测子面的显式裁定
- 未命中的子面也必须标记 `not-applicable`，不得停留在 `not-started`
- 触发时机
- 绕过结果与残留未解点
- `run/anti-root-bypass.js`
- `run/anti-frida-bypass.js`
- `run/integrity-bypass.js`
- `run/cert-pinning-bypass.js`

如果包含 Dynamic Dex / Shell，还必须补充：

- `DexClassLoader / InMemoryDexClassLoader` 等装载点
- `ClassLoader` 树或装载点
- dump / 重建状态
- `run/class-loader-trace.js`
- `run/dex-loader-dump-notes.md`
- 若命中 `bangcle-libdexhelper`，补充外层 SO、`.init_array`、relocation、解密链、内层 ELF 和 DEX 验证证据
- `run/bangcle-libdexhelper-evidence.md`

如果包含 Crypto / protocol，还必须补充：

- 协议 / 密码边界
- 关键输入边界与动态依赖
- 验收夹具
- `run/protocol-notes.md`
- `run/crypto-fixtures.json`

如果包含 Static triage，还必须补充：

- Manifest / 组件 / 导出面结论
- `run/static-triage-notes.md`
- `run/component-map.md`

如果包含 Runtime hooking，还必须补充：

- Frida hook 时机、线程和样本边界
- `run/frida-java-template.js`
- `run/frida-native-template.js`

如果包含 Java API，还必须补充：

- API client、`baseUrl`、endpoint 与鉴权边界
- `run/api-map.md`

如果包含调用链，还必须补充：

- UI -> ViewModel / Repository / 网络或 Native sink 的链路
- `run/call-chain.md`

如果包含 Native SO，还必须补充：

- 目标 SO、关键符号、桥接关系与主要结论
- `run/native-notes.md`

如果包含 WebView / Hybrid，还必须补充：

- WebView 入口、JS bridge、容器边界与关键回调
- `run/webview-bridge-notes.md`

如果包含 Storage / IPC，还必须补充：

- 存储位置、敏感字段、Provider / Binder / Intent 关键入口
- `run/storage-ipc-notes.md`

如果包含 Split delivery，还必须补充：

- split 结构、安装或重组路径
- `run/split-delivery-notes.md`
- `run/split-layout.json`

如果包含 Framework runtime，还必须补充：

- `Flutter / Hermes / Unity` 运行时类型
- 运行时类型、容器边界、主要资源或模块位置
- `run/framework-runtime-notes.md`
- `run/framework-runtime-map.json`

如果包含 Native Network，还必须补充：

- Java 与 Native 网络栈分层、pinning 命中层与旁路状态
- `run/network-stack-notes.md`

如果包含 ART Runtime，还必须补充：

- 进程模型、触发时机、编译状态与 deopt / attach 策略
- `run/art-runtime-notes.md`

如果包含 Anti-emulator / anti-debug，还必须补充：

- 模拟器 / 调试检测面、触发时机与当前旁路方式
- `run/anti-emulator-bypass.js`

如果包含 Smali patch，还必须补充：

- patch 目标、改动原因、重打包 / 重签名 / 安装验证结果
- `run/smali-patch-notes.md`

如果包含 CTF，还必须补充：

- flag / solver 入口、关键约束与验收脚本
- `run/solver-template.py`

如果包含 Deobfuscation，还必须补充：

- 混淆类型（FLA/BR/SUB）、工具链与还原策略
- `run/deobfuscation-notes.md`

如果包含 VMP Analysis，还必须补充：

- VM 类型、handler table 提取方法与 opcode mapping 策略
- `run/vmp-analysis-notes.md`

如果包含 Unidbg Simulation，还必须补充：

- 模拟环境配置、JNI 补全状态与调用验证
- `run/unidbg-simulation-notes.md`

如果包含 Device Fingerprint，还必须补充：

- 采集维度、风控参数生成链路与绕过策略
- `run/device-fingerprint-notes.md`

如果包含 Hook Injection，还必须补充：

- 注入方式、Hook 机制与目标函数验证
- `run/hook-injection-notes.md`

如果包含 Trace Analysis，还必须补充：

- trace 采集配置（工具、模块范围、粒度）与切片/污点分析结果
- 若做算法还原，附 Python 复现与真实输入输出验证记录
- `run/trace-analysis-notes.md`

如果包含 Kernel-Assisted RE，还必须补充：

- 用户态工具失败的系统性证据（不是"没成功"而是"被拦截"）
- 内核工具选择理由与部署记录（eBPF / HWBP / PTE hook / seccomp / SVC monitor）
- `run/kernel-assisted-re-notes.md`

如果包含 Stealth Hook，还必须补充：

- `Stealth Hook` 升级裁定：目标必须是 A6/A7 且用户态 hook 被系统性拦截，不得因为单次 Frida 失败直接升级
- 模式选择理由（HWBP / PTE+DBI / Ghost Mem / LSPlant stealth）与反检测面裁定
- 外部工具选择记录（若用户实际选择尝试：GitHub 链接、本地产物路径、版本或 commit、SHA256）、设备侧验证记录、hook 点、命中证据、残留风险
- `run/stealth-hook-notes.md`

如果包含 SO Runtime Evidence，还必须补充：

- SO 可分析性判定结论（加密 / 壳化 / 自解密 / 运行时重建 / 可直接分析）与命中特征证据
- 运行期 dump/fix 产物路径、dump 时机（call_constructors / dlopen / maps-stable / 匿名段）、ELF 重建校验结果
- 匿名执行证据 6 项（运行期 maps、可执行段枚举、mmap/mprotect(PROT_EXEC)/memfd_create 来源、pc/lr 归属、跳入匿名段证据、匿名段 dump/fix 产物）
- 内核级 syscall 证据（kill/tgkill/exit/SIGSEGV/SIGTRAP/faccessat/openat + pc/lr/sp 归属）
- 崩溃 7 步闭环进度
- `run/so-runtime-evidence-notes.md`

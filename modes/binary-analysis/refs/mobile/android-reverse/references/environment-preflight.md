# 环境预检与工具链可用性协议

> 本文件收纳按当前路线执行的工具链验证、运行时环境探测、模拟器 + 强保护决策规则。
> SKILL.md 保留触发指针。首次运行动态工具、连接设备、安装或执行目标状态变更前必须读取；纯静态路线不因没有设备而阻塞。

## 目录

- 工具分类
- 可用性验证
- 运行时环境预检（任务初始化阶段必须执行）
- 模拟器 + A4+ 组合预警（硬性输出检查点）
- 替代工具能力边界

## 工具分类

- **有等效 CLI 替代**：jadx-pro-mcp → jadx CLI；dex2jar MCP → d2j-dex2jar CLI。不可用时**允许静默降级到 CLI**，首条回复中声明降级即可
- **无等效 CLI 替代**：ida-pro-mcp（SO 深度反编译/OLLVM 分析）、frida MCP（动态 hook 注入）。只有当前路线确实需要该能力时，不可用才必须停下来请求用户启动；不得把未选用工具的离线状态变成全局阻塞，也不得静默降级到 radare2 等弱替代
- **用户声明优先工具**：`mt-mcp` / MT 管理器属于用户显式指定的交互工具。用户声明已连接或要求优先使用时，必须先做可用性检查并写入 `task.json.toolchain`；不可调用时记录 `[工具阻塞]` 或 `[工具降级]`，不得静默改走 shell / adb / Frida。

## 可用性验证

**首次使用前**：验证用户明确指定的工具和当前 `nextExecutableAction` 需要的工具是否在线。不要为了形式完整枚举当前路线不会使用的全部 MCP；此验证属于输入基线操作，不受时序阻断限制。

**验证结果处理**：全部在线 → 用 `task-record-attempt --kind=tool --status=success` 记录到 `route-state.toolReadiness` 后继续执行；有等效 CLI 替代的离线 → `[工具降级]`；无替代的离线 → `[工具阻塞]` 归类为"允许停下"条件 2。用户优先工具未被记录为 `verified / blocked / unavailable / skipped` 前，`task-advance` 必须返回 `needs-tool-preflight`，不得静默降级。

**MT 前台条件**：若 `task.json.toolchain.preferredTools` 或用户原话包含 `mt-mcp` / MT 管理器，执行任何 MT MCP 动作前必须确认 MT 管理器在手机顶层前台。若目标 App 在前台，先请求或执行前台切换；若无法切换，记录 `[工具阻塞] mt-mcp requires MT Manager foreground`，不得把超时解释为目标 App 行为。

**MT HTTP MCP endpoint 路径**：若用户提供 `http://host:port/mcp` 这类地址，即使当前工具 namespace 未暴露 `mt-mcp`，也必须先尝试 HTTP JSON-RPC 直连：

1. 确认 MT 管理器在设备前台
2. POST `initialize` 到 endpoint，确认 server 名称或 capabilities
3. 调用 `tools/list`，确认存在 `mt_apk_*` 工具
4. 调用 `mt_apk_list_available_apks` 或 `mt_apk_open` 获取当前 APK handle
5. 用 `task-record-attempt --kind=tool --tool=mt-mcp --status=success --endpoint=<url> --foreground --tools-listed --evidence=<log>` 落盘

若任一步失败，必须用 `task-record-attempt --kind=tool --tool=mt-mcp --status=blocked|failed --actual=<原因>` 记录。只有记录后才允许降级到 jadx / rg / adb / Frida。

## 运行时环境预检（首次设备或动态操作前执行）

当前路线首次需要 Frida/ADB、动态 dump、安装启动、设备抓包或其他设备状态操作时，必须先探测设备环境。纯静态反编译、Manifest/资源检查、离线 SO/DEX 初筛无需设备预检，保持 `task.json::executionContext.deviceMode=none` 和 `deviceReady=false`：

1. `adb devices -l` — 设备名含 `emulator` 或地址为 `127.0.0.1:*` → **模拟器/云手机**（最强信号，不可被后续属性检查否定）
2. `adb shell getprop ro.hardware` — 含 `qemu`/`goldfish`/`ranchu`/`vbox86`/`nox`/`bluestacks`/`chendu` → 模拟器
3. `adb shell getprop ro.kernel.qemu` — 值为 `1` → 确认模拟器
4. `adb shell getprop ro.build.flavor` — 含 `generic`/`sdk` → 模拟器构建
5. `adb shell su -c "id" 2>/dev/null` — 含 `uid=0` → 已 Root
6. 判定规则：步骤 1 命中 → 模拟器（不可被步骤 2-4 否定）；步骤 2-4 任一命中 → 模拟器；均未命中 → 真机
7. **用户声明优先**：若用户明确说"模拟器"/"emulator"但检测判定为真机，以用户声明为准按模拟器路径执行，输出 `[环境预警] 用户声明模拟器但属性检测未确认，以用户声明为准`
8. 若当前路线需要设备但 adb 不可用，停下来询问用户："当前设备是真机还是模拟器？是否有 Root 权限？"；仍可推进的纯静态工作不因此停止
9. 将结果写入 `task.json::executionContext.deviceMode`（`emulator` / `physical`）、`deviceReady=true` 和 `rooted`（`true` / `false`）；工具可用性仍由 `state/route-state.json::toolReadiness` 保存

## 模拟器 + 强保护决策点

只有同时观察到模拟器/云手机、目标存在反模拟器或高层 Anti-Frida/早期自毁证据，且下一路线需要当前环境缺失的能力时，才输出环境决策说明。A4 标签本身不触发停机。

说明应列出实际证据、当前 ABI/ROM/进程存活结果、当前环境仍可用的路线，以及切换真机能新增什么能力。不要声称模拟器或 A4 必然使 Frida/eBPF/FART 不可用；这些能力取决于镜像、内核、ABI 和目标检测。

如果静态分析或低风险观测仍可推进，说明后继续推进；只有用户选择会实质改变设备环境、或下一步具有清数据/安装等风险时才等待回复。

## 替代工具能力边界

无替代工具不可用时，首选请求用户启动。用户说"稍后启动"→ 允许继续不需该工具的阶段，进展到必须使用时再次停下请求；用户说"没有"→ 按 `[否决落盘]` 记入 `userRejectedApproaches`，之后使用弱替代。

> Frida 的 frida-server 活跃确认与版本匹配是**每次使用前**的检查（不是任务初始化阶段的环境预检），见 `references/hook-snippets.md` 的"frida-server 预检"节。当本轮需要 jadx 或 IDA 且 PATH 未命中时，先查 PATH、项目 `scripts/`、`third_party/`、已有记录和常见路径；仍未命中必须做宿主机全盘搜索（Windows 枚举盘符搜 `jadx.bat`/`ida64.exe`/`idat64.exe`；Linux/macOS 用 `find`/`mdfind`/`locate`），命令、范围、候选与结果落盘；全盘仍找不到才询问用户路径（详见 `jadx-usage.md`、`native-so-playbook.md`）。

# macOS 安全机制绕过分析（Gatekeeper / SIP / AMFI / 公证）

> 定位：从**逆向分析视角**拆解 macOS 四大安全机制——它们各自验什么、拦截在哪一层、绕过分析要满足什么前置条件。
> 与 `dynamic/macos-process-injection.md` 的「绕过 TCC/Gatekeeper/SIP 阻断注入」引用对应。
> 授权范围：仅对已获授权的目标做安全机制逆向与绕过分析；结论遵循字节级证据 + whoami 级最小影响；删除/破坏性操作只提示不执行。

---

## 0. 机制分层速览

| 机制 | 验什么 | 拦在哪 | 绕过分析焦点 |
|---|---|---|---|
| **Gatekeeper** | 应用来源（公证/隔离属性） | 首次启动（用户态 `syspolicyd`） | quarantine xattr、公证票据、spctl 评估 |
| **SIP**（System Integrity Protection） | 系统关键路径写保护 + 内核扩展/调试限制 | 内核（`csrutil` 配置） | csrutil 配置位、受保护目录、debug 限制 |
| **AMFI**（Apple Mobile File Integrity） | 代码签名 + 库校验 + 调试许可 | 内核（exec/映射时） | `get-task-allow`/库校验/`CS_OPS` 判定 |
| **公证（Notarization）** | 应用经 Apple 扫描无恶意 | 下载来源（`stapled` 票据） | 公证票据存在性、离线公证缓存 |

---

## 1. Gatekeeper

### 工作原理
- 首次执行来源不明应用时，`syspolicyd` 检查 `com.apple.quarantine` 扩展属性与公证状态，决定是否放行。
- 命令行观察评估结果：

```bash
xattr -l ./app                                  # 查 quarantine 属性
spctl -a -vv ./app 2>&1                         # 评估（rejected/accepted 及原因）
codesign -dv --verbose=4 ./app 2>&1             # 看公证/隔离来源
```

### 逆向分析点
- **隔离属性来源**：`com.apple.quarantine` 记录下载来源（应用/URL），是 Gatekeeper 触发的前提。
- **绕过分析的合法路径**：移除隔离属性（`xattr -d com.apple.quarantine ./app`）或让应用满足公证——这属于「本地样本分析前的前置处理」，不是对生产系统发起攻击。
- 判据：`spctl -a -vv` 从 `rejected` 变 `accepted`，且 `xattr` 无 quarantine。

---

## 2. SIP（System Integrity Protection）

### 工作原理
- 内核级写保护 `/System`、`/usr`（除 `/usr/local`）、`/bin`、`/sbin` 等；限制 `task_for_pid` 调试、内核扩展加载、`dtrace` 等。
- 配置查看（仅恢复环境可改）：

```bash
csrutil status                                  # 查看 SIP 状态
csrutil enable --without debug                  # 恢复环境里放宽调试（示例，需重启）
```

### 逆向分析点
- **受影响面**：SIP 开启时无法调试受保护系统进程、无法写系统路径——限制「系统组件级」逆向。
- **绕过分析的合法路径**：目标为用户态应用（不受 SIP 目录保护）时无需关 SIP；仅当必须调试受 SIP 保护的系统进程/写系统路径时，才需在恢复环境 `csrutil disable` 或 `--without debug`（需物理/管理员权限，重启生效）。
- 判据：`csrutil status` 输出各保护位（`System Integrity Protection status: enabled/disabled`），按需记录调试限制是否解除。

---

## 3. AMFI（Apple Mobile File Integrity）

### 工作原理
- 内核执行/映射代码时校验代码签名；执行 `CS_OPS` 判定（`CS_VALID`/`CS_DEBUGGED`/`CS_GET_TASK_ALLOW` 等）。
- 控制「能否调试」（`get-task-allow` entitlement）、「能否加载任意 dylib」（Hardened Runtime 下的 `disable-library-validation`）。
- 命令行观察：

```bash
codesign -d --entitlements :- ./app 2>/dev/null | grep -E "get-task-allow|library-validation|jit"
codesign -dv --verbose=4 ./app | grep -E "flags|runtime"
```

### 逆向分析点
- **调试许可**：`com.apple.security.get-task-allow` 决定能否 lldb attach——无它则 `task_for_pid` 被 AMFI 拒。
- **库注入**：Hardened Runtime（`flags=runtime`）默认禁第三方 dylib 注入；有 `disable-library-validation` 才放行（进程注入面的关键前提，见 macos-process-injection.md）。
- **签名状态**：`codesign -dv` 的 `flags=0x0`（无 Hardened Runtime）与 `flags=0x10000(runtime)` 决定后续注入/调试路线。
- 判据：从 entitlement + flags 判定「该样本能否直接调试/注入，否则需先补 entitlement 重签」。

---

## 4. 公证（Notarization）

### 工作原理
- 应用上传 Apple 扫描，通过后签发「公证票据」（notarization ticket），可 `stapled`（钉）进应用。
- 观察：

```bash
codesign -dv --verbose=4 ./app 2>&1 | grep -i "notar\|stapled"
spctl -a -vv ./app 2>&1
```

### 逆向分析点
- **票据存在性**：`stapled` 票据离线可验（`stapler validate`），决定 Gatekeeper 离线场景是否放行。
- **公证与本地分析的边界**：本地样本分析不需要「通过公证」，只需理解「有隔离属性会触发 Gatekeeper、无票据则离线拒绝」——绕过分析即 §1 的隔离属性处理。
- 判据：`stapler validate ./app` 判断票据有效性。

---

## 5. 组合分析流程（逆向视角）

```text
1. 签名/entitlement 判可行性（§3：能否调试/注入）→
2. 隔离属性判 Gatekeeper 触发（§1）→
3. SIP 判「是否需要关保护才能调试系统进程」（§2，仅必要时）→
4. 公证票据判离线放行（§4）→
5. 落地：调试（lldb）/注入（dylib）/补丁重签名（macho-triage.md §6）。
```

判据：每个机制产出「验什么 → 当前状态 → 是否构成阻断 → 绕过/前置处理路径」一条结论，全部落字节级证据（codesign 输出/xattr/csrutil 状态）。

---

## 延伸

- Mach-O 结构与重签名路线：`platform/macos-reverse/references/macho-triage.md`。
- 进程注入技术（dylib hijack/XPC/Mach port）：`dynamic/macos-process-injection.md`。
- TCC 权限模型逆向：`platform/macos-reverse/references/macho-triage.md` §3。

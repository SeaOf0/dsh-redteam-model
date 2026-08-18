# Mach-O 分诊与 macOS 破解/逆向路线

> 定位：从「3 条命令分诊」扩为**完整破解/逆向路线**——Mach-O 结构识别 → codesign/entitlement 分析 →
> TCC 权限模型逆向 → launchd 持久化 → lldb 动态调试 → 补丁与重签名。
> 与 `macos-reverse/SKILL.md`（工作流/工具链）互补：本篇给逐步可执行路线与判据。
> 平台专属工具按检测制表述：otool/codesign/lldb 为 macOS 系，非 macOS 环境换对应工具并如实标注「macOS 工具链缺失」。

---

## 1. Mach-O 结构识别

```bash
file ./app                          # 判定 Mach-O / universal / fat binary
lipo -info ./app                    # universal：列出架构 slice
otool -hv ./app                     # Mach header：magic/cputype/filetype（MH_EXECUTE/MH_DYLIB/MH_BUNDLE）
otool -l ./app | head -80           # load commands：LC_SEGMENT_64/LC_LOAD_DYLIB/LC_CODE_SIGNATURE/LC_RPATH
otool -L ./app                      # 依赖 dylib 列表
otool -Iv ./app                     # 导入符号（间接符号表）
nm -m ./app                         # 符号（含 weak/undefined）
```

判据：file 输出确认 Mach-O；`otool -l` 中 `LC_CODE_SIGNATURE` 存在 = 已签名；`filetype` 区分可执行/dylib/bundle。

---

## 2. codesign / entitlement 分析

```bash
codesign -dv --verbose=4 ./app                       # 签名详情：标识/团队/是否 Hardened Runtime
codesign -d --entitlements :- ./app 2>/dev/null       # 导出 entitlements（冒号 :- 到 stdout）
spctl -a -vv ./app 2>&1                               # Gatekeeper 评估（公证/隔离属性）
xattr -l ./app                                        # com.apple.quarantine 隔离属性
```

关注点（破解/绕过视角）：

| 字段 | 含义 | 逆向含义 |
|---|---|---|
| `flags=0x10000(runtime)` | Hardened Runtime | 限制库注入/JIT，需对应 entitlement 解锁 |
| `com.apple.security.get-task-allow` | 允许调试（Debug） | 有它才能 lldb attach 调试 |
| `com.apple.security.cs.disable-library-validation` | 关库校验 | 允许加载未签名/任意签名 dylib（注入口） |
| `com.apple.security.cs.allow-jit` | 允许 JIT | Hardened Runtime 下的 JIT 豁免 |
| `com.apple.quarantine` | 隔离属性 | 触发 Gatekeeper 评估路径 |

判据：entitlements 里「允许调试/关库校验/关 dyld 环境变量」等标志决定后续 lldb/注入可行性；签名标识与团队 ID 决定重签名策略。

---

## 3. TCC 权限模型逆向

TCC（Transparency, Consent, and Control）= macOS 权限门，控制「谁（bundle id/进程）能访问敏感数据（摄像头/麦克风/桌面/通讯录/定位）」。

```text
1. 判定目标涉及的 TCC 类别：静态搜 TCC 敏感 API
   （如 AVFoundation 摄像头、CoreLocation、NSContactsUsageDescription）。
   对应 Info.plist 的 UsageDescription 键（NSCameraUsageDescription 等）。
2. TCC 数据库位置（本机分析环境）：
   用户级 ~/Library/Application Support/com.apple.TCC/TCC.db
   系统级 /Library/Application Support/com.apple.TCC/TCC.db
   查询（sqlite3，检测后使用）：
   sqlite3 TCC.db "SELECT service,client,auth_value FROM access;"
3. 逆向关注：
   - 哪个 bundle id 被授予了哪些 service；
   - auth_value 含义（0=拒绝/2=允许/3=仅本次）；
   - 目标程序是否滥用已授权 TCC（如已授权「桌面」则读桌面文件）。
```

判据：能从 TCC 数据库 + 静态 API 命中，还原「目标依赖哪些 TCC 权限、当前授权状态、是否存在越权读取」。

---

## 4. launchd 持久化逆向

```text
1. 定位持久化载体（LaunchAgent/Daemon plist）：
   用户级 ~/Library/LaunchAgents/
   系统级 /Library/LaunchAgents/ /Library/LaunchDaemons/
   plist 字段：Label/ProgramArguments/RunAtLoad/KeepAlive/StartInterval/MachServices。
2. 解析（检测 plutil 后使用）：
   plutil -p ~/Library/LaunchAgents/com.example.plist
3. 逆向关注：ProgramArguments 指向的可执行、MachServices 暴露的 XPC 服务名、
   RunAtLoad/KeepAlive 自启行为、用户名（Daemon 以 root 跑）。
```

判据：还原「开机/登录后哪些程序被拉起、以什么身份、暴露什么 XPC 服务」——与进程注入面（macos-process-injection.md）衔接。

---

## 5. lldb 动态调试

```bash
lldb ./app
(lldb) breakpoint set -n main            # 或按符号/地址
(lldb) breakpoint set -a 0x100001234      # 按地址（注意 PIE + ASLR slide）
(lldb) image list -o -f                   # 看 ASLR slide（基址偏移）
(lldb) run
(lldb) register read / memory read -c 32 $rdi
(lldb) dis -n main / ni / si
```

要点：

- PIE 样本先 `image list -o` 拿 slide，静态地址 + slide = 运行时地址。
- 需要调试权限：entitlement 含 `get-task-allow` 或关闭 SIP（见 macos-security-bypass）。
- 观察 ObjC/Swift 调用：`image lookup -rn "selector"`、`po`（ObjC 表达式）。

判据：断点命中、寄存器/内存/调用栈与静态结论互证，产出动态证据。

---

## 6. 补丁与重签名

破解/还原后把补丁落盘并重签名（macOS 强制签名校验，未签名/改字节的二进制无法加载）：

```bash
# 1. 定位补丁点（文件偏移，用 otool -l 把虚拟地址转文件偏移，或用 lldb/hopper）
# 2. 打补丁（python3 写字节，或 lldb memory write 后导出）
# 3. 去除原签名 + 重签（ad-hoc 签名，或用自己的开发者证书）：
codesign --force --deep --sign - ./app           # ad-hoc 重签
codesign --force --deep --sign "Developer ID" ./app  # 用证书重签
# 4. 校验
codesign -dv --verbose=4 ./app
codesign --verify --deep --strict ./app
```

要点：

- `--deep` 递归签 bundle 内嵌框架；`--force` 覆盖旧签名；`--sign -` 为 ad-hoc（本地可跑、不公证）。
- 打补丁后原 `LC_CODE_SIGNATURE` 失效，必须重签才能运行；重签后 Gatekeeper/公证状态改变（`spctl` 重新评估）。
- 改了 entitlements 需重签时重新注入 entitlement 文件（`codesign --entitlements ent.plist`）。

判据：`codesign --verify --deep --strict` 通过 + 补丁后样本能运行 + 记录补丁字节/偏移证据。

---

## 7. 一条龙路线（破解场景）

```text
结构识别（§1）→ 签名/entitlement 判可行性（§2）→ 静态定位验证点（字符串/API）→
lldb 动态确认（§5）→ 算法还原/补丁（software-cracking）→ 重签名（§6）→ 运行验证。
涉及 TCC/launchd 越权面（§3/§4）时记录权限与持久化证据。
```

---

## 延伸

- Gatekeeper/SIP/AMFI/公证的绕过视角：`macos-security-bypass/SKILL.md`（refs 根目录，与 dynamic/macos-process-injection.md 的悬空引用对应）。
- 进程注入（dylib hijack/XPC/Mach port）：`dynamic/macos-process-injection.md`。
- 反调试（ptrace/DTrace/TCC 保护）：`methodology/anti-debugging.md`。

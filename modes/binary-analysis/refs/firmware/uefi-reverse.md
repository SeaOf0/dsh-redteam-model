# UEFI 固件逆向专项

> 定位：`firmware/firmware-analysis.md` 与 `firmware-pentest/`（binwalk/emba/emulation-fuzz）是 IoT 视角，本篇补 **UEFI 专项**——
> SPI 读取、固件卷/模块（DXE·PEI）解析、Setup 变量（NVRAM）、Secure Boot 绕过、UEFI 驱动分析。
> 工具按检测制：`command -v` 探测 UEFITool/chipsec/ghidra 等，缺失走四级兜底。

---

## 0. UEFI 固件结构概览

```text
SPI Flash 镜像
├─ FD（Firmware Device，固件设备）
│  ├─ FV（Firmware Volume，固件卷）
│  │  ├─ PEI 模块（Pre-EFI Initialization，早期初始化）
│  │  ├─ DXE 模块（Driver eXecution Environment，驱动执行环境）
│  │  └─ SMM 模块（System Management Mode，高权限）
│  ├─ NVRAM（Setup 变量 / 启动项 / 证书）
│  └─ 引导载荷（BootLoader）
```

逆向焦点：DXE 驱动（含 SMM 模块）承载最多安全逻辑（Secure Boot 校验、变量访问门禁）；NVRAM 存 Setup 变量与证书。

---

## 1. 镜像获取（SPI 读取）

```text
1. 硬件：SPI 编程器（如 CH341A）夹取固件 flash，读取镜像。
2. 软件：厂商更新包提取（解包 .cap/.fd/.bin）；或 UEFI shell 的 dump 工具。
3. 校验：file + 大小对齐（通常 8/16/32 MB），首字节为 FD 头。
```

判据：镜像含可识别的 `_FVH`（Firmware Volume Header）魔数（`_FVH` 0x5F465648），或 FD 头签名。

---

## 2. 解析（UEFITool / UEFIExtract）

```bash
# UEFITool：GUI 浏览固件卷/模块/节
# UEFIExtract：命令行提取所有模块到目录
UEFIExtract image.bin all
# 提取后每个模块是一个 PE32 文件（DXE/PEI），可直接反汇编
file output/*.efi
```

输出解读：每个 DXE/PEI 模块 = 一个 PE32 可执行；NVRAM 区 = 可变/证书/启动项数据。

判据：`UEFIExtract all` 产出多个 `.efi`/PE32 模块 + NVRAM 数据块，模块可用 Ghidra/IDA 打开。

---

## 3. DXE / PEI 模块分析

```text
1. 反汇编 DXE 驱动（Ghidra/IDA），efiXplorer（IDA 插件）标注 UEFI 类型与 protocol。
2. 识别模块职责：
   - 含 gEfiLoadedImageProtocol / gEfiSecurityArchProtocol → 安全相关（Secure Boot）。
   - 含 gEfiVariableArchProtocol → 变量访问（NVRAM 门禁）。
   - SMM 模块（SMM 入口）→ 高权限逻辑，重点审。
3. 交叉引用 protocol GUID 与 handler 函数。
```

判据：识别出「安全 protocol 的 handler」与「变量访问门禁」，即定位到 Secure Boot / NVRAM 安全逻辑。

---

## 4. Setup 变量（NVRAM）分析

```text
1. UEFITool 定位 NVRAM 区（含 EFI 变量）。
2. 关注：SecureBoot、SetupMode、PK（Platform Key）/KEK（Key Exchange Key）/db/dbx（签名数据库）。
3. 用 chipsec 或 UEFITool 提取变量，还原「当前 Secure Boot 状态 + 信任链证书」。
```

```bash
# chipsec（检测后使用，需管理员/物理访问）
chipsec_util uefi var-list
chipsec_util uefi var-read SecureBoot <guid>
```

判据：`SecureBoot` 变量值（0=关/1=开）+ `SetupMode`（1=可写密钥）+ PK/KEK/db 内容，判定信任链可被谁改写。

---

## 5. Secure Boot 绕过分析（逆向视角）

```text
1. 定位校验逻辑：DXE 驱动里验证镜像签名/哈希的 handler。
2. 分析信任链：PK → KEK → db（允许的签名/哈希）→ dbx（黑名单）。
3. 绕过分析面：
   - SetupMode=1 且 PK 未设 → 可注入自定义 KEK/db（合法配置态）。
   - dbx 未覆盖目标哈希 → 已吊销镜像仍可能被加载（吊销不完整）。
   - 校验 handler 的 bug（如只验哈希不验签名、比较长度错误）→ 逻辑绕过。
```

判据：能写出「从信任链 → 校验 handler → 可绕过点」的完整证据链（字节级），不虚构可利用性。

---

## 6. UEFI 驱动分析（含 SMM）

```text
1. SMM 模块入口（SMM handler）：定位 SwSmi 编号（软件 SMI 触发码）。
2. 分析 SMM handler 的参数校验（缺校验 = 任意地址读写，高危）。
3. 关注 SMRAM 访问、变量写门禁（SMM 可绕过 DXE 门禁）。
```

判据：识别 SMM handler 及 SwSmi 编号、校验缺失点；结论交 pentest/attack-defense 做利用验证（本模式只到「发现」）。

---

## 7. 工具链速查

| 工具 | 用途 |
|---|---|
| UEFITool / UEFIExtract | 固件卷/模块解析与提取 |
| chipsec | SPI 读取、变量读写、SMM 分析 |
| efiXplorer（IDA 插件） | UEFI 类型/protocol 标注 |
| Ghidra / IDA | 模块反汇编/反编译 |
| binwalk | 快速扫描嵌入文件（粗分诊） |

---

## 来源与延伸

- UEFITool：https://github.com/LongSoft/UEFITool
- chipsec：https://github.com/chipsec/chipsec
- IoT 固件通用分析（binwalk/emba/emulation-fuzz）：`firmware/firmware-analysis.md`、`firmware/firmware-pentest/`。
- 内核驱动逆向（与 SMM/DXE 安全逻辑呼应）：`methodology/reverse-engineering/references/kernel-driver-reverse.md`。

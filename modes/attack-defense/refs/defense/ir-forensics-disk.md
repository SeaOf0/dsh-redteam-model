---
name: ir-forensics-disk
description: >
  磁盘取证完整手册：覆盖磁盘镜像获取 (dd/dcffld/FTK)、磁盘镜像分析 (Autopsy/The Sleuth Kit)、
  固件提取 (binwalk)、文件雕刻恢复 (foremost/scalpel)、删除文件恢复 (PhotoRec)。
  包含取证获取最佳实践、证据链管理、磁盘分析方法论、工具命令速查表和 MITRE ATT&CK 映射。
domain: cybersecurity
subdomain: digital-forensics
tags: [disk-forensics, imaging, autopsy, sleuth-kit, file-carving, firmware, photo-rec, evidence]
version: 2.0.0
---

# 磁盘取证 — 完整手册

## 适用场景

**适用于:** 安全事件磁盘证据获取与分析、删除文件恢复、磁盘镜像分析、固件提取与逆向、
文件雕刻恢复、事件调查中的磁盘证据链管理。

**不适用于:** 内存取证（见 ir-forensics-*）、网络取证（见 network-traffic-analysis）、
移动设备取证（见 mobile-forensics）。

**前置条件:**
- 取证工作站 (Linux 推荐: SIFT/REMnux/Caine)
- 写 blocker 硬件或软件
- 足够存储空间（镜像通常为目标磁盘 2 倍）
- 证据链表格和封签

---

## Part A：取证方法论

### 1. 磁盘镜像获取

#### 1.1 使用 dd/dc3dd/dcfldd

```bash
# 基础 dd 镜像 (添加哈希校验)
dd if=/dev/sda of=/evidence/disk_image.dd bs=4M status=progress
sha256sum /evidence/disk_image.dd > /evidence/disk_image.dd.sha256

# dcfldd (内建哈希和进度)
dcfldd if=/dev/sda of=/evidence/disk_image.dd \
  hash=sha256 \
  hashwindow=1G \
  hashlog=/evidence/hash.log \
  bs=4M \
  status=on \
  statusinterval=1G

# dc3dd (法证改进版)
dc3dd if=/dev/sda \
  of=/evidence/disk_image.dd \
  hash=sha256 \
  log=/evidence/acquisition.log \
  verb=on \
  mds=sha256

# EWF 格式镜像 (EnCase 兼容)
ewfacquire /dev/sda \
  -c best \
  -f encase6 \
  -C "Investigator Name" \
  -e "Case #2024-001" \
  -t "Suspect Disk" \
  -o /evidence/

# 分割大镜像
dd if=/dev/sda of=/evidence/part_%03d.dd bs=4M split=1G
```

#### 1.2 远程/网络获取

```bash
# 通过 netcat 远程获取
# 目标机:
dd if=/dev/sda bs=4M | nc 192.168.1.100 9000

# 取证工作站:
nc -l -p 9000 > /evidence/remote_image.dd

# 通过 SSH 加密传输
dd if=/dev/sda bs=4M | ssh forensic@workstation "cat > /evidence/remote_image.dd"

# 使用 Guymager (GUI 工具)
guymager  # 支持 dd, EWF, AFF 格式
```

#### 1.3 虚拟机/云环境获取

```bash
# VMware 快照转磁盘
vmware-vdiskmanager -r source.vmdk -t 0 /evidence/flat.vmdk

# AWS EBS 快照
aws ec2 create-snapshot --volume-id vol-xxx --description "Forensic Snapshot"
aws ec2 create-volume --snapshot-id snap-xxx --availability-zone us-east-1a

# Azure 磁盘快照
az snapshot create --resource-group RG --name forensic-snap --source /subscriptions/xxx/disks/disk-name

# 从云快照获取镜像
aws ec2 describe-snapshots --snapshot-ids snap-xxx
# 挂载到取证 EC2 实例
```

#### 1.4 证据链文档

```markdown
## 磁盘镜像获取记录

日期/时间: YYYY-MM-DD HH:MM UTC
调查人员: [姓名]
案件编号: [编号]
设备描述: [品牌/型号/序列号]
磁盘信息: [型号/容量/序列号/S.M.A.R.T.状态]

获取方法:
□ 写保护器: [型号]
□ 工具: [dd/dcfldd/EWF]
□ 哈希算法: SHA-256

哈希值:
- 源磁盘: [pre-hash]
- 镜像文件: [post-hash]
- 匹配: □ 是 □ 否

签名:
- 获取人: _____________ 日期: _____
- 见证人: _____________ 日期: _____
```

### 2. 磁盘镜像分析

#### 2.1 Autopsy 使用

```bash
# 安装 Autopsy
apt install -y autopsy

# 创建新案件
# GUI: https://localhost:9999/autopsy
# 或命令行:
autopsy -c /evidence/case1 -d /evidence/disk_image.dd

# 关键分析步骤:
# 1. 添加数据源 → 磁盘镜像
# 2. Ingest Module 选择:
#    ☑ Recent Activity
#    ☑ Hash Lookup
#    ☑ File Type Identification
#    ☑ Keyword Search
#    ☑ Email Parser
#    ☑ Encryption Detection
#    ☑ Extension Mismatch Detection
#    ☑ OS Account Parser
#    ☑ Activity Diagram

# 关键搜索
# 搜索关键词: password, confidential, secret, admin
# 搜索文件扩展名: .ps1, .bat, .exe, .dll, .zip
# 搜索时间范围: 事件发生窗口

# 数据源分析:
# - 文件系统浏览 ($MFT, 目录结构)
# - 已删除文件恢复
# - 时间线分析
# - Web 浏览器历史
# - 电子邮件
# - 注册表分析
```

#### 2.2 The Sleuth Kit (TSK) 命令行

```bash
# 分区信息
mmls /evidence/disk_image.dd

# 文件系统信息
fsstat -o 204800 /evidence/disk_image.dd  # -o = 分区偏移

# 列出文件和目录
fls -o 204800 /evidence/disk_image.dd
fls -o 204800 -r /evidence/disk_image.dd  # 递归

# 查找文件名
find -o 204800 /evidence/disk_image.dd -name "*.exe"

# 读取文件内容 (通过 inode)
icat -o 204800 /evidence/disk_image.dd 12345 > extracted_file.exe

# 检查已分配/未分配簇
blkls -o 204800 /evidence/disk_image.dd

# 提取未分配空间
blkls -o 204800 -l /evidence/disk_image.dd > unallocated.img

# MFT 分析
istat -o 204800 /evidence/disk_image.dd 0     # $MFT
istat -o 204800 /evidence/disk_image.dd 5     # 根目录

# 时间线构建
fls -o 204800 -m "C:/" /evidence/disk_image.dd > body.txt
mactime -b body.txt -z UTC > timeline.csv

# 搜索文件内容
srch_strings -a /evidence/disk_image.dd | grep -i "password\|secret\|confidential"
```

#### 2.3 时间线分析

```bash
# 使用 log2timeline (Plaso)
log2timeline.py --storage-file /evidence/case1.plaso /evidence/disk_image.dd

# 生成时间线
psort.py -o l2tcsv /evidence/case1.plaso > timeline_full.csv

# 过滤特定时间范围
psort.py -o l2tcsv /evidence/case1.plaso "date > '2024-01-15 08:00:00' AND date < '2024-01-15 18:00:00'" > timeline_filtered.csv

# 过滤特定活动
psort.py -o l2tcsv /evidence/case1.plaso "source_short == 'LOG' AND message CONTAINS 'execution'" > timeline_exec.csv
```

### 3. 文件雕刻恢复

#### 3.1 Foremost

```bash
# 从磁盘镜像恢复已删除文件
foremost -i /evidence/disk_image.dd -o /evidence/carved/

# 自定义配置 (foremost.conf)
cat > foremost.conf << 'CONF'
# 文件签名定义
jpg y 150000 \xff\xd8\xff\xe0\x00\x10 \xff\xd9
jpg y 150000 \xff\xd8\xff\xe1 \xff\xd9
png y 150000 \x89\x50\x4e\x47 \xae\x42\x60\x82
gif y 150000 \x47\x49\x46\x38 \x00\x3b
pdf y 5000000 \x25\x50\x44\x46 \x25\x45\x4f\x46
doc y 150000 \xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1
zip y 150000 \x50\x4b\x03\x04 \x50\x4b\x05\x06
exe y 150000 \x4d\x5a
ps1 y 50000 #ps1
bat y 50000 @echo
CONF

foremost -c foremost.conf -i /evidence/disk_image.dd -o /evidence/carved_custom/
```

#### 3.2 Scalpel (改进版)

```bash
# 安装
apt install -y scalpel

# 编辑 scalpel.conf 启用需要的文件类型
scalpel -c /etc/scalpel/scalpel.conf -i /evidence/disk_image.dd -o /evidence/scalpel_output/

# 从未分配空间雕刻
blkls -o 204800 /evidence/disk_image.dd | scalpel -c /etc/scalpel/scalpel.conf -o /evidence/scalpel_unalloc/
```

### 4. 删除文件恢复

#### 4.1 PhotoRec

```bash
# 交互式恢复
photorec /evidence/disk_image.dd
# 选择: 分区 → 文件系统类型 → 输出目录 → 文件类型

# 命令行模式 (非交互)
photorec /d /evidence/photorec_output/ /cmd /evidence/disk_image.dd partition_none,options,fileopt,everything,enable,search

# 特定文件类型恢复
# 编辑 photorec 配置: 只启用需要的类型
photorec /d /evidence/docs_only/ /cmd /evidence/disk_image.dd partition_none,options,fileopt,doc,enable,pdf,enable,xls,enable,ppt,enable,search
```

#### 4.2 ext3/ext4 删除文件恢复

```bash
# 使用 extundelete
extundelete /evidence/disk_image.dd --restore-all
extundelete /evidence/disk_image.dd --restore-file path/to/deleted/file.txt
extundelete /evidence/disk_image.dd --restore-inode 12345

# 使用 debugfs (ext 文件系统)
debugfs /evidence/disk_image.dd
debugfs: lsdel    # 列出已删除 inode
debugfs: dump <12345> /evidence/recovered_file.txt

# NTFS 恢复 (使用 NTFS 工具)
# 使用 TestDisk
testdisk /evidence/disk_image.dd
# → Advanced → List → 选择已删除文件 → Copy
```

### 5. 固件提取与分析

#### 5.1 binwalk 固件分析

```bash
# 扫描固件中的嵌入文件和签名
binwalk /evidence/firmware.bin

# 详细扫描 (含熵分析)
binwalk -E /evidence/firmware.bin  # 熵分析图

# 自动提取
binwalk -e /evidence/firmware.bin

# 递归提取 (提取后继续扫描)
binwalk -Me /evidence/firmware.bin

# 指定提取规则
binwalk --dd='gzip:gz' --dd='lzma:lzma' /evidence/firmware.bin

# 常见固件结构识别
binwalk /evidence/router_firmware.bin
# 输出:
# DECIMAL       HEX         DESCRIPTION
# 0             0x0         uImage header, ...
# 32            0x20        LZMA compressed data, ...
# 1048576       0x100000    Squashfs filesystem, ...

# 提取 Squashfs
unsquashfs -d /evidence/squashfs_root /evidence/firmware.bin-100000.squashfs

# 提取 CPIO 归档
cpio -idmv < /evidence/extracted/cpio_rootfs
```

#### 5.2 固件静态分析

```bash
# 提取可执行文件
find /evidence/extracted/ -type f -executable | head -20

# 分析 ELF 二进制
file /evidence/extracted/usr/bin/*
readelf -h /evidence/extracted/usr/sbin/httpd
readelf -S /evidence/extracted/usr/sbin/httpd  # 节表

# 检查硬编码凭证
grep -r "password\|admin\|root\|default" /evidence/extracted/etc/ 2>/dev/null
grep -r "password\|passwd" /evidence/extracted/ --include="*.conf" --include="*.cfg"

# 检查 Web 目录
find /evidence/extracted/ -name "*.php" -o -name "*.cgi" -o -name "*.sh"

# 检查启动脚本
cat /evidence/extracted/etc/init.d/*
cat /evidence/extracted/etc/rc.d/*

# 检查后门特征
strings /evidence/extracted/usr/sbin/* | grep -iE "backdoor|telnetd|shell|cmd|exec"
```

---

## Part B：取证最佳实践

### 6. 证据管理

```markdown
## 数字证据管理清单

获取前:
□ 设备拍照 (含序列号、连接状态)
□ 证据标签 (案件号、日期、描述)
□ 写保护器验证 (确认只读)
□ 获取前哈希 (如可行)

获取中:
□ 完整磁盘镜像 (非文件拷贝)
□ 日志记录获取过程 (工具、参数、时间)
□ 哈希校验 (获取前后对比)
□ 多份备份 (至少 2 份，不同介质)

获取后:
□ 证据封签
□ 安全存储 (加密/物理安全)
□ 访问日志 (谁/何时/为何访问)
□ 原始证据只读 (分析用副本)

分析中:
□ 只分析副本
□ 记录所有操作 (工具、命令、输出)
□ 关键发现截图
□ 时间戳使用 UTC
```

### 7. 取证报告模板

```markdown
## 磁盘取证分析报告

### 1. 案件概述
- 案件编号:
- 委托方:
- 调查人员:
- 分析日期:

### 2. 证据描述
| 项目 | 描述 |
|------|------|
| 证据编号 | EX-001 |
| 设备类型 | 笔记本电脑 |
| 磁盘大小 | 256 GB SSD |
| 文件系统 | NTFS |
| 镜像格式 | EWF (EnCase) |
| SHA-256 | [hash] |
| 获取日期 | YYYY-MM-DD |

### 3. 分析方法
- 工具: Autopsy 4.x, TSK, Plaso
- 搜索关键词: [list]
- 时间范围: [range]

### 4. 关键发现
| # | 时间 (UTC) | 类型 | 描述 | 证据位置 |
|---|-----------|------|------|---------|
| 1 | | 文件 | | |
| 2 | | 注册表 | | |
| 3 | | 网络 | | |

### 5. 时间线
[关键事件时间线]

### 6. 结论
[分析结论和建议]

### 7. 附录
- 工具版本
- 完整命令记录
- 哈希验证报告
```

---

## 速查表

### 磁盘取证工具速查

| 工具 | 功能 | 命令示例 |
|------|------|---------|
| dd | 原始镜像 | `dd if=/dev/sda of=image.dd bs=4M` |
| dcfldd | 法证 dd | `dcfldd if=/dev/sda of=image.dd hash=sha256` |
| dc3dd | 法证 dd (改进) | `dc3dd if=/dev/sda of=image.dd hash=sha256` |
| ewfacquire | EWF 格式镜像 | `ewfacquire /dev/sda -f encase6` |
| guymager | GUI 镜像获取 | `guymager` |
| autopsy | GUI 磁盘分析 | `autopsy` |
| mmls | 分区表分析 | `mmls image.dd` |
| fls | 文件列表 | `fls -o 2048 -r image.dd` |
| icat | 文件提取 | `icat -o 2048 image.dd 12345 > file` |
| fsstat | 文件系统信息 | `fsstat -o 2048 image.dd` |
| blkls | 块列表 | `blkls -o 2048 image.dd` |
| foremost | 文件雕刻 | `foremost -i image.dd -o output/` |
| scalpel | 文件雕刻 | `scalpel -c conf -i image.dd -o output/` |
| photorec | 删除文件恢复 | `photorec image.dd` |
| testdisk | 分区恢复 | `testdisk image.dd` |
| binwalk | 固件分析 | `binwalk -e firmware.bin` |
| plaso | 时间线 | `log2timeline.py case.plaso image.dd` |
| FTK Imager | Windows 镜像获取 | GUI 工具 |

### 文件签名 (Magic Numbers)

| 文件类型 | Hex 签名 | ASCII |
|---------|---------|-------|
| JPEG | FF D8 FF E0 / FF D8 FF E1 | ÿØÿà / ÿØÿá |
| PNG | 89 50 4E 47 | .PNG |
| GIF | 47 49 46 38 | GIF8 |
| PDF | 25 50 44 46 | %PDF |
| ZIP | 50 4B 03 04 | PK |
| RAR | 52 61 72 21 | Rar! |
| 7z | 37 7A BC AF 27 1C | 7z¯' |
| EXE | 4D 5A | MZ |
| ELF | 7F 45 4C 46 | .ELF |
| DOC/DOCX | D0 CF 11 E0 / 50 4B 03 04 | ÐÏ.à / PK |
| SQLite | 53 51 4C 69 74 65 | SQLite |
| Registry | 72 65 67 66 | regf |

### 取证获取检查清单

```
□ 写保护器已验证 (只读)
□ 源设备信息已记录 (型号/SN/容量)
□ 获取前计算源设备哈希 (如支持)
□ 使用经过验证的工具 (dd/dcfldd/EWF)
□ 获取过程日志已保存
□ 镜像文件 SHA-256 已计算
□ 哈希匹配已验证
□ 证据标签已填写
□ 证据封签已签署
□ 备份副本已创建
□ 安全存储位置已记录
```

---

## MITRE ATT&CK 映射

| Technique ID | 名称 | 阶段 | 取证指标 |
|-------------|------|------|---------|
| T1070.004 | File Deletion | 防御绕过 | 已删除文件恢复 |
| T1070.001 | Clear Windows Event Logs | 防御绕过 | 日志文件分析 |
| T1005 | Data from Local System | 收集 | 文件访问时间线 |
| T1036 | Masquerading | 防御绕过 | 文件签名 vs 扩展名 |
| T1059 | Command Scripting | 执行 | 脚本文件发现 |
| T1564 | Hide Artifacts | 防御绕过 | 隐藏文件/ADS 分析 |
| T1140 | Deobfuscate/Decode Files | 防御绕过 | 编码文件识别 |
| T1027 | Obfuscated Files | 防御绕过 | 打包/加密文件提取 |
| T1204 | User Execution | 执行 | 恶意文件时间线 |
| T1547 | Boot Autostart | 持久化 | 启动项/注册表分析 |

---

## 前置条件

```bash
# SIFT 工作站 (推荐)
# 下载: https://github.com/teamdfir/sift

# 或手动安装
apt install -y autopsy sleuthkit foremost scalpel testdisk \
  photorec binwalk plaso ewf-tools guymager dc3dd dcfldd

# 验证工具
which mmls fls icat foremost photorec binwalk log2timeline.py

# 写保护器硬件
# 推荐: Tableau T35u (USB 3.0)
# 或: WiebeTech USB WriteBlocker
```

---

## Part C：2025-2026 更新

### 8. SSD / TRIM 对磁盘取证的影响

#### 8.1 SSD 与 HDD 取证差异

| 特性 | HDD (机械硬盘) | SSD (固态硬盘) |
|------|---------------|---------------|
| 数据删除后可恢复性 | 高 — 删除仅标记目录项，数据保留在扇区 | 低 — TRIM 指令触发后控制器异步擦除数据块 |
| 磨损均衡 (Wear Leveling) | 不适用 | FTL 层动态映射 LBA→PBA，同一逻辑地址数据物理位置不断变化 |
| 垃圾回收 (GC) | 不适用 | 后台合并有效页并擦除整块，导致已删除数据不可恢复 |
| 加密 (SED) | 少见 | 多数消费级 SSD 自带硬件加密 (OPAL/SED) |
| 取证镜像完整性 | 位级镜像可完整复制 | 位级镜像仅捕获 FTL 暴露的逻辑映射，无法获取物理芯片原始数据 |

#### 8.2 TRIM 机制详解

```markdown
## TRIM 工作流程

1. OS 发出删除文件命令 → 文件系统标记簇为空闲
2. OS 向 SSD 控制器发送 TRIM 命令 (ATA TRIM / SCSI UNMAP)
3. SSD 控制器将对应 LBA 标记为可回收
4. 垃圾回收线程在后台异步擦除对应 NAND 块
5. 数据在物理层面被清除，无法通过软件恢复

## TRIM 触发条件
- 手动删除文件
- 格式化分区 (Windows quick format 触发 TRIM)
- 修剪命令 (fstrim / defrag /TRIM)
- Windows: 已默认开启 (fsutil behavior query DisableDeleteNotify → 0)
- Linux: fstrim.timer 或 mount discard 选项
- macOS: 默认启用 TRIM (Apple SSD); 第三方 SSD 需手动启用
```

#### 8.3 SSD 取证策略

```bash
# === 关键原则：时间就是一切 ===
# 发现 SSD 证据后，立即断电（非正常关机）以减少 GC 和 TRIM 执行窗口

# 1. 禁用 TRIM 后获取镜像（取证工作站）
# Linux: 确保 mount 不使用 discard 选项
mount | grep discard  # 应无输出

# 确认系统 TRIM 定时器已停止
systemctl stop fstrim.timer
systemctl disable fstrim.timer

# 2. 在目标系统上临时禁用 TRIM
# Windows (需要管理员):
fsutil behavior set DisableDeleteNotify 1

# Linux:
echo 0 > /sys/block/sda/queue/discard_max_bytes

# 3. 尽快获取镜像
# 使用 dc3dd 或 dcfldd，附加 SHA-256 哈希校验
dc3dd if=/dev/sda of=/evidence/ssd_image.dd hash=sha256 log=/evidence/ssd_acq.log

# 4. SSD 特殊考量
# - 如果 SSD 支持 ATA Security 特性，考虑冻结安全状态
# - 对于自加密 SSD (SED), 需要获取加密密钥或使用厂商工具解锁
# - NVMe SSD: 使用 nvme-cli 获取 SMART 和 namespace 信息
nvme smart-log /dev/nvme0
nvme ns-list /dev/nvme0
nvme id-ns /dev/nvme0n1
```

#### 8.4 SSD 数据恢复可能性评估

```markdown
## SSD 数据恢复可能性矩阵

| 场景 | TRIM 状态 | 恢复可能性 | 推荐方法 |
|------|----------|-----------|---------|
| 误删文件，未重启 | 已启用 | 中-低 | 立即断电 → 芯片级提取 (需专业设备) |
| 误删文件，已重启 | 已启用 | 极低 | 文件雕刻尝试 (可能已被 GC 清除) |
| 格式化 (快速) | 已启用 | 低 | 文件雕刻 + $MFT 残留分析 (NTFS) |
| 格式化 (完整) | 已启用 | 极低 | 仅芯片级提取可能恢复部分数据 |
| TRIM 已禁用/不支持 | 未启用 | 高 | 标准文件雕刻和恢复方法 |
| 硬件故障 | N/A | 中 | 芯片直读 (NAND dump, 需拆芯片) |
| 加密 SSD + 无密钥 | N/A | 极低 | 需要从内存提取密钥 (见内存取证) |

## 芯片级提取工具
- PC-3000 SSD (Ace Lab) — 商业工具，支持主流 SSD 控制器
- Rusolut VNR — NAND 芯片直读和重组
- Flash Extractor — 开源 NAND 提取框架
```

---

### 9. Autopsy 4.x 最新功能 (2025)

#### 9.1 Autopsy 4.21+ 新特性

```markdown
## Autopsy 4.x 主要更新 (2024-2025)

### 核心改进
- 多线程 Ingest Pipeline: 显著加快大型磁盘镜像分析速度
- 改进的数据源类型: 支持 APFS, ext4, Btrfs 文件系统
- 可编程 Ingest Module: 支持 Python 和 Groovy 脚本扩展
- 通信分析模块: 可视化电话/短信/邮件通信关系图

### 新 Ingest Module
- **Plaso 集成**: 直接在 Autopsy 中运行 log2timeline
- **YARA 规则扫描**: 支持自定义 YARA 规则匹配文件
- **Central Repository**: 跨案件关联分析 (相同哈希、相同文件)
- **数据源聚合**: 同时分析多个磁盘镜像/卷
- **VM 分析**: 直接加载 VMDK/VHD/VHDX 文件
- **Android/iOS 备份解析**: iTunes/ADB 备份分析

### 报表增强
- HTML 报表导出改进
- 标记系统 (Tags) 可自定义
- 时间线可视化 (Timeline UI)
```

#### 9.2 Autopsy 命令行与自动化

```bash
# Autopsy 4.x 命令行模式 (多平台)
# Linux:
./autopsy --caseName="Case001" --dataSource="/evidence/disk.dd" --ingestModule="HashLookup,RecentActivity"

# Windows:
autopsy64.exe --caseName="Case001" --dataSource="D:\evidence\disk.dd"

# 批量分析脚本
for img in /evidence/images/*.dd; do
  echo "Analyzing: $img"
  ./autopsy --caseName="$(basename $img .dd)" \
    --dataSource="$img" \
    --outputDir="/evidence/reports/" \
    --ingestModule="HashLookup,RecentActivity,FileType,KeywordSearch"
done

# Python 扩展示例 (Autopsy Ingest Module)
# 放置于 ~/.autopsy/python_modules/ 目录
# 可自定义文件过滤、关键词匹配、IOC 提取等逻辑
```

#### 9.3 Autopsy 与 TSK 配合

```bash
# TSK 4.12+ 新功能
# 支持 APFS 文件系统
fsstat -f apfs -o 0 /evidence/apfs_image.dd

# exFAT 时间戳精确解析
fls -f ext4 -o 2048 -m "C:/" /evidence/image.dd > body_full.txt

# Btrfs 支持
btrfs-debug-tree /evidence/btrfs_image.dd

# 使用 tsk_loaddb 加速 Autopsy 数据库加载
tsk_loaddb /evidence/case_db /evidence/disk_image.dd
```

---

### 10. 文件雕刻恢复 (foremost / PhotoRec / scalpel) — 进阶

#### 10.1 Foremost 进阶用法

```bash
# 从未分配空间和空闲块雕刻
# Step 1: 提取未分配空间
blkls -o 2048 /evidence/image.dd > /evidence/unallocated.raw

# Step 2: 针对未分配空间雕刻
foremost -i /evidence/unallocated.raw -o /evidence/carved_unalloc/

# Step 3: 从空闲块雕刻 (NTFS)
blkls -o 2048 -s /evidence/image.dd > /evidence/slack.raw
foremost -i /evidence/slack.raw -o /evidence/carved_slack/

# 自定义雕刻规则 (foremost.conf) — 2025 更新
cat > /evidence/foremost_custom.conf << 'CONF'
# 现代文件格式签名
webp y 5000000 \x52\x49\x46\x46 \x00\x00\x00\x00
heic y 5000000 \x00\x00\x00\x18\x66\x74\x79\x70\x68\x65\x69\x63
avif y 5000000 \x00\x00\x00\x18\x66\x74\x79\x70\x61\x76\x69\x66
docx y 5000000 \x50\x4B\x03\x04\x14\x00\x06\x00 \x50\x4B\x05\x06
xlsx y 5000000 \x50\x4B\x03\x04\x14\x00\x06\x00 \x50\x4B\x05\x06
onenote y 10000000 \xE4\x52\x5C\x7B\x8C\xD8\xA7\x4D\xAE\xB1\xF6\x79
dockerfile y 500000 FROM
yaml_conf y 200000 ---\n
CONF

foremost -c /evidence/foremost_custom.conf -i /evidence/image.dd -o /evidence/carved_custom/
```

#### 10.2 Scalpel 并行雕刻

```bash
# Scalpel 并发雕刻 (利用多核)
# 编辑 /etc/scalpel/scalpel.conf 启用目标文件类型
scalpel -c /etc/scalpel/scalpel.conf \
  -i /evidence/image.dd \
  -o /evidence/scalpel_out/ \
  -T 4  # 使用 4 线程

# 从特定偏移范围雕刻
dd if=/evidence/image.dd bs=512 skip=1000000 count=5000000 | \
  scalpel -c /etc/scalpel/scalpel.conf -o /evidence/scalpel_range/
```

#### 10.3 PhotoRec 进阶

```bash
# PhotoRec 7.1+ 支持的文件类型 (2025)
# 新增: HEIC/HEIF, AVIF, WebP, DWG 2024, ODF 1.3, APNG

# 按文件类型分组恢复
photorec /d /evidence/photorec_docs/ /cmd /evidence/image.dd \
  partition_none,options,fileopt,doc,enable,pdf,enable,xls,enable,ppt,enable,search

photorec /d /evidence/photorec_media/ /cmd /evidence/image.dd \
  partition_none,options,fileopt,jpg,enable,png,enable,mp4,enable,mov,enable,search

photorec /d /evidence/photorec_archives/ /cmd /evidence/image.dd \
  partition_none,options,fileopt,zip,enable,rar,enable,sevenz,enable,gz,enable,search

# 从 SSD TRIM 后的镜像尝试恢复
# 注意: TRIM 后成功率极低，但文件系统元数据可能残留在 $MFT/日志中
# 方法: 先用 fsstat/fls 分析文件系统结构，定位残留元数据
fls -o 2048 -r -p /evidence/ssd_image.dd | grep "(deleted)" > /evidence/deleted_entries.txt
```

---

### 11. 时间线分析 — 完整流程

#### 11.1 TSK 基础时间线

```bash
# Step 1: 从磁盘镜像提取文件系统元数据
# NTFS
fls -o 2048 -m "C:/" -r /evidence/image.dd > /evidence/body_ntfs.txt

# ext4
fls -o 2048 -m "/" -r -f ext4 /evidence/image.dd > /evidence/body_ext4.txt

# APFS (macOS)
fls -o 0 -m "/" -r -f apfs /evidence/image.dd > /evidence/body_apfs.txt

# Step 2: 使用 mactime 生成 CSV 时间线
mactime -b /evidence/body_ntfs.txt -z UTC > /evidence/timeline_tsk.csv

# Step 3: 过滤关键时间窗口
awk -F',' '$1 >= "2024-06-15T08:00:00" && $1 <= "2024-06-15T18:00:00"' /evidence/timeline_tsk.csv

# Step 4: 检查 MAC 时间异常
# m = modification, a = access, c = creation (MFT), b = birth
grep -E "\.ps1|\.bat|\.exe|\.dll" /evidence/timeline_tsk.csv | \
  awk -F',' '$7 == "m" || $7 == "c"' > /evidence/suspicious_times.csv
```

#### 11.2 Plaso (log2timeline) 超级时间线

```bash
# 完整超级时间线构建
log2timeline.py \
  --storage-file /evidence/case_super.plaso \
  --parsers "winreg,pefile,mft,usnjrnl,winevtx,chrome,firefox,sqlite" \
  /evidence/image.dd

# 查看 Plaso 支持的解析器列表
log2timeline.py --parsers list

# 2025 新增解析器
# - Microsoft Teams chat logs
# - Windows Activity History (ActivitiesCache.db)
# - Windows Search index (Windows.edb)
# - Docker container logs
# - WSL (Windows Subsystem for Linux) 文件系统
# - macOS Unified Log

# 生成 CSV 输出
psort.py -o l2tcsv /evidence/case_super.plaso > /evidence/timeline_super.csv

# 生成 JSON 输出 (供 ELK/Splunk 导入)
psort.py -o json_line /evidence/case_super.plaso > /evidence/timeline_super.json

# 过滤特定时间范围 + 特定来源
psort.py -o l2tcsv /evidence/case_super.plaso \
  "date > '2024-06-15 00:00:00' AND date < '2024-06-16 00:00:00'" \
  > /evidence/timeline_day.csv

# 过滤特定活动类型
psort.py -o l2tcsv /evidence/case_super.plaso \
  "source_short == 'LOG' AND (message CONTAINS 'powershell' OR message CONTAINS 'cmd.exe')" \
  > /evidence/timeline_shell.csv

# 时间线可视化
# 使用 Timesketch (Google 开源时间线分析平台)
timesketch import /evidence/timeline_super.json --name "Case001"
# 浏览器访问 Timesketch UI 进行交互式分析
```

---

### 12. 云磁盘取证

#### 12.1 AWS EBS 取证

```bash
# === AWS EBS 卷取证流程 ===

# Step 1: 对目标 EC2 实例的 EBS 卷创建快照
aws ec2 create-snapshot \
  --volume-id vol-0abcdef1234567890 \
  --description "Forensic: Incident IR-2025-001 $(date +%Y%m%d_%H%M%S)" \
  --tag-specifications "ResourceType=snapshot,Tags=[{Key=Case,Value=IR-2025-001}]" \
  --region us-east-1

# Step 2: 记录快照 ID
# 输出: snap-0xxyyzz...

# Step 3: 在隔离的取证 VPC 中创建卷
aws ec2 create-volume \
  --snapshot-id snap-0xxyyzz \
  --availability-zone us-east-1a \
  --volume-type gp3 \
  --tag-specifications "ResourceType=volume,Tags=[{Key=Forensic,Value=true}]" \
  --region us-east-1

# Step 4: 将卷挂载到取证 EC2 实例
aws ec2 attach-volume \
  --volume-id vol-new \
  --instance-id i-forensic \
  --device /dev/sdf \
  --region us-east-1

# Step 5: 在取证实例上获取镜像
ssh forensic@取证实例
sudo dcfldd if=/dev/xvdf of=/evidence/aws_vol_image.dd hash=sha256 bs=4M

# Step 6: 或者导出快照到 S3 用于异地分析
aws ec2 export-snapshot \
  --snapshot-id snap-0xxyyzz \
  --target-s3-bucket forensic-evidence-bucket \
  --target-format VMDK

# === AWS Lambda 无服务器取证 ===
# 对于 Lambda 函数容器文件系统，使用 /tmp 目录分析
# Lambda 不持久化文件系统，需在运行时获取
```

#### 12.2 Azure 磁盘取证

```bash
# === Azure 托管磁盘取证 ===

# Step 1: 创建磁盘快照
az snapshot create \
  --resource-group RG-Production \
  --name forensic-snap-$(date +%Y%m%d%H%M%S) \
  --source /subscriptions/xxx/resourceGroups/RG-Production/providers/Microsoft.Compute/disks/vm-disk-name \
  --sku Standard_LRS

# Step 2: 从快照创建托管磁盘
az disk create \
  --resource-group RG-Forensics \
  --name forensic-disk-001 \
  --source forensic-snap-xxx \
  --size-gb 128

# Step 3: 将磁盘挂载到取证 VM
az vm disk attach \
  --resource-group RG-Forensics \
  --vm-name forensic-vm \
  --name forensic-disk-001

# Step 4: 在取证 VM 上获取镜像
# SSH 到取证 VM
sudo dcfldd if=/dev/sdb of=/mnt/evidence/azure_disk.dd hash=sha256 bs=4M

# Step 5: 或导出为 VHD
az disk grant-access \
  --resource-group RG-Forensics \
  --name forensic-disk-001 \
  --access-level Read \
  --duration-in-seconds 3600

# 使用 SAS URI 下载 VHD
az storage blob download --uri "<SAS-URI>" --file /evidence/azure_disk.vhd
```

#### 12.3 GCP 持久磁盘取证

```bash
# === GCP Persistent Disk 取证 ===

# Step 1: 创建磁盘快照
gcloud compute disks snapshot disk-name \
  --zone=us-central1-a \
  --snapshot-names=forensic-snap-$(date +%Y%m%d%H%M%S) \
  --description="Forensic: Incident IR-2025-001"

# Step 2: 从快照创建新磁盘
gcloud compute disks create forensic-disk-001 \
  --source-snapshot=forensic-snap-xxx \
  --zone=us-central1-a \
  --type=pd-standard

# Step 3: 将磁盘挂载到取证 VM
gcloud compute instances attach-disk forensic-vm \
  --disk=forensic-disk-001 \
  --zone=us-central1-a

# Step 4: 获取镜像
gcloud compute disks export forensic-disk-001 \
  --destination-uri=gs://forensic-evidence-bucket/disk001.tar.gz \
  --image-format=raw

# 或在取证 VM 内使用 dd
sudo dcfldd if=/dev/sdb of=/mnt/evidence/gcp_disk.dd hash=sha256 bs=4M
```

#### 12.4 云取证通用注意事项

```markdown
## 云磁盘取证注意事项

1. **管辖权与合规**: 确认云区域数据所在司法管辖区，遵守 GDPR/数据本地化法规
2. **快照一致性**: 云快照为崩溃一致性 (crash-consistent)，非应用一致性
3. **日志保存**: 同步获取云操作日志 (CloudTrail / Activity Log / Audit Log)
4. **IAM 权限**: 取证操作需要最小权限原则，记录所有 API 调用
5. **网络隔离**: 取证 VM 必须在隔离 VPC/VNet 中，禁止公网访问
6. **加密磁盘**:
   - AWS: KMS 加密 EBS 需要密钥策略授权
   - Azure: Disk Encryption (BitLocker/DM-Crypt) 需要密钥
   - GCP: CMEK 加密 PD 需要 Cloud KMS 权限
7. **成本控制**: 快照和取证 VM 产生持续费用，完成后及时清理
8. **证据链**: 记录所有 API 调用、快照 ID、时间戳、操作者身份
```

---

### 13. 加密磁盘取证

#### 13.1 BitLocker 取证

```bash
# === Windows BitLocker 加密磁盘 ===

# 方法 1: 从内存转储提取恢复密钥 (需配合内存取证)
# 使用 Volatility 3 的 bitlocker 插件
vol3 -f /evidence/memory.dmp windows.bitlocker.BitLocker

# 方法 2: 从注册表提取密钥信息
# 挂载磁盘镜像后
regripper -r /evidence/image.dd -p bitlocker

# 方法 3: 使用恢复密钥解密
# recovery key 格式: XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX
# 方法 A: dislocker (Linux)
apt install -y dislocker
dislocker -r -V /evidence/bitlocker_image.dd -p XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX -- /evidence/bitlocker_decrypted/

# 挂载解密后的分区
mount -o loop,ro /evidence/bitlocker_decrypted/dislocker-file /mnt/decrypted/

# 方法 B: FTK Imager (Windows)
# File → Add Evidence Item → 勾选 "Decrypt BitLocker" → 输入恢复密钥

# 方法 4: 从 Active Directory 提取恢复密钥 (域环境)
# 使用管理员权限
Get-ADObject -Filter {ObjectClass -eq "msFVE-RecoveryInformation"} -Properties *
# 或
manage-bde -protectors -get C: -Type RecoveryPassword

# 方法 5: 从 TPM 提取 (物理访问)
# 需要在启动状态下从 TPM 读取 Volume Master Key
# 使用 tpm2-tools
tpm2_nvread 0x01000000
```

#### 13.2 LUKS 取证

```bash
# === Linux LUKS (Linux Unified Key Setup) ===

# Step 1: 检查 LUKS 头信息
cryptsetup luksDump /evidence/luks_image.dd
# 记录: Cipher, Key size, UUID, 使用的 key slot

# Step 2: 使用已知密码/密钥文件打开
cryptsetup --type luks open --key-file /evidence/keyfile \
  /evidence/luks_image.dd luks_forensic

# 或交互输入密码
cryptsetup luksOpen /evidence/luks_image.dd luks_forensic

# Step 3: 挂载解密后的映射设备
mount -o ro /dev/mapper/luks_forensic /mnt/luks_decrypted/

# Step 4: 获取解密后的镜像
dcfldd if=/dev/mapper/luks_forensic of=/evidence/luks_decrypted.dd hash=sha256 bs=4M

# Step 5: 分析完成后关闭
cryptsetup luksClose luks_forensic

# LUKS2 新特性 (2025)
# - Argon2id 密钥派生 (替代 PBKDF2)
# - 支持 LUKS2 头部修复
cryptsetup repair --type LUKS2 /evidence/luks2_image.dd
```

#### 13.3 FileVault 取证

```bash
# === macOS FileVault 2 (XTS-AES-128) ===

# 方法 1: 使用恢复密钥
# FileVault 恢复密钥格式: 4组字母数字 (XXXX-XXXX-XXXX-XXXX) 或个人恢复密钥
# 在 macOS 取证工作站上:
diskutil apfs unlockVolume /dev/diskXsY -passphrase XXXX-XXXX-XXXX-XXXX

# 方法 2: 使用 institutional recovery key (.keychain)
# 需要组织部署的 FileVault 恢复密钥
fdesetup usingrecoverykey -key /path/to/recovery_key.plist

# 方法 3: 从内存中提取 FileVault 密钥
# 使用 OSXpmem 或 osxmemcapture 获取内存
# 然后使用 Volatility 3 mac.Bash 或 keychain 分析

# 方法 4: iCloud 恢复密钥 (终端用户设备)
# 用户可通过 Apple ID 重置 FileVault 密码

# 方法 5: 使用第三方工具
# BlackLight (BlackBag Technologies) — 商业取证工具，支持 FileVault 解密
# MacQuisition — 创建解密镜像
```

#### 13.4 加密取证通用策略

```markdown
## 加密磁盘取证决策树

                    ┌─ 有密码/恢复密钥 → 直接解密
                    │
                    ├─ 域环境 (AD) → 从 AD 提取恢复密钥
                    │
    发现加密磁盘 ──┼─ 内存转储可用 → 从内存提取密钥
                    │
                    ├─ TPM 可访问 → 从 TPM 提取密钥
                    │
                    ├─ iCloud/MSA → 通过合法程序请求恢复密钥
                    │
                    └─ 无任何密钥来源 →
                       ├─ 密码暴力破解 (耗时)
                       │  └─ BitLocker: hashcat -m 22100
                       └─ 仅分析未加密分区/元数据

## 密码暴力破解参考
# BitLocker (hashcat)
bitlocker2john /evidence/bitlocker_image.dd > hash.txt
hashcat -m 22100 hash.txt wordlist.txt

# LUKS (john)
luks2john /evidence/luks_image.dd > hash.txt
john --wordlist=wordlist.txt hash.txt
```

---

### 14. 更新 MITRE ATT&CK 映射 (2025)

| Technique ID | 名称 | 阶段 | 取证指标 | 更新说明 |
|-------------|------|------|---------|---------|
| T1070.004 | File Deletion | 防御绕过 | 已删除文件恢复; SSD TRIM 加速删除 | SSD 取证需快速响应 |
| T1070.001 | Clear Windows Event Logs | 防御绕过 | 日志文件分析; 事件日志残留 | |
| T1005 | Data from Local System | 收集 | 文件访问时间线; USN Journal 分析 | |
| T1036 | Masquerading | 防御绕过 | 文件签名 vs 扩展名检测 | |
| T1059 | Command Scripting | 执行 | 脚本文件发现; PowerShell 日志 | |
| T1564 | Hide Artifacts | 防御绕过 | 隐藏文件/ADS 分析; | |
| T1140 | Deobfuscate/Decode Files | 防御绕过 | 编码文件识别 | |
| T1027 | Obfuscated Files | 防御绕过 | 打包/加密文件提取 | |
| T1204 | User Execution | 执行 | 恶意文件时间线 | |
| T1547 | Boot Autostart | 持久化 | 启动项/注册表分析 | |
| **T1564.006** | **NTFS File Attributes** | **防御绕过** | **ADS (Alternate Data Streams) 分析** | 新增 |
| **T1027.005** | **Indicator Removal: Timestomping** | **防御绕过** | **$MFT 时间戳异常; $Standard_Information vs $File_Name** | 新增 |
| **T1002** | **Data Encrypted for Impact** | **影响** | **勒索软件加密特征; 文件熵值分析** | 新增 |
| **T1486** | **Data Encrypted for Impact** | **影响** | **勒索软件文件扩展名; 勒索信发现** | 新增 |
| **T1490** | **Inhibit System Recovery** | **影响** | **VSS 删除痕迹; bcdedit /recoveryenabled 修改** | 新增 |
| **T1561** | **Disk Wipe** | **影响** | **磁盘擦除工具痕迹; S.M.A.R.T. 记录** | 新增 |
| **T1561.001** | **Disk Content Wipe** | **影响** | **全盘零填充/随机填充检测** | 新增 |
| **T1562.001** | **Disable Security Tools** | **防御绕过** | **EDR/AV 卸载记录; 注册表修改** | 新增 |
| **T1127** | **Trusted Developer Utilities** | **执行** | **MSBuild/dotnet 编译痕迹; 临时文件** | 新增 |
| **T1047** | **WMI** | **执行** | **WMI 仓库文件 (objects.data) 分析** | 新增 |
| **T1053** | **Scheduled Task/Job** | **持久化/执行** | **任务计划 XML 文件; at.log/Schtasks 日志** | 新增 |
| **T1070.006** | **Timestomping** | **防御绕过** | **$SI/$FN 时间戳不一致; 精度差异** | 新增 |
| **T1553** | **Subvert Trust Controls** | **防御绕过** | **代码签名验证; 证书文件分析** | 新增 |

---

### 15. 更新速查表 — 2025 工具补充

| 工具 | 功能 | 命令示例 | 备注 |
|------|------|---------|------|
| nvme-cli | NVMe SSD 信息获取 | `nvme smart-log /dev/nvme0` | SSD 取证必备 |
| dislocker | BitLocker 解密 | `dislocker -V image.dd -p KEY -- /mnt/dec` | Linux 平台 |
| cryptsetup | LUKS 解密 | `cryptsetup luksOpen image.dd forensics` | Linux 原生 |
| eraser | 安全擦除检测 | 检查 S.M.A.R.T. 和自由空间熵值 | |
| Plaso 2025+ | 超级时间线 | `log2timeline.py case.plaso image.dd` | 新增多个解析器 |
| Timesketch | 时间线可视化 | `timesketch import timeline.json` | Google 开源 |
| FTK Imager | Windows 取证获取 | 支持 BitLocker 解密 | 免费版可用 |
| diskutil | macOS APFS/FileVault | `diskutil apfs unlockVolume` | macOS 原生 |
| AWS CLI | AWS EBS 快照/卷 | `aws ec2 create-snapshot` | 云取证 |
| az CLI | Azure 磁盘快照 | `az snapshot create` | 云取证 |
| gcloud | GCP PD 快照 | `gcloud compute disks snapshot` | 云取证 |
| Volatility 3 | 内存密钥提取 | `vol3 -f mem.dmp windows.bitlocker` | 加密密钥恢复 |

---

### 16. 关键参考

- SSD TRIM 与数据恢复研究: [阿里云开发者社区](https://developer.aliyun.com/article/1707549)
- SSD 数据恢复方法 (专利 CN112286719B): [Google Patents](https://patents.google.com/patent/CN112286719B/zh)
- SSD 取证格式化 TRIM 恢复技术: [inhdd.com](https://www.inhdd.com/28067638.html)
- Autopsy 官方文档: https://www.sleuthkit.org/autopsy/
- The Sleuth Kit: https://github.com/sleuthkit/sleuthkit
- Plaso / log2timeline: https://github.com/log2timeline/plaso
- Timesketch: https://github.com/google/timesketch

---

## Part D：2025-2026 精细化补充

### 17. SSD TRIM 取证前沿 — DRAT/DZAT 深度分析

#### 17.1 TRIM 后数据读取行为分类

```markdown
## TRIM 后 SSD 数据读取行为 (Elcomsoft 2025-06 研究)

SSD 在收到 TRIM 命令后对已 TRIM LBA 的读取响应取决于两个 ACS-2 特性:

| 特性 | 全称 | 行为 | 取证影响 |
|------|------|------|---------|
| DRAT | Deterministic Read After Trim | 读取 TRIM 后的 LBA 返回确定性值（每次相同），但不一定是零 | 数据可能被控制器"冻结"但不再变化 |
| DZAT | Deterministic Zero After Trim | 读取 TRIM 后的 LBA 始终返回全零 | 数据在逻辑层已不可获取 |

### DRAT/DZAT 组合与取证可行性

| DRAT | DZAT | TRIM 后读取结果 | 取证恢复策略 |
|------|------|----------------|-------------|
| ✗ | ✗ | 非确定性（可能返回旧数据残余） | 标准文件雕刻可能成功 |
| ✓ | ✗ | 确定性但非零值 | 数据已被控制器映射，文件雕刻不可靠 |
| ✓ | ✓ | 确定性返回全零 | 逻辑层数据已丢失，仅芯片级提取可能 |
| ✓ (non-deterministic) | ✓ | 混合行为 | 取决于具体控制器固件实现 |

### 关键发现 (Elcomsoft 2025)
1. 大多数现代 SSD (SATA + NVMe) 同时支持 DRAT 和 DZAT
2. NVMe SSD 通过 Dataset Management 命令实现 TRIM 等效功能 (Deallocate)
3. 部分 SSD 在 DRAT=true 但 DZAT=false 时，可能短暂保留可读取的残余数据
4. 自加密 SSD (SED/OPAL) 即使 TRIM 前数据也已加密，取证需先获取加密密钥
```

#### 17.2 NVMe SSD 取证专项

```bash
# === NVMe SSD 取证增强流程 ===

# 1. NVMe 健康状态与 TRIM 配置检查
nvme smart-log /dev/nvme0
nvme get-feature -f 0x0a /dev/nvme0  # Volatile Write Cache
nvme get-feature -f 0x0d /dev/nvme0  # Number of Queues

# 2. NVMe Namespace 信息（关键：LBA 格式决定扇区大小）
nvme id-ns /dev/nvme0n1
# 注意: 现代 NVMe 支持 4KB 扇区 (LBA Format 0x02) 而非传统 512B
# dd 镜像时 bs=4k 可能更适合

# 3. NVMe Dataset Management (TRIM 等效) 状态
# 检查 NVMe 是否支持 Dealocate (TRIM)
nvme id-ctrl /dev/nvme0 | grep -i "oncs"  # ONCS bit 2 = Dataset Management support

# 4. NVMe 固件版本记录（关键证据链信息）
nvme get-log -i 0x03 /dev/nvme0  # Firmware Slot Information
# 记录: 当前固件版本、固件更新历史

# 5. NVMe 取证镜像优化
# 使用 4K 块大小匹配 NVMe LBA 格式
dc3dd if=/dev/nvme0n1 of=/evidence/nvme_image.dd bs=4k hash=sha256 log=/evidence/nvme_acq.log

# 6. NVMe Temperauture 历史记录（SSD 健康状态证据）
nvme get-log -i 0x05 /dev/nvme0  # SMART/Health Information
nvme get-log -i 0x0d /dev/nvme0  # Temperature Threshold
```

#### 17.3 SSD 数据恢复决策树（2025 更新版）

```markdown
## SSD 数据恢复决策树 v2.0

                    ┌─ DRAT=false, DZAT=false → 标准文件雕刻可能成功
                    │
                    ├─ DRAT=true, DZAT=false → 尝试文件雕刻 + 文件系统元数据分析
                    │
    发现 SSD ───────┼─ DRAT=true, DZAT=true → 仅以下方法可能:
                    │   ├─ 芯片级提取 (PC-3000 SSD / Rusolut VNR)
                    │   ├─ Factory Access Mode (Elcomsoft 方法)
                    │   └─ NAND 直读 (需拆解、仅专业实验室)
                    │
                    ├─ SED/OPAL 自加密 → 先获取密钥:
                    │   ├─ 内存转储提取 (Volatility bitlocker 插件等效)
                    │   ├─ TPM 提取 (物理访问运行中系统)
                    │   ├─ AD 恢复密钥 (BitLocker/企业环境)
                    │   └─ 无密钥 → 不可解密
                    │
                    └─ NVMe Deallocated → 逻辑层返回零
                        └─ 仅芯片级提取可能（且需要控制器特定工具）

## 快速响应黄金法则（SSD 取证）
1. 发现 SSD 后立即断电（非正常关机）→ 阻止 GC 执行
2. 不要通过 USB 适配器获取（部分适配器会发送 TRIM）
3. 使用写保护器（Tableau T35u + NVMe 适配器）
4. 记录 SSD 型号、固件版本、SMART 信息
5. 尽快完成镜像获取
```

来源: [Elcomsoft TRIM DRAT DZAT SSD Forensics (2025-06)](https://blog.elcomsoft.com/2025/06/what-trim-drat-and-dzat-really-mean-for-ssd-forensics/)

---

### 18. Autopsy 4.23.0 — MCP Server + AI 集成

#### 18.1 Autopsy MCP over STDIO Server

```markdown
## Autopsy 4.23.0 重大更新 (2025)

### 核心新特性: MCP Server (Model Context Protocol)

Autopsy 4.23.0 引入了 MCP over STDIO Server，允许取证人员通过 Claude Desktop
或其他 GenAI MCP 客户端以自然语言查询和分析 Autopsy 取证数据。

#### 架构
Autopsy (MCP Server) ← STDIO → Claude Desktop / LM Studio (MCP Client)

#### 功能
- 自然语言查询案件数据（"列出所有在 2025-03-15 创建的 EXE 文件"）
- AI 辅助总结关键发现
- 智能关联跨数据源证据
- 自动生成取证报告摘要

#### 配置 (Windows)
1. 安装 Autopsy 4.23.0+
2. 安装 Claude Desktop
3. 配置 claude_desktop_config.json:
   {
     "mcpServers": {
       "autopsy": {
         "command": "C:\\Program Files\\Autopsy-4.23.0\\bin\\autopsy64.exe",
         "args": ["--mcp"]
       }
     }
   }
4. 打开 Autopsy 案件 → 在 Claude Desktop 中查询

### 其他新特性
- Signed EXE（代码签名增强可信度）
- Extract Thumbnails 模块（Mark McKinnon 贡献）
- PropertySheetEnrichment 扩展点
- Cyber Triage 深度集成（事件响应联动）
- BitLocker 支持（4.22.0 引入，4.23.0 增强）
```

来源: [Autopsy 4.23.0 Release](https://www.autopsy.com/autopsy-4-23-0-release-claude-ai-assistant-mcp-cyber-triage-integration/)

---

### 19. AI/LLM 辅助磁盘取证

#### 19.1 AI 取证研究前沿

```markdown
## AI/LLM 辅助磁盘取证 — 2025-2026 研究前沿

### 学术研究
1. ScienceDirect 系统综述 (2025): 33 篇同行评审论文分析
   - LLM 在数字取证全生命周期应用映射
   - 关键能力: 证据分类自动化、时间线异常检测、日志关联分析
   - 主要挑战: 幻觉问题、证据可采性、链式推理可靠性

2. EAI ICDF2C 2025 最佳论文
   - LLM 辅助数字取证调查
   - 重点关注受损系统分析中的 AI 辅助能力

3. arXiv 2504.02963: 数字取证 LLM 时代综述
   - 分析工作流自动化
   - 证据处理标准化
   - AI 增强但不应完全替代人工判断

4. AutoDFBench (ACM 2025)
   - AI 生成取证代码自动化验证框架
   - 基于 NIST 计算机取证工具测试程序标准
   - 关键价值: 确保自动化工具的取证可靠性

5. LLM 驱动时间线分析 (forensicsandsecurity.com 2025)
   - LLM 解析、关联、分类 Plaso 时间线事件
   - 自动识别异常行为模式
   - 减少人工审查时间 60-80%
```

#### 19.2 商业 AI 取证工具

```markdown
## 商业 AI 取证工具生态 (2025-2026)

| 工具 | AI 能力 | 适用场景 | 定位 |
|------|---------|---------|------|
| Autopsy MCP + Claude | 自然语言查询案件数据 | 桌面/服务器取证 | 开源 + AI 集成 |
| BelkaGPT | 离线 AI 分析助手 | 全源取证 | 商业/离线优先 |
| Magnet AXIOM | Artifact-first + AI 加速 | 多源关联取证 | 商业/企业 |
| Magnet AXIOM Cyber | 远程采集 + AI 分析 | 企业级 IR | 商业/SaaS |
| Cyber Triage | AI 辅助事件分类 | 快速分流 | 商业/IR |

### BelkaGPT 特点
- 离线运行（不发送数据到云端，保护证据安全）
- 集成于 Belkasoft X 全源取证平台
- 支持自然语言查询和自动报告生成
- 符合离线优先 (Offline-First) DFIR 安全要求

### Magnet AXIOM 2025-2026 更新
- Artifact-first 分析方法（按类型而非文件系统组织证据）
- 计算扩展 59% 能力提升（多步网络攻击分析）
- ChatGPT 工件恢复（浏览器 AI 对话历史提取）
- Chromium 更新解析 + 私信应用支持
- 跨源关联（计算机 + 移动 + 云 + 车载）

### 行业趋势
- 2025 年平均入侵停留时间: 241 天 (DFIR 2026 Report)
- AI 使取证分析更快、更便宜、更可重复
- 离线优先 DFIR 防止分析过程中证据污染和数据泄露
```

#### 19.3 LLM 辅助取证脚本示例

```python
#!/usr/bin/env python3
"""
LLM 辅助 Autopsy/TSK 时间线异常检测
- 读取 Plaso CSV 时间线
- 调用 LLM API 进行异常行为模式识别
- 输出可疑事件列表

注意: 此脚本仅用于辅助分析，最终判断需人工确认
"""

import csv
import json
import requests
from datetime import datetime, timedelta

def parse_plaso_csv(csv_path, time_window_hours=24):
    """解析 Plaso 输出的 CSV 时间线，提取指定时间窗口事件"""
    events = []
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append({
                'timestamp': row.get('datetime', ''),
                'source': row.get('source_short', ''),
                'message': row.get('message', ''),
                'parser': row.get('parser', '')
            })
    return events

def detect_anomalous_timeline(events, api_endpoint="http://localhost:11434/api/generate"):
    """
    使用本地 LLM (Ollama) 检测时间线中的异常行为
    输入: 事件列表
    输出: 可疑事件列表 + AI 分析结果
    """
    # 将事件摘要发送给 LLM
    event_summary = "\n".join([
        f"[{e['timestamp']}] {e['source']}: {e['message'][:200]}"
        for e in events[:500]  # 限制 token 数量
    ])

    prompt = f"""Analyze this forensic timeline for suspicious patterns.
Focus on: execution anomalies, privilege escalation indicators, anti-forensics behavior,
unusual file access patterns, and lateral movement indicators.

Timeline events:
{event_summary}

Return JSON with:
- "suspicious_events": list of event indices with reason
- "attack_phase": estimated MITRE ATT&CK phase
- "confidence": 0-100
- "recommendations": list of next investigation steps"""

    try:
        response = requests.post(api_endpoint, json={
            "model": "llama3",
            "prompt": prompt,
            "stream": False
        }, timeout=120)
        return response.json().get('response', '')
    except Exception as e:
        return f"LLM analysis error: {e}"

# 使用示例
# events = parse_plaso_csv('/evidence/timeline_super.csv')
# result = detect_anomalous_timeline(events)
# print(result)
```

---

### 20. 容器/K8s 磁盘取证

#### 20.1 容器文件系统取证

```bash
# === 容器文件系统取证流程 ===

# 1. Docker 容器文件系统提取
# 获取容器 ID
docker ps -a

# 导出容器文件系统为 tar
docker export <container_id> > /evidence/container_fs.tar

# 或使用 docker cp 提取特定文件
docker cp <container_id>:/var/log /evidence/container_logs/

# 提取容器层差异（对比基础镜像）
docker history <image_name> --no-trunc > /evidence/image_history.txt
docker inspect <container_id> > /evidence/container_inspect.json

# 2. K8s Pod 卷取证
# 获取 Pod 信息
kubectl get pods -n <namespace>
kubectl describe pod <pod_name> -n <namespace>

# 对持久卷创建快照（AWS EBS）
kubectl get pv
# 找到对应 EBS 卷 ID 后创建快照
aws ec2 create-snapshot --volume-id vol-xxx --description "K8s PV Forensic"

# 3. 容器运行时取证（CRIU 检查点/恢复）
# 注意: CRIU 可创建运行中容器的检查点
# 对取证而言，这意味着可以冻结容器状态进行分析
kubectl debug <pod_name> -n <namespace> --image=ubuntu --target=<container_name>

# 4. ephemeral 容器临时文件系统
# /tmp 目录内容在容器停止后丢失
# 方法: 在容器运行时通过 kubectl exec 获取
kubectl exec <pod_name> -n <namespace> -- tar cf - /tmp > /evidence/container_tmp.tar
kubectl exec <pod_name> -n <namespace> -- tar cf - /var/log > /evidence/container_varlog.tar

# 5. 从已停止容器恢复数据
# Docker: 即使容器已删除，层可能仍在 /var/lib/docker/overlay2/
sudo ls /var/lib/docker/overlay2/
# 找到对应层目录后直接分析
sudo diff -rq /var/lib/docker/overlay2/<layer_id>/diff/ /evidence/base_image/
```

#### 20.2 K8s 节点磁盘取证

```bash
# === K8s 节点磁盘取证 ===

# 1. 节点隔离（阻止调度新 Pod）
kubectl cordon <node_name>
kubectl drain <node_name> --ignore-daemonsets --delete-emptydir-data

# 2. 关键取证路径
# Kubelet 数据目录
/var/lib/kubelet/           # Pod 配置、卷挂载
/var/lib/kubelet/pods/      # 各 Pod 的卷数据和配置
/var/log/pods/              # Pod 日志
/var/log/containers/        # 容器日志（符号链接）

# 容器运行时数据
/var/lib/docker/            # Docker 数据（overlay2 层、镜像）
/var/lib/containerd/        # containerd 数据
/var/lib/containers/        # CRI-O 数据

# K8s etcd 数据（控制面节点）
/var/lib/etcd/              # etcd 数据目录（集群状态数据库）

# 3. 取证镜像获取
# 方法 A: 节点 SSH 访问
ssh node-user@<node_ip>
sudo dcfldd if=/dev/sda of=/mnt/evidence/k8s_node.dd hash=sha256 bs=4M

# 方法 B: 云快照
# AWS: 对节点 EBS 卷创建快照
aws ec2 create-snapshot --volume-id <node_vol_id> --description "K8s Node Forensic"
```

---

### 21. 反取证技术演进与对抗

```markdown
## 反取证技术演进 (2025-2026)

### 1. 数据销毁增强
| 技术 | 描述 | 取证对抗 |
|------|------|---------|
| SSD TRIM + GC | TRIM 触发后垃圾回收异步清除数据 | 立即断电、芯片级提取 |
| 安全擦除工具 | ATA Secure Erase/NVMe Sanitize | 检查 SMART 计数器、固件操作日志 |
| 加密擦除 | 删除加密密钥而非数据（SED） | 从内存/TPM 获取密钥 |
| 全盘加密 | BitLocker/LUKS/FileVault 全盘加密 | 密钥提取: 内存→TPM→AD→暴力破解 |

### 2. 时间戳篡改 (Timestomping)
- 修改 $Standard_Information 时间戳（用户态可见）
- 保留 $File_Name 时间戳（仅 NTFS 系统态访问）
- **检测方法**: 比较 $SI 和 $FN 时间戳差异
  ```bash
  # 使用 TSK 检测 Timestomping
  # $SI 和 $FN 时间戳不一致表明篡改
  istat -o 2048 /evidence/image.dd <inode_number>
  # 比对 Modified/Accessed/Created 时间差异
  ```

### 3. 数据隐藏
| 技术 | 描述 | 检测方法 |
|------|------|---------|
| ADS (NTFS) | 文件流隐藏数据 | TSK: `icat -o 2048 image.dd <inode>:<stream_name>` |
| Slack Space | 文件末尾未使用空间 | `blkls -s` 提取 slack space |
| Volume Shadow Copy | 隐藏在 VSS 快照中 | `vshadowinfo` + `vshadowmount` |
| Steganography | 嵌入图像/音频文件 | StegDetect/StegExpose/熵值分析 |
| Unallocated Space | 未分配簇中的数据 | `blkls` → foremost/scalpel 雕刻 |

### 4. 日志清除对抗
- Windows 事件日志清除 → 检测 Event ID 1102 (Security 日志清除)
- Linux 日志删除 → 检查 /var/log/ 时间戳异常 + journalctl --verify
- 应用日志清除 → 检查日志轮转配置中的异常修改

### 5. 虚拟化/沙箱检测
- 虚拟机中执行恶意活动后删除虚拟磁盘
- 取证策略: 检查宿主机虚拟化层日志、VM 快照残留
```

---

### 22. 取证工具生态更新 (2025-2026)

| 工具 | 版本 | 新特性 | 适用场景 | 类型 |
|------|------|--------|---------|------|
| Autopsy | 4.23.0 | MCP Server + Claude AI + Signed EXE + Cyber Triage | 磁盘/服务器取证 | 开源 |
| Belkasoft X | 2025+ | BelkaGPT 离线 AI + 全源取证 + 离线优先 | 全源取证 | 商业 |
| Magnet AXIOM | 2025+ | Artifact-first + ChatGPT 工件 + 59% 能力提升 | 多源关联取证 | 商业 |
| Forensic Timeliner | v2.2 | CSV 输出优化 + 多源时间线聚合 | 时间线分析 | 开源 |
| Plaso | 2025+ | 新增 Docker/WSL/macOS Unified Log 解析器 | 超级时间线 | 开源 |
| Timesketch | 2025+ | UI 增强 + LLM 集成实验性支持 | 时间线可视化 | 开源 |
| PC-3000 SSD | 2025+ | SAFE MODE 硬件级 TRIM 绕过 | SSD 芯片级提取 | 商业 |
| Rusolut VNR | 2025+ | NAND 芯片直读和重组 | SSD 芯片级提取 | 商业 |
| FTK Imager | 2025+ | BitLocker 解密增强 | Windows 取证获取 | 免费 |
| Cyber Triage | 2025+ | AI 辅助事件分流 + Autopsy 集成 | 快速 IR 分流 | 商业 |
| bulk_extractor | 2.0+ | 高速特征提取 + 新模式匹配 | 大规模数据扫描 | 开源 |
| Dislocker | 2025+ | BitLocker Linux 解密 | 加密磁盘取证 | 开源 |

### 工具选择决策树

```markdown
## 磁盘取证工具选择决策树

                ┌─ 预算充足 → Magnet AXIOM / Belkasoft X
                │
                ├─ 开源优先 →
                │   ├─ 磁盘分析: Autopsy + TSK
                │   ├─ 时间线: Plaso + Timesketch
                │   └─ 文件雕刻: foremost + PhotoRec
                │
    取证需求 ──┼─ SSD 专用 → PC-3000 SSD / Rusolut VNR
                │
                ├─ AI 辅助 → Autopsy MCP + Claude / BelkaGPT
                │
                ├─ 加密磁盘 →
                │   ├─ BitLocker: dislocker / FTK Imager
                │   ├─ LUKS: cryptsetup
                │   └─ FileVault: diskutil / BlackLight
                │
                ├─ 云环境 →
                │   ├─ AWS: EBS 快照 + CLI
                │   ├─ Azure: 托管磁盘快照 + az CLI
                │   └─ GCP: PD 快照 + gcloud
                │
                └─ 容器/K8s →
                    ├─ docker export + overlay2 层分析
                    └─ kubectl exec + 节点磁盘镜像
```

---

### 23. 2025-2026 综合 CVE 速查（磁盘取证相关）

| CVE | 产品 | CVSS | 描述 | 取证影响 |
|-----|------|------|------|---------|
| CVE-2025-15467 | OpenSSL CMS | Critical | 栈溢出 Pre-Auth RCE | 磁盘加密工具依赖 OpenSSL 的需关注 |
| CVE-2025-68121 | Go crypto/tls | Critical | Config.Clone 泄漏 session ticket key | 云取证 TLS 流量解密能力受影响 |
| CVE-2025-23266 | NVIDIA Container Toolkit | 9.0 | CDI spec LD_PRELOAD 容器逃逸 | 容器取证环境安全风险 |
| CVE-2025-31133 | runc | 7.5 | maskedPaths 竞争逃逸 | 容器取证环境隔离突破 |
| CVE-2025-52881 | runc | 7.0 | procfs 写重定向 | 容器取证环境安全 |

---

### 24. 中文社区精华参考

| 来源 | 标题/描述 | 链接 |
|------|----------|------|
| 奇安信 | 盘古石电子数据综合取证系统（取证战星）— 融合固定、提取、分析 | [qianxin.com](https://www.qianxin.com/product/detail/pid/344) |
| 安全客 | 电子数据取证 — 计算机取证常用镜像工具和专业取证软件 | [anquanke.com](https://www.anquanke.com/post/id/278110) |
| 安全内参 | 全球七大顶尖网络取证工具 | [secrss.com](https://www.secrss.com/articles/247) |
| 知乎 | Linux 硬盘和内存镜像取证 | [zhuanlan.zhihu.com](https://zhuanlan.zhihu.com/p/57972778) |
| GoUpSec | 五个免费的数字取证工具（bulk_extractor 等） | [goupsec.com](https://www.goupsec.com/news/18383.html) |
| 华为云 | NVIDIA Container Toolkit 容器逃逸漏洞 CVE-2025-23266 | [support.huaweicloud.com](https://support.huaweicloud.com/bulletin-cce/CVE-2025-23266.html) |
| 阿里云 AVD | NVIDIA Container Toolkit 高危容器逃逸 | [avd.aliyun.com](https://avd.aliyun.com/detail?id=AVD-2025-23266) |
| FreeBuf | 一文讲述内存取证的数据保存、数据分析、CTF 实战案例 | [freebuf.com](https://m.freebuf.com/articles/network/274353.html) |
| 12309 检察网 | 做实电子数据跨境取证有力惩治涉外网络犯罪 (2025) | [12309.gov.cn](https://login.12309.gov.cn:8443/spp/llyj/202510/t20251031_709908.shtml) |
| 华安 | 2025 年中国电子数据取证行业发展现状及前景展望 | [huaon.com](https://m.huaon.com/channel/trend/1077335.html) |

---

### 25. 防御升级路线图

```markdown
## 磁盘取证能力升级路线图 (P0-P3 分级)

### P0 — 立即行动 (0-30 天)
- [ ] 更新 Autopsy 至 4.23.0 并测试 MCP + Claude 集成
- [ ] 建立 SSD 快速响应流程（断电→写保护→镜像→48h 内完成）
- [ ] 验证 NVMe SSD 取证镜像获取流程
- [ ] 建立加密磁盘解密能力清单（BitLocker/LUKS/FileVault）

### P1 — 短期优化 (1-3 个月)
- [ ] 部署 Plaso 最新版并测试 Docker/WSL/macOS Unified Log 解析器
- [ ] 建立容器/K8s 取证 SOP（docker export + overlay2 层分析）
- [ ] 评估 AI 辅助取证工具（BelkaGPT/Autopsy MCP/Forensic Timeliner）
- [ ] 更新文件雕刻签名库（HEIC/AVIF/WebP/现代文档格式）

### P2 — 中期建设 (3-6 个月)
- [ ] 建立云磁盘取证自动化管线（AWS/Azure/GCP 快照→镜像→分析）
- [ ] 集成 Timesketch 时间线可视化平台
- [ ] 建立反取证检测能力（Timestomping/ADS/Slack Space 自动化检测脚本）
- [ ] 开展 LLM 辅助时间线异常分析 PoC

### P3 — 长期演进 (6-12 个月)
- [ ] 建立企业级磁盘取证平台（Autopsy + Plaso + Timesketch + AI 集成）
- [ ] 制定 SSD 芯片级提取外包流程（与 PC-3000 SSD 实验室合作）
- [ ] 开展 AI 取证代码验证（AutoDFBench 框架）确保自动化可靠性
- [ ] 建立取证人员 AI 辅助分析培训体系
```

---

### 26. 更新关键参考

- Autopsy 4.23.0 Release: https://www.autopsy.com/autopsy-4-23-0-release-claude-ai-assistant-mcp-cyber-triage-integration/
- Elcomsoft TRIM DRAT DZAT (2025-06): https://blog.elcomsoft.com/2025/06/what-trim-drat-and-dzat-really-mean-for-ssd-forensics/
- LLM in Digital Forensics Systematic Review: https://www.sciencedirect.com/science/article/pii/S2666281725001830
- AI Digital Forensics (arXiv): https://arxiv.org/html/2504.02963v1
- AutoDFBench (ACM): https://dl.acm.org/doi/full/10.1145/3712716.3712718
- Belkasoft DFIR Trends 2025: https://belkasoft.com/dfir-trends-2025
- Magnet State of Enterprise DFIR 2026: https://www.magnetforensics.com/resources/state-of-enterprise-dfir-2026-report/
- Belkasoft Top DFIR Software 2026: https://belkasoft.com/top-digital-forensics-software-2026
- Cyber Triage Tool Comparison 2026: https://www.cybertriage.com/blog/computer-forensic-tools-comparison-chart-2026/
- SSD TRIM 与数据恢复研究: https://developer.aliyun.com/article/1707549

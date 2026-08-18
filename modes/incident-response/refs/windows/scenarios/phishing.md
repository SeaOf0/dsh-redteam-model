# 钓鱼事件排查（Windows 侧）

> 正文自写原创，命令与判据自写，来源链接见文末。
> 适用：邮件钓鱼（宏文档/lnk/iso 附件、钓鱼链接）、IM 投递文件。钓鱼是**入口类事件**——本文件管「入口还原+落地链」，后续执行/横向/持久化走通用排查面。

## 1. 排查主线

```
邮件证据固定 → 入口还原（谁点的/何时/什么附件）→ 落地与执行链 → 影响评估 → 通用排查面收尾
```

## 2. 邮件证据固定（先于一切）

- 邮件原件（.eml/.msg）从网关/客户端导出，不要只留截图；登记哈希。
- 头部要点：`Return-Path`（真实退信域）、`Received` 链（经过的服务器与时区时序）、`X-Originating-IP`（发件来源）、`Reply-To` 与 From 不一致（典型钓鱼）。
- 附件/链接 IOC：附件 SHA256、URL 列表、短链展开（被动解析，不主动访问落地页）。

## 3. 入口还原（受害主机侧）

```powershell
# Outlook 下载的附件落点（默认）
Get-ChildItem "$env:USERPROFILE\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook" -Recurse -Force -ErrorAction SilentlyContinue | Select Name,LastWriteTime,Length
Get-ChildItem "$env:USERPROFILE\Downloads" -Force | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-14)} | Select Name,LastWriteTime
# 浏览器下载记录（交叉验证投递渠道）
copy "$env:LOCALAPPDATA%\Google\Chrome\User Data\Default\History" $env:TEMP\h.db
python3 -c "import sqlite3;[print(r) for r in sqlite3.connect(r'$env:TEMP\h.db').execute('select datetime(start_time/1000000-11644473600,\'unixepoch\'),target_path,url from downloads order by start_time desc limit 50')]"
```

- 可疑判据：附件文件在 Content.Outlook/Downloads 出现且时间与邮件投递时间吻合；文档类（docm/xls/lnk/iso/img）哈希与邮件附件一致。

## 4. 落地与执行链（时间窗交叉）

```powershell
# 用户执行痕迹：Prefetch（执行过即留痕，含首次/最近运行）
Get-ChildItem C:\Windows\Prefetch -Filter *.pf | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-14)} | Select Name,LastWriteTime | Sort LastWriteTime
# Amcache：首次执行记录（含 SHA1）
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-AppLocker/EXE and DLL';Id=8003} -MaxEvents 200 -ErrorAction SilentlyContinue
# 宏文档执行链：Office 进程拉起 cmd/powershell（4688，Sysmon 1 更细）
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 5000 |
  Where-Object {$_.Message -match 'WINWORD.EXE|EXCEL.EXE|POWERPNT.EXE' -and $_.Message -match 'cmd.exe|powershell.exe|wscript.exe|mshta.exe|rundll32.exe'} |
  Select TimeCreated,Message -First 20
```

- 可疑判据（时间相关性+行为链）：邮件投递时间 → 附件落盘时间 → Prefetch/Amcache 首次执行时间 → 子进程拉起时间，四点串成链；`WINWORD.EXE → cmd.exe → powershell -enc` 为宏攻击典型链；lnk/iso 附件则看解挂载/解压目录（`mountvol` 挂载痕迹、`C:\Users\*\AppData\Local\Temp` 下解包目录）。
- 钓鱼链接入口：浏览器历史里失陷窗内访问钓鱼 URL（配合 DNS 缓存 `ipconfig /displaydns` 找解析记录）。

## 5. 影响评估与收尾

- 凭据暴露面：该用户是否在钓鱼页提交了口令（询问+浏览器表单历史）；邮箱自身是否被用作二次投递（发件箱/OWA 发送记录）。
- 后续链：入口确定后，恶意样本按 `../malware/trojan-virus.md` 排查、持久化按 `../persistence/persistence-points.md` 全表过、横向按 `../logs/windows-eventid-detection.md` Type 3/10 还原。
- 证据登记：邮件原件、附件哈希、四点时间链、后续链发现全部进 evidence-index。

## 来源

- https://book.noptrace.com/
- MITRE ATT&CK T1566（Phishing）：https://attack.mitre.com/techniques/T1566/

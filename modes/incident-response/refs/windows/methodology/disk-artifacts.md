# Windows 盘面取证 artifacts（文件系统/注册表/浏览器）

> 数字取证线的深度手册：每项 artifact 给出 内容 / 取证值 / 采集与解析方式。
> 纪律：镜像优先、只读次之、逐项哈希、时区与时钟漂移先记录再比对。

## 优先序总表

| 优先 | Artifact | 位置 | 回答什么问题 | 工具 |
|---|---|---|---|---|
| 1 | `$MFT` | `C:$MFT`（NTFS 隐藏元文件） | 每个文件的创建/修改/MFT 修改/访问四时间；**删除后记录仍存**——追已删文件与落地时间 | MFTECmd（KAPE 组件）、分析器 python |
| 2 | `$UsnJrnl` | `C:$Extend\$UsnJrnl:$J` | 细粒度变更流（创建/删除/重命名/覆盖），补 MFT 粒度 | MFTECmd / python 解析记录结构 |
| 3 | Prefetch | `C:\Windows\Prefetch\*.pf` | 程序执行史：最后运行时间/运行次数/加载的 DLL 列表（注意新系统仅部分场景生成） | PECmd（KAPE） |
| 4 | Amcache | `C:\Windows\appcompat\Programs\Amcache.hve` | 首次执行与安装的程序清单（含 SHA1） | RegRipper 类/KAPE AmcacheParser |
| 5 | Shimcache | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | EXE/DLL 执行痕迹（顺序有时间语义、时间字段弱） | KAPE AppCompatCacheParser |
| 6 | Lnk / JumpLists | `用户目录\AppData\Roaming\Microsoft\Windows\Recent\` | 打开过的文件/远程共享/频率与最近时间 | LECmd（KAPE）/ python 解析 LNK 结构 |
| 7 | Shellbags | `NTUSER.DAT` 的 UsrClassDat | 浏览过哪些目录（含已删目录与 ZIP 内浏览） | KAPE/SBECmd |
| 8 | 注册表用户痕迹 | NTUSER.dat：RunMRU / TypedPaths / UserAssist（程序使用计数） | 用户行为面：输过什么/访问路径/常用程序 | RegRipper / python reg 解析 |
| 9 | 浏览器 | `AppData\Local\...\User Data\Default\History`（Chromium SQLite） | 浏览/下载记录、表单 | sqlite 只读查询 |
| 10 | 系统 hive | SYSTEM/SAM/SOFTWARE | 系统信息/账户/时区/网络配置（环境还原） | 各解析器 |

## 时间语义四时间（MFT）

- SI（标准信息：创建/修改/访问/记录变更）与 FNI（文件名记录时间）**不一致即反取证信号**
  （timestomp 通常只改 SI 不改 FNI）——两者偏差本身入证据。
- 反逝时间检查：$StandardInformation 与 $FileName 的时间差、以及 `nanosecond` 尾数异常
  （整秒倍数+全零尾数常见于工具伪造）。

## 采集与解析纪律

1. **镜像优先**：dd/E01 全盘镜像，哈希链登记（evidence-index 父-子血缘）；
2. **无法镜像**：至少只读挂载（Windows 侧写阻断/FTK Imager 类只读预览），逐 artifact
   提取后即时哈希；
3. **时间基准**：记录目标机时区与时钟漂移（SYSTEM hive 与网络时间源对照），归并进
   attack-timeline 前统一；
4. **解析产物**：CSV/JSON 落 `artifacts/<hash>/`，时间线行引用来源 artifact 名。

## 与其他线互证

- 执行史（Prefetch/Amcache）× 内存线（进程态）× 日志（4688 进程创建）三方对照；
- 删除史（$UsnJrnl/$MFT）对应日志 1102 清审计/清除类事件——只删文件不清日志=半吊子
  清痕，交叉点即突破；
- 浏览史（Shellbags/浏览器）对应失陷定性中的"人为操作 vs 自动化行为"判读。

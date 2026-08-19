# 免杀实验实现集（lab/）

> 按本地攻防实验循环使用：每个实现 = 源码 + 构建命令 + **技术↔检测侧配对表**（NOTES.md）。
> 纪律照 av-playbook：本地默认验证环境（V1 实验计划三声明先行）；判定结论引用引擎原文行
> + 哈希对照；结论范围 ≤ 已测环境（V4）；投递授权目标走作战循环与操作痕迹台账。

## 实现清单

| # | 实现 | 对抗面 | 依赖 |
|---|---|---|---|
| 01 | 直接系统调用（SSN 动态解析 stub） | 用户态 hook（ntdll inline） | mingw |
| 02 | patchless AMSI（上下文破坏） | AMSI 内容扫描 | PowerShell/.NET |
| 03 | ETW 压制（EtwEventWrite 补丁） | ETW 遥测 | mingw |
| 04 | ntdll 磁盘重映射去 hook | 用户态 hook 恢复 | mingw |
| 05 | 加密载荷加载器（分层解密+RW→RX） | 静态特征/内存扫描（骨架含睡眠加密位） | mingw+python3 |
| 06 | 硬件断点拦截（VEH+Dr 寄存器） | AMSI/ETW（不改代码字节） | mingw |
| 07 | 各语言 webshell（PHP 加密通讯/JSP 字节码马/ASPX 反射马） | 语义与静态引擎 | php/java/.NET 容器 |
| 08 | 内存马四型（Tomcat Filter/Spring Controller/Java Agent attach/ASPX Module） | 无文件驻留 | 对应中间件 |
| 09 | C2 流量行为定制（malleable profile 四件套） | NDR/WAF 流量侧 | — |
| 10 | 通用连接器生态魔改（冰蝎密钥协商改造/哥斯拉协议骨架/蚁剑自定义编码器/菜刀基线/客户端三路线） | 流量设备+D盾+操作机 EDR | php/node/容器 |

## 构建

`./build.sh [编号]`（默认全部；产物落 build/<编号>/，哈希自动登记 build/manifest.txt）。

## 判定与配对

每实现跑本地引擎族矩阵（Defender 最新定义+商业 EDR 模拟），结果按环境逐个登记进该实现
NOTES.md 判定表；检测侧视角（对应遥测/规则初稿）同表配对——缺一侧按 V3 不完整处理。

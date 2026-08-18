# packer 技能（shellcode 免杀加载器打包）

> 本目录随 av-evasion 预设打包分发。
> 定位：把 .bin shellcode 打包成免杀 Windows 可执行文件的工程技能——注入技术/SyscallN 参数表、
> 防御模块、加解密、随机化、Go stager、QVM 专项绕过（UUID 编码 + Fiber + IAT 欺骗 + Overlay 注水）。

## 目录

| 文件 | 内容 |
|---|---|
| `SKILL.md` | 主流程与关键约束（先读；完整阅读路径见 references/overview.md） |
| `references/layout.md` | 目录职责约定 |
| `references/techniques.md` | 注入技术与 SyscallN 参数表 |
| `references/defense-modules.md` | 防御模块实现模式 |
| `references/encryption.md` | 加解密逻辑参考 |
| `references/randomization.md` | 随机化规范 |
| `references/gostager.md` | Go stager 详细流程（CS stager 解析 → HTTP 下载 beacon + 反射加载） |
| `references/qvm-bypass.md` | QVM 专项绕过（UUID 编码/Fiber/IAT 欺骗/Overlay 注水/PE 修复） |
| `references/verification.md` | 编译前/编译后验证 |
| `references/troubleshooting.md` | 排障 |
| `scripts/` | 构建辅助脚本（build_qvm.py / parse_stager.py / verify_pre.py / verify_pe.py / encrypt.go / encrypt_ipv4.go，共 44K） |
| `assets/versioninfo.json` | 静态资源模板 |

## 工具边界（源包未随附项）

- **`tools/sgn.exe`、`tools/keystone.dll`**（8.7M，Windows 二进制）**不随预设分发**：
  - Windows 环境：从源技能包复制到本目录 `tools/` 即可按 SKILL.md 使用；
  - 其他平台：sgn/keystone 无原生替代时按三级兜底（MCP/安装请求）或走 SKILL.md 的
    等价实现路径，如实标注验证环境。
- 脚本依赖：python3（build_qvm.py/parse_stager.py/verify_*.py）与 go（encrypt*.go），
  开工先按工具平面检测制 `command -v` 探测并登记。

## 合规与使用

- 与 av-evasion persona 一致：本地默认验证环境，授权目标按任务执行；每项技术必须配
  检测侧视角（OPSEC 情报）；产物哈希登记 + 判定日志三件套（Gate V3）。
- 本目录随预设打包分发。

## 工具版本基线（源包 tools/ 元数据）

| 工具 | 版本 | 来源 | 说明 |
|------|------|------|------|
| sgn.exe | v2.0.1 | https://github.com/EgeBalci/sgn | SGN 多态编码器（Windows 环境从源包复制或自行构建） |
| keystone.dll | — | 随 sgn 发布 | SGN 依赖的汇编引擎 |

二进制不随预设分发；上述版本为源包验证过的基线——目标机自备时按此版本核对。

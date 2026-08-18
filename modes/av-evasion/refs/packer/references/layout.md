# 目录职责约定

本目录采用分层组织，避免将实现细节全部堆在 `SKILL.md`。

## 目录分工

- `tools/`：外部二进制工具与运行时依赖。
  - 当前：`sgn.exe`、`keystone.dll`
  - 约定：二进制文件放 `tools/`，不要放 `scripts/`。
- `scripts/`：可执行辅助脚本（可读源码）。
  - 当前：`encrypt.go`、`encrypt_ipv4.go`、`parse_stager.py`、`build_qvm.py`、`verify_pre.py`、`verify_pe.py`
- `references/`：说明性文档、流程细节、排障手册。
- `assets/`：静态资源模板。
  - 当前：`versioninfo.json`

## 为什么 `sgn.exe` 放 `tools/`

`sgn.exe` 属于第三方可执行二进制，不是本 skill 的源码脚本。放在 `tools/` 更利于：
- 与 `scripts/` 的源码职责分离
- 版本/来源/替换管理
- 降低文档阅读时的认知负担

## 维护规则

1. `SKILL.md` 只保留入口流程与导航。
2. 长脚本、长排障、长说明下沉到 `references/`。
3. 新增工具时，二进制放 `tools/`，源码脚本放 `scripts/`。
4. 文档命令统一使用 `<python命令>` 占位，由环境检查决定 `python3` 或 `python`。
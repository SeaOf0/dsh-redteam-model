# android-reverse

framework-first 的 Android 应用逆向技能仓库。把授权 Android 应用逆向任务沉淀为可执行协议、task-local、topic registry 与 QA 回归。

## 文档职责

| 文件 | 角色 |
|---|---|
| `SKILL.md` | 模型运行入口；边界、首读顺序、阶段协议、专题要求与交付契约 |
| `PROMPTS.md` | 提示词模板库；可复制模板与拼装片段 |
| `README.md` | 本文件；仓库结构、开发命令与维护入口 |

执行细节以 `SKILL.md` 与 `docs/reference/*.md` 为准。

## 仓库结构

```
SKILL.md                  # 技能入口
PROMPTS.md                # 模板库
commands/                 # 斜杠命令 (/decompile)
docs/reference/           # 正式规则、协议、矩阵与验收
references/               # 按需加载的 playbook / 模板 / 输入样例
topics/                   # registry-backed topic 定义
scripts/cases/            # 抽象 case/workflow
scripts/*.sh, *.ps1       # 自动化脚本 (check-deps, decompile, find-api-calls, install-dep)
artifacts/tasks/_TEMPLATE/# task-local 模板
tools/                    # task / topic / qa 工具
agents/openai.yaml        # OpenAI 兼容 agent 接口
```

覆盖口径与专题清单见 `docs/reference/capability-matrix.md`。

## 常用命令

```powershell
# 依赖与环境
bash scripts/check-deps.sh              # 检查工具链
bash scripts/install-dep.sh jadx        # 安装单个依赖
bash scripts/decompile.sh target.apk -o output/ --deobf  # 反编译
bash scripts/find-api-calls.sh output/sources/ --all      # 搜索 API 端点

# QA 与发布
npm run check      # 结构、契约、topic 静态检查
npm run smoke      # 临时 workspace 演练 smoke 场景
npm test           # check + smoke

# task-local 生命周期
node tools/task/task-init.mjs <task-id> --task-input=<input.json>
node tools/task/task-migrate.mjs <task-id> --to=2 --dry-run
node tools/task/task-sync.mjs <task-id>
node tools/task/task-advance.mjs <task-id>
node tools/task/task-verify.mjs <task-id>
node tools/task/task-baseline.mjs <task-id> --source=<original.apk> --resigned=<noop.apk> --evidence=<refs> --signature-verified --installed --launched
node tools/task/task-close.mjs <task-id>
```

Windows 用户将 `bash scripts/*.sh` 替换为 `powershell -File scripts/*.ps1`，参数名用 `-Output` / `-Deobf` / `-All`。

## 专题成熟度

<!-- BEGIN GENERATED: topic-maturity-summary -->
- `synthetic-e2e` (`8`): `crypto-protocol`, `dex-loader`, `framework-runtime`, `jni-bridge`, `protection-bypass`, `runtime-hooking`, `split-delivery`, `static-triage`
- `guided` (`10`): `ctf`, `deobfuscation`, `device-fingerprint`, `hook-injection`, `kernel-assisted-re`, `so-runtime-evidence`, `stealth-hook`, `trace-analysis`, `unidbg-simulation`, `vmp-analysis`
- `closed-loop` (`9`): `anti-emulator-debug`, `art-runtime`, `call-flow`, `java-api`, `native-network`, `native-so`, `smali-patching`, `storage-ipc`, `webview-hybrid`
- `reference-only` (`0`): none published yet
<!-- END GENERATED: topic-maturity-summary -->

maturity 代表仓库级 task model、formal validation 与 topic pack 保证级别，不直接等价于真实样本实战回归完备度。

## 维护入口

- 运行协议：`SKILL.md`
- 模板库：`PROMPTS.md`
- task 生命周期：`tools/task/*.mjs`
- QA 检查：`tools/qa/*.mjs`
- topic 定义：`topics/*/topic.json`

# Repo Conventions

## 目录职责

- `docs/reference/`: 正式规则与评估口径
- `references/`: 任务执行时按需补读的专项参考
- `scripts/cases/`: 抽象 case
- `artifacts/tasks/_TEMPLATE/`: task-local 模板
- `tools/qa/`: 仓库级检查脚本

## 命名规则

- 文档用 `kebab-case`
- case 用 `android-<topic>-workflow.mjs`
- task-local 产物优先用语义化命名

## 内容规则

- 正式规则写在 `docs/reference`
- 任务方法写在 `references`
- 不把真实目标样本写入公开层


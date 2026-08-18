# dsh-product-subagents

DSH 宿主平面插件：为七个安全预设的 `tool-subagent` 产品行（`provider: claude-code` /
`provider: codex`，工具名 `subagent_claude_code` / `subagent_codex`）补上缺失的 provider。
官方宿主只注册 `spawn`/`fork`；`dsh-tool-subagent` 在 provider 缺失时不注册工具、不报错
（静默降级），本插件注册这两个名字后，`provider-added` 事件让各预设的工具行自动挂上——
**预设一行都不用改**。

## 机制

- 每个 provider 无头 spawn 本机 CLI：claude 走 `-p`（prompt 经 stdin、答案在 stdout）；
  codex 走 `exec --skip-git-repo-check --sandbox <mode> -C <cwd> -o <tmpfile>`（最终消息从
  `-o` 文件取，stdin 传指令）。
- 模型后端完全归 CLI 自己的配置（`~/.claude/settings.json` 的 env 段、`~/.codex/config.toml`
  供应商）——本插件不碰任何密钥；DeepSeek API 等 Anthropic/OpenAI 兼容后端由 CLI 配置接入。
- run 契约映射：exit 0 → `completed`（stdout/-o 为最终文本）；abort/dispose → `aborted`；
  超时/非零退出/spawn 失败 → `error`（附 stderr 尾部）；超时默认 600s，SIGTERM 后 5s 补 SIGKILL。
- **错误指路（v0.1.1）**：error 输出末尾附 provider 感知的兜底链指引（claude 失败→
  subagent_codex→DSH 原生；codex 失败→DSH 原生）+「报告须注明实际复核方式」——降级
  显式可见。**刻意不实现**插件内静默回退到 dsh LLM：会无形摧毁跨 harness 双签独立性
  
- capabilities 全空：CLI 子代理无法强制 outputSchema/depthLimit/toolFilter/persona，请求带
  这些能力会被注册表在上游明确拒绝（UNSUPPORTED_CAPABILITY），不静默忽略。

## 配置（cordis.patch.yml 行）

```yaml
claudeCode: { bin: claude, timeoutMs: 600000, extraArgs: [], env: {} }
codex:      { bin: codex, sandbox: workspace-write, timeoutMs: 600000, extraArgs: [], env: {} }
```

`env` 会合并覆盖到 `process.env` 之上（可选；密钥仍应留在 CLI 自己的配置里）。

## 验证

- `node test/run.mjs` — 23 项离线单测（FakeChild，不联网）
- `node test/smoke.mjs` — 真 CLI 冒烟（各发一条 "reply ok"
  claude-code 15s / codex 48s 双 completed）
- `node ../../../.zcode/chain-probe.mjs` — 五预设作用域工具面应出现两个产品工具

## 安装

web profile `package.json`：dependencies 加 `@dsh-external/dsh-product-subagents` 的
link + `dsh.profile.bundles` 追加同名 bundle，`pnpm install`，**重启 dsh web 生效**。

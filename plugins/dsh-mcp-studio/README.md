# dsh-mcp-studio

> DeepSeek Harness (dsh) 的 MCP 服务器工作台 —— 实时挂载、真实连接状态、工具预览、一键导入，全部在一个设置页里完成，保存即生效，无需重启。

A one-page MCP server studio for DeepSeek Harness (dsh): live-mount servers, real connection state straight from the tool registry, per-server tool preview, JSON one-click import — every save applies immediately, no restart ever needed.

---

## 功能亮点 / Features

| 能力 | 说明 |
|---|---|
| **实时挂载** | 每个启用的服务器由内置 `@deepseek-ai/dsh-mcp-client` 桥接挂载，模型以 `mcp__<名称>__<工具>` 直接调用；编辑即热切换，禁用/删除即卸载 |
| **真实状态** | 状态直接聚合 dsh 工具注册表（`ctx.tools.view()`），已连接/启动中/未连接/失败（含错误详情）/已禁用，连接中带脉冲呼吸灯 |
| **工具预览浮层** | 点“N 个工具”徽章弹出独立浮层：服务器名、工具总数、全部工具名与简介，支持即时筛选；浮层自动适配视口（上下翻转/钳制/压缩高度，滚动跟随） |
| **工具调用监控** | 订阅会话事件流，记录每次调用的服务器/工具/耗时/成败；内存环形缓冲 200 条（容量明示 N/200）、20 条/页翻页、按服务器筛选、两步确认一键清空、重启即清零 |
| **连接诊断** | 一键发起独立完整 MCP 握手（stdio 临时子进程 / streamable-http 直连），展示握手耗时、协商协议版本、服务器信息、工具数 |
| **JSON 一键导入** | 兼容 Claude Desktop（`{"mcpServers":…}`）、VS Code（`{"servers":…}`）、Cline/Roo（含 `disabled`）、裸映射、无包装单对象、多层包装；自动识别 stdio/http、env/headers、重名加后缀 |
| **模板库** | 内置 9 个常用服务器预设芯片：Everything / Filesystem / Fetch / Memory / Seq Thinking / Puppeteer / GitHub / **Chrome DevTools** / HTTP 示例 |
| **配置导出** | 当前全部配置或单台服务器一键复制为 `mcpServers` JSON，与导入构成闭环 |
| **排序与筛选** | 卡片拖拽排序（保存持久化）、按名称/命令/URL 搜索、四态状态筛选、紧凑/舒适密度切换 |
| **设计** | 全程 `--dsw-alias-*` 主题令牌（明暗皮肤自适应），层级靠字号/间距/状态色表达，零 emoji 零图标装饰 |

## 快速开始 / Quick Start

要求：dsh ≥ 0.1.0-rc.6（`dsh plugin` 自动登记 bundles 行为）、Node ^22.19 或 ≥24。

```bash
# 方式一：GitHub（本仓库）
npx @deepseek-ai/dsh plugin --profile web add github:SeaOf0/dsh-mcp-studio

# 方式二：npm（发布后）
npx @deepseek-ai/dsh plugin --profile web add dsh-mcp-studio

# 方式三：本地路径 / 内网
npx @deepseek-ai/dsh plugin --profile web add link:/path/to/dsh-mcp-studio
```

装完重启 `dsh web`，设置对话框出现 **MCP 工作台**（位于侧边卡片之下）。卸载同样一条命令：

```bash
npx @deepseek-ai/dsh plugin --profile web remove dsh-mcp-studio
```

## 使用 / Usage

- **添加服务器**：点“添加服务器”手动配置，或“粘贴 JSON”导入现成配置（抽屉自带模板与格式化按钮，也可点预设芯片一键填入）
- **对话调用**：直接对模型说“用 github 服务器查一下 xxx 仓库”，模型自动调用 `mcp__github__*` 工具
- **看状态**：统计条实时显示服务器/已启用/已连接/工具总数；卡片状态灯绿色呼吸 = 已连接
- **查工具**：点“N 个工具”徽章弹浮层；“测试连接”跑一次独立握手看协议版本与耗时

配置持久化在 `~/.dsh/settings.yaml` 的 `mcp-studio` 段。

## 架构 / Architecture

```
src/
├── index.ts          # 宿主插件：settings namespace、挂载引擎（签名 diff 热切换）、
│                     # session/event 工具调用监控（环形缓冲 + inflight TTL 清扫）
├── types.ts          # schema、跨字段校验、mcp-client 配置投影、参数行切分
├── settings-rpc.ts   # loopback 通道：status / settings / diagnose / executions-clear
├── diagnose.ts       # 独立 MCP 握手（stdio 子进程 / HTTP 含 SSE 解析）
└── client/
    ├── McpStudioPage.tsx  # 统计条、筛选栏、拖拽排序、JSON 抽屉、执行记录表
    ├── ServerCard.tsx     # 状态灯卡片、工具预览浮层（视口自适应）、诊断面板
    ├── mcp-json.ts        # 全格式解析器 + 导出器（往返保真）
    ├── presets.ts         # 9 个内置模板
    └── styles.ts          # 设计系统（--dsw-alias-* 令牌）
```

## 开发 / Development

```bash
pnpm install --config.minimum-release-age=0 --config.auto-install-peers=false
pnpm check   # typecheck + 15 个单测 + 构建（Host ESM bundle + Web client CJS bundle）
```

宿主 bundle 已 external 化全部 `@deepseek-ai/*` 依赖，运行时从 `~/.dsh/profiles/node_modules`（dsh CLI 维护的宿主包仓库）解析，用户机器无需额外安装；`lib/` 随仓库提交，git 安装零构建、不触发 pnpm 构建白名单。

## License

MIT

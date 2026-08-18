# 微信小程序安全评估流水线

> 一套完整的微信小程序（PC 端）安全评估工具链。  
> 偏移自动提取 → Frida 注入 → CDP 代理 → MCP 工具链 → AI 渗透测试

---

## 架构

```
┌─────────────────────────────────────────────────────────────────┐
│  偏移提取工具 (Python)                                           │
│  文件：偏移提取工具/extract_wmpf_offsets.py                       │
│  依赖：pip install pefile capstone                              │
│  用途：从 flue.dll 自动提取 Frida 偏移量                          │
└──────────────────────┬──────────────────────────────────────────┘
                       │ 生成 addresses.{version}.json
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│  WMPFDebugger (Node.js) — Frida-only 模式                       │
│  文件：WMPFDebugger/src/index.ts（已修改）                       │
│  依赖：npm install && npm install frida@16.6.6                  │
│  用途：只做 Frida 注入，不开 debug/proxy server                   │
│  配置：WMPFDebugger/frida/config/addresses.{version}.json        │
└──────────────────────┬──────────────────────────────────────────┘
                       │ Frida 注入（修改 CDP 过滤器和场景号）
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│  e0e1-wx 引擎 (Python)                                          │
│  文件：e0e1-wx/start_engine.py（手动启动）                       │
│         e0e1-wx/package/devtools/engine.py（已修改）              │
│  用途：启动 debug server (9421) + proxy server (62000)           │
│  注意：engine.py 已跳过 Frida 注入，只保留服务器功能               │
└──────────────────────┬──────────────────────────────────────────┘
                       │ CDP 协议 (ws://127.0.0.1:62000)
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│  e0e1-wx MCP Server (Python)                                    │
│  端口：49999                                                    │
│  用途：通过 MCP 工具连接 CDP，提供安全分析接口                     │
└──────────────────────┬──────────────────────────────────────────┘
                       │ MCP 协议 (Streamable HTTP)
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│  Claude Code / AI Agent                                        │
│  用途：通过 MCP 工具链自动执行渗透测试                             │
└─────────────────────────────────────────────────────────────────┘
```

---

## 目录结构

```
├── 偏移提取工具/                          # 独立工具，可直接使用
│   ├── extract_wmpf_offsets.py          # Windows 偏移提取脚本
│   ├── extract_macos_offsets.py         # macOS 偏移提取脚本
│   ├── SKILL.md                         # IDA 人工分析引导
│   ├── reference.md                     # Windows 参考文档
│   ├── reference-macos.md               # macOS 参考文档
│   ├── requirements.txt                 # pefile + capstone
│   └── examples/                        # 示例配置
│
├── WMPFDebugger/                         # 原始项目 + 修改
│   ├── src/index.ts                     # [已修改] Frida-only 模式
│   ├── src/cli.ts / logger.ts
│   ├── src/third-party/                 # 微信协议文件
│   ├── frida/hook.js                    # Frida Hook 脚本
│   ├── frida/config/                    # 38 个版本偏移配置
│   ├── 一键启动.bat                      # 启动 WMPFDebugger (Frida)
│   ├── auto-extract.bat                 # 一键提取偏移
│   ├── package.json / tsconfig.json
│   └── README.md / README.zh.md
│
├── e0e1-wx/                              # 原始项目 + 修改
│   ├── package/devtools/engine.py        # [已修改] 跳过 Frida
│   ├── start_engine.py                   # [新增] 手动启动引擎
│   ├── main.py / requirements.txt
│   ├── tools/config/win/                # 38 个版本偏移配置
│   └── README.md / SKILL.md
│
└── README.md                             # 本文件
```

---

## 前置条件

| 项目 | 要求 | 说明 |
|------|------|------|
| 操作系统 | Windows 10/11 | 仅支持 Windows |
| 微信 PC 版 | 4.x 以上 | 自动安装 WMPF |
| Python | 3.10+ | 推荐 3.12 |
| Node.js | **20 LTS** | frida@16.6.6 需要 Node.js v20 |
| 内存 | 至少 16GB | 分析 flue.dll 需要大量内存 |

---

## 安装

### 1. 偏移提取工具

```bash
cd 偏移提取工具
pip install -r requirements.txt
```

验证：
```bash
python extract_wmpf_offsets.py --version 25297
```

### 2. WMPFDebugger

```bash
cd WMPFDebugger
npm install
npm install frida@16.6.6    # 必须锁 v16.6.6，否则 ESM 不兼容！
npm install -g ts-node       # 全局安装 ts-node
```

> **重要：** frida 的二进制文件与 Node.js 版本强绑定。  
> 如果你使用 Node.js v20，frida@16.6.6 会自动下载对应的二进制。  
> 如果你使用 Node.js v22+，frida 会报 `NODE_MODULE_VERSION` 错误。  
> 解决方案：降级到 Node.js 20 LTS，或使用 `nvm` 管理版本。

验证：
```bash
node -e "const f = require('frida'); console.log('frida OK:', typeof f.getLocalDevice)"
# 输出: frida OK: function
```

### 3. e0e1-wx

```bash
cd e0e1-wx
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

---

## 启动流程（关键！顺序不能错）

### 完整启动顺序

```
第 1 步：启动 WMPFDebugger（Frida 注入）
         双击 WMPFDebugger/一键启动.bat
         或: cd WMPFDebugger && node -r ts-node/register src/index.ts
         等待出现: [frida] script loaded, WMPF version: xxx

第 2 步：启动 e0e1-wx 引擎（debug server + proxy server）
         打开新终端，cd e0e1-wx
         运行: python start_engine.py
         等待出现: [OK] debug server (9421) + proxy server (62000) started

第 3 步：打开微信小程序
         在微信中点击打开一个小程序（不是拖拽）
         小程序会自动连接到 debug server (9421)

第 4 步：启动 e0e1-wx GUI（MCP Server）
         在 e0e1-wx 目录运行: python main.py
         MCP Server 在 49999 端口自动启动

第 5 步：连接 Claude Code
         注册 MCP: claude mcp add wxcdp --transport http http://127.0.0.1:49999/mcp
         开始渗透测试
```

### 启动顺序图

```
时间线 →
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ WMPFDebugger │    │ e0e1-wx 引擎 │    │ 打开小程序   │    │ e0e1-wx GUI  │
│ (Frida 注入) │ →  │ (9421+62000) │ →  │ (连 9421)    │ →  │ (MCP 49999)  │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

> **重要：** 如果顺序搞反了（先开小程序再启动引擎），小程序不会自动连接 debug server。  
> 此时需要关掉小程序重新打开，或者重启微信。

---

## 微信更新后的操作

```
第 1 步：双击 WMPFDebugger/auto-extract.bat
         （自动检测最新 flue.dll，提取偏移，写入 config 目录）
         或手动:
         python 偏移提取工具/extract_wmpf_offsets.py --version 新版本号

第 2 步：按上面的启动流程重新启动
```

---

## 端口一览

| 端口 | 用途 | 由谁启动 | 必须先启动 |
|------|------|---------|-----------|
| 9421 | debug server（小程序连接） | `start_engine.py` | WMPFDebugger |
| 62000 | CDP 代理（DevTools 连接） | `start_engine.py` | WMPFDebugger |
| 49999 | MCP Server（AI 工具链） | `python main.py` | 引擎 + 小程序 |

---

## 修改说明

### WMPFDebugger 修改内容

| 文件 | 修改 |
|------|------|
| `src/index.ts` | **Frida-only 模式** — 不启动 debug/proxy server，由 e0e1-wx 接管 |
| `src/index.ts` | **轮询等待** — frida_server 每 2 秒重试，最多等 60 秒 |
| `src/index.ts` | **异常保护** — .catch() 防止 Frida 注入失败导致进程退出 |
| `src/index.ts` | **保底逻辑** — PPID 查找失败时用第一个 WeChatAppEx 进程 |
| `一键启动.bat` | [新增] 启动脚本，带 Node.js 版本检查 |

### e0e1-wx 修改内容

| 文件 | 修改 |
|------|------|
| `package/devtools/engine.py` | `start()` 跳过 Frida 注入，只启动 debug/proxy server |
| `package/devtools/engine.py` | `_start_frida_sync()` 返回 `(None, None)` |
| `start_engine.py` | [新增] 独立启动引擎脚本（不依赖 GUI） |

---

## 偏移提取原理

`extract_wmpf_offsets.py` 从 `flue.dll`（约 235MB）中提取三个关键偏移：

| 偏移 | 作用 | 提取方法 |
|------|------|---------|
| `LoadStartHookOffset` | 开 F12 入口 | 扫描 `.pdata` 表，定位 `AppletIndexContainer::OnLoadStart` |
| `CDPFilterHookOffset` | CDP 过滤器入口 | 搜索 `SendToClientFilter` 字符串 → 交叉引用 → 父函数中第一个 E8 call |
| `SceneOffsets[6]` | 场景号修改偏移 | 追踪 `OnLoadStart` 函数中的指针链 |

### flue.dll 位置

```
%APPDATA%\Tencent\xwechat\xplugin\Plugins\RadiumWMPF\{版本号}\extracted\runtime\flue.dll
```

### 如果自动提取失败

使用 IDA Pro 打开 `flue.dll`，参考 `偏移提取工具/SKILL.md` 的指引手动分析。

---

## 常见问题

### Q: 一键启动.bat 报 frida 加载错误
```
NODE_MODULE_VERSION 115 → 需要 NODE_MODULE_VERSION 137
```
**原因：** frida 二进制与 Node.js 版本不匹配。  
**解决：** 切换到 Node.js 20 LTS，重新安装 `npm install frida@16.6.6`。

### Q: CDP 连接不上（62000 端口未监听）
**原因：** e0e1-wx 引擎未启动。  
**解决：** 运行 `python start_engine.py` 启动引擎。

### Q: CDP 能连上但没响应（超时）
**原因：** 小程序未连接到 debug server (9421)。  
**解决：** 关掉小程序重新打开，确保 debug server 先于小程序启动。

### Q: appservice 上下文不可访问
**原因：** 小程序未完全打开（拖拽预览状态），或 MCP 缓存了旧 context ID。  
**解决：** 确保在微信中点击打开（不是拖拽）小程序。重启 e0e1-wx GUI。

### Q: 偏移提取脚本失败
**原因：** 新版本 flue.dll 结构变化。  
**解决：** 使用 IDA Pro + `偏移提取工具/SKILL.md` 手动分析。

### Q: 启动后 WMPFDebugger 窗口一闪而过
**原因：** ts-node 未安装或 frida 未正确安装。  
**解决：** `npm install -g ts-node`，`npm install frida@16.6.6`。

---

## 许可证

- `偏移提取工具/` — AGPL-3.0
- `WMPFDebugger/` — GPL-2.0
- `e0e1-wx/` — 请参考原项目许可证

本项目仅用于授权安全研究、学习和调试场景，请勿用于未授权目标或违反相关法律法规的用途。
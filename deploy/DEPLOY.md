# 九预设 dsh-redteam-model 自包含部署套件（八专业模式 + redteam 主模式）

**dsh-redteam-model/ 目录即完整交付物**：`modes/`（九预设全部资产：八专业模式 + redteam 主模式的
persona/组合行/playbook/refs）+ `shared/`（共享技能）+ `plugins/`（九个模式插件）+ `deploy/`（本工具）。
预设发现链接指向 **modes/**——DSH 发现器只扫其直接子目录（九个干净预设），shared/plugins/deploy
平铺在链接之外、不进模式列表。打包 dsh-redteam-model tar.gz 移交任何机器（macOS / Windows /
Linux）即可一键部署。

## 组件清单（dsh-redteam-model/ 内）

| 组件 | 位置 | 作用 | 挂载平面 |
|---|---|---|---|
| 五专业模式 | `modes/{pentest,code-audit,binary-analysis,attack-defense,av-evasion}/` | persona/工具行/playbook/refs（自包含、零本机路径、工具平面检测制） | —（预设本体，链接即 modes/） |
| CTF 解题模式 | `modes/ctf-solver/` | CTF 竞赛解题台：题面登记、模块路由（competition-* 技能）、解题循环、flag 台账与复盘；两门（board/flag） | —（预设本体，链接即 modes/） |
| 云安全攻防模式 | `modes/cloud-security/` | 云平台（AWS/Azure/GCP/阿里云/腾讯云/华为云）+ 云原生（K8s/容器/Serverless/CI-CD）渗透：暴露面测绘、凭证利用、IAM 提权、元数据 SSRF、容器/K8s 逃逸、云检测缺口；七门（C1-C7） | —（预设本体，链接即 modes/） |
| 应急溯源模式 | `modes/incident-response/` | Windows/Linux 应急响应与攻击溯源：日志分析、恶意程序排查（webshell/内存马/木马/病毒/勒索）、失陷调查、攻击链还原报告、持久化与隐藏后门排查；五门（I1-I5） | —（预设本体，链接即 modes/） |
| redteam 主模式 | `modes/redteam/` | 泛化安全研究员：任务路由（浅做/专业路由/多任务协同）+ 台账 + 全局总结与下一步建议；无自建门（总控只消费专业模式 gate-pass）、无 refs 库（知识靠六 playbook） | —（预设本体，roster 置顶 order:0） |
| 共享技能与资源 | `shared/skills/`（ecosystem-cooperation、independent-review、red-team-command-doctrine、redteam-boundary-policy）；`shared/refs/`（成果登记字段语义词典）；`shared/scripts/`（工具平面探测合并脚本 .sh/.ps1） | 九预设 customSkillDirs 共同加载；refs/scripts 随包分发 | 随预设加载 |
| dsh-stage-gate | `plugins/` | stage_gate/gates_list 门禁工具（32 门结构校验：pentest 3 + code-audit 3 + binary 3 + attack-defense 5 + av 4 + ir 5 + cloud 7 + ctf 2） | 宿主（bundles，全模式可见） |
| dsh-product-subagents | `plugins/` | subagent_claude_code / subagent_codex 的 provider（无头 spawn 本机 CLI；模型后端随 CLI 自身配置） | 宿主（bundles） |
| dsh-route-boost | `plugins/` | 逐轮治理信封（(模式,阶段)推断 + gate/双签/边界/refs 指针，变化才投快照） | 宿主（bundles） |
| dsh-refusal-guard | `plugins/` | 拒答检测与一次性临近性再注入 | 宿主（bundles） |
| dsh-sec-enforce | `plugins/` | 确定性工具拦截（报告门/写边界/高危/速率特征 + enforce-log 留痕） | 宿主（bundles） |
| dsh-hunter | `plugins/` | 「hunter狩猎」：FOFA/Hunter/Quake 三平台资产搜索（统一 DSL 自动转语法/限额分页导出）+ 代码审计一键实测流水线（L0 指纹判定/L1 仅授权资产）+ 会话标签页（与 redteam 成果并排） | 宿主（bundles） |
| dsh-redteam-results | `plugins/` | 会话隔离成果页「redteam 成果」（九模式侧栏；五板式（CTF 复用 ledger 台账板式）：渗透/代审=漏洞报告、二进制/攻防/免杀=产物清单、研究员=任务台账、应急=攻击链时间线、云安全=云攻击路径；redteam_finding_register/update/delete） | 宿主（bundles） |
| dsh-scanner-tools | `plugins/` | nuclei_scan/httpx_probe/ffuf_fuzz（速率纪律/防盲打/证据落盘） | **preset 平面**（仅 pentest/attack-defense/cloud-security 预设行挂载） |
| dsh-mcp-studio | `plugins/` | MCP 加载工作台（通用类 MCP 宿主层共用挂载） | 宿主（bundles） |

## 目标机一键部署（跨平台：win / mac / linux）

目标机唯一前置：**node >= 22**（DSH 本身要求）。不需要 bash、python；pnpm/dsh 经 npx 拉起。

```bash
tar -xzf dsh-redteam-model-bundle-*.tar.gz && cd dsh-redteam-model/deploy
node deploy.mjs            # 或：npx ./deploy —— 链接预设+挂载插件+安装（幂等可重跑）
node deploy.mjs --check    # 离线验证：九预设挂载 + 插件行真实 loader 路径 + dsh.bundle 声明
node deploy.mjs --start    # 后台启动 dsh web（http://127.0.0.1:3080）
node deploy.mjs --bundle   # 重新打包 presets 根（本机用；系统 tar，Win10+ 自带 bsdtar）
# Windows：tar -xzf 同样可用（Win10+ bsdtar）；预设链接用 junction 免管理员
```

幂等语义：已有 `~/.dsh/.agent-presets` 链接/目录**备份成 .bak-时间戳（绝不删除）**；
profiles/web/package.json 只增不改（link 依赖 + bundles，插件路径一律指向 dsh-redteam-model/plugins/）。

## 部署后人工验证（2 分钟）

1. 浏览器开 http://127.0.0.1:3080，roster 应列出七个预设（redteam 安全研究员置顶 + 渗透测试/代码审计/二进制分析/攻防评估/免杀对抗/应急溯源）；
2. 任一会话里让模型调 `gates_list`——返回八模式门禁 schema（32 门）即 stage-gate 生效；
3. pentest/attack-defense 会话可见 `nuclei_scan/httpx_probe/ffuf_fuzz`（其余模式不可见=preset
   平面正确）；任一模式会话可见 `subagent_claude_code/subagent_codex`（调用需目标机有
   claude/codex CLI，后端随其自身配置）；
4. 九预设会话发起任务后应看到 `[route-boost] mode=... phase=...` 运行时上下文快照（阶段切换
   时更新；redteam 会话的信封为无门总控版 + 技能指针知识行）；非安全预设不注入；
5. 报告写入 `reports/` 前若 gate-log 无本模式报告门 PASS，写入会被 sec-enforce 拦截并指路
   （确定性门禁生效的直观验证）；
6. （可选）MCP：按 dsh-mcp-studio 的方式接入 burpsuite/yakit/chrome-dev-mcp 等宿主层共用。

## 机器差异项（bundle 不含，目标机自备或走降级）

- **claude / codex CLI**（可选）：产品子代理通道；缺失时工具调用返回可读错误并附兜底链指引，
  DSH 原生子代理（subagent/subagent_fork）不受影响。模型后端随 CLI 自身配置
  （不同源=异构双签，同源=同源互证并在报告注明）；
- **工具链**（nmap/nuclei/httpx/ffuf/jadx/frida/mingw 等）：五 playbook 已改「工具平面检测制」
  ——开工 `command -v` 探测登记 evidence-index.md tool-plane 节，缺失走三级兜底（检测到的
  优先 → MCP → 安装请求，安装命令跨平台 brew/apt/pip/go/npm）；nuclei 首用一次性下载模板库；
- **静态审计标准**已内置（fortify-kingdom 分类定级 + chanzi-rules 122 条语义知识 +
  semgrep-oss 1080 条可执行规则 + 自建 402 条），零外部依赖；Fortify 本体仅作可选增强参照；
- **refs 零本机路径**（打包铁律）；跨平台命令等价见 ecosystem-cooperation「跨平台执行公约」；
- **dsh 默认预设**：新机默认仍是官方 cordis；如需本项目预设为默认，改 ~/.dsh/settings.yaml 的
  agent-presets.default。
- **Kali MCP 服务端**（可选，`deploy/assets/`）：`kali-mcp-server/` 为维护源目录、
  `kali-mcp-server.zip` 为部署资产（源目录变更后重打包：进入源目录
  `zip -rqX ../kali-mcp-server.zip . -x "*.pyc" -x "*__pycache__*"`）。在 Kali 主机上部署的
  安全工具 MCP 服务（streamable-http，端口 8765）——把 Kali 上的 260+ 安全工具（nmap/nuclei/
  sqlmap/ffuf/httpx/netexec/impacket 全家/evil-winrm/responder/msf/radare2/volatility3 等）封装为
  结构化 MCP 工具远程调用；执行器带并发上限（默认 4，环境变量 KALI_MCP_MAX_CONCURRENT 可调）、
  超长输出智能截断（output_truncated 标记）、逐工具超时。部署：
  `unzip kali-mcp-server.zip -d ~/kali-mcp && cd ~/kali-mcp && pip install -r requirements.txt &&
  python3 mcp_server.py --transport streamable-http --host 0.0.0.0 --port 8765 --allowed-host <本机IP>`；
  客户端在 mcp-studio 一键预设「Kali MCP」填 `http://<kali-ip>:8765/mcp` 开启（默认关）。
  服务无认证，仅在隔离/内网可达范围开放；被包装的工具均须已装在 Kali 上（未装即如实报错，
  走通道降级）。许可证 MIT（zip 内 LICENSE）。

## 重新打包（本机）

```bash
cd dsh-redteam-model/deploy && node deploy.mjs --bundle   # 产出 dsh-redteam-model/dsh-redteam-model-bundle-<date>.tar.gz
# 内容 = dsh-redteam-model/ 交付净量（modes 九预设 + shared + plugins + deploy）
# 排除：node_modules/.git/.zcode/.DS_Store + 管理文档（DESIGN/PROGRESS/测试——
# 含本机实测记录与本地路径，仅留源目录供维护者；目标机需要时另行手动拷贝）
```

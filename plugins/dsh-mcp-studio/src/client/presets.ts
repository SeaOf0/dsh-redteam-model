/**
 * Built-in one-click server presets: JSON snippets for the MCP servers
 * people most commonly wire up. Each chip fills the paste drawer; importing
 * stages the row(s) as usual.
 */
export interface ServerPreset {
  readonly id: string
  readonly label: string
  readonly description: string
  readonly json: string
}

export const SERVER_PRESETS: readonly ServerPreset[] = [
  {
    id: 'chrome-devtools',
    label: 'Chrome DevTools',
    description: 'Chrome DevTools MCP：页面快照、点击、填表、网络与控制台（默认关闭；开启即经 npx 拉起）',
    json: '{\n  "mcpServers": {\n    "chrome-devtools": {\n      "command": "npx",\n      "args": ["-y", "chrome-devtools-mcp@latest"],\n      "disabled": true\n    }\n  }\n}',
  },
  {
    id: 'kali',
    label: 'Kali MCP',
    description: '远程 Kali 武器库（nmap/nuclei/sqlmap/netexec/impacket/msf 等 100+ 工具）。默认关闭：先把 <kali-ip> 换成 Kali 机地址（服务端以 streamable-http 运行在 8765），再开启；长扫描工具建议调大单次调用超时',
    json: '{\n  "mcpServers": {\n    "kali": {\n      "type": "http",\n      "url": "http://<kali-ip>:8765/mcp",\n      "disabled": true\n    }\n  }\n}',
  },
  {
    id: 'webshell',
    label: 'Webshell MCP',
    description: 'webshell 管理器 MCP（连接/命令执行/文件/数据库/载荷插件，与 dsh-webshell-mgr 同核）。默认关闭：把 <dsh-webshell-mgr-path> 替换为 dsh-webshell-mgr 插件目录的绝对路径后开启；dsh 会话内优先用宿主原生 webshell_* 模型工具，本服务面向外部 harness',
    json: '{\n  "mcpServers": {\n    "webshell": {\n      "command": "node",\n      "args": ["<dsh-webshell-mgr-path>/mcp/server.mjs"],\n      "disabled": true\n    }\n  }\n}',
  },
  {
    id: 'everything',
    label: 'Everything',
    description: 'MCP 官方测试服务器，含 echo/add 等工具，适合验证链路',
    json: '{\n  "mcpServers": {\n    "everything": {\n      "command": "npx",\n      "args": ["-y", "@modelcontextprotocol/server-everything"]\n    }\n  }\n}',
  },
  {
    id: 'filesystem',
    label: 'Filesystem',
    description: '受限目录的文件读写与搜索',
    json: '{\n  "mcpServers": {\n    "filesystem": {\n      "command": "npx",\n      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]\n    }\n  }\n}',
  },
  {
    id: 'fetch',
    label: 'Fetch',
    description: '网页抓取转 Markdown',
    json: '{\n  "mcpServers": {\n    "fetch": {\n      "command": "uvx",\n      "args": ["mcp-server-fetch"]\n    }\n  }\n}',
  },
  {
    id: 'memory',
    label: 'Memory',
    description: '知识图谱式持久记忆',
    json: '{\n  "mcpServers": {\n    "memory": {\n      "command": "npx",\n      "args": ["-y", "@modelcontextprotocol/server-memory"]\n    }\n  }\n}',
  },
  {
    id: 'sequential-thinking',
    label: 'Seq Thinking',
    description: '结构化分步推理工具',
    json: '{\n  "mcpServers": {\n    "seq-thinking": {\n      "command": "npx",\n      "args": ["-y", "@modelcontextprotocol/server-sequential-thinking"]\n    }\n  }\n}',
  },
  {
    id: 'puppeteer',
    label: 'Puppeteer',
    description: '浏览器自动化（导航/截图/点击）',
    json: '{\n  "mcpServers": {\n    "puppeteer": {\n      "command": "npx",\n      "args": ["-y", "@modelcontextprotocol/server-puppeteer"]\n    }\n  }\n}',
  },
  {
    id: 'github',
    label: 'GitHub',
    description: '仓库/Issue/PR 操作，需要 token',
    json: '{\n  "mcpServers": {\n    "github": {\n      "command": "npx",\n      "args": ["-y", "@modelcontextprotocol/server-github"],\n      "env": { "GITHUB_TOKEN": "ghp_xxx" }\n    }\n  }\n}',
  },
  {
    id: 'http-example',
    label: 'HTTP 示例',
    description: 'streamable-http 传输的模板',
    json: '{\n  "mcpServers": {\n    "remote": {\n      "type": "http",\n      "url": "http://localhost:3000/mcp",\n      "headers": { "Authorization": "Bearer token" }\n    }\n  }\n}',
  },
]

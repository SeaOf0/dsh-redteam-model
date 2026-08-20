# Kali MCP Server

Kali Linux 安全工具的 MCP（Model Context Protocol）服务端：把主机上的安全工具链
（侦察 / 扫描 / Web 测试 / 内网横向 / 密码攻击 / 取证 / PWN 等）封装为结构化 MCP 工具，
供远程 AI 客户端按需调用。

## 部署（Kali 主机）

```bash
pip install -r requirements.txt        # 或 pipx / venv 按环境自选
python3 mcp_server.py --transport streamable-http \
  --host 0.0.0.0 --port 8765 \
  --allowed-host <本机对外IP>          # SDK 的 DNS 重绑定保护默认只放行 localhost
```

- 传输模式：`stdio`（本机客户端）/ `sse`（旧式远程）/ `streamable-http`（推荐远程，端点 `/mcp`）
- `--allowed-host` 可多次传入；`--disable-dns-protection` 仅限隔离网络使用
- `--tool-profile full` 注册全部工具；工具均为本机已装二进制的包装，未装的工具调用时会如实报错
- 兼容旧式 API server 后端时可用环境变量 `KALI_MCP_SERVER` 指定地址（本地执行模式不需要）

## 客户端接入（dsh / mcp-studio）

- 传输选 `streamable-http`，URL 填 `http://<kali-ip>:8765/mcp`
- 长扫描工具（nmap 全端口 / nuclei 全模板等）建议在客户端调大单次调用超时

## 安全注记

- 服务本身无认证：仅在主机隔离 / 内网可达范围内开放，不要暴露到不受信网络
- 输出遵守调用方的证据与速率纪律；工具产生的任何流量由使用方授权范围约束

## 许可

MIT（见 LICENSE）。

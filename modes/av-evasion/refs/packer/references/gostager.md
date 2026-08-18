# Go Stager 流程细节

本文件承接 `SKILL.md` 中的 Go stager 分支细节。Go stager 用于 **CS HTTP/HTTPS stager**，通过 `parse_stager.py` 提取 C2 信息后，Go 原生实现 HTTP 下载 + 反射加载。

---

## GS-Step 1: 解析 stager

```bash
<python命令> <skill_dir>/scripts/parse_stager.py <stager.bin>
```

输出 JSON 字段：

| 字段 | CS stager |
|------|-----------|
| `type` | `cs-http` / `cs-https` |
| `protocol` | `http` / `https` |
| `host` | 域名/IP |
| `port` | 端口 |
| `uri` | `/xxx` |
| `url` | `https://host:port/uri` |
| `user_agent` | `Mozilla/...` |
| `entry_offset` | 反射加载器偏移 |
| `headers` | `[...]` |
| `file_size` | 文件大小 |

---

## GS-Step 2: CS stager 字段映射（唯一来源）

- `url <- json.url`
- `user_agent <- json.user_agent`
- `entry_offset <- json.entry_offset`
- `headers <- json.headers`

缺失处理：
- `url` 为空：停止流程，重跑解析。
- `entry_offset` 缺失或为 `0`：停止流程，优先重跑解析，不做手工猜测。
- `user_agent` 为空：使用脚本默认值；用户明确指定时以用户输入为准。
- `headers` 为空：仅最小请求头（至少 User-Agent），不手工臆造 profile 专属头。

## GS-Step 3: CS stager 请求对齐

- User-Agent 以 `json.user_agent` 为准。
- 自定义 header/cookie 优先以 `json.headers` 为准进行对齐。
- 与 profile 不一致时先复核解析结果，再做后续调整。

## GS-Step 4: 编译

Go stager 编译命令统一使用 `-trimpath` 去除本地路径信息：

```bash
# bash (Git Bash / WSL)
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -H windowsgui" -o <output>.exe <source>.go
```
```cmd
:: Windows CMD
set GOOS=windows&& set GOARCH=amd64&& go build -trimpath -ldflags="-s -w -H windowsgui" -o <output>.exe <source>.go
```

| 参数 | 作用 |
|------|------|
| `-trimpath` | 去除源码文件系统路径，避免泄露开发环境路径 |
| `-s` | 去除符号表 |
| `-w` | 去除 DWARF 调试信息 |
| `-H windowsgui` | 无控制台窗口（GUI 子系统） |

编译后执行 PE 验证，详见 `references/verification.md`。

---

## 分流决策速查

| `json.type` | 路线 | 核心逻辑 | 关键字段 |
|-------------|------|----------|----------|
| `cs-http` / `cs-https` | HTTP 下载 + 反射加载 | Go 发起 HTTP GET 下载 beacon DLL，通过 `entry_offset` 反射加载 | `url`, `user_agent`, `entry_offset`, `headers` |

# 堡垒机 / JumpServer 攻击面

> 定位：堡垒机（JumpServer 及其开源组件）本身作为「资产账号托管中枢」的攻击面专篇。
> 攻陷堡垒机 ≈ 一次性拿下其托管的所有资产账号（服务器/数据库/网络设备），是权限主线上的「集权点」。
> 本专篇覆盖组件架构 → 已知 CVE 复现链 → 未授权/会话令牌/凭据库攻击面 → 检测点，全链口径
> （前置条件 → 命令/工具 → 参数 → 输出解读 → 规避 → 证据要求）。
> 外部来源：2025-2026 前沿经联网核实，见文末「参考」。

---

## 一、组件架构与信任边界

JumpServer 是典型的「Core + 连接组件 + 前端」分层架构。理解组件职责是定位攻击面的前提：

| 组件 | 职责 | 默认端口 | 攻击面关键词 |
|---|---|---|---|
| Core | 主后端（Django/Celery）：资产管理、账号托管、会话录像、认证授权、API | 8080（HTTP，Nginx 反代后对外 80/443） | 认证/授权绕过、Celery 任务注入、录像/回放 API、凭据库 |
| Koko | SSH/Telnet 连接代理（Go）：把用户的 Web 会话桥接成到目标资产的 SSH/Telnet | 2222（SSH）、5000（对外被反代） | SSH 会话注入、连接代理绕过、未授权连接 |
| Luna | Web Terminal（前端 WebSocket 终端） | 由 Core 反代，通常 `/luna/` | WebSocket 会话劫持、XSS、组件 RCE |
| Lion | 数据库连接代理（MySQL/MariaDB 等） | 由 Koko/Core 调度 | 数据库连接绕过、组件 RCE |
| Magnus / Celery | 异步任务与录像回放服务（Celery + redis） | 内部 | 任务注入、replay 命令注入 |

**信任边界要点**：
- 各组件之间通过**共享 token / 内网直连**通信，组件之间的鉴权往往弱于对外 API——拿下一个组件即可横向到其他组件。
- 录像文件（replay）与 `video/` 接口是历史高危集中点：一旦能「读录像/注入录像」，等于拿到会话内明文命令与凭证。
- 资产账号托管库（Core 的 `assets` / `system user` 模块，密码用 Fernet/AES 加密存储）是最终目标：解密密钥在 Core 的配置文件（`SECRET_KEY` / `BOOTSTRAP_TOKEN`）中。

---

## 二、已知 CVE 复现链

### 2.1 CVE-2025-62712 — ConnectionToken（superconnectiontoken）权限验证不当

**漏洞类型**：权限管理错误 / 连接令牌验证不当（Improper Validation of Connection Token）
**影响**：未授权获取连接令牌 → 越权连接资产 / 会话令牌泄露
**发现时间**：2025-11 披露

**原理**：JumpServer 的 `superconnectiontoken`（超级连接令牌）机制用于组件间建立连接会话；其生成/校验链存在权限管理错误，攻击者可在未通过正常鉴权的情况下构造或复用连接令牌，绕过「连接会话必须属于当前用户/当前资产」的校验，实现越权连接甚至接管会话。

**前置条件**：
- 网络可达 Core 的 HTTP 服务（对外 80/443，或内网 8080）
- 无需有效账户（未授权场景）或仅需低权限账户（越权场景）

**复现链（授权测试口径）**：

```bash
# 1) 确认目标 JumpServer 版本与指纹
curl -s http://<target>/api/v1/health/ | head -c 400
curl -s http://<target>/core/auth/password/reset/ -o /dev/null -w "%{http_code}\n"
# 指纹：登录页脚、/api/v1/ 返回的版本字段、x-jms-version 响应头

# 2) 定位会话/连接接口（越权对象：目标资产 session 与 connection token）
curl -s http://<target>/api/v1/terminal/sessions/ \
  -H "Authorization: Bearer <低权限用户 token>" | jq '.results[] | {id, asset, user}'

# 3) 构造/复用 superconnectiontoken（核心：绕过「token 与资产/会话绑定」校验）
#    按厂商通告，缺陷在于连接令牌的生成与鉴权校验分离；授权测试中应：
#    - 用低权限 token 请求高权限资产的连接令牌，观察是否被拒绝（应拒绝，漏洞则放行）
#    - 记录请求/响应原样作为证据
```

**输出解读**：
- `401/403` → 校验生效；`200` 且返回 `connect_token`/`superconnectiontoken` → 命中未授权/越权。
- 命中后该令牌可直接用于 Koko SSH 或 Web Terminal 建立到目标资产的连接。

**证据要求**：请求/响应原文 + 返回的连接令牌可复现连接（最小影响：仅 `whoami`/`id` 回显）+ 版本号 + 复现时间戳。

**修复口径**：升级到厂商通告的修复版本；如未升级，记录为 P0 缺口。

### 2.2 CVE-2025-27095 — 权限绕过（历史同类）

**类型**：认证/授权绕过（Authorization Bypass）。与 2.1 同属「组件间令牌/会话授权」缺陷簇，攻击面相同：越权访问资产、会话录像与连接令牌。
**复现思路**：与 2.1 同链，重点验证「低权限用户 → 高权限资产连接/录像读取」是否被正确拦截。
**来源**：<https://securitricks.com/cve/CVE-2025-27095>

### 2.3 2023 Sep 系列 — Core/Luna/Koko 未授权 RCE 簇

**代表 CVE**：CVE-2023-42818（Core replay/Celery 命令注入）、CVE-2023-42819（Luna WebSocket RCE）、CVE-2023-42820（Koko SSH 会话 RCE）。同批还有 Koko/Luna 的多项越权（JS-2023.09.27 通告）。

**原理（Core replay API 链）**：Core 的终端录像回放接口把用户可控参数传入 Celery 异步任务，未做严格校验，导致**命令注入/任意文件读写**；配合录像文件路径可控，可写入恶意内容并触发执行，最终 RCE。部分分析把该链路的「任务对象/会话对象反序列化」归为不安全反序列化——攻击面本质是 replay/会话处理链的输入校验缺失。

```bash
# 概念复现链（授权测试；针对 2023 未修复版本）
# 1) 利用录像回放 API 的 task 参数注入（示意，参数名以目标版本为准）
#    POST /api/v1/terminal/replays/  携带可控 session_id/task_id
# 2) 任意文件读取：让 Celery 任务读取 Core 配置文件（含 SECRET_KEY / DB 口令）
# 3) 任意文件写入：写入 webshell 或覆盖启动脚本 → RCE
# 4) 拿到 Core 后：解密资产账号凭据库 → 全网资产沦陷
```

**检测与修复**：升级至 2023-09-27 通告版本以上；核心是「录像接口/任务参数白名单 + Celery 任务不直接拼接 shell 命令」。

---

## 三、未授权 / 会话令牌 / 凭据库攻击面（非 CVE 通用面）

### 3.1 未授权访问面

| 面 | 探测 | 判定 |
|---|---|---|
| 版本/健康接口泄露 | `GET /api/v1/health/` | 返回版本/组件状态 → 用于 CVE 匹配 |
| 静态文件/前端不设防 | `GET /luna/`、`GET /static/` | 泄露版本与部署结构 |
| 录像文件直读 | `GET /media/replay/...`、`GET /api/v1/terminal/replays/<id>/` | 未鉴权可读 → 会话明文泄露 |

### 3.2 会话令牌 / 会话劫持面

```bash
# 会话录像与回放读取（会话明文命令 + 屏幕录像）
curl -s http://<target>/api/v1/terminal/sessions/?limit=100 \
  -H "Authorization: Bearer <token>" | jq '.results[] | select(.is_finished==true) | {id, asset, user, protocol}'

# 会话录像下载（若存在越权可下载他人会话）
curl -s -o replay.gz http://<target>/media/replay/<session_id>.replay.gz
# 解析：JumpServer 录像为 tar+json 命令流，含每条命令明文（whoami/密码等）
```

### 3.3 凭据库攻击面（最终目标）

- Core 的资产账号（system user / account）密码加密存储，加密密钥来自 `SECRET_KEY`/`BOOTSTRAP_TOKEN`（`config.yml` / 环境变量）。
- 攻陷 Core 后：`cat config.yml | grep -iE "SECRET_KEY|BOOTSTRAP_TOKEN|DB_"` → 用 Fernet 解密账号库 → 得到所有托管资产明文账号密码。
- 该步骤即「堡垒机沦陷 → 全网沦陷」的证据链终点。

---

## 四、检测点（目标侧应留痕迹）

| 攻击行为 | Windows/Linux 事件 | 网络/应用日志 | EDR/SIEM 遥测 |
|---|---|---|---|
| 未授权 API 探测（health/version） | — | Nginx access log：`/api/v1/health/`、`/api/v1/terminal/` 高频访问 | 单源 IP 短时间多 API 路径 |
| 越权读取会话/录像 | — | Core 应用日志：异常 `terminal/sessions` 读取 + 用户与资源不匹配 | 会话读取量突增 |
| 连接令牌越权使用 | — | Core 日志：`connect_token` 生成与使用主体不一致 | 新连接主体 ≠ 会话属主 |
| Celery 任务注入 | — | Celery/redis 日志：异常 task 参数 | 非白名单命令执行 |
| 凭据库解密/批量导出 | 文件访问 `config.yml` | Core 日志：账号导出 API 调用 | 进程读取 `SECRET_KEY` 文件 |

---

## 五、参考

- CVE-2025-62712（superconnectiontoken 权限管理错误）：<https://www.secrss.com/articles/84628>、<https://blog.nsfocus.net/【漏洞通告】jumpserver连接令牌验证不当漏洞（cve-2025-62712）/>
- CVE-2025-27095：<https://securitricks.com/cve/CVE-2025-27095>
- JumpServer 2023 Sep 系列漏洞通知（JS-2023.09.27）：<https://jumpserver.org/blog/security-20230927.html>
- JumpServer CVE 全景：<https://app.opencve.io/cve/?vendor=jumpserver&product=jumpserver>

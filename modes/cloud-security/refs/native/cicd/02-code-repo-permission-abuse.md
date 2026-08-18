# 代码仓库权限滥用

> 定位：代码仓库是 CI/CD 链的最上游，也是凭证与源码的集中地。本手册梳理仓库访问权限、
> 分支保护、凭据泄漏与只读探测，每条路径配检测侧对照。破坏性步骤标「授权内人工确认后执行」。

## 1. 攻击面

代码仓库攻击面：

| 面 | 形态 | 风险 |
|---|---|---|
| 访问面 | 公开/内部仓库未设保护、越权读 | 源码与密钥泄露 |
| 权限面 | 过宽的写权限、缺分支保护、弱 Code Review | 直接投毒主分支 |
| 凭据面 | token/部署密钥/云凭证提交进历史 | 复用身份横向 |
| 元数据面 | `.git` 目录泄露、提交历史含敏感信息 | 源码/密钥/内部端点暴露 |

核心风险：仓库历史是只增的，一次误提交的密钥会永久留在历史里，删除远端文件不等于删除
历史记录。

## 2. 暴露面探测（只读命令优先）

### 2.1 仓库可见性只读盘点

```bash
# 用仓库平台 API 只读查询仓库可见性、分支保护、协作者（有 token 时）
# 通用：git 只读操作
git ls-remote <repo-url>        # 匿名可列分支 = 仓库公开/匿名可读
```

判定口径：匿名 `ls-remote` 成功 = 仓库公开或内部可匿名读；能列全部协作者且含大量外部
账号 = 权限面过宽。

### 2.2 提交历史敏感信息只读扫描

```bash
git log --oneline --all          # 只读历史
git log -p --all | grep -iE 'AKIA|BEGIN (RSA|OPENSSH|EC|PRIVATE) KEY|ghp_|glpat|password\s*=|secret'
# 或本地用密钥扫描（只读，不外传）
git grep -iE 'AKIA[0-9A-Z]{16}|BEGIN PRIVATE KEY' $(git rev-list --all) 2>/dev/null | head
```

判定口径：命中云 AK 前缀、私钥头、平台 token 前缀 = 历史密钥泄露，登记所属 commit 与
时间，提示轮换。

### 2.3 `.git` 目录暴露只读探测

```bash
# Web 站点若暴露 .git 目录，可只读探测（不改动）
curl -s -o /dev/null -w '%{http_code}' https://<target>/.git/config
curl -s https://<target>/.git/config 2>/dev/null
```

判定口径：`.git/config` 可读 = 源码库暴露，可恢复完整仓库（含历史密钥）。

## 3. 缺陷与利用路径

### 3.1 仓库公开/内部匿名可读 + 历史密钥

- 缺陷：仓库设为 public/internal 且无保护，或 `.git` 目录随 Web 部署暴露；历史里含密钥。
- 验证命令（只读）：`git ls-remote` / `curl .git/config` + 历史扫描。
- 影响：源码、密钥、内部端点一次性泄露。
- 检测侧：仓库访问审计（匿名/异常克隆）；secret scanning 对历史全量扫描；Web 服务器访问
  日志记录 `.git` 请求。

### 3.2 分支保护缺失 / 写权限过宽

- 缺陷：主分支无保护（无强制 PR、无 Code Review、可 force push），任意有写权限者（含被
  社工/泄露 token 者）直接推主分支。
- 验证命令（只读）：读分支保护配置（平台 API）看 `required_pull_request_reviews`、
  `enforce_admins`、`allow_force_pushes`。
- 影响：恶意代码直进生产；历史被 force push 抹除证据。
- 检测侧：仓库审计记录 push/force push 与保护规则变更；CI 审计记录主分支构建异常。

### 3.3 部署密钥 / 平台 token 提交进历史

- 缺陷：开发者把部署私钥、平台 PAT、云 AK 提交进仓库（常因 `git add .` 误加）。
- 验证命令（只读）：历史扫描（见 2.2）。
- 影响：token/私钥可复用，横向到仓库/云/生产。
- 检测侧：secret scanning 命中；平台审计记录 token 使用与源 IP；云审计记录 AK 调用。

### 3.4 协作者/服务账号权限残留

- 缺陷：离职员工、外包、僵尸服务账号仍保有写权限；bot token 权限过宽。
- 验证命令（只读）：列协作者与访问令牌（平台 API 只读），比对在册人员。
- 影响：残留身份成为长期入口。
- 检测侧：仓库访问审计（异常账号活动）；身份生命周期审计（离职权未回收）。

### 3.5 元数据泄露（提交信息/内部端点/配置）

- 缺陷：提交信息、README、配置文件里暴露内部域名、数据库连接串、CI 内部地址，辅助后续
  内网渗透。
- 验证命令（只读）：`git log --oneline` 读提交信息 + 仓库内搜内部端点特征。
- 影响：泄露内网拓扑，降低横向成本。
- 检测侧：仓库内容扫描（端点/密钥模式）；访问审计。

### 3.6 分支保护绕过与合入投毒（合并提交注入）

- 缺陷：通过 force push、保护规则缺口、或取得写权限后绕过 Code Review，把后门合并进主分支；
  或利用合并提交（merge commit）隐藏改动。
- 验证命令（只读）：读分支保护与合入规则；`git log --graph --oneline` 审计合入历史与异常
  提交。
- 影响：后门进主分支，随流水线进生产。
- 检测侧：仓库审计记录 merge/force push/保护规则变更；CI 审计主分支构建异常。

## 4. 提权与持久化

- 提权链：历史密钥 → 云/平台身份 → 写权限 → 投毒主分支 → 生产；`.git` 暴露 → 源码 →
  内部端点 → 内网渗透。
- 持久化（授权内人工确认后执行）：植入恶意提交/后门文件、追加 deploy key、保留高权 bot
  token；逐项登记 `environment-restore.md`。

## 5. 检测与加固要点

### 5.1 检测事件名对照

| 攻击行为 | 检测层 + 事件 |
|---|---|
| 异常克隆/匿名访问 | 仓库访问审计（匿名/异常 IP/大流量） |
| 历史密钥泄露 | secret scanning 命中 + 平台审计 token 使用 |
| force push 抹证据 | 仓库审计 force push + 保护规则变更 |
| 主分支直接推送 | 仓库审计 push（绕过 PR） |
| 残留身份活动 | 身份生命周期审计 + 仓库审计异常账号 |

### 5.2 加固要点

- 仓库私有化 + 访问白名单；`.git` 目录禁止 Web 暴露（部署排除）。
- 主分支保护：强制 PR + Code Review + 禁 force push；写权限最小化 + 定期回收。
- 密钥不入库：secret scanning + pre-commit 钩子 + 已泄露密钥立即轮换（历史清除需重写，
  授权内人工确认后执行）。
- 平台 token 短生命周期 + 最小 scope + 异常告警。

## 6. MITRE ATT&CK 映射

| 技术 | ATT&CK ID |
|---|---|
| 历史凭证泄露 | T1552 Unsecured Credentials |
| 复用泄露身份 | T1078 Valid Accounts |
| 仓库供应链投毒 | T1195 Supply Chain Compromise |
| 源码/云存储窃取 | T1530 Data from Cloud Storage |

## 7. 证据记录要点

- 每条路径登记四要素（身份→权限→资源→影响）+ 证据编号，落 attack-paths.md。
- 历史密钥登记所属 commit 与时间，提示轮换。
- 破坏性步骤在 environment-restore.md 逐项登记还原方式。

## 8. 只读探测命令速查

| 探测目标 | 只读命令 |
|---|---|
| 仓库可见性 | `git ls-remote`（匿名探测） |
| 历史密钥 | `git log -p --all` + grep 密钥模式 |
| .git 暴露 | `curl -s https://<target>/.git/config` |
| 分支保护 | 平台 API 读保护规则 |

# CI-CD 流水线攻击面：构建系统凭据泄露、Runner 接管

> 定位：CI/CD 是「代码 → 制品 → 生产」的自动通道，一旦失陷等于把恶意代码直接送进生产。
> 本手册梳理流水线入口、构建系统凭据、Runner 接管路径与只读探测，每条路径配检测侧对照。
> 破坏性步骤标「授权内人工确认后执行」。

## 1. 攻击面

CI/CD 流水线攻击面四段：

| 段 | 形态 | 风险 |
|---|---|---|
| 入口面 | 仓库 PR/推送、外部触发、恶意提交 | 触发恶意流水线 |
| 凭据面 | 流水线内置凭据（云 AK/SK、部署密钥、token） | 凭据泄露放大 |
| 执行面 | Runner/构建机/自托管代理被接管 | 在构建机执行代码 |
| 输出面 | 制品、镜像、发布动作被篡改 | 投毒进生产 |

核心风险：流水线凭据通常有「部署到生产」的高权限，远大于开发者个人权限；Runner 常驻
构建机，接管后可持续驻留。

## 2. 暴露面探测（只读命令优先）

### 2.1 流水线与触发源只读盘点

```bash
# 以代码仓库/CI 平台的只读 API 列流水线、触发规则、密钥变量名（值需权限，先看键名）
# 通用：列仓库的 CI 配置文件（只读）
# GitHub Actions 工作流、GitLab CI 配置、Jenkinsfile 等
ls .github/workflows/ 2>/dev/null && cat .github/workflows/*.yml 2>/dev/null | grep -iE 'secret|token|key'
```

判定口径：工作流文件里直接写密钥、或引用过宽的凭据名、或 `pull_request_target` 高危触发
（不鉴权即跑）——登记。

### 2.2 流水线凭据只读盘点（看键名与作用域）

```bash
# 列 CI 平台的变量/密钥名（值不可读时看键名与保护状态）
# GitHub: 仓库 Secrets 键名、GitLab CI/CD Variables 键名与 mask/protected 标志
# Jenkins: 凭据列表（只读，有权限时）
```

判定口径：出现 `AWS_*`/`*_DEPLOY_KEY`/`KUBE_*`/`REGISTRY_*` 等部署级密钥 = 高价值目标；
`protected` 未开 = 任意分支可读。

### 2.3 Runner / 构建机只读盘点

```bash
# 自托管 Runner 列表与标签（只读）
# GitLab: runners 列表、GitHub: self-hosted runner 列表
# 看 Runner 是否跑在特权/共享构建机、是否可被外部 PR 触发
```

判定口径：自托管 Runner 被配置为可运行未审核的 fork PR = Runner 接管前置；Runner 标签
暴露了构建机用途。

## 3. 缺陷与利用路径

### 3.1 流水线凭据泄露（密钥变量可被任意分支/PR 读取）

- 缺陷：CI 密钥变量未设 `protected`/环境限定，恶意分支或 fork PR 的流水线即可读取（通过
  `echo $SECRET` 打日志、写入文件等）。
- 验证命令（只读）：读 CI 配置看密钥作用域；读工作流看是否在未受保护事件上引用密钥。
- 影响：拿到部署级密钥（云 AK/SK、registry 凭证、部署 token），横向到生产。
- 检测侧：CI 审计记录密钥变量访问/使用；云审计记录该密钥后续调用（异常源）；secret
  scanning 扫流水线日志。

### 3.2 `pull_request_target` / 未审核 PR 触发高危流水线

- 缺陷：工作流用 `pull_request_target`（GitHub）或等价机制，fork PR 触发时继承了仓库的
  `GITHUB_TOKEN` 与 secrets，恶意 PR 可直接读密钥并写主仓库。
- 验证命令（只读）：读工作流文件看 `on: pull_request_target` 及是否引用 secrets。
- 影响：未审核的外部 PR 即触发高权流水线，密钥泄露 + 主仓库投毒。
- 检测侧：CI 审计记录 PR 触发事件与密钥使用；仓库审计记录异常 PR 合入/写操作。

### 3.3 Runner / 构建机接管（自托管 Runner 执行未审核代码）

- 缺陷：自托管 Runner 接受 fork PR 的任意代码执行，且构建机未隔离、含宿主编排凭证；攻击者
  通过恶意 PR 在 Runner 上执行代码，窃取 Runner 本地的凭证/`~/.ssh`/云元数据。
- 验证命令（只读）：读 Runner 配置（是否跑未审核 fork、是否特权容器、挂载了哪些宿主路径）。
- 影响：Runner 常驻构建机，接管后窃取部署凭证、横向内网、篡改后续构建。
- 检测侧：CI 审计记录 Runner 作业执行与发起 PR；构建机主机审计（异常进程/外联/读敏感
  文件）；云审计记录构建机实例角色的异常使用。

### 3.4 流水线配置篡改（改工作流注入后门）

- 缺陷：能写仓库 CI 配置的主体（含通过 PR 触发链拿到写权限者）篡改工作流，在构建/部署
  阶段注入后门或外传密钥。
- 验证命令（只读）：读工作流文件找可疑步骤（外发请求、写密钥到日志、下载执行外部脚本）。
- 影响：恶意步骤随流水线跑进生产。
- 检测侧：仓库审计记录 CI 配置变更（谁改、改了什么）；CI 审计记录异常步骤执行；云审计
  记录部署动作。

### 3.5 构建系统自身凭据泄露（API token/部署密钥外泄）

- 缺陷：CI 平台的 API token、部署密钥提交进代码仓库或写在公开位置，攻击者复用 token 直接
  操作流水线与仓库。
- 验证命令（只读）：仓库历史搜索 token 特征（`git log -p | grep -iE 'ghp_|glpat|AKIA|BEGIN.*KEY'`）。
- 影响：token 即流水线/仓库控制权。
- 检测侧：secret scanning 命中；CI/仓库平台审计记录 token 使用与源 IP；异常调用告警。

### 3.6 流水线缓存/制品缓存投毒（跨构建污染）

- 缺陷：构建缓存（依赖缓存、层缓存、制品缓存）被投毒，后续构建复用时中招，且难定位污染点。
- 验证命令（只读）：读流水线缓存配置与复用策略；比对缓存内容与可信源 digest。
- 影响：污染跨构建扩散，进生产制品。
- 检测侧：缓存访问与同步审计；构建日志解析目标审计；制品签名验签失败记录。

## 4. 提权与持久化

- 提权链：恶意 PR → 高权流水线 → 部署级密钥 → 云账号/生产；Runner 接管 → 构建机凭证 →
  内网/云元数据 → 横向。
- 持久化（授权内人工确认后执行）：在 Runner 构建机落后门、在流水线加隐蔽步骤、追加部署
  token；逐项登记 `environment-restore.md`。

## 5. 检测与加固要点

### 5.1 检测事件名对照

| 攻击行为 | 检测层 + 事件 |
|---|---|
| 密钥被未受保护分支读取 | CI 审计密钥访问 + 云审计密钥调用 |
| 恶意 PR 触发高权流水线 | CI 审计 PR 触发事件 + 仓库审计 |
| Runner 执行未审核代码 | CI 审计 Runner 作业 + 构建机主机审计 |
| 流水线配置篡改 | 仓库审计 CI 配置变更 + CI 审计异常步骤 |
| token 外泄复用 | secret scanning + 平台审计 token 使用 |

### 5.2 加固要点

- 密钥变量按环境/分支保护（protected + 环境限定）；fork PR 禁访问 secrets。
- 高危触发用 `pull_request`（无密钥）+ 显式审核，禁 `pull_request_target` 引用 secrets。
- 自托管 Runner 隔离：容器化、不跑未审核 fork、禁挂宿主敏感路径、短生命周期临时 Runner。
- 流水线配置变更设保护分支 + 强制 Code Review；平台 token 最小权限 + 短生命周期 + 轮换。
- CI 审计与云审计联动，异常构建即告警。

## 6. MITRE ATT&CK 映射

| 技术 | ATT&CK ID |
|---|---|
| 流水线供应链投毒 | T1195 Supply Chain Compromise |
| 信任关系滥用（PR/凭据） | T1199 Trusted Relationship |
| 复用流水线凭据 | T1078 Valid Accounts |
| Runner 命令执行 | T1059 Command and Scripting Interpreter |

## 7. 证据记录要点

- 每条路径登记四要素（身份→权限→资源→影响）+ 证据编号，落 attack-paths.md。
- 流水线凭据键名、作用域、Runner 配置登记 cloud-assets.md。
- 破坏性步骤在 environment-restore.md 逐项登记还原方式。

## 8. 只读探测命令速查

| 探测目标 | 只读命令 |
|---|---|
| 流水线配置与密钥名 | 读 CI 配置文件 + 列 Secrets 键名 |
| 密钥作用域 | 读变量 protected/环境限定标志 |
| Runner 配置 | 读自托管 Runner 列表与标签 |
| 工作流触发 | 读 on 事件与 pull_request_target 引用 |

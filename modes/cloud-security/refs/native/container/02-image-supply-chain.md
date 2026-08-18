# 镜像供应链：Dockerfile 缺陷、镜像层泄露、私有仓库未授权

> 定位：镜像是把代码、依赖、配置与凭证一起打包的供应链单元。本手册梳理构建期缺陷
> （Dockerfile）、分发期泄露（镜像层/历史）、仓库访问缺陷（私有仓库未授权），以及只读
> 探测与检测侧对照。凭证发现后提示轮换，破坏性步骤标「授权内人工确认后执行」。

## 1. 攻击面

镜像供应链的攻击面分三段：

| 段 | 形态 | 风险 |
|---|---|---|
| 构建期 | Dockerfile 写死密码、ARG/ENV 传密钥、COPY 敏感文件、多阶段漏清理 | 密钥进镜像 |
| 存储期 | 镜像层与 `docker history` 保留删除过的文件、历史命令 | 历史层泄露密钥/源码 |
| 分发期 | 私有仓库未鉴权/弱鉴权、镜像标签被篡改、签名未启用/可绕过 | 越权拉取、投毒镜像 |

核心判定：一段镜像里「曾经存在过但现在删掉的秘密」仍可恢复，因为分层存储不可变。

## 2. 暴露面探测（只读命令优先）

### 2.1 私有仓库未授权探测（只读）

```bash
# 仓库 API 只读探测（各实现端点略异，核心是 /v2/ 目录与 tags）
curl -s -o /dev/null -w '%{http_code}' https://<registry>/v2/
curl -s https://<registry>/v2/_catalog                     # 列出所有镜像（未授权时高危）
curl -s https://<registry>/v2/<image>/tags/list            # 列出某镜像全部标签
```

判定口径：`/v2/_catalog` 返回镜像列表 = 仓库匿名可读（高危）；`/v2/` 200 但 catalog 403 =
 仅目录可达；返回 401 = 需认证（正常）。

### 2.2 镜像历史与层只读盘点（有镜像时）

```bash
docker history --no-trunc <image>           # 看每层的构建命令（可能含 ARG 密钥）
docker inspect <image> | jq '.[].Config.Env'   # 看 ENV 是否含明文密钥
# 层内搜索（拉取后本地只读搜索，不联网外传）
docker save <image> -o /tmp/img.tar 2>/dev/null && tar -tf /tmp/img.tar | head
```

判定口径：`docker history` 出现 `ARG AWS_SECRET_ACCESS_KEY=...` 或 `RUN ... password=` 即
密钥进层；`docker inspect` 的 `Env` 含 `*_KEY`/`*_SECRET` 即泄露。

### 2.3 镜像归属与签名只读盘点

```bash
docker trust inspect --pretty <image> 2>/dev/null   # 看是否启用内容信任/DCT
# 看镜像 digest 与标签对应（防篡改）
docker inspect <image> --format '{{.RepoDigests}}'
```

判定口径：无 RepoDigests 或无签名 = 无法证明镜像未被篡改，登记供应链风险。

## 3. 缺陷与利用路径

### 3.1 Dockerfile 构建参数传密钥（ARG 泄露）

- 缺陷：`ARG AWS_SECRET_ACCESS_KEY` + `RUN ...` 使用，或 `docker build --build-arg` 传密钥，
  值固化在镜像历史层。
- 验证命令（只读）：`docker history --no-trunc <image>` 看 ARG/ENV 行的明文。
- 影响：密钥可从镜像恢复，横向到云账号/内部系统。
- 检测侧：镜像仓库访问日志；secret scanning（扫描镜像层与历史）命中；云审计记录该密钥
  后续调用。

### 3.2 多阶段构建清理不彻底 / COPY 敏感文件

- 缺陷：非多阶段构建或中间层 COPY 了 `.env`/私钥/源码后 `rm`，但因分层仍可恢复。
- 验证命令（只读）：`docker history` 找 `COPY .env` 等步骤；拉取中间层 dump 搜索（本地）。
- 影响：历史层泄露密钥、证书、内部源码。
- 检测侧：镜像扫描工具检出层内密钥（secret scanning）；仓库拉取审计记录越权/异常 pull。

### 3.3 私有仓库未授权可拉（_catalog 泄露）

- 缺陷：仓库未开认证，或 token 服务允许匿名获取 catalog 权限。
- 验证命令（只读）：`curl -s https://<registry>/v2/_catalog` 返回镜像列表；
  `curl -s https://<registry>/v2/<image>/tags/list` 返回标签。
- 影响：拉取全部私有镜像，其中含内部应用、密钥、代码。
- 检测侧：仓库访问日志（匿名/catalog 请求）；云审计记录仓库 API 调用；网络层记录异常大
  流量拉取。

### 3.4 镜像标签漂移与未签名分发（投毒前置）

- 缺陷：`latest`/可变标签未 pin digest，未启用签名（Notary/Cosign），攻击者可替换镜像。
- 验证命令（只读）：`docker inspect --format '{{.RepoDigests}}'` 看是否 pin digest；
  `docker trust inspect` 看签名状态。
- 影响：运行时拉到的镜像可能已被投毒（后门/挖矿/凭证窃取）。
- 检测侧：仓库推送审计（异常 push/overwrite）；签名验证日志（验签失败）；运行时审计记录
  异常容器行为（外联、写敏感路径）。

### 3.5 基础镜像供应链（上游投毒）

- 缺陷：引用被投毒的基础镜像（公共仓库同名抢注、依赖镜像被篡改）。
- 验证命令（只读）：核对基础镜像 digest 与归属；SBOM 只读比对（`syft`/`grype` 生成 SBOM，
  不联网外传）。
- 影响：上游恶意代码进生产。
- 检测侧：SBOM/SCA 比对已知恶意组件；镜像仓库归属审计；运行时异常进程检测。

### 3.6 仓库缓存/代理投毒（中间层替换制品）

- 缺陷：私有仓库前置了缓存/代理（如 registry mirror、pull-through cache），缓存层被投毒或
  配置错误，上游制品被替换后所有下游拉取即中招。
- 验证命令（只读）：读缓存/代理配置与上游映射；核对拉取制品 digest 与上游一致
  （`docker pull` 后 `docker inspect --format '{{.RepoDigests}}'`）。
- 影响：投毒扩散到所有使用该缓存的下游构建与运行。
- 检测侧：缓存层访问与同步审计；制品 digest 漂移告警；运行时异常行为检测。

## 4. 提权与持久化

- 提权链：镜像内密钥 → 云/内部系统；私有仓库越权 → 拉内部镜像找密钥/源码 → 复用身份；
  镜像投毒 → 运行时后门 → 逃逸（见 `01-container-escape-paths.md`）。
- 持久化（授权内人工确认后执行）：向未鉴权仓库推送带后门镜像、篡改可变标签；逐项登记
  `environment-restore.md`。

## 5. 检测与加固要点

### 5.1 检测事件名对照

| 攻击行为 | 检测层 + 事件 |
|---|---|
| 匿名拉取 catalog | 仓库访问日志 `GET /v2/_catalog` + 匿名主体 |
| 密钥进镜像层 | secret scanning 命中（镜像扫描 CI 门禁） |
| 镜像被替换/篡改 | 仓库 push 审计 + 验签失败日志 |
| 投毒镜像运行 | 运行时审计异常进程/外联/写敏感路径 |
| 历史层密钥外泄 | 云审计记录该密钥异常调用 |

### 5.2 加固要点

- 构建：多阶段构建 + 构建后用 BuildKit secret 挂载（`--mount=type=secret`），禁 ARG 传
  密钥；`.dockerignore` 排除 `.env`/私钥。
- 仓库：开启认证与 RBAC；私有仓库禁匿名 catalog；启用签名（Cosign/Notary）+ 准入验签。
- 运行时：pin digest 拉取；SBOM 生成与漏洞扫描入 CI 门禁；运行时审计兜底。

## 6. MITRE ATT&CK 映射

| 技术 | ATT&CK ID |
|---|---|
| 镜像/依赖供应链投毒 | T1195 Supply Chain Compromise |
| 植入内部镜像 | T1525 Implant Internal Image |
| 镜像内凭证泄露 | T1552 Unsecured Credentials |
| 镜像仓库探测 | T1613 Container and Resource Discovery |

## 7. 证据记录要点

- 每条路径登记四要素（身份→权限→资源→影响）+ 证据编号，落 attack-paths.md。
- 镜像内发现的密钥脱敏引用，登记归属后提示轮换。
- 破坏性步骤在 environment-restore.md 逐项登记还原方式。

## 8. 只读探测命令速查

| 探测目标 | 只读命令 |
|---|---|
| 仓库匿名可读 | `curl /v2/_catalog` |
| 镜像历史密钥 | `docker history --no-trunc` |
| ENV 密钥 | `docker inspect` Config.Env |
| 签名状态 | `docker trust inspect --pretty` |

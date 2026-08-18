# Serverless 函数供应链与依赖投毒

> 定位：Serverless 函数把依赖打包进部署包，供应链风险从「镜像」变成「部署包 + 依赖清单 +
> 公共包仓库」。本手册梳理依赖投毒、部署包缺陷、包仓库信任链与只读探测，每条路径配检测侧
> 对照。破坏性步骤标「授权内人工确认后执行」。

## 1. 攻击面

函数供应链三段：

| 段 | 形态 | 风险 |
|---|---|---|
| 依赖源 | 公共包仓库（npm/PyPI/Maven）被抢注/投毒、锁文件缺失 | 恶意依赖进函数 |
| 部署包 | 打包进密钥/源码/本地配置、层（Layer）被篡改 | 凭证与代码泄露 |
| 分发链 | CI 打包环节被投毒、制品存储被篡改 | 运行时拉取恶意产物 |

核心风险：函数冷启动时加载的第三方依赖以函数执行角色运行，依赖投毒 = 直接拿执行角色权限。

## 2. 暴露面探测（只读命令优先）

### 2.1 依赖清单与锁文件只读盘点

```bash
# 拿部署包（只读下载到本地分析，不外传）
aws lambda get-function --function-name <f> --query 'Code.Location'
# 本地解包读依赖清单（只读）
unzip -l <pkg.zip> | grep -E 'package.json|requirements.txt|pom.xml|go.mod'
cat package.json 2>/dev/null | jq '.dependencies'        # 看依赖与版本是否锁定
```

判定口径：依赖清单无锁文件（`package-lock.json`/`requirements` 未 pin 版本）= 可被上游
新版本投毒；命中已知恶意包名/版本 = 供应链失陷。

### 2.2 层（Layer）与运行时只读盘点

```bash
aws lambda list-layers --query 'Layers[].{name:LayerName,arn:LayerVersionArn}'
aws lambda get-function --function-name <f> --query 'Configuration.Layers'
```

判定口径：引用了非官方/共享 Layer = 需核对 Layer 归属与内容；Layer 内可能带恶意代码或
凭证。

### 2.3 部署包内容只读扫描

```bash
# 本地解包搜密钥与可疑文件（只读，不外传）
unzip -l <pkg.zip> | grep -iE '\.env|\.pem|id_rsa|credentials|token'
```

判定口径：部署包含 `.env`/私钥/凭证文件 = 打包泄露（高危）。

## 3. 缺陷与利用路径

### 3.1 依赖未锁定 → 上游版本投毒

- 缺陷：`requirements.txt`/`package.json` 用范围版本（`^1.0.0`、`>=1.0`）或未提交锁文件，
  上游包被投毒后，函数重建时自动拉入恶意版本。
- 验证命令（只读）：读依赖清单看版本是否 pin；比对部署包内实际安装版本与清单。
- 影响：恶意依赖以执行角色运行，窃取环境变量/凭据/内部数据。
- 检测侧：依赖扫描（SCA）在构建/部署期检出；函数日志记录异常网络外联；云审计记录函数
  执行角色的异常资源访问。

### 3.2 公共包抢注 / 拼写混淆（typosquatting）

- 缺陷：依赖名被抢注或依赖了拼写相近的恶意包，开发者误装。
- 验证命令（只读）：依赖清单与官方已知恶意包清单比对；核对包源仓库归属（只读查询）。
- 影响：恶意包代码进函数。
- 检测侧：SCA 恶意包告警；函数运行时异常行为（外联/写文件）；仓库下载日志。

### 3.3 部署包打包泄露密钥与源码

- 缺陷：打包脚本把 `.env`、私钥、测试密钥、源码 `.git` 目录打进部署包。
- 验证命令（只读）：`unzip -l` 搜敏感文件名；`get-function` 下载包本地扫描。
- 影响：部署包可被读权限者拿到密钥与源码。
- 检测侧：云审计记录部署包下载（`GetFunction` Code.Location 访问）；secret scanning 扫
  部署包；制品存储访问审计。

### 3.4 Layer 投毒 / 共享层未审计

- 缺陷：函数引用了第三方/共享 Layer，Layer 内含恶意代码或过期漏洞组件，且无归属审计。
- 验证命令（只读）：`list-layers` + `get-function` 读 Layers；核对 Layer 归属与版本。
- 影响：恶意 Layer 代码以执行角色运行。
- 检测侧：Layer 发布/引用审计；运行时异常行为；依赖/漏洞扫描覆盖 Layer。

### 3.5 CI 打包环节被投毒

- 缺陷：CI 流水线被接管后，在构建期注入后门或替换制品（与 cicd 手册联动
  `../cicd/01-pipeline-attack-surface.md`）。
- 验证命令（只读）：核对制品 digest 与构建记录；CI 配置只读盘点。
- 影响：运行时拉取恶意制品。
- 检测侧：CI 构建审计 + 制品签名验签；云审计记录制品存储异常写入。

### 3.6 私有包代理/缓存投毒（内部依赖源被污染）

- 缺陷：组织私有包代理（npm/PyPI/Maven 镜像）被投毒或缓存了恶意版本，后续所有函数构建
  自动拉入。
- 验证命令（只读）：读私有代理配置与上游映射；比对缓存包版本与上游；函数依赖锁定状态。
- 影响：恶意依赖扩散到所有函数。
- 检测侧：代理访问与缓存审计；SCA 告警；构建日志解析目标审计；制品签名验签。

## 4. 提权与持久化

- 提权链：恶意依赖/Layer → 函数执行角色 → 云资源越权 → 横向；部署包密钥 → 云/第三方系统。
- 持久化（授权内人工确认后执行）：投毒私有包仓库让后续函数自动中招；在 Layer 植入后门。
  逐项登记 `environment-restore.md`。

## 5. 检测与加固要点

### 5.1 检测事件名对照

| 攻击行为 | 检测层 + 事件 |
|---|---|
| 恶意依赖安装 | SCA 构建期告警 + 函数日志异常外联 |
| 部署包下载 | 云审计 `GetFunction`（Code.Location）+ 制品存储访问审计 |
| 部署包密钥泄露 | secret scanning 扫部署包/层 |
| Layer 引用异常 | 云审计 `UpdateFunctionConfiguration`（Layers 变更） |
| 制品替换 | CI 构建审计 + 制品验签失败 |

### 5.2 加固要点

- 依赖锁定（锁文件 + 固定版本）+ 私有包代理 + SCA 扫描入 CI 门禁。
- 部署包最小化（排除 `.env`/私钥/`.git`）；用 Layer 分离依赖并审计其归属。
- 制品签名（Sigstore/Cosign）+ 运行时验签；部署包存储私有 + 访问审计。
- 函数运行时开启异常行为监控（外联白名单、写敏感路径告警）。

## 6. MITRE ATT&CK 映射

| 技术 | ATT&CK ID |
|---|---|
| 依赖/部署包供应链投毒 | T1195 Supply Chain Compromise |
| 制品篡改 | T1601 Modify System Image |
| 信任关系滥用 | T1199 Trusted Relationship |

## 7. 证据记录要点

- 每条路径登记四要素（身份→权限→资源→影响）+ 证据编号，落 attack-paths.md。
- 依赖清单、SBOM、部署包扫描结论登记 evidence-index.md。
- 破坏性步骤在 environment-restore.md 逐项登记还原方式。

## 8. 只读探测命令速查

| 探测目标 | 只读命令 |
|---|---|
| 依赖清单 | 部署包解包读 package.json/requirements.txt |
| Layer 盘点 | `list-layers` / `get-function` Layers |
| 部署包密钥 | `unzip -l` 搜 .env/私钥 |
| SBOM | `syft`/`grype` 本地生成 |
| 私有代理配置 | 读私有包代理上游映射与缓存策略 |
| 制品签名验签 | `cosign verify` / 准入验签日志只读查询 |

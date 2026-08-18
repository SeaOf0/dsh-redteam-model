# semgrep-oss — 开源静态审计规则集（离线分发）

本目录存放从开源 semgrep 规则库挑选的 **security 类** 规则，供 code-audit 预设离线使用。所有规则均为 `category: security` 且带 CWE 映射，可被 `semgrep --config <文件/目录>` 直接消费。

---

## 1. 来源与版本

| 项 | 值 |
|---|---|
| 上游仓库 | [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules)（原 returntocorp/semgrep-rules，主体） + [trailofbits/semgrep-rules](https://github.com/trailofbits/semgrep-rules)（二批） |
| 快照 commit | `f4b63d53728515b8af24bb6dd5b11eb015f23871` |
| 快照时间 | 2024-05-20T08:25:09Z（`chore: fix some typos in comments (#3354)`） |
| 下载方式 | `codeload.github.com` tarball（semgrep-rules 锁定 commit f4b63d5；trailofbits 取 main 分支快照 2026-08-17） |

> **为何锁定此 commit**：该仓库是一个滚动发布、无 tag/release 的规则库。`f4b63d5…` 是**最后一个仍采用 LGPL-2.1 许可的 commit**——紧随其后的 `80137c2932`（2024-05-20T14:05:49Z）把 LICENSE 替换为专有的 *Semgrep Rules License v1.0*。详见下文许可说明。

---

## 2. 许可证结论（各源）

| 规则源 | 许可证 | 能否给 semgrep 直接用 | 本批是否纳入 |
|---|---|---|---|
| **semgrep/semgrep-rules**（本次快照） | **LGPL-2.1 + Commons Clause v1.0** | ✅ YAML 规则 | ✅ 主体（788 条） |
| semgrep/semgrep-rules（当前 develop HEAD） | **Semgrep Rules License v1.0**（专有，**禁止再分发**） | ✅ YAML 但**不可分发** | ❌ 弃用 |
| PyCQA/bandit | Apache-2.0 | ❌ Python 原生 `.py` 检查器，非 semgrep 规则 | ❌ 仅知识参考 |
| securego/gosec | Apache-2.0 | ❌ Go 原生规则，非 semgrep 规则 | ❌ 仅知识参考 |
| github/codeql（security queries） | MIT | ❌ QL 语言，semgrep 无法解析 | ❌ 仅知识参考 |
| ZupIT/horusec | Apache-2.0 | ❌ 自有引擎，非 semgrep 规则 | ❌ 仅知识参考 |
| trailofbits/semgrep-rules | AGPL-3.0 | ✅ YAML 规则 | ✅ 二批纳入（118 文件/120 条，附其 LICENSE；内部分发合规：随附许可声明、保留署名、未修改；若对外/SaaS 化需再评估 AGPL 义务） |

### 关键结论：semgrep-rules **不是** LGPL-2.1，而是 LGPL-2.1 + Commons Clause，且现已变专有

- **历史（本快照采用）**：`LICENSE` = *Commons Clause v1.0* 叠加在 *LGPL-2.1* 之上。Commons Clause 仅限制「将规则作为产品/服务向第三方收费出售（Sell）」，**不禁止**内部分发、二次分发（非卖品）、修改（需保留署名并标注修改）。
- **现状（develop HEAD）**：*Semgrep Rules License v1.0* 明确「`does not allow you to distribute the rules`」「`internal business purposes only`」——**禁止再分发**，与本预设「离线分发、任何机器可用」的诉求冲突，故**不可**采用当前 HEAD。

**内部分发合规性**：本次快照处于 LGPL-2.1 + Commons Clause 许可下。预设内部交付、离线审计属于「内部业务用途 + 非卖品分发」，符合许可；本目录已随附上游 `LICENSE` 原文（Commons Clause + LGPL-2.1 声明）以满足「复制须随附许可声明」的要求。若未来要**对外商业化**这些规则，需改用其他许可源或重新评估。

---

## 3. 规则数量统计（共 1080 条 / 1078 个规则文件：semgrep-rules 788 + trailofbits 120 条〔118 文件〕 + gitleaks 172）

| 语言目录 | 规则数 | 说明 |
|---|---|---|
| `java/` | 115 | 含 spring / servlets / rmi / jax-rs / android / jboss / jjwt / mongodb / lang 等 security 规则 |
| `python/` | 185 | 含 django / flask / sqlalchemy / jwt / jinja2 / cryptography / pycryptodome / lang 等（裁剪后） |
| `javascript/` | 161 | 含 express / react / angular / node 生态 / browser / lang 等 |
| `typescript/` | 13 | 含 angular / nestjs / react / lang |
| `php/` | 59 | 含 lang / doctrine / laravel / symfony / cakephp / wordpress 等 |
| `go/` | 66 | 含 lang / gorm / grpc / gorilla / jwt-go / aws-lambda 等 |
| `c/` | 12 | 内存安全 / UAF / double-free / 格式串 等 |
| `csharp/` | 48 | 含 dotnet / lang / razor 等 |
| `ruby/` | 69 | 含 rails / brakeman / lang / aws-lambda 等 |
| `trailofbits/` | 118 文件/120 条 | Trail of Bits 安全规则：python 24 / yaml 24（ansible·docker-compose·github-actions 凭据与不加密 URL）/ go 18 / generic 17 / ruby 15 / hcl 9（terraform·nomad 配置）/ javascript 7（apollo-graphql CSRF/CORS）/ jvm 2 / rs 1 / swift 1 |
| `generic/` | 232 | 49 条 `secrets/security/`（通用密钥/凭据检测）+ 11 条 `nginx/`（配置安全）+ **172 条 `secrets/gitleaks/`（厂商专属密钥枚举）** |
| **合计** | **1080 条**（1078 文件） | semgrep-rules 788 保持 ≤800 上限；二批（trailofbits/gitleaks）经用户确认补入 |

---

## 4. 挑选标准

1. **仅 security**：只取 `category: security` 的规则；跳过 correctness / performance / best-practice / style 类（这些在上游的 `*/correctness`、`*/best-practice` 目录，未纳入）。
2. **CWE 映射优先**：本快照内所有 security 规则均带 `cwe:` 元数据，天然满足「CWE 映射存在优先」。
3. **语言覆盖对齐审计手册**：java、python、php、javascript/typescript、go、c/cpp、csharp、ruby、generic（配置/secret）。
4. **单语言上限 ~200、总量 ≤800**：优先保留高价值类别（RCE / SQLi / SSRF / XXE / XSS / 反序列化 / 路径穿越 / 密钥泄露 / 弱加密）。
5. **本地落盘**：仅复制 `.yaml` 规则文件（不含上游测试用例 `.java/.py/.go/.php/.txt` 夹具），离线可用。

### 扩展规则源

- **trailofbits/semgrep-rules**：全量纳入（仅排除 `*.test.yaml` 测试夹具与非规则文件）——Trail of Bits
  审计实战规则，全部 `category: security` + CWE，与 semgrep-rules 快照互补（Go 并发/ETH、
  HCL 基础设施、GitHub Actions 凭据、Ansible 不加密 URL 等盲区）。
- **gitleaks 厂商密钥枚举**：semgrep-rules 快照的 `generic/secrets/gitleaks/` 172 条
  （AWS/GCP/Azure/Slack/Stripe/Adafruit/… 等厂商 token 正则），上批因预算未纳入，本批补入。

### 明确裁剪项（可复现）

- **python**：剔除 `pyramid/`（cookie 标志类）、`lang/security/audit/insecure-transport/`（INFO 级 HTTP/urllib/SSL）、`*-tainted-env-args.yaml`（env-args 污点重复项）、`aws-lambda/security/`（与 lang 核心 RCE/SQLi 冗余）、`airflow`/`fastapi`/`docker` 单条、以及 11 条「detected/冷门库」（telnetlib/ftplib/sh/dask/mako 等）。
- **ruby**：剔除 `rails/security/audit/xss/templates/`（模板重复项）、已废弃的 Rails 3 mass-assignment（`model-attr-accessible` 等）、低价值（divide-by-zero / 反向 tabnabbing / HTTP verb 混淆等）。
- **generic**：仅保留 `secrets/security/`（通用 `detected-*` 密钥检测）与 `nginx/` 配置；上游 `secrets/gitleaks/`（172 条厂商专属密钥枚举）因预算未纳入，可按需补充。

---

## 5. 验证结果

使用 `semgrep 1.172.0` 的 `semgrep --validate --config <路径>` 逐语言目录全量校验（覆盖全部 788 条，0 配置错误）：

```
PASS  java        (115 rules)
PASS  python      (185 rules)
PASS  javascript  (161 rules)
PASS  typescript  ( 13 rules)
PASS  php         ( 59 rules)
PASS  go          ( 66 rules)
PASS  c           ( 12 rules)
PASS  csharp      ( 48 rules)
PASS  ruby        ( 69 rules)
PASS  generic     ( 60 rules)
TOTAL_VALIDATED = 788
```

- 一批：逐语言目录全量 **10/10 目录、788/788 条通过，0 配置错误**；抽验单文件 18/18。
- 二批：`trailofbits/` 目录级 **120 条通过**；`generic/secrets/gitleaks/` 目录级 **172 条通过**。

---

## 6. 与本地自建规则的边界

本目录（`semgrep-oss/`）为**上游开源规则快照**，与预设自建规则**互不重叠、互不引用**：

- 自建 Java 规则：`refs/lang/java-audit/semgrep-rules/`（约 400 条，含 frontend-config / java-* / js-security / react-security / vue-security）。
- 自建 PHP 规则：`refs/lang/php-audit/semgrep-rules/`。

自建规则在 `refs/lang/*-audit/` 下，本目录在 `refs/standards/` 下，物理隔离。两者可叠加使用，但需注意：上游 `java/`、`php/` 规则与自建规则可能存在**同义覆盖**（例如上游 `php/…/exec-use` 与自建 `php-cmd-sink` 语义相近），审计时以「取并集 + 人工去重」为准。

---

## 7. 目录结构

规则按语言分目录，语言目录内保留上游相对子路径（如 `java/lang/security/audit/…`、`python/django/security/…`），以便溯源与后续增量更新。

```
semgrep-oss/
├── LICENSE            # 上游许可原文（Commons Clause + LGPL-2.1）
├── README.md          # 本文件
├── java/
├── python/
├── javascript/
├── typescript/
├── php/
├── go/
├── c/
├── csharp/
├── ruby/
├── trailofbits/            # AGPL-3.0（附 LICENSE）：Trail of Bits 审计规则 118 文件
│   ├── python/ go/ ruby/ javascript/ jvm/ rs/ swift/ generic/ yaml/ hcl/
└── generic/
    ├── secrets/security/   # 通用密钥/凭据检测
    ├── secrets/gitleaks/   # 172 条厂商专属密钥枚举（二批）
    └── nginx/              # nginx 配置安全
```

---

## 8. 更新与再生成

如需更新或补充规则：

```bash
# 重新拉取同一快照（或改用其他 commit，注意许可边界）
curl -sSL -o /tmp/sr.tar.gz \
  https://codeload.github.com/semgrep/semgrep-rules/tar.gz/f4b63d53728515b8af24bb6dd5b11eb015f23871
tar -xzf /tmp/sr.tar.gz -C /tmp
```

- **禁止**直接采用 `develop`/`master` HEAD（专有 *Semgrep Rules License v1.0*，禁止再分发）。
- 如需「更宽松许可」的补充源，可评估 `trailofbits/semgrep-rules`（AGPL-3.0，Go/Python/C/JS 安全规则）。

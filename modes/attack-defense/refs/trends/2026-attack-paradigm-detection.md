---
name: 2026-attack-paradigm-detection
description: >
  2026 攻击新范式与检测对照（社区核源）：边界设备出血（Citrix Bleed 2 / FortiBleed——snprintf
  残留泄露类与防火墙僵尸化运维）、勒索铁三角（BYOVD 杀 EDR → 供应链凭据 → RMM 走内网）、
  Containerd 检查点逃逸。每项按「攻击机理 × 检测/加固对照」成对呈现，供攻防评估的攻击面选择
  与 detection gap 设计两头用。
domain: cybersecurity
subdomain: attack-defense
tags: [edge-device, citrix-bleed, fortibleed, byovd, rmm-abuse, ransomware, detection-gap, 2026]
version: 1.0.0
---

# 2026 攻击范式与检测对照（先知/补天核源）

> 三篇社区深析的合并提炼：forum.butian.net/share/4949（边界设备）、/share/4948（勒索铁三角）、
> /share/4954（Containerd）。**共同主题：攻击者全程踩在"合法"区域——检测范式必须从
> "识别恶意"转向"定义正常"。**

## 1. 边界设备出血（Citrix Bleed 2 × FortiBleed）

### 攻击机理（红队攻击面）

- **CVE-2025-5777（Citrix Bleed 2）**：`snprintf` 返回值语义债——返回"本应写入的长度"而非
  "实际写入长度"，发送长度被当真 → 超长 Host 头（0x6000）触发后 **18KB 栈残留随响应吐出**
  （NSC_USER/NSC_TASS 等他人活跃会话令牌）；端点 `/nf/auth/startwebview.do` 无需认证；
  与 Heartbleed 同族的"残留数据泄露"类（内存释放不清零 + 发送长度未验证）；
- **Host 长度限制绕过**：`Host: foo.foo.foo...foo.example.com`（foo.×3000）——协议合法的
  超长子域名，中间件长度校验失效；
- **FortiBleed 哲学**：不利用漏洞——43 万台 FortiGate 当僵尸节点**运维**：CLI 合法命令集内
  （`diagnose sniffer packet`）抓包、存凭证、分类定价，1.1 亿条 VPN 密码进地下市场，
  **同一操作员同时供 INC Ransom 与 Lynx 两家勒索团伙**；
- **市场融合**：FortiBleed 凭证（入口清单）× Citrix Bleed 2（万能钥匙）交叉销售——
  买家两样都买，数小时内从零到勒索。

### 检测与加固对照（detection gap 设计）

| 面 | 检测/加固 | 原理 |
|---|---|---|
| 内存泄露类通用 | **响应大小异常告警**（反向代理/WAF 层，该端点正常响应 <几 KB，>几十 KB 即断+人审） | 比 IoC 签名有效：Bleed 3 换端点/触发方式，只要泄内存响应就异常变大 |
| 补丁优先级 | VPN/认证边界设备 = **域控同级**（CISA 对 Bleed 2 只给 1 天窗口） | "所有暴露在认证之前的代码路径都是下一个 Bleed 候选" |
| 令牌生命周期 | 会话超时 8-24h → **2-4h + 强制重认证** | 缩小泄露令牌的可利用窗口 |
| FortiGate 失陷 | `execute log display category event` 查异常 IP admin 登录；**非维护窗口的 sniffer 命令执行**=强入侵信号 | 攻击在合法 CLI 内，只能靠行为基线 |
| 日志完整性 | 设备日志实时转发外部不可篡改 SIEM | 攻击链第七步是清审计日志 |

## 2. 勒索铁三角（BYOVD → 供应链凭据 → RMM）

### 攻击机理

- **范式**：`[BYOVD 杀 EDR] → [供应链凭据进大门] → [RMM 工具走内网]`——内核层拔牙/正门进/合法通道；
- **BYOVD 2026 白菜化**：54 个勒索家族在用、35 个被滥用签名驱动；RaaS 从加购项变**基础套餐标配**；
- IOCTL 滥用机理：硬件厂商把设备 DACL 设"所有人可读写"+ IOCTL 无调用者校验 → 管理员权限即可
  让驱动代劳 `ZtTerminateProcess`/清内核回调/物理内存读写（无需 SYSTEM 提权链）；
- 形态演进：Reynolds（驱动加载+杀 EDR+加密一条龙单文件）→ GentleKiller（**400+ 安全产品进程
  死亡名单**逐个强杀）；PoC 清单见 github.com/BlackSnufkin/BYOVD（CVE-2025-52915/1055、
  2026-3609/8501 等）；
- **RMM 滥用**：TeamViewer/AnyDesk/SimpleHelp/SuperOps——企业自己授权的白名单工具当横向通道，
  全程无"恶意"工具。

### 检测与加固对照

| 面 | 检测/加固 | 原理 |
|---|---|---|
| BYOVD | **驱动加载 × 进程终止的时序关联**进 SIEM：刚加载 2019 年主板工具驱动 → EDR 进程终止 | 纯时序异常关联，不依赖签名验证/行为特征——最强告警信号 |
| BYOVD | EDR 之外的独立管道：TPM 2.0 远程证明、Secure Boot 日志上报 | EDR 被杀后 SIEM 仍能看到"白名单外内核驱动加载" |
| RMM | **RMM 行为基线三问**：何时连（维护窗口）/从哪连（IP 归属）/连上干什么（装软件 vs vssadmin delete shadows） | 周六凌晨东欧 IP 的 TeamViewer 会话+首连即 vssadmin = 高优告警 |
| 凭证 | VPN/设备管理密码定期轮换、禁默认凭证、系统间不同密码 | 1.1 亿条凭证里大量两年未换/一密打通关 |

### 范式结论（评估报告引用级）

> "铁三角"每一项都在利用"正常"与"恶意"的灰色地带——BYOVD 是合法签名驱动、RMM 是企业授权软件、
> 供应链凭据是合法会话。**基于"攻击者会用恶意工具"前提的检测模型全部失效；防御核心是定义什么是
> 正常，然后标记所有偏离。**（Anubis 完整攻击链：Arctic Wolf 2026-07 报告）

## 3. Containerd 检查点逃逸（2026）

- 主题：容器运行时 checkpoint/restore（CRIU）机制的逃逸面（forum.butian.net/share/4954 系列）；
- 评估挂点：容器链路评估时把 checkpoint 功能开启状态纳入攻击面枚举；细节读原文。

## 来源

- [补天 — 边界设备在出血：Citrix Bleed 两次死亡轮回与 FortiBleed 的 43 万台僵尸墙](https://forum.butian.net/share/4949)
- [补天 — 勒索软件的"铁三角"：当攻击者开始用你家管理工具打你](https://forum.butian.net/share/4948)
- [补天 — Containerd 容器逃逸系列：2026 年容器运行时的"检查点"危机](https://forum.butian.net/share/4954)
- 关联：Arctic Wolf Anubis 报告（2026-07）、SOCRadar FortiBleed 凭证市场证据、watchTowr Labs Bleed 2 技术分析

---
name: ai-assisted-hunting
description: >
  AI 时代的非预期漏洞挖掘技巧集：报错吐凭证、CDN 桶→真实桶溯源、base 服务业务语义枚举、
  业务字段字典构造、动态占位符参数构造、WAF 绕过无限推理。来源为 2026 社区实战案例提炼，
  供 agent 在挖掘阶段主动套用「目标驱动 + 非预期路径」的思路扩展攻击面。
domain: cybersecurity
subdomain: web-security
tags: [ai-assisted, hunting, unexpected, oauth, storage-bucket, fuzzing, waf-bypass]
version: 1.0.0
---

# AI 辅助非预期挖掘技巧集

> 来源：奇安信攻防社区《AI 渗透初探：从零开始的实战赋能记录》（forum.butian.net/share/4944，2026）。
> 定位：这不是「AI 使用教程」——本模式自身就是 AI。这里收的是**人机协同实战中被验证的非预期突破案例**，
> 每条给「入口特征 → 非预期路径 → 落地验证」，供挖掘卡壳时逐条对照。

## 核心理念：目标驱动，不给打法

- 卡壳时的提示词策略不是「怎么测 X」，而是**给目标 + 边界，让推理自由展开**（目标：拿到该接口可用
  凭证；边界：只读/最小影响）。多条非预期突破都产生于「人工定目标、AI 找路径」的分工。
- 交替节奏：人工一步（发现攻击面）→ AI 一步（无限推理落地）→ 人工判断（真伪/价值）→ 分析总结。
  AI 步产出的「报错、时间差、语义联想」是主要增量来源。

## 技巧 1：报错吐凭证（fuzz 的非预期出口）

- 入口：小程序/接口需要 code 换 token（`/wechat/miniapp/getTokenByWechat` 类），正常 fuzz 值全无效。
- 非预期路径：把 code 值换成 `x\n\r` 等畸形值触发后端异常——**异常栈/回显带出 access_token 与 secret**。
- 判据：任何「输入被下游服务消费」的参数（code/ticket/token/key），常规字典打完不收工，
  补一轮**畸形值/控制字符/类型错位**（`x\n\r`、超长、数组、对象）打报错面。

## 技巧 2：CDN 桶 → 真实桶溯源

- 入口：存储桶经 CDN 分发（`hash.cdn.example.com`），桶遍历可见但翻页参数（list-type=2/max-keys）全失效。
- 非预期路径：CDN 层存储桶是**阉割 API**（无翻页）——放弃翻页转而**找未分发的原生桶域名**：
  以企业域名构造三级域名字典碰撞（s3/oss/cos/deliver 等前缀 × 主域），原生地址 `/deliver` 路径内容
  与 CDN 域一致即打正；原生桶翻页可用 → 枚举出 metrics 桶 → **桶访问日志里记录全部桶名**（200+）→
  桶名作字典再 Fuzz。
- 判据：遇 CDN 化的存储资产，「绕过 CDN 限制」与「找源站」两条路都要走；日志类桶是资产图的富矿。

## 技巧 3：base 服务业务语义枚举

- 入口：已知一个 base 路径（`/ly-ms/application`），其后端服务体系还有兄弟模块。
- 非预期路径：按业务语义构造 base 字典（`/ly-ms/user`、`/ly-ms/admin`、`/api`、`/admin-api`…）批量探测
  → 新 base 下挂 heapdump/swagger → heapdump 解析拿云凭证（CAM/AK-SK）→ 权限大的直接接管云资产
  （实战案例：33 台云服务器）。
- 判据：**heapdump 是最高价值单点**——任何 base 服务都值得专门 fuzz 一轮 heapdump；
  JS（含异步/内嵌）+小程序反编译产物是 base 枚举的语料源。

## 技巧 4：业务字段字典构造（替代公开字典）

- 入口：四级长路由（`/a/b/c/very-long-action`），公开字典命中率趋零。
- 非预期路径：从 JS/接口清单提取业务实体名（category/appKey/option…）按路由风格生成组合字典；
  语义贴合度远高于通用字典；联动 Burp（MCP/上游代理）实时看命中。
- 判据：长路径/业务化路由的 fuzz 一律走「业务语料构造」而不是通用字典；企微 token 泄露类接口
  （`/qywx/api/auth/fetchAccessToken`）就是业务字典打出来的。

## 技巧 5：动态占位符参数构造

- 入口：JS 里挖到路由模板 `{{xxx}}`（`/api/category/{{category}}/options`），参数与动态段未知。
- 非预期路径：从 JS 上下文语义构造动态段值（分类名、数字 uid、key 枚举），直接未授权增删改查。
- 判据：JS 分析产出「接口骨架」后不终止——动态段的**取值域**也从同一 JS 的常量/枚举里构造。

## 技巧 6：WAF 绕过的推理式生成（报错盲注形态）

- 入口：order by/sort 参数报错定位为注入点，WAF 拦截常规 payload。
- 实战产出形态（腾讯云 WAF 实测过）：`rand(exp(44-(crc32((database()))>=2614572253)))` ——
  嵌套函数（crc32 比较→布尔→算术→rand 回显）绕特征。
- 判据：绕 WAF 的思路扩到「不常见函数组合」：报错/布尔/时间盲的载体函数族轮换
  （crc32/exp/rand/log/conv…），而不是只在注释与编码层变体。

## 来源

- [奇安信攻防社区 — AI 渗透初探：从零开始的实战赋能记录](https://forum.butian.net/share/4944)

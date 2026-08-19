---
name: capability-primitive-chaining
description: >
  能力原语拼图与状态空间搜索：把每个发现抽象成能力原语（read/write/exec/ssrf/cred…），
  用 RCE 等式与低危→原语映射表组链，正反向搜索推导攻击链。用于「扫不到单点大洞」的
  僵局破解——RCE 不是一个漏洞，是一组能力凑齐后的涌现。
domain: cybersecurity
subdomain: offensive
tags: [chaining, primitives, low-severity-abuse, attack-path, rce]
version: 1.0.0
---

# 能力原语拼图（僵局破解思维）

> 心法：没有单点 RCE/反序列化/上传 ≠ 打不动。任务不是「找 RCE 漏洞」，是**凑齐执行所需的原语**——
> 几个 info/低危拼出代码执行是常态。与十二面挖掘面互补：十二面按漏洞类型展开，本文件按**能力拼图**展开。

## 1. 原语抽象

把每个发现不记成「漏洞 X」，记成「**现在拥有什么能力 + 限制**」：

```
read(path)  write(path)  exec(cmd)  ssrf(url)  sqli  redirect(url)  eval_expr
idor(id)  cred(svc,priv)  coerce_auth  write_acl  upload(ext,path)
```

## 2. RCE 等式（满足任意一条即成）

| 等式 | 条件组合 |
|---|---|
| A | 能写文件 + 文件被当代码执行 |
| B | 能控配置/env + 配置指向你的代码 |
| C | 能进管理面 + 面板自带执行功能（不是漏洞，是功能） |
| D | 有凭据 + 服务有合法执行入口（滥用合法功能） |
| E | 能任意读 + 读到凭据 + 凭据可登录执行点 |
| F | 能控数据 + 数据流入危险 sink（eval/模板/SQL） |

## 3. 低危 → 原语映射（「鸡肋」翻译成拼图碎片）

| 低危发现 | 翻译 | 喂给等式 |
|---|---|---|
| info 泄露（.git/备份/堆栈） | 源码/路径/密钥 | B/E/F |
| LFI/任意读 | 读配置密钥；或日志投毒 | E / A |
| SSRF（哪怕只 GET） | 打内网 Redis/Consul/K8s/云元数据；元数据临时凭据 | C / D |
| 弱/默认/复用凭据 | 进带任务/插件/webhook/CI 功能的后台 | C |
| CORS/CSRF/XSS | 借管理员浏览器调执行类功能 | C |
| 可控上传（哪怕限扩展名） | 配路径穿越/解析差异/.htaccess | A |
| 配置写入 | 改模板/日志/连接串 | B |
| SQLi（哪怕只读） | 读 hash/密钥；或 OUTFILE | E / A |
| 模板可控 | SSTI | F |
| 原型污染 | 污染下游属性 | F |

## 4. 状态空间搜索（无现成链时）

- **正向**：对每个能力问「能解锁什么」；对每对能力问「组合出什么」
  （read+write=改配置；ssrf+内网 Redis=RCE；sqli+FILE 权限=webshell；idor+mass-assign=改他人 admin）；
- **反向**（卡住时主用）：锁定目标=执行命令 → 选最接近现状的等式当模板 → 缺哪个原语设为子目标 →
  手上哪个低危/功能/info 泄露能凑出它 → 凑不出就递归拆或换等式 → **正反向在中间相遇=完整链浮现** →
  逐段验证；
- 纪律：推导出的链是**假设**（标「疑似」记入台账），逐段实际执行+证据后才 confirmed。

## 5. 突破口清单（看到别走开）

- **功能即原语**：后台的任务计划/插件/模板编辑/SQL 控制台/文件管理器/导入导出/webhook——
  合法功能，登进去就是现成的执行/读写原语。视角里没有「功能/漏洞」之分，只有「能力」；
- **跨协议跳跃**：SSRF 的 gopher/dict/file 把「只能发 HTTP」变成「打 Redis/发 SMTP/读文件」；
- **凭据复用是万能胶**：任意一处拿到的密码/key 默认全网复用全部喷一遍——横向常比纵向快；
- **解析差异**：上传校验/路由/反代三方理解不一致的缝隙里有绕过（双扩展名/编码/Host 混淆）；
- **时间维度**：TOCTOU/token 可预测/缓存投毒——把「偶尔」变「稳定」，把不可利用变可利用；
- **跨域兑现**：每拿一个能力问「它在别的域值多少钱」——Web SSRF→云元数据接管账户；
  APK 硬编码→直连内部 API 绕前端鉴权；供应链→CI 密钥进生产；
- **创造模式**（已知组合用尽时）：重审能力边界（只能读 /var/log？/proc/self/environ 呢）；
  找等价 RCE 的 sink（写 crontab/.bashrc/CI 配置/LD_PRELOAD/authorized_keys/systemd unit 都=RCE）；
  把信息差当侧信道（报错/时序/响应长度）；假设取反——列「我以为不可能」逐条问「凭什么不可能」。

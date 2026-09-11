# OSINT 情报源操作手册 (S0/S1 阶段用)

自动化 API 只覆盖测绘平台; 企业架构/备案细节/DNS 历史这些半自动源按本手册走 (浏览器 MCP 或带频控脚本)。

---

## 1. 企业架构: 母公司 → 二级子公司 (含控股比例)

授权范围通常给母公司名, 子公司清单要自己挖:

| 渠道 | 用法 | 拿到什么 |
|---|---|---|
| **爱企查 aiqicha.baidu.com** | 搜公司全称 → 公司详情页 → "对外投资"标签 | 被投企业名/投资比例/注册资本 — **控股比例字段直接给** |
| 企查查/天眼查 | 同上, 付费墙更紧 | 同上 |
| 国家企业信用信息公示系统 gsxt.gov.cn | 官方权威, 滑块验证码硬 | 股东与出资 |
| 母公司官网"关于我们/成员企业" | 静态页面直接爬 | 成员企业名单(常有链接到子公司域名) |
| 年报/招股书/债券募集说明书 | 巨潮资讯 cninfo.com.cn 搜母公司 | 最权威的子公司+持股比例清单 |

**爱企查半自动技巧 (浏览器 MCP)**:
1. 打开 `https://aiqicha.baidu.com/s?q=<公司全称>` 拿到 pid;
2. 详情页 `https://aiqicha.baidu.com/company_detail/<pid>` 页面源里 `window.pageData` 是整页 JSON, 含对外投资数组(投资比例字段 ratio);
3. 取 `ratio >= 50%`(控股) 或授权书口径的企业名单 → 填 scope.json units。
4. 反爬: 频控明显, 每页停 3~5s, 触发验证码就换浏览器指纹或手工。

**名称变体枚举**: 子公司注册名 ≠ 品牌名 (如"中化化肥有限公司"≠"中化化肥"); 备案主体名用注册全称搜, 品牌名给关键词打分用。

## 2. 备案 (ICP) 查询渠道矩阵

| 渠道 | 自动化 | 说明 |
|---|---|---|
| FOFA `icp=` / Hunter `icp.number=` / Quake `icp:` | ✅ 全自动 | **首选**, 反查即得资产; 先有备案号 |
| beianx.cn | 半自动 | `s1_scope_tools.py --beianx <domain>` 尽力抓; 频控严 |
| 站长工具 ICP chinaz | 半自动 | 浏览器查, 有 API 付费版 |
| 工信部 beian.miit.gov.cn | ❌ 手工 | 登录+验证码墙; 终审判例以它为准 |
| 天眼查/企查查备案标签 | 半自动 | 主体→备案域名列表最全 |

**闭环用法**: 爱企查拿主体名 → 工信部/天眼查拿主体备案号 → 填 scope.json icp 字段 → s2 跑 ICP 反查拉全资产 → `s1 --icp-census` 反向核对新备案号补全单位。

## 3. DNS 历史解析 / 存活考古

用途: 找已下架但 IP 仍活的老系统 (A记录消失≠服务下线, `--connect-to` 直达 IP+Host 仍可访问, 实战多次靠此打中已删 DNS 的目标)。

| 渠道 | 用法 |
|---|---|
| FOFA `domain="x.com"` | 平台库存=事实上的历史测绘, DNS 删除的资产常仍在库 |
| SecurityTrails API | `GET https://api.securitytrails.com/v1/history/<domain>/dns/a` 头 APIKEY; 历史A记录最全, 有免费档 |
| ViewDNS.info | `GET https://api.viewdns.info/iphistory/?domain=x&apikey=K&output=json` 免费key, iphistory+reversedns |
| 微步在线 X情报 x.threatbook.cn | 域名情报页含解析历史, 浏览器查 |
| DNSDumpster / dnstrails.com | 浏览器, 免费 |

拿到历史 IP 后: `curl --connect-to host:443:IP:443 https://host/` 验证 vhost 是否仍活。

## 4. 搜索引擎资产搜索 (Bing/Baidu/Google)

不可脚本化大规模(反爬), 用 AI 的 WebSearch 工具或浏览器少量精准查:

```
site:*.example.com -www          # 泛子域收录
"example.com" 登录               # 业务系统页
site:example.com intitle:登录|管理|后台
site:example.com (xlsx|docx|pdf) # 泄露文档, 内含内网域名/邮箱前缀
"京ICP备12345678号"              # 备案号反查关联站
```

Bing 对 site: 泛解析支持最好; Baidu 次之; Google 需代理且易触发验证码。
额外: `github.com/search?q="example.com"` 搜代码泄漏(内网地址/密钥/邮箱); 网盘/文库类用 site:pan.baidu.com 等。

## 5. 其他补充源

- **微信小程序**: 目标单位的业务小程序常直连后端 API (抓包拿域名, 补进测绘); 小程序包反编译含 api 域名清单。
- **APP**: apk 反编译 grep 域名/ak-sk (高价值: OSS AK、SDK key)。
- **公众号菜单链接**: 企微/公众号入口页常带未收录子域。
- **favicon 反查**: 拿到目标 favicon 的 mmh3 后 `fofa icon_hash=` 全网找同模板站 (开发商一套模板卖多家的, 顺藤摸瓜找兄弟单位系统)。
- **C 段**: 主域 IP 段 `fofa ip="1.2.3.4/24"` 托管邻居; 但注意 tarpit 假阳性(端口全开的 IP 是诱捕/黑洞, 见 quality-rules.md)。

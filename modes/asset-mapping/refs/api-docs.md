# 测绘平台 API 参考 (s2_engines.py 后备知识)

统一输出 schema (engines_all.jsonl 每行):
`{engine, query, url, domain, ip, port, scheme, protocol, title, icp_no, icp_unit, component, region, status_code, updated_at, source_tag}`
去重口径: `host:port:scheme` (见 `_common.norm_key`)。

---

## FOFA (fofa.info)

- 端点: `GET https://fofa.info/api/v1/search/all`
- 参数: `key`, `qbase64`(查询词 base64), `size=100`(每页上限), `page`, `fields=host,ip,port,domain,icp,title,server,protocol`
- 常用语法: `domain="example.com"`(域名树) / `icp="京ICP备xxx号"`(备案反查, **央企备案号被赌博站伪造重灾区, 结果必须过滤**) / `cert="example.com"`(证书) / `icon_hash="-123"`(favicon反查)
- 响应: `{"error": false, "size": 总数, "results": [[host, ip, ...]]}`; `error:true` 时看 message(810=封禁, 820=配额)
- 配额: F点按条扣; 单查询默认取前 3 页 × 100 条(足够测绘面), 需要全量再加 `--max-pages`
- 每页间隔 ≥2s; FOFA 对同 key 高频会 481, 退避。

## Hunter 鹰图 (hunter.qianxin.com)

- 端点: `GET https://hunter.qianxin.com/openApi/search`
- 参数: `api-key`, `search`(base64), `page`, `page_size=100`(上限), `is_web=3`(web资产), `bind`/`start_time`/`end_time`(时间窗)
- 常用语法: `domain.suffix="example.com"` / `icp.number="京ICP备xxx号"` / `web.title="xxx"`
- 响应: `{"code":200? "data": {"total", "arr":[...], "rest_quota": 剩余积分}, "message"}` — **每次打印 rest_quota**, 积分耗尽前通知用户
- 字段映射: url/ip/port/protocol/domain/web_title/component[]/status_code/number(备案号)/company(备案主体)/province/city/updated_at
- 速率: ≥3s/查询; 免费档积分有限, 优先 domain.suffix 查询, icp 反查挑重点。

## Quake (quake.360.net)

- 端点: `POST https://quake.360.net/api/v3/search/quake_service`, 头 `X-QuakeToken`
- Body: `{"query": "domain:\"example.com\"", "start": 0, "size": 100, "include": [字段白名单]}`
- 常用语法: `domain:"x.com"` / `icp:"京ICP备xxx号"` / `cert:"x.com"` / `favicon:"hash"`
- 响应: `{"code":0, "data":[{ip,port,service:{http:{host,title}}}], "meta.pagination.total}`
- 配额: Credit 按条扣, 注册送额度; `GET /api/v3/user/info` 可查余量
- 速率: ≥2s; include 白名单能显著减少扣费字段。

## ZoomEye 钟馗之眼 (api.zoomeye.hk / api.zoomeye.org.cn)

- 鉴权: 头 `API-KEY: <key>` (新版); 旧 JWT 已弃用
- 资产: `GET /host/search?query=site:example.com&page=1&pagesize=20`
- 子域: `GET /domain/search?q=example.com` → `{list:[{name}], total}` (子域枚举好手, 配额便宜)
- 配额: `GET /resources-info` (按天免费额度)
- 限制: **不支持 ICP 反查**, 只跑域名面; 每页 20 条, max-pages=3 → 60 条/域

## Shodan (api.shodan.io)

- 资产: `GET /shodan/host/search?key=K&query=hostname:example.com&page=1` (每页100, **每页1 query credit**)
- 子域: `GET /dns/domain/example.com` → `{subdomains:[...]}` (免费)
- 配额: `GET /api-info` → `query_credits`
- 中国境内资产覆盖弱于 FOFA/Hunter/Quake, 当补充源; ICP 无, 国内备案场景价值低。

---

## 常见坑 (实战教训)

1. **伪造 ICP 备案**: 赌博/私彩站批量伪造央企备案号, IP 集中 154.x/156.x/179.x 等海外段。处置: `s5_dedupe.py` 自动按 IP 段+博彩标题剔除; 终判看主体是否在授权单位表。
2. **ICP 号前缀匹配**: 备案号带 `-1/-2` 主体序号, 比对时先剥掉尾序号再前缀匹配。
3. **配额断点**: 所有查询器 `[skip]` 已有非空结果文件的查询, 中断重跑不重复扣费; Hunter 每查询打印剩余积分。
4. **crt.sh 高峰超时**: 内置 3 次重试+sleep5, 仍失败域名重跑 s3 即续传。
5. **泛解析**: 必须 s4 检测后再算存活, 否则字典域全是假存活。
6. **ZoomEye/Shodan 无 ICP 面**: 备案反查只在 FOFA/Hunter/Quake 三家做。
7. **Hunter page_size 合法值集有限**: 实战验证 1/10/50/100 可用, 30 报"页大小不合法"。
8. **Hunter 无账户信息端点**: /openApi/user/info 等均 404, 配额只能从搜索响应 `rest_quota` 读(doctor 用 1 积分微型搜索体检)。
9. **按名称找资产**: 中文公司名只有 Hunter `company=` 支持(备案主体名精确匹配); FOFA `org=` 是 TLS 证书 O 字段(多为英文全称, 中文名基本 0 结果); Quake `org:""` 同证书口径。
10. **FOFA 每页上限 100**: 单查询最多翻 10000 条; 大单位 ICP 反查建议 `--max-pages 5` 起。

## key 申请入口

| 平台 | 地址 | 计费 | 备注 |
|---|---|---|---|
| FOFA | fofa.info → 个人中心 | F点/条 | 境内资产覆盖第一档 |
| Hunter | hunter.qianxin.com → 个人中心 | 积分/条 | 免费档送积分; 唯一中文公司名反查 |
| Quake | quake.360.net | Credit/条 | 注册送额度 |
| ZoomEye | zoomeye.org.cn | 按天免费额度 | API-KEY 鉴权 |
| Shodan | shodan.io | query credit/页 | 境内弱, 补充源 |

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S0 目标展开 + 密钥体检 — 五种入口把"用户给的东西"变成 scope.json 草稿。

用法:
  python3 s0_expand.py --work <目录> --doctor                     # ① 体检 keys.json (配额/有效性/能力矩阵)
  python3 s0_expand.py --work <目录> --domain a.com,b.com         # ② 域名入口 → 主域/备案主体展开
  python3 s0_expand.py --work <目录> --ip 1.2.3.4                 # ③ IP 入口 → C段资产+归属反查
  python3 s0_expand.py --work <目录> --cidr 1.2.3.0/24
  python3 s0_expand.py --work <目录> --group "XX集团"              # ④ 集团/单位名入口 (备案公司名+证书org双路)
  python3 s0_expand.py --work <目录> --unit "XX有限公司"
  python3 s0_expand.py --work <目录> --keyword "XX平台"            # ⑤ 关键字入口 (标题搜索, 噪音大仅出候选)

输出: runs/scope_draft.json (人工核对后改名 scope.json 正式生效)
无任何 key 时: doctor 会给出申请地址与"免费链路仍可跑什么"的降级矩阵。
"""
import argparse, base64, ipaddress, json, os, re, sys
from collections import Counter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import api_get, load_keys, runs_dir, sub_dir

# 中国常见二级后缀: 这些下面还要再取一层才是注册域 (a.com.cn → 注册域=a.com.cn)
SLD2 = {'com.cn', 'net.cn', 'gov.cn', 'org.cn', 'edu.cn', 'ac.cn'}


def registrable(dom):
    """从子域名归约出注册域 (无 PSL 依赖的轻量实现, 覆盖国内主流后缀)。"""
    p = (dom or '').strip().lower().split('.')
    if len(p) >= 3 and '.'.join(p[-2:]) in SLD2:
        return '.'.join(p[-3:])
    return '.'.join(p[-2:]) if len(p) >= 2 else dom


HELP_NOKEY = """
┌─ 未检测到任何测绘平台 key ─────────────────────────────────────────┐
│ 提供以下任意一份即可显著提升测绘能力(按国内企业资产覆盖排序):        │
│   FOFA    https://fofa.info  (个人中心→个人API key; F点计费)        │
│   Hunter  https://hunter.qianxin.com (个人中心→API; 积分计费)       │
│   Quake   https://quake.360.net (控制台→API key; Credit计费)       │
│   ZoomEye https://www.zoomeye.org.cn (API-KEY; 按天免费额度)       │
│   Shodan  https://www.shodan.io (Account→API key; 境内资产弱)      │
│ 把 key 填进 <work>/keys.json (模板 assets/keys.example.json)。      │
│                                                                    │
│ 完全无 key 的免费降级链路(仍可跑):                                  │
│   crt.sh + RapidDNS 子域枚举 → DNS 存活/泛解析 → 温和探测+种子指纹  │
│   (缺平台查询 = 缺 ICP 反查/组件/地区字段, 资产面只有子域名展开)     │
└────────────────────────────────────────────────────────────────────┘"""


# ---------------------------------------------------------------------------
# doctor: 逐平台验证 key + 配额
# ---------------------------------------------------------------------------

def doctor(work):
    keys = load_keys(work)
    have = {k: v for k, v in keys.items() if isinstance(v, dict) and v.get('key')}
    if not have:
        print(HELP_NOKEY)
        return
    print(f'检测到 {len(have)} 个平台 key, 逐一体检:\n')
    caps = []
    # FOFA
    if 'fofa' in have:
        st, r = api_get('https://fofa.info/api/v1/info/my', {'key': have['fofa']['key']})
        ok = isinstance(r, dict) and r.get('error') is False
        quota = ''
        if ok:
            quota = f"F点={r.get('fofa_point', '?')} API点={r.get('api_point', '?')} 到期={str(r.get('vip_level', ''))[:20]}"
        print(f"  [fofa]    {'OK ' if ok else 'FAIL ' + str(r)[:80]}  {quota}")
        caps.append(ok)
    # Hunter: 无账户信息端点(实战验证404), 用1积分微型搜索验证key+读回剩余积分
    if 'hunter' in have:
        q = base64.b64encode('domain.suffix="hunter.qianxin.com"'.encode()).decode()
        st, r = api_get('https://hunter.qianxin.com/openApi/search',
                        {'api-key': have['hunter']['key'], 'search': q,
                         'page': 1, 'page_size': 1, 'is_web': 3})
        data = (r or {}).get('data') if isinstance(r, dict) else None
        ok = isinstance(data, dict)
        print(f"  [hunter]  {'OK ' if ok else 'FAIL ' + str(r)[:80]}  "
              f"剩余积分={data.get('rest_quota', '?') if ok else ''}")
        caps.append(ok)
    # Quake
    if 'quake' in have:
        st, r = api_get('https://quake.360.net/api/v3/user/info', {},
                        headers={'X-QuakeToken': have['quake']['key']})
        ok = isinstance(r, dict) and r.get('code') == 0
        d = (r or {}).get('data') or {}
        print(f"  [quake]   {'OK ' if ok else 'FAIL ' + str(r)[:80]}  "
              f"credit={d.get('credit', '?')} 到期={str(d.get('user', {}).get('expiration_time', '?'))[:19] if ok else ''}")
        caps.append(ok)
    # ZoomEye
    if 'zoomeye' in have:
        base = have['zoomeye'].get('base', 'https://api.zoomeye.hk').rstrip('/')
        st, r = api_get(base + '/resources-info', {}, headers={'API-KEY': have['zoomeye']['key']})
        ok = isinstance(r, dict) and (r.get('status') in (200, '200') or 'resources' in r)
        print(f"  [zoomeye] {'OK ' if ok else 'FAIL ' + str(r)[:80]}  {json.dumps(r, ensure_ascii=False)[:100] if ok else ''}")
        caps.append(ok)
    # Shodan
    if 'shodan' in have:
        st, r = api_get('https://api.shodan.io/api-info', {'key': have['shodan']['key']})
        ok = isinstance(r, dict) and 'query_credits' in r
        print(f"  [shodan]  {'OK ' if ok else 'FAIL ' + str(r)[:80]}  "
              f"query_credits={r.get('query_credits', '?') if ok else ''}")
        caps.append(ok)
    n_ok = sum(1 for c in caps if c)
    print(f'\n能力矩阵: {n_ok}/{len(caps)} 平台可用')
    if n_ok == 0:
        print(HELP_NOKEY)
    else:
        need_icp = any(k in have for k in ('fofa', 'hunter', 'quake'))
        print(f"  ICP备案反查: {'✅' if need_icp else '❌ (缺 fofa/hunter/quake)'}")
        print(f"  证书org反查: {'✅' if 'fofa' in have or 'quake' in have else '❌'}")
        print(f"  中文公司名反查: {'✅' if 'hunter' in have else '❌ (仅 hunter company= 支持)'}")
        print(f"  子域枚举(crt.sh/RapidDNS): ✅ 永远可用")


# ---------------------------------------------------------------------------
# 平台查询小封装 (展开只取小样本, 省配额; 全量交给 s2)
# ---------------------------------------------------------------------------

def fofa_search(key, q, size=50, fields='host,ip,port,domain,icp,title'):
    q64 = base64.b64encode(q.encode()).decode()
    st, r = api_get('https://fofa.info/api/v1/search/all',
                    {'key': key, 'qbase64': q64, 'size': size, 'fields': fields})
    if not isinstance(r, dict) or r.get('error') is True:
        return None, str(r)[:100]
    return r.get('results') or [], r.get('size', 0)


def hunter_search(key, q, page_size=10):
    """page_size 合法值集有限(实战验证 1/10/50/100 可用, 30 报'页大小不合法')。展开只取候选,10条够。"""
    qb64 = base64.b64encode(q.encode()).decode()
    st, r = api_get('https://hunter.qianxin.com/openApi/search',
                    {'api-key': key, 'search': qb64, 'page': 1, 'page_size': page_size, 'is_web': 3})
    data = (r or {}).get('data') if isinstance(r, dict) else None
    if not isinstance(data, dict):
        return None, str(r)[:100]
    return data.get('arr') or [], data.get('rest_quota')


# ---------------------------------------------------------------------------
# ② 域名入口: domain= → ICP主体/关联主域
# ---------------------------------------------------------------------------

def expand_domain(work, domains, keys):
    fk = (keys.get('fofa') or {}).get('key')
    hk = (keys.get('hunter') or {}).get('key')
    if not fk and not hk:
        print('[!] 域名展开至少需要 fofa 或 hunter key (--doctor 看降级方案)')
        return
    icps, owners, related = Counter(), Counter(), Counter()
    titles = {}
    for d in domains:
        if fk:
            rows, tot = fofa_search(fk, f'domain="{d}"')
            if rows is None:
                print(f'[fofa] {d}: {tot}')
            else:
                print(f'[fofa] {d}: {tot} 条')
                for r in rows:
                    host, ip, port, dom, icp, title = (list(r) + [''] * 6)[:6]
                    if icp:
                        icps[re.sub(r'[-—–]\d+$', '', icp)] += 1
                    if dom and dom != d and '.' in dom:
                        related[registrable(dom)] += 1
                    titles[host] = title
        if hk:
            arr, rest = hunter_search(hk, f'domain.suffix="{d}"')
            if arr is None:
                print(f'[hunter] {d}: {rest}')
            else:
                print(f'[hunter] {d}: {len(arr)} 条 (剩余积分 {rest})')
                for it in arr:
                    if it.get('number'):
                        icps[re.sub(r'[-—–]\d+$', '', it['number'])] += 1
                    if it.get('company'):
                        owners[it['company']] += 1
    draft_unit = [{
        'name': (owners.most_common(1)[0][0] if owners else domains[0]),
        'system': '-',
        'domains': domains,
        'icp': [i for i, _ in icps.most_common(5)],
        'note': '域名入口自动展开, 备案主体/关联主域待人工核对'
    }]
    extra_domains = [d for d, n in related.most_common(10) if n >= 2 and d not in domains]
    if extra_domains:
        draft_unit.append({'name': '(候选关联主域, 待归属)', 'system': '-', 'domains': extra_domains,
                           'icp': [], 'note': 'FOFA domain 字段高频出现的其它主域'})
    save_draft(work, {'units': draft_unit},
               hints=[f'备案主体候选: {owners.most_common(3)}',
                      f'备案号候选: {icps.most_common(5)}',
                      '下一步: 爱企查核主体股权关系(osint-sources.md §1); 把确认的 icp 号回填后跑 s2 做全量 ICP 反查'])


# ---------------------------------------------------------------------------
# ③ IP/CIDR 入口: ip= → C段资产+归属反查
# ---------------------------------------------------------------------------

def expand_ip(work, ip_or_cidr, keys):
    fk = (keys.get('fofa') or {}).get('key')
    hk = (keys.get('hunter') or {}).get('key')
    if not fk and not hk:
        print('[!] IP 展开至少需要 fofa 或 hunter key')
        return
    rows = []
    if fk:
        rows, tot = fofa_search(fk, f'ip="{ip_or_cidr}"', size=100)
        print(f'[fofa] ip="{ip_or_cidr}": {tot if rows is not None else "ERR"} 条')
        if rows is None:
            rows = []
    if hk and not rows:
        arr, rest = hunter_search(hk, f'ip="{ip_or_cidr}"', page_size=100)
        if arr is not None:
            print(f'[hunter] {len(arr)} 条 (剩余积分 {rest})')
            rows = [[it.get('url', ''), it.get('ip', ''), it.get('port', ''),
                     it.get('domain', ''), it.get('number', ''), it.get('web_title', '')] for it in arr]
    icps, doms = Counter(), Counter()
    for r in rows:
        host, ip, port, dom, icp, title = (list(r) + [''] * 6)[:6]
        if icp:
            icps[re.sub(r'[-—–]\d+$', '', icp)] += 1
        if dom and '.' in dom:
            doms[registrable(dom)] += 1
    # 验证 CIDR/IP 合法性
    try:
        ipaddress.ip_network(ip_or_cidr if '/' in ip_or_cidr else ip_or_cidr + '/32', strict=False)
    except ValueError:
        print('[!] 非法 IP/CIDR')
        return
    save_draft(work, {'targets_ip': [ip_or_cidr],
                      'units': ([{'name': f'IP目标 {ip_or_cidr}', 'system': '-',
                                  'domains': [d for d, _ in doms.most_common(5)],
                                  'icp': [i for i, _ in icps.most_common(3)],
                                  'note': 'IP入口展开: 归属需人工确认(C段多为云托管邻居)'}]
                                 if icps or doms else [])},
               hints=[f'备案号候选: {icps.most_common(5)}', f'主域候选: {doms.most_common(5)}',
                      '该 IP/CIDR 已写入 scope 草稿 targets_ip 字段 → s5 阶段网段内资产自动算范围内'])


# ---------------------------------------------------------------------------
# ④⑤ 集团/单位/关键字入口: hunter company= + fofa org=
# ---------------------------------------------------------------------------

def expand_name(work, name, keys, mode='group'):
    fk = (keys.get('fofa') or {}).get('key')
    hk = (keys.get('hunter') or {}).get('key')
    if not hk and not fk:
        print('[!] 名称展开建议至少配 hunter (中文备案公司名 company= 查询); fofa org= 仅证书O字段(多为英文)')
        if not fk and not hk:
            return
    owners, icps, doms = Counter(), Counter(), Counter()
    if hk:
        arr, rest = hunter_search(hk, f'company="{name}"', page_size=10)
        if arr is None:
            print(f'[hunter] company 查询失败: {rest}')
        else:
            print(f'[hunter] company="{name}": {len(arr)} 条 (剩余积分 {rest})')
            for it in arr:
                if it.get('company'):
                    owners[it['company']] += 1
                if it.get('number'):
                    icps[re.sub(r'[-—–]\d+$', '', it['number'])] += 1
                d = it.get('domain') or ''
                if '.' in d:
                    doms[registrable(d)] += 1
    if fk:
        rows, tot = fofa_search(fk, f'org="{name}"', size=50)
        if rows is None:
            print(f'[fofa] org="{name}" 查询失败: {tot}')
        elif not rows:
            print(f'[fofa] org="{name}": 0 条 (org=是证书O字段多为英文全称, 中文名请依赖 hunter company=)')
        else:
            print(f'[fofa] org="{name}": {tot} 条')
            for r in rows:
                host, ip, port, dom, icp, title = (list(r) + [''] * 6)[:6]
                if icp:
                    icps[re.sub(r'[-—–]\d+$', '', icp)] += 1
                if dom and '.' in dom:
                    doms[registrable(dom)] += 1
    units = []
    for owner, _ in owners.most_common(8):
        units.append({'name': owner, 'system': '-',
                      'domains': [], 'icp': [],
                      'note': f'"{name}" 的备案主体候选, 待爱企查核控股关系'})
    save_draft(work, {'units': units},
               hints=[f'备案主体候选: {owners.most_common(5)}',
                      f'备案号候选: {icps.most_common(5)}',
                      f'主域候选: {doms.most_common(8)}',
                      '多级控股穿透 checklist (osint-sources.md §1):',
                      f'  1) 爱企查搜"{name}" → 对外投资 tab → 取持股比例≥50%(或授权口径)的企业;',
                      '  2) 对每个子公司重复该步, BFS 到第4级, 全资100%优先;',
                      '  3) 记录每个主体的备案号(天眼查/工信部)回填 icp 字段;',
                      '  4) 排除授权书排除的主体 → scope.json 定稿'])


# ---------------------------------------------------------------------------

def save_draft(work, extra, hints):
    out = os.path.join(runs_dir(work), 'scope_draft.json')
    draft = {'_comment': 'scope 草稿 — 人工核对(爱企查股权+备案真伪)后改名 scope.json 生效',
             'project': '待填-项目名', 'authorization': '待填-授权方+窗口+排除主体',
             'criteria': '范围单位全部公网资产(不限于靶标系统)',
             'units': [], 'sub_overrides': {}, 'group_domains_out_of_scope': [],
             'keywords': {}, 'targets_ip': []}
    draft.update(extra)
    draft['_hints'] = hints
    json.dump(draft, open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(f'\nscope 草稿 → {out}')
    for h in hints:
        print('  ▸', h)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--work', default='.')
    ap.add_argument('--doctor', action='store_true')
    ap.add_argument('--domain', default='')
    ap.add_argument('--ip', default='')
    ap.add_argument('--cidr', default='')
    ap.add_argument('--group', default='')
    ap.add_argument('--unit', default='')
    ap.add_argument('--keyword', default='')
    args = ap.parse_args()
    keys = load_keys(args.work)

    if args.doctor:
        doctor(args.work)
        return
    if args.domain:
        expand_domain(args.work, [d.strip() for d in args.domain.split(',') if d.strip()], keys)
    elif args.ip or args.cidr:
        expand_ip(args.work, args.ip or args.cidr, keys)
    elif args.group or args.unit:
        expand_name(args.work, args.group or args.unit, keys)
    elif args.keyword:
        print('[keyword] 关键字入口噪音大, 仅给查询词建议(不自动跑):')
        print(f'  fofa: title="{args.keyword}" / hunter: web.title="{args.keyword}"')
        print(f'  建议先确认目标主体名, 再走 --group 入口')
    else:
        ap.print_help()


if __name__ == '__main__':
    main()

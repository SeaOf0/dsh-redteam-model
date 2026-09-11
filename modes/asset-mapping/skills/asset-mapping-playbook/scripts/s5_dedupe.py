#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S5 合并去重 + 归属判定 + 垃圾过滤。

用法: python3 s5_dedupe.py --work <项目目录>

输入: runs/engines/engines_all.jsonl + scope.json (+ runs/dns/wildcard.json)
输出: runs/assets.jsonl   每行一条最终资产 (含归属/关联度/在范围标记)

归属优先级: 子域例外表 > 域名后缀匹配 > ICP主体匹配 > 集团域范围外 > 未知(范围外)
垃圾过滤:   ICP 在范围内但域名不在任何单位主域下 → 伪造备案嫌疑;
             IP 落在已知垃圾段或标题含博彩词 → 丢弃并计数。
"""
import argparse, ipaddress, json, os, re, sys
from collections import Counter, defaultdict
from urllib.parse import urlparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import load_scope, norm_key, merge_record, runs_dir

# 非web服务端口(测绘保留但 s6 不探测, 标记供打点阶段参考)
NONWEB_PORTS = {21, 22, 23, 25, 110, 143, 993, 995, 1433, 1521, 2181, 3306, 3389,
                5432, 5672, 6379, 8161, 9092, 9200, 9300, 11211, 15672, 1883, 27017, 50070}

# 常见伪造备案垃圾集群特征 (可按项目在 scope.json junk_ip_prefixes 扩展)
JUNK_IP_PREFIX = ['154.', '156.', '179.', '45.204', '116.206.181.', '156.239']
JUNK_TITLE_KW = ['博彩', '赌博', '彩票', '六合彩', '私彩', '娱乐城', '开户', '澳门', '威尼斯人',
                 'mg电子', 'kb体育', '真人荷官', '色情', 'av视频']


def attr(domain, icp_no, scope, unit_by_domain, icp_by_unit, sub_ovr, group_oos):
    """返回 (unit, note, in_scope)。"""
    if domain in sub_ovr:
        u, note = sub_ovr[domain]
        return u, note, u not in ('范围外', '【范围外】')
    if domain:
        parts = domain.lower().split('.')
        for i in range(len(parts) - 1):
            suf = '.'.join(parts[i:])
            if suf in unit_by_domain:
                return unit_by_domain[suf], '', True
        for g in group_oos:
            if domain == g or domain.endswith('.' + g):
                return '【范围外】', '集团域(未授权子域)', False
    if icp_no:
        base = re.sub(r'[-—–]\d+$', '', icp_no)
        for unit, icps in icp_by_unit.items():
            for icp in icps:
                if base.startswith(re.sub(r'[-—–]\d+$', '', icp.replace('号', ''))):
                    return unit, 'ICP归属(域名不在主域表,需人工确认)', True
    return '【范围外】', '未知归属', False


def relevance(unit, domain, title, url, kw_map, unit_by_domain):
    kws = kw_map.get(unit) or []
    if not kws:
        return '中'
    label, blob = domain, f"{domain} {title} {url}".lower()
    parts = domain.split('.')
    for i in range(len(parts) - 1):
        suf = '.'.join(parts[i:])
        if suf in unit_by_domain or suf == domain.split('.', 1)[-1]:
            label = '.'.join(parts[:i])
            break
    blob = f"{label} {blob}".lower()
    for kw in kws:
        if kw.isascii() and len(kw) <= 5:
            if re.search(r'\b' + re.escape(kw) + r'\b', blob):
                return '高'
        elif kw in blob:
            return '高'
    return '中'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--work', default='.')
    args = ap.parse_args()

    scope = load_scope(args.work)
    src = os.path.join(runs_dir(args.work), 'engines', 'engines_all.jsonl')
    if not os.path.isfile(src):
        raise SystemExit('[!] 先跑 s2_engines.py 生成 engines_all.jsonl')

    unit_by_domain, icp_by_unit, sub_ovr = {}, {}, {}
    kw_map = scope.get('keywords') or {}
    junk_prefixes = list(set(JUNK_IP_PREFIX + (scope.get('junk_ip_prefixes') or [])))
    for u in scope['units']:
        for d in u.get('domains') or []:
            unit_by_domain[d.lower()] = u['name']
        for i in u.get('icp') or []:
            icp_by_unit.setdefault(u['name'], []).append(i)
    for k, v in (scope.get('sub_overrides') or {}).items():
        sub_ovr[k.lower()] = (v.get('unit', '【范围外】'), v.get('note', ''))
    group_oos = [g.lower() for g in (scope.get('group_domains_out_of_scope') or [])]
    targets_ip = []
    for t in scope.get('targets_ip') or []:
        try:
            targets_ip.append(ipaddress.ip_network(t if '/' in t else t + '/32', strict=False))
        except ValueError:
            pass

    store, junk_dropped = {}, 0
    for line in open(src, encoding='utf-8'):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if not rec.get('url'):
            continue
        # 垃圾过滤: 域名不在范围主域 + (IP垃圾段 或 博彩标题) 且 ICP是范围备案号 → 伪造备案
        dom = (rec.get('domain') or '').lower()
        in_dom_tree = any(dom == d or dom.endswith('.' + d) for d in unit_by_domain)
        if not in_dom_tree:
            ip, title = rec.get('ip') or '', rec.get('title') or ''
            if ip.startswith(tuple(junk_prefixes)) or any(k in title for k in JUNK_TITLE_KW):
                junk_dropped += 1
                continue
        merge_record(store, rec)

    rows = []
    for k, r in store.items():
        domain = (r.get('domain') or k.split(':')[0]).lower()
        if not r.get('domain') and '.' in (r.get('url') or ''):
            p = urlparse(r['url'] if '//' in r['url'] else 'http://' + r['url'])
            domain = (p.hostname or '').lower()
        unit, note, in_scope = attr(domain, r.get('icp_no') or '', scope,
                                    unit_by_domain, icp_by_unit, sub_ovr, group_oos)
        # IP 目标网段: 用户显式指定的 IP/CIDR 直接算范围内
        ip = r.get('ip') or ''
        if not in_scope and ip:
            try:
                if any(ipaddress.ip_address(ip) in net for net in targets_ip):
                    unit, note, in_scope = 'IP目标', '用户指定IP/CIDR', True
            except ValueError:
                pass
        rel = relevance(unit, domain, r.get('title') or '', r.get('url') or '', kw_map, unit_by_domain) if in_scope else '-'
        # 非web服务端口标记 (s6 只探测 http/https, 这类资产保留但不探测)
        try:
            if int(r.get('port') or 0) in NONWEB_PORTS:
                note = (note + '; ' if note else '') + '非web服务端口(测绘保留,不探测)'
        except (TypeError, ValueError):
            pass
        r.update({'domain': domain, 'unit': unit if in_scope else '【范围外】',
                  'in_scope': in_scope, 'note': note, 'rel': rel})
        rows.append(r)

    # ---- tarpit / CDN 完整性标记 ----
    ports_by_ip, doms_by_ip = defaultdict(set), defaultdict(set)
    for r in rows:
        if r.get('ip'):
            try:
                ports_by_ip[r['ip']].add(int(r.get('port') or 0))
            except (TypeError, ValueError):
                pass
            if r.get('domain'):
                doms_by_ip[r['ip']].add(r['domain'])
    for r in rows:
        ip = r.get('ip')
        if not ip:
            continue
        if len(ports_by_ip[ip]) >= 30:
            r['note'] = (r['note'] + '; ' if r['note'] else '') + f'tarpit嫌疑(该IP出现{len(ports_by_ip[ip])}个端口,勿当真实资产)'
        elif len(doms_by_ip[ip]) >= 5:
            r['note'] = (r['note'] + '; ' if r['note'] else '') + f'CDN/共享托管嫌疑(同IP挂{len(doms_by_ip[ip])}个域名, C段推演勿用此IP)'
    order = {u['name']: i for i, u in enumerate(scope['units'])}
    rows.sort(key=lambda r: (0 if r['in_scope'] else 1, order.get(r['unit'], 99), r.get('domain', ''), str(r.get('port'))))

    out = os.path.join(runs_dir(args.work), 'assets.jsonl')
    with open(out, 'w', encoding='utf-8') as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')

    n_in = sum(1 for r in rows if r['in_scope'])
    print(f'assets: {len(rows)} (范围内 {n_in} / 范围外 {len(rows) - n_in}), 伪造备案垃圾剔除 {junk_dropped}')
    for u in scope['units']:
        mine = [r for r in rows if r['unit'] == u['name']]
        print(f"  {u['name']}: {len(mine)} 资产, 高关联 {sum(1 for r in mine if r.get('rel') == '高')}")
    print('DEDUPE DONE ->', out)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S4 DNS 校验 — 泛解析检测 + 子域名批量存活解析。

用法:
  python3 s4_dns_alive.py --work <项目目录> [--dns 223.5.5.5] [--threads 12]

产物:
  runs/dns/wildcard.json      每主域泛解析判定 {domain: {wildcard: bool, ips: []}}
  runs/dns/alive_subs.txt     "子域 ip1,ip2" 每行一条 (仅存活)
判定规则: 对每个主域解析两个随机标签子域, 均解析出同一IP → 泛解析;
         泛解析主域的子域必须解析到"与泛解析IP不同"的地址才算存活新资产。
"""
import argparse, json, os, random, shutil, string, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import load_scope, sub_dir


CDN_CNAME_KW = ('cdn', 'cloudf', 'waf', 'akamai', 'fastly', 'aliyun', 'wscdn', 'qiniudns',
                'kunlun', 'alikunlun', 'cdn.dnsv1', 'ccgslb', 'ourdvs', 'cdnhcky', 'qcloud')

HAS_DIG = shutil.which('dig') is not None
if not HAS_DIG:
    print('[!] 未找到 dig, 退化为 socket 解析 (无 CNAME 视图, 泛解析检测精度降低)')


def dig(host, dns, qtype='A'):
    """dig +short; 返回去空行列表。无 dig 时 socket 兜底(仅A)。"""
    try:
        if not HAS_DIG:
            if qtype != 'A':
                return []
            import socket
            ips = sorted({x[4][0] for x in socket.getaddrinfo(host, None, socket.AF_INET)})
            return ips
        out = subprocess.run(['dig', '+short', host, qtype, f'@{dns}', '+time=3', '+tries=1'],
                             capture_output=True, text=True, timeout=8).stdout
        return [x.strip() for x in out.splitlines() if x.strip()]
    except Exception:
        return []


def resolve(host, dns):
    a = [x for x in dig(host, dns, 'A') if x and x[0].isdigit()]
    if a:
        return a[:3]
    cn = dig(host, dns, 'CNAME')
    return cn[:1]


def is_cdn_cname(cname):
    c = (cname or '').lower()
    return any(k in c for k in CDN_CNAME_KW)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--work', default='.')
    ap.add_argument('--dns', default='223.5.5.5')
    ap.add_argument('--threads', type=int, default=12)
    args = ap.parse_args()

    scope = load_scope(args.work)
    out = sub_dir(args.work, 'dns')
    crt = sub_dir(args.work, 'crt')
    mains = sorted({d for u in scope['units'] for d in (u.get('domains') or [])})

    # ---- 泛解析检测 ----
    wc_path = os.path.join(out, 'wildcard.json')
    wc = json.load(open(wc_path)) if os.path.isfile(wc_path) else {}
    rnd = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    for dom in mains:
        if dom in wc:
            continue
        probes = [f'{rnd}{i}.{dom}' for i in (1, 2)]
        ips = set()
        for p in probes:
            for ip in resolve(p, args.dns):
                ips.add(ip)
        wc[dom] = {'wildcard': len(ips) > 0, 'wildcard_ips': sorted(ips)}
        print(f'[wildcard] {dom}: {"泛解析!" if ips else "无泛解析"} {sorted(ips)[:2]}')
    json.dump(wc, open(wc_path, 'w'), ensure_ascii=False, indent=1)

    # ---- 子域存活 ----
    subs = set()
    for f in os.listdir(crt):
        if f.endswith('.txt'):
            for line in open(os.path.join(crt, f)):
                line = line.strip()
                if line:
                    subs.add(line)
    subs |= {d for d in mains}
    print(f'resolving {len(subs)} subdomains via {args.dns} ...')

    def one(s):
        ips = resolve(s, args.dns)
        if not ips:
            return None
        # CNAME 指向 CDN → 存活但标记(非源站, C段推演不可用)
        cn = dig(s, args.dns, 'CNAME')
        tag = ''
        if any(is_cdn_cname(c) for c in cn):
            tag = 'CDN'
        return (s, ips + ([tag] if tag else []))

    alive_path = os.path.join(out, 'alive_subs.txt')
    alive = {}
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        for r in ex.map(one, sorted(subs)):
            if r:
                alive[r[0]] = r[1]

    # 泛解析主域: 剔除与泛解析IP完全一致的"假存活"
    dropped = 0
    for dom, info in wc.items():
        if info['wildcard']:
            for s in list(alive):
                if s.endswith('.' + dom) and set(alive[s]) <= set(info['wildcard_ips']):
                    del alive[s]
                    dropped += 1
    with open(alive_path, 'w') as f:
        for s in sorted(alive):
            f.write(f"{s} {','.join(alive[s])}\n")
    print(f'alive: {len(alive)} / {len(subs)} (泛解析剔除 {dropped})')
    print('DNS DONE')


if __name__ == '__main__':
    main()

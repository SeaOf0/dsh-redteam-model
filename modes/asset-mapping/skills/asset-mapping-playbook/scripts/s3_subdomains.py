#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S3 子域名枚举 — crt.sh 证书透明 + RapidDNS (+ 可选 Shodan DNS/FOFA聚合并入)。

用法:
  python3 s3_subdomains.py --work <项目目录> [--source crt,rapid]

产物: runs/crt/<domain>.txt  每行一个子域 (含泛解析星号记录已剥离)。
注意: crt.sh 高峰期超时常见, 内置 3 次重试; 失败域名最后汇总列出。
"""
import argparse, json, os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import load_scope, sub_dir, curl_get


def crtsh(domain, proxy=None):
    for attempt in range(3):
        out = curl_get(f'https://crt.sh/?q=%.{domain}&output=json', timeout=60, proxy=proxy)
        out = out.strip()
        if out.startswith('['):
            try:
                names = set()
                for row in json.loads(out):
                    for n in str(row.get('name_value') or '').split('\n'):
                        n = n.strip().lstrip('*.').lower()
                        if n.endswith('.' + domain) or n == domain:
                            names.add(n)
                return sorted(names), ''
            except Exception:
                pass
        time.sleep(5)
    return None, 'crt.sh 超时/限流'


def rapiddns(domain, proxy=None):
    html = curl_get(f'https://rapiddns.io/subdomain/{domain}?full=1', timeout=30, proxy=proxy)
    if not html:
        return None, 'rapiddns 不可达'
    names = set(re.findall(r'([A-Za-z0-9_.-]+\.' + re.escape(domain) + r')\b', html))
    return sorted(n.lower().strip('.') for n in names), ''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--work', default='.')
    ap.add_argument('--source', default='crt,rapid')
    ap.add_argument('--proxy', default='', help='可选 http(s) 代理, 如 http://127.0.0.1:7890')
    args = ap.parse_args()

    scope = load_scope(args.work)
    out = sub_dir(args.work, 'crt')
    srcs = {x.strip() for x in args.source.split(',')}
    domains = sorted({d for u in scope['units'] for d in (u.get('domains') or [])})
    failed = []

    for dom in domains:
        f = os.path.join(out, dom + '.txt')
        if os.path.isfile(f) and os.path.getsize(f) > 0:
            print(f'[skip] {dom}')
            continue
        got, err = set(), ''
        if 'crt' in srcs:
            r, err = crtsh(dom, args.proxy or None)
            if r:
                got |= set(r)
            else:
                failed.append((dom, err))
        if 'rapid' in srcs:
            r2, err2 = rapiddns(dom, args.proxy or None)
            if r2:
                got |= set(r2)
        if got:
            with open(f, 'w') as fh:
                fh.write('\n'.join(sorted(got)))
            print(f'[{dom}] {len(got)} subdomains')
        else:
            print(f'[{dom}] 无结果 ({err})')
        time.sleep(2)
    if failed:
        print('crt.sh 失败域名(稍后重跑即可断点续传):', ', '.join(d for d, _ in failed))
    print('SUBDOMAIN DONE')


if __name__ == '__main__':
    main()

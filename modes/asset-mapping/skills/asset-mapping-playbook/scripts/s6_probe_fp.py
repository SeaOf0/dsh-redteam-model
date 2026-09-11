#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S6 温和探测 + 指纹识别 (WAF感知, 仅授权范围内资产)。

用法:
  python3 s6_probe_fp.py --work <项目目录> [--threads 10] [--skip-paths] [--fpdb <unified_rules.json>]

三阶段:
  phase1 根路径探测: 状态码/标题/Server/JS标记/meta generator/favicon mmh3/WAF识别
  phase2 敏感路径探测: actuator/druid/swagger/nacos/... (轻量判定, 见 quality-rules.md 假阳性清单)
  phase3 指纹匹配: 关键词规则(body/title/header) + 路径规则; 默认用 skill 自带种子库,
                   可用 fpdb_update.py 重建全量库后 --fpdb 指定

产物: runs/probe/{root.json, paths.json, fp.json}
"""
import argparse, base64, json, os, random, re, sys, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import fetch, favicon_hash, runs_dir

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEED_FPDB = os.path.join(SKILL_DIR, 'assets', 'fpdb_seed.json')

TITLE_RE = re.compile(rb'<title[^>]*>(.*?)</title>', re.I | re.S)
META_GEN = re.compile(rb'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)

WAF_MARKS = ['请求被拦截', '访问被拦截', '安全拦截', '防火墙', '雷池', 'safeline', '创宇盾',
             'webknight', '云waf', '安恒', '明御', '长亭', '深信服', 'sangfor', '访问过于频繁',
             'illegal request', 'blocked by', 'intercepted', '异常流量', 'ddos protection',
             '站点已过期', 'captcha', '等待验证']
WAF_SERVER = ('safedog', 'yunsuo', 'sangfor', 'waf', 'cwaf', 'aliyunwaf', 'anquanbao',
              'baiduyun', 'tencent-waf', 'openresty-waf')

JS_MARKS = ['ruoyi', '若依', 'jeecg', 'ant-design', 'antd', 'umi.js', 'vue-element-admin',
            'layuimini', 'easyweb', 'qiankun', 'element-ui', 'iview', 'bootstrap-table',
            'nacos', 'seeyon', 'ecology', 'eoffice', 'tongda', '金蝶', '用友', '泛微', '致远',
            '通达', '帆软', 'finereport', 'kingdee', 'yonyou', 'sso', 'cas', 'aTrust',
            'easyconnect', 'onlyoffice']

MAGIC_PATHS = ['/actuator', '/actuator/health', '/druid/index.html', '/swagger-ui.html',
               '/v2/api-docs', '/doc.html', '/nacos/', '/eureka/apps',
               '/xxl-job-admin/toLogin', '/solr/', '/jenkins/login', '/seeyon/',
               '/prod-api/captchaImage', '/login']


def waf_hit(code, headers, body_txt):
    s = (headers.get('server') or headers.get('Server') or '').lower()
    if any(x in s for x in WAF_SERVER):
        return 'server头:' + s[:30]
    low = body_txt[:3000].lower()
    if code in (403, 412, 418, 429, 493, 499) and any(m in low or m in body_txt[:600] for m in WAF_MARKS):
        return '拦截页'
    return ''


def load_fpdb(path):
    if path and os.path.isfile(path):
        return json.load(open(path))
    if os.path.isfile(SEED_FPDB):
        return json.load(open(SEED_FPDB))
    return {'rules': [], 'hash_rules': [], 'path_rules': []}


def match_fp(rec, fpdb):
    """对 root 探测结果跑关键词规则; 返回命中的产品列表。"""
    body = rec.get('body_head', '')
    title = rec.get('title', '')
    hdr = ' '.join(f"{k}: {v}" for k, v in (rec.get('headers_flat') or {}).items())
    hay = {'body': body[:20000], 'title': title, 'header': hdr}
    hits = set()
    for r in fpdb.get('rules') or []:
        loc = r.get('loc')
        if loc not in hay:
            continue
        h = hay[loc].lower()
        if all(kw.lower() in h for kw in r['kws']):
            hits.add(r['product'])
    # favicon hash 规则
    fh = rec.get('favicon_mmh3')
    if fh is not None:
        for h in fpdb.get('hash_rules') or []:
            if h.get('hash') == fh:
                hits.add(h['product'])
    return sorted(hits)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--work', default='.')
    ap.add_argument('--threads', type=int, default=10)
    ap.add_argument('--skip-paths', action='store_true', dest='skip_paths')
    ap.add_argument('--fpdb', default='')
    args = ap.parse_args()

    assets_path = os.path.join(runs_dir(args.work), 'assets.jsonl')
    if not os.path.isfile(assets_path):
        raise SystemExit('[!] 先跑 s5_dedupe.py')
    out = os.path.join(runs_dir(args.work), 'probe')
    os.makedirs(out, exist_ok=True)
    fpdb = load_fpdb(args.fpdb)
    print(f'fpdb: kw={len(fpdb.get("rules") or [])} hash={len(fpdb.get("hash_rules") or [])} '
          f'path={len(fpdb.get("path_rules") or [])}')

    targets = []
    seen = set()
    for line in open(assets_path, encoding='utf-8'):
        r = json.loads(line)
        if not r.get('in_scope'):
            continue
        k = r['_key']
        if k in seen:
            continue
        seen.add(k)
        targets.append(r)
    print(f'in-scope web targets: {len(targets)}')

    lock, results = threading.Lock(), {}

    def probe_root(t):
        time.sleep(random.uniform(0.05, 0.4))
        url = t['url'] if '://' in t['url'] else 'http://' + t['url']
        code, headers, body = fetch(url, timeout=8)
        if code is None:
            return {'url': url, 'error': (headers or {}).get('error'), 'ts': time.time()}
        bt = body.decode('utf-8', 'ignore')
        m = TITLE_RE.search(body)
        rec = {
            'url': url, '_key': t['_key'], 'code': code,
            'server': headers.get('server', headers.get('Server', '')),
            'xpb': headers.get('x-powered-by', headers.get('X-Powered-By', '')),
            'setcookie': (headers.get('set-cookie', headers.get('Set-Cookie', '')) or '')[:120],
            'location': (headers.get('location', headers.get('Location', '')) or '')[:160],
            'title': (m.group(1).decode('utf-8', 'ignore').strip() if m else '')[:80],
            'gen': (META_GEN.search(body).group(1).decode('utf-8', 'ignore')
                    if META_GEN.search(body) else ''),
            'js': sorted({mk for mk in JS_MARKS if mk.lower() in bt.lower()})[:12],
            'waf': waf_hit(code, headers, bt),
            'body_head': bt[:1500], 'len': len(body),
            'headers_flat': {k.lower(): str(v)[:120] for k, v in headers.items() if k != 'error'},
            'ts': time.time(),
        }
        if code in (200, 302, 401, 403):
            time.sleep(random.uniform(0.05, 0.2))
            fc, fh_, fb = fetch(url.rstrip('/') + '/favicon.ico', timeout=5)
            if fc == 200 and fb:
                rec['favicon_mmh3'] = favicon_hash(fb)
        return rec

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(probe_root, t): t for t in targets}
        for i, fu in enumerate(as_completed(futs), 1):
            r = fu.result()
            if r:
                with lock:
                    results[r['url']] = r
            if i % 100 == 0:
                print(f'root {i}/{len(targets)}', flush=True)
    json.dump(results, open(os.path.join(out, 'root.json'), 'w'), ensure_ascii=False)
    ok = sum(1 for v in results.values() if v.get('code') is not None)
    print(f'phase1: {ok}/{len(targets)} responded')

    # ---- phase2 敏感路径 ----
    if not args.skip_paths:
        responsive = [t for t in targets
                      if results.get(t['url'] if '://' in t['url'] else 'http://' + t['url'], {}).get('code') is not None]
        random.shuffle(responsive)

        def probe_paths(t):
            url = (t['url'] if '://' in t['url'] else 'http://' + t['url']).rstrip('/')
            hits = []
            for p in MAGIC_PATHS:
                time.sleep(random.uniform(0.08, 0.35))
                code, headers, body = fetch(url + p, timeout=6)
                if code is None:
                    continue
                bt = body.decode('utf-8', 'ignore')
                m = TITLE_RE.search(body)
                interesting = code in (200, 302, 401) and (
                    (code == 200 and (('json' in (headers.get('content-type', headers.get('Content-Type', '')) or '')
                                       and p not in ('/', '/login')) or len(bt) > 120))
                    or code in (200, 302))
                if interesting:
                    hits.append({'path': p, 'code': code,
                                 'title': (m.group(1).decode('utf-8', 'ignore').strip() if m else '')[:60],
                                 'ctype': (headers.get('content-type', headers.get('Content-Type', '')) or '')[:40],
                                 'head': bt[:300]})
            return {'url': url, 'paths': hits}

        path_res = {}
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = {ex.submit(probe_paths, t): t for t in responsive}
            for fu in as_completed(futs):
                r = fu.result()
                with lock:
                    path_res[r['url']] = r
        json.dump(path_res, open(os.path.join(out, 'paths.json'), 'w'), ensure_ascii=False)
        nhit = sum(1 for v in path_res.values() if v['paths'])
        print(f'phase2: {len(path_res)} probed, {nhit} with path hits')

    # ---- phase3 指纹 ----
    fp = {}
    for url, rec in results.items():
        if rec.get('code') is None:
            continue
        prods = match_fp(rec, fpdb)
        extra = rec.get('gen') or ''
        if prods or extra:
            fp[url] = {'products': prods, 'generator': extra,
                       'js': rec.get('js', []), 'favicon_mmh3': rec.get('favicon_mmh3'),
                       'waf': rec.get('waf')}
    json.dump(fp, open(os.path.join(out, 'fp.json'), 'w'), ensure_ascii=False)
    nfp = sum(1 for v in fp.values() if v['products'])
    print(f'phase3: {nfp} targets fingerprinted')
    print('PROBE DONE')


if __name__ == '__main__':
    main()

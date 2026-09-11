#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""指纹库全量重建 — 拉取开源指纹库并归一化为统一规则格式。

用法:
  python3 fpdb_update.py [--proxy http://127.0.0.1:7890] [--out <skill>/assets/unified_rules.json]

源 (四库合一, ~8300 条规则 / 4200+ 产品):
  EASY233_Finger  github.com/EASY233/Finger        (finger.json, ehole格式)
  EHole           github.com/EdgeSecurityTeam/EHole (fingerprint.json)
  FingerprintHub  github.com/0x727/FingerprintHub   (web_fingerprint_v4.json, nuclei风格路径规则)
  fingers_http    chainreactors/fingers http规则    (fingers.json)

输出格式: {"rules":[{product,loc,kws[],source}], "hash_rules":[{product,hash}],
          "path_rules":[{product,path,loc,kws[],ci,source}]}
GitHub 直连不通时走 --proxy 或 jsdelivr CDN 自动回退。
"""
import argparse, json, os, subprocess, sys, urllib.request

SRC = [
    ('EASY233', 'https://raw.githubusercontent.com/EASY233/Finger/main/library/finger.json',
     'https://cdn.jsdelivr.net/gh/EASY233/Finger@main/library/finger.json'),
    ('EHole', 'https://raw.githubusercontent.com/EdgeSecurityTeam/EHole/main/fingerprint.json',
     'https://cdn.jsdelivr.net/gh/EdgeSecurityTeam/EHole@main/fingerprint.json'),
    ('FPHub', 'https://raw.githubusercontent.com/0x727/FingerprintHub/main/web_fingerprint_v4.json',
     'https://cdn.jsdelivr.net/gh/0x727/FingerprintHub@main/web_fingerprint_v4.json'),
    ('fingers', 'https://raw.githubusercontent.com/Mr-xn/Finger/main/fingers_http.json',
     'https://cdn.jsdelivr.net/gh/Mr-xn/Finger@main/fingers_http.json'),
]


def get(url, proxy):
    if proxy:
        out = subprocess.run(['curl', '-sm', '60', '-x', proxy, '-L', url],
                             capture_output=True, timeout=90).stdout
        return out if out[:1] in (b'[', b'{') else b''
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read()
    except Exception:
        return b''


def fetch_source(name, direct, cdn, proxy):
    for url in ((direct, cdn) if not proxy else (direct,)):
        raw = get(url, proxy)
        if raw:
            try:
                return name, json.loads(raw)
            except Exception:
                continue
    return name, None


def normalize(items):
    rules, hash_rules, path_rules = [], [], []
    for source, data in items:
        if not data:
            print(f'[!] {source} 拉取失败, 跳过')
            continue
        # ehole 风格
        if isinstance(data, dict) and 'fingerprint' in data:
            for r in data['fingerprint']:
                cms, method, loc, kws = r.get('cms'), r.get('method'), r.get('location'), r.get('keyword') or []
                if method == 'keyword' and loc in ('body', 'title', 'header') and kws:
                    rules.append({'product': cms, 'loc': loc, 'kws': [k.lower() for k in kws], 'source': source})
                elif method == 'favicon_hash':
                    for k in kws:
                        try:
                            hash_rules.append({'product': cms, 'hash': int(k), 'source': source})
                        except Exception:
                            pass
        # fingers_http 风格
        elif isinstance(data, list) and data and 'rule' in (data[0] or {}):
            for item in data:
                name = item.get('name')
                for sub in item.get('rule') or []:
                    rex = sub.get('regexps') or {}
                    for loc in ('body', 'header', 'title'):
                        pats = rex.get(loc) or []
                        if not isinstance(pats, list):
                            continue
                        for pat in pats:
                            if 3 <= len(pat) <= 80:
                                rules.append({'product': name, 'loc': loc, 'kws': [pat.lower()], 'source': source})
        # nuclei 风格
        elif isinstance(data, list) and data and 'http' in (data[0] or {}):
            for r in data:
                name = (r.get('info') or {}).get('name') or r.get('id')
                for block in r.get('http') or []:
                    paths = [p.replace('{{BaseURL}}', '') for p in block.get('path', [])]
                    for m in block.get('matchers', []):
                        if m.get('type') != 'word':
                            continue
                        words = [w.lower() for w in m.get('words', []) if isinstance(w, str)]
                        if not words:
                            continue
                        part = m.get('part', 'body')
                        loc = 'header' if part == 'header' else ('title' if part == 'title' else 'body')
                        for p in paths[:1]:
                            path_rules.append({'product': name, 'path': p, 'loc': loc, 'kws': words,
                                               'ci': m.get('case-insensitive', True), 'source': source})
        print(f'[+] {source}: 累计 kw={len(rules)} hash={len(hash_rules)} path={len(path_rules)}')

    # 去重
    seen, out_r = set(), []
    for r in rules:
        k = (r['product'], r['loc'], tuple(sorted(r['kws'])))
        if k not in seen:
            seen.add(k)
            out_r.append(r)
    seen_h, out_h = set(), []
    for h in hash_rules:
        k = (h['product'], h['hash'])
        if k not in seen_h:
            seen_h.add(k)
            out_h.append(h)
    seen_p, out_p = set(), []
    for p in path_rules:
        if not p['path'] or len(p['path']) > 60:
            continue
        k = (p['product'], p['path'])
        if k not in seen_p:
            seen_p.add(k)
            out_p.append(p)
    return {'rules': out_r, 'hash_rules': out_h, 'path_rules': out_p}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--proxy', default='')
    ap.add_argument('--out', default=os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), 'assets', 'unified_rules.json'))
    args = ap.parse_args()

    items = [fetch_source(*s, proxy=args.proxy or None) for s in SRC]
    db = normalize(items)
    json.dump(db, open(args.out, 'w', encoding='utf-8'), ensure_ascii=False)
    print(f'unified fpdb -> {args.out}')
    print(f"kw rules: {len(db['rules'])} | hash rules: {len(db['hash_rules'])} | path rules: {len(db['path_rules'])}")


if __name__ == '__main__':
    main()

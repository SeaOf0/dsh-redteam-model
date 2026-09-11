#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S2 测绘平台统一查询器 — FOFA / Hunter / Quake / ZoomEye(钟馗之眼) / Shodan。

用法:
  python3 s2_engines.py --work <项目目录> [--only fofa,hunter] [--max-pages 3] [--no-icp]

行为:
  * 只跑 keys.json 里配置了密钥的平台; 每平台对 scope.json 的
    每个主域跑"域名查询"、每个备案号跑"ICP反查" (支持的平台)。
  * 断点续跑: 已有非空结果文件的查询自动 [skip]。
  * 限速 2~3.5s/查询, 每页后输出剩余配额。
  * 原始响应存 runs/engines/<engine>__<tag>.json;
    归一化记录统一追加 runs/engines/engines_all.jsonl (字段见 _common 注释)。
"""
import argparse, base64, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import api_get, api_post_json, gentle_sleep, runs_dir

# ---------------------------------------------------------------------------


def out_dir(work):
    d = os.path.join(runs_dir(work), 'engines')
    os.makedirs(d, exist_ok=True)
    return d


def append_jsonl(path, recs):
    with open(path, 'a', encoding='utf-8') as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')


def done(f):
    return os.path.isfile(f) and os.path.getsize(f) > 10


# ============================ FOFA ============================

def fofa_query(keys, scope, work, args):
    key = keys['fofa'].get('key')
    if not key:
        print('[fofa] 无key, 跳过')
        return
    d = out_dir(work)
    jsonl = os.path.join(d, 'engines_all.jsonl')
    plans = []
    for u in scope['units']:
        for dom in u.get('domains') or []:
            plans.append((f'fofa__dom__{dom}', f'domain="{dom}"'))
        if not args.no_icp:
            for icp in u.get('icp') or []:
                plans.append((f'fofa__icp__{icp}', f'icp="{icp}号"'))
    for tag, q in plans:
        f = os.path.join(d, tag + '.json')
        if done(f):
            print(f'[fofa skip] {tag}')
            continue
        q64 = base64.b64encode(q.encode()).decode()
        recs, total, page = [], 0, 1
        while page <= args.max_pages:
            st, resp = api_get('https://fofa.info/api/v1/search/all', {
                'key': key, 'qbase64': q64, 'size': 100, 'page': page,
                'fields': 'host,ip,port,domain,icp,title,server,protocol',
            })
            if not isinstance(resp, dict) or resp.get('error') is True or not isinstance(resp.get('results'), list):
                print(f'[fofa] {q} 第{page}页异常: {str(resp)[:120]}')
                break
            total = resp.get('size', total)
            for r in resp['results']:
                host, ip, port, domain, icp, title, server, protocol = (list(r) + [''] * 8)[:8]
                if not host:
                    continue
                recs.append({
                    'engine': 'fofa', 'query': q,
                    'url': host, 'domain': domain, 'ip': ip, 'port': port,
                    'scheme': 'https' if str(host).startswith('https') else 'http',
                    'protocol': protocol or '', 'title': (title or '')[:80],
                    'icp_no': icp or '', 'icp_unit': '', 'component': server or '',
                    'region': '', 'status_code': '', 'updated_at': '', 'source_tag': 'FOFA',
                })
            if len(resp['results']) < 100:
                break
            page += 1
            gentle_sleep(1.5, 2.5)
        json.dump({'query': q, 'total': total, 'count': len(recs), 'results': recs},
                  open(f, 'w', encoding='utf-8'), ensure_ascii=False)
        append_jsonl(jsonl, recs)
        print(f'[fofa] {q}: total={total} got={len(recs)} (F点剩余见官方控制台)')
        gentle_sleep()


# ============================ Hunter(鹰图) ============================

def hunter_query(keys, scope, work, args):
    key = keys['hunter'].get('key')
    if not key:
        print('[hunter] 无key, 跳过')
        return
    d = out_dir(work)
    jsonl = os.path.join(d, 'engines_all.jsonl')
    plans = []
    for u in scope['units']:
        for dom in u.get('domains') or []:
            plans.append((f'hunter__dom__{dom}', f'domain.suffix="{dom}"'))
        if not args.no_icp:
            for icp in u.get('icp') or []:
                plans.append((f'hunter__icp__{icp}', f'icp.number="{icp}号"'))
    for tag, q in plans:
        f = os.path.join(d, tag + '.json')
        if done(f):
            print(f'[hunter skip] {tag}')
            continue
        qb64 = base64.b64encode(q.encode()).decode()
        start_time, end_time = '', ''
        if getattr(args, 'hunter_days', 365):
            from datetime import date, timedelta
            end_time = date.today().isoformat()
            start_time = (date.today() - timedelta(days=args.hunter_days)).isoformat()
        recs, total, page, rest = [], 0, 1, '?'
        while page <= args.max_pages:
            st, resp = api_get('https://hunter.qianxin.com/openApi/search', {
                'api-key': key, 'search': qb64, 'page': page, 'page_size': 100,
                'is_web': 3, 'bind': 'true', 'start_time': start_time, 'end_time': end_time,
            })
            data = (resp or {}).get('data') if isinstance(resp, dict) else None
            if not isinstance(data, dict) or not isinstance(data.get('arr'), list):
                msg = (resp or {}).get('message') if isinstance(resp, dict) else str(resp)[:120]
                print(f'[hunter] {q} 第{page}页异常: {msg}')
                break
            total, rest = data.get('total', total), data.get('rest_quota', rest)
            for it in data['arr']:
                if not it.get('url'):
                    continue
                recs.append({
                    'engine': 'hunter', 'query': q,
                    'url': it['url'], 'domain': it.get('domain') or '', 'ip': it.get('ip') or '',
                    'port': it.get('port'), 'scheme': 'https' if str(it.get('url', '')).startswith('https') else 'http',
                    'protocol': it.get('protocol') or '', 'title': (it.get('web_title') or '')[:80],
                    'icp_no': it.get('number') or '', 'icp_unit': it.get('company') or '',
                    'component': '; '.join(
                        f"{c.get('name', '')}{':' + c['version'] if c.get('version') else ''}"
                        for c in (it.get('component') or [])[:6]),
                    'region': f"{it.get('province', '')}{it.get('city', '')}",
                    'status_code': it.get('status_code'), 'updated_at': it.get('updated_at') or '',
                    'source_tag': 'Hunter',
                })
            if len(data['arr']) < 100 or len(recs) >= total:
                break
            page += 1
            gentle_sleep(1.5, 2.5)
        json.dump({'query': q, 'total': total, 'count': len(recs), 'results': recs},
                  open(f, 'w', encoding='utf-8'), ensure_ascii=False)
        append_jsonl(jsonl, recs)
        print(f'[hunter] {q}: total={total} got={len(recs)} 剩余积分={rest}')
        gentle_sleep()


# ============================ Quake ============================

def quake_query(keys, scope, work, args):
    key = keys['quake'].get('key')
    if not key:
        print('[quake] 无key, 跳过')
        return
    d = out_dir(work)
    jsonl = os.path.join(d, 'engines_all.jsonl')
    include = ['ip', 'port', 'transport', 'service.name',
               'service.http.host', 'service.http.title', 'service.http.response.http_status',
               'location.province_cn', 'location.city_cn', 'service.http.response.headers']
    plans = []
    for u in scope['units']:
        for dom in u.get('domains') or []:
            plans.append((f'quake__dom__{dom}', f'domain:"{dom}"'))
        if not args.no_icp:
            for icp in u.get('icp') or []:
                plans.append((f'quake__icp__{icp}', f'icp:"{icp}号"'))
    size = int(keys['quake'].get('size', 100))
    for tag, q in plans:
        f = os.path.join(d, tag + '.json')
        if done(f):
            print(f'[quake skip] {tag}')
            continue
        recs, total, start = [], 0, 0
        while start < (args.max_pages * size):
            st, resp = api_post_json(
                'https://quake.360.net/api/v3/search/quake_service',
                {'query': q, 'start': start, 'size': size, 'ignore_cache': False, 'include': include},
                headers={'X-QuakeToken': key})
            data = (resp or {}).get('data') if isinstance(resp, dict) else None
            if not isinstance(data, list):
                msg = (resp or {}).get('message') if isinstance(resp, dict) else str(resp)[:120]
                print(f'[quake] {q} start={start} 异常: {msg}')
                break
            total = (((resp or {}).get('meta') or {}).get('pagination') or {}).get('total', total)
            for it in data:
                http = ((it.get('service') or {}).get('http')) or {}
                host = http.get('host') or ''
                scheme = 'https' if (it.get('service') or {}).get('name') == 'https' else 'http'
                if not host:
                    continue
                recs.append({
                    'engine': 'quake', 'query': q,
                    'url': f"{scheme}://{host}" + ('' if ((scheme == 'https' and it.get('port') == 443) or (scheme == 'http' and it.get('port') == 80)) else f":{it.get('port')}"),
                    'domain': host, 'ip': it.get('ip') or '', 'port': it.get('port'),
                    'scheme': scheme, 'protocol': (it.get('service') or {}).get('name') or '',
                    'title': (http.get('title') or '')[:80], 'icp_no': '', 'icp_unit': '',
                    'component': '', 'region': f"{(it.get('location') or {}).get('province_cn', '')}{(it.get('location') or {}).get('city_cn', '')}",
                    'status_code': http.get('response', {}).get('http_status', ''),
                    'updated_at': '', 'source_tag': 'Quake',
                })
            if len(data) < size or len(recs) >= total:
                break
            start += size
            gentle_sleep(1.5, 2.5)
        json.dump({'query': q, 'total': total, 'count': len(recs), 'results': recs},
                  open(f, 'w', encoding='utf-8'), ensure_ascii=False)
        append_jsonl(jsonl, recs)
        print(f'[quake] {q}: total={total} got={len(recs)}')
        gentle_sleep()


# ============================ ZoomEye(钟馗之眼) ============================

def zoomeye_query(keys, scope, work, args):
    cfg = keys.get('zoomeye') or {}
    key = cfg.get('key')
    if not key:
        print('[zoomeye] 无key, 跳过')
        return
    base = cfg.get('base', 'https://api.zoomeye.hk').rstrip('/')
    hdr = {'API-KEY': key}
    # 配额
    st, info = api_get(base + '/resources-info', {}, headers=hdr)
    if isinstance(info, dict):
        print(f"[zoomeye] 配额: {json.dumps(info.get('resources') or info, ensure_ascii=False)[:160]}")
    d = out_dir(work)
    jsonl = os.path.join(d, 'engines_all.jsonl')
    for u in scope['units']:
        for dom in u.get('domains') or []:  # ZoomEye 不支持 ICP 反查, 只做域名面
            tag = f'zoomeye__dom__{dom}'
            f = os.path.join(d, tag + '.json')
            if done(f):
                print(f'[zoomeye skip] {tag}')
                continue
            recs, page, total = [], 1, 0
            while page <= args.max_pages:
                st, resp = api_get(base + '/host/search',
                                   {'query': f'site:{dom}', 'page': page, 'pagesize': 20},
                                   headers=hdr)
                lst = (resp or {}).get('list') if isinstance(resp, dict) else None
                if not isinstance(lst, list):
                    print(f'[zoomeye] {dom} 第{page}页异常: {str(resp)[:120]}')
                    break
                total = (resp or {}).get('total', total)
                for it in lst:
                    port = it.get('portinfo') or {}
                    host = (it.get('site') or '').split('/')[0] or it.get('ip', '')
                    if not host:
                        continue
                    scheme = 'https' if (port.get('service') or {}).get('name') == 'https' or port.get('ssl') else 'http'
                    recs.append({
                        'engine': 'zoomeye', 'query': f'site:{dom}',
                        'url': f"{scheme}://{host}" + ('' if (scheme == 'https' and it.get('port') == 443) or (scheme == 'http' and it.get('port') == 80) else f":{it.get('port')}"),
                        'domain': host if '.' in host and not host.replace('.', '').isdigit() else '',
                        'ip': it.get('ip') or '', 'port': it.get('port'),
                        'scheme': scheme, 'protocol': (port.get('service') or {}).get('name') or '',
                        'title': (port.get('title') or '')[:80], 'icp_no': '', 'icp_unit': '',
                        'component': (port.get('server') or '')[:60],
                        'region': '', 'status_code': '', 'updated_at': '', 'source_tag': 'ZoomEye',
                    })
                if len(lst) < 20:
                    break
                page += 1
                gentle_sleep(1.5, 2.5)
            json.dump({'query': f'site:{dom}', 'total': total, 'count': len(recs), 'results': recs},
                      open(f, 'w', encoding='utf-8'), ensure_ascii=False)
            append_jsonl(jsonl, recs)
            print(f'[zoomeye] site:{dom}: total={total} got={len(recs)}')
            gentle_sleep()


# ============================ Shodan ============================

def shodan_query(keys, scope, work, args):
    key = keys['shodan'].get('key')
    if not key:
        print('[shodan] 无key, 跳过')
        return
    st, info = api_get('https://api.shodan.io/api-info', {'key': key})
    if isinstance(info, dict):
        print(f"[shodan] query_credits={info.get('query_credits')}")
    d = out_dir(work)
    jsonl = os.path.join(d, 'engines_all.jsonl')
    for u in scope['units']:
        for dom in u.get('domains') or []:
            tag = f'shardan__dom__{dom}'
            f = os.path.join(d, tag + '.json')
            if done(f):
                print(f'[shodan skip] {tag}')
                continue
            recs, page, total = [], 1, 0
            while page <= args.max_pages:
                st, resp = api_get('https://api.shodan.io/shodan/host/search',
                                   {'key': key, 'query': f'hostname:{dom}', 'page': page})
                ms = (resp or {}).get('matches') if isinstance(resp, dict) else None
                if not isinstance(ms, list):
                    print(f'[shodan] {dom} 第{page}页异常: {str(resp)[:120]}')
                    break
                total = (resp or {}).get('total', total)
                for it in ms:
                    http = it.get('http') or {}
                    hostnames = it.get('hostnames') or ['']
                    host = hostnames[0] or it.get('ip_str', '')
                    scheme = 'https' if (it.get('ssl') or http.get('ssl')) or it.get('port') in (443, 8443) else 'http'
                    recs.append({
                        'engine': 'shodan', 'query': f'hostname:{dom}',
                        'url': f"{scheme}://{host}:{it.get('port')}",
                        'domain': host if '.' in host and not host.replace('.', '').isdigit() else '',
                        'ip': it.get('ip_str') or '', 'port': it.get('port'),
                        'scheme': scheme, 'protocol': 'http' if http else str(it.get('_shodan', {}).get('module', '')),
                        'title': (http.get('title') or '')[:80], 'icp_no': '', 'icp_unit': '',
                        'component': (http.get('server') or '')[:60],
                        'region': '', 'status_code': http.get('status'), 'updated_at': '', 'source_tag': 'Shodan',
                    })
                if len(ms) < 100:
                    break
                page += 1
                gentle_sleep(1.5, 2.5)
            json.dump({'query': f'hostname:{dom}', 'total': total, 'count': len(recs), 'results': recs},
                      open(f, 'w', encoding='utf-8'), ensure_ascii=False)
            append_jsonl(jsonl, recs)
            print(f'[shodan] hostname:{dom}: total={total} got={len(recs)}')
            gentle_sleep()


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--work', default='.')
    ap.add_argument('--only', default='', help='逗号分隔: fofa,hunter,quake,zoomeye,shodan')
    ap.add_argument('--max-pages', type=int, default=3, dest='max_pages')
    ap.add_argument('--no-icp', action='store_true', dest='no_icp')
    ap.add_argument('--proxy', default='', help='http(s) 代理, 用于 shodan/zoomeye 等国际源')
    ap.add_argument('--hunter-days', type=int, default=365, dest='hunter_days',
                    help='Hunter 时间窗(天), 0=不限; 默认近一年')
    args = ap.parse_args()

    from _common import load_keys, load_scope, set_proxy
    keys, scope = load_keys(args.work), load_scope(args.work)
    only = {x.strip() for x in args.only.split(',') if x.strip()}

    jobs = {'fofa': fofa_query, 'hunter': hunter_query, 'quake': quake_query,
            'zoomeye': zoomeye_query, 'shodan': shodan_query}
    for name, fn in jobs.items():
        if only and name not in only:
            continue
        if name in ('shodan', 'zoomeye') and args.proxy:
            set_proxy(args.proxy)
        elif args.proxy:
            set_proxy(None)
        fn(keys, scope, args.work, args)
    print('ENGINES DONE')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""asset-mapping skill 共享工具库。
约定: 每个测绘项目一个工作目录 <work>/, 内含:
  keys.json   平台API密钥 (缺哪个平台就跳过哪个)
  scope.json  范围定义 (单位→域名/备案号)
  runs/       各阶段产物 (engines/ crt/ dns/ probe/ *.jsonl *.xlsx)
仅依赖 python3 标准库; Excel 输出另需 openpyxl。
"""
import base64, json, os, random, ssl, subprocess, time
import urllib.request, urllib.error
from urllib.parse import urlparse

UA = ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36')

# ---------------------------------------------------------------------------
# 工作目录/输入文件
# ---------------------------------------------------------------------------

def borrow_hunter_keys():
    """只读借用 dsh-hunter 插件已配置的 API key（~/.dsh/hunter/hunter.db configs 表）。

    - 仅覆盖 fofa/hunter/quake（dsh-hunter 支持面）；进程内使用、绝不落盘。
    - 读取失败（文件不存在/表缺失/sqlite 不可用/schema 变更）静默返回 {}，等价于无 key。
    """
    out = {}
    try:
        import sqlite3
        db_path = os.path.join(os.path.expanduser('~'), '.dsh', 'hunter', 'hunter.db')
        if not os.path.isfile(db_path):
            return out
        con = sqlite3.connect('file:%s?mode=ro' % db_path, uri=True)
        try:
            rows = con.execute(
                "SELECT platform, key_value FROM configs WHERE key_value != ''"
            ).fetchall()
        finally:
            con.close()
        for platform, key in rows:
            platform = str(platform).strip().lower()
            if platform in ('fofa', 'hunter', 'quake') and key:
                out[platform] = {'key': str(key)}
    except Exception:
        return {}
    return out


def load_keys(work):
    p = os.path.join(work, 'keys.json')
    local = {}
    if os.path.isfile(p):
        local = json.load(open(p))
    # key 三分支之借用分支：keys.json 缺的平台，从 dsh-hunter 只读借用补齐（不落盘）。
    have = {k for k, v in local.items() if isinstance(v, dict) and v.get('key')}
    missing = {'fofa', 'hunter', 'quake'} - have
    if missing:
        for plat, kv in borrow_hunter_keys().items():
            if plat in missing:
                local[plat] = kv
                print('[i] 借用 dsh-hunter 已配 %s key（进程内使用，不落盘；持久化请填 keys.json）' % plat)
    return local


def load_scope(work):
    p = os.path.join(work, 'scope.json')
    if not os.path.isfile(p):
        raise SystemExit(f'[!] 缺少范围文件 {p} — 参照 skill assets/scope.example.json 先建好')
    return json.load(open(p))


def runs_dir(work):
    d = os.path.join(work, 'runs')
    os.makedirs(d, exist_ok=True)
    return d


def sub_dir(work, name):
    d = os.path.join(runs_dir(work), name)
    os.makedirs(d, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# 统一记录 / 去重 key  (测绘平台结果都归一到这个 schema)
# ---------------------------------------------------------------------------
# {engine, query, url, domain, ip, port, scheme, protocol, title,
#  icp_no, icp_unit, component, region, status_code, updated_at, source_tag}

def norm_key(url):
    """host:port:scheme 归一化 —— 多源合并去重的唯一口径。对已归一化的 key 幂等。"""
    if not url:
        return ''
    if url.count(':') == 2 and '//' not in url:      # 已是 host:port:scheme 形态
        h, port, scheme = url.lower().split(':')
        if h and port.isdigit() and scheme in ('http', 'https'):
            return url.lower()
    u = url if '//' in url else 'http://' + url
    p = urlparse(u)
    if not p.hostname:
        return url.lower()
    try:
        port = p.port
    except ValueError:
        port = None
    port = port or (443 if p.scheme == 'https' else 80)
    return f"{p.hostname.lower()}:{port}:{p.scheme}"


def merge_record(store, rec, enrich_fields=('icp_no', 'icp_unit', 'title', 'ip', 'domain',
                                            'component', 'region', 'status_code')):
    """按 norm_key 合并: 后到的源只补空字段 + 追加来源标记, 不覆盖已有值。"""
    k = rec.get('_key') or norm_key(rec.get('url') or '')
    if not k:
        return
    rec['_key'] = k
    if k in store:
        ex = store[k]
        for f in enrich_fields:
            if not ex.get(f) and rec.get(f):
                ex[f] = rec[f]
        if rec.get('source_tag') and rec['source_tag'] not in ex.get('source_tag', ''):
            ex['source_tag'] = (ex.get('source_tag', '') + '+' + rec['source_tag']).strip('+')
        return
    store[k] = rec


# ---------------------------------------------------------------------------
# HTTP (探测用: 忽略TLS告警 / 不跟跳转 / UA伪装)
# ---------------------------------------------------------------------------

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=_CTX))

# 全局可选代理 (API 访问国际源如 shodan/zoomeye 时设置)
_PROXY = None


def set_proxy(p):
    global _PROXY
    _PROXY = p


def _api_opener():
    if _PROXY:
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({'http': _PROXY, 'https': _PROXY}))
    return urllib.request.build_opener()


def fetch(url, timeout=8, method='GET'):
    """返回 (status, headers-dict, body-bytes); 异常时 status=None。"""
    req = urllib.request.Request(url, method=method, headers={
        'User-Agent': UA,
        'Accept': 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9',
    })
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(65536)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(65536)
        except Exception:
            body = b''
        return e.code, dict(e.headers or {}), body
    except Exception as ex:
        return None, {'error': str(ex)[:120]}, b''


def api_get(url, params, headers=None, timeout=25):
    """GET + urlencoded params, 返回 (status, resp-json-or-text)。"""
    from urllib.parse import urlencode
    full = url + ('&' if '?' in url else '?') + urlencode(params)
    req = urllib.request.Request(full, headers=headers or {})
    try:
        with _api_opener().open(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, raw.decode('utf-8', 'ignore')
    except urllib.error.HTTPError as e:
        raw = e.read() if e.fp else b''
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw.decode('utf-8', 'ignore')[:500]
    except Exception as ex:
        return None, f'request-error: {ex}'


def api_post_json(url, payload, headers=None, timeout=25):
    data = json.dumps(payload).encode()
    hdr = {'Content-Type': 'application/json', 'User-Agent': UA}
    hdr.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdr)
    try:
        with _api_opener().open(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, raw.decode('utf-8', 'ignore')
    except urllib.error.HTTPError as e:
        raw = e.read() if e.fp else b''
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw.decode('utf-8', 'ignore')[:500]
    except Exception as ex:
        return None, f'request-error: {ex}'


def curl_get(url, timeout=30, proxy=None):
    """curl 兜底 (处理 urllib 不便的场景, 可走代理)。返回 stdout 文本。"""
    cmd = ['curl', '-sm', str(timeout), '-A', UA, url]
    if proxy:
        cmd[-1:-1] = ['-x', proxy]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10).stdout
    except Exception:
        return ''


def gentle_sleep(a=2.0, b=3.5):
    time.sleep(random.uniform(a, b))


# ---------------------------------------------------------------------------
# murmurhash3 x86_32 (FOFA icon_hash 口径) —— favicon 指纹比对用
# ---------------------------------------------------------------------------

def mmh3_32(data: bytes, seed: 0) -> int:
    data = bytearray(data)
    length, nblocks, h1 = len(data), len(data) // 4, seed
    c1, c2 = 0xcc9e2d51, 0x1b873593
    for i in range(nblocks):
        k1 = int.from_bytes(data[i * 4:(i + 1) * 4], 'little')
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1, tail = 0, data[nblocks * 4:]
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 >= 0x80000000 else h1


def favicon_hash(body: bytes) -> int:
    return mmh3_32(base64.b64encode(body))

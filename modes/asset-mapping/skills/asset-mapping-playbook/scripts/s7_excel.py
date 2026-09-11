#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S7 测绘Excel输出 — 五工作表 (测绘总表/域名清单/子域名清单/单位汇总/测绘说明)。

用法: python3 s7_excel.py --work <项目目录> [--name 项目名]
依赖: openpyxl
"""
import argparse, json, math, os, sys
from collections import Counter
from datetime import date
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import load_scope, runs_dir

try:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
except ImportError:
    raise SystemExit('[!] 缺 openpyxl: pip3 install openpyxl')

THIN = Border(*[Side(style='thin', color='CCCCCC')] * 4)
HDR_FILL = PatternFill('solid', fgColor='1F4E79')
HDR_FONT = Font(color='FFFFFF', bold=True, size=11)
OUT_FILL = PatternFill('solid', fgColor='E7E6E6')   # 范围外=灰
HIGH_FILL = PatternFill('solid', fgColor='FCE4D6')  # 高关联=橙
NEW_FILL = PatternFill('solid', fgColor='E2EFDA')   # 新发现=绿


def hdr(ws, ncol):
    ws.append([None] * ncol)  # placeholder removed below
    ws.delete_rows(ws.max_row)
    for c in ws[1]:
        c.fill, c.font, c.border = HDR_FILL, HDR_FONT, THIN


def style_row(ws, fill=None):
    r = ws.max_row
    for c in ws[r]:
        c.border = THIN
        c.alignment = Alignment(vertical='center')
        if fill:
            c.fill = fill


def set_widths(ws, widths):
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--work', default='.')
    ap.add_argument('--name', default='')
    args = ap.parse_args()

    scope = load_scope(args.work)
    proj = args.name or scope.get('project', '企业资产测绘')
    today = date.today().isoformat()

    rows = [json.loads(l) for l in open(os.path.join(runs_dir(args.work), 'assets.jsonl'), encoding='utf-8')]
    dns_dir = os.path.join(runs_dir(args.work), 'dns')
    crt_dir = os.path.join(runs_dir(args.work), 'crt')
    probe_dir = os.path.join(runs_dir(args.work), 'probe')

    # 指纹并入
    fp = {}
    fp_path = os.path.join(probe_dir, 'fp.json')
    if os.path.isfile(fp_path):
        for url, v in json.load(open(fp_path)).items():
            fp[url.rstrip('/')] = v
    def fp_of(url):
        v = fp.get((url or '').rstrip('/')) or {}
        return ', '.join(v.get('products') or []) or (v.get('generator') or '')

    units = scope['units']
    unit2sys = {u['name']: u.get('system', '-') for u in units}
    all_domains = sorted({d for u in units for d in (u.get('domains') or [])})
    dom_assets = Counter(r.get('domain') for r in rows if r.get('domain'))

    wb = Workbook()

    # ============ Sheet1 测绘总表 ============
    ws = wb.active
    ws.title = '测绘总表'
    headers = ['序号', '二级单位', '靶标/业务系统', '资产URL', '域名', 'IP', '端口', '协议/服务',
               '网站标题', '组件指纹', '指纹(探测)', '归属省市', '状态码', 'ICP备案号', 'ICP备案单位',
               '靶标关联度', '数据来源', '备注']
    ws.append(headers)
    for c in ws[1]:
        c.fill, c.font, c.border = HDR_FILL, HDR_FONT, THIN
    for i, r in enumerate(rows, 1):
        ws.append([i, r['unit'], unit2sys.get(r['unit'].replace('【范围外】', ''), '-'),
                   r.get('url', ''), r.get('domain', ''), r.get('ip', ''), r.get('port', ''),
                   r.get('protocol', ''), (r.get('title') or '')[:60], r.get('component', ''),
                   fp_of(r.get('url', '')), r.get('region', ''), r.get('status_code', ''),
                   r.get('icp_no') or '未备案/未获取', r.get('icp_unit', ''),
                   r.get('rel', ''), r.get('source_tag', ''), r.get('note', '')])
        if not r.get('in_scope'):
            style_row(ws, OUT_FILL)
        elif r.get('rel') == '高':
            style_row(ws, HIGH_FILL)
        else:
            style_row(ws)
    set_widths(ws, [6, 16, 20, 42, 30, 15, 7, 10, 30, 30, 22, 12, 8, 20, 26, 9, 12, 28])
    ws.freeze_panes = 'A2'
    ws.auto_filter.ref = ws.dimensions

    # ============ Sheet2 域名清单 ============
    wc = json.load(open(os.path.join(dns_dir, 'wildcard.json'))) \
        if os.path.isfile(os.path.join(dns_dir, 'wildcard.json')) else {}
    alive = {}
    alive_path = os.path.join(dns_dir, 'alive_subs.txt')
    if os.path.isfile(alive_path):
        for line in open(alive_path):
            p = line.split()
            if p:
                alive[p[0]] = p[1] if len(p) > 1 else ''
    dom_icp, dom_icp_unit = {}, {}
    for r in rows:
        if r.get('domain') and r.get('icp_no') and r['domain'] not in dom_icp:
            dom_icp[r['domain']] = r['icp_no']
            dom_icp_unit[r['domain']] = r.get('icp_unit', '')
    ws2 = wb.create_sheet('域名清单')
    ws2.append(['序号', '二级单位', '域名', 'ICP备案号', 'ICP备案单位', '泛解析检测',
                '存活子域数', '资产条数(平台)', '发现来源'])
    for c in ws2[1]:
        c.fill, c.font, c.border = HDR_FILL, HDR_FONT, THIN
    unit_by_domain = {d: u['name'] for u in units for d in (u.get('domains') or [])}
    for i, d in enumerate(all_domains, 1):
        alive_cnt = sum(1 for s in alive if s.endswith('.' + d))
        ws2.append([i, unit_by_domain.get(d, ''), d, dom_icp.get(d, ''), dom_icp_unit.get(d, ''),
                    '泛解析!' if (wc.get(d) or {}).get('wildcard') else '无泛解析',
                    alive_cnt, dom_assets.get(d, 0), 'scope.json'])
        style_row(ws2, NEW_FILL if (wc.get(d) or {}).get('wildcard') else None)
    set_widths(ws2, [6, 16, 30, 20, 28, 11, 11, 14, 14])
    ws2.freeze_panes = 'A2'

    # ============ Sheet3 子域名清单 ============
    ws3 = wb.create_sheet('子域名清单(DNS存活)')
    ws3.append(['序号', '主域名', '子域名', '归属单位', 'DNS存活', '解析IP', '是否在资产表'])
    for c in ws3[1]:
        c.fill, c.font, c.border = HDR_FILL, HDR_FONT, THIN
    asset_domains = {r.get('domain') for r in rows if r.get('domain')}
    i = 0
    for sub in sorted(alive):
        main = next((d for d in all_domains if sub == d or sub.endswith('.' + d)), '')
        i += 1
        ws3.append([i, main, sub, unit_by_domain.get(main, '【范围外】'), '是', alive[sub],
                    '是' if sub in asset_domains else '否'])
        style_row(ws3)
    set_widths(ws3, [6, 26, 40, 16, 9, 26, 13])
    ws3.freeze_panes = 'A2'
    ws3.auto_filter.ref = ws3.dimensions

    # ============ Sheet4 单位汇总 ============
    ws4 = wb.create_sheet('单位汇总')
    ws4.append(['二级单位', '靶标/业务系统', '主域名', '范围内资产数', '高关联资产数', '主站ICP备案', '存活子域数', '备注'])
    for c in ws4[1]:
        c.fill, c.font, c.border = HDR_FILL, HDR_FONT, THIN
    for u in units:
        mine = [r for r in rows if r['unit'] == u['name']]
        doms = u.get('domains') or []
        icps = Counter(r['icp_no'] for r in mine if r.get('icp_no'))
        subs = sum(1 for s in alive if any(s == d or s.endswith('.' + d) for d in doms))
        ws4.append([u['name'], u.get('system', '-'), ', '.join(doms) or '(挂靠集团域)',
                    len(mine), sum(1 for r in mine if r.get('rel') == '高'),
                    '; '.join(icps.keys()) or '-', subs, u.get('note', '')])
        for c in ws4[ws4.max_row]:
            c.border = THIN
            c.alignment = Alignment(vertical='top', wrap_text=True)
    oos = [r for r in rows if not r.get('in_scope')]
    if oos:
        ws4.append(['【范围外】', '-', ', '.join(scope.get('group_domains_out_of_scope') or []),
                    len(oos), '-', '-', sum(1 for s in alive if not any(
                        s == d or s.endswith('.' + d) for u in units for d in (u.get('domains') or []))),
                    '未授权/未归属; 剔除项见测绘说明'])
        for c in ws4[ws4.max_row]:
            c.border, c.fill = THIN, OUT_FILL
    set_widths(ws4, [16, 22, 36, 13, 12, 30, 11, 36])
    for row in ws4.iter_rows(min_row=2):
        txt = max((str(c.value or '') for c in row), key=len)
        ws4.row_dimensions[row[0].row].height = max(16, 16 * math.ceil(len(txt) / 60))

    # ============ Sheet5 框架资产(指纹/路径命中) ============
    ws6 = wb.create_sheet('框架资产(指纹命中)', 4)
    ws6.append(['序号', '二级单位', '资产URL', '指纹命中', '敏感路径命中', 'WAF', 'favicon_mmh3'])
    for c in ws6[1]:
        c.fill, c.font, c.border = HDR_FILL, HDR_FONT, THIN
    paths_json = {}
    paths_path = os.path.join(probe_dir, 'paths.json')
    if os.path.isfile(paths_path):
        paths_json = json.load(open(paths_path))
    unit_by_url = {}
    for r in rows:
        u = (r.get('url') or '').rstrip('/')
        if u.startswith('http'):
            unit_by_url[u] = r.get('unit', '')
    fw_i = 0
    for url in sorted(fp):
        v = fp[url]
        ph = '; '.join(f"{p['path']}({p['code']})" for p in (paths_json.get(url, {}) or {}).get('paths', []))
        if not v.get('products') and not ph:
            continue
        fw_i += 1
        ws6.append([fw_i, unit_by_url.get(url, ''), url,
                    ', '.join(v.get('products') or []) or (v.get('generator') or ''),
                    ph, v.get('waf', ''), v.get('favicon_mmh3', '')])
        style_row(ws6)
    set_widths(ws6, [6, 16, 44, 36, 40, 12, 14])
    ws6.freeze_panes = 'A2'
    ws6.auto_filter.ref = ws6.dimensions

    # ============ Sheet6 测绘说明 ============
    n_in = sum(1 for r in rows if r.get('in_scope'))
    engines = Counter(r.get('source_tag', '?') for r in rows)
    ws5 = wb.create_sheet('测绘说明')
    notes = [
        [f'{proj} · 资产测绘', ''],
        ['生成日期', today],
        ['授权范围', scope.get('authorization', '')],
        ['测绘口径', scope.get('criteria', '范围单位全部公网资产(不限于靶标系统)')],
        ['数据来源', f'平台分布: {dict(engines)}; 子域: crt.sh/RapidDNS; DNS: 公共DNS批量存活校验+泛解析检测; 探测: 根路径/favicon/敏感路径(温和)'],
        ['合并口径', f'多平台按 host:port:scheme 归一去重, 共{len(rows)}条(范围内{n_in}/范围外{len(rows) - n_in}); ICP字段互补补全'],
        ['准确性控制', '①泛解析检测(随机子域双探针); ②伪造备案垃圾过滤(IP垃圾段+博彩标题); ③范围外主体人工剔除; ④子域仅保留DNS存活'],
        ['填表规则', '高关联=橙底; 范围外=灰底; 泛解析域名=绿底标记'],
        ['局限', '内网型系统无公网暴露需现场测绘; 平台ICP反查仅采样; crt.sh超时域名可重跑s3断点续传'],
    ]
    for r in notes:
        ws5.append(r)
    ws5.column_dimensions['A'].width = 22
    ws5.column_dimensions['B'].width = 110
    for row in ws5.iter_rows(min_row=2):
        txt = str(row[1].value or '')
        ws5.row_dimensions[row[0].row].height = max(16, 16 * math.ceil(len(txt) / 52))
    ws5['A1'].font = Font(bold=True, size=13)

    out = os.path.join(args.work, f'{proj}_资产测绘_{today}.xlsx')
    wb.save(out)
    print('saved:', out)
    print(f'rows={len(rows)} in_scope={n_in} domains={len(all_domains)} alive_subs={len(alive)}')


if __name__ == '__main__':
    main()

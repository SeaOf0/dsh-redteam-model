#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S1 范围文件辅助工具 — ICP备案清册起草 + 单域备案快查。

用法:
  # 从已有平台查询结果里提炼 备案号→(主体, 域名列表) 清册, 人工核对后填回 scope.json
  python3 s1_scope_tools.py --work <项目目录> --icp-census

  # 单个域名的备案信息快查 (beianx.cn 抓取, 尽力而为)
  python3 s1_scope_tools.py --beianx example.com

说明: 工信部官方备案查询(beian.miit.gov.cn)有登录+验证码墙, 全自动不可行;
     本工具用平台ICP字段+第三方快查做"清册草稿", 终稿以人工核对为准。
     企业架构(母公司→二级子公司+控股比例)推荐爱企查浏览器流程, 见 references/osint-sources.md。
"""
import argparse, json, os, re, sys
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import curl_get, runs_dir


def icp_census(work):
    """聚合 engines_all.jsonl 的 ICP 字段 → runs/icp_census.json"""
    src = os.path.join(runs_dir(work), 'engines', 'engines_all.jsonl')
    if not os.path.isfile(src):
        raise SystemExit('[!] 先跑 s2_engines.py')
    m = defaultdict(lambda: {'units': set(), 'domains': set(), 'n_assets': 0})
    for line in open(src, encoding='utf-8'):
        try:
            r = json.loads(line)
        except Exception:
            continue
        icp = (r.get('icp_no') or '').strip()
        if not icp:
            continue
        e = m[re.sub(r'[-—–]\d+$', '', icp)]
        if r.get('icp_unit'):
            e['units'].add(r['icp_unit'])
        if r.get('domain'):
            e['domains'].add(r['domain'])
        e['n_assets'] += 1
    out = os.path.join(runs_dir(work), 'icp_census.json')
    data = {k: {'units': sorted(v['units']), 'domains': sorted(v['domains'])[:20],
                'domain_count': len(v['domains']), 'n_assets': v['n_assets']}
            for k, v in sorted(m.items(), key=lambda x: -x[1]['n_assets'])}
    json.dump(data, open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(f'ICP清册: {len(data)} 个备案号 -> {out}')
    for k, v in list(data.items())[:30]:
        print(f"  {k:22s} {v['units'][:1]} 域名{v['domain_count']} 资产{v['n_assets']}")
    print('→ 人工核对主体真伪后, 把真实备案号(去掉末尾-序号)填入 scope.json 各单位 icp 字段')


def beianx(domain):
    html = curl_get(f'https://www.beianx.cn/search/{domain}', timeout=20)
    icp = re.findall(r'(京|沪|粤|浙|苏|鲁|川|渝|津|冀|晋|蒙|辽|吉|黑|皖|闽|赣|豫|鄂|湘|桂|琼|黔|滇|藏|陕|甘|青|宁|新)ICP[备证]\d+号', html)
    unit = re.search(r'<div class="company"[^>]*>([^<]{4,40})</div>', html)
    print(f'{domain}: ICP={sorted(set(icp)) or "未抓到"} 主体={unit.group(1) if unit else "未抓到"}')
    print('提示: beianx 有频控, 失败就换浏览器手工查 (见 references/osint-sources.md 备案渠道矩阵)')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--work', default='.')
    ap.add_argument('--icp-census', action='store_true', dest='icp_census')
    ap.add_argument('--beianx', default='')
    args = ap.parse_args()
    if args.icp_census:
        icp_census(args.work)
    elif args.beianx:
        beianx(args.beianx)
    else:
        ap.print_help()


if __name__ == '__main__':
    main()

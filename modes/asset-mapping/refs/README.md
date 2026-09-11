# asset-mapping refs 知识库索引

资产测绘模式（asset-mapping）静态知识库。三篇均为实战提炼原文，不做改写；正文引用以相对路径为准。

| 文档 | 行数 | 内容 |
|---|---|---|
| [api-docs.md](api-docs.md) | 74 | 五平台（FOFA/Hunter/Quake/ZoomEye/Shodan）API 端点与参数、统一输出 schema、常用查询语法、错误码、key 申请入口表、十大实战坑清单 |
| [osint-sources.md](osint-sources.md) | 74 | 半自动情报源操作手册：爱企查控股穿透 SOP（BFS/持股口径/window.pageData 技巧）、ICP 备案渠道矩阵、DNS 历史解析考古（--connect-to 验证）、搜索引擎资产语法、小程序/APP/公众号/favicon 反查/C 段 |
| [quality-rules.md](quality-rules.md) | 46 | 准确性铁律：归属判定优先级链与 ICP 剥序号、假阳性四类（伪造备案/泛解析/tarpit/CDN）、指纹假阳性五条甄别、平台数据口径四条、Excel 交付规范、授权纪律 |

## 与技能/脚本的分工

- 管线执行（s0→s7 脚本用法与参数）在技能 `skills/asset-mapping-playbook/SKILL.md`。
- 本目录只放静态知识：查语法（api-docs）、查渠道（osint-sources）、查判定规则（quality-rules）。

## 维护约定

- 原文不改写；新增发现以追加小节方式扩展并在本 README 登记。
- 禁止本机绝对路径；引用保持相对路径。

---
name: php-vuln-scanner
description: PHP 组件版本漏洞检测工具。扫描 composer.json / composer.lock 或 jar/包元信息，匹配已知漏洞规则并输出报告（包含可能的触发点分析框架）。
---

# PHP 依赖漏洞扫描器（php-vuln-scanner）

扫描 PHP 项目的 Composer 依赖，识别已知安全漏洞（CVE/Advisory），并给出与路由/入口的关联推断框架。

## 输入
- `source_path`：源码根目录

支持目标：
- `composer.json`
- `composer.lock`
- 目录递归（在多个子模块下找 composer.lock）

## 规则与输出
- 规则匹配：使用内置/外部规则集（例如 `references/php-vulnerability.yaml`，如存在则优先）
- 输出到：
```
{output_path}/vuln_report/
  {project_name}_composer_vuln_report_{timestamp}.md
```

## 扫描流程（必做）

> **交叉验证建议**：若项目环境中可执行 `composer audit`，建议将其输出与本 skill 的规则匹配结果交叉比对，以提升 CVE 覆盖率。`composer audit` 使用 Packagist 实时 advisory 数据库，可补充本 skill 内置规则集可能存在的时效性盲区。两者取并集作为最终漏洞清单。

1. 依赖枚举
   - 解析 composer.lock 获取 package 名称与版本
   - 处理多模块时按模块分组输出
2. 漏洞匹配
   - 针对已知 CVE 规则匹配影响版本区间
3. 触发点分析（框架）
   - 识别已知高危组件可能进入的功能域：路由入口、序列化/模板、上传/下载、鉴权链
   - 建议使用 `php-route-mapper` 输出路由后做“受影响路由推断”
4. 组件->路由关联推断（必做，缺失则无法驱动流水线）
   - 输入依赖：读取 `routes_{timestamp}.md` 与 `params_{timestamp}.md`（与 `shared/IO_PATH_CONVENTION.md` 一致；独立落盘时常为 `route_mapping/` 下同名文件；流水线合并时读总报告等价章节）
   - 证据优先级：
     1) 代码中直接引用该组件的类/函数（例如 `use Vendor\\Pkg\\{value}`、`new {value}`、`Vendor\\{value}::`）
     2) 通过模板/序列化/上传/网络相关的“已知接入点”识别该组件所在功能域（再反查路由）
     3) 仅基于命名推断属于兜底：必须标注为 `⚠️待验证`
   - 对每个漏洞组件输出：
     - 组件的代码引用位置（文件路径 + 函数/类名，若无行号则写“待定位”但仍给出文件路径）
     - 组件可能触发的 sink 功能域（SQL/TPL/DESER/FILE/UPLOAD/SSRF/XSS/AUTH 等）
     - 推断受影响路由/入口（必须逐条列出路由条目，禁止省略；每条必须同时给出 `route_id` 与路由字符串，确保可直接回填给 `php-route-tracer`）

## 输出报告结构（强制）
```markdown
# {project_name} - Composer 组件漏洞扫描报告
生成时间: {timestamp}
分析路径: {source_path}

## 风险统计
（按 Critical/High/Medium/Low 分类，不得省略）

## 漏洞详情（逐条列出）
=== [CVE-xxxx-xxxx] {组件} {版本} ===
- 影响版本:
- 当前版本:
- 严重等级:
- 可能触发点（推断框架）:
- 代码引用位置（证据）:
  - 文件: path/to/xxx.php
  - 证据: 函数/类/调用片段（必须给出最小可定位片段）
- 受影响路由/入口（结合 route-mapper，给出“推断理由”）:
- 路由清单（逐条列出，禁止省略）:（必须同时给出 `route_id` 与路由字符串）
- 推断理由（必须明确是 1/2/3 优先级哪种证据方式）
- 修复建议:
```

## 关键组件触发点矩阵（强制：用于驱动流水线阶段 3）
| 组件 | 规则/影响等级 | 对应 sink 功能域 | 受影响路由/入口数量 | 受影响路由/入口（逐条列出） | 证据等级（直接引用/功能域/待验证） |


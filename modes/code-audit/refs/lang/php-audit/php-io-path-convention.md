# 输入/输出路径约定（全 skill 统一）

本文件消除「只写文件名」与「带目录前缀」两种写法之间的歧义。**所有 `php-*` skill 与 `php-audit-pipeline` 均适用。**

## 两种执行形态

| 形态 | 含义 |
|------|------|
| **流水线合并** | 由 `php-audit-pipeline` 编排时，各产物多为**汇总 MD 内的逻辑章节标题/分段**，不一定在磁盘上建独立文件。 |
| **单 skill 独立跑** | 仅调用某一 skill 时，可按各 skill 的「输出目录结构」**真实创建**子目录与文件。 |

同一 **逻辑名**（如下表「规范名」）在两种形态下**内容等价**，仅载体不同。

## 规范名与别名（等价）

| 规范名（逻辑） | 常见物理路径（独立跑 mapper 时） | 说明 |
|----------------|-----------------------------------|------|
| `routes_{timestamp}.md` | `route_mapping/routes_{timestamp}.md` | 路由清单；`route_mapping/` 为 `php-route-mapper` 建议目录 |
| `params_{timestamp}.md` | `route_mapping/params_{timestamp}.md` | 与路由逐条对应的参数结构 |
| `auth_mapping_{timestamp}.md` | `auth_audit/auth_mapping_{timestamp}.md` | 鉴权静态映射（阶段 1） |
| `auth_audit_report_{timestamp}.md` | `auth_audit/auth_audit_report_{timestamp}.md` | 鉴权深度审计（阶段 4 / TRACE_AUDIT） |
| `high_risk_routes_{timestamp}.md` | `cross_analysis/high_risk_routes_{timestamp}.md` | 高危路由/合成入口列表（阶段 3） |
| `trace_batch_plan_{timestamp}.md` | `cross_analysis/trace_batch_plan_{timestamp}.md` | 分批追踪计划 |
| `vuln_report/...` | `{output_path}/vuln_report/...` | 组件漏洞（如 composer 报告） |
| `vuln_audit/{type}_{timestamp}.md` | `{output_path}/vuln_audit/...` | 各 sink 子审计产出 |
| `global_sink_fallback/...` | `{output_path}/global_sink_fallback/...` | 阶段 2.5 静态兜底 |
| `route_tracer/{route_id}/...` | `{output_path}/route_tracer/...` | 按 `route_id` 分桶的 trace |

**读取规则**：子 skill 写「`route_mapping/routes_*.md`」时，在流水线合并模式下应理解为 **「总报告中与 `routes_{timestamp}.md` 对应的路由章节」**；若磁盘上仅有规范路径之一，以实际存在者为准。

## 编写 PoC 时的占位符

与 pipeline「关键约束」一致：真实路由与参数须替换进 PoC；`{host}`、`{cookie}`、`{token}` 等可作为会话相关占位符。

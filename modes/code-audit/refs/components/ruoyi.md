# 若依（RuoYi）专项审计手册

> 定位：国内高频开源后台管理框架（Spring Boot + MyBatis + Shiro/Spring Security）。
> 版本分代先锁：**RuoYi 单体版（Thymeleaf 服务端渲染）/ RuoYi-Vue（前后端分离）/
  RuoYi-Cloud（微服务）**——三代攻击面差异大，`pom.xml` 锁版本再动手。

## 已知漏洞面清单（逐项核对）

1. **定时任务 RCE（经典面）**：系统监控→定时任务（SysJob）的「调用目标字符串」可指定
   任意 Bean 方法/SpEL 形态 → 后台低权限即可 RCE。核对点：①调用目标校验白名单
   （`targetVerify`/黑白名单配置）是否启用、强度如何；②定时任务功能是否暴露给低权角色；
   ③新版内置白名单可绕过形态（反射链/完整类名）核对。
2. **Shiro rememberMe 反序列化**：旧版默认密钥（`kPH+bIxk5D2deZiIxcaaaA==` 等公开默认
   值）→ 伪造 rememberMe cookie 触发反序列化 RCE。核对点：密钥是否改过；shiro 版本；
   对照本目录 `shiro.md` 专项全流程。
3. **Druid 监控未授权**：`/druid/*` statViewServlet 未配密码或密码默认 → SQL 监控/URI
   监控/数据源信息泄露（session 泄露面）。核对点：`application.yml` 的 statViewServlet
   loginUsername/allow 配置。
4. **SQL 注入面**：列表排序字段（`orderByColumn`/`isAsc` 直拼 `ORDER BY`）、数据权限
   注解 `${params.dataScope}` 注入、字典/配置查询的历史拼接点。
5. **Thymeleaf SSTI（单体版）**：Controller 返回视图名拼接用户输入（`return prefix +
   "/edit"` 形态中可控段）→ 模板注入 RCE。前后端分离版无此面（如实标注不适用）。
6. **文件上传/下载**：通用下载接口路径穿越（`/common/download/resource` 类的历史穿越
   面）；头像/富文本上传校验。
7. **默认凭据与越权**：默认 admin 口令未改；接口级 `@PreAuthorize` 注解遗漏（二次开发
   新增接口常见）。

## Sink 快速核对（二次开发增量）

- mapper XML 全量 grep `${}`（对照 `#{}`）；QueryWrapper `last()/apply(` 拼接；
- 新增 Controller 的权限注解覆盖率（路由清单×注解清单对账——遗漏即越权候选）；
- 新增定时任务目标串（对照第 1 条）。

## 审计流程建议

锁版本与分代 → 上表七面逐项核 → Shiro/Fastjson 类依赖对照对应专项 → 二次开发走
模块×sink 矩阵 → 覆盖矩阵登记。利用条件纪律同 `jeecg-boot.md`（版本区间/配置开关全列）。

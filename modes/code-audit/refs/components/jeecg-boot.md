# JeecgBoot 专项审计手册

> 定位：国内高频低代码企业应用平台（Java + Spring Boot + MyBatis-Plus + Vue）。
> 审计口径：先核已知漏洞面（版本比对+利用条件），再增量审二次开发代码。
> 版本分代：1.x / 2.x / 3.x——行为差异大，先锁 `pom.xml` 与 `package.json` 版本。

## 已知漏洞面清单（逐项核对）

1. **JWT 密钥硬编码**：`application.yml` 的 `jeecg.signatureSecret`/jwt secret 为默认值或
   弱值 → 伪造任意用户（含 admin）token。核对点：密钥是否改过、强度如何；拿到密钥=
   认证全穿（后续一切接口面直达）。
2. **JimuReport（积木报表）面**：
   - `queryFieldBySql` 类接口收任意 SQL → SQL 注入（拖库/读文件面）；
   - 报表模板/表达式处的 Freemarker 模板注入 → RCE（`<#assign>`/`freemarker.template.utility.Execute`
     形态；模板沙箱配置核对）；
   - 未授权访问面（鉴权配置遗漏的历史版本）。
3. **Online 表单/代码生成器**：在线报表设计、代码生成的接口暴露度——未授权时=低代码
   平台最高危面（直接建查询/改模板/写文件）。
4. **文件上传面**：头像/富文本/附件接口的后缀与内容校验（历史版本存在绕过面）；
   落地路径与解析执行（同 RCE 主线「文件上传」类判定）。
5. **监控与调试残留**：Spring Boot actuator 端点（env/heapdump）、swagger/druid 暴露、
   test 演示模块未摘除。
6. **依赖反序列化**：历史版本捆绑的 fastjson/shiro/log4j 版本核对（对照本目录对应专项）。

## Sink 快速核对（二次开发增量）

- MyBatis-Plus：mapper 中 `${}`（对比 `#{}`）；QueryWrapper 的 `last(`/`apply(` 拼接；
- 控制器：`@RequestBody` 进 SQL 拼接/文件路径/模板串；
- 权限注解遗漏：新加接口无 `@RequiresPermissions` 类注解=越权面（对照路由清单）。

## 审计流程建议

Triage 锁版本 → 上表六面逐项核（有命中先走双链确证）→ 未命中面登记「已核无」→
二次开发增量走模块×sink 矩阵（java-sink-reference）→ 覆盖矩阵登记。

## 利用条件纪律

每条已知面的利用都列前提（版本区间/配置开关/鉴权状态/依赖在场）——版本不匹配或条件
不满足时如实标「不适用」，不硬套公开 POC。

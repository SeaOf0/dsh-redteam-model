# 腾讯云 安全攻防 refs

面向授权安全测试的腾讯云服务攻防方法论文档集，覆盖计算、存储、数据库、身份、网络与元数据攻击面。全部为原创中文方法论文档，供红队/安全研究员在授权范围内开展云安全评估时查阅。

## 索引

- [cvm.md](cvm.md) — CVM 云服务器攻防（实例/镜像/密钥对/安全组/用户数据/元数据）
- [cos.md](cos.md) — COS 对象存储攻防（bucket/object/ACL/公有读/桶接管/静态网站）
- [database.md](database.md) — TencentDB 云数据库攻防（MySQL/PostgreSQL/SQL Server/TDSQL/公网访问）
- [cam.md](cam.md) — CAM 访问管理攻防（用户/角色/策略/SecretId/SecretKey/STS）
- [network.md](network.md) — VPC/子网/安全组/CLB/NAT 网络攻防
- [metadata-ssrf.md](metadata-ssrf.md) — 从 SSRF 到元数据 CAM 临时凭证攻防

## 使用约定

- 所有验证命令以只读探测优先，破坏性操作需「授权内人工确认后执行」。
- 文档内互相引用使用相对路径（如 `./cam.md`）。
- 检测侧对照统一采用「攻击者视角 vs 防守者审计日志视角」。
- 审计事件名以腾讯云 CloudAudit 操作审计为准。

共 6 篇。

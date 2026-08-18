# Microsoft Azure 云安全攻防参考

本目录为 Azure 厂商级云安全攻防方法论文档，覆盖计算、存储、数据库、身份、网络与托管标识六大攻击面。全部为原创中文方法论，供红队/安全研究员在授权范围内开展云安全评估时查阅。

## 文档索引

- [vm.md](vm.md) — Azure VM 计算实例攻防（扩展/托管磁盘/自定义脚本扩展 Run Command/密钥）
- [blob.md](blob.md) — Blob Storage 对象存储攻防（容器/公有访问级别/SAS/连接字符串/存储账户密钥）
- [sql-database.md](sql-database.md) — Azure SQL Database / Cosmos DB 云数据库攻防（防火墙/管理员/公开端点）
- [entra-id.md](entra-id.md) — Entra ID（原 Azure AD）身份与权限攻防（租户/用户/应用/服务主体/角色 RBAC）
- [network.md](network.md) — VNet/网络安全组(NSG)/负载均衡/应用网关网络攻防
- [managed-identity-ssrf.md](managed-identity-ssrf.md) — 从 SSRF 到托管标识(Managed Identity)元数据 token 攻防

共 6 篇。

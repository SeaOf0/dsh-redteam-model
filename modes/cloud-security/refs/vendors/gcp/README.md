# Google Cloud（GCP）云安全攻防知识库

本目录收录 GCP 各核心服务的云安全攻防方法论文档，全部为授权安全测试方法论，供红队/安全研究员在授权范围内开展云安全评估时查阅。文档统一采用「攻击面 → 信息收集 → 配置缺陷与利用路径 → 权限提升与持久化 → 防御与检测」五段结构，每条利用路径均附「攻击者视角 vs 防守者审计日志视角」对照。

## 目录索引

- [compute-engine.md](compute-engine.md) — Compute Engine 计算实例攻防（实例/启动脚本/服务账号/访问范围 scope）
- [cloud-storage.md](cloud-storage.md) — Cloud Storage 对象存储攻防（bucket 公开访问/统一权限/对象 ACL/桶接管）
- [cloud-sql.md](cloud-sql.md) — Cloud SQL 云数据库攻防（MySQL/PostgreSQL/SQL Server/公开 IP/实例）
- [iam.md](iam.md) — Cloud IAM 与权限攻防（成员/角色/服务账号/服务账号密钥/Workload Identity）
- [network.md](network.md) — VPC/子网/防火墙规则/Cloud Load Balancing 网络攻防
- [metadata-ssrf.md](metadata-ssrf.md) — 从 SSRF 到元数据服务账号 token 攻防

## 篇数统计

共 6 篇。

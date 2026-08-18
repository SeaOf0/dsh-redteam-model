# AWS 云安全攻防 refs 索引

本目录为 AWS 厂商级云安全攻防方法论文档，供红队/安全研究员在授权范围内开展云安全评估时查阅。全部为原创中文方法论文档。

## 索引

- [ec2.md](ec2.md) — EC2 计算实例攻防（用户数据/AMI/密钥对/SSM/元数据）
- [s3.md](s3.md) — S3 对象存储攻防（桶爆破/ACL/策略/公开访问/桶接管）
- [rds.md](rds.md) — RDS 云数据库攻防（MySQL/PostgreSQL/SQL Server/公开访问/快照）
- [iam.md](iam.md) — IAM 与权限攻防（用户/角色/策略/AccessKey/sts AssumeRole/跨账户信任）
- [network.md](network.md) — VPC/安全组/NACL/ELB/Route53 网络攻防
- [ssrf-metadata.md](ssrf-metadata.md) — 从 SSRF 到元数据凭证（IMDSv1/v2）攻防

共 6 篇。

## 使用说明

- 各文档统一结构：攻击面 → 信息收集/暴露面探测 → 常见配置缺陷与利用路径 → 权限提升与持久化路径 → 防御与检测要点。
- 每条利用路径均给出攻击者视角与防守者审计日志视角的对照，命令以只读探测与最小影响验证为准。
- 破坏性步骤（删桶/删实例/改策略/改密码/公开快照等）一律标注「授权内人工确认后执行」。
- 本文档仅用于授权安全测试。

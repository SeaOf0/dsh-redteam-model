---
name: php-crypto-audit
description: PHP Web 源码加密与密钥安全审计工具。识别弱哈希/弱加密/硬编码密钥/签名校验缺陷，输出分级、PoC 与修复建议（禁止省略）。
---

# PHP 加密与密钥安全审计（php-crypto-audit）

分析 PHP 项目源码中密码/令牌/敏感数据的加密与哈希实现，检测：
- 弱哈希（MD5/SHA1/无 salt）
- 不安全的对称/非对称加密使用（ECB、固定 IV、错误模式）
- 签名校验缺陷（JWT 未验证、HMAC 用错、算法选择可控）
- 硬编码密钥/明文 key 泄露

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-CRYPTO-{序号}`

## 必检 Sink（强制）
必须搜索并分析以下实现点（按项目实际替换）：
- 密码哈希：`md5/sha1/hash`（非 password_hash）、`crypt` 参数误用
- 安全哈希：`password_hash`/`password_verify`（检查是否参数正确）
- 对称加密：`openssl_encrypt/decrypt`（检查 mode/iv）
- 签名：`hash_hmac`、`openssl_sign`、JWT verify/签名比较实现

## 必检要求（强制）
- 必须定位“密钥来源”：硬编码/环境变量/配置文件/请求参数
- 必须判断“校验是否可靠”：是否存在算法可控或比较时序泄露
- 必须输出修复建议与迁移方案（例如升级哈希算法、强制使用参数化模式）

## PoC（强制框架）
由于加密类漏洞可能依赖环境，PoC 至少要给出：
- 可执行的“验证框架”（例如构造 JWT payload 并解释应当发生的验证失败/绕过）
- 或给出可观测的证据（例如日志泄露、错误模式产生可逆结果）

## 报告输出
```
{output_path}/vuln_audit/crypto_{timestamp}.md
```


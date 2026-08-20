#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
容器安全工具包 - Docker/Kubernetes 安全评估

支持的功能:
- Docker容器逃逸检测
- Kubernetes集群枚举
- 容器镜像漏洞扫描
- 特权容器检测
- Secret提取
- RBAC权限分析
- 服务账户令牌提取

用于CTF竞赛和授权的安全评估
"""

import os
import subprocess
import json
import re
import base64
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from enum import Enum

from .base import (
    BaseTool, tool, ToolCategory, RiskLevel,
    ToolResult, ResultStatus
)


class ContainerRuntime(Enum):
    """容器运行时"""
    DOCKER = "docker"
    CONTAINERD = "containerd"
    PODMAN = "podman"
    CRI_O = "cri-o"


@dataclass
class ContainerInfo:
    """容器信息"""
    id: str
    name: str
    image: str
    status: str
    privileged: bool = False
    capabilities: List[str] = None
    mounts: List[Dict] = None


# ==================== Docker 安全工具 ====================

@tool(
    name="docker_enum",
    category=ToolCategory.CONTAINER,
    description="Docker枚举 - 枚举Docker容器、镜像和网络",
    risk_level=RiskLevel.LOW,
    timeout=120
)
class DockerEnum(BaseTool):
    """Docker枚举工具"""

    async def execute(self,
                     socket_path: str = "/var/run/docker.sock",
                     remote_host: str = "") -> ToolResult:
        """
        枚举Docker环境

        Args:
            socket_path: Docker socket路径
            remote_host: 远程Docker主机 (如 tcp://192.168.1.100:2375)
        """
        results = {
            "containers": [],
            "images": [],
            "networks": [],
            "volumes": [],
            "privileged_containers": [],
            "exposed_ports": [],
            "dangerous_mounts": []
        }

        docker_cmd = "docker"
        if remote_host:
            docker_cmd = f"docker -H {remote_host}"
        elif socket_path != "/var/run/docker.sock":
            docker_cmd = f"docker -H unix://{socket_path}"

        try:
            # 枚举容器
            containers_cmd = f"{docker_cmd} ps -a --format '{{{{json .}}}}'"
            containers_result = subprocess.run(
                containers_cmd, shell=True, capture_output=True, text=True, timeout=30
            )

            for line in containers_result.stdout.strip().split('\n'):
                if line:
                    try:
                        container = json.loads(line)
                        results["containers"].append(container)

                        # 检查容器详细信息
                        inspect_cmd = f"{docker_cmd} inspect {container.get('ID', container.get('Names', ''))}"
                        inspect_result = subprocess.run(
                            inspect_cmd, shell=True, capture_output=True, text=True, timeout=30
                        )

                        if inspect_result.returncode == 0:
                            inspect_data = json.loads(inspect_result.stdout)[0]

                            # 检查特权容器
                            if inspect_data.get("HostConfig", {}).get("Privileged"):
                                results["privileged_containers"].append(container)

                            # 检查危险挂载
                            mounts = inspect_data.get("Mounts", [])
                            for mount in mounts:
                                if mount.get("Source") in ["/", "/etc", "/var/run/docker.sock", "/proc", "/sys"]:
                                    results["dangerous_mounts"].append({
                                        "container": container.get("Names"),
                                        "mount": mount
                                    })

                            # 检查暴露的端口
                            ports = inspect_data.get("NetworkSettings", {}).get("Ports", {})
                            for port, bindings in ports.items():
                                if bindings:
                                    for binding in bindings:
                                        if binding.get("HostIp") in ["0.0.0.0", ""]:
                                            results["exposed_ports"].append({
                                                "container": container.get("Names"),
                                                "port": port,
                                                "host_port": binding.get("HostPort")
                                            })

                    except json.JSONDecodeError:
                        pass

            # 枚举镜像
            images_cmd = f"{docker_cmd} images --format '{{{{json .}}}}'"
            images_result = subprocess.run(
                images_cmd, shell=True, capture_output=True, text=True, timeout=30
            )

            for line in images_result.stdout.strip().split('\n'):
                if line:
                    try:
                        results["images"].append(json.loads(line))
                    except:
                        pass

            # 枚举网络
            networks_cmd = f"{docker_cmd} network ls --format '{{{{json .}}}}'"
            networks_result = subprocess.run(
                networks_cmd, shell=True, capture_output=True, text=True, timeout=30
            )

            for line in networks_result.stdout.strip().split('\n'):
                if line:
                    try:
                        results["networks"].append(json.loads(line))
                    except:
                        pass

            return ToolResult(
                status=ResultStatus.SUCCESS,
                data=results,
                summary=f"发现 {len(results['containers'])} 容器, {len(results['privileged_containers'])} 特权容器"
            )

        except Exception as e:
            return ToolResult(
                status=ResultStatus.ERROR,
                error=str(e),
                summary="Docker枚举失败"
            )


@tool(
    name="docker_escape_check",
    category=ToolCategory.CONTAINER,
    description="Docker逃逸检测 - 检测容器逃逸可能性",
    risk_level=RiskLevel.MEDIUM,
    timeout=120
)
class DockerEscapeCheck(BaseTool):
    """Docker逃逸检测"""

    async def execute(self) -> ToolResult:
        """
        检测Docker逃逸可能性

        在容器内部运行，检测各种逃逸向量
        """
        results = {
            "is_container": False,
            "escape_vectors": [],
            "capabilities": [],
            "mounts": [],
            "recommendations": []
        }

        # 检查是否在容器内
        if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
            results["is_container"] = True
        else:
            # 检查cgroup
            try:
                with open("/proc/1/cgroup", "r") as f:
                    cgroup = f.read()
                    if "docker" in cgroup or "kubepods" in cgroup or "containerd" in cgroup:
                        results["is_container"] = True
            except:
                pass

        if not results["is_container"]:
            return ToolResult(
                status=ResultStatus.NO_RESULTS,
                data=results,
                summary="不在容器环境中"
            )

        # 检查逃逸向量

        # 1. 检查Docker socket
        if os.path.exists("/var/run/docker.sock"):
            results["escape_vectors"].append({
                "type": "docker_socket",
                "severity": "CRITICAL",
                "description": "Docker socket已挂载，可以创建特权容器逃逸",
                "exploit": "docker run -v /:/host -it alpine chroot /host"
            })

        # 2. 检查特权模式
        try:
            with open("/proc/self/status", "r") as f:
                status = f.read()
                if "CapEff:\t0000003fffffffff" in status or "CapEff:\tffffffffffffffff" in status:
                    results["escape_vectors"].append({
                        "type": "privileged_container",
                        "severity": "CRITICAL",
                        "description": "容器以特权模式运行",
                        "exploit": "mount /dev/sda1 /mnt && chroot /mnt"
                    })
        except:
            pass

        # 3. 检查危险capabilities
        try:
            result = subprocess.run("capsh --print", shell=True, capture_output=True, text=True, timeout=10)
            caps = result.stdout

            dangerous_caps = {
                "cap_sys_admin": "可以挂载文件系统，容器逃逸",
                "cap_sys_ptrace": "可以ptrace其他进程",
                "cap_net_admin": "可以修改网络配置",
                "cap_sys_module": "可以加载内核模块",
                "cap_dac_override": "可以绕过文件权限检查",
                "cap_dac_read_search": "可以读取任意文件",
            }

            for cap, desc in dangerous_caps.items():
                if cap in caps.lower():
                    results["capabilities"].append(cap)
                    results["escape_vectors"].append({
                        "type": f"capability_{cap}",
                        "severity": "HIGH",
                        "description": desc
                    })
        except:
            pass

        # 4. 检查cgroup逃逸 (CVE-2022-0492)
        try:
            result = subprocess.run(
                "cat /sys/fs/cgroup/*/release_agent 2>/dev/null || cat /sys/fs/cgroup/release_agent 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                results["escape_vectors"].append({
                    "type": "cgroup_escape",
                    "severity": "HIGH",
                    "description": "可能存在cgroup逃逸漏洞 (CVE-2022-0492)",
                })
        except:
            pass

        # 5. 检查/proc挂载
        try:
            with open("/proc/mounts", "r") as f:
                mounts = f.read()
                results["mounts"] = mounts.split('\n')

                if "host" in mounts or " / " in mounts:
                    results["escape_vectors"].append({
                        "type": "host_mount",
                        "severity": "CRITICAL",
                        "description": "主机根目录已挂载"
                    })

                if "/etc" in mounts:
                    results["escape_vectors"].append({
                        "type": "etc_mount",
                        "severity": "HIGH",
                        "description": "主机/etc目录已挂载"
                    })
        except:
            pass

        # 6. 检查设备访问
        if os.path.exists("/dev/sda") or os.path.exists("/dev/nvme0n1"):
            results["escape_vectors"].append({
                "type": "device_access",
                "severity": "CRITICAL",
                "description": "可以访问主机磁盘设备"
            })

        # 7. 检查内核模块
        try:
            result = subprocess.run("lsmod 2>/dev/null", shell=True, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout:
                results["escape_vectors"].append({
                    "type": "kernel_modules",
                    "severity": "HIGH",
                    "description": "可以查看/加载内核模块"
                })
        except:
            pass

        return ToolResult(
            status=ResultStatus.SUCCESS,
            data=results,
            summary=f"发现 {len(results['escape_vectors'])} 个潜在逃逸向量"
        )


@tool(
    name="docker_image_scan",
    category=ToolCategory.CONTAINER,
    description="Docker镜像漏洞扫描 - 使用Trivy扫描容器镜像",
    risk_level=RiskLevel.LOW,
    timeout=600
)
class DockerImageScan(BaseTool):
    """Docker镜像漏洞扫描"""

    async def execute(self,
                     image: str,
                     severity: str = "CRITICAL,HIGH",
                     output_format: str = "json") -> ToolResult:
        """
        扫描Docker镜像漏洞

        Args:
            image: 镜像名称或ID
            severity: 漏洞严重级别过滤
            output_format: 输出格式 (json, table)
        """
        # 优先使用Trivy
        trivy_result = await self._scan_with_trivy(image, severity, output_format)
        if trivy_result.status == ResultStatus.SUCCESS:
            return trivy_result

        # 备选使用Grype
        grype_result = await self._scan_with_grype(image, severity)
        if grype_result.status == ResultStatus.SUCCESS:
            return grype_result

        # 都不可用时，使用Docker自带的scout
        return await self._scan_with_scout(image)

    async def _scan_with_trivy(self, image: str, severity: str, output_format: str) -> ToolResult:
        """使用Trivy扫描"""
        cmd = f"trivy image --severity {severity} --format {output_format} {image}"

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)

            if result.returncode == 0:
                data = json.loads(result.stdout) if output_format == "json" else result.stdout

                vuln_count = 0
                if isinstance(data, dict) and "Results" in data:
                    for r in data["Results"]:
                        vuln_count += len(r.get("Vulnerabilities", []))

                return ToolResult(
                    status=ResultStatus.SUCCESS,
                    data=data,
                    summary=f"Trivy扫描完成，发现 {vuln_count} 个漏洞"
                )
        except FileNotFoundError:
            pass
        except Exception as e:
            pass

        return ToolResult(status=ResultStatus.ERROR, error="Trivy扫描失败")

    async def _scan_with_grype(self, image: str, severity: str) -> ToolResult:
        """使用Grype扫描"""
        cmd = f"grype {image} --output json"

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)

            if result.returncode == 0:
                data = json.loads(result.stdout)
                matches = data.get("matches", [])

                return ToolResult(
                    status=ResultStatus.SUCCESS,
                    data=data,
                    summary=f"Grype扫描完成，发现 {len(matches)} 个漏洞"
                )
        except:
            pass

        return ToolResult(status=ResultStatus.ERROR, error="Grype扫描失败")

    async def _scan_with_scout(self, image: str) -> ToolResult:
        """使用Docker Scout扫描"""
        cmd = f"docker scout cves {image} --format json"

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)

            if result.returncode == 0:
                data = json.loads(result.stdout) if result.stdout else {}
                return ToolResult(
                    status=ResultStatus.SUCCESS,
                    data=data,
                    summary="Docker Scout扫描完成"
                )
        except:
            pass

        return ToolResult(
            status=ResultStatus.ERROR,
            error="没有可用的镜像扫描工具。安装: apt install trivy",
            summary="镜像扫描工具不可用"
        )


# ==================== Kubernetes 安全工具 ====================

@tool(
    name="k8s_enum",
    category=ToolCategory.CONTAINER,
    description="Kubernetes枚举 - 枚举K8s集群资源和配置",
    risk_level=RiskLevel.LOW,
    timeout=180
)
class K8sEnum(BaseTool):
    """Kubernetes集群枚举"""

    async def execute(self,
                     kubeconfig: str = "",
                     namespace: str = "",
                     all_namespaces: bool = True) -> ToolResult:
        """
        枚举Kubernetes集群

        Args:
            kubeconfig: kubeconfig文件路径
            namespace: 指定命名空间
            all_namespaces: 枚举所有命名空间
        """
        results = {
            "cluster_info": {},
            "namespaces": [],
            "pods": [],
            "services": [],
            "secrets": [],
            "configmaps": [],
            "serviceaccounts": [],
            "roles": [],
            "dangerous_configs": []
        }

        kubectl = "kubectl"
        if kubeconfig:
            kubectl = f"kubectl --kubeconfig={kubeconfig}"

        ns_flag = "-A" if all_namespaces else (f"-n {namespace}" if namespace else "")

        try:
            # 获取集群信息
            cluster_cmd = f"{kubectl} cluster-info"
            cluster_result = subprocess.run(cluster_cmd, shell=True, capture_output=True, text=True, timeout=30)
            results["cluster_info"]["raw"] = cluster_result.stdout

            # 获取版本
            version_cmd = f"{kubectl} version --output=json"
            version_result = subprocess.run(version_cmd, shell=True, capture_output=True, text=True, timeout=30)
            if version_result.returncode == 0:
                results["cluster_info"]["version"] = json.loads(version_result.stdout)

            # 枚举命名空间
            ns_cmd = f"{kubectl} get namespaces -o json"
            ns_result = subprocess.run(ns_cmd, shell=True, capture_output=True, text=True, timeout=30)
            if ns_result.returncode == 0:
                ns_data = json.loads(ns_result.stdout)
                results["namespaces"] = [item["metadata"]["name"] for item in ns_data.get("items", [])]

            # 枚举Pods
            pods_cmd = f"{kubectl} get pods {ns_flag} -o json"
            pods_result = subprocess.run(pods_cmd, shell=True, capture_output=True, text=True, timeout=60)
            if pods_result.returncode == 0:
                pods_data = json.loads(pods_result.stdout)
                for pod in pods_data.get("items", []):
                    pod_info = {
                        "name": pod["metadata"]["name"],
                        "namespace": pod["metadata"]["namespace"],
                        "status": pod["status"]["phase"],
                        "containers": []
                    }

                    # 检查容器安全配置
                    for container in pod["spec"].get("containers", []):
                        container_info = {
                            "name": container["name"],
                            "image": container["image"]
                        }

                        security_context = container.get("securityContext", {})
                        if security_context.get("privileged"):
                            container_info["privileged"] = True
                            results["dangerous_configs"].append({
                                "type": "privileged_container",
                                "pod": pod_info["name"],
                                "container": container["name"],
                                "namespace": pod_info["namespace"]
                            })

                        if security_context.get("runAsRoot") or security_context.get("runAsUser") == 0:
                            results["dangerous_configs"].append({
                                "type": "root_container",
                                "pod": pod_info["name"],
                                "container": container["name"]
                            })

                        pod_info["containers"].append(container_info)

                    results["pods"].append(pod_info)

            # 枚举Services
            svc_cmd = f"{kubectl} get services {ns_flag} -o json"
            svc_result = subprocess.run(svc_cmd, shell=True, capture_output=True, text=True, timeout=30)
            if svc_result.returncode == 0:
                svc_data = json.loads(svc_result.stdout)
                results["services"] = [
                    {
                        "name": svc["metadata"]["name"],
                        "namespace": svc["metadata"]["namespace"],
                        "type": svc["spec"]["type"],
                        "ports": svc["spec"].get("ports", [])
                    }
                    for svc in svc_data.get("items", [])
                ]

            # 枚举Secrets（只获取名称）
            secrets_cmd = f"{kubectl} get secrets {ns_flag} -o json"
            secrets_result = subprocess.run(secrets_cmd, shell=True, capture_output=True, text=True, timeout=30)
            if secrets_result.returncode == 0:
                secrets_data = json.loads(secrets_result.stdout)
                results["secrets"] = [
                    {
                        "name": secret["metadata"]["name"],
                        "namespace": secret["metadata"]["namespace"],
                        "type": secret["type"]
                    }
                    for secret in secrets_data.get("items", [])
                ]

            # 枚举ServiceAccounts
            sa_cmd = f"{kubectl} get serviceaccounts {ns_flag} -o json"
            sa_result = subprocess.run(sa_cmd, shell=True, capture_output=True, text=True, timeout=30)
            if sa_result.returncode == 0:
                sa_data = json.loads(sa_result.stdout)
                results["serviceaccounts"] = [
                    {
                        "name": sa["metadata"]["name"],
                        "namespace": sa["metadata"]["namespace"]
                    }
                    for sa in sa_data.get("items", [])
                ]

            return ToolResult(
                status=ResultStatus.SUCCESS,
                data=results,
                summary=f"发现 {len(results['pods'])} Pods, {len(results['secrets'])} Secrets"
            )

        except Exception as e:
            return ToolResult(
                status=ResultStatus.ERROR,
                error=str(e),
                summary="Kubernetes枚举失败"
            )


@tool(
    name="k8s_secret_extract",
    category=ToolCategory.CONTAINER,
    description="Kubernetes Secret提取 - 提取和解码K8s Secrets",
    risk_level=RiskLevel.HIGH,
    timeout=120
)
class K8sSecretExtract(BaseTool):
    """Kubernetes Secret提取"""

    async def execute(self,
                     secret_name: str = "",
                     namespace: str = "default",
                     all_secrets: bool = False,
                     kubeconfig: str = "") -> ToolResult:
        """
        提取Kubernetes Secrets

        Args:
            secret_name: Secret名称
            namespace: 命名空间
            all_secrets: 提取所有secrets
            kubeconfig: kubeconfig文件路径
        """
        results = {
            "secrets": [],
            "decoded_data": {}
        }

        kubectl = f"kubectl --kubeconfig={kubeconfig}" if kubeconfig else "kubectl"

        try:
            if all_secrets:
                cmd = f"{kubectl} get secrets -n {namespace} -o json"
            else:
                cmd = f"{kubectl} get secret {secret_name} -n {namespace} -o json"

            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                data = json.loads(result.stdout)

                secrets_list = data.get("items", [data]) if "items" in data else [data]

                for secret in secrets_list:
                    secret_info = {
                        "name": secret["metadata"]["name"],
                        "namespace": secret["metadata"]["namespace"],
                        "type": secret["type"],
                        "data": {}
                    }

                    # 解码base64数据
                    for key, value in secret.get("data", {}).items():
                        try:
                            decoded = base64.b64decode(value).decode('utf-8', errors='replace')
                            secret_info["data"][key] = decoded

                            # 检测敏感信息
                            if any(keyword in key.lower() for keyword in ["password", "token", "key", "secret", "credential"]):
                                if secret_info["name"] not in results["decoded_data"]:
                                    results["decoded_data"][secret_info["name"]] = {}
                                results["decoded_data"][secret_info["name"]][key] = decoded
                        except:
                            secret_info["data"][key] = "[无法解码]"

                    results["secrets"].append(secret_info)

            return ToolResult(
                status=ResultStatus.SUCCESS,
                data=results,
                summary=f"提取 {len(results['secrets'])} 个Secrets"
            )

        except Exception as e:
            return ToolResult(
                status=ResultStatus.ERROR,
                error=str(e),
                summary="Secret提取失败"
            )


@tool(
    name="k8s_rbac_enum",
    category=ToolCategory.CONTAINER,
    description="Kubernetes RBAC分析 - 分析RBAC权限配置",
    risk_level=RiskLevel.LOW,
    timeout=180
)
class K8sRBACEnum(BaseTool):
    """Kubernetes RBAC分析"""

    async def execute(self,
                     namespace: str = "",
                     kubeconfig: str = "") -> ToolResult:
        """
        分析Kubernetes RBAC配置

        Args:
            namespace: 命名空间（空则分析集群级别）
            kubeconfig: kubeconfig文件路径
        """
        results = {
            "roles": [],
            "cluster_roles": [],
            "role_bindings": [],
            "cluster_role_bindings": [],
            "dangerous_permissions": [],
            "privilege_escalation_paths": []
        }

        kubectl = f"kubectl --kubeconfig={kubeconfig}" if kubeconfig else "kubectl"

        dangerous_verbs = ["*", "create", "delete", "patch", "update"]
        dangerous_resources = [
            "secrets", "pods", "deployments", "daemonsets",
            "clusterroles", "clusterrolebindings", "roles", "rolebindings",
            "serviceaccounts", "pods/exec", "pods/attach"
        ]

        try:
            # 获取Roles
            if namespace:
                roles_cmd = f"{kubectl} get roles -n {namespace} -o json"
            else:
                roles_cmd = f"{kubectl} get roles -A -o json"

            roles_result = subprocess.run(roles_cmd, shell=True, capture_output=True, text=True, timeout=60)
            if roles_result.returncode == 0:
                roles_data = json.loads(roles_result.stdout)
                for role in roles_data.get("items", []):
                    role_info = {
                        "name": role["metadata"]["name"],
                        "namespace": role["metadata"].get("namespace", ""),
                        "rules": role.get("rules", [])
                    }
                    results["roles"].append(role_info)

                    # 检查危险权限
                    for rule in role.get("rules", []):
                        for resource in rule.get("resources", []):
                            for verb in rule.get("verbs", []):
                                if (resource in dangerous_resources or resource == "*") and \
                                   (verb in dangerous_verbs):
                                    results["dangerous_permissions"].append({
                                        "type": "role",
                                        "name": role_info["name"],
                                        "resource": resource,
                                        "verb": verb,
                                        "namespace": role_info["namespace"]
                                    })

            # 获取ClusterRoles
            cr_cmd = f"{kubectl} get clusterroles -o json"
            cr_result = subprocess.run(cr_cmd, shell=True, capture_output=True, text=True, timeout=60)
            if cr_result.returncode == 0:
                cr_data = json.loads(cr_result.stdout)
                for cr in cr_data.get("items", []):
                    if not cr["metadata"]["name"].startswith("system:"):
                        cr_info = {
                            "name": cr["metadata"]["name"],
                            "rules": cr.get("rules", [])
                        }
                        results["cluster_roles"].append(cr_info)

                        # 检查危险权限
                        for rule in cr.get("rules", []):
                            for resource in rule.get("resources", []):
                                for verb in rule.get("verbs", []):
                                    if (resource in dangerous_resources or resource == "*") and \
                                       (verb in dangerous_verbs):
                                        results["dangerous_permissions"].append({
                                            "type": "clusterrole",
                                            "name": cr_info["name"],
                                            "resource": resource,
                                            "verb": verb
                                        })

            # 获取RoleBindings
            rb_cmd = f"{kubectl} get rolebindings -A -o json"
            rb_result = subprocess.run(rb_cmd, shell=True, capture_output=True, text=True, timeout=60)
            if rb_result.returncode == 0:
                rb_data = json.loads(rb_result.stdout)
                results["role_bindings"] = [
                    {
                        "name": rb["metadata"]["name"],
                        "namespace": rb["metadata"].get("namespace", ""),
                        "role_ref": rb.get("roleRef", {}),
                        "subjects": rb.get("subjects", [])
                    }
                    for rb in rb_data.get("items", [])
                ]

            # 获取ClusterRoleBindings
            crb_cmd = f"{kubectl} get clusterrolebindings -o json"
            crb_result = subprocess.run(crb_cmd, shell=True, capture_output=True, text=True, timeout=60)
            if crb_result.returncode == 0:
                crb_data = json.loads(crb_result.stdout)
                for crb in crb_data.get("items", []):
                    if not crb["metadata"]["name"].startswith("system:"):
                        results["cluster_role_bindings"].append({
                            "name": crb["metadata"]["name"],
                            "role_ref": crb.get("roleRef", {}),
                            "subjects": crb.get("subjects", [])
                        })

            # 分析权限提升路径
            results["privilege_escalation_paths"] = self._find_privesc_paths(results)

            return ToolResult(
                status=ResultStatus.SUCCESS,
                data=results,
                summary=f"发现 {len(results['dangerous_permissions'])} 个危险权限配置"
            )

        except Exception as e:
            return ToolResult(
                status=ResultStatus.ERROR,
                error=str(e),
                summary="RBAC分析失败"
            )

    def _find_privesc_paths(self, results: Dict) -> List[Dict]:
        """分析权限提升路径"""
        paths = []

        for perm in results["dangerous_permissions"]:
            if perm["resource"] in ["secrets", "*"] and perm["verb"] in ["get", "list", "*"]:
                paths.append({
                    "path": f"通过{perm['name']}读取secrets获取凭证",
                    "severity": "HIGH",
                    "permission": perm
                })

            if perm["resource"] in ["pods", "*"] and perm["verb"] in ["create", "*"]:
                paths.append({
                    "path": f"通过{perm['name']}创建特权Pod",
                    "severity": "CRITICAL",
                    "permission": perm
                })

            if perm["resource"] in ["pods/exec", "*"] and perm["verb"] in ["create", "*"]:
                paths.append({
                    "path": f"通过{perm['name']}执行Pod命令",
                    "severity": "HIGH",
                    "permission": perm
                })

        return paths


@tool(
    name="k8s_pod_escape",
    category=ToolCategory.CONTAINER,
    description="Kubernetes Pod逃逸 - 检测和利用Pod逃逸向量",
    risk_level=RiskLevel.HIGH,
    timeout=180
)
class K8sPodEscape(BaseTool):
    """Kubernetes Pod逃逸检测"""

    async def execute(self) -> ToolResult:
        """
        检测Kubernetes Pod逃逸可能性
        """
        results = {
            "is_k8s_pod": False,
            "service_account": {},
            "escape_vectors": [],
            "api_server_access": False,
            "token_path": ""
        }

        # 检查是否在K8s Pod中
        token_paths = [
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/run/secrets/kubernetes.io/serviceaccount/token"
        ]

        for path in token_paths:
            if os.path.exists(path):
                results["is_k8s_pod"] = True
                results["token_path"] = path
                break

        if not results["is_k8s_pod"]:
            return ToolResult(
                status=ResultStatus.NO_RESULTS,
                data=results,
                summary="不在Kubernetes Pod环境中"
            )

        try:
            # 读取服务账户token
            with open(results["token_path"], 'r') as f:
                token = f.read().strip()
                results["service_account"]["token"] = token[:50] + "..."

            # 读取namespace
            ns_path = os.path.dirname(results["token_path"]) + "/namespace"
            if os.path.exists(ns_path):
                with open(ns_path, 'r') as f:
                    results["service_account"]["namespace"] = f.read().strip()

            # 检查API Server访问
            api_server = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
            api_port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")

            check_cmd = f"curl -sk https://{api_server}:{api_port}/api --header 'Authorization: Bearer {token}' --max-time 5"
            check_result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True, timeout=10)

            if check_result.returncode == 0 and "kind" in check_result.stdout:
                results["api_server_access"] = True

                # 检查权限
                perms_cmd = f"curl -sk https://{api_server}:{api_port}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews --header 'Authorization: Bearer {token}' -X POST -H 'Content-Type: application/json' --data '{{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectAccessReview\",\"spec\":{{\"resourceAttributes\":{{\"verb\":\"list\",\"resource\":\"secrets\"}}}}}}' --max-time 5"
                perms_result = subprocess.run(perms_cmd, shell=True, capture_output=True, text=True, timeout=10)

                if '"allowed":true' in perms_result.stdout:
                    results["escape_vectors"].append({
                        "type": "secret_access",
                        "severity": "HIGH",
                        "description": "服务账户可以列出secrets",
                        "exploit": f"kubectl --token={token[:20]}... get secrets -A"
                    })

        except Exception as e:
            results["error"] = str(e)

        # 运行Docker逃逸检测
        docker_escape = DockerEscapeCheck()
        docker_result = await docker_escape.execute()
        if docker_result.data and docker_result.data.get("escape_vectors"):
            results["escape_vectors"].extend(docker_result.data["escape_vectors"])

        return ToolResult(
            status=ResultStatus.SUCCESS,
            data=results,
            summary=f"发现 {len(results['escape_vectors'])} 个逃逸向量"
        )


@tool(
    name="peirates_attack",
    category=ToolCategory.CONTAINER,
    description="Peirates Kubernetes渗透 - Kubernetes渗透测试框架",
    risk_level=RiskLevel.HIGH,
    timeout=300
)
class PeiratesAttack(BaseTool):
    """Peirates Kubernetes渗透框架"""

    async def execute(self,
                     action: str = "enum",
                     kubeconfig: str = "",
                     token: str = "") -> ToolResult:
        """
        执行Peirates渗透测试

        Args:
            action: 动作 (enum, secrets, pods, exec)
            kubeconfig: kubeconfig路径
            token: ServiceAccount token
        """
        cmd = ["peirates"]

        if kubeconfig:
            cmd.extend(["-k", kubeconfig])
        if token:
            cmd.extend(["-t", token])

        # 根据action设置参数
        action_map = {
            "enum": "",
            "secrets": "-s",
            "pods": "-p",
        }

        if action in action_map and action_map[action]:
            cmd.append(action_map[action])

        try:
            result = subprocess.run(
                " ".join(cmd), shell=True, capture_output=True, text=True,
                timeout=300
            )

            return ToolResult(
                status=ResultStatus.SUCCESS if result.returncode == 0 else ResultStatus.ERROR,
                data={"output": result.stdout, "stderr": result.stderr},
                summary=f"Peirates {action} 完成"
            )

        except FileNotFoundError:
            return ToolResult(
                status=ResultStatus.ERROR,
                error="Peirates未安装",
                summary="Peirates未安装"
            )


# 导出所有工具
__all__ = [
    "DockerEnum",
    "DockerEscapeCheck",
    "DockerImageScan",
    "K8sEnum",
    "K8sSecretExtract",
    "K8sRBACEnum",
    "K8sPodEscape",
    "PeiratesAttack",
]

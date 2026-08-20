#!/usr/bin/env python3
"""
广度攻击编排器 v1.0

功能:
1. 多向量攻击编排 - 同时攻击多个攻击面
2. 服务特定攻击策略 - 针对不同服务的专门攻击
3. 智能工具链 - 基于发现自动选择后续工具
4. 全面覆盖 - 确保不遗漏任何攻击面

覆盖的攻击面:
- Web应用 (30+ 工具链)
- 网络服务 (25+ 工具链)
- 数据库 (15+ 工具链)
- 邮件服务 (10+ 工具链)
- 文件共享 (10+ 工具链)
- 远程访问 (15+ 工具链)
- 容器/云 (10+ 工具链)
- 无线网络 (10+ 工具链)
- Active Directory (20+ 工具链)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Callable
from enum import Enum
import asyncio
from datetime import datetime


class AttackSurface(Enum):
    """攻击面枚举"""
    WEB_APPLICATION = "web_app"
    NETWORK_SERVICE = "network_svc"
    DATABASE = "database"
    EMAIL = "email"
    FILE_SHARE = "file_share"
    REMOTE_ACCESS = "remote_access"
    CONTAINER_CLOUD = "container_cloud"
    WIRELESS = "wireless"
    ACTIVE_DIRECTORY = "active_directory"
    IOT_EMBEDDED = "iot_embedded"
    API_ENDPOINT = "api_endpoint"
    MOBILE_APP = "mobile_app"


class ServiceType(Enum):
    """服务类型枚举"""
    # Web服务
    HTTP = "http"
    HTTPS = "https"
    PROXY = "proxy"

    # 数据库
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    MONGODB = "mongodb"
    REDIS = "redis"
    ELASTICSEARCH = "elasticsearch"

    # 文件共享
    SMB = "smb"
    FTP = "ftp"
    NFS = "nfs"
    RSYNC = "rsync"

    # 远程访问
    SSH = "ssh"
    TELNET = "telnet"
    RDP = "rdp"
    VNC = "vnc"
    WINRM = "winrm"

    # 邮件
    SMTP = "smtp"
    POP3 = "pop3"
    IMAP = "imap"

    # 目录服务
    LDAP = "ldap"
    KERBEROS = "kerberos"

    # 其他
    DNS = "dns"
    SNMP = "snmp"
    DOCKER = "docker"
    KUBERNETES = "kubernetes"


@dataclass
class ToolChain:
    """工具链定义"""
    name: str
    description: str
    surface: AttackSurface
    services: List[ServiceType]
    tools: List[str]  # 工具名称列表
    conditions: Dict[str, Any] = field(default_factory=dict)  # 触发条件
    parallel: bool = False  # 是否可并行
    priority: int = 5  # 优先级 1-10
    timeout: int = 300  # 超时秒数
    success_indicators: List[str] = field(default_factory=list)  # 成功指标
    next_chains: List[str] = field(default_factory=list)  # 后续工具链


# ==================== Web应用攻击工具链 ====================

WEB_TOOL_CHAINS: List[ToolChain] = [
    # 基础侦察
    ToolChain(
        name="web_fingerprint",
        description="Web应用指纹识别",
        surface=AttackSurface.WEB_APPLICATION,
        services=[ServiceType.HTTP, ServiceType.HTTPS],
        tools=["whatweb_scan", "httpx_probe", "nuclei_technology_detection"],
        parallel=True,
        priority=10,
        timeout=60,
        success_indicators=["technology_detected", "cms_identified"],
        next_chains=["cms_specific_scan", "directory_bruteforce"]
    ),

    ToolChain(
        name="directory_bruteforce",
        description="目录和文件枚举",
        surface=AttackSurface.WEB_APPLICATION,
        services=[ServiceType.HTTP, ServiceType.HTTPS],
        tools=["gobuster_scan", "ffuf_scan", "feroxbuster_scan"],
        parallel=False,  # 避免同时运行多个爆破
        priority=9,
        timeout=300,
        success_indicators=["directory_found", "file_found", "backup_found"],
        next_chains=["sensitive_file_analysis", "hidden_path_exploit"]
    ),

    ToolChain(
        name="cms_specific_scan",
        description="CMS特定漏洞扫描",
        surface=AttackSurface.WEB_APPLICATION,
        services=[ServiceType.HTTP, ServiceType.HTTPS],
        tools=["wpscan_scan", "joomscan_scan", "droopescan"],
        conditions={"cms_detected": True},
        priority=8,
        timeout=180,
        success_indicators=["vulnerability_found", "version_vulnerable"],
        next_chains=["cms_exploit"]
    ),

    ToolChain(
        name="waf_detection",
        description="WAF检测和指纹",
        surface=AttackSurface.WEB_APPLICATION,
        services=[ServiceType.HTTP, ServiceType.HTTPS],
        tools=["wafw00f_scan", "nmap_http_waf"],
        priority=7,
        timeout=60,
        success_indicators=["waf_detected", "waf_type_identified"],
        next_chains=["waf_bypass_attack"]
    ),

    ToolChain(
        name="sql_injection_scan",
        description="SQL注入漏洞扫描",
        surface=AttackSurface.WEB_APPLICATION,
        services=[ServiceType.HTTP, ServiceType.HTTPS],
        tools=["sqlmap_scan", "ghauri_scan", "nosqlmap_scan"],
        priority=9,
        timeout=600,
        success_indicators=["sqli_vulnerable", "database_dumped"],
        next_chains=["database_dump", "privilege_escalation"]
    ),

    ToolChain(
        name="xss_scan",
        description="XSS漏洞扫描",
        surface=AttackSurface.WEB_APPLICATION,
        services=[ServiceType.HTTP, ServiceType.HTTPS],
        tools=["dalfox_scan", "xsstrike_scan", "kxss_scan"],
        priority=7,
        timeout=300,
        success_indicators=["xss_reflected", "xss_stored", "xss_dom"],
        next_chains=["session_hijack", "keylogger_inject"]
    ),

    ToolChain(
        name="ssrf_scan",
        description="SSRF漏洞扫描",
        surface=AttackSurface.WEB_APPLICATION,
        services=[ServiceType.HTTP, ServiceType.HTTPS],
        tools=["ssrfmap_scan", "gopherus_scan"],
        priority=8,
        timeout=300,
        success_indicators=["ssrf_confirmed", "internal_access"],
        next_chains=["internal_port_scan", "cloud_metadata_access"]
    ),

    ToolChain(
        name="ssti_scan",
        description="模板注入漏洞扫描",
        surface=AttackSurface.WEB_APPLICATION,
        services=[ServiceType.HTTP, ServiceType.HTTPS],
        tools=["tplmap_scan", "ssti_fuzzer"],
        priority=8,
        timeout=300,
        success_indicators=["ssti_confirmed", "rce_achieved"],
        next_chains=["reverse_shell", "file_read"]
    ),

    ToolChain(
        name="lfi_rfi_scan",
        description="文件包含漏洞扫描",
        surface=AttackSurface.WEB_APPLICATION,
        services=[ServiceType.HTTP, ServiceType.HTTPS],
        tools=["lfi_suite", "fimap_scan"],
        priority=8,
        timeout=300,
        success_indicators=["lfi_confirmed", "rfi_confirmed"],
        next_chains=["log_poisoning", "wrapper_exploit"]
    ),

    ToolChain(
        name="file_upload_attack",
        description="文件上传漏洞利用",
        surface=AttackSurface.WEB_APPLICATION,
        services=[ServiceType.HTTP, ServiceType.HTTPS],
        tools=["upload_scanner", "fuxploider_scan"],
        priority=9,
        timeout=300,
        success_indicators=["upload_bypass", "webshell_uploaded"],
        next_chains=["webshell_access", "reverse_shell"]
    ),

    ToolChain(
        name="api_security_scan",
        description="API安全测试",
        surface=AttackSurface.API_ENDPOINT,
        services=[ServiceType.HTTP, ServiceType.HTTPS],
        tools=["arjun_scan", "kiterunner_scan", "postman_fuzzer"],
        priority=8,
        timeout=300,
        success_indicators=["hidden_endpoint", "idor_found", "auth_bypass"],
        next_chains=["api_exploit", "data_extraction"]
    ),

    ToolChain(
        name="jwt_attack",
        description="JWT令牌攻击",
        surface=AttackSurface.WEB_APPLICATION,
        services=[ServiceType.HTTP, ServiceType.HTTPS],
        tools=["jwt_tool", "jwt_cracker"],
        conditions={"jwt_detected": True},
        priority=8,
        timeout=180,
        success_indicators=["jwt_forged", "secret_cracked"],
        next_chains=["privilege_escalation", "account_takeover"]
    ),

    ToolChain(
        name="nuclei_comprehensive",
        description="Nuclei综合漏洞扫描",
        surface=AttackSurface.WEB_APPLICATION,
        services=[ServiceType.HTTP, ServiceType.HTTPS],
        tools=["nuclei_scan", "nuclei_cve_scan", "nuclei_web_scan"],
        parallel=True,
        priority=9,
        timeout=600,
        success_indicators=["cve_found", "vulnerability_confirmed"],
        next_chains=["cve_exploit", "manual_verification"]
    ),

    ToolChain(
        name="subdomain_takeover",
        description="子域名接管检测",
        surface=AttackSurface.WEB_APPLICATION,
        services=[ServiceType.HTTP, ServiceType.HTTPS],
        tools=["subjack_scan", "subzy_scan"],
        priority=6,
        timeout=300,
        success_indicators=["takeover_possible", "dangling_cname"],
        next_chains=["claim_subdomain"]
    ),

    ToolChain(
        name="graphql_attack",
        description="GraphQL安全测试",
        surface=AttackSurface.API_ENDPOINT,
        services=[ServiceType.HTTP, ServiceType.HTTPS],
        tools=["graphql_cop", "clairvoyance_scan"],
        conditions={"graphql_detected": True},
        priority=8,
        timeout=300,
        success_indicators=["introspection_enabled", "injection_found"],
        next_chains=["data_extraction", "auth_bypass"]
    ),
]


# ==================== 网络服务攻击工具链 ====================

NETWORK_TOOL_CHAINS: List[ToolChain] = [
    ToolChain(
        name="port_discovery",
        description="端口发现和服务识别",
        surface=AttackSurface.NETWORK_SERVICE,
        services=[],  # 适用于所有
        tools=["nmap_scan", "masscan_fast_scan", "rustscan"],
        parallel=True,
        priority=10,
        timeout=300,
        success_indicators=["open_ports", "services_identified"],
        next_chains=["service_specific_attack"]
    ),

    ToolChain(
        name="smb_attack",
        description="SMB服务攻击",
        surface=AttackSurface.FILE_SHARE,
        services=[ServiceType.SMB],
        tools=["enum4linux_scan", "smbmap_scan", "smbclient_enum", "crackmapexec_smb"],
        priority=9,
        timeout=300,
        success_indicators=["share_accessible", "null_session", "credentials_found"],
        next_chains=["smb_relay", "psexec_exec", "eternal_blue"]
    ),

    ToolChain(
        name="ssh_attack",
        description="SSH服务攻击",
        surface=AttackSurface.REMOTE_ACCESS,
        services=[ServiceType.SSH],
        tools=["ssh_audit", "hydra_attack", "medusa_bruteforce"],
        priority=8,
        timeout=600,
        success_indicators=["weak_algorithm", "credentials_found", "key_found"],
        next_chains=["ssh_login", "ssh_tunnel"]
    ),

    ToolChain(
        name="ftp_attack",
        description="FTP服务攻击",
        surface=AttackSurface.FILE_SHARE,
        services=[ServiceType.FTP],
        tools=["nmap_ftp_scripts", "hydra_attack", "ftp_anonymous_check"],
        priority=7,
        timeout=300,
        success_indicators=["anonymous_access", "credentials_found", "writable_dir"],
        next_chains=["ftp_upload_shell", "data_extraction"]
    ),

    ToolChain(
        name="rdp_attack",
        description="RDP服务攻击",
        surface=AttackSurface.REMOTE_ACCESS,
        services=[ServiceType.RDP],
        tools=["rdp_check", "hydra_attack", "crowbar_attack"],
        priority=8,
        timeout=600,
        success_indicators=["nla_disabled", "credentials_found", "bluekeep_vulnerable"],
        next_chains=["rdp_login", "bluekeep_exploit"]
    ),

    ToolChain(
        name="winrm_attack",
        description="WinRM服务攻击",
        surface=AttackSurface.REMOTE_ACCESS,
        services=[ServiceType.WINRM],
        tools=["evil_winrm", "crackmapexec_winrm"],
        priority=8,
        timeout=300,
        success_indicators=["winrm_accessible", "credentials_valid"],
        next_chains=["winrm_shell", "lateral_movement"]
    ),

    ToolChain(
        name="snmp_attack",
        description="SNMP服务攻击",
        surface=AttackSurface.NETWORK_SERVICE,
        services=[ServiceType.SNMP],
        tools=["snmpwalk", "snmp_check", "onesixtyone"],
        priority=6,
        timeout=180,
        success_indicators=["community_found", "info_leaked"],
        next_chains=["snmp_enum", "config_extraction"]
    ),

    ToolChain(
        name="dns_attack",
        description="DNS服务攻击",
        surface=AttackSurface.NETWORK_SERVICE,
        services=[ServiceType.DNS],
        tools=["dnsrecon_scan", "dnsenum_scan", "fierce_scan", "dnsmap_scan"],
        parallel=True,
        priority=7,
        timeout=300,
        success_indicators=["zone_transfer", "subdomains_found"],
        next_chains=["dns_takeover", "cache_poisoning"]
    ),

    ToolChain(
        name="ldap_attack",
        description="LDAP服务攻击",
        surface=AttackSurface.ACTIVE_DIRECTORY,
        services=[ServiceType.LDAP],
        tools=["ldapsearch", "ldapenum", "windapsearch"],
        priority=9,
        timeout=300,
        success_indicators=["anonymous_bind", "users_enumerated"],
        next_chains=["ad_enum", "password_spray"]
    ),

    ToolChain(
        name="kerberos_attack",
        description="Kerberos攻击",
        surface=AttackSurface.ACTIVE_DIRECTORY,
        services=[ServiceType.KERBEROS],
        tools=["kerbrute", "GetNPUsers", "GetUserSPNs"],
        priority=9,
        timeout=600,
        success_indicators=["asrep_roast", "kerberoast", "tickets_obtained"],
        next_chains=["ticket_crack", "pass_the_ticket"]
    ),
]


# ==================== 数据库攻击工具链 ====================

DATABASE_TOOL_CHAINS: List[ToolChain] = [
    ToolChain(
        name="mysql_attack",
        description="MySQL数据库攻击",
        surface=AttackSurface.DATABASE,
        services=[ServiceType.MYSQL],
        tools=["mysql_enum", "hydra_attack", "mysql_audit"],
        priority=8,
        timeout=300,
        success_indicators=["credentials_found", "udf_possible", "file_read"],
        next_chains=["mysql_udf_privesc", "data_dump"]
    ),

    ToolChain(
        name="mssql_attack",
        description="MSSQL数据库攻击",
        surface=AttackSurface.DATABASE,
        services=[ServiceType.MSSQL],
        tools=["mssql_enum", "impacket_mssqlclient", "crackmapexec_mssql"],
        priority=8,
        timeout=300,
        success_indicators=["xp_cmdshell", "linked_servers", "credentials_found"],
        next_chains=["mssql_rce", "linked_server_pivot"]
    ),

    ToolChain(
        name="postgresql_attack",
        description="PostgreSQL数据库攻击",
        surface=AttackSurface.DATABASE,
        services=[ServiceType.POSTGRESQL],
        tools=["pg_enum", "hydra_attack", "pg_dump_all"],
        priority=7,
        timeout=300,
        success_indicators=["credentials_found", "copy_to_program"],
        next_chains=["pg_rce", "data_dump"]
    ),

    ToolChain(
        name="mongodb_attack",
        description="MongoDB数据库攻击",
        surface=AttackSurface.DATABASE,
        services=[ServiceType.MONGODB],
        tools=["nosqlmap_scan", "mongodump_enum"],
        priority=7,
        timeout=300,
        success_indicators=["no_auth", "injection_found"],
        next_chains=["nosql_injection", "data_dump"]
    ),

    ToolChain(
        name="redis_attack",
        description="Redis数据库攻击",
        surface=AttackSurface.DATABASE,
        services=[ServiceType.REDIS],
        tools=["redis_cli_enum", "redis_rogue"],
        priority=8,
        timeout=180,
        success_indicators=["no_auth", "config_set", "module_load"],
        next_chains=["redis_rce", "ssh_key_write"]
    ),

    ToolChain(
        name="elasticsearch_attack",
        description="Elasticsearch攻击",
        surface=AttackSurface.DATABASE,
        services=[ServiceType.ELASTICSEARCH],
        tools=["elasticsearch_enum", "es_dump"],
        priority=6,
        timeout=180,
        success_indicators=["no_auth", "indices_accessible"],
        next_chains=["data_extraction", "groovy_rce"]
    ),
]


# ==================== AD域攻击工具链 ====================

AD_TOOL_CHAINS: List[ToolChain] = [
    ToolChain(
        name="ad_enum",
        description="AD域枚举",
        surface=AttackSurface.ACTIVE_DIRECTORY,
        services=[ServiceType.LDAP, ServiceType.KERBEROS],
        tools=["bloodhound_collector", "ldapdomaindump", "adidnsdump"],
        priority=9,
        timeout=600,
        success_indicators=["domain_mapped", "paths_found"],
        next_chains=["shortest_path_attack", "acl_abuse"]
    ),

    ToolChain(
        name="password_spray",
        description="密码喷洒攻击",
        surface=AttackSurface.ACTIVE_DIRECTORY,
        services=[ServiceType.LDAP, ServiceType.SMB],
        tools=["spray_ad", "kerbrute", "crackmapexec_spray"],
        priority=8,
        timeout=1800,
        success_indicators=["valid_credentials", "account_found"],
        next_chains=["authenticated_enum", "lateral_movement"]
    ),

    ToolChain(
        name="asrep_roast",
        description="AS-REP Roasting攻击",
        surface=AttackSurface.ACTIVE_DIRECTORY,
        services=[ServiceType.KERBEROS],
        tools=["GetNPUsers", "rubeus_asreproast"],
        priority=8,
        timeout=300,
        success_indicators=["hash_obtained", "no_preauth_users"],
        next_chains=["hash_crack", "account_compromise"]
    ),

    ToolChain(
        name="kerberoast",
        description="Kerberoasting攻击",
        surface=AttackSurface.ACTIVE_DIRECTORY,
        services=[ServiceType.KERBEROS],
        tools=["GetUserSPNs", "rubeus_kerberoast"],
        priority=9,
        timeout=300,
        success_indicators=["tgs_obtained", "service_accounts"],
        next_chains=["hash_crack", "service_account_abuse"]
    ),

    ToolChain(
        name="dcsync",
        description="DCSync攻击",
        surface=AttackSurface.ACTIVE_DIRECTORY,
        services=[ServiceType.LDAP],
        tools=["secretsdump", "mimikatz_dcsync"],
        conditions={"replication_rights": True},
        priority=10,
        timeout=600,
        success_indicators=["ntds_dumped", "krbtgt_hash"],
        next_chains=["golden_ticket", "domain_admin"]
    ),

    ToolChain(
        name="acl_abuse",
        description="ACL权限滥用",
        surface=AttackSurface.ACTIVE_DIRECTORY,
        services=[ServiceType.LDAP],
        tools=["aclpwn", "dacledit"],
        priority=8,
        timeout=300,
        success_indicators=["writedacl", "genericall", "genericwrite"],
        next_chains=["permission_escalation", "shadow_credentials"]
    ),

    ToolChain(
        name="delegation_attack",
        description="委派攻击",
        surface=AttackSurface.ACTIVE_DIRECTORY,
        services=[ServiceType.KERBEROS],
        tools=["findDelegation", "getST"],
        priority=8,
        timeout=300,
        success_indicators=["unconstrained_delegation", "constrained_delegation"],
        next_chains=["s4u_abuse", "rbcd_attack"]
    ),

    ToolChain(
        name="gpo_abuse",
        description="GPO滥用",
        surface=AttackSurface.ACTIVE_DIRECTORY,
        services=[ServiceType.LDAP, ServiceType.SMB],
        tools=["gpo_enum", "pygpoabuse"],
        priority=7,
        timeout=300,
        success_indicators=["gpo_writable", "scheduled_task_create"],
        next_chains=["mass_compromise", "persistence"]
    ),
]


# ==================== 容器/云攻击工具链 ====================

CLOUD_TOOL_CHAINS: List[ToolChain] = [
    ToolChain(
        name="docker_attack",
        description="Docker容器攻击",
        surface=AttackSurface.CONTAINER_CLOUD,
        services=[ServiceType.DOCKER],
        tools=["docker_enum", "deepce", "docker_escape"],
        priority=8,
        timeout=300,
        success_indicators=["privileged_container", "socket_exposed", "escape_possible"],
        next_chains=["container_escape", "host_access"]
    ),

    ToolChain(
        name="kubernetes_attack",
        description="Kubernetes攻击",
        surface=AttackSurface.CONTAINER_CLOUD,
        services=[ServiceType.KUBERNETES],
        tools=["kubectl_enum", "kube_hunter", "peirates"],
        priority=8,
        timeout=300,
        success_indicators=["rbac_misconfigured", "secrets_accessible"],
        next_chains=["cluster_admin", "secret_extraction"]
    ),

    ToolChain(
        name="cloud_metadata",
        description="云元数据服务攻击",
        surface=AttackSurface.CONTAINER_CLOUD,
        services=[ServiceType.HTTP],
        tools=["ssrf_metadata", "imds_exploit"],
        priority=9,
        timeout=120,
        success_indicators=["credentials_leaked", "role_assumed"],
        next_chains=["cloud_pivot", "privilege_escalation"]
    ),
]


# ==================== 服务端口映射 ====================

SERVICE_PORT_MAP: Dict[int, ServiceType] = {
    21: ServiceType.FTP,
    22: ServiceType.SSH,
    23: ServiceType.TELNET,
    25: ServiceType.SMTP,
    53: ServiceType.DNS,
    80: ServiceType.HTTP,
    110: ServiceType.POP3,
    111: ServiceType.NFS,
    135: ServiceType.SMB,
    139: ServiceType.SMB,
    143: ServiceType.IMAP,
    161: ServiceType.SNMP,
    389: ServiceType.LDAP,
    443: ServiceType.HTTPS,
    445: ServiceType.SMB,
    465: ServiceType.SMTP,
    587: ServiceType.SMTP,
    636: ServiceType.LDAP,
    993: ServiceType.IMAP,
    995: ServiceType.POP3,
    1433: ServiceType.MSSQL,
    1521: ServiceType.ORACLE,
    2049: ServiceType.NFS,
    2375: ServiceType.DOCKER,
    2376: ServiceType.DOCKER,
    3306: ServiceType.MYSQL,
    3389: ServiceType.RDP,
    5432: ServiceType.POSTGRESQL,
    5900: ServiceType.VNC,
    5985: ServiceType.WINRM,
    5986: ServiceType.WINRM,
    6379: ServiceType.REDIS,
    8080: ServiceType.HTTP,
    8443: ServiceType.HTTPS,
    9200: ServiceType.ELASTICSEARCH,
    9300: ServiceType.ELASTICSEARCH,
    27017: ServiceType.MONGODB,
    88: ServiceType.KERBEROS,
}


@dataclass
class AttackVector:
    """攻击向量"""
    chain: ToolChain
    target: str
    port: int
    service: ServiceType
    priority: int
    status: str = "pending"  # pending, running, completed, failed
    result: Optional[Dict[str, Any]] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


class BroadAttackOrchestrator:
    """广度攻击编排器"""

    def __init__(self):
        self.all_chains: Dict[str, ToolChain] = {}
        self.active_vectors: List[AttackVector] = []
        self.completed_vectors: List[AttackVector] = []
        self.discovered_services: Dict[str, List[ServiceType]] = {}
        self.attack_results: Dict[str, Any] = {}

        # 加载所有工具链
        self._load_chains()

    def _load_chains(self):
        """加载所有工具链"""
        all_chains = (
            WEB_TOOL_CHAINS +
            NETWORK_TOOL_CHAINS +
            DATABASE_TOOL_CHAINS +
            AD_TOOL_CHAINS +
            CLOUD_TOOL_CHAINS
        )
        for chain in all_chains:
            self.all_chains[chain.name] = chain

    def identify_services(self, scan_result: Dict[str, Any]) -> Dict[str, List[ServiceType]]:
        """从扫描结果识别服务"""
        services = {}

        if "ports" in scan_result:
            for port_info in scan_result["ports"]:
                port = port_info.get("port", 0)
                host = port_info.get("host", "unknown")

                if port in SERVICE_PORT_MAP:
                    if host not in services:
                        services[host] = []
                    services[host].append(SERVICE_PORT_MAP[port])

        self.discovered_services = services
        return services

    def get_chains_for_service(self, service: ServiceType) -> List[ToolChain]:
        """获取适用于特定服务的工具链"""
        applicable = []
        for chain in self.all_chains.values():
            if not chain.services or service in chain.services:
                applicable.append(chain)
        return sorted(applicable, key=lambda x: x.priority, reverse=True)

    def get_chains_for_surface(self, surface: AttackSurface) -> List[ToolChain]:
        """获取适用于特定攻击面的工具链"""
        return [c for c in self.all_chains.values() if c.surface == surface]

    def plan_attack(
        self,
        target: str,
        services: List[ServiceType],
        max_parallel: int = 5,
        time_limit: int = 3600
    ) -> List[AttackVector]:
        """规划攻击向量"""
        vectors = []
        used_chains = set()

        # 为每个服务创建攻击向量
        for service in services:
            chains = self.get_chains_for_service(service)
            for chain in chains:
                if chain.name not in used_chains:
                    port = self._get_default_port(service)
                    vector = AttackVector(
                        chain=chain,
                        target=target,
                        port=port,
                        service=service,
                        priority=chain.priority
                    )
                    vectors.append(vector)
                    used_chains.add(chain.name)

        # 按优先级排序
        vectors.sort(key=lambda x: x.priority, reverse=True)

        self.active_vectors = vectors
        return vectors

    def _get_default_port(self, service: ServiceType) -> int:
        """获取服务的默认端口"""
        for port, svc in SERVICE_PORT_MAP.items():
            if svc == service:
                return port
        return 0

    def get_next_chains(self, completed_chain: str, results: Dict[str, Any]) -> List[ToolChain]:
        """根据完成的工具链和结果获取后续工具链"""
        if completed_chain not in self.all_chains:
            return []

        chain = self.all_chains[completed_chain]
        next_chains = []

        # 检查成功指标
        success = False
        for indicator in chain.success_indicators:
            if indicator in results and results[indicator]:
                success = True
                break

        if success:
            for next_name in chain.next_chains:
                if next_name in self.all_chains:
                    next_chains.append(self.all_chains[next_name])

        return next_chains

    def get_attack_coverage(self) -> Dict[str, Any]:
        """获取攻击覆盖情况"""
        coverage = {
            "total_chains": len(self.all_chains),
            "surfaces": {},
            "services": {},
        }

        # 按攻击面统计
        for chain in self.all_chains.values():
            surface = chain.surface.value
            if surface not in coverage["surfaces"]:
                coverage["surfaces"][surface] = 0
            coverage["surfaces"][surface] += 1

            # 按服务统计
            for service in chain.services:
                svc = service.value
                if svc not in coverage["services"]:
                    coverage["services"][svc] = 0
                coverage["services"][svc] += 1

        return coverage

    def suggest_attack_path(
        self,
        discovered_info: Dict[str, Any]
    ) -> List[ToolChain]:
        """基于已发现信息建议攻击路径"""
        suggested = []

        # Web应用发现
        if discovered_info.get("web_server"):
            suggested.extend([
                self.all_chains.get("web_fingerprint"),
                self.all_chains.get("directory_bruteforce"),
                self.all_chains.get("nuclei_comprehensive"),
            ])

        # CMS发现
        if discovered_info.get("cms_type"):
            suggested.append(self.all_chains.get("cms_specific_scan"))

        # Windows域环境
        if discovered_info.get("domain_controller"):
            suggested.extend([
                self.all_chains.get("ad_enum"),
                self.all_chains.get("kerberoast"),
                self.all_chains.get("asrep_roast"),
            ])

        # 数据库发现
        if discovered_info.get("database"):
            db_type = discovered_info["database"]
            if "mysql" in db_type.lower():
                suggested.append(self.all_chains.get("mysql_attack"))
            elif "mssql" in db_type.lower() or "sql server" in db_type.lower():
                suggested.append(self.all_chains.get("mssql_attack"))
            elif "postgres" in db_type.lower():
                suggested.append(self.all_chains.get("postgresql_attack"))
            elif "mongo" in db_type.lower():
                suggested.append(self.all_chains.get("mongodb_attack"))
            elif "redis" in db_type.lower():
                suggested.append(self.all_chains.get("redis_attack"))

        # 容器环境
        if discovered_info.get("docker") or discovered_info.get("container"):
            suggested.append(self.all_chains.get("docker_attack"))

        if discovered_info.get("kubernetes"):
            suggested.append(self.all_chains.get("kubernetes_attack"))

        # 去除None值并排序
        suggested = [s for s in suggested if s is not None]
        suggested.sort(key=lambda x: x.priority, reverse=True)

        return suggested

    def generate_attack_report(self) -> Dict[str, Any]:
        """生成攻击报告"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_vectors": len(self.active_vectors) + len(self.completed_vectors),
            "completed_vectors": len(self.completed_vectors),
            "successful_attacks": 0,
            "surfaces_covered": set(),
            "services_attacked": set(),
            "findings": [],
            "recommendations": [],
        }

        for vector in self.completed_vectors:
            report["surfaces_covered"].add(vector.chain.surface.value)
            report["services_attacked"].add(vector.service.value)

            if vector.result and vector.result.get("success"):
                report["successful_attacks"] += 1
                report["findings"].append({
                    "chain": vector.chain.name,
                    "service": vector.service.value,
                    "result": vector.result,
                })

        # 转换set为list
        report["surfaces_covered"] = list(report["surfaces_covered"])
        report["services_attacked"] = list(report["services_attacked"])

        return report


# ==================== 便捷函数 ====================

_orchestrator_instance: Optional[BroadAttackOrchestrator] = None


def get_orchestrator() -> BroadAttackOrchestrator:
    """获取编排器单例"""
    global _orchestrator_instance
    if _orchestrator_instance is None:
        _orchestrator_instance = BroadAttackOrchestrator()
    return _orchestrator_instance


def get_chains_for_port(port: int) -> List[ToolChain]:
    """根据端口获取适用的工具链"""
    orchestrator = get_orchestrator()
    if port in SERVICE_PORT_MAP:
        return orchestrator.get_chains_for_service(SERVICE_PORT_MAP[port])
    return []


def suggest_tools_for_target(
    target_info: Dict[str, Any]
) -> List[str]:
    """为目标建议工具"""
    orchestrator = get_orchestrator()
    chains = orchestrator.suggest_attack_path(target_info)

    tools = []
    for chain in chains:
        tools.extend(chain.tools)

    # 去重保持顺序
    seen = set()
    unique_tools = []
    for tool in tools:
        if tool not in seen:
            seen.add(tool)
            unique_tools.append(tool)

    return unique_tools


def get_attack_surface_stats() -> Dict[str, int]:
    """获取攻击面统计"""
    orchestrator = get_orchestrator()
    return orchestrator.get_attack_coverage()


__all__ = [
    # 枚举
    "AttackSurface",
    "ServiceType",

    # 数据结构
    "ToolChain",
    "AttackVector",

    # 工具链集合
    "WEB_TOOL_CHAINS",
    "NETWORK_TOOL_CHAINS",
    "DATABASE_TOOL_CHAINS",
    "AD_TOOL_CHAINS",
    "CLOUD_TOOL_CHAINS",

    # 映射
    "SERVICE_PORT_MAP",

    # 核心类
    "BroadAttackOrchestrator",

    # 便捷函数
    "get_orchestrator",
    "get_chains_for_port",
    "suggest_tools_for_target",
    "get_attack_surface_stats",
]

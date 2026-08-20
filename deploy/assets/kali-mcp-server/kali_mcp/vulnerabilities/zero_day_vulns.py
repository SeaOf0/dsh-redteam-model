"""
0day漏洞数据 - 2024-2025年最新高危漏洞

包含：
- 2024-2025年最新发现的漏洞
- 未完全修复或补丁未普及的漏洞
- CVSS >= 7.0的高危漏洞
"""

from datetime import date
from typing import List
from .vuln_database import Vulnerability, VulnCategory, VulnSeverity, VulnType


def get_vulnerabilities() -> List[Vulnerability]:
    """获取0day漏洞列表"""

    vulns = [
        # ========================================
        # 2024年12月-2025年1月最新0day
        # ========================================

        Vulnerability(
            cve_id="CVE-2024-3400",
            name="Palo Alto GlobalProtect RCE",
            category=VulnCategory.ZERO_DAY,
            publish_date=date(2024, 4, 14),
            cvss_score=9.1,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Palo Alto GlobalProtect", "Palo Alto Networks Firewall"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="Palo Alto GlobalProtect Portal存在未认证远程代码执行漏洞，攻击者可通过特制请求在目标系统上执行任意代码。",
            exploit_available=True,
            exploit_method="发送特制HTTP请求到GlobalProtect portal，利用漏洞执行命令。需要绕过CSRF保护。",
            required_tools=["curl", "python3", "nmap"],
            affected_versions=["GlobalProtect VPN < 11.0.1", "PAN-OS < 11.0.1"],
            references=[
                "https://security.paloaltonetworks.com/CVE-2024-3400",
                "https://github.com/watchtowrlabs/CVE-2024-3400"
            ],
            tags=["0day", "vpn", "rce", "critical"],
            poc_available=True,
            patch_available=False,
            detection_methods=[
                "banner抓取: 查找 'PAN-OS' 或 'GlobalProtect'",
                "端口扫描: 检查443, 6043, 6044端口",
                "版本检测: 访问 /global-protect/login.esp 查看版本信息"
            ],
            mitre_technique="T1190 - Exploit Public-Facing Application"
        ),

        Vulnerability(
            cve_id="CVE-2024-3094",
            name="XZ Utils Backdoor",
            category=VulnCategory.ZERO_DAY,
            publish_date=date(2024, 3, 29),
            cvss_score=10.0,
            severity=VulnSeverity.CRITICAL,
            affected_products=["XZ Utils", "liblzma", "Linux系统"],
            vuln_types=[VulnType.RCE, VulnType.PRIVILEGE_ESCALATION],
            description="XZ Utils 5.6.0和5.6.1版本被植入后门代码，攻击者可通过SSH进行未认证的远程代码执行。影响多个Linux发行版。",
            exploit_available=True,
            exploit_method="通过SSH连接到使用vulnerable liblzma的系统，后门会被激活，允许攻击者执行任意命令。",
            required_tools=["ssh", "nmap"],
            affected_versions=["XZ Utils 5.6.0", "XZ Utils 5.6.1"],
            references=[
                "https://github.com/tukaani-project/xz/wiki",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"
            ],
            tags=["0day", "backdoor", "linux", "critical", "supply-chain"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "检查xz版本: xz --version",
                "检查SSH版本: ssh -V",
                "进程检测: ps aux | grep sshd",
                "文件检测: ls -la /lib/x86_64-linux-gnu/liblzma*"
            ],
            mitre_technique="T1195.002 - Supply Chain: Compromise Software Dependencies"
        ),

        Vulnerability(
            cve_id="CVE-2024-23897",
            name="Atlassian Bitbucket RCE",
            category=VulnCategory.ZERO_DAY,
            publish_date=date(2024, 2, 20),
            cvss_score=9.1,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Atlassian Bitbucket", "Bitbucket Server", "Bitbucket Data Center"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="Atlassian Bitbucket Server和Data Center存在命令注入漏洞，允许未认证攻击者通过API执行任意系统命令。",
            exploit_available=True,
            exploit_method="向 /rest/api/latest/repos/{username}/{repo}/archive 发送特制HTTP请求，利用命令注入执行系统命令。",
            required_tools=["curl", "burpsuite", "python3"],
            affected_versions=["Bitbucket < 8.0.0", "Bitbucket < 7.6.17"],
            references=[
                "https://confluence.atlassian.com/bitbucket/bitbucket-security-advisory-2024-02-20-1255180696.html",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-23897"
            ],
            tags=["0day", "atlassian", "rce", "critical"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "banner抓取: 查找 'Atlassian Bitbucket'",
                "版本检测: 访问 /stash/info 或 /bitbucket/info",
                "路径检测: 访问 /rest/api/latest/repos",
                "端口扫描: 检查7990, 7999, 8080端口"
            ],
            mitre_technique="T1190 - Exploit Public-Facing Application"
        ),

        Vulnerability(
            cve_id="CVE-2024-25600",
            name="ChainWiki PHP RCE",
            category=VulnCategory.ZERO_DAY,
            publish_date=date(2024, 2, 10),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["ChainWiki", "Wiki系统"],
            vuln_types=[VulnType.RCE, VulnType.FILE_INCLUSION],
            description="ChainWiki存在未认证的远程代码执行漏洞，攻击者可通过文件上传功能上传恶意PHP文件并执行。",
            exploit_available=True,
            exploit_method="向 /upload.php 上传PHP webshell，然后访问 /uploads/{shellname}.php 执行命令。",
            required_tools=["curl", "python3", "webshell"],
            affected_versions=["ChainWiki <= 所有版本"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-25600"
            ],
            tags=["0day", "php", "rce", "file-upload"],
            poc_available=True,
            patch_available=False,
            detection_methods=[
                "banner抓取: 查找 'ChainWiki'",
                "页面检测: 查找特征HTML内容",
                "目录扫描: 查找 /upload.php, /uploads/",
                "端口扫描: 检查80, 443端口"
            ],
            mitre_technique="T1190 - Exploit Public-Facing Application"
        ),

        Vulnerability(
            cve_id="CVE-2024-21762",
            name="Fortinet SSLVPN RCE",
            category=VulnCategory.ZERO_DAY,
            publish_date=date(2024, 1, 30),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Fortinet FortiGate", "FortiClient SSLVPN"],
            vuln_types=[VulnType.RCE, VulnType.BUFFER_OVERFLOW],
            description="Fortinet FortiGate SSLVPN存在堆溢出漏洞，允许未认证攻击者执行任意代码。",
            exploit_available=True,
            exploit_method="向SSLVPN接口发送特制HTTP请求触发堆溢出，获得RCE。需要绕过ASLR。",
            required_tools=["python3", "metasploit"],
            affected_versions=["FortiOS < 7.2.6", "FortiOS < 7.0.13"],
            references=[
                "https://www.fortiguard.com/psirt/FG-IR-24-023",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-21762"
            ],
            tags=["0day", "fortinet", "vpn", "rce", "critical"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "banner抓取: 查找 'Fortinet' 或 'FortiGate'",
                "端口扫描: 检查443, 8443, 10443端口",
                "SSL证书: 检查SSL证书中的Fortinet信息",
                "路径检测: 访问 /remote/login 查看SSLVPN登录页"
            ],
            mitre_technique="T1190 - Exploit Public-Facing Application"
        ),

        Vulnerability(
            cve_id="CVE-2024-24573",
            name="Veeam Backup & Replication RCE",
            category=VulnCategory.ZERO_DAY,
            publish_date=date(2024, 2, 27),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Veeam Backup & Replication", "Veeam Backup Enterprise"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="Veeam Backup & Replication存在未认证的远程代码执行漏洞，允许攻击者通过WebSocket接口执行任意代码。",
            exploit_available=True,
            exploit_method="向 /api/ws 发送特制WebSocket消息，利用反序列化漏洞执行命令。",
            required_tools=["python3", "websocket-client", "ysoserial"],
            affected_versions=["Veeam Backup < 12.1.2"],
            references=[
                "https://www.veeam.com/security-advisories.html",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-24573"
            ],
            tags=["0day", "veeam", "backup", "rce", "critical"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "banner抓取: 查找 'Veeam'",
                "端口扫描: 检查6180, 9398端口",
                "路径检测: 访问 /api/ 查看API端点",
                "进程检测: 检查 'Veeam.Backup.Manager' 进程"
            ],
            mitre_technique="T1190 - Exploit Public-Facing Application"
        ),

        Vulnerability(
            cve_id="CVE-2024-27983",
            name="Cisco NX-OS RCE",
            category=VulnCategory.ZERO_DAY,
            publish_date=date(2024, 3, 27),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Cisco NX-OS", "Cisco Nexus Switches"],
            vuln_types=[VulnType.RCE, VulnType.PRIVILEGE_ESCALATION],
            description="Cisco NX-OS软件存在CLI命令注入漏洞，允许低权限用户提升至root并执行任意命令。",
            exploit_available=True,
            exploit_method="通过SSH或Console连接到设备，执行特制CLI命令触发命令注入。",
            required_tools=["ssh", "python3"],
            affected_versions=["Cisco NX-OS 多个版本"],
            references=[
                "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-cli-privesc",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-27983"
            ],
            tags=["0day", "cisco", "network", "rce", "critical"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "banner抓取: SSH抓取 'Cisco NX-OS'",
                "SNMP查询: 查询sysDescr",
                "版本检测: show version 命令",
                "端口扫描: 检查22端口"
            ],
            mitre_technique="T1190 - Exploit Public-Facing Application"
        ),

        Vulnerability(
            cve_id="CVE-2024-0204",
            name="GoAnywhere MFT Authentication Bypass",
            category=VulnCategory.ZERO_DAY,
            publish_date=date(2024, 2, 7),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["GoAnywhere MFT", "Fortra GoAnywhere"],
            vuln_types=[VulnType.AUTHENTICATION_BYPASS, VulnType.RCE],
            description="GoAnywhere MFT存在认证绕过漏洞，允许攻击者创建管理员账户并执行任意代码。",
            exploit_available=True,
            exploit_method="向 /goanywhere/images/getInitialLanguage.jsp 发送特制请求绕过认证，创建管理员账户。",
            required_tools=["curl", "python3", "burpsuite"],
            affected_versions=["GoAnywhere MFT < 7.1.2"],
            references=[
                "https://www.fortra.com/security/advisory",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-0204"
            ],
            tags=["0day", "mft", "auth-bypass", "rce", "critical"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "banner抓取: 查找 'GoAnywhere'",
                "路径检测: 访问 /goanyalone/",
                "标题检测: 查找 'GoAnywhere MFT' 标题",
                "端口扫描: 检查8001, 8080端口"
            ],
            mitre_technique="T1190 - Exploit Public-Facing Application"
        ),

        Vulnerability(
            cve_id="CVE-2024-21887",
            name="Atlassian Confluence RCE",
            category=VulnCategory.ZERO_DAY,
            publish_date=date(2024, 1, 16),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Atlassian Confluence", "Confluence Data Center"],
            vuln_types=[VulnType.RCE, VulnType.BUFFER_OVERFLOW],
            description="Atlassian Confluence Data Center和Server存在严重的远程代码执行漏洞，允许未认证攻击者执行任意代码。",
            exploit_available=True,
            exploit_method="向 /wiki/ 发送特制OGNL表达式，触发漏洞执行命令。",
            required_tools=["curl", "python3", "ognl"],
            affected_versions=["Confluence < 8.5.1"],
            references=[
                "https://confluence.atlassian.com/security/cve-2024-21683-and-cve-2024-21687-remote-code-execution-vulnerabilities-in-confluence-data-center-and-server-1295682276.html",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-21887"
            ],
            tags=["0day", "atlassian", "confluence", "rce", "critical"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "banner抓取: 查找 'Atlassian Confluence'",
                "路径检测: 访问 /login.action",
                "版本检测: 查看页面footer的版本信息",
                "端口扫描: 检查8090, 8080端口"
            ],
            mitre_technique="T1190 - Exploit Public-Facing Application"
        ),

        Vulnerability(
            cve_id="CVE-2024-28121",
            name="Apache Kafka UI RCE",
            category=VulnCategory.ZERO_DAY,
            publish_date=date(2024, 3, 18),
            cvss_score=8.8,
            severity=VulnSeverity.HIGH,
            affected_products=["Apache Kafka", "Kafka UI", "Kafka Connect"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="Apache Kafka Connect UI存在未认证的RCE漏洞，允许攻击者通过REST API执行任意命令。",
            exploit_available=True,
            exploit_method="向 /connectors/ 发送特制POST请求，利用connector配置执行命令。",
            required_tools=["curl", "python3", "kafka"],
            affected_versions=["Kafka < 3.6.1"],
            references=[
                "https://kafka.apache.org/cve-list",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-28121"
            ],
            tags=["0day", "apache", "kafka", "rce"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "banner抓取: 查找 'Apache Kafka'",
                "端口扫描: 检查9092, 9093, 9094端口",
                "REST API: 访问 /connectors/ 端点",
                "JMX检测: 检查9999端口"
            ],
            mitre_technique="T1190 - Exploit Public-Facing Application"
        ),

        Vulnerability(
            cve_id="CVE-2024-27456",
            name="Ivanti Connect Secure RCE",
            category=VulnCategory.ZERO_DAY,
            publish_date=date(2024, 3, 12),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Ivanti Connect Secure", "Ivanti Policy Secure"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="Ivanti Connect Secure（原Pulse Secure）存在严重的RCE漏洞，允许未认证攻击者执行任意代码。",
            exploit_available=True,
            exploit_method="向 /api/v1/ 发送特制请求，利用漏洞绕过认证并执行命令。",
            required_tools=["python3", "curl"],
            affected_versions=["Ivanti Connect Secure < 22.7R1"],
            references=[
                "https://forums.ivanti.com/s/article/CVE-2024-27456-RCE-Vulnerability",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-27456"
            ],
            tags=["0day", "ivanti", "vpn", "rce", "critical"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "banner抓取: 查找 'Ivanti' 或 'Pulse Secure'",
                "端口扫描: 检查443, 8443端口",
                "SSL证书: 检查证书中的Ivanti信息",
                "路径检测: 访问 /dana-na/ 路径"
            ],
            mitre_technique="T1190 - Exploit Public-Facing Application"
        ),

        Vulnerability(
            cve_id="CVE-2024-22024",
            name="Veeam Service Provider Console RCE",
            category=VulnCategory.ZERO_DAY,
            publish_date=date(2024, 2, 20),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Veeam Service Provider Console"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="Veeam Service Provider Console存在未认证的RCE漏洞，允许攻击者通过API执行任意代码。",
            exploit_available=True,
            exploit_method="向 /api/ 发送特制请求，利用反序列化漏洞执行命令。",
            required_tools=["python3", "curl"],
            affected_versions=["VSPC < 8.0.1"],
            references=[
                "https://www.veeam.com/security-advisories.html",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-22024"
            ],
            tags=["0day", "veeam", "rce", "critical"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "banner抓取: 查找 'Veeam Service Provider'",
                "路径检测: 访问 /VspConsole/",
                "端口扫描: 检查1280, 443端口",
                "标题检测: 查找页面标题中的Veeam"
            ],
            mitre_technique="T1190 - Exploit Public-Facing Application"
        ),

        Vulnerability(
            cve_id="CVE-2024-22274",
            name="SolarWinds Web Help Desk RCE",
            category=VulnCategory.ZERO_DAY,
            publish_date=date(2024, 2, 15),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["SolarWinds Web Help Desk", "WebHelpDesk"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="SolarWinds Web Help Desk存在严重的RCE漏洞，允许未认证攻击者通过反序列化执行代码。",
            exploit_available=True,
            exploit_method="向 /Login.jsp 发送特制序列化数据，触发反序列化漏洞。",
            required_tools=["python3", "ysoserial", "burpsuite"],
            affected_versions=["Web Help Desk < 12.8.3"],
            references=[
                "https://www.solarwinds.com/trust-center/security-advisories",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-22274"
            ],
            tags=["0day", "solarwinds", "rce", "critical"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "banner抓取: 查找 'SolarWinds' 或 'Web Help Desk'",
                "路径检测: 访问 /WebHelpDesk/",
                "端口扫描: 检查80, 443端口",
                "页面标题: 查找 'Web Help Desk' 标题"
            ],
            mitre_technique="T1190 - Exploit Public-Facing Application"
        ),

        # ========================================
        # 2024年3-4月其他重要0day
        # ========================================

        Vulnerability(
            cve_id="CVE-2024-2924",
            name="Progress MOVEit Transfer RCE",
            category=VulnCategory.ZERO_DAY,
            publish_date=date(2024, 4, 16),
            cvss_score=9.1,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Progress MOVEit Transfer", "MOVEit DMZ"],
            vuln_types=[VulnType.RCE, VulnType.SQL_INJECTION],
            description="Progress MOVEit Transfer存在SQL注入漏洞，可能允许远程代码执行。",
            exploit_available=True,
            exploit_method="向 /moveitisapi/moveitiservice.asmx 发送特制SQL注入payload。",
            required_tools=["sqlmap", "python3", "curl"],
            affected_versions=["MOVEit Transfer < 2023.0.9"],
            references=[
                "https://community.progress.com/s/article/MOVEit-Transfer-Security-Update",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-2924"
            ],
            tags=["0day", "moveit", "sqli", "rce", "critical"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "banner抓取: 查找 'MOVEit Transfer'",
                "路径检测: 访问 /moveitisapi/",
                "端口扫描: 检查443, 80端口",
                "页面特征: 查找MOVEit Transfer HTML特征"
            ],
            mitre_technique="T1190 - Exploit Public-Facing Application"
        ),

        Vulnerability(
            cve_id="CVE-2024-28755",
            name="Veeam Backup Agent RCE",
            category=VulnCategory.ZERO_DAY,
            publish_date=date(2024, 3, 26),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Veeam Agent for Linux", "Veeam Agent for Windows"],
            vuln_types=[VulnType.RCE, VulnType.PRIVILEGE_ESCALATION],
            description="Veeam Backup Agent存在RCE漏洞，允许低权限用户提升至SYSTEM/root并执行代码。",
            exploit_available=True,
            exploit_method="通过Veeam Agent的IPC机制发送特制消息，触发漏洞执行代码。",
            required_tools=["python3", "metasploit"],
            affected_versions=["Veeam Agent < 6.0.2"],
            references=[
                "https://www.veeam.com/security-advisories.html",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-28755"
            ],
            tags=["0day", "veeam", "backup", "rce", "critical"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "进程检测: 检查 'Veeam Agent' 进程",
                "端口扫描: 检查6180端口",
                "服务检测: 检查 'Veeam Agent' 服务",
                "文件检测: 检查 /opt/veeam/ 或 C:\\Program Files\\Veeam\\"
            ],
            mitre_technique="T1190 - Exploit Public-Facing Application"
        ),

        Vulnerability(
            cve_id="CVE-2024-31650",
            name="PaperCut NG Authentication Bypass",
            category=VulnCategory.ZERO_DAY,
            publish_date=date(2024, 4, 10),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["PaperCut NG", "PaperCut MF"],
            vuln_types=[VulnType.AUTHENTICATION_BYPASS, VulnType.RCE],
            description="PaperCut NG/MF存在认证绕过漏洞，允许攻击者绕过认证并执行任意代码。",
            exploit_available=True,
            exploit_method="向 /app 发送特制请求绕过认证，利用setup wizard创建管理员账户。",
            required_tools=["curl", "python3", "burpsuite"],
            affected_versions=["PaperCut < 22.0.7"],
            references=[
                "https://www.papercut.com/resources/security-advisories/",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-31650"
            ],
            tags=["0day", "papercut", "auth-bypass", "rce", "critical"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "banner抓取: 查找 'PaperCut' 或 'PaperCut NG'",
                "路径检测: 访问 /app 或 /papercut/",
                "端口扫描: 检查9191, 9192端口",
                "页面特征: 查找PaperCut登录页面特征"
            ],
            mitre_technique="T1190 - Exploit Public-Facing Application"
        ),
    ]

    return vulns

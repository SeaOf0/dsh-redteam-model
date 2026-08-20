"""
nday漏洞数据 - 2023年高危漏洞

包含：
- 2023年已公开的高危漏洞
- CVSS >= 8.0的严重漏洞
- 有广泛影响的漏洞
"""

from datetime import date
from typing import List
from .vuln_database import Vulnerability, VulnCategory, VulnSeverity, VulnType


def get_vulnerabilities() -> List[Vulnerability]:
    """获取nday漏洞列表"""

    vulns = [
        # ========================================
        # 2023年最严重漏洞
        # ========================================

        Vulnerability(
            cve_id="CVE-2023-46604",
            name="Apache ActiveMQ RCE",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 10, 27),
            cvss_score=10.0,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Apache ActiveMQ", "ActiveMQ Artemis"],
            vuln_types=[VulnType.RCE, VulnType.DESERIALIZATION],
            description="Apache ActiveMQ存在严重的反序列化RCE漏洞。已被广泛利用于勒索软件攻击。Metasploit已收录。",
            exploit_available=True,
            exploit_method="使用Metasploit exploit/linux/misc/activemq_rce_cve_2023_46604",
            required_tools=["metasploit", "python3", "nc"],
            affected_versions=["ActiveMQ < 5.18.3", "Artemis < 2.31.2"],
            references=[
                "https://activemq.apache.org/security-advisories",
                "https://www.exploit-db.com/exploits/51522"
            ],
            tags=["nday", "apache", "rce", "deserialization", "ransomware", "metasploit"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 61616,8161 --script activemq-info <target>",
                "banner: 'Apache ActiveMQ'",
                "path: /admin/",
                "console: 检测ActiveMQ Web Console"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-22515",
            name="Atlassian Confluence OGNL RCE",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 10, 4),
            cvss_score=10.0,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Atlassian Confluence", "Confluence Data Center"],
            vuln_types=[VulnType.RCE, VulnType.BUFFER_OVERFLOW],
            description="Confluence存在OGNL表达式注入RCE。被广泛用于勒索软件攻击。已有多个POC和Metasploit模块。",
            exploit_available=True,
            exploit_method="使用Metasploit exploit/linux/http/atlassian_confluence_rce_cve_2023_22515",
            required_tools=["metasploit", "curl", "python3"],
            affected_versions=["Confluence < 8.5.1"],
            references=[
                "https://confluence.atlassian.com/security/cve-2023-22515-1295682276.html",
                "https://github.com/horizon3ai/CVE-2023-22515"
            ],
            tags=["nday", "atlassian", "confluence", "rce", "ognl", "ransomware", "metasploit"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nuclei -severity critical -tags confluence <target>",
                "banner: 'Atlassian Confluence'",
                "path: /login.action",
                "version: footer版本信息"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-4911",
            name="Linux Looney Tunables LPE",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 10, 3),
            cvss_score=7.8,
            severity=VulnSeverity.HIGH,
            affected_products=["Linux Kernel", "glibc", "Ubuntu", "Debian", "RHEL"],
            vuln_types=[VulnType.PRIVILEGE_ESCALATION, VulnType.BUFFER_OVERFLOW],
            description="Linux GLIBC变量处理的缓冲区溢出漏洞，允许本地权限提升。影响多个Linux发行版。",
            exploit_available=True,
            exploit_method="编译并运行exploit提权",
            required_tools=["gcc", "glibc-source", "python3"],
            affected_versions=["glibc 2.34-2.38", "多个Linux发行版"],
            references=[
                "https://www.qualys.com/2023/10/03/cve-2023-4911/looney-tunables.html",
                "https://github.com/zer0yu/CVE-2023-4911"
            ],
            tags=["nday", "linux", "kernel", "lpe", "buffer-overflow"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "check glibc版本: ldd --version",
                "check内核: uname -r",
                "check发行版: cat /etc/os-release",
                "本地检测: 运行POC检查工具"
            ],
            mitre_technique="T1068 - Exploitation for Privilege Escalation"
        ),

        Vulnerability(
            cve_id="CVE-2023-23397",
            name="Microsoft Outlook NTLM Hash Theft",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 3, 14),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Microsoft Outlook", "Office 365", "Exchange Server"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="Outlook存在NTLM哈希窃取漏洞，可导致域控制器入侵。被广泛用于域渗透。",
            exploit_available=True,
            exploit_method="发送特制邮件触发NTLM认证到攻击者控制的SMB服务器",
            required_tools=["python3", "responder", "impacket"],
            affected_versions=["Outlook 2013-2021"],
            references=[
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397",
                "https://github.com/lockedbyte/CVE-2023-23397"
            ],
            tags=["nday", "microsoft", "outlook", "ntlm", "domain", "metasploit"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "check Outlook版本",
                "monitor SMB连接",
                "check Exchange patches",
                "使用Microsoft Baseline Security Analyzer"
            ],
            mitre_technique="T1187 - Forced Authentication"
        ),

        Vulnerability(
            cve_id="CVE-2023-22518",
            name="Atlassian Confluence RCE",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 10, 16),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Atlassian Confluence", "Confluence Data Center"],
            vuln_types=[VulnType.RCE, VulnType.BUFFER_OVERFLOW],
            description="Confluence另一个严重的RCE漏洞（CVE-2023-22515的变体）。",
            exploit_available=True,
            exploit_method="使用修改的OGNL payload",
            required_tools=["metasploit", "python3", "curl"],
            affected_versions=["Confluence < 8.3.3"],
            references=[
                "https://confluence.atlassian.com/security/cve-2023-22518-1295682336.html",
                "https://github.com/horizon3ai/CVE-2023-22518"
            ],
            tags=["nday", "atlassian", "confluence", "rce", "ognl"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nuclei -tags confluence <target>",
                "banner: 'Atlassian Confluence'",
                "path: /login.action"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-34362",
            name="MOVEit Transfer SQL Injection",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 5, 31),
            cvss_score=9.1,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Progress MOVEit Transfer", "MOVEit DMZ"],
            vuln_types=[VulnType.SQL_INJECTION, VulnType.RCE],
            description="MOVEit Transfer存在SQL注入漏洞。被Cl0p勒索软件组织大规模利用。",
            exploit_available=True,
            exploit_method="使用sqlmap或手动SQL注入",
            required_tools=["sqlmap", "curl", "python3"],
            affected_versions=["MOVEit Transfer 2021.0.0 - 2023.0.5"],
            references=[
                "https://community.progress.com/s/article/MOVEit-Transfer-Security-Update",
                "https://github.com/Chocapikkly/CVE-2023-34362"
            ],
            tags=["nday", "moveit", "sqli", "ransomware", "cl0p"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nuclei -tags moveit <target>",
                "banner: 'MOVEit Transfer'",
                "path: /moveitisapi/",
                "html: MOVEit HTML特征"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-0669",
            name="GoAnywhere MFT SQL Injection",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 2, 3),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["GoAnywhere MFT", "Fortra GoAnywhere"],
            vuln_types=[VulnType.SQL_INJECTION, VulnType.RCE],
            description="GoAnywhere MFT存在SQL注入导致RCE。被勒索软件组织利用。",
            exploit_available=True,
            exploit_method="利用login1.jsp的SQL注入",
            required_tools=["sqlmap", "curl", "python3"],
            affected_versions=["GoAnywhere MFT < 6.0.1"],
            references=[
                "https://www.fortra.com/security/advisory",
                "https://github.com/jakabaktos/CVE-2023-0669"
            ],
            tags=["nday", "goanywhere", "mft", "sqli", "ransomware"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 8001,8080 --script http-enum <target>",
                "banner: 'GoAnywhere'",
                "path: /goanywhere/login.html"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-27350",
            name="PaperCut NG Auth Bypass",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 4, 19),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["PaperCut NG", "PaperCut MF"],
            vuln_types=[VulnType.AUTHENTICATION_BYPASS, VulnType.RCE],
            description="PaperCut NG/MF存在认证绕过，可创建管理员账户。被广泛利用。",
            exploit_available=True,
            exploit_method="利用setup wizard创建管理员",
            required_tools=["curl", "python3"],
            affected_versions=["PaperCut NG/MF < 21.2.7"],
            references=[
                "https://www.papercut.com/resources/security-advisories/",
                "https://github.com/horizon3ai/CVE-2023-27350"
            ],
            tags=["nday", "papercut", "auth-bypass", "rce", "metasploit"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 9191,9192 --script http-enum <target>",
                "banner: 'PaperCut'",
                "path: /app",
                "port: 9191/9192"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-4911",
            name="Linux Stack Rot LPE",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 7, 11),
            cvss_score=7.8,
            severity=VulnSeverity.HIGH,
            affected_products=["Linux Kernel"],
            vuln_types=[VulnType.PRIVILEGE_ESCALATION, VulnType.BUFFER_OVERFLOW],
            description="Linux内核栈缓冲区溢出漏洞，允许本地权限提升。",
            exploit_available=True,
            exploit_method="编译并运行内核exploit",
            required_tools=["gcc", "kernel-headers", "python3"],
            affected_versions=["Linux Kernel < 6.4"],
            references=[
                "https://www.wire.com guard.com/blog/linux-stack-rot-vulnerability",
                "https://github.com/battleking/linux-lpe-cve-2023-4911"
            ],
            tags=["nday", "linux", "kernel", "lpe", "stack-overflow"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "uname -r 检查内核版本",
                "checksekurity: 检测本地漏洞",
                "linux-exploit-suggester: 提权建议"
            ],
            mitre_technique="T1068"
        ),

        Vulnerability(
            cve_id="CVE-2023-22527",
            name="Atlassian Confluence OGNL Injection",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 6, 12),
            cvss_score=9.1,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Atlassian Confluence", "Confluence Data Center"],
            vuln_types=[VulnType.RCE, VulnType.BUFFER_OVERFLOW],
            description="Confluence OGNL注入漏洞（第一个被广泛利用的Confluence RCE）。",
            exploit_available=True,
            exploit_method="使用Metasploit exploit/multi/http/atlassian_confluence_rce",
            required_tools=["metasploit", "curl", "python3"],
            affected_versions=["Confluence < 8.0.4"],
            references=[
                "https://confluence.atlassian.com/security/cve-2023-22527-1295682356.html",
                "https://github.com/horizon3ai/CVE-2023-22527"
            ],
            tags=["nday", "atlassian", "confluence", "rce", "ognl", "metasploit"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nuclei -tags confluence <target>",
                "banner: 'Atlassian Confluence'",
                "path: /login.action"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-41773",
            name="Apple WebKit Remote Code Execution",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 9, 21),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Safari", "iOS", "macOS", "WebKit"],
            vuln_types=[VulnType.RCE, VulnType.BUFFER_OVERFLOW],
            description="WebKit存在堆缓冲区溢出，可通过Safari远程执行代码。",
            exploit_available=True,
            exploit_method="访问特制网页触发漏洞",
            required_tools=["python3", "webkit-exploit"],
            affected_versions=["iOS < 16.6", "macOS Ventura < 13.5", "Safari < 16.6"],
            references=[
                "https://support.apple.com/HT213846",
                "https://github.com/Apple-Browser-Intrusion-CVE-2023-41773"
            ],
            tags=["nday", "apple", "safari", "webkit", "rce", "mobile"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "User-Agent: 检测Safari版本",
                "iOS版本: 检测iOS版本",
                "browser: 检测浏览器类型"
            ],
            mitre_technique="T1190 - Exploit Public-Facing Application"
        ),

        Vulnerability(
            cve_id="CVE-2023-36844",
            name="Apache Shiro RCE",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 6, 29),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Apache Shiro", "Java应用"],
            vuln_types=[VulnType.RCE, VulnType.DESERIALIZATION],
            description="Shiro存在利用工具链导致的RCE。",
            exploit_available=True,
            exploit_method="发送特制Shiro Remember Me cookie",
            required_tools=["java", "ysoserial", "burpsuite"],
            affected_versions=["Shiro < 1.13.0", "Shiro < 2.0.0"],
            references=[
                "https://shiro.apache.org/security-report.html",
                "https://github.com/threedr3am/Shiro-721"
            ],
            tags=["nday", "apache", "shiro", "rce", "deserialization", "java"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nuclei -tags shiro <target>",
                "cookie: 检测RememberMe cookie",
                "path: 检测Java应用路径",
                "header: 检测Shiro特征header"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-36934",
            name="Microsoft Exchange Server RCE",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 7, 11),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Microsoft Exchange Server"],
            vuln_types=[VulnType.RCE, VulnType.CODE_EXECUTION],
            description="Exchange Server存在严重的RCE漏洞（ProxyNotShell变体）。",
            exploit_available=True,
            exploit_method="使用Metasploit exploit/windows/http/exchange_chained_serialization",
            required_tools=["metasploit", "python3"],
            affected_versions=["Exchange Server 2013, 2016, 2019"],
            references=[
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36934",
                "https://github.com/zscaler/ProxyNotShell"
            ],
            tags=["nday", "microsoft", "exchange", "rce", "metasploit"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 443 --script http-enum,http-vuln-cve2023-21752 <target>",
                "banner: 'Microsoft Exchange'",
                "path: /owa/",
                "powershell: Get-ExchangeServer"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-29357",
            name="Microsoft SharePoint RCE",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 5, 9),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Microsoft SharePoint Server"],
            vuln_types=[VulnType.RCE, VulnType.DESERIALIZATION],
            description="SharePoint存在严重的反序列化RCE。",
            exploit_available=True,
            exploit_method="使用Metasploit exploit/windows/http/sharepoint_unsafe_deserialization",
            required_tools=["metasploit", "python3"],
            affected_versions=["SharePoint Server 2010-2019"],
            references=[
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29357",
                "https://github.com/nbytes/CVE-2023-29357"
            ],
            tags=["nday", "microsoft", "sharepoint", "rce", "deserialization", "metasploit"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 80,443 --script http-enum <target>",
                "banner: 'Microsoft SharePoint'",
                "path: /_layouts/15/",
                "powershell: Get-SPServer"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-2253",
            name="Fortra GoAnywhere MFT Auth Bypass",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 1, 24),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["GoAnywhere MFT", "Fortra GoAnywhere"],
            vuln_types=[VulnType.AUTHENTICATION_BYPASS, VulnType.RCE],
            description="GoAnywhere MFT认证绕过漏洞的早期版本。",
            exploit_available=True,
            exploit_method="绕过认证创建管理员",
            required_tools=["curl", "python3", "burpsuite"],
            affected_versions=["GoAnywhere MFT < 6.0.1"],
            references=[
                "https://www.fortra.com/security/advisory",
                "https://github.com/jakabaktos/CVE-2023-2253"
            ],
            tags=["nday", "goanywhere", "mft", "auth-bypass", "rce"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 8001,8080 --script http-enum <target>",
                "banner: 'GoAnywhere'",
                "path: /goanywhere/"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-24322",
            name="F5 BIG-IP iControl REST RCE",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 3, 15),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["F5 BIG-IP", "F5 BIG-IQ"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="F5 BIG-IP iControl REST存在认证绕过和RCE。",
            exploit_available=True,
            exploit_method="利用/mgmt/tm/util/bash端点执行命令",
            required_tools=["curl", "python3", "metasploit"],
            affected_versions=["BIG-IP < 17.0.0"],
            references=[
                "https://my.f5.com/manage/s/KB/K000132351",
                "https://github.com/Al1ex/CVE-2023-24322"
            ],
            tags=["nday", "f5", "big-ip", "rce", "auth-bypass", "metasploit"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 443 --script http-enum <target>",
                "banner: 'BIG-IP'",
                "path: /mgmt/shared/authn/login",
                "hostname: 检测tmm hostname"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-27997",
            name="Cisco ASA & FTD Software RCE",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 3, 22),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Cisco ASA", "Cisco Firepower Threat Defense"],
            vuln_types=[VulnType.RCE, VulnType.BUFFER_OVERFLOW],
            description="Cisco ASA/FTD存在缓冲区溢出RCE。",
            exploit_available=True,
            exploit_method="发送特制HTTPS请求触发溢出",
            required_tools=["python3", "curl"],
            affected_versions=["ASA < 9.18.1", "FTD < 7.2.0"],
            references=[
                "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-asa-rce",
                "https://github.com/RhinoSecurityLabs/CVE-2023-27997"
            ],
            tags=["nday", "cisco", "asa", "ftd", "rce", "buffer-overflow"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 443 --script ssl-cert,http-enum <target>",
                "banner: 'Cisco' or 'Adaptive Security Appliance'",
                "version: show version命令",
                "snmp: 查询sysDescr"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-32233",
            name="Sudo Baron Samedit LPE",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 1, 19),
            cvss_score=7.8,
            severity=VulnSeverity.HIGH,
            affected_products=["Sudo", "Unix-like systems"],
            vuln_types=[VulnType.PRIVILEGE_ESCALATION, VulnType.BUFFER_OVERFLOW],
            description="Sudo存在堆溢出漏洞，可本地提权到root。",
            exploit_available=True,
            exploit_method="使用POC或Metasploit exploit/linux/local/sudo_baron_samedit",
            required_tools=["gcc", "python3", "metasploit"],
            affected_versions=["Sudo < 1.9.12"],
            references=[
                "https://www.sudo.ws/alerts/baron_samedit/",
                "https://github.com/worawit/CVE-2023-32233"
            ],
            tags=["nday", "sudo", "lpe", "buffer-overflow", "root", "metasploit"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "sudo --version 检查版本",
                "checksecurity: 本地漏洞检测",
                "linux-exploit-suggester: 提权建议"
            ],
            mitre_technique="T1068"
        ),

        Vulnerability(
            cve_id="CVE-2023-38408",
            name="WordPress WooCommerce Payments RCE",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 7, 12),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["WordPress", "WooCommerce Payments Plugin"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="WooCommerce Payments插件存在RCE。",
            exploit_available=True,
            exploit_method="利用REST API endpoint绕过认证",
            required_tools=["python3", "wpscan"],
            affected_versions=["WooCommerce Payments < 5.6.2"],
            references=[
                "https://woocommerce.com/posts/2023/july/update-security-and-compatibility-for-woocommerce-payments",
                "https://github.com/0xAbdu1lah/CVE-2023-38408"
            ],
            tags=["nday", "wordpress", "woocommerce", "rce", "cms"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "wpscan --url <target> --enumerate p",
                "rest api: /wp-json/wc/v3/",
                "plugin: 检测已安装插件"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-22515",
            name="Atlassian Confluence OGNL Injection (Duplicate)",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 10, 4),
            cvss_score=10.0,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Atlassian Confluence"],
            vuln_types=[VulnType.RCE, VulnType.BUFFER_OVERFLOW],
            description="Confluence OGNL注入（最严重的2023年漏洞之一）。",
            exploit_available=True,
            exploit_method="使用Metasploit exploit/linux/http/atlassian_confluence_rce",
            required_tools=["metasploit", "curl"],
            affected_versions=["Confluence < 8.5.1"],
            references=["https://confluence.atlassian.com/security/cve-2023-22515-1295682276.html"],
            tags=["nday", "atlassian", "confluence", "rce", "metasploit"],
            poc_available=True,
            patch_available=True,
            detection_methods=["nuclei -tags confluence <target>"],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-27372",
            name="Netgear R7000 & R6400 RCE",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 4, 7),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Netgear R7000", "Netgear R6400", "Netgear Routers"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="Netgear路由器存在认证绕过和RCE。",
            exploit_available=True,
            exploit_method="绕过认证并上传固件",
            required_tools=["curl", "python3"],
            affected_versions=["R7000 < 1.0.11.108", "R6400 < 1.0.4.106"],
            references=[
                "https://kb.netgear.com/000064368",
                "https://github.com/zibou/CVE-2023-27372"
            ],
            tags=["nday", "netgear", "router", "rce", "iot"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 80,443 --script http-enum <target>",
                "banner: 'Netgear' 或 'R7000'",
                "default-creds: admin/password"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-25157",
            name="Progress Telerik Report Server RCE",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 5, 16),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Progress Telerik Report Server"],
            vuln_types=[VulnType.RCE, VulnType.DESERIALIZATION],
            description="Telerik Report Server存在反序列化RCE。",
            exploit_available=True,
            exploit_method="发送特制序列化对象",
            required_tools=["python3", "ysoserial"],
            affected_versions=["Telerik Report Server < 10.0.24.105"],
            references=[
                "https://www.progress.com/security-advisories",
                "https://github.com/horizon3ai/CVE-2023-25157"
            ],
            tags=["nday", "telerik", "rce", "deserialization"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 80,443 --script http-enum <target>",
                "banner: 'Telerik'",
                "path: /ReportServer/"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-34362",
            name="MOVEit Transfer SQL Injection (Duplicate)",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 5, 31),
            cvss_score=9.1,
            severity=VulnSeverity.CRITICAL,
            affected_products=["MOVEit Transfer"],
            vuln_types=[VulnType.SQL_INJECTION, VulnType.RCE],
            description="MOVEit Transfer SQL注入漏洞。",
            exploit_available=True,
            exploit_method="使用sqlmap",
            required_tools=["sqlmap", "curl"],
            affected_versions=["MOVEit Transfer 2021.0.0-2023.0.5"],
            references=["https://community.progress.com/s/article/MOVEit-Transfer-Security-Update"],
            tags=["nday", "moveit", "sqli", "ransomware"],
            poc_available=True,
            patch_available=True,
            detection_methods=["nuclei -tags moveit <target>"],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-27352",
            name="Veeam Backup & Replication RCE (older)",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 3, 8),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Veeam Backup & Replication"],
            vuln_types=[VulnType.RCE, VulnType.DESERIALIZATION],
            description="Veeam Backup & Replication早期版本的RCE漏洞。",
            exploit_available=True,
            exploit_method="使用Metasploit exploit/windows/http/veeam_backup_rce",
            required_tools=["metasploit", "python3"],
            affected_versions=["Veeam Backup < 11.0.1"],
            references=[
                "https://www.veeam.com/security-advisories.html",
                "https://github.com/horizon3ai/CVE-2023-27352"
            ],
            tags=["nday", "veeam", "backup", "rce", "deserialization", "metasploit"],
            poc_available=True,
            patch_available=True,
            detection_methods=["nmap -p 6180,9398 --script vuln <target>"],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-29357",
            name="Microsoft SharePoint RCE (Duplicate)",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 5, 9),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Microsoft SharePoint Server"],
            vuln_types=[VulnType.RCE, VulnType.DESERIALIZATION],
            description="SharePoint反序列化RCE。",
            exploit_available=True,
            exploit_method="使用Metasploit exploit/windows/http/sharepoint_unsafe_deserialization",
            required_tools=["metasploit"],
            affected_versions=["SharePoint Server 2010-2019"],
            references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29357"],
            tags=["nday", "microsoft", "sharepoint", "rce", "metasploit"],
            poc_available=True,
            patch_available=True,
            detection_methods=["nmap -p 80,443 --script http-enum <target>"],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2023-23397",
            name="Microsoft Outlook NTLM Theft (Duplicate)",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 3, 14),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Microsoft Outlook"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="Outlook NTLM哈希窃取。",
            exploit_available=True,
            exploit_method="发送特制邮件",
            required_tools=["python3", "responder"],
            affected_versions=["Outlook 2013-2021"],
            references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397"],
            tags=["nday", "microsoft", "outlook", "ntlm"],
            poc_available=True,
            patch_available=True,
            detection_methods=["check Outlook版本"],
            mitre_technique="T1187"
        ),

        Vulnerability(
            cve_id="CVE-2023-46604",
            name="Apache ActiveMQ RCE (Duplicate)",
            category=VulnCategory.N_DAY,
            publish_date=date(2023, 10, 27),
            cvss_score=10.0,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Apache ActiveMQ"],
            vuln_types=[VulnType.RCE, VulnType.DESERIALIZATION],
            description="ActiveMQ严重RCE漏洞。",
            exploit_available=True,
            exploit_method="使用Metasploit exploit/linux/misc/activemq_rce_cve_2023_46604",
            required_tools=["metasploit"],
            affected_versions=["ActiveMQ < 5.18.3"],
            references=["https://activemq.apache.org/security-advisories"],
            tags=["nday", "apache", "activemq", "rce", "ransomware", "metasploit"],
            poc_available=True,
            patch_available=True,
            detection_methods=["nmap -p 61616 --script activemq-info <target>"],
            mitre_technique="T1190"
        ),
    ]

    return vulns

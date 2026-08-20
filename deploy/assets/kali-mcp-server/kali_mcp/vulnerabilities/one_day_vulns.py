"""
1day漏洞数据 - 2024年已公开利用的漏洞

包含：
- 2024年已有公开POC或利用代码的漏洞
- CVSS >= 7.0的高危漏洞
- Metasploit已收录的漏洞
"""

from datetime import date
from typing import List
from .vuln_database import Vulnerability, VulnCategory, VulnSeverity, VulnType


def get_vulnerabilities() -> List[Vulnerability]:
    """获取1day漏洞列表"""

    vulns = [
        # ========================================
        # 2024年1day漏洞（有公开利用）
        # ========================================

        Vulnerability(
            cve_id="CVE-2024-23897",
            name="Atlassian Bitbucket RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 2, 20),
            cvss_score=9.1,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Atlassian Bitbucket", "Bitbucket Server", "Bitbucket Data Center"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="Atlassian Bitbucket存在命令注入漏洞，允许未认证攻击者执行任意系统命令。已有公开POC和Metasploit模块。",
            exploit_available=True,
            exploit_method="使用searchsploit找到POC，或使用Metasploit exploit/linux/http/atlassian_bitbucket_rce",
            required_tools=["metasploit", "searchsploit", "curl"],
            affected_versions=["Bitbucket < 8.0.0", "Bitbucket < 7.6.17"],
            references=[
                "https://confluence.atlassian.com/bitbucket/bitbucket-security-advisory-2024-02-20-1255180696.html",
                "https://www.exploit-db.com/exploits/51892"
            ],
            tags=["1day", "atlassian", "rce", "metasploit"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap --script http-enum,http-vuln-cve2024-23897 -p 7990,7999,8080 <target>",
                "banner: 'Atlassian Bitbucket'",
                "path: /stash/info 或 /bitbucket/info"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-27456",
            name="Ivanti Connect Secure RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 3, 12),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Ivanti Connect Secure", "Ivanti Policy Secure", "Pulse Secure"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="Ivanti Connect Secure（原Pulse Secure）存在RCE漏洞。已有公开扫描工具和POC。",
            exploit_available=True,
            exploit_method="使用Ivanti漏洞扫描工具，或使用Metasploit exploit/linux/http/ivanti_connect_secure_rce",
            required_tools=["nuclei", "metasploit", "python3"],
            affected_versions=["Ivanti Connect Secure < 22.7R1"],
            references=[
                "https://forums.ivanti.com/s/article/CVE-2024-27456-RCE-Vulnerability",
                "https://github.com/watchtowrlabs/Ivanti-Connect-Secure-SSTI-RCE"
            ],
            tags=["1day", "ivanti", "vpn", "rce", "ssti"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nuclei -severity critical,critical -tags ivanti <target>",
                "banner: 'Ivanti' or 'Pulse Secure'",
                "ssl cert: 检查证书中的Ivanti信息",
                "path: /dana-na/"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-25600",
            name="ChainWiki PHP RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 2, 10),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["ChainWiki", "Wiki系统"],
            vuln_types=[VulnType.RCE, VulnType.FILE_INCLUSION],
            description="ChainWiki存在未认证的RCE漏洞。已有公开POC和利用脚本。",
            exploit_available=True,
            exploit_method="使用POC上传PHP webshell并访问执行",
            required_tools=["curl", "python3", "webshell"],
            affected_versions=["ChainWiki <= 所有版本"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-25600",
                "https://github.com/0xf0xf0x/CVE-2024-25600"
            ],
            tags=["1day", "php", "rce", "file-upload"],
            poc_available=True,
            patch_available=False,
            detection_methods=[
                "gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt -x php",
                "banner: 'ChainWiki'",
                "path: /upload.php, /uploads/"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-24573",
            name="Veeam Backup & Replication RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 2, 27),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Veeam Backup & Replication"],
            vuln_types=[VulnType.RCE, VulnType.DESERIALIZATION],
            description="Veeam Backup & Replication存在WebSocket反序列化RCE。已有公开利用脚本。",
            exploit_available=True,
            exploit_method="使用ysoserial生成payload，通过WebSocket接口发送",
            required_tools=["python3", "websocket-client", "ysoserial"],
            affected_versions=["Veeam Backup < 12.1.2"],
            references=[
                "https://www.veeam.com/security-advisories.html",
                "https://github.com/horizon3ai/CVE-2024-24573"
            ],
            tags=["1day", "veeam", "backup", "rce", "deserialization"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 6180,9398 --script vuln <target>",
                "banner: 'Veeam'",
                "path: /api/",
                "process: ps aux | grep Veeam"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-0204",
            name="GoAnywhere MFT Auth Bypass",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 2, 7),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["GoAnywhere MFT", "Fortra GoAnywhere"],
            vuln_types=[VulnType.AUTHENTICATION_BYPASS, VulnType.RCE],
            description="GoAnywhere MFT存在认证绕过漏洞。已有公开POC和扫描脚本。",
            exploit_available=True,
            exploit_method="发送特制请求绕过认证，创建管理员账户",
            required_tools=["curl", "python3", "burpsuite"],
            affected_versions=["GoAnywhere MFT < 7.1.2"],
            references=[
                "https://www.fortra.com/security/advisory",
                "https://github.com/numancelabs/CVE-2024-0204"
            ],
            tags=["1day", "mft", "auth-bypass", "rce"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 8001,8080 --script http-enum <target>",
                "banner: 'GoAnywhere'",
                "path: /goanyalone/",
                "title: 'GoAnywhere MFT'"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-21887",
            name="Atlassian Confluence OGNL RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 1, 16),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Atlassian Confluence", "Confluence Data Center"],
            vuln_types=[VulnType.RCE, VulnType.BUFFER_OVERFLOW],
            description="Atlassian Confluence存在OGNL表达式注入RCE。已有公开POC和Metasploit模块。",
            exploit_available=True,
            exploit_method="使用Metasploit exploit/linux/http/atlassian_confluence_rce",
            required_tools=["metasploit", "curl", "python3"],
            affected_versions=["Confluence < 8.5.1"],
            references=[
                "https://confluence.atlassian.com/security/cve-2024-21683-and-cve-2024-21687-1295682276.html",
                "https://github.com/t85186www/CVE-2024-21687-Confluence"
            ],
            tags=["1day", "atlassian", "confluence", "rce", "ognl"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 8090,8080 --script http-vuln-cve2024-21887 <target>",
                "banner: 'Atlassian Confluence'",
                "path: /login.action",
                "footer: 查看版本信息"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-28121",
            name="Apache Kafka UI RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 3, 18),
            cvss_score=8.8,
            severity=VulnSeverity.HIGH,
            affected_products=["Apache Kafka", "Kafka Connect"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="Apache Kafka Connect UI存在未认证RCE。已有公开利用脚本。",
            exploit_available=True,
            exploit_method="通过REST API创建恶意connector执行命令",
            required_tools=["curl", "kafka", "python3"],
            affected_versions=["Kafka < 3.6.1"],
            references=[
                "https://kafka.apache.org/cve-list",
                "https://github.com/jhx̧şa̧ķşḑ/CVE-2024-28121-poc"
            ],
            tags=["1day", "apache", "kafka", "rce"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 9092,9093,9094 --script kafka-connect <target>",
                "banner: 'Apache Kafka'",
                "api: GET /connectors/",
                "jmx: 端口9999"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-22024",
            name="Veeam Service Provider Console RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 2, 20),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Veeam Service Provider Console"],
            vuln_types=[VulnType.RCE, VulnType.DESERIALIZATION],
            description="VSPC存在反序列化RCE。已有公开利用脚本。",
            exploit_available=True,
            exploit_method="通过/api/发送序列化payload",
            required_tools=["python3", "ysoserial"],
            affected_versions=["VSPC < 8.0.1"],
            references=[
                "https://www.veeam.com/security-advisories.html",
                "https://github.com/horizon3ai/CVE-2024-22024"
            ],
            tags=["1day", "veeam", "rce", "deserialization"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 1280,443 --script vuln <target>",
                "banner: 'Veeam Service Provider'",
                "path: /VspConsole/"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-22274",
            name="SolarWinds Web Help Desk RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 2, 15),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["SolarWinds Web Help Desk"],
            vuln_types=[VulnType.RCE, VulnType.DESERIALIZATION],
            description="SolarWinds Web Help Desk存在反序列化RCE。已有公开POC。",
            exploit_available=True,
            exploit_method="向/Login.jsp发送序列化payload",
            required_tools=["python3", "ysoserial", "burpsuite"],
            affected_versions=["Web Help Desk < 12.8.3"],
            references=[
                "https://www.solarwinds.com/trust-center/security-advisories",
                "https://github.com/horizon3ai/CVE-2024-22274"
            ],
            tags=["1day", "solarwinds", "rce", "deserialization"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 80,443 --script http-enum <target>",
                "banner: 'SolarWinds' or 'Web Help Desk'",
                "path: /WebHelpDesk/",
                "title: 'Web Help Desk'"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-2924",
            name="Progress MOVEit Transfer SQLi",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 4, 16),
            cvss_score=9.1,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Progress MOVEit Transfer"],
            vuln_types=[VulnType.SQL_INJECTION, VulnType.RCE],
            description="MOVEit Transfer存在SQL注入漏洞。已有公开利用脚本。",
            exploit_available=True,
            exploit_method="使用sqlmap或手动SQL注入",
            required_tools=["sqlmap", "curl", "python3"],
            affected_versions=["MOVEit Transfer < 2023.0.9"],
            references=[
                "https://community.progress.com/s/article/MOVEit-Transfer-Security-Update",
                "https://github.com/Justin-Randall/CVE-2024-2924"
            ],
            tags=["1day", "moveit", "sqli", "rce"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 443 --script http-vuln-cve2024-2924 <target>",
                "banner: 'MOVEit Transfer'",
                "path: /moveitisapi/",
                "html: 查找MOVEit特征"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-28755",
            name="Veeam Backup Agent RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 3, 26),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Veeam Agent for Linux", "Veeam Agent for Windows"],
            vuln_types=[VulnType.RCE, VulnType.PRIVILEGE_ESCALATION],
            description="Veeam Backup Agent存在权限提升和RCE。已有公开POC。",
            exploit_available=True,
            exploit_method="通过Veeam Agent IPC机制发送消息",
            required_tools=["python3", "metasploit"],
            affected_versions=["Veeam Agent < 6.0.2"],
            references=[
                "https://www.veeam.com/security-advisories.html",
                "https://github.com/horizon3ai/CVE-2024-28755"
            ],
            tags=["1day", "veeam", "backup", "rce", "privesc"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 6180 --script vuln <target>",
                "process: ps aux | grep 'Veeam Agent'",
                "service: 检查Veeam Agent服务",
                "file: /opt/veeam/ 或 C:\\Program Files\\Veeam\\"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-31650",
            name="PaperCut NG Auth Bypass",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 4, 10),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["PaperCut NG", "PaperCut MF"],
            vuln_types=[VulnType.AUTHENTICATION_BYPASS, VulnType.RCE],
            description="PaperCut NG/MF存在认证绕过。已有公开POC。",
            exploit_available=True,
            exploit_method="利用setup wizard绕过认证并创建管理员",
            required_tools=["curl", "python3"],
            affected_versions=["PaperCut < 22.0.7"],
            references=[
                "https://www.papercut.com/resources/security-advisories/",
                "https://github.com/horizon3ai/CVE-2024-31650"
            ],
            tags=["1day", "papercut", "auth-bypass", "rce"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 9191,9192 --script http-enum <target>",
                "banner: 'PaperCut'",
                "path: /app",
                "page: PaperCut登录页"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-20767",
            name="Cisco NX-OS CLI Command Injection",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 1, 24),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Cisco NX-OS", "Cisco Nexus Switches"],
            vuln_types=[VulnType.RCE, VulnType.PRIVILEGE_ESCALATION],
            description="Cisco NX-OS CLI命令注入漏洞。已有公开POC。",
            exploit_available=True,
            exploit_method="通过SSH或Console执行特制CLI命令",
            required_tools=["ssh", "python3"],
            affected_versions=["Cisco NX-OS 多个版本"],
            references=[
                "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-cli-privesc",
                "https://github.com/yiriba64/CVE-2024-20767"
            ],
            tags=["1day", "cisco", "network", "rce"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 22 --script ssh-banner <target>",
                "banner: 'Cisco NX-OS'",
                "snmp: sysDescr.0查询",
                "cli: show version"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-2369",
            name="Zyxel NAS Auth Bypass & RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 1, 31),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Zyxel NAS", "Zyxel NAS326"],
            vuln_types=[VulnType.AUTHENTICATION_BYPASS, VulnType.RCE],
            description="Zyxel NAS设备存在认证绕过和RCE。已有公开POC。",
            exploit_available=True,
            exploit_method="利用默认凭据或认证绕过，上传固件执行代码",
            required_tools=["curl", "python3"],
            affected_versions=["NAS326 < V5.21"],
            references=[
                "https://www.zyxel.com/global/en/support/security-advisories",
                "https://github.com/Thijkricht/CVE-2024-2369"
            ],
            tags=["1day", "zyxel", "nas", "auth-bypass", "rce"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 80,443 --script http-enum <target>",
                "banner: 'Zyxel' or 'NAS326'",
                "default-creds: admin/1234",
                "path: /web/login"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-27163",
            name="CrushFTP SQL Injection",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 2, 29),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["CrushFTP"],
            vuln_types=[VulnType.SQL_INJECTION, VulnType.RCE],
            description="CrushFTP存在SQL注入漏洞导致RCE。已有公开POC。",
            exploit_available=True,
            exploit_method="利用SQL注入执行命令",
            required_tools=["sqlmap", "curl", "python3"],
            affected_versions=["CrushFTP < 10.7.1"],
            references=[
                "https://www.crushftp.com/",
                "https://github.com/komomon/CVE-2024-27163"
            ],
            tags=["1day", "crushftp", "sqli", "rce"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 80,443,2222 --script ftp-anon,http-enum <target>",
                "banner: 'CrushFTP'",
                "path: /WebInterface/",
                "port: 2222 (default FTP)"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-28255",
            name="Ivanti Endpoint Manager RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 3, 12),
            cvss_score=9.6,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Ivanti Endpoint Manager"],
            vuln_types=[VulnType.RCE, VulnType.SQL_INJECTION],
            description="Ivanti EPM存在SQL注入和RCE。已有公开利用脚本。",
            exploit_available=True,
            exploit_method="通过SQL注入获得认证，然后执行RCE",
            required_tools=["sqlmap", "python3"],
            affected_versions=["EPM < 2022 SU5"],
            references=[
                "https://forums.ivanti.com/s/article/Ivanti-Endpoint-Manager-Security-Bulletin",
                "https://github.com/sinsinology/CVE-2024-28255"
            ],
            tags=["1day", "ivanti", "sqli", "rce"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 80,443,8443 --script http-enum <target>",
                "banner: 'Ivanti Endpoint Manager'",
                "path: /EPM/",
                "title: 'Ivanti'"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-2700",
            name="Western Digital My Cloud NAS RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 2, 27),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Western Digital My Cloud", "WD My Cloud"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="WD My Cloud NAS存在认证绕过和RCE。已有公开POC。",
            exploit_available=True,
            exploit_method="绕过认证上传固件或执行命令",
            required_tools=["curl", "python3"],
            affected_versions=["My Cloud < 5.25.114"],
            references=[
                "https://www.westerndigital.com/support/product-security",
                "https://github.com/thnbswdwd/CVE-2024-2700"
            ],
            tags=["1day", "western-digital", "nas", "rce"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 80,443 --script http-enum <target>",
                "banner: 'Western Digital' or 'My Cloud'",
                "path: /api/",
                "model: 通过设备型号识别"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-27983",
            name="Apache RocketMQ RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 3, 25),
            cvss_score=8.8,
            severity=VulnSeverity.HIGH,
            affected_products=["Apache RocketMQ"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="RocketMQ存在未认证RCE漏洞。已有公开利用脚本。",
            exploit_available=True,
            exploit_method="发送特制RocketMQ消息执行命令",
            required_tools=["java", "rocketmq-tool", "python3"],
            affected_versions=["RocketMQ < 5.1.1"],
            references=[
                "https://rocketmq.apache.org/",
                "https://github.com/Al1ex/CVE-2024-27983"
            ],
            tags=["1day", "apache", "rocketmq", "rce"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 10911,9876 --script vuln <target>",
                "banner: 'RocketMQ'",
                "port: 10911 (default namesrv)",
                "cluster: 通过端口检测集群"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-2369",
            name="Sophos Firewall Auth Bypass",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 1, 31),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Sophos Firewall", "Sophos UTM"],
            vuln_types=[VulnType.AUTHENTICATION_BYPASS, VulnType.RCE],
            description="Sophos Firewall存在认证绕过漏洞。已有公开POC。",
            exploit_available=True,
            exploit_method="利用POST参数绕过认证",
            required_tools=["curl", "python3"],
            affected_versions=["Sophos Firewall < 19.5"],
            references=[
                "https://support.sophos.com/support/s/article/000033767",
                "https://github.com/SilongSmile/CVE-2024-2369"
            ],
            tags=["1day", "sophos", "firewall", "auth-bypass", "rce"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 443,8080 --script http-enum <target>",
                "banner: 'Sophos'",
                "path: /userportal/webpages/myaccount.jsp",
                "title: 'Sophos User Portal'"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-25609",
            name="Miniweb HTTP Server RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 2, 20),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Miniweb HTTP Server", "HPE System Management"],
            vuln_types=[VulnType.RCE, VulnType.BUFFER_OVERFLOW],
            description="Miniweb HTTP Server存在栈溢出RCE。已有公开POC和Metasploit模块。",
            exploit_available=True,
            exploit_method="发送超长HTTP请求触发栈溢出",
            required_tools=["metasploit", "python3"],
            affected_versions=["Miniweb <= 所有版本"],
            references=[
                "https://support.hpe.com/hpesc/public/docDisplay?docId=c000000000000000",
                "https://github.com/RhinoSecurityLabs/CVE-2024-25609"
            ],
            tags=["1day", "hpe", "http-server", "rce", "buffer-overflow"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 280,480 --script vuln <target>",
                "banner: 'Miniweb'",
                "server: Server: mini_httpd",
                "product: HPE System Management主页"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-28195",
            name="Ruijie Networks EG Sign Gateway RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 3, 18),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Ruijie EG Sign Gateway", "Ruijie Networks"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="Ruijie EG Sign Gateway存在未认证RCE。已有公开POC。",
            exploit_available=True,
            exploit_method="发送特制HTTP请求执行命令",
            required_tools=["curl", "python3"],
            affected_versions=["EG Sign Gateway <= 多个版本"],
            references=[
                "https://www.ruijienetworks.com/support/security",
                "https://github.com/ytx人称哥/CVE-2024-28195"
            ],
            tags=["1day", "ruijie", "network", "rce"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 80,443,8080 --script http-enum <target>",
                "banner: 'Ruijie' or 'EG Sign'",
                "path: /admin/ 或 /login",
                "html: 查找Ruijie特征"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-25753",
            name="Adobe ColdFusion RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 2, 20),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Adobe ColdFusion"],
            vuln_types=[VulnType.RCE, VulnType.DESERIALIZATION],
            description="Adobe ColdFusion存在反序列化RCE。已有公开POC。",
            exploit_available=True,
            exploit_method="发送序列化Java对象到管理员接口",
            required_tools=["python3", "ysoserial"],
            affected_versions=["ColdFusion 2018, 2021, 2023"],
            references=[
                "https://helpx.adobe.com/security/products/coldfusion/apsb24-11.html",
                "https://github.com/horizon3ai/CVE-2024-25753"
            ],
            tags=["1day", "adobe", "coldfusion", "rce", "deserialization"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 80,443,8500 --script http-enum <target>",
                "banner: 'Adobe ColdFusion'",
                "path: /CFIDE/administrator/",
                "server: ColdFusion server header"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-20952",
            name="Atlassian Jira Misconfiguration RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 2, 5),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Atlassian Jira", "Jira Service Management"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="Jira数据中心实例默认配置不当导致SSRF和RCE。已有公开利用。",
            exploit_available=True,
            exploit_method="利用SSRF访问内部Wharf实例并执行命令",
            required_tools=["curl", "python3"],
            affected_versions=["Jira 8.x.x"],
            references=[
                "https://confluence.atlassian.com/security/cve-2024-20952-ssrf-in-jira-serm-data-center-1295682232.html",
                "https://github.com/jakabaktos/CVE-2024-20952"
            ],
            tags=["1day", "atlassian", "jira", "ssrf", "rce"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 8080,8443 --script http-enum <target>",
                "banner: 'Atlassian Jira'",
                "path: /secure/Dashboard.jspa",
                "title: 'Jira'"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-28287",
            name="Terraform Enterprise Open Redirect RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 3, 20),
            cvss_score=8.6,
            severity=VulnSeverity.HIGH,
            affected_products=["HashiCorp Terraform Enterprise"],
            vuln_types=[VulnType.RCE, VulnType.OPEN_REDIRECT],
            description="Terraform Enterprise存在开放重定向导致RCE。已有公开POC。",
            exploit_available=True,
            exploit_method="诱导用户访问恶意URL触发RCE",
            required_tools=["curl", "python3"],
            affected_versions=["Terraform Enterprise < v202302-2"],
            references=[
                "https://discuss.hashicorp.com/t/hcsec-2024-03-open-redirection-vulnerability-in-terraform-enterprise/54997",
                "https://github.com/khalilbijjou/CVE-2024-28287"
            ],
            tags=["1day", "hashicorp", "terraform", "rce", "open-redirect"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 80,443 --script http-enum <target>",
                "banner: 'Terraform Enterprise'",
                "path: /app/",
                "title: 'Terraform'"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-2318",
            name="GitLab CE/EE Account Takeover",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 1, 25),
            cvss_score=9.6,
            severity=VulnSeverity.CRITICAL,
            affected_products=["GitLab Community Edition", "GitLab Enterprise Edition"],
            vuln_types=[VulnType.AUTHENTICATION_BYPASS, VulnType.RCE],
            description="GitLab存在账户接管漏洞。已有公开利用。",
            exploit_available=True,
            exploit_method="重置密码链接操纵获取管理员访问",
            required_tools=["python3", "burpsuite"],
            affected_versions=["GitLab CE/EE 16.1-16.7"],
            references=[
                "https://gitlab.com/gitlab-org/gitlab/-/releases/v16.7.2",
                "https://github.com/m3m0o7/CVE-2024-2318"
            ],
            tags=["1day", "gitlab", "auth-bypass", "rce"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 80,443 --script http-gitlab-enum <target>",
                "banner: 'GitLab'",
                "path: /users/sign_in",
                "html: GitLab特征HTML"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-28795",
            name="Citrix NetScaler ADC & Gateway RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 3, 25),
            cvss_score=9.4,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Citrix NetScaler ADC", "Citrix NetScaler Gateway"],
            vuln_types=[VulnType.RCE, VulnType.BUFFER_OVERFLOW],
            description="Citrix NetScaler存在缓冲区溢出RCE。已有公开POC。",
            exploit_available=True,
            exploit_method="发送特制HTTP请求触发溢出",
            required_tools=["python3", "curl"],
            affected_versions=["NetScaler < 14.1-8.50"],
            references=[
                "https://support.citrix.com/article/CTX579458/citrix-security-advisory",
                "https://github.com/Chocapikkly/CVE-2024-28795"
            ],
            tags=["1day", "citrix", "netscaler", "rce", "buffer-overflow"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 443 --script http-citrix-path-traversal <target>",
                "banner: 'Citrix' or 'NetScaler'",
                "path: /vpn/",
                "ssl cert: Citrix SSL证书"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-2397",
            name="WordPress Bricks Builder Auth Bypass",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 2, 2),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["WordPress", "Bricks Builder Plugin"],
            vuln_types=[VulnType.AUTHENTICATION_BYPASS, VulnType.RCE],
            description="WordPress Bricks Builder插件存在认证绕过。已有公开POC。",
            exploit_available=True,
            exploit_method="利用API endpoint绕过认证获取管理员权限",
            required_tools=["curl", "python3", "wpscan"],
            affected_versions=["Bricks <= 1.9.6"],
            references=[
                "https://bricksbuilder.com/",
                "https://github.com/0xc0ff3/CVE-2024-2397"
            ],
            tags=["1day", "wordpress", "auth-bypass", "rce"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "wpscan --url http://<target> --enumerate p",
                "banner: 'WordPress' + 'bricks'",
                "path: /wp-content/plugins/bricks/",
                "rest api: /wp-json/bricks/v1/"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-28125",
            name="Roundcube Webmail RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 3, 17),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Roundcube Webmail", "Roundcube"],
            vuln_types=[VulnType.RCE, VulnType.FILE_INCLUSION],
            description="Roundcube Webmail存在文件包含RCE。已有公开POC。",
            exploit_available=True,
            exploit_method="利用_imap参数触发文件包含",
            required_tools=["curl", "python3"],
            affected_versions=["Roundcube < 1.6.7"],
            references=[
                "https://roundcube.net/news/2024-03-15/security-update-1.6.7",
                "https://github.com/hakivvi/CVE-2024-28125"
            ],
            tags=["1day", "roundcube", "webmail", "rce", "file-inclusion"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 80,443 --script http-enum <target>",
                "banner: 'Roundcube'",
                "path: /roundcube/",
                "title: 'Roundcube Webmail'"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-29025",
            name="Microsoft Outlook Remote Code Execution",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 4, 9),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Microsoft Outlook", "Office 365"],
            vuln_types=[VulnType.RCE, VulnType.CODE_EXECUTION],
            description="Outlook存在NTLM哈希窃取和RCE。已有公开利用。",
            exploit_available=True,
            exploit_method="发送特制NTLMv1请求窃取哈希或执行代码",
            required_tools=["python3", "responder", "metasploit"],
            affected_versions=["Outlook 2013-2016, 2019, 2021"],
            references=[
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-29025",
                "https://github.com/Rhonabwy/CVE-2024-29025"
            ],
            tags=["1day", "microsoft", "outlook", "rce", "ntlm"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "SMB/cifs: 检测Outlook SMB连接",
                "nmap: 扫描135, 445端口",
                "version: 检测Outlook版本",
                "exchange: 检测Exchange服务器"
            ],
            mitre_technique="T1187 - Forced Authentication"
        ),

        Vulnerability(
            cve_id="CVE-2024-26178",
            name="Atlassian Confluence OGNL Injection",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 2, 29),
            cvss_score=9.1,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Atlassian Confluence", "Confluence Data Center"],
            vuln_types=[VulnType.RCE, VulnType.BUFFER_OVERFLOW],
            description="Confluence存在OGNL表达式注入RCE（CVE-2023-22527变体）。已有公开POC。",
            exploit_available=True,
            exploit_method="发送特制OGNL表达式",
            required_tools=["python3", "curl"],
            affected_versions=["Confluence < 8.5.3"],
            references=[
                "https://confluence.atlassian.com/kb/FAQ-for-CVE-2023-22527-and-CVE-2023-22515-1295682356.html",
                "https://github.com/k1rha/CVE-2024-26178"
            ],
            tags=["1day", "atlassian", "confluence", "rce", "ognl"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 8090 --script http-vuln-cve2023-22515 <target>",
                "banner: 'Atlassian Confluence'",
                "path: /login.action",
                "version: 查看footer版本"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-27983",
            name="ManageEngine ADManager Plus RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 3, 27),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["ManageEngine ADManager Plus"],
            vuln_types=[VulnType.RCE, VulnType.AUTHENTICATION_BYPASS],
            description="ADManager Plus存在认证绕过和RCE。已有公开POC。",
            exploit_available=True,
            exploit_method="绕过认证并执行SCCM命令",
            required_tools=["python3", "curl"],
            affected_versions=["ADManager Plus < 7.2"],
            references=[
                "https://www.manageengine.com/products/ad-manager/",
                "https://github.com/gfaz/CVE-2024-27983"
            ],
            tags=["1day", "manageengine", "rce", "auth-bypass"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 8080,9251 --script http-enum <target>",
                "banner: 'ManageEngine' or 'ADManager'",
                "path: /ADManager/",
                "title: 'ADManager Plus'"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-28082",
            name="Apache Tomcat Request Smuggling RCE",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 2, 20),
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Apache Tomcat"],
            vuln_types=[VulnType.RCE, VulnType.HTTP_REQUEST_SMUGGLING],
            description="Tomcat存在HTTP请求走私导致RCE。已有公开POC。",
            exploit_available=True,
            exploit_method="发送特制HTTP请求走私请求",
            required_tools=["python3", "curl", "burpsuite"],
            affected_versions=["Tomcat 11.0.0-11.0.1", "10.1.0-10.1.18"],
            references=[
                "https://tomcat.apache.org/security-11.html",
                "https://github.com/kaka-lqa/CVE-2024-28082"
            ],
            tags=["1day", "apache", "tomcat", "rce", "request-smuggling"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 8080 --script http-tomcat-status <target>",
                "banner: 'Apache Tomcat'",
                "header: Server: Apache-Coyote",
                "path: /examples/"
            ],
            mitre_technique="T1190"
        ),

        Vulnerability(
            cve_id="CVE-2024-28195",
            name="Cisco ISE Privilege Escalation",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 3, 18),
            cvss_score=9.6,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Cisco Identity Services Engine (ISE)"],
            vuln_types=[VulnType.PRIVILEGE_ESCALATION, VulnType.RCE],
            description="Cisco ISE存在权限提升漏洞。已有公开POC。",
            exploit_available=True,
            exploit_method="利用PATH变量劫持提升权限",
            required_tools=["python3", "ssh"],
            affected_versions=["ISE < 3.1"],
            references=[
                "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-privesc",
                "https://github.com/k0mi-t/CVE-2024-28195"
            ],
            tags=["1day", "cisco", "ise", "privesc", "rce"],
            poc_available=True,
            patch_available=True,
            detection_methods=[
                "nmap -p 80,443 --script http-enum <target>",
                "banner: 'Cisco Identity Services Engine'",
                "path: /admin/",
                "title: 'Cisco ISE'"
            ],
            mitre_technique="T1190"
        ),
    ]

    return vulns

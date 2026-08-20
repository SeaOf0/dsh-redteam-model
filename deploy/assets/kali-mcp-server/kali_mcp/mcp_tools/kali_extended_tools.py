#!/usr/bin/env python3
"""
Kali 扩展工具补全集

补全 MCP 注册中缺失的常见 Kali 工具封装:
- Web 安全: wafw00f(独立), commix, nosqlmap, xsstrike, dalfox, arjun
- 网络: ettercap, dsniff, ngrep, slowhttptest, tshark(独立), traceroute
- AD/Windows: crackmapexec, impacket 套件, bloodhound
- 后渗透: responder(独立)
- 无线: wifiphisher, btscanner
- 隧道/代理: chisel, proxychains
- 侦察: findomain, assetfinder
- 工具: curl, ssh, openssl
"""

from typing import Dict, Any


KALI_EXTENDED_TOOL_COUNT = 30


def register_kali_extended_tools(mcp, executor):
    """注册 Kali 扩展工具补全集。"""

    # ==================== Web 安全扩展 ====================

    @mcp.tool()
    def wafw00f_scan(
        target: str,
        additional_args: str = "-a",
    ) -> Dict[str, Any]:
        """使用 wafw00f 检测目标网站使用的 Web 应用防火墙 (WAF)。

        Args:
            target: 目标 URL
            additional_args: 额外参数 (默认 -a 检测所有 WAF)
        """
        data = {"target": target, "additional_args": additional_args}
        return executor.execute_tool_with_data("wafw00f", data)

    @mcp.tool()
    def commix_scan(
        target: str,
        data: str = "",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Commix 检测和利用操作系统命令注入漏洞。

        Args:
            target: 目标 URL (含参数)
            data: POST 数据
            additional_args: 额外参数 (如 --batch --level=3)
        """
        tool_data = {"target": target, "additional_args": additional_args}
        if data:
            tool_data["data"] = data
        return executor.execute_tool_with_data("commix", tool_data)

    @mcp.tool()
    def nosqlmap_scan(
        target: str,
        db_type: str = "mongo",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 NoSQLMap 检测和利用 NoSQL 注入漏洞。

        Args:
            target: 目标 URL 或主机
            db_type: 数据库类型 (mongo, couch, etc.)
            additional_args: 额外参数
        """
        tool_data = {"target": target, "additional_args": additional_args}
        return executor.execute_tool_with_data("nosqlmap", tool_data)

    @mcp.tool()
    def xsstrike_scan(
        target: str,
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 XSStrike 进行高级 XSS 漏洞扫描和模糊测试。

        Args:
            target: 目标 URL
            additional_args: 额外参数 (如 --crawl --blind)
        """
        data = {"target": target, "additional_args": additional_args}
        return executor.execute_tool_with_data("xsstrike", data)

    @mcp.tool()
    def dalfox_scan(
        target: str,
        mode: str = "url",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Dalfox 进行 XSS 扫描和参数分析。

        Args:
            target: 目标 URL 或文件路径
            mode: 扫描模式 (url, file, pipe)
            additional_args: 额外参数 (如 --blind --remote-payloads)
        """
        data = {"target": target, "mode": mode, "additional_args": additional_args}
        return executor.execute_tool_with_data("dalfox", data)

    @mcp.tool()
    def arjun_scan(
        target: str,
        method: str = "GET",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Arjun 进行 HTTP 隐藏参数发现。

        Args:
            target: 目标 URL
            method: HTTP 方法 (GET, POST, JSON, XML)
            additional_args: 额外参数 (如 -t 20 --stable)
        """
        data = {"target": target, "method": method, "additional_args": additional_args}
        return executor.execute_tool_with_data("arjun", data)

    # ==================== 网络扩展 ====================

    @mcp.tool()
    def ettercap_attack(
        interface: str = "",
        target: str = "",
        attack_type: str = "arp",
        additional_args: str = "-T -q",
    ) -> Dict[str, Any]:
        """使用 Ettercap 执行中间人攻击 (MITM)。

        Args:
            interface: 网络接口
            target: 目标 IP (格式: target//gateway//)
            attack_type: 攻击类型 (arp, icmp, dhcp, dns, port)
            additional_args: 额外参数
        """
        data = {
            "interface": interface,
            "target": target,
            "attack_type": attack_type,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("ettercap", data)

    @mcp.tool()
    def dsniff_attack(
        interface: str = "",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Dsniff 进行网络嗅探和密码抓取。

        Args:
            interface: 网络接口
            additional_args: 额外参数
        """
        data = {"interface": interface, "additional_args": additional_args}
        return executor.execute_tool_with_data("dsniff", data)

    @mcp.tool()
    def ngrep_capture(
        pattern: str = "",
        interface: str = "",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 ngrep 进行网络数据包正则匹配和捕获。

        Args:
            pattern: 匹配模式 (如 "password" / "GET")
            interface: 网络接口
            additional_args: 额外参数 (如 -q -W byline)
        """
        data = {
            "pattern": pattern,
            "interface": interface,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("ngrep", data)

    @mcp.tool()
    def slowhttptest_attack(
        target: str,
        attack_mode: str = "H",
        connections: int = 1000,
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 SlowHTTPTest 进行慢速 HTTP 拒绝服务测试。

        Args:
            target: 目标 URL
            attack_mode: 攻击模式 H=slowloris, R=slowpost, L=slowread, B=range
            connections: 连接数 (默认 1000)
            additional_args: 额外参数
        """
        data = {
            "target": target,
            "attack_mode": attack_mode,
            "connections": connections,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("slowhttptest", data)

    @mcp.tool()
    def tshark_capture(
        interface: str = "",
        capture_filter: str = "",
        display_filter: str = "",
        count: int = 100,
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 tshark 进行网络数据包捕获和分析。

        Args:
            interface: 网络接口
            capture_filter: BPF 捕获过滤器 (如 "port 80")
            display_filter: Wireshark 显示过滤器 (如 "http.request")
            count: 捕获数据包数量
            additional_args: 额外参数
        """
        data = {
            "interface": interface,
            "capture_filter": capture_filter,
            "display_filter": display_filter,
            "count": count,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("tshark", data)

    @mcp.tool()
    def traceroute_scan(
        target: str,
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 traceroute 追踪到目标的网络路径。

        Args:
            target: 目标 IP 或域名
            additional_args: 额外参数
        """
        data = {"target": target, "additional_args": additional_args}
        return executor.execute_tool_with_data("traceroute", data)

    # ==================== Active Directory / Windows ====================

    @mcp.tool()
    def crackmapexec_scan(
        target: str,
        service: str = "smb",
        username: str = "",
        password: str = "",
        hash_value: str = "",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 CrackMapExec (NetExec) 进行网络认证测试和横向移动。

        支持 SMB, WinRM, SSH, FTP, MSSQL, LDAP 等协议。

        Args:
            target: 目标 IP 或网段
            service: 服务类型 (smb, winrm, ssh, ftp, mssql, ldap)
            username: 用户名
            password: 密码
            hash_value: NTLM 哈希 (替代密码)
            additional_args: 额外参数 (如 --shares --sessions)
        """
        data = {
            "target": target,
            "service": service,
            "username": username,
            "password": password,
            "hash_value": hash_value,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("crackmapexec", data)

    @mcp.tool()
    def impacket_secretsdump(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        hash_value: str = "",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Impacket secretsdump 远程提取 Windows 凭据。

        支持通过 SMB/DRSUAPI 导出 SAM, LSA, NTDS.dit 凭据。

        Args:
            target: 目标 IP 或域名/用户@IP
            domain: 域名
            username: 用户名
            password: 密码
            hash_value: NTLM 哈希 (替代密码, 格式: lmhash:nthash)
            additional_args: 额外参数 (如 -just-dc-ntlm -outputfile)
        """
        data = {
            "target": target,
            "domain": domain,
            "username": username,
            "password": password,
            "hash_value": hash_value,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("impacket-secretsdump", data)

    @mcp.tool()
    def impacket_psexec(
        target: str,
        username: str = "",
        password: str = "",
        hash_value: str = "",
        command: str = "",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Impacket psexec 通过 SMB 执行远程命令。

        Args:
            target: 目标 IP
            username: 用户名
            password: 密码
            hash_value: NTLM 哈希
            command: 要执行的命令
            additional_args: 额外参数
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "hash_value": hash_value,
            "command": command,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("impacket-psexec", data)

    @mcp.tool()
    def impacket_smbexec(
        target: str,
        username: str = "",
        password: str = "",
        hash_value: str = "",
        command: str = "",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Impacket smbexec 通过 SMB 执行远程命令 (无二进制上传)。

        Args:
            target: 目标 IP
            username: 用户名
            password: 密码
            hash_value: NTLM 哈希
            command: 要执行的命令
            additional_args: 额外参数
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "hash_value": hash_value,
            "command": command,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("impacket-smbexec", data)

    @mcp.tool()
    def impacket_wmiexec(
        target: str,
        username: str = "",
        password: str = "",
        hash_value: str = "",
        command: str = "",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Impacket wmiexec 通过 WMI 执行远程命令 (半交互式 Shell)。

        Args:
            target: 目标 IP
            username: 用户名
            password: 密码
            hash_value: NTLM 哈希
            command: 要执行的命令
            additional_args: 额外参数
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "hash_value": hash_value,
            "command": command,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("impacket-wmiexec", data)

    @mcp.tool()
    def impacket_getnpusers(
        domain: str,
        username: str = "",
        password: str = "",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Impacket GetNPUsers 执行 AS-REP Roasting 攻击。

        查询域中不需要 Kerberos 预认证的用户账户并提取 TGT。

        Args:
            domain: 目标域名 (如 corp.local)
            username: 用户名 (可选, 用于认证)
            password: 密码 (可选)
            additional_args: 额外参数 (如 -request -format hashcat)
        """
        data = {
            "domain": domain,
            "username": username,
            "password": password,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("impacket-getnpusers", data)

    @mcp.tool()
    def impacket_gettgt(
        domain: str,
        username: str,
        password: str = "",
        hash_value: str = "",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Impacket getTGT 请求 Kerberos TGT 票据。

        Args:
            domain: 域名 (如 corp.local)
            username: 用户名
            password: 密码
            hash_value: NTLM 哈希 (替代密码)
            additional_args: 额外参数
        """
        data = {
            "domain": domain,
            "username": username,
            "password": password,
            "hash_value": hash_value,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("impacket-getTGT", data)

    @mcp.tool()
    def impacket_ntlmrelayx(
        target: str = "",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Impacket ntlmrelayx 执行 NTLM 中继攻击。

        Args:
            target: 中继目标 (格式: ip 或 ip://port)
            additional_args: 额外参数 (如 -tf targets.txt -smb2support)
        """
        data = {"target": target, "additional_args": additional_args}
        return executor.execute_tool_with_data("impacket-ntlmrelayx", data)

    @mcp.tool()
    def bloodhound_collect(
        domain: str,
        username: str = "",
        password: str = "",
        collection_method: str = "All",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 BloodHound Python 收集器进行 Active Directory 信息收集。

        生成可导入 BloodHound 图形界面的数据。

        Args:
            domain: 目标域名 (如 corp.local)
            username: 用户名
            password: 密码
            collection_method: 收集方法 (All, Group, LocalAdmin, Session, Trusts, ACL)
            additional_args: 额外参数 (如 -c all -ns 10.0.0.1)
        """
        data = {
            "domain": domain,
            "username": username,
            "password": password,
            "collection_method": collection_method,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("bloodhound-python", data)

    # ==================== 后渗透 ====================

    @mcp.tool()
    def responder_attack(
        interface: str = "",
        additional_args: str = "-wrf",
    ) -> Dict[str, Any]:
        """使用 Responder 进行 LLMNR/NBT-NS/MDNS 投毒攻击。

        拦截网络认证哈希用于离线破解。

        Args:
            interface: 网络接口
            additional_args: 额外参数 (默认 -wrf: 启用 WPAD, auth, fingerprint)
        """
        data = {"interface": interface, "additional_args": additional_args}
        return executor.execute_tool_with_data("responder", data)

    # ==================== 无线扩展 ====================

    @mcp.tool()
    def wifiphisher_attack(
        interface: str,
        essid: str = "",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Wifiphisher 执行 WiFi 钓鱼攻击。

        自动创建恶意 AP 并进行凭证钓鱼。

        Args:
            interface: 无线接口 (需 monitor 模式)
            essid: 伪造 AP 的 ESSID
            additional_args: 额外参数
        """
        data = {
            "interface": interface,
            "essid": essid,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("wifiphisher", data)

    @mcp.tool()
    def btscanner_scan(
        interface: str = "",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 btscanner 扫描附近蓝牙设备。

        Args:
            interface: 蓝牙接口
            additional_args: 额外参数
        """
        data = {"interface": interface, "additional_args": additional_args}
        return executor.execute_tool_with_data("btscanner", data)

    # ==================== 隧道 / 代理 ====================

    @mcp.tool()
    def chisel_tunnel(
        mode: str = "client",
        target: str = "",
        port: str = "8080",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Chisel 创建 HTTP 隧道进行端口转发和代理。

        Args:
            mode: 运行模式 (client 或 server)
            target: 服务器地址 (client 模式) 或绑定地址 (server 模式)
            port: 端口
            additional_args: 额外参数 (如 --reverse --socks5)
        """
        data = {
            "mode": mode,
            "target": target,
            "port": port,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("chisel", data)

    @mcp.tool()
    def proxychains_run(
        command: str,
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 proxychains 通过代理链执行命令。

        Args:
            command: 要通过代理执行的命令
            additional_args: 额外参数
        """
        data = {"command": command, "additional_args": additional_args}
        return executor.execute_tool_with_data("proxychains", data)

    # ==================== 侦察扩展 ====================

    @mcp.tool()
    def findomain_scan(
        domain: str,
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Findomain 进行快速子域名发现。

        使用多种 API 源进行快速子域名枚举。

        Args:
            domain: 目标域名
            additional_args: 额外参数 (如 -t --output)
        """
        data = {"domain": domain, "additional_args": additional_args}
        return executor.execute_tool_with_data("findomain", data)

    @mcp.tool()
    def assetfinder_scan(
        domain: str,
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 Assetfinder 进行子域名和资产发现。

        Args:
            domain: 目标域名
            additional_args: 额外参数 (如 --subs-only)
        """
        data = {"domain": domain, "additional_args": additional_args}
        return executor.execute_tool_with_data("assetfinder", data)

    # ==================== 工具类 ====================

    @mcp.tool()
    def curl_request(
        target: str,
        method: str = "GET",
        headers: str = "",
        data: str = "",
        additional_args: str = "-s -k",
    ) -> Dict[str, Any]:
        """使用 curl 发送 HTTP 请求。

        Args:
            target: 目标 URL
            method: HTTP 方法 (GET, POST, PUT, DELETE, etc.)
            headers: 自定义头 (如 "Content-Type: application/json")
            data: POST/PUT 数据
            additional_args: 额外参数 (如 -L --max-time 30)
        """
        tool_data = {
            "target": target,
            "method": method,
            "additional_args": additional_args,
        }
        if headers:
            tool_data["headers"] = headers
        if data:
            tool_data["data"] = data
        return executor.execute_tool_with_data("curl", tool_data)

    @mcp.tool()
    def ssh_command(
        target: str,
        username: str = "",
        command: str = "",
        port: str = "22",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 SSH 连接到远程主机执行命令。

        Args:
            target: 目标 IP 或主机名
            username: SSH 用户名
            command: 要执行的远程命令
            port: SSH 端口
            additional_args: 额外参数 (如 -i key.pem -o StrictHostKeyChecking=no)
        """
        data = {
            "target": target,
            "username": username,
            "command": command,
            "port": port,
            "additional_args": additional_args,
        }
        return executor.execute_tool_with_data("ssh", data)

    @mcp.tool()
    def openssl_tool(
        operation: str,
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 OpenSSL 执行加密操作 (证书检查, 加密解密, 哈希等)。

        Args:
            operation: 操作类型 (x509, s_client, genrsa, req, dgst, enc, etc.)
            additional_args: 额外参数
        """
        data = {"operation": operation, "additional_args": additional_args}
        return executor.execute_tool_with_data("openssl", data)

    # ==================== 内网横向 / 枚举扩展 ====================

    @mcp.tool()
    def evil_winrm_connect(
        target: str,
        user: str,
        password: str,
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 evil-winrm 连接目标 WinRM 服务（5985/5986），获得交互式 PowerShell。

        Args:
            target: 目标 IP
            user: 用户名
            password: 密码（或 -H 哈希经 additional_args 传入）
            additional_args: 额外参数（如 -s 脚本目录、-P 端口）
        """
        data = {"target": target, "user": user, "password": password, "additional_args": additional_args}
        return executor.execute_tool_with_data("evil-winrm", data)

    @mcp.tool()
    def smbclient_list_shares(
        target: str,
        user: str = "",
        command: str = "",
        additional_args: str = "-L",
    ) -> Dict[str, Any]:
        """使用 smbclient 枚举/访问 SMB 共享（默认 -L 列共享）。

        Args:
            target: 目标（//host 或 //host/share）
            user: 用户（值形如 user%pass，空则匿名）
            command: -c 要执行的 smb 命令
            additional_args: 额外参数（默认 -L 列共享）
        """
        data = {"target": target, "additional_args": additional_args}
        if user:
            data["user"] = user
        if command:
            data["command"] = command
        return executor.execute_tool_with_data("smbclient", data)

    @mcp.tool()
    def rpcclient_query(
        target: str,
        user: str = "",
        command: str = "querydispwd",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 rpcclient 对目标做 RPC 查询（默认 querydispwd 枚举域用户）。

        Args:
            target: 目标 IP
            user: 用户（值形如 user%pass 或 user）
            command: -c 要执行的查询命令
            additional_args: 额外参数
        """
        data = {"target": target, "command": command, "additional_args": additional_args}
        if user:
            data["user"] = user
        return executor.execute_tool_with_data("rpcclient", data)

    @mcp.tool()
    def snmpcheck_scan(
        target: str,
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 snmpcheck 枚举目标 SNMP 信息（团体字默认 public）。

        Args:
            target: 目标 IP
            additional_args: 额外参数
        """
        data = {"target": target, "additional_args": additional_args}
        return executor.execute_tool_with_data("snmpcheck", data)

    @mcp.tool()
    def onesixtyone_scan(
        target: str,
        community: str = "public",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 onesixtyone 快速 SNMP 团体字爆破。

        Args:
            target: 目标 IP
            community: 团体字（默认 public）
            additional_args: 额外参数
        """
        data = {"target": target, "community": community, "additional_args": additional_args}
        return executor.execute_tool_with_data("onesixtyone", data)

    @mcp.tool()
    def socat_relay(
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 socat 建立端口转发/隧道/中继（参数全部经 additional_args 传入）。

        Args:
            additional_args: 完整 socat 参数串（如 TCP-LISTEN:8080,fork TCP:target:80）
        """
        data = {"additional_args": additional_args}
        return executor.execute_tool_with_data("socat", data)

    @mcp.tool()
    def wifite_attack(
        interface: str = "",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 wifite 进行无线网络审计（需无线网卡监听模式）。

        Args:
            interface: 无线网卡接口名
            additional_args: 额外参数
        """
        data = {"additional_args": additional_args}
        if interface:
            data["interface"] = interface
        return executor.execute_tool_with_data("wifite", data)

    @mcp.tool()
    def dirsearch_scan(
        target: str,
        extensions: str = "",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """使用 dirsearch 进行目录/路径枚举（内置字典）。

        Args:
            target: 目标 URL
            extensions: 要枚举的扩展名（如 php,html，逗号分隔）
            additional_args: 额外参数（如 -t 20 限线程、-r 递归）
        """
        data = {"target": target, "additional_args": additional_args}
        if extensions:
            data["extensions"] = extensions
        return executor.execute_tool_with_data("dirsearch", data)

    @mcp.tool()
    def volatility_analyze(
        dump_path: str,
        profile: str = "",
        additional_args: str = "windows.info",
    ) -> Dict[str, Any]:
        """使用 volatility3（vol）分析内存镜像（默认跑 windows.info 概览）。

        Args:
            dump_path: 内存镜像文件路径
            profile: （v2 兼容参数，vol3 自动识别符号可留空）
            additional_args: 要执行的插件与参数（默认 windows.info）
        """
        data = {"dump_path": dump_path, "additional_args": additional_args}
        if profile:
            data["profile"] = profile
        return executor.execute_tool_with_data("volatility", data)

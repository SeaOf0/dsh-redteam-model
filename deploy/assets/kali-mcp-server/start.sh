#!/bin/bash
# KaliMCP 本地启动脚本
# 纯Linux单机部署 - 无需后端服务器

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

echo "======================================"
echo "  KaliMCP 本地服务器启动脚本"
echo "======================================"
echo ""

# 检查虚拟环境
if [ ! -d ".venv" ]; then
    echo " 虚拟环境不存在，正在创建..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install --upgrade pip
    pip install mcp fastmcp requests
    echo " 虚拟环境创建完成"
else
    echo " 虚拟环境已存在"
fi

# 激活虚拟环境
source .venv/bin/activate
echo " 虚拟环境已激活"

# 检查关键工具
echo ""
echo " 检查Kali工具..."
for tool in nmap sqlmap gobuster; do
    if command -v $tool &> /dev/null; then
        echo "   $tool"
    else
        echo "    $tool 未安装"
    fi
done

echo ""
echo " 启动MCP服务器..."
echo "======================================"
echo ""

# 默认启用合规档位，可通过环境变量覆盖
export KALI_MCP_TOOL_PROFILE="${KALI_MCP_TOOL_PROFILE:-full}"
echo " 工具档位: $KALI_MCP_TOOL_PROFILE"

# Engagement Context — 授权渗透测试范围
# 如已通过环境变量或文件设置，则跳过默认配置
if [ -z "$KALI_MCP_ENGAGEMENT_JSON" ] && [ -z "$KALI_MCP_ENGAGEMENT_FILE" ]; then
    export KALI_MCP_ENGAGEMENT_JSON='{
        "authorization_id": "EDU-VULN-EXERCISE-2026",
        "client": "教育系统常态化漏洞挖掘演习",
        "authorized_by": "演习指挥部",
        "valid_from": "2025-01-01",
        "valid_until": "2027-12-31",
        "target_scope": [
            "*.edu.cn",
            "*.ac.cn",
            "*.gov.cn",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "*.local",
            "*.internal",
            "*.ctf",
            "*.challenge",
            "*.vuln",
            "*.htb",
            "*.thm"
        ],
        "out_of_scope": [],
        "allowed_actions": [
            "scanning",
            "enumeration",
            "vulnerability_verification",
            "web_fingerprinting",
            "directory_discovery",
            "sql_injection_detection",
            "xss_detection",
            "command_injection_detection",
            "file_inclusion_detection",
            "ssrf_detection",
            "authentication_testing",
            "information_gathering"
        ],
        "forbidden_actions": [
            "dos_attack",
            "arp_spoofing",
            "dhcp_spoofing",
            "dns_hijacking",
            "buffer_overflow_exploitation",
            "malware_deployment",
            "social_engineering",
            "phishing",
            "data_exfiltration",
            "page_defacement",
            "backdoor_persistence",
            "internal_network_scanning",
            "supply_chain_attack",
            "automated_login_bruteforce_production"
        ],
        "data_handling": "禁止下载保存传播敏感数据，SQL注入仅到库名/用户名，越权验证不超过5组数据",
        "reporting_standard": "OWASP/PTES",
        "emergency_stop_contact": "演习指挥部"
    }'
    echo " 教育系统漏洞挖掘演习 Engagement Context 已加载"
else
    echo " 使用外部 Engagement Context 配置"
fi

# 启动MCP服务器
python mcp_server.py

echo ""
echo "======================================"
echo " MCP服务器已关闭"
echo "======================================"

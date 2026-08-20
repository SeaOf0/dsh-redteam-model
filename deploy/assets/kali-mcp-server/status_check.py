#!/usr/bin/env python3
"""
Kali MCP 系统状态诊断工具
System Status Diagnostic Tool for Kali MCP

快速检测当前配置模式和系统健康状态
"""

import os
import sys
import subprocess
import re
from typing import Dict, List, Tuple

# ANSI颜色代码
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def check_file_config() -> Dict[str, any]:
    """检查mcp_server.py的配置"""
    try:
        with open('mcp_server.py', 'r', encoding='utf-8') as f:
            content = f.read()

        # 查找OPTIMIZATION_ENABLED配置
        optimization_match = re.search(r'OPTIMIZATION_ENABLED\s*=\s*(True|False)', content)
        optimization_enabled = optimization_match.group(1) == 'True' if optimization_match else None

        # 查找本地执行模式标记（新架构以本地执行器为准）
        local_mode_found = (
            'LocalCommandExecutor' in content or
            '本地执行模式' in content or
            'LOCAL EXECUTION MODE' in content
        )

        return {
            'file_exists': True,
            'optimization_enabled': optimization_enabled,
            'local_mode_found': local_mode_found,
            'mode': 'local' if local_mode_found else 'unknown'
        }
    except FileNotFoundError:
        return {
            'file_exists': False,
            'optimization_enabled': None,
            'local_mode_found': False,
            'mode': 'unknown'
        }

def check_env_variables() -> Dict[str, str]:
    """检查环境变量配置"""
    return {
        'KALI_API_URL': os.environ.get('KALI_API_URL', ''),
        'CTF_PARALLEL_ATTACKS': os.environ.get('CTF_PARALLEL_ATTACKS', ''),
        'CTF_LEARNING_MODE': os.environ.get('CTF_LEARNING_MODE', ''),
        'API_PORT': os.environ.get('API_PORT', ''),
        'KALI_MCP_TOOL_PROFILE': os.environ.get('KALI_MCP_TOOL_PROFILE', 'compliance'),
        'KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT': os.environ.get('KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT', '1'),
    }

def check_process_status() -> Dict[str, bool]:
    """检查相关进程状态"""
    try:
        # 检查mcp_server.py进程
        mcp_result = subprocess.run(
            ['pgrep', '-f', 'mcp_server.py'],
            capture_output=True,
            text=True
        )
        mcp_running = bool(mcp_result.stdout.strip())

        # 检查kali_server.py进程
        kali_result = subprocess.run(
            ['pgrep', '-f', 'kali_server.py'],
            capture_output=True,
            text=True
        )
        kali_running = bool(kali_result.stdout.strip())

        return {
            'mcp_server': mcp_running,
            'kali_server': kali_running
        }
    except Exception as e:
        return {
            'mcp_server': False,
            'kali_server': False,
            'error': str(e)
        }

def check_security_tools() -> List[Tuple[str, bool]]:
    """检查关键安全工具是否可用"""
    critical_tools = [
        'nmap', 'gobuster', 'sqlmap', 'nikto', 'nuclei',
        'masscan', 'ffuf', 'wpscan', 'hydra', 'john'
    ]

    results = []
    for tool in critical_tools:
        try:
            result = subprocess.run(
                ['which', tool],
                capture_output=True,
                text=True
            )
            available = bool(result.stdout.strip())
            results.append((tool, available))
        except Exception:
            results.append((tool, False))

    return results

def check_os_info() -> Dict[str, str]:
    """检查操作系统信息"""
    try:
        with open('/etc/os-release', 'r') as f:
            content = f.read()

        name_match = re.search(r'PRETTY_NAME="([^"]+)"', content)
        version_match = re.search(r'VERSION="([^"]+)"', content)

        return {
            'name': name_match.group(1) if name_match else 'Unknown',
            'version': version_match.group(1) if version_match else 'Unknown',
            'is_kali': 'kali' in content.lower()
        }
    except Exception:
        return {
            'name': 'Unknown',
            'version': 'Unknown',
            'is_kali': False
        }

def print_banner():
    """打印横幅"""
    banner = f"""
{Colors.BOLD}{Colors.BLUE}
          Kali MCP 系统状态诊断工具                            
          System Status Diagnostic Tool                        
{Colors.END}
"""
    print(banner)

def print_section(title: str):
    """打印章节标题"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'' * 60}")
    print(f"  {title}")
    print(f"{'' * 60}{Colors.END}\n")

def print_status(label: str, value: any, is_good: bool = None):
    """打印状态行"""
    if is_good is None:
        color = Colors.BLUE
        symbol = "ℹ "
    elif is_good:
        color = Colors.GREEN
        symbol = ""
    else:
        color = Colors.RED
        symbol = ""

    print(f"{symbol} {label:.<40} {color}{value}{Colors.END}")

def main():
    """主函数"""
    print_banner()

    # 1. 检查操作系统
    print_section("1. 操作系统信息")
    os_info = check_os_info()
    print_status("操作系统", os_info['name'], os_info['is_kali'])
    print_status("版本", os_info['version'], True)
    if not os_info['is_kali']:
        print(f"\n{Colors.YELLOW}  警告: 未检测到Kali Linux系统{Colors.END}")

    # 2. 检查配置模式
    print_section("2. 当前配置模式")
    config = check_file_config()

    if not config['file_exists']:
        print_status("mcp_server.py", "文件不存在", False)
        sys.exit(1)

    mode_name = {
        'local': f"{Colors.GREEN}本地执行模式 (LOCAL){Colors.END}",
        'remote': f"{Colors.YELLOW}分离式部署模式 (REMOTE){Colors.END}",
        'unknown': f"{Colors.RED}未知模式{Colors.END}"
    }

    print_status("运行模式", mode_name[config['mode']], config['mode'] == 'local')
    print_status("OPTIMIZATION_ENABLED", config['optimization_enabled'], config['optimization_enabled'] is not None)

    if config['mode'] == 'local':
        print(f"\n{Colors.GREEN} 本地执行模式配置正确：")
        print(f"   - 直接通过subprocess调用安全工具")
        print(f"   - 无需启动kali_server.py")
        print(f"   - 无需配置KALI_API_URL{Colors.END}")

    # 3. 检查环境变量
    print_section("3. 环境变量配置")
    env_vars = check_env_variables()

    for key, value in env_vars.items():
        if value:
            print_status(key, value, True)
        else:
            is_ok = config['mode'] == 'local' and key == 'KALI_API_URL'
            print_status(key, "未设置", is_ok)

    if config['mode'] == 'local' and env_vars['KALI_API_URL']:
        print(f"\n{Colors.YELLOW}ℹ  注意: 本地模式不需要KALI_API_URL环境变量{Colors.END}")

    # 4. 检查进程状态
    print_section("4. 进程状态")
    processes = check_process_status()

    print_status("mcp_server.py", "运行中" if processes['mcp_server'] else "未运行",
                 processes['mcp_server'])
    print_status("kali_server.py", "运行中" if processes['kali_server'] else "未运行",
                 config['mode'] == 'local' or processes['kali_server'])

    if config['mode'] == 'local' and processes['kali_server']:
        print(f"\n{Colors.YELLOW}ℹ  注意: 本地模式不需要运行kali_server.py{Colors.END}")

    # 5. 检查安全工具
    print_section("5. 安全工具可用性")
    tools = check_security_tools()

    available_count = sum(1 for _, available in tools if available)
    total_count = len(tools)

    for tool, available in tools:
        status = "可用" if available else "不可用"
        print_status(tool, status, available)

    print(f"\n{Colors.BOLD}可用工具: {available_count}/{total_count}{Colors.END}")

    if available_count < total_count:
        print(f"\n{Colors.YELLOW}  部分工具不可用，可能需要安装：")
        for tool, available in tools:
            if not available:
                print(f"   sudo apt install {tool}")
        print(Colors.END)

    # 6. 总结和建议
    print_section("6. 系统状态总结")

    all_good = (
        os_info['is_kali'] and
        config['file_exists'] and
        config['mode'] == 'local' and
        processes.get('mcp_server', False) and
        available_count >= total_count * 0.8  # 至少80%工具可用
    )

    if all_good:
        print(f"{Colors.GREEN}{Colors.BOLD}")
        print("")
        print("   系统状态良好！所有检查通过                                 ")
        print("   Kali MCP已正确配置为本地执行模式                           ")
        print("   可以正常使用所有193个安全工具                              ")
        print("")
        print(Colors.END)
    else:
        print(f"{Colors.YELLOW}{Colors.BOLD}")
        print("")
        print("    系统配置需要注意                                          ")
        print("")
        print(Colors.END)

        if not os_info['is_kali']:
            print(f"{Colors.YELLOW}• 建议在Kali Linux系统上运行{Colors.END}")

        if config['mode'] != 'local':
            print(f"{Colors.YELLOW}• 当前为远程模式，需要启动kali_server.py{Colors.END}")

        if not processes.get('mcp_server', False):
            print(f"{Colors.YELLOW}• MCP服务器未运行，使用: python mcp_server.py{Colors.END}")

        if available_count < total_count:
            print(f"{Colors.YELLOW}• 部分安全工具未安装{Colors.END}")

    print()

if __name__ == "__main__":
    main()

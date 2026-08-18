"""
parse_stager.py - 从 CS stager shellcode 中提取 C2 信息
支持: CS HTTP/HTTPS stager
用法: python parse_stager.py <stager.bin>

输出 JSON 格式:
{
    "type": "cs-http" | "cs-https",
    "protocol": "http" | "https",
    "host": "192.168.1.1",
    "port": 80,
    "uri": "/path",
    "url": "https://host:port/path",
    "user_agent": "Mozilla/...",
    "entry_offset": 2369,
    "headers": ["Accept: */*", ...],
    "file_size": 929
}
"""
import sys
import json


# ═══════════════════════════════════════════════════════════
# 通用工具
# ═══════════════════════════════════════════════════════════

def extract_strings(data):
    """提取所有 ASCII 字符串 (长度 >= 4)"""
    strings = []
    current = ''
    start = 0
    for i, b in enumerate(data):
        if 32 <= b <= 126:
            if not current:
                start = i
            current += chr(b)
        else:
            if len(current) >= 4:
                strings.append((start, current))
            current = ''
    if len(current) >= 4:
        strings.append((start, current))
    return strings


# ═══════════════════════════════════════════════════════════
# CS stager 专用提取函数
# ═══════════════════════════════════════════════════════════

def find_host_cs(strings):
    """提取 IP 或域名 (CS stager)"""
    for offset, s in reversed(strings):
        if s[0].isdigit() and '.' in s:
            parts = s.split('.')
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return s
    for offset, s in reversed(strings):
        if '.' in s and not s.startswith('/') and not s.startswith('Accept'):
            if not s.startswith('Mozilla') and not s.startswith('User'):
                if any(s.endswith(tld) for tld in ['.com','.net','.org','.io','.xyz','.top','.cn']):
                    return s
    return None


def find_port_cs(data):
    """提取端口 — CS: mov r8d, imm32 (41 B8 XX XX XX XX)"""
    for i in range(len(data) - 6):
        if data[i] == 0x41 and data[i+1] == 0xB8:
            p = int.from_bytes(data[i+2:i+6], 'little')
            if 1 <= p <= 65535 and p not in (4096, 8192, 0x1000, 0x2000):
                return p
    return 80


def find_uri_cs(strings):
    """提取 URI (CS stager)"""
    for offset, s in strings:
        if s.startswith('/') and len(s) > 1:
            return s
    return '/'


def find_user_agent_cs(strings):
    """提取 User-Agent (CS stager)"""
    for offset, s in strings:
        if 'Mozilla' in s:
            if s.startswith('User-Agent: '):
                return s[len('User-Agent: '):]
            return s
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def find_entry_offset_cs(data):
    """提取反射加载器入口偏移 (48 05 XX XX XX XX 50 C3)"""
    for i in range(len(data) - 8):
        if data[i] == 0x48 and data[i+1] == 0x05 and data[i+6] == 0x50 and data[i+7] == 0xC3:
            return int.from_bytes(data[i+2:i+6], 'little')
    return 0


def detect_protocol_cs(data, port):
    """检测协议: HTTP 或 HTTPS (CS stager)"""
    for i in range(len(data) - 4):
        if data[i] == 0x68:
            val = int.from_bytes(data[i+1:i+5], 'little')
            if val & 0x00800000:
                return 'https'
    if port == 443:
        return 'https'
    return 'http'


def find_extra_headers_cs(strings):
    """提取额外的 HTTP headers (CS stager)"""
    headers = []
    for offset, s in strings:
        if ':' in s and any(s.startswith(h) for h in ['Accept', 'Cookie', 'Referer', 'Host']):
            headers.append(s)
    return headers


# ═══════════════════════════════════════════════════════════
# 类型检测与分发
# ═══════════════════════════════════════════════════════════

def detect_stager_type(strings):
    """检测 CS stager"""
    cs_host = find_host_cs(strings)
    if cs_host:
        cs_signals = 0
        for _, s in strings:
            if 'Mozilla' in s:
                cs_signals += 1
            if 'InternetConnect' in s or 'wininet' in s.lower():
                cs_signals += 1
            if 'Accept' in s:
                cs_signals += 1
        if cs_signals >= 1 or cs_host:
            return 'cs'
    return None


# ═══════════════════════════════════════════════════════════
# 主解析函数
# ═══════════════════════════════════════════════════════════

def parse_stager(filepath):
    """解析 CS stager shellcode，提取 C2 信息"""
    with open(filepath, 'rb') as f:
        data = f.read()

    strings = extract_strings(data)
    stager_type = detect_stager_type(strings)

    if stager_type is None:
        print("ERROR: Cannot identify stager type (not CS stager)", file=sys.stderr)
        sys.exit(1)

    host = find_host_cs(strings)
    port = find_port_cs(data)
    protocol = detect_protocol_cs(data, port)
    uri = find_uri_cs(strings)
    user_agent = find_user_agent_cs(strings)
    entry_offset = find_entry_offset_cs(data)
    headers = find_extra_headers_cs(strings)

    if not host:
        print("ERROR: Cannot find host/IP in CS stager", file=sys.stderr)
        sys.exit(1)
    if entry_offset == 0:
        print("ERROR: Cannot find reflective loader entry offset in CS stager", file=sys.stderr)
        sys.exit(1)

    url = f"{protocol}://{host}:{port}{uri}"

    return {
        "type": f"cs-{protocol}",
        "protocol": protocol,
        "host": host,
        "port": port,
        "uri": uri,
        "url": url,
        "user_agent": user_agent,
        "entry_offset": entry_offset,
        "headers": headers,
        "file_size": len(data),
    }


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <stager.bin>", file=sys.stderr)
        sys.exit(1)

    result = parse_stager(sys.argv[1])
    print(json.dumps(result, indent=2))

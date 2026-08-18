#!/usr/bin/env python3
"""编译后 PE 验证：检查 EXE 文件有效性和敏感字符串泄露
用法: <python命令> verify_pe.py <exe_path>
"""
import sys

if len(sys.argv) < 2:
    print(f"用法: {sys.argv[0]} <exe_path>")
    sys.exit(1)

exe_path = sys.argv[1]

with open(exe_path, 'rb') as f:
    data = f.read()

print(f'File size: {len(data)} bytes')
if data[:2] != b'MZ':
    print('FATAL: Not a valid PE file')
    sys.exit(1)

# Go runtime 不可避免的泄露（kernel32 基础 API）
go_runtime_leaks = {b'kernel32.dll', b'VirtualAlloc', b'CreateThread', b'WaitForSingleObject'}
# 用户代码应隐藏的 API（通过 XOR 编码动态加载）
user_hidden = {
    b'VirtualProtect', b'RtlMoveMemory', b'GlobalMemoryStatusEx',
    b'ntdll.dll', b'AmsiScanBuffer', b'EtwEventWrite',
    b'NtProtectVirtualMemory', b'NtAllocateVirtualMemory',
}

go_leaked = []
user_leaked = []
for s in go_runtime_leaks:
    count = data.count(s)
    if count > 0:
        go_leaked.append(f'{s.decode()}: {count}x')
for s in user_hidden:
    count = data.count(s)
    if count > 0:
        user_leaked.append(f'{s.decode()}: {count}x')

if go_leaked:
    print('INFO: Go runtime strings found (normal for Go binaries):')
    for l in go_leaked:
        print(f'  {l}')

if user_leaked:
    print('WARN: User-hidden strings found in PE (should be XOR-encoded):')
    for l in user_leaked:
        print(f'  {l}')
    print('  Action: Check XOR encoding of these API names in Go source.')
else:
    print('OK: All user-hidden API strings are obfuscated')

print('PE verification complete.')

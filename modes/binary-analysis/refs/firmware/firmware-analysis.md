---
name: firmware-analysis
description: Firmware malware analysis — extraction, filesystem inspection, UEFI/BIOS rootkit detection, embedded binary reverse engineering, QEMU emulation
---

# Firmware Analysis

## Purpose
Self-contained guide for analyzing firmware images for embedded malware, backdoors, and unauthorized modifications in routers, IoT devices, UEFI/BIOS, and embedded systems.

## Technique checklist

### 1. Firmware extraction and identification
- Binwalk signature scanning for embedded filesystems and compressed data
- Recursive extraction of nested components
- Entropy analysis for encrypted/compressed regions
- Filesystem identification: SquashFS, JFFS2, CramFS, ext4, UBI
- Bootloader analysis (U-Boot, GRUB, custom)

### 2. Filesystem analysis
- Directory structure enumeration and anomaly detection
- SUID binary identification
- Startup script inspection (rcS, inittab, rc.d)
- Hardcoded credential search (passwords, SSH keys, tokens)
- Unauthorized SSH key detection
- Cron-based persistence (reverse shells, callback timers)
- Network configuration backdoors (iptables rules, netcat)
- ELF binary identification and architecture classification

### 3. Binary reverse engineering (embedded)
- Architecture detection: ARM, MIPS, AARCH64, x86
- String extraction for IoC discovery (IPs, URLs, shell commands)
- Hash comparison against known-good firmware baseline
- Ghidra disassembly with correct architecture profile
- radare2 quick triage (afl, pdf, iz)
- Shared library hooking detection (.so modification)

### 4. UEFI/BIOS firmware analysis
- UEFITool firmware volume parsing and module extraction
- chipsec platform security assessment
- SPI Flash dump and integrity verification
- Secure Boot status audit
- S3 Boot Script integrity check
- YARA scanning for known UEFI malware signatures

### 5. Known UEFI malware families
- LoJax (APT28): First in-the-wild UEFI rootkit, SPI Flash modification
- MosaicRegressor: Modular UEFI framework, multi-payload delivery
- CosmicStrand: UEFI firmware rootkit, kernel modification during boot
- BlackLotus: UEFI bootkit bypassing Windows 11 Secure Boot
- ESPecter: EFI System Partition bootkit, boot manager modification
- MoonBounce: SPI Flash implant, CORE_DXE module modification
- FinSpy UEFI: Surveillance software with UEFI persistence

### 6. Dynamic analysis via emulation
- QEMU user-mode emulation with chroot
- firmadyne automated firmware simulation
- Network service enumeration in emulated environment
- Traffic capture and C2 communication detection
- Firmware Analysis Toolkit (FAT) automation

### 7. Reporting
- Firmware metadata (vendor, model, version, build date)
- Extraction results (filesystem type, kernel version, architecture)
- Modified files compared to known-good baseline
- Backdoor binary analysis and RE findings
- Hardcoded credentials and unauthorized access mechanisms
- IoC extraction (IPs, domains, file hashes, SSH keys)
- Remediation recommendations

## Decision tree

```
Firmware sample
├─ IoT/embedded device?
│  ├─ Extract with binwalk -eM
│  ├─ Analyze filesystem for backdoors
│  ├─ RE suspicious binaries with Ghidra (ARM/MIPS)
│  └─ Emulate with QEMU/firmadyne
├─ UEFI/BIOS firmware?
│  ├─ Parse with UEFITool
│  ├─ chipsec security audit
│  ├─ Compare against vendor baseline hash
│  ├─ YARA scan for known UEFI malware
│  └─ Check Secure Boot and SPI write protection
└─ Modified firmware?
   ├─ Hash comparison against known-good
   ├─ Diff filesystem contents
   ├─ Check startup scripts and cron
   └─ Analyze new/modified binaries
```

## Tools table

| Tool | Purpose | Stage |
|------|---------|-------|
| binwalk | Firmware extraction and analysis | Extraction |
| UEFITool | UEFI firmware parsing | UEFI |
| chipsec | Platform security assessment | UEFI/Hardware |
| Ghidra | Embedded binary RE (ARM/MIPS) | Analysis |
| radare2 | Quick binary triage | Analysis |
| QEMU | Firmware emulation | Dynamic |
| firmadyne | Automated firmware simulation | Dynamic |
| YARA | Signature scanning | Detection |

## Detection indicators
- Firmware hash mismatch against vendor baseline
- Unknown ELF binaries not present in clean firmware
- Modified startup scripts with reverse shell or callback entries
- Unauthorized SSH keys in authorized_keys
- New SUID binaries or modified shared libraries
- SPI Flash modifications outside official updates
- UEFI modules not matching vendor DXE drivers
- Entropy anomalies indicating encrypted payload regions

## Firmware Extraction Workflow

### Extract and Identify Components
```bash
# Identify embedded filesystems and compressed data
binwalk firmware.bin

# Extract all identified components
binwalk -e firmware.bin

# Recursive extraction with signature scanning
binwalk -eM firmware.bin

# Entropy analysis for encrypted/compressed regions
binwalk -E firmware.bin

# Handle SquashFS filesystems
unsquashfs _firmware.bin.extracted/squashfs-root.img
ls squashfs-root/
```

### Filesystem Analysis
```bash
# Search for suspicious files
find squashfs-root/ -name "*.sh" -exec ls -la {} \;
find squashfs-root/ -perm -4000 -type f          # SUID binaries
find squashfs-root/ -name "*.so" -newer squashfs-root/bin/busybox

# Check startup scripts for backdoors
cat squashfs-root/etc/init.d/rcS
cat squashfs-root/etc/inittab

# Search hardcoded credentials
grep -rn "password\|passwd\|secret\|key\|token" squashfs-root/etc/ 2>/dev/null
grep -rn "root:" squashfs-root/etc/shadow 2>/dev/null

# Check unauthorized SSH keys
find squashfs-root/ -name "authorized_keys" -exec cat {} \;

# Check cron for reverse shells
find squashfs-root/ -name "crontab" -o -name "cron*" | xargs cat 2>/dev/null

# Identify all ELF binaries
find squashfs-root/ -type f -exec file {} \; | grep ELF
```

### Reverse Engineering Suspicious Binaries
```bash
# Architecture identification
file squashfs-root/usr/bin/suspicious_binary

# String extraction for IoC
strings squashfs-root/usr/bin/suspicious_binary | grep -iE "http|ip|port|shell|connect|exec"

# Hash comparison against baseline
sha256sum squashfs-root/usr/bin/* > current_hashes.txt
# diff baseline_hashes.txt current_hashes.txt

# radare2 quick triage
r2 -A squashfs-root/usr/bin/suspicious_binary
# Commands: afl (functions), pdf @main (disasm main), iz (strings)
```

### UEFI/BIOS Analysis
```bash
# chipsec platform security assessment
python chipsec_main.py -m common.bios_wp          # BIOS write protection
python chipsec_main.py -m common.spi_lock          # SPI Flash lock
python chipsec_main.py -m common.secureboot        # Secure Boot status
python chipsec_main.py -m common.uefi.s3bootscript # S3 resume script

# Dump UEFI firmware from live system
python chipsec_util.py spi dump firmware_dump.rom

# YARA scan for known UEFI malware
yara -r uefi_malware_rules.yar firmware_dump.rom
```

### QEMU Firmware Emulation
```bash
# Mount extracted filesystem
sudo mount -o loop squashfs-root.img /mnt/firmware

# QEMU user-mode emulation with chroot
sudo cp /usr/bin/qemu-arm-static /mnt/firmware/usr/bin/
sudo chroot /mnt/firmware /bin/sh

# Automated emulation with firmadyne
python3 fat.py firmware.bin

# Network analysis in emulated environment
nmap -sV localhost -p 1-65535
tcpdump -i tap0 -w firmware_traffic.pcap
```

## Analysis Report Template
```
Firmware Malware Analysis Report
===================================
Device:            [vendor/model]
Firmware version:  [version]
Architecture:      [ARM/MIPS/x86]
Filesystem:        [SquashFS/JFFS2/etc.]
Extraction method: [UART/JTAG/binwalk]

Integrity Check
Vendor hash:       [known-good SHA-256]
Analyzed hash:     [actual SHA-256]
Modified files:    [count and list]

Backdoor Findings
[!] New/modified binaries with analysis
[!] Hardcoded credentials discovered
[!] Unauthorized SSH keys
[!] Persistence mechanisms (cron, rcS)

Extracted IoCs
C2 IPs/domains:    [list]
File hashes:       [list]
SSH keys:          [list]

Remediation
1. Reflash with clean vendor firmware
2. Change all device credentials
3. Upgrade to latest firmware version
4. Monitor for re-compromise indicators
```

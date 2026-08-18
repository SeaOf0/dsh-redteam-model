---
name: threat-hunting-procedures
description: >-
  Hypothesis-driven threat hunting procedures covering persistence, credential access, lateral movement, C2 beaconing, defense evasion, data exfiltration, and supply chain compromise detection across endpoint, network, and identity telemetry.
---

# SKILL: Threat Hunting Procedures

## 1. QUICK START

1. Form a hypothesis based on threat intelligence or ATT&CK technique.
2. Identify required data sources for the hypothesis.
3. Develop structured queries across relevant telemetry.
4. Execute hunts in phases: broad sweep, focused analysis, deep investigation.
5. Document findings: true positive, false positive, or no evidence found.
6. Convert confirmed detections into persistent detection rules.

## 2. RULES / METHODOLOGY

### 2.1 Hunting Methodology

```
Hypothesis -> Data Collection -> Analysis -> Conclusion -> Detection Rule
     |              |               |            |              |
     v              v               v            v              v
 "APT29 may      Pull Sysmon,    Query for     Confirmed     Sigma rule
  use WMI for    Auth, DNS      WMI event     T1546.003     deployed to
  persistence"   logs           subscription                production
```

### 2.2 Hunt Categories by ATT&CK Tactic

#### Persistence (TA0003)

**Registry Run Key Persistence (T1547.001)**
```spl
index=sysmon EventCode=12 OR EventCode=13
| where match(TargetObject, "(?i)(Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run|RunOnce|RunServices)")
| where NOT match(Image, "(?i)(svchost|msiexec|wisptis|ctfmon|googledrivesync|onedrive|dropbox)\.exe")
| table _time Computer Image TargetObject Details User
```

**Scheduled Task Persistence (T1053.005)**
```spl
index=wineventlog (EventCode=4698 OR EventCode=4702)
| where match(TaskContent, "(?i)(powershell|cmd|wscript|cscript|mshta|certutil|bitsadmin)")
| table _time Computer TaskName TaskContent SubjectUserName
```

**WMI Subscription Persistence (T1546.003)**
```spl
index=sysmon EventCode=19 OR EventCode=20 OR EventCode=21
| table _time Computer EventNamespace Query Operation User
```

**Startup Folder Persistence (T1547.001)**
```spl
index=sysmon EventCode=11
| where match(TargetFilename, "(?i)(Startup|Startup\\\\|AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup)")
| where NOT match(Image, "(?i)(msiexec|explorer)\.exe")
| table _time Computer Image TargetFilename User
```

**Service Installation (T1543.003)**
```spl
index=wineventlog EventCode=7045 OR EventCode=4697
| where match(ServiceFileName, "(?i)(C:\\\\Users|C:\\\\ProgramData|C:\\\\Temp|\\AppData)")
| table _time Computer ServiceName ServiceFileName ServiceStartType
```

**DNS-Based Persistence (T1136.004)**
```spl
index=dns query_type="TXT"
| where len(query) > 50
| stats count by src_ip query response
| where count > 10
```

#### Credential Access (TA0006)

**LSASS Access (T1003.001)** - See edr-telemetry-analysis leaf

**DCSync Attack (T1003.006)**
```spl
index=wineventlog EventCode=4662
| where match(Properties, ".*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2.*")
    OR match(Properties, ".*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*")
| where NOT match(SubjectUserName, ".*\\$$")
| table _time Computer SubjectUserName SubjectDomainName
```

**Credential Stuffing (T1110.004)**
```spl
index=auth action=failure
| bin _time span=5m
| stats count as failures dc(user) as unique_accounts by src_ip _time
| where failures > 20 AND unique_accounts > 5
| eval attack_type="CREDENTIAL_STUFFING"
```

#### Lateral Movement (TA0008)

**DCOM Lateral Movement (T1021.003)**
```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(mmc\.exe|eventvwr\.exe|compmgmt\.exe)")
    AND match(ParentImage, "(?i)(svchost\.exe)")
    AND match(CommandLine, "(?i)-Embedding")
| table _time Computer ParentImage Image CommandLine User
```

**WMI Lateral Movement (T1047)**
```spl
index=sysmon EventCode=1
| where Image="*\\wmiprvse.exe" AND ParentImage="*\\svchost.exe"
| where match(CommandLine, "(?i)(cmd|powershell|cscript|wscript)")
| table _time Computer CommandLine User TargetComputer
```

**Account Manipulation (T1098)**
```spl
index=wineventlog (EventCode=4720 OR EventCode=4722 OR EventCode=4738 OR EventCode=4740 OR EventCode=4767)
| where NOT match(SubjectUserName, "(?i)(MSOL_|Adminitrator|SVC_)")
| table _time Computer SubjectUserName TargetUserName EventCode TaskCategory
```

#### Command and Control (TA0011)

**C2 Beaconing - Frequency Analysis**
```spl
index=proxy OR index=firewall
| where dest_ip=<external_ip>
| stats count as connections, dc(dest_port) as ports,
    avg(bytes_out) as avg_out, stdev(_time) as time_stdev
    by src_ip dest_ip
| where time_stdev < 100 AND connections > 50
| eval beaconing_score=round(connections/time_stdev, 2)
| where beaconing_score > 5
```

**Cobalt Strike Beacon Detection**
```spl
index=sysmon EventCode=3
| where match(Image, "(?i)(rundll32|dllhost|svchost|wmiprvse|powershell)\.exe")
    AND dest_port IN ("443", "80", "8080", "8443")
| lookup threatintel_lookup ip as dest_ip OUTPUT threat_type
| where isnotnull(threat_type) OR match(dest_hostname, "(?i)(cdn|cloud|update)")
| table _time Computer Image dest_ip dest_port dest_hostname bytes_out
```

**Domain Fronting (T1090.004)**
```spl
index=proxy
| where match(http_host, "(?i)(cloudfront|azureedge|cloudapp|akamaized)")
| stats count by src_ip http_host dest_ip
| where count > 100
```

#### Defense Evasion (TA0005)

**Timestomping (T1070.006)**
```spl
index=sysmon EventCode=2
| eval file_modified=strptime(UtcTime, "%Y-%m-%d %H:%M:%S")
| eval created_gap=abs(file_modified - _time)
| where created_gap > 86400 AND match(TargetFilename, "(?i)(\.exe|\.dll|\.ps1|\.bat)")
| table _time Computer Image TargetFilename PreviousCreationUtcTime
```

**Process Injection (T1055)**
```spl
index=sysmon EventCode=8
| where NOT match(SourceImage, "(?i)(svchost|csrss|lsass|wininit|services)\.exe")
| table _time Computer SourceImage TargetImage StartAddress StartFunction
```

#### Exfiltration (TA0010)

**Data Staging Before Exfiltration**
```spl
index=sysmon EventCode=11
| where match(TargetFilename, "(?i)(\\\\Temp\\\\|\\\\tmp\\\\|\\\\Public\\\\|\\\\Downloads\\\\)")
    AND match(TargetFilename, "(?i)(\.zip|\.rar|\.7z|\.tar|\.gz)")
| stats count sum(filesize) as total_bytes by Computer User TargetFilename
| where total_bytes > 10485760
```

**Data Exfiltration Indicators**
```spl
index=proxy action=allowed direction=outbound
| stats sum(bytes_out) as total_bytes dc(dest_ip) as unique_dests by src_ip user
| eval total_mb=round(total_bytes/1048576, 2)
| where total_mb > 500 OR unique_dests > 50
```

#### Other Hunt Types

**Shadow Copy Deletion (T1490)**
```spl
index=wineventlog EventCode=1 Image="*\\vssadmin.exe"
    CommandLine="*delete*shadows*"
| table _time Computer CommandLine User
```

**Unusual Service Installations**
```spl
index=wineventlog EventCode=7045
| where NOT match(ServiceName, "(?i)(Windows|Microsoft|Google|Adobe|CrowdStrike)")
| table _time Computer ServiceName ServiceFileName ServiceType
```

**Webshell Activity**
```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)(w3wp|apache|nginx|httpd|tomcat)")
    AND match(Image, "(?i)(cmd|powershell|wscript|cscript)")
| table _time Computer ParentImage Image CommandLine
```

**Supply Chain Compromise**
```spl
index=sysmon EventCode=7 OR EventCode=1
| where match(ImageLoaded, "(?i)(\\\\Temp\\\\|\\\\Downloads\\\\|\\\\AppData\\\\)")
    AND match(ImageLoaded, "(?i)\.dll$")
| stats count by Computer Image ImageLoaded Signed
| where Signed="false"
```

### 2.3 APT Hunting Framework

For advanced persistent threat hunting, apply structured methodology:

1. **Reconnaissance phase**: Map environment, identify high-value targets, baseline normal activity.
2. **Initial access hunting**: Monitor for phishing indicators, exploit attempts, supply chain vectors.
3. **Persistence hunting**: Search for all known persistence mechanisms across endpoints.
4. **C2 hunting**: Frequency analysis on network connections, JA3 fingerprinting, beaconing detection.
5. **Lateral movement hunting**: Track credential use patterns, remote sessions, abnormal authentication.
6. **Exfiltration hunting**: Monitor data volumes, unusual destinations, staging activity.

## 3. EXAMPLES

### Example 1: Comprehensive Persistence Hunt

```spl
index=sysmon (EventCode=12 OR EventCode=13 OR EventCode=1 OR EventCode=11)
| where (
    match(TargetObject, "(?i)(CurrentVersion\\\\Run|RunOnce|Services|Scheduled|WMI)") OR
    match(TargetFilename, "(?i)(Startup|autorun|\.job|\.vbs|\.ps1)") OR
    match(CommandLine, "(?i)(schtasks|sc\.exe create|reg\.exe add.*Run|wmic.*creatre)")
)
| where NOT match(Image, "(?i)(msiexec|svchost|explorer|system)\.exe")
| eval hunt_type=case(
    match(TargetObject, "(?i)Run"), "REGISTRY_RUN_KEY",
    match(TargetObject, "(?i)Services"), "SERVICE_PERSISTENCE",
    match(CommandLine, "(?i)schtasks"), "SCHEDULED_TASK",
    match(TargetFilename, "(?i)Startup"), "STARTUP_FOLDER",
    true(), "OTHER"
)
| table _time Computer hunt_type Image TargetObject TargetFilename CommandLine User
```

### Example 2: Network Beaconing Hunt (Zeek DNS)

```spl
index=dns
| stats count as queries, dc(query) as unique_domains,
    avg(len(query)) as avg_query_len,
    stdev(_time) as time_variance
    by src_ip
| where queries > 100 AND time_variance < 300 AND avg_query_len > 30
| eval beaconing_probability=round(queries / (time_variance + 1), 2)
| where beaconing_probability > 0.5
| eval hunt_finding="POTENTIAL_DNS_BEACONING"
| table src_ip queries unique_domains avg_query_len beaconing_probability
```

## 4. VALIDATION

### Hunt Documentation Template

```
Hunt ID: TH-[CATEGORY]-[DATE]-[SEQ]
Hypothesis: [What we're looking for and why]
ATT&CK Technique: TXXXX.XXX
Data Sources: [List required telemetry]
Time Range: [Hunt window]
Queries Used: [SPL/KQL/Sigma used]
Results:
  - True Positives: [N findings confirmed malicious]
  - False Positives: [N findings confirmed benign]
  - No Evidence Found: [No matches in environment]
Conclusion: [Summary of hunt outcome]
Detection Rule: [Link to new rule if TP found]
```

### Hunt Metrics

- Hunts completed per month (target: 8-12)
- Average time per hunt (target: 4-8 hours)
- True positive rate (target: > 30% of hunts yield findings)
- Detection rules created from hunts (target: > 50% of TP hunts produce rules)
- ATT&CK coverage improvement from hunts

## 5. REFERENCES

- **MITRE ATT&CK**: https://attack.mitre.org/ -- Technique taxonomy for hunt hypothesis generation
- **SQRRL Hunting Methodology**: Hypothesis-driven hunting framework
- **Cyber Kill Chain**: https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html
- **SigmaHQ**: https://github.com/SigmaHQ/sigma -- Convert hunt queries to persistent rules
- **Zeek**: https://zeek.org/ -- Network observation for C2 and exfiltration hunts
- **Velociraptor**: https://docs.velociraptor.app/ -- Endpoint artifact collection for hunts
- **MITRE ATT&CK Navigator**: https://mitre-attack.github.io/attack-navigator/ -- Coverage tracking

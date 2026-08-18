---
name: suricata-snort-rules
description: >-
  Write, tune, and deploy Suricata and Snort IDS/IPS rules for network threat detection. Covers rule syntax, protocol-aware detection, JA3/JA3S fingerprinting, EVE JSON logging, performance tuning, and SIEM integration.
---

# SKILL: Suricata / Snort Rules

## 1. QUICK START

1. Define the network threat or behavior to detect.
2. Write a detection rule with correct header (action, protocol, source/dest, ports).
3. Add rule options: content matches, flow direction, thresholds, metadata.
4. Validate syntax with `suricata -T` or `snort -T`.
5. Test against PCAP samples, tune false positives, deploy to production sensor.

## 2. RULES / METHODOLOGY

### 2.1 Rule Header Syntax

```
action protocol source_ip source_port -> dest_ip dest_port (options;)
```

| Field | Values |
|-------|--------|
| Action | `alert`, `drop` (IPS), `pass`, `reject` |
| Protocol | `tcp`, `udp`, `icmp`, `http`, `dns`, `tls`, `smb`, `ssh` |
| IP/Port | `$HOME_NET`, `$EXTERNAL_NET`, `any`, specific IPs, CIDR ranges |
| Direction | `->` (unidirectional), `<>` (bidirectional) |

### 2.2 Suricata Rule Options (Key Keywords)

```
msg:"rule description";           # Alert message
content:"pattern";                # Content match (case sensitive)
nocase;                           # Case insensitive content match
offset:N;                         # Start search at byte offset N
depth:N;                          # Search only N bytes deep
distance:N;                       # Pattern must be N bytes after previous match
within:N;                         # Pattern must be within N bytes of previous match
flow:to_server,established;       # Flow direction and state
sid:XXXXXXX;                      # Unique rule ID (1000000+ for local rules)
rev:N;                            # Rule revision number
classtype:category;               # Alert classification
priority:N;                       # Priority (1=highest)
threshold:type both, track by_src, count N, seconds M;  # Rate limiting
reference:url,https://...;        # External reference
```

### 2.3 Protocol-Aware Detection (Suricata App-Layer)

```
# HTTP detection
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP malicious user-agent"; \
    http.user_agent; content:"curl/"; \
    sid:9000001; rev:1;)

# DNS detection
alert dns $HOME_NET any -> any any (msg:"DNS tunneling long query"; \
    dns.query; content:"."; offset:50; \
    sid:9000002; rev:1;)

# TLS JA3 fingerprinting
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Cobalt Strike JA3 hash"; \
    ja3.hash; content:"72a589da586844d7f0818ce684948eea"; \
    sid:9000003; rev:1;)

# SSH brute force
alert ssh $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH brute force"; \
    flow:to_server; \
    threshold:type both, track by_src, count 10, seconds 60; \
    sid:9000004; rev:1;)

# SMB detection
alert smb any any -> $HOME_NET 445 (msg:"SMB Mimikatz execution"; \
    flow:established,to_server; \
    content:"mimikatz"; nocase; \
    sid:9000005; rev:1;)

# File extraction
alert http any any -> any any (msg:"Suspicious EXE download"; \
    filestore; filemagic; \
    sid:9000006; rev:1;)
```

### 2.4 Snort 3 Rule Format (Lua Configuration)

```lua
-- Snort 3 uses Lua for configuration, rules similar format
-- snort.lua
HOME_NET = '10.10.0.0/16'
EXTERNAL_NET = '!$HOME_NET'

ips = {
    enable_builtin_rules = true,
    include = RULE_PATH .. '/local.rules',
    variables = {
        ports = {
            HTTP_PORTS = '80 8080 8443',
            SSH_PORTS = '22',
            DNS_PORTS = '53'
        }
    }
}
```

### 2.5 Suricata Configuration Essentials

```yaml
# /etc/suricata/suricata.yaml
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"

af-packet:
  - interface: eth1
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    use-mmap: yes
    ring-size: 200000

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      community-id: true
      types:
        - alert:
            payload: yes
            payload-printable: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: yes
            force-hash: [md5, sha256]
        - anomaly:
            enabled: yes

app-layer:
  protocols:
    tls:
      ja3-fingerprints: yes
    ssh:
      hassh: yes
```

### 2.6 Rule Performance Tuning

1. **Use `flow:established`** to skip connection setup packets.
2. **Anchor content matches** with `offset` and `depth` to limit search space.
3. **Use specific protocols** (`http`, `dns`, `tls`) instead of raw `tcp`/`udp`.
4. **Apply thresholds** to high-frequency rules to prevent alert flooding.
5. **Suppress known false positives** per source/destination.
6. **Disable unused rule categories** to reduce processing overhead.

### 2.7 HIDS Integration (Wazuh/OSSEC)

Complement network IDS with host-based detection:

- **File Integrity Monitoring (FIM)**: Track changes to critical system binaries and configs.
- **Rootkit Detection**: Scan for known rootkit signatures and suspicious processes.
- **Log Analysis Rules**: Parse authentication, process creation, and service events.
- **Active Response**: Auto-block IPs after brute force or disable accounts after credential dump.

## 3. EXAMPLES

### Example 1: Reverse Shell Detection

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 ( \
    msg:"LOCAL Suspected Reverse Shell on Port 4444"; \
    flow:established,to_server; \
    content:"/bin/sh"; nocase; \
    sid:1000001; rev:1; \
    classtype:trojan-activity; priority:1;)
```

### Example 2: DNS Tunneling via Query Length

```
alert dns $HOME_NET any -> any any ( \
    msg:"LOCAL DNS Tunneling - Long Query Name"; \
    dns.query; content:"."; offset:50; \
    sid:1000003; rev:1; \
    classtype:policy-violation; priority:2;)
```

### Example 3: Cobalt Strike C2 via JA3

```
alert tls $HOME_NET any -> $EXTERNAL_NET any ( \
    msg:"LOCAL Cobalt Strike JA3 Hash Detected"; \
    ja3.hash; content:"72a589da586844d7f0818ce684948eea"; \
    sid:1000010; rev:1; \
    classtype:trojan-activity; priority:1; \
    reference:url,https://attack.mitre.org/software/S0154/;)
```

### Example 4: Port Scan Detection with Threshold

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any ( \
    msg:"LOCAL Port Scan SYN Flood"; \
    flow:stateless; flags:S,12; \
    threshold:type both, track by_src, count 100, seconds 10; \
    sid:1000005; rev:1; \
    classtype:attempted-recon; priority:2;)
```

### Example 5: Data Exfiltration via Large HTTP POST

```
alert http $HOME_NET any -> $EXTERNAL_NET any ( \
    msg:"LOCAL Large HTTP POST Upload - Potential Exfiltration"; \
    flow:to_server,established; \
    http.method; content:"POST"; \
    threshold:type both, track by_src, count 5, seconds 300; \
    sid:1000020; rev:1; \
    classtype:policy-violation; priority:2;)
```

### Example 6: SIEM Integration (Elastic)

```bash
# Filebeat Suricata module
sudo tee /etc/filebeat/modules.d/suricata.yml << 'EOF'
- module: suricata
  eve:
    enabled: true
    var.paths: ["/var/log/suricata/eve.json"]
EOF

# Parse and analyze alerts
cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert") | \
    [.timestamp, .src_ip, .dest_ip, .alert.signature, .alert.severity] | @csv'
```

## 4. VALIDATION

### Configuration Validation

```bash
# Suricata: validate configuration and rules
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Snort 3: validate configuration
snort -c /usr/local/etc/snort/snort.lua -T

# Test against PCAP
suricata -c /etc/suricata/suricata.yaml -r test_traffic.pcap -l /tmp/test/
snort -c snort.lua -r test_traffic.pcap
```

### Rule Testing Workflow

```bash
# 1. Validate syntax
suricata -T -c /etc/suricata/suricata.yaml

# 2. Test against known-malicious PCAP
suricata -r malicious.pcap -l /tmp/test/

# 3. Check alerts generated
cat /tmp/test/eve.json | jq 'select(.event_type=="alert")'

# 4. Test false positive rate with benign traffic
suricata -r normal_traffic.pcap -l /tmp/baseline/
# Verify: no alerts from expected rules

# 5. Performance monitoring
cat /var/log/suricata/eve.json | jq 'select(.event_type=="stats") | .stats.capture'
# kernel_drops must be 0
```

### Tuning and False Positive Reduction

```bash
# Identify top firing rules
grep -oP 'sid:\d+' /var/log/snort/alert_fast.txt | sort | uniq -c | sort -rn | head -20

# Suppress noisy rules per source
# suppress.conf:
# suppress gen_id 1, sig_id 2100498, track by_src, ip 10.10.1.100
```

## 5. REFERENCES

- **Suricata Documentation**: https://suricata.readthedocs.io/ -- Official Suricata reference
- **Snort 3 Documentation**: https://snort.org/documents -- Official Snort reference
- **Emerging Threats Rules**: https://rules.emergingthreats.net/ -- Community and Pro rule sets
- **Suricata JA3**: https://suricata.readthedocs.io/en/stable/rules/tls-keywords.html -- TLS fingerprinting
- **Community ID**: https://github.com/corelight/community-id-spec -- Standardized flow identification
- **suricata-update**: https://github.com/OISF/suricata-update -- Rule management tool
- **Wazuh HIDS**: https://wazuh.com/ -- Host-based intrusion detection for endpoint coverage

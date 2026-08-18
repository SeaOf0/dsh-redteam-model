---
name: evidence-first-audit
description: Evidence-first security code auditing workflow. Use when you need to audit a repository or selected files for vulnerabilities, plan and execute a recon-analysis-verification-report workflow, run local static/security tools without Docker, normalize findings, verify source-to-sink evidence, or produce an evidence-grounded code audit report.
---

# 证据优先代码审计（Evidence-First Audit）

## Core Posture

Use the four-phase loop: **recon -> analysis -> verification -> report**.

Prioritize a small number of well-evidenced findings over broad noisy output. Never report a vulnerability until the file exists, the referenced code was read from the target, and the line number or location is grounded in the target repository.

Stay Docker-free. Use only local files, built-in shell/search tools, and user-provided security tools already on `PATH` or placed under the skill's optional `tools/` directory. Do not install or download tools for the user.

## Quick Start

From a target repository:

```bash
python <skill>/scripts/recon_snapshot.py /path/to/repo --out audit-recon.json
python <skill>/scripts/local_security_scan.py /path/to/repo --out audit-scan.json --markdown audit-scan.md
```

If external tools are missing, the scan script records them as missing and still runs the built-in pattern pass. If a tool may require network access, run it only when the user explicitly allows that for the audit.

## Workflow

1. **Scope**
   - Confirm the target path, selected files, exclusions, and whether the task is a quick triage or a deeper audit.
   - Respect existing user changes and avoid modifying the target repo unless the user asks for fixes.
   - Set default exclusions: `.git`, `node_modules`, `dist`, `build`, `coverage`, `.venv`, `venv`, `__pycache__`, `target`, `vendor`.

2. **Recon**
   - Run `scripts/recon_snapshot.py` or manually collect the same facts: languages, frameworks, dependency manifests, entry points, auth/payment/upload/admin areas, and high-risk APIs.
   - Read only representative files at first. Use semantic reasoning and precise searches rather than recursively dumping the project.
   - Hand off a concise map: tech stack, entry points, high-risk areas, recommended tools, and initial questions.

3. **Analysis**
   - Run available local tools with `scripts/local_security_scan.py`, then inspect the highest-signal results manually.
   - For each suspected issue, trace **source -> transforms/guards -> sink**. Treat scanner hits as leads, not proof.
   - Use the vulnerability patterns in [vulnerability-patterns.md](references/vulnerability-patterns.md) when choosing sources, sinks, bypasses, and remediation.
   - Use [framework-checklists.md](references/framework-checklists.md) for Django, Flask, FastAPI, Express, React, and Supabase-specific checks.

4. **Verification**
   - Re-read the exact file and surrounding lines before promoting a finding.
   - Confirm whether validation, escaping, authorization, parameterization, allowlists, or framework defaults break the exploit path.
   - When useful, write a small local harness that mocks dependencies and demonstrates the property being tested. Keep it inert and local; do not require a running service or Docker.
   - Mark uncertain findings honestly instead of inflating confidence.

5. **Report**
   - Lead with confirmed and likely issues, ordered by severity and exploitability.
   - Include evidence: file, line, code snippet, data flow, impact, verification method, confidence, and concrete remediation.
   - Separate tool coverage and missing-tool gaps from actual vulnerabilities.

## Finding Schema

Use this shape for normalized findings:

```json
{
  "vulnerability_type": "sql_injection",
  "severity": "critical|high|medium|low",
  "title": "Short specific title",
  "file_path": "relative/path.ext",
  "line_start": 42,
  "code_snippet": "code read from the target",
  "source": "user-controlled input",
  "sink": "dangerous API or privileged operation",
  "guards": ["validation or escaping observed"],
  "verification": "confirmed|likely|uncertain|false_positive",
  "confidence": 0.0,
  "impact": "practical impact",
  "recommendation": "specific fix"
}
```

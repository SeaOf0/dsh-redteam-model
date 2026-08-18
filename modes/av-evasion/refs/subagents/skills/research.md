---
name: research
description: Search GitHub for security techniques (shellcode loaders, evasion methods, C2 patterns), analyze code patterns, and save structured knowledge to the knowledge base. Use this skill when the user wants to research security techniques, search GitHub for code patterns, analyze malware techniques for defensive purposes, or update the knowledge base with new findings. Triggers on phrases like "search GitHub", "research techniques", "analyze code", "find methods", "update knowledge base", "研究", "搜索".
version: 2.0.0
---

# Research Skill

Search, analyze, and document security techniques from GitHub and other sources for defensive security research purposes.

## Authorization Context

**AUTHORIZED USE CASE: Defensive Security Research**

This skill is used for:
- Understanding attacker techniques to improve detection capabilities
- Developing security product testing methodologies
- Red team / blue team training exercises
- Security product evaluation and improvement

## When to Use This Skill

- User asks to search GitHub for security-related code
- User wants to research evasion or loader techniques
- User says phrases like "search for", "research", "analyze", "find methods"
- User mentions shellcode, loader, evasion, AMSI, ETW, syscall, etc.

## Workflow

### Step 1: GitHub Search

Use the `gh` CLI tool to search GitHub. Start with broad queries, then narrow down.

```bash
# Search repositories
gh search repos "shellcode loader language:C stars:>20" --limit 20

# Search code patterns
gh search code "VirtualAlloc PAGE_EXECUTE_READWRITE" --language c --limit 30

# Search specific topics
gh search repos "AMSI bypass" --limit 15
gh search repos "syscall direct" --language c --limit 15
```

### Step 2: Repository Analysis

For promising repositories, fetch key files:

```bash
# Get repository info
gh repo view owner/repo

# List files
gh api repos/owner/repo/contents

# Get specific file content
gh api repos/owner/repo/contents/path/to/file.c --jq '.content' | base64 -d
```

### Step 3: Pattern Extraction

Extract and categorize techniques by type:

| Category | Keywords |
|----------|----------|
| **Memory Allocation** | VirtualAlloc, HeapCreate, NtAllocateVirtualMemory, MappedFile |
| **Code Execution** | CreateThread, EnumWindows, APC, Fiber, callback |
| **API Obfuscation** | API hashing, PEB walk, GetProcAddress, dynamic resolve |
| **String Obfuscation** | XOR, AES, stack strings, compile-time encryption |
| **Anti-Analysis** | IsDebuggerPresent, CheckRemoteDebugger, anti-VM, sandbox |
| **Syscall** | direct syscall, indirect syscall, SSN, Hell's Gate |

### Step 4: Knowledge Base Storage

Save findings using the knowledge base commands:

```bash
# Add loader technique
python lib/knowledge_manager.py add-loader-technique \
  --storage embedded \
  --allocator VirtualAlloc \
  --copier memcpy \
  --executor callback

# Add evasion technique with dedup check
python lib/knowledge_manager.py dedup-check \
  --name "Technique Name" \
  --type "api_obfuscation" \
  --description "..." \
  --apis "API1,API2"

# If unique, add it
python lib/knowledge_manager.py add-evasion \
  --name "Technique Name" \
  --type "api_obfuscation" \
  --description "Detailed description" \
  --code-template "// code here" \
  --apis "API1,API2" \
  --complexity "medium"
```

### Step 5: Output Summary

After research, provide:

1. **Techniques Found**: List with brief descriptions
2. **Complexity Assessment**: simple/medium/complex
3. **Knowledge Base Status**: NEW / DUPLICATE / VARIATION
4. **References**: GitHub URLs

## Deduplication Rules

| Condition | Action |
|-----------|--------|
| Exact name match | SKIP - Duplicate |
| Same technique, different name | SKIP - Duplicate |
| Same goal, different implementation | ADD - Both useful |
| Different goal, similar APIs | ADD - Different purpose |
| Same source, same approach | SKIP - Duplicate |
| Same source, different approach | ADD - Variation |

## Important Rules

1. **DO NOT** use output redirection (`>/dev/null`, `2>/dev/null`) - causes approval delays
2. **DO NOT** use `cd` combined with other commands - use absolute paths instead
3. **ALWAYS** check for duplicates before adding to knowledge base
4. **ALWAYS** save findings to knowledge base after analysis
5. Use `samples/calc.bin` only for testing loaders (if applicable)

## Bash Command Guidelines

**CORRECT:**
```bash
gh search repos "shellcode loader"
python lib/knowledge_manager.py add-evasion --name "..."
```

**INCORRECT:**
```bash
gh search repos "query" 2>/dev/null
cd "/some/path" && python lib/knowledge_manager.py add-evasion
```

**Note:** Use relative paths from project root (lib/knowledge_manager.py), not absolute paths, for portability.

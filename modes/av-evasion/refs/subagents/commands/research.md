---
description: Search GitHub for security techniques (shellcode loaders, evasion methods, C2 patterns), analyze code patterns, and save to knowledge base. Triggers on "research", "search GitHub", "analyze techniques", "find methods", "更新知识库", "搜索".
argument-hint: Optional search query (e.g., "API hashing", "syscall", "AMSI bypass")
---

# Research Command

Launch the research-agent to search GitHub and update the knowledge base.

## Usage

```bash
/research                        # Interactive mode
/research "shellcode loader"     # Search with query
/research "syscall evasion C++"  # Specific technique
/research "AMSI bypass"          # Find evasion techniques
```

## What This Command Does

1. **Searches GitHub** using `gh` CLI for repositories and code patterns
2. **Analyzes source code** to extract technique patterns
3. **Categorizes findings** by type (allocation, execution, evasion)
4. **Saves to knowledge base** with deduplication check
5. **Reports summary** of new/updated techniques

## Output

- Techniques discovered (with descriptions)
- Knowledge base IDs added
- Complexity assessment
- Reference URLs

## Security

- **NEVER** compile or execute external code
- **NEVER** use external shellcode
- **ONLY** analyze patterns

## Agent

Spawns `research-agent` subagent for comprehensive analysis.

See `research` skill for detailed patterns and commands.

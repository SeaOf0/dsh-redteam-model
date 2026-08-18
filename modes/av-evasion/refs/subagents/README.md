# Evasion Agent Teams

An automated security research toolkit for defensive purposes.

## Project Goal

Build an automated sub-agent team for security research, integrated with Claude Code. All subagents work through Claude Code conversation.

## Authorization Context

**AUTHORIZED USE CASE: Defensive Security Research**

This toolkit is used for:
- Understanding attacker techniques to improve detection capabilities
- Developing security product testing methodologies
- Red team / blue team training exercises
- Security product evaluation and improvement

## Sub Agents

| Agent | Description | Trigger |
|-------|-------------|---------|
| **research-agent** | Search GitHub for techniques, analyze code, update knowledge base | `/research` |
| **loadergen-agent** | Generate shellcode loaders from knowledge base | `/loader_generate` |
| **evasion-agent** | Integrate evasion techniques into existing loaders | `/evasion_integrate` |
| **c2-evasion-agent** | Analyze C2 source, find detection rules, modify code | `/c2_evasion` |
| **tools-evasion-agent** | Analyze pen-test tools, find detection rules, modify source | `/tools_evasion` |

## Commands

### `/research [query]`
Search GitHub for security techniques and update knowledge base.

```bash
/research                        # Interactive mode
/research "syscall evasion"      # Search specific technique
/research "AMSI bypass C++"      # With language filter
```

### `/loader_generate [options]`
Generate shellcode loaders from knowledge base components.

```bash
/loader_generate                      # Single random loader
/loader_generate 5                    # Batch generate 5
/loader_generate --executor callback  # Specific executor
/loader_generate --complexity medium  # Filter complexity
```

### `/evasion_integrate <path> [options]`
Add evasion techniques to an existing loader.

```bash
/evasion_integrate ./loader.c                        # Auto-select
/evasion_integrate ./loader.c --type api_obfuscation # Specific type
/evasion_integrate ./loader.c --complexity simple    # Filter
```

### `/c2_evasion <path>`
Analyze C2 framework and modify source for detection evasion.

```bash
/c2_evasion ./sliver-client
/c2_evasion ./mythic-agent
```

### `/tools_evasion <path>`
Analyze penetration testing tool and modify source for detection evasion.

```bash
/tools_evasion ./crackmapexec
/tools_evasion ./mimikatz
/tools_evasion ./nmap
```

## Directory Structure

```
.claude/
├── agents/           # Sub-agent definitions
│   ├── research-agent.md
│   ├── loadergen-agent.md
│   ├── evasion-agent.md
│   ├── c2-evasion-agent.md
│   └── tools-evasion-agent.md
├── commands/         # User commands
│   ├── research.md
│   ├── loader_generate.md
│   ├── evasion_integrate.md
│   ├── c2_evasion.md
│   └── tools_evasion.md
├── skills/           # Detailed skill instructions
│   ├── research.md
│   ├── loader_generate.md
│   ├── evasion_integrate.md
│   ├── c2_evasion/
│   └── tools_evasion/
└── README.md

knowledge-base/       # Knowledge storage
├── loader_techniques.json
├── evasion_techniques.json
└── scenarios.json

lib/                  # Utility scripts
└── knowledge_manager.py

rules/                # Detection rules and analysis results
├── {tool_name}/      # Per-tool analysis directory
│   ├── yara/         # YARA rules
│   ├── sigma/        # Sigma rules
│   ├── network/      # Network rules
│   ├── tool_profile.md
│   ├── behavior_analysis.md
│   └── modifications_summary.md
└── README.md

samples/              # Test samples
└── calc.bin

output/               # Generated outputs
```

## Knowledge Base

The knowledge base stores techniques discovered by research-agent:

- **loader_techniques.json**: Loading methods (allocation, execution, storage)
- **evasion_techniques.json**: Evasion methods (API obfuscation, anti-analysis, etc.)
- **scenarios.json**: Record of generated loader combinations

### KB Commands

```bash
# List techniques
python lib/knowledge_manager.py list-evasion
python lib/knowledge_manager.py get-components

# Add technique
python lib/knowledge_manager.py add-evasion --name "..." --type "api_obfuscation"

# Check duplicates
python lib/knowledge_manager.py dedup-check --name "..."
```

## Rules Directory

The `rules/` directory stores detection rules and analysis results:

- **YARA Rules**: File/memory pattern matching rules
- **Sigma Rules**: Log-based detection rules
- **Network Rules**: IDS/IPS signatures
- **Analysis Results**: Per-tool behavior analysis and modification reports

## Security Rules

1. **NEVER** run or test generated executables - compilation success is sufficient
2. **ONLY** use `samples/calc.bin` for loader testing
3. **ONLY** modify code in user-provided paths
4. **ALWAYS** document all changes made
5. Use relative paths (not absolute) for portability

## License

For authorized defensive security research only.

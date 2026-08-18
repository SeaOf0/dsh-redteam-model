---
description: Integrate evasion techniques into existing shellcode loaders. Add API hashing, string encryption, syscalls, etc. to user-provided code. Triggers on "integrate evasion", "add evasion", "bypass", "hardening", "免杀", "二开".
argument-hint: Required: path to loader source (e.g., "/path/to/loader.c") + optional technique filters
---

# Evasion Integrate Command

Launch the evasion-agent to add evasion techniques to an existing loader.

## Usage

```bash
/evasion_integrate /path/to/loader.c                           # Auto-select techniques
/evasion_integrate /path/to/loader.c --type api_obfuscation    # Specific type
/evasion_integrate /path/to/loader.c --type string_obfuscation,anti_analysis
/evasion_integrate /path/to/loader.c --complexity simple       # Filter by complexity
/evasion_integrate /path/to/loader.c --technique T001,T003     # Specific IDs
```

## What This Command Does

1. **Reads** user-provided loader source code
2. **Queries** evasion techniques from knowledge base
3. **Analyzes** compatibility with the loader
4. **Integrates** selected techniques into the code
5. **Compiles** modified loader
6. **Reports** all changes made

## Evasion Types

| Type | Description | Complexity |
|------|-------------|------------|
| api_obfuscation | API hashing, PEB walking | medium |
| string_obfuscation | XOR encryption, stack strings | simple |
| memory_evasion | Permission flipping (RW→RX) | simple |
| execution_evasion | Direct/indirect syscall | complex |
| anti_analysis | Anti-debug, anti-VM | medium |
| amsi_etw_bypass | AMSI/ETW patching | medium |
| unhooking | NTDLL unhooking | complex |

## Output

- Modified source: `output/evasion_<id>.c`
- Compiled executable: `output/evasion_<id>.exe`
- Changes summary:
  - Techniques applied
  - APIs modified
  - Detection risk assessment

## Security

- **ONLY** modify user-provided code
- **NEVER** run generated executables
- Compilation success is sufficient

## Agent

Spawns `evasion-agent` subagent for technique integration.

See `evasion_integrate` skill for detailed patterns.

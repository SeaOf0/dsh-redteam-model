# Rule Analysis for Tools

Parse and understand detection rules (YARA, Sigma, etc.) to identify detection patterns.

## Rule Format Reference

### YARA Rule Structure

```yara
rule <rule_name> {
    meta:
        author = "..."
        description = "..."
        date = "..."

    strings:
        $s1 = "string_pattern" wide ascii    # String pattern
        $h1 = { 48 83 EC 58 }                  # Hex pattern
        $r1 = /regex_pattern/                  # Regex pattern

    condition:
        any of them                            # Condition logic
}
```

### Sigma Rule Structure

```yaml
title: Rule Title
id: uuid
status: test/stable/deprecated
description: Rule description
author: Author name
date: YYYY-MM-DD
tags:
    - attack.tactic
    - attack.technique
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\tool.exe'
        CommandLine|contains: 'argument'
    condition: selection
level: low/medium/high/critical
```

## Pattern Types

### YARA Pattern Types

| Type | Syntax | Example | Detection Method |
|------|--------|---------|-----------------|
| String | `$s = "text"` | `$s = "mimikatz"` | Exact string match |
| String (wide) | `$s = "text" wide` | `$s = "mimikatz" wide` | Unicode string |
| String (ascii) | `$s = "text" ascii` | `$s = "mimikatz" ascii` | ASCII string |
| Hex | `$h = { bytes }` | `$h = { 48 83 EC 58 }` | Byte sequence |
| Hex (wildcard) | `$h = { ?? ?? }` | `$h = { B8 ?? ?? 00 }` | Wildcard bytes |
| Regex | `$r = /pattern/` | `$r = /X-[a-z]+-Id/` | Pattern match |

### Sigma Field Modifiers

| Modifier | Meaning | Example |
|----------|---------|---------|
| `contains` | Substring match | `CommandLine\|contains: 'mimikatz'` |
| `startswith` | Prefix match | `Image\|startswith: 'C:\Temp'` |
| `endswith` | Suffix match | `Image\|endswith: '\tool.exe'` |
| `re` | Regex match | `CommandLine\|re: '.*--beacon.*'` |
| `all` | All must match | `CommandLine\|contains\|all: ['a', 'b']` |

## Rule Parsing Workflow

### Step 1: Parse Rule Metadata

Extract basic information:
- Rule name/title
- Author
- Description
- Detection level (criticality)
- MITRE ATT&CK tags

### Step 2: Extract Detection Patterns

For each detection rule, extract all patterns:

**YARA Pattern Extraction:**
```markdown
## Rule: rule_name

### Strings
| ID | Pattern | Type | Modifiers |
|----|---------|------|-----------|
| $s1 | "BeaconOutput" | string | wide ascii |
| $h1 | { 48 83 EC 58 } | hex | - |
| $r1 | /X-[a-z]+-Id/ | regex | - |

### Condition
- Logic: `any of them`
- Meaning: Any single pattern match triggers detection
```

**Sigma Pattern Extraction:**
```markdown
## Rule: rule_title

### Logsource
| Field | Value |
|-------|-------|
| category | process_creation |
| product | windows |

### Detection Selection
| Field | Modifier | Value | Meaning |
|-------|----------|-------|---------|
| Image | endswith | '\tool.exe' | Executable path ends with tool.exe |
| CommandLine | contains | '--beacon' | Command line contains --beacon |

### Condition
- Logic: `selection` (all conditions in selection must match)
```

### Step 3: Categorize Detection Type

| Detection Type | Pattern Characteristics | Evasion Approach |
|---------------|------------------------|------------------|
| **String signature** | Exact strings | String encryption/encoding |
| **Hex signature** | Byte sequences | Compiler flags, code modification |
| **Behavior signature** | API calls, process patterns | Behavior modification |
| **Hash signature** | File hashes | Any modification to binary |
| **Command signature** | CLI arguments | Argument modification |
| **Path signature** | File paths | Path modification |

## Pattern Analysis Examples

### Example 1: String Pattern

```yara
$s1 = "mimikatz" wide ascii
```

**Analysis:**
- Type: String pattern
- Target: Executable name or internal string
- Evasion: Rename executable, encrypt string

### Example 2: Hex Pattern

```yara
$h1 = { 48 83 EC 58 }  # sub rsp, 0x58
```

**Analysis:**
- Type: Function prologue
- Target: Function with 0x58 bytes stack allocation
- Evasion: Compiler flags (-fomit-frame-pointer), reduce stack usage

### Example 3: Sigma Process Creation

```yaml
detection:
    selection:
        Image|endswith: '\crackmapexec.exe'
        CommandLine|contains|all:
            - ' --local-auth'
            - ' -u '
            - ' -p '
```

**Analysis:**
- Type: Process creation detection
- Target: Executable name + command arguments
- Evasion: Rename executable, modify argument names

### Example 4: Sigma Process Access

```yaml
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        StartModule: ''
```

**Analysis:**
- Type: Process access detection
- Target: LSASS process access
- Evasion: Use alternative credential access methods

## Output Format

For each rule, create: `rules/{tool_name}/rule_analysis/{rule_name}.md`

```markdown
# Rule Analysis: {rule_name}

## Rule Info

| Attribute | Value |
|-----------|-------|
| Source | [URL/Repository] |
| Author | [Author] |
| Type | [YARA/Sigma/etc.] |
| Category | [process_creation/network/etc.] |
| Level | [low/medium/high/critical] |

## Patterns

### Pattern 1: {pattern_id}
| Attribute | Value |
|-----------|-------|
| Type | [string/hex/regex] |
| Pattern | `{pattern_value}` |
| Meaning | [What this detects] |

### Pattern 2: {pattern_id}
...

## Condition
- Logic: [condition logic]
- Threshold: [any/all/count]

## Detection Context
- When triggered: [Event type that triggers this rule]
- Detection point: [Where detection occurs]

## Source Code Location

| Pattern | Source File | Line | Context |
|---------|-------------|------|---------|
| $s1 | http.go | 78 | HTTP header constant |
| $h1 | main.c | 45 | Function prologue |

## Evasion Strategy

| Strategy | Feasible | Effort | Priority |
|----------|----------|--------|----------|
| String encryption | Yes | Low | 1 |
| Rename | Yes | Low | 2 |
| Behavior change | No | - | - |

## Notes
- [Additional observations]
```

## Important Notes

1. **Parse all patterns** - Every pattern in a rule is a detection point
2. **Understand condition logic** - `any` vs `all` affects evasion strategy
3. **Identify source** - Find where each pattern originates in code
4. **Categorize type** - String/hex/behavior patterns require different approaches
5. **Document context** - Understanding why a pattern exists helps evasion planning

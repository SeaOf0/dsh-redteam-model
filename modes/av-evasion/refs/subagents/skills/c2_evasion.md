---
name: c2_evasion
description: Analyze C2 framework source code, find detection rules (YARA, Sigma, Snort, etc.), and directly modify source code to evade detection. Use this skill when the user wants to "analyze C2", "C2 evasion", "modify C2", "bypass C2 detection", "YARA analysis", "C2免杀", or work with C2 framework detection evasion. Triggers on phrases containing C2, beacon, implant, YARA, detection bypass, evasion modification. Make sure to use this skill whenever the user mentions C2 frameworks, implants, beacons, or YARA analysis for evasion purposes.
version: 10.0.0
---

# C2 Evasion Skill

Analyze C2 frameworks and modify source code to evade detection for authorized security testing.

## Authorization Context

**AUTHORIZED USE CASE: Defensive Security Research**

- Understanding detection signatures to improve security products
- Red team assessments with explicit authorization
- Security product testing and evaluation

## Workflow

```
Phase 1: Identify C2 Components
    └─ Find implant/beacon/agent directories
Phase 2: Detection Search → Read references/detection_search.md
    └─ Search YARA, Sigma, network rules
Phase 3: Per-Rule Analysis → Read references/rule_analysis.md
    └─ For EACH rule: parse patterns, find source, develop evasion strategy
Phase 3.5: Hex Analysis → Read references/hex_analysis.md
    └─ Analyze hex patterns, check Makefile
Phase 3.6: Binary Analysis → Read references/binary_analysis.md
    └─ Check shellcode, resources, configs
Phase 3.7: String Search → Read references/string_search.md
    └─ Proactive sensitive string search
Phase 4: Modification → Read references/source_modify.md
    └─ Apply targeted changes (compiler flags FIRST, then source)
Phase 5: Verification
    └─ Verify all patterns removed
Phase 6: Documentation
    └─ Create modifications_summary.md
```

## Priority Framework

| Priority | Component | Action |
|----------|-----------|--------|
| 1 (HIGHEST) | Implant/Beacon/Agent | MODIFY |
| 2 (HIGH) | Network Exposure | MODIFY |
| 3 (SKIP) | Internal Strings | SKIP |

## Phase 1: Identify C2 Components

```bash
# Explore directory structure
ls -la <path>
find <path> -name "*.c" -o -name "*.go" -o -name "*.rs" -o -name "*.py"

# Find implant directories
# Common names: agent/, beacon/, implant/, client/, src_beacon/, src_gopher/
```

## Phase 2-3.7: Read Reference Files

| Phase | Reference File | Purpose |
|-------|----------------|---------|
| 2 | `references/detection_search.md` | YARA/Sigma search commands |
| 3 | `references/rule_analysis.md` | Per-rule analysis & evasion planning |
| 3.5 | `references/hex_analysis.md` | Hex pattern analysis |
| 3.6 | `references/binary_analysis.md` | Shellcode/resource analysis |
| 3.7 | `references/string_search.md` | Sensitive string search |
| 4 | `references/source_modify.md` | Modification patterns |

## Phase 3: Per-Rule Analysis

**CRITICAL: Every rule MUST have an evasion plan.**

For EACH YARA/Sigma rule:

1. **Parse all patterns** - Extract every $s1, $a1, hex pattern
2. **Identify pattern source** - Find what in code creates this pattern
3. **Develop evasion strategies** with priority:
   - **Priority 1**: Compiler flags (lowest effort, highest impact)
   - **Priority 2**: Build configuration changes
   - **Priority 3**: Source code modifications
   - **Priority 4**: Function/struct refactoring
4. **Select best strategy** and implement
5. **Document** in `./rules/<c2_name>/rule_analysis/<rule_name>.md`

**Decision Matrix:**

| Pattern Type | Compiler Flag | Source Change | Both Needed |
|--------------|--------------|---------------|-------------|
| Function prologue | ✅ Often enough | ✅ Alternative | Rare |
| String bytes | ❌ No effect | ✅ Required | N/A |
| API sequence | ⚠️ May help | ✅ Required | Sometimes |
| Config structure | ❌ No effect | ✅ Required | N/A |

## Phase 4: Targeted Modification

**Priority Order:**
1. **Compiler flags FIRST** - `-O2`, `-fomit-frame-pointer`, `-fno-stack-protector`
2. **Source changes SECOND** - Only if compiler flags insufficient

**String Obfuscation:**
```c
// Before: char* header = "BeaconOutput";
// After: char header[] = { 0x07, 0x02, ... }; // XOR encrypted
```

**Function Rename (Go):**
```go
// Before: func taskProcess(...) { }
// After: func cmdProc(...) { }
```

**Makefile Changes:**
```makefile
CFLAGS += -fno-stack-protector -fno-ident
LDFLAGS += -Wl,--build-id=none -Wl,--gc-sections
```

## Phase 5: Verification

```bash
# Verify patterns removed
grep -rn "BeaconOutput" <path>  # Should return nothing
grep -rn "taskProcess" <path>   # Should return nothing
```

## Phase 6: Documentation

Create `./rules/<c2_name>/modifications_summary.md`:

```markdown
# C2 Evasion Report

## C2 Framework: <name>
## Rules Analyzed: X YARA, Y Sigma, Z Network

## Binary Assets Analyzed
| Asset | Type | Risk | Action |
|-------|------|------|--------|
| shellcode.bin | Raw | HIGH | Encrypted |

## Hex Pattern Analysis
| Pattern | Type | Evasion Method | Status |
|---------|------|----------------|--------|
| { 48 83 EC 58 } | Prologue | Reduced locals | Evaded |

## String Modifications
| Pattern | File | Modification | Status |
|---------|------|--------------|--------|
| "BeaconOutput" | http.go:78 | XOR encrypt | Evaded |

## Detection Risk: Low/Medium/High
```

## Important Rules

1. **NEVER skip a rule** - Every YARA/Sigma rule must have an analysis
2. **ALWAYS try compiler flags first** - Lowest effort, highest impact
3. ONLY modify code in user-provided path
4. ANALYZE hex patterns - DO NOT skip them
5. ALWAYS check Makefile for evasion opportunities
6. ALWAYS check binary assets (shellcode, configs)
7. NEVER test/run modified binaries
8. Document ALL changes with reasons

## Output Directory

```
./rules/<c2_name>/
├── yara/
├── sigma/
├── network/
├── rule_analysis/
│   └── <rule_name>.md      # Per-rule analysis
├── binary_assets/
│   └── analysis.md
├── hex_analysis.md
└── modifications_summary.md
```

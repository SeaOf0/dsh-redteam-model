---
name: tools_evasion
description: Analyze penetration testing tools and modify source code to evade detection. Usage: /tools_evasion <tool_path>
arguments:
  - name: tool_path
    description: Path to the penetration testing tool directory or file
    required: true
---

You are tasked with analyzing a penetration testing tool and modifying its source code to evade detection.

## Input

Tool Path: {{tool_path}}

## Workflow

Follow these phases in order:

### Phase 1: Tool Understanding

1. Read README and documentation files
2. Analyze source code structure
3. Identify programming language and build system
4. Determine tool purpose and use cases
5. Create tool profile at `rules/{tool_name}/tool_profile.md`

### Phase 2: Open Source Detection (if applicable)

1. Check if the tool is open source
2. Extract keywords (name, author, features)
3. Search GitHub for tool-specific detection rules
4. Save found rules to `rules/{tool_name}/yara/`, `rules/{tool_name}/sigma/`, etc.

### Phase 3: Behavior Analysis

1. Analyze source code for core behavior patterns:
   - Network behavior (HTTP headers, URLs, ports)
   - Process behavior (creation, injection)
   - File behavior (paths, operations)
   - API usage patterns
   - String constants
2. Extract behavioral signatures
3. Search for behavior-based detection rules
4. Save found rules

### Phase 4: Rule Collection

1. Organize all found rules
2. Create rule inventory at `rules/{tool_name}/rule_inventory.md`
3. Categorize by type (YARA, Sigma, Network, etc.)

### Phase 5: Per-Rule Analysis

For EACH detection rule found:
1. Parse all patterns (strings, hex, regex)
2. Identify pattern sources in the tool code
3. Develop evasion strategies (prioritize compiler flags)
4. Create analysis file at `rules/{tool_name}/rule_analysis/{rule_name}.md`

### Phase 6: Source Modification

**CRITICAL: Directly modify source files using Edit tool.**

1. FIRST: Try build configuration changes (compiler flags)
2. SECOND: Apply source code modifications if needed
3. Create tasks for each modification
4. Verify each change

Modification priority:
1. Compiler flags (lowest effort, highest impact)
2. Build configuration
3. String obfuscation
4. API obfuscation
5. Function rename
6. Behavior change (last resort)

### Phase 7: Verification & Summary

1. Verify all patterns are removed from source
2. Test compilation (do NOT run the tool)
3. Create final report at `rules/{tool_name}/modifications_summary.md` including:
   - Tool profile
   - Rules analyzed
   - Modifications applied
   - Unevadable items with reasons
   - Detection risk assessment
   - Recommendations

## Output Directory Structure

```
rules/{tool_name}/
├── yara/
│   └── *.yar
├── sigma/
│   └── *.yml
├── network/
│   └── *.rules
├── other_rules/
├── tool_profile.md
├── behavior_analysis.md
├── rule_inventory.md
├── rule_analysis/
│   └── *.md
└── modifications_summary.md
```

## Important Rules

1. **NEVER skip a rule** - Every detection rule must have an analysis
2. **ALWAYS try compiler flags first** - Lowest effort, highest impact
3. **ONLY modify code in user-provided path** - Never touch other files
4. **PRESERVE functionality** - Tool must work after modification
5. **NEVER run/test modified tools** - Compilation success is sufficient
6. **Document everything** - All changes must be recorded
7. **Report unevadable items** - Explain why evasion is not possible
8. **Direct modification** - Use Edit tool directly, don't just document

## Authorization

This is for authorized security research only:
- Red team assessments with proper authorization
- Security product testing
- Defensive security research

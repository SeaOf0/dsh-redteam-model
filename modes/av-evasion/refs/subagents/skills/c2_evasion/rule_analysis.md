# Rule Analysis and Evasion Planning

Analyze each YARA/Sigma rule and develop specific evasion strategies.

## Key Principle

**Every rule MUST have an evasion plan.** Even hex patterns can be evaded through source code or build changes.

## Analysis Process

For EACH detection rule found, follow this process:

### Step 1: Parse All Patterns

Extract every pattern from the rule:

```yaml
Rule: Windows_Trojan_Adaptix.yar

Pattern $a1:
  hex: 48 81 EC A8 01 00 00 ...
  type: function_prologue
  meaning: sub rsp, 0x1A8 (stack allocation)

Pattern $a2:
  hex: 48 83 EC 58 ...
  type: function_prologue
  meaning: sub rsp, 0x58 (stack allocation)
```

### Step 2: Identify Pattern Source

| Pattern Type | How to Find Source |
|--------------|-------------------|
| Function prologue `{ 48 83 EC XX }` | Search for large stack allocations in source |
| String bytes `{ 68 74 74 70 }` | Search for the string in source |
| API sequence `{ B9 77 00 00 }` | Search for API call patterns |
| Config structure `{ 8D ?? ?? E8 }` | Search for struct initialization |
| Function call `{ E8 XX XX XX XX }` | Identify caller/callee functions |

```bash
# Function prologue: stack allocation 0x1A8 = 424 bytes
grep -rn "char buffer\[424\]" <path>
grep -rn "char buffer\[0x1A8\]" <path>
grep -rn "struct.*{" <path> | look for large structs

# String bytes: 68 74 74 70 = "http"
echo "68 74 74 70" | xxd -r -p  # Convert to string
grep -rn "http" <path>
```

### Step 3: Develop Evasion Strategies

For each pattern, determine possible evasion methods:

| Strategy | Priority | Effort | Effectiveness |
|----------|----------|--------|---------------|
| **Compiler flags** | 1 (HIGHEST) | Low | Changes all hex patterns |
| **Reduce stack allocation** | 2 | Medium | Changes function prologue |
| **Heap allocation** | 3 | Medium | Eliminates stack pattern |
| **Function refactoring** | 4 | High | Changes many patterns |
| **String encryption** | 5 | Low | Removes string bytes |
| **Code reordering** | 6 | Medium | Changes instruction sequence |

### Step 4: Evaluate and Select Best Strategy

**Priority Order:**

1. **Compiler flags** (lowest effort, affects multiple patterns)
2. **Build configuration** (Makefile, CMakeLists)
3. **Source code changes** (if compiler flags insufficient)
4. **Struct/function refactoring** (last resort)

## Analysis Output Format

For each rule, create an analysis:

```markdown
## Rule: Windows_Trojan_Adaptix_2779784c.yar

### Patterns Analysis

| Pattern | Type | Meaning | Source Location |
|---------|------|---------|-----------------|
| $a1 | function_prologue | sub rsp, 0x1A8 | Large function with 424-byte stack |
| $a2 | function_prologue | sub rsp, 0x58 | Function with 88-byte stack |

### Evasion Strategies

| Strategy | Feasible | Effort | Priority |
|----------|----------|--------|----------|
| **Compiler flags** | ✅ Yes | Low | 1 (BEST) |
| Heap allocation | ✅ Yes | Medium | 2 |
| Function split | ✅ Yes | High | 3 |

### Recommended Action

**Primary: Modify Makefile compiler flags**

```makefile
# Add these flags to change function prologues:
CFLAGS += -O2 \                    # Optimization changes code
          -fomit-frame-pointer \   # Removes frame pointer
          -fno-stack-protector \   # Removes canary
          -mno-stack-arg-probe     # Removes stack probe
```

### Expected Outcome

After compiler flag changes:
- Original: `48 81 EC A8 01 00 00` (sub rsp, 0x1A8)
- New: Different instruction sequence

### Verification

```bash
# Rebuild
make clean && make

# Check if pattern still exists
xxd beacon.exe | grep "48 81 ec a8 01"
```

## Decision Matrix

| Pattern Type | Compiler Flag | Source Change | Both Needed |
|--------------|--------------|---------------|-------------|
| Function prologue | ✅ Often enough | ✅ Alternative | Rare |
| String bytes | ❌ No effect | ✅ Required | N/A |
| API sequence | ⚠️ May help | ✅ Required | Sometimes |
| Config structure | ❌ No effect | ✅ Required | N/A |
| Build timestamp | ✅ Required | ❌ N/A | N/A |

## Complete Rule Analysis Template

```markdown
## Rule Analysis: [rule_name]

**Author**: [from meta]
**Target**: [implant/server/both]
**Pattern Count**: X

### Pattern 1: $a1
- **Hex**: `XX XX XX XX ...`
- **Type**: [function_prologue/string/api_sequence/config/other]
- **Meaning**: [what this pattern represents]
- **Source Cause**: [what in source creates this]
- **Source Location**: [file:line or "N/A - build artifact"]

### Pattern 2: $a2
...

### Evasion Strategy

**Option A: Compiler Flags** (Priority 1)
- Feasible: [Yes/No]
- Flags to add: `-flag1 -flag2`
- Expected change: [description]

**Option B: Source Modification** (Priority 2)
- Feasible: [Yes/No]
- Files to modify: [list]
- Changes: [description]

**Option C: Build Configuration** (Priority 3)
- Feasible: [Yes/No]
- Config to change: [description]

### Selected Strategy
[Choose the best option with reasoning]

### Implementation
[Specific commands/changes to make]

### Verification Command
```bash
[command to verify pattern is gone]
```
```

## Important Rules

1. **NEVER skip a rule** - Every rule must have an analysis
2. **ALWAYS try compiler flags first** - Lowest effort, highest impact
3. **Document WHY a strategy was chosen** - For future reference
4. **Verify after each change** - Ensure pattern is actually removed
5. **Update the analysis if strategy fails** - Iterative process

---
name: x64dbg-reversing
description: "Perform dynamic reverse engineering and debugging using X64dbg/X32dbg through natural language commands powered by X64dbg MCP. Use this skill whenever the user wants to: debug executables, analyze program behavior at runtime, set breakpoints, inspect memory and registers, trace execution flow, bypass anti-debug protections, patch binary code, dump PE sections, or any task related to x64dbg/x32dbg debugging. Make sure to use this skill when users mention x64dbg, x32dbg, debugging, runtime analysis, breakpoint, memory inspection, register inspection, anti-debug bypass, or reverse engineering with a debugger - even if they don't explicitly mention 'MCP' or 'skill'."
---

# X64dbg Reversing Skill

This skill enables AI-powered dynamic reverse engineering through the X64dbg MCP server. It provides comprehensive guidance for debugging, memory analysis, breakpoint management, and binary patching.

## Prerequisites

- x64dbg or x32dbg installed (download from qq:212717393)
- x64dbg MCP plugin installed (x64dbg_mcp.dp64/x32dbg_mcp.dp32)
- Node.js >= 18 for the MCP server
- MCP server running (x64dbg-mcp-server via npx)

## Architecture

```
MCP Client (Claude) --> TypeScript MCP Server --> C++ Plugin (in x64dbg) --> x64dbg Engine
     (stdio)              (localhost:27042)         (REST API)
```

## Available Tools

### 1. Debugger Control

**x64dbg_debug** - Control execution flow
| Action | Description |
|--------|-------------|
| `run` | Resume execution |
| `pause` | Pause debugger |
| `force_pause` | Force pause immediately |
| `step_into` | Step into function calls |
| `step_over` | Step over function calls |
| `step_out` | Step out of current function |
| `stop_debug` | Stop debugging session |
| `restart_debug` | Restart debuggee |
| `run_to_address` | Run until specified address |
| `state` | Get current debugger state |

### 2. Register Operations

**x64dbg_registers** - Read/write CPU registers
| Action | Description |
|--------|-------------|
| `get_all` | Get all general purpose registers |
| `get_specific` | Get specific register(s) |
| `get_flags` | Get CPU flags (ZF, CF, OF, etc.) |
| `get_avx512` | Get AVX-512 registers |
| `set` | Set register value |

### 3. Memory Operations

**x64dbg_memory** - Memory read/write/manage
| Action | Description |
|--------|-------------|
| `read` | Read memory at address |
| `write` | Write data to memory |
| `info` | Get memory region info |
| `is_valid` | Check if address is valid |
| `is_code` | Check if address is code |
| `allocate` | Allocate new memory |
| `free` | Free allocated memory |
| `protect` | Change memory protection |
| `map` | Map file into memory |

### 4. Stack Analysis

**x64dbg_stack** - Call stack and stack memory
| Action | Description |
|--------|-------------|
| `get_call_stack` | Unwind and display call stack |
| `read` | Read raw stack memory |
| `pointers` | Get stack pointers |
| `seh_chain` | Get SEH (Structured Exception Handler) chain |
| `return_address` | Get return address at offset |
| `comment` | Get comment at stack address |

### 5. Disassembly

**x64dbg_disassembly** - Disassemble code
| Action | Description |
|--------|-------------|
| `at_address` | Disassemble at specific address |
| `function` | Disassemble entire function |
| `info` | Get instruction info (operands, etc.) |
| `assemble` | Assemble instructions to bytes |

### 6. Breakpoints

**x64dbg_breakpoints** - Full breakpoint management
| Action | Description |
|--------|-------------|
| `set_software` | Set software breakpoint (int3) |
| `set_hardware` | Set hardware breakpoint |
| `set_memory` | Set memory breakpoint |
| `delete` | Delete breakpoint |
| `enable` | Enable breakpoint |
| `disable` | Disable breakpoint |
| `toggle` | Toggle breakpoint state |
| `set_condition` | Set breakpoint condition |
| `set_log` | Set breakpoint log message |
| `reset_hit_count` | Reset breakpoint hit counter |
| `get` | Get breakpoint info |
| `list` | List all breakpoints |
| `configure` | Configure breakpoint options |
| `configure_batch` | Configure multiple breakpoints |

### 7. Tracing

**x64dbg_tracing** - Execution tracing
| Action | Description |
|--------|-------------|
| `into` | Trace into instructions |
| `over` | Trace over instructions |
| `run` | Run with tracing enabled |
| `stop` | Stop tracing |
| `animate` | Animate execution with tracing |
| `conditional_run` | Run with conditions |
| `log_setup` | Configure trace logging |
| `hitcount` | Set hit count conditions |
| `type` | Set trace type |

### 8. Symbols & Labels

**x64dbg_symbols** - Symbol and label management
| Action | Description |
|--------|-------------|
| `resolve` | Resolve symbol at address |
| `address` | Get address of symbol name |
| `search` | Search for symbols |
| `list_module` | List symbols in module |
| `get_label` | Get label at address |
| `set_label` | Set label at address |
| `get_comment` | Get comment at address |
| `set_comment` | Set comment at address |
| `bookmark` | Manage bookmarks |

### 9. Search Operations

**x64dbg_search** - Search for patterns
| Action | Description |
|--------|-------------|
| `pattern` | Search byte pattern (AOB) |
| `string` | Search for strings |
| `string_at` | Find string at address |
| `symbol_auto_complete` | Auto-complete symbols |
| `encode_type` | Encode data types |

### 10. Modules

**x64dbg_modules** - Module information
| Action | Description |
|--------|-------------|
| `list` | List loaded modules |
| `get_info` | Get module information |
| `get_base` | Get module base address |
| `get_section` | Get section info |
| `get_party` | Get module classification (user/system) |

### 11. Threads

**x64dbg_threads** - Thread management
| Action | Description |
|--------|-------------|
| `list` | List all threads |
| `current` | Get current thread |
| `count` | Get thread count |
| `info` | Get thread detailed info |
| `teb` | Get Thread Environment Block address |
| `name` | Get/set thread name |
| `switch` | Switch to thread |
| `suspend` | Suspend thread |
| `resume` | Resume thread |

### 12. Process Information

**x64dbg_process** - Process details
| Action | Description |
|--------|-------------|
| `basic` | Basic process info |
| `detailed` | Detailed process info |
| `cmdline` | Get command line |
| `elevated` | Check elevation status |
| `dbversion` | Get debugger version |
| `set_cmdline` | Set command line |

### 13. Anti-Debug

**x64dbg_antidebug** - Anti-debug detection/bypass
| Action | Description |
|--------|-------------|
| `peb` | Get PEB fields |
| `teb` | Get TEB fields |
| `dep` | Check DEP status |
| `hide_debugger` | Hide debugger from detection |

### 14. Exceptions

**x64dbg_exceptions** - Exception handling
| Action | Description |
|--------|-------------|
| `set` | Set exception breakpoint |
| `delete` | Delete exception breakpoint |
| `list` | List exception breakpoints |
| `list_codes` | List known exception codes |
| `skip` | Skip exception |

### 15. Analysis

**x64dbg_analysis** - Code analysis
| Action | Description |
|--------|-------------|
| `function` | Analyze function |
| `xrefs_to` | Get cross-references to address |
| `xrefs_from` | Get cross-references from address |
| `basic_blocks` | Get basic blocks |
| `source` | Get source information |
| `mnemonic_brief` | Get instruction reference |

**x64dbg_control_flow** - Control flow analysis
| Action | Description |
|--------|-------------|
| `cfg` | Get control flow graph |
| `branch_dest` | Get branch destination |
| `is_jump_taken` | Check if jump was taken |
| `loops` | Detect loops in function |
| `func_type` | Determine function type |
| `add_function` | Add function definition |
| `delete_function` | Delete function definition |

### 16. Patching

**x64dbg_patches** - Code patching
| Action | Description |
|--------|-------------|
| `list` | List applied patches |
| `apply` | Apply patch |
| `restore` | Restore original bytes |
| `export` | Export patches |

### 17. Dumping

**x64dbg_dumping** - PE dumping
| Action | Description |
|--------|-------------|
| `pe_header` | Dump PE header |
| `sections` | Dump sections |
| `imports` | Dump import table |
| `exports` | Dump export table |
| `entry_point` | Dump entry point |
| `relocations` | Dump relocations |
| `dump_module` | Dump entire module |
| `fix_iat` | Fix import address table |
| `export_patch_file` | Export as patch file |

### 18. Handles

**x64dbg_handles** - Handle inspection
| Action | Description |
|--------|-------------|
| `list_handles` | List open handles |
| `list_tcp` | List TCP connections |
| `list_windows` | List windows |
| `list_heaps` | List heaps |
| `get_name` | Get handle name |
| `close` | Close handle |

### 19. Command Execution

**x64dbg_command** - Execute x64dbg commands
| Action | Description |
|--------|-------------|
| `execute` | Execute single command |
| `script` | Execute script |
| `evaluate` | Evaluate expression |
| `format` | Format value |
| `set_init_script` | Set initialization script |
| `get_init_script` | Get initialization script |
| `get_hash` | Get debugger hash |
| `get_events` | Get debug events |

## Workflow

### 1. Session Start

```
Always begin with:
1. x64dbg_debug state - Verify debugger is ready
2. x64dbg_process basic - Understand the target
3. x64dbg_modules list - See loaded modules
```

### 2. Setting Breakpoints

```
Common breakpoint patterns:

Function entry:
x64dbg_breakpoints set_software address="0x401000"

API call:
x64dbg_breakpoints set_software address="kernel32.CreateFileW" (use actual VA)

Memory breakpoint on variable:
x64dbg_breakpoints set_memory address="0x404000" size=4

Conditional breakpoint:
x64dbg_breakpoints set_condition bp_id=1 condition="EAX != 0"
```

### 3. Execution Control

```
Stepping patterns:

Step into (enter function):
x64dbg_debug step_into

Step over (skip function):
x64dbg_debug step_over

Run to address:
x64dbg_debug run_to_address address="0x401500"

Run until condition met:
x64dbg_breakpoints set_condition bp_id=1 condition="ESI == EBX"
```

### 4. Memory Inspection

```
Reading memory:

Read 128 bytes at address:
x64dbg_memory read address="0x401000" size=128

Read as different types:
x64dbg_memory read address="0x404000" size=8 type="qword"

Reading strings:
x64dbg_search string_at address="0x404000"

Stack inspection:
x64dbg_stack get_call_stack
x64dbg_stack read address="RSP" size=64
```

### 5. Register Analysis

```
Get all registers:
x64dbg_registers get_all

Get specific register:
x64dbg_registers get_specific register="RAX,RBX,RCX"

Get flags:
x64dbg_registers get_flags

Set register (for patching execution):
x64dbg_registers set register="RAX" value=0x1234
```

## Common Debugging Patterns

### Pattern 1: Find String Reference

```
1. Search for string:
   x64dbg_search string pattern="Password:"

2. Get xrefs to string address:
   x64dbg_analysis xrefs_to address="0x404000"

3. Set breakpoint at referencing code:
   x64dbg_breakpoints set_software address="0x401234"

4. Run and analyze when hit
```

### Pattern 2: Trace API Calls

```
1. Set breakpoints on imports:
   x64dbg_breakpoints set_software address="kernel32.CreateFileW"
   x64dbg_breakpoints set_log bp_id=1 log="CreateFileW called!"

2. Run program:
   x64dbg_debug run

3. Inspect call stack:
   x64dbg_stack get_call_stack
```

### Pattern 3: Bypass Anti-Debug

```
1. Check PEB for BeingDebugged:
   x64dbg_antidebug peb field="BeingDebugged"

2. Hide debugger:
   x64dbg_antidebug hide_debugger

3. Check other anti-debug flags:
   x64dbg_antidebug peb field="NtGlobalFlag"

4. Set exception to skip:
   x64dbg_exceptions skip exception_code="0x80000003"
```

### Pattern 4: Analyze Function

```
1. Disassemble function:
   x64dbg_disassembly function address="0x401000"

2. Get cross-references:
   x64dbg_analysis xrefs_to address="0x401000"
   x64dbg_analysis xrefs_from address="0x401000"

3. Get control flow:
   x64dbg_control_flow cfg address="0x401000"

4. Detect loops:
   x64dbg_control_flow loops address="0x401000"
```

### Pattern 5: Patch and Dump

```
1. Patch bytes:
   x64dbg_patches apply address="0x401000" bytes="90 90"

2. List patches:
   x64dbg_patches list

3. Dump modified section:
   x64dbg_dumping dump_module section=".text"

4. Export patch file:
   x64dbg_dumping export_patch_file filename="patch.bin"
```

## Memory Operations Deep Dive

### Reading Memory Types

| Type | Size | Use Case |
|------|------|----------|
| `byte` | 1 | Individual bytes |
| `word` | 2 | 16-bit values |
| `dword` | 4 | 32-bit values |
| `qword` | 8 | 64-bit values |
| `float` | 4 | Single precision |
| `double` | 8 | Double precision |
| `ascii` | N | Null-terminated string |
| `unicode` | N | Wide string |

### Writing Shellcode

```
1. Allocate memory:
   x64dbg_memory allocate size=0x1000 protect="rwx"

2. Write shellcode (as hex bytes):
   x64dbg_memory write address="0x20000" bytes="48 89 C7 ...""

3. Execute:
   x64dbg_debug run_to_address address="0x20000"
```

## Breakpoint Conditions

### Condition Syntax

x64dbg uses C-like expressions for conditions:
- `EAX == 0` - Register equality
- `DWORD[ESP+4] == 1` - Memory dereference
- `RAX > 0x100` - Comparison
- `strlen("test")` - Function calls

### Log Format Strings

```
Breakpoint log messages support:
{x} - Hex value
{d} - Decimal value
{s} - String at address
{@} - Current address

Example:
"Value at ESP+4: {d@RSP+4}"
"RAX points to: {s@RAX}"
```

> **调试方法论 + 插件生态 + 脚本系统**：读 `references/x64dbg-debugging-and-plugins.md`
> （软件/硬件/内存断点选型、xAnalyzer/ScyllaHide/TitanHide/Baymax、x64dbg 脚本语法与常用脚本）。

## Anti-Debug Bypass

### Common PEB Fields

| Field | Check | Bypass |
|-------|-------|--------|
| `BeingDebugged` | IsProcess64Bit | Set to 0 |
| `NtGlobalFlag` | Heap flags | Set to 0 |
| `ReadSharedEnvironment` | NtQueryInformationProcess | Hide debugger |

### Quick Bypass Commands

```
Hide from common checks:
x64dbg_antidebug hide_debugger

Verify PEB state:
x64dbg_antidebug peb

Check DEP:
x64dbg_antidebug dep

Skip INT3 breakpoints:
x64dbg_exceptions skip exception_code="0x80000003"
```

## Thread Analysis

### Listing Threads

```
Get all threads:
x64dbg_threads list

Get current thread:
x64dbg_threads current

Get thread info:
x64dbg_threads info thread_id=1234

Get TEB:
x64dbg_threads teb thread_id=1234
```

### Switching Threads

```
Switch to thread:
x64dbg_threads switch thread_id=5678

Suspend thread:
x64dbg_threads suspend thread_id=5678

Resume thread:
x64dbg_threads resume thread_id=5678
```

## PE Dumping

### Dump Types

| Type | Description |
|------|-------------|
| `pe_header` | Full PE header |
| `sections` | All sections |
| `imports` | Import directory |
| `exports` | Export directory |
| `entry_point` | Entry point code |
| `relocations` | Relocation data |

### IAT Reconstruction

```
1. Dump imports:
   x64dbg_dumping imports

2. Fix IAT:
   x64dbg_dumping fix_iat original_iat="0x401000"

3. Dump fixed module:
   x64dbg_dumping dump_module base="0x400000"
```

> **方法论**（OEP 定位体系 + IAT 重建算法 + ImportREC/Scylla/手修对比 + B1 三验判据）：
> 读 `references/unpacking-oep-iat.md`。本文件是「命令怎么敲」，那篇是「壳在哪、OEP 怎么找、
> IAT 怎么修、修完怎么判合格」。

## Error Handling

### Common Issues

| Error | Cause | Solution |
|-------|-------|----------|
| "Debugger must be paused" | Tool requires pause | Pause or hit breakpoint |
| "No active debug session" | No target loaded | File > Open in x64dbg |
| "Debugger must be running" | Command needs run state | Run target first |
| "Connection refused" | Plugin not loaded | Check x64dbg log |

### Debugging the Debugger

```
If tools fail:
1. Check plugin loaded:
   x64dbg_command execute command="mcpserver status"

2. Verify health:
   curl http://127.0.0.1:27042/api/health

3. Check debugger state:
   x64dbg_debug state
```

## Best Practices

1. **Always check state first** - Verify debugger is ready before operations
2. **Use symbolic names** - Breakpoint on CreateFileW vs raw addresses
3. **Set meaningful labels** - sub_401000 -> authenticate_user
4. **Log breakpoint conditions** - Don't just break, record values
5. **Document your findings** - Comments in x64dbg persist in IDB
6. **Use hardware breakpoints** - For memory access, don't modify code
7. **Export patches early** - Save your work before closing
8. **Understand calling conventions** - x64: RCX,RDX,R8,R9; x86: stack

## Quick Reference

### Debugger States
- `stopped` - No target
- `running` - Executing
- `paused` - Breakpoint hit or paused
- `terminated` - Process exited

### Common Registers (x64)
| Register | Purpose |
|----------|---------|
| RAX | Return value |
| RCX,RDX,R8,R9 | First 4 args |
| RSI,RDI | Source,Dest |
| RSP | Stack pointer |
| RBP | Frame pointer |
| RIP | Instruction pointer |

### Calling Conventions (x64)
1. Args in RCX, RDX, R8, R9
2. Stack aligned to 16 bytes
3. Shadow space (32 bytes) reserved
4. RAX returns value

### Calling Conventions (x86)
1. Args pushed right-to-left
2. EAX,ECX,EDX caller-saved
3. EBP,EBX,ESI,EDI callee-saved
4. EAX returns value

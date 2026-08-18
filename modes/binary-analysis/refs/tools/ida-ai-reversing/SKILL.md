---
name: ida-reversing
description: "Perform reverse engineering and binary analysis in IDA Pro using natural language commands powered by IDA MCP. Use this skill whenever the user wants to: analyze executable files, understand function behavior, decompile code, explore cross-references, search for strings or bytes, patch binary code, document reverse engineering findings, or any task related to IDA Pro analysis. Make sure to use this skill when users mention IDA, reverse engineering, binary analysis, decompilation, disassembly, malware analysis, exploit development, CTF challenges, or software security research - even if they don't explicitly mention 'MCP' or 'skill'."
---

# IDA Reversing Skill

This skill enables AI-powered reverse engineering in IDA Pro through the Model Context Protocol (MCP). It provides comprehensive guidance for analyzing binaries, understanding code behavior, and documenting findings.

## Prerequisites

- IDA Pro installed (version 7.0+ recommended)qq:212717393
- IDA MCP plugin installed and configured
- IDA MCP server running (typically on localhost:13337 or similar)

## Available Tools

The IDA MCP exposes these tool categories:

### Connection & Metadata
- `check_connection()` - Verify IDA MCP server is running
- `get_metadata()` - Get information about current IDB database

### Function Management
- `get_functions()` - List all functions in the binary
- `get_function_by_name(name)` - Get function info by exact name
- `get_function_by_address(address)` - Get function info by address
- `get_decompile_function(address)` - Get pseudocode decompilation
- `get_disasm(address)` - Get assembly disassembly

### Cross-References
- `get_xrefs_from(address)` - Get cross-references from an address
- `get_xrefs_to(address)` - Get cross-references to an address
- `callees(addrs)` - Get functions called by specified function(s)
- `callers(addr)` - Get functions that call specified function

### Data Operations
- `get_strings()` - List all strings in the binary
- `get_imports()` - List imported functions
- `get_exports()` - List exported functions
- `get_segments()` - List memory segments

### Search Operations
- `search_text(pattern)` - Search for text patterns
- `search_bytes(pattern)` - Search for byte sequences
- `search_immediate(value)` - Search for immediate values in instructions

### Type System
- `list_local_types()` - List all local types
- `get_type(address)` - Get inferred type at address
- `get_structs()` - List all structures/unions
- `get_struct(name)` - Get structure definition

### Modification Operations
- `set_comments(items)` - Set comments at addresses
- `rename_function(address, new_name)` - Rename functions
- `rename_variable(function, old_name, new_name)` - Rename local variables
- `patch_asm(items)` - Patch assembly instructions
- `apply_type(address, type_str)` - Apply type signature

### Stack Analysis
- `get_stack_frame(function)` - Get stack frame information

### Selection
- `get_selection()` - Get current IDA selection range

## Workflow

### 1. Initial Assessment

When given a new binary to analyze:

```
Always start with:
1. get_metadata() - Understand the binary
2. get_functions() - Get overview of all functions
3. get_imports() - Understand external dependencies
4. get_exports() - Identify entry points and interfaces
```

### 2. Function Analysis

**For understanding a specific function:**
1. Use `get_function_by_address()` or `get_function_by_name()`
2. Get decompilation with `get_decompile_function()`
3. Get cross-references to understand usage context
4. Analyze stack frame if relevant

**Pattern:**
```
get_function_by_address("0x401000")
get_decompile_function("0x401000")
get_xrefs_to("0x401000")  // Who calls this
get_xrefs_from("0x401000") // What does this call
```

### 3. String and Pattern Search

```
Finding interesting strings:
1. get_strings() - Get all strings
2. search_text("password") - Search for specific patterns

Finding cryptographic constants:
1. search_immediate(0x64) - Search for common crypto values
2. search_bytes("49 4E 47") - Search for magic bytes
```

### 4. Code Flow Analysis

```
Tracing execution flow:
1. Start with entry point or target function
2. Use get_xrefs_from() to find called functions
3. Use callees() for deeper call chain analysis
4. Document interesting code paths
```

## Function Analysis Workflow

### Identifying Key Functions

| Binary Type | Look For |
|------------|----------|
| PE/EXE | Entry point, WinMain, main, DllMain |
| DLL | Exported functions, DllEntryPoint |
| SO (Android) | JNI functions, native methods |
| Kernel driver | DriverEntry, IRP handlers |

### Decompilation Best Practices

```
When decompiling:
1. First get the function address and name
2. Read the pseudocode carefully
3. Cross-reference with assembly if pseudocode seems wrong
4. Rename variables for clarity
5. Add comments to document logic
6. Apply types for function signatures
```

### Common Function Signatures to Look For

| Category | Common Signatures |
|----------|------------------|
| Memory | malloc, calloc, free, memcpy, memset |
| File | fopen, fread, fwrite, fclose |
| Network | socket, connect, send, recv |
| Crypto | AES, RSA, SHA, MD5 initialization |
| String | strcpy, strcmp, strlen, sprintf |

## Cross-Reference Analysis

### Understanding Data Flow

```
Xrefs analysis pattern:
- get_xrefs_to() finds who USES this address
- get_xrefs_from() finds what THIS addresses USES

Example - finding string usage:
1. Find string with search_text("config")
2. Get xrefs_to for that string address
3. Analyze functions that reference it
```

### Call Graph Analysis

```
Call graph pattern:
callers() - Who calls this function (inverse call graph)
callees() - What does this function call (forward call graph)

For understanding a hook/callback:
1. get_xrefs_to(callback_addr) - Who registers it
2. get_xrefs_from(callback_addr) - What triggers it
```

## Search and Discovery

### String Search

```
get_strings() returns all strings - filter for:
- File paths (C:\\, /etc/, /var/)
- URLs and domains
- Error messages
- Debug output
- suspicious encoded data
```

### Byte Search

```
search_bytes() for:
- Magic bytes (MZ, \\x7fELF, PK\\x03\\x04)
- Protocol headers
- Embedded resources
- Encrypted signatures
```

### Immediate Value Search

```
search_immediate() for:
- Cryptographic constants (0x67, 0x101, 0x10001)
- Socket ports
- Flag values
- Protocol-specific numbers
```

## Type System

### Applying Types

```
For function signatures:
apply_type("0x401000", "int __stdcall connect(int s, const sockaddr *name, int namelen)")

For structures:
get_structs() to see available
get_struct("sockaddr_in") to see definition

For custom types:
list_local_types() to see what's defined
```

### Structure Analysis

```
Common structures to identify:
- sockaddr_in / sockaddr_in6 (network addresses)
- FILE (file handles)
- pthread_t / HANDLE (threads/processes)
- Custom protocol headers
```

## Code Annotation

### Commenting Strategy

```
Types of comments:
1. Repeatable comments - appear at all xref locations
2. Regular comments - at specific address

set_comments format:
[
  {"address": "0x401000", "text": "Initializes global config", "repeatable": true},
  {"address": "0x401050", "text": "Buffer overflow here!", "repeatable": false}
]
```

### Renaming Conventions

```
Function naming:
- Original names often stripped: sub_401000 -> calculate_checksum
- Use descriptive names based on behavior

Variable renaming:
- Local variables start with "var_"
- Registers have names like "r8" or "arg_0"
- Rename to meaningful names: var_10 -> bytes_read
```

## Binary Patching

### Safe Patching

```
patch_asm format:
[
  {"address": "0x401000", "old_bytes": "90 90", "new_bytes": "EB 01"},
  {"address": "0x401005", "old_bytes": "74 05", "new_bytes": "75 05"}
]

Always:
1. Document original bytes
2. Note why you're patching
3. Consider implications for other code
```

### Common Patches

| Patch Type | Use Case |
|-----------|----------|
| NOP slide | Remove instructions |
| JMP bypass | Skip problematic code |
| Byte change | Toggle flags/conditions |
| Function hook | Redirect calls |

## Security Analysis

### Common Vulnerability Patterns

| Vulnerability | IDA Pattern |
|--------------|-------------|
| Buffer overflow | strcpy, gets without bounds |
| Format string | printf(s) where s is user-controlled |
| Integer overflow | Length calculations before allocation |
| Use after free | Dereferencing freed pointers |
| Command injection | system, exec, popen with user input |

### Crypto Identification

```
Look for:
- Constant arrays (S-boxes, round keys)
- Shift/XOR operations in loops
- Comparison with expected hash
- RSA/ECC initialization
```

## Documentation

### Reverse Engineering Documentation Template

```
# Binary: [filename]
## Metadata
- Architecture: x86/x64/ARM
- Compiler: MSVC/GCC/Clang
- Stripped: Yes/No

## Entry Points
- main: 0x401000
- DllMain: 0x401500

## Key Functions
### Function 0x401000: calculate_checksum
- Purpose: [what it does]
- Inputs: [parameters]
- Outputs: [return values]
- Notes: [interesting observations]

## Strings of Interest
- "Password:" @ 0x404000
- "Config path" @ 0x404100

## Cross-Reference Graph
[document calling relationships]
```

## Error Handling

### Common Issues

| Issue | Solution |
|-------|----------|
| Function not found | Check address format (0x prefix) |
| Decompilation fails | Try disassembly instead |
| Connection refused | Verify IDA MCP server is running |
| Slow response | Large binaries may timeout, try smaller ranges |

### Debugging Analysis

```
If stuck:
1. Verify connection with check_connection()
2. Try simpler queries first (get_functions)
3. Check if IDB is loaded
4. Verify address is in valid segment
```

## Best Practices

1. **Always start broad** - Get overview before diving deep
2. **Document as you go** - Comments save time later
3. **Use xrefs extensively** - Understanding data flow is key
4. **Rename meaningfully** - sub_401000 is not helpful
5. **Apply types** - Function signatures clarify usage
6. **Cross-check decompilation** - Pseudocode can be misleading
7. **Consider context** - Same function name, different library versions
8. **Watch for stripped binaries** - May need signature matching

## Quick Reference

### Address Formats
- Hex with prefix: "0x401000"
- Some tools use: "401000" (no prefix)

### Function Patterns

```
get_function_by_address("0x401000")
get_decompile_function("0x401000")
get_xrefs_from("0x401000")
```

### Search Patterns

```
search_text("password")
search_bytes("49 4E 53")
search_immediate(8086)
```

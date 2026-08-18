---
description: Generate shellcode loaders by combining components from knowledge base. Creates working C/C++/Rust loaders using documented techniques. Triggers on "generate loader", "create loader", "shellcode loader", "生成loader".
argument-hint: Optional: count (e.g., "5" for batch), shellcode file (e.g., "path/to/shellcode.bin"), or filters (e.g., "--executor callback --shellcode my.bin")
---

# Loader Generate Command

Launch the loadergen-agent to generate shellcode loaders from the knowledge base.

## Usage

```bash
/loader_generate                                # Single random loader (uses samples/calc.bin)
/loader_generate 5                              # Batch generate 5 loaders
/loader_generate --shellcode path/to/sc.bin     # Use custom shellcode file
/loader_generate my.bin                         # Shorthand: use my.bin as shellcode
/loader_generate --executor callback            # Specific executor
/loader_generate --allocator NtAllocateVirtualMemory
/loader_generate --complexity medium            # Filter by complexity
/loader_generate --language rust                # Rust loader
/loader_generate 3 --shellcode custom.bin       # Batch with custom shellcode
```

## What This Command Does

1. **Queries components** from `loader_techniques.json`
2. **Checks duplicates** in `scenarios.json`
3. **Generates code** combining random/specified components
4. **Compiles** with MinGW (C/C++) or Cargo (Rust)
5. **Records result** in knowledge base

## Components

| Category | Options |
|----------|---------|
| Storage | embedded, resource, remote_url, encrypted_resource |
| Allocator | VirtualAlloc, HeapCreate, NtAllocateVirtualMemory |
| Copier | memcpy, RtlMoveMemory, loop_copy |
| Executor | function_pointer, CreateThread, callback, APC, Fiber |

## Output

- Generated source: `output/loader_<id>.c` (or `.cpp`, `.rs`)
- Compiled executable: `output/loader_<id>.exe`
- Knowledge base scenario ID

## Shellcode File

| Option | Description |
|--------|-------------|
| `--shellcode <path>` | Specify custom shellcode bin file |
| No flag | Uses default `samples/calc.bin` |
| Shorthand | `<file.bin>` treated as `--shellcode <file.bin>` |

Examples:
```bash
/loader_generate --shellcode ./payloads/custom.bin
/loader_generate 5 --shellcode my.bin
/loader_generate my.bin --executor callback
```

## Security

- Default shellcode: `samples/calc.bin` (for safe testing)
- Custom shellcode: user-provided bin files allowed
- **NEVER** run generated executables
- Compilation success is sufficient

## Agent

Spawns `loadergen-agent` subagent for code generation.

See `loader_generate` skill for detailed templates and workflow.

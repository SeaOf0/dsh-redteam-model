# Native Analysis

Use this reference when Java code delegates signing, token generation, encryption, or request assembly to JNI or `.so` libraries.

## Decision Tree

After JADX triage:

- If the algorithm is visible in Java, stay in Java
- If Java calls a `native` method, inspect the SO
- If the app works without a sign, do not reverse the SO unnecessarily
- If offline reproduction is required, consider unidbg after confirming the native call boundary

## First Pass on Native Code

Identify:

- `native` method declarations in Java
- `System.loadLibrary` call sites
- the target SO file name
- whether JNI is static (`Java_*` exports) or dynamic (`JNI_OnLoad`, `RegisterNatives`)

## Rizin Command Template

Prefer `rizin` / `rz-bin` for the first pass when available. It is a good fit for lightweight JNI and `.so` triage before deeper reversing.

### 1. Basic ELF triage

```bash
file libfoo.so
rz-bin -I libfoo.so
rz-bin -s libfoo.so
rz-bin -i libfoo.so
rz-bin -E libfoo.so
```

What to look for:

- architecture and bitness
- linked libraries
- exported `Java_*` symbols
- whether `JNI_OnLoad` is present
- suspicious imports such as crypto, socket, SSL, compression, or logging APIs

### 2. String search

```bash
rz-strings -a libfoo.so | rg 'http|https|Java_|JNI_OnLoad|RegisterNatives|encrypt|sign|ssl|socket'
```

Useful targets:

- URL or host fragments
- `RegisterNatives`
- log tags
- error strings
- crypto or signing hints

### 3. Function inventory and JNI entrypoints

```bash
rizin -qc "aaa; afl; q" libfoo.so
rizin -qc "aaa; afl~JNI; q" libfoo.so
rizin -qc "aaa; pdf @ sym.JNI_OnLoad; q" libfoo.so
rizin -qc "aaa; pdr @ sym.JNI_OnLoad; q" libfoo.so
```

Use this to answer:

- does the library export JNI functions directly?
- does `JNI_OnLoad` register methods dynamically?
- which functions are worth hooking first?

### 4. Save disassembly to local files

```bash
rizin -qc "aaa; pdf @ sym.JNI_OnLoad; q" libfoo.so > JNI_OnLoad.asm
rizin -qc "aaa; pdr @ sym.JNI_OnLoad; q" libfoo.so > JNI_OnLoad.pseudo.c
```

For a specific function:

```bash
rizin -qc "aaa; pdf @ sym.Java_com_example_Signer_getSign; q" libfoo.so > getSign.asm
```

### 5. Fallback without rizin

```bash
readelf -d libfoo.so
readelf -Ws libfoo.so
nm -D libfoo.so | rg 'Java_|JNI_OnLoad|RegisterNatives'
objdump -T libfoo.so
objdump -d libfoo.so > libfoo.objdump.asm
strings -a libfoo.so | rg 'http|https|Java_|JNI_OnLoad|RegisterNatives|encrypt|sign|ssl|socket'
```

Use the fallback path when `rizin` is unavailable or when you only need quick confirmation of JNI exports and suspicious strings.

## Questions to Answer

- What native method generates the value of interest?
- What arguments are passed in from Java?
- Which arguments vary per request?
- Which arguments are device- or session-bound?
- Is the return value the final sign, or an intermediate token?

## Practical Workflow

1. Find the Java call site
2. Record the Java-side arguments and nearby context
3. Inspect the SO for matching entrypoints
4. Confirm inputs and outputs with runtime hooks if possible
5. Only then decide whether deeper reversing is worth the effort

## Signs That Native Inspection Is Needed

- `native` methods are called during request preparation
- Java code only marshals arguments and immediately returns the native result
- sign-related constants or headers appear, but no Java implementation exists

## When to Escalate to unidbg

Use unidbg only when the user specifically needs one of these:

- offline signature generation
- repeatable execution without a live device
- deeper understanding of a native algorithm that cannot be recovered from light hooks

Do not jump to unidbg before identifying:

- the exact JNI entrypoint
- the minimal required arguments
- whether environment dependencies exist

## Output Template

```markdown
## Native Sign Assessment

- Java entrypoint: `com.example.Signer.nativeGetSign(...)`
- SO: `libsign.so`
- JNI style: dynamic registration
- Inputs: body, timestamp, deviceId, session token
- Output: request signature string
- Confidence: medium
- Recommended next step: Frida hook entry and return value before deeper SO analysis
```

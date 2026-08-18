---
allowed-tools: Bash, Read, Glob, Grep, Write, Edit
description: Decompile an Android APK/XAPK/JAR/AAR and analyze its structure
user-invocable: true
argument-hint: <path to APK, XAPK, JAR, or AAR file>
argument: path to APK, XAPK, JAR, or AAR file (optional)
---

# /decompile

Decompile an Android application and perform initial structure analysis.

## Instructions

You are starting the Android reverse engineering workflow. Follow these steps:

### Step 1: Get the target file

If the user provided a file path as an argument, use that. Otherwise, ask the user for the path to the APK, XAPK, JAR, or AAR file they want to decompile.

### Step 2: Check and install dependencies

Run the dependency check:

```bash
bash skills/android-reverse-engineering/scripts/check-deps.sh
```

Parse the output looking for `INSTALL_REQUIRED:` and `INSTALL_OPTIONAL:` lines.

**If required dependencies are missing**, install them one by one:

```bash
bash skills/android-reverse-engineering/scripts/install-dep.sh java
bash skills/android-reverse-engineering/scripts/install-dep.sh jadx
```

The install script auto-detects the OS and installs without sudo when possible (user-local install to `~/.local/`). If sudo is needed, it will prompt — if the user declines or sudo is unavailable, the script prints exact manual instructions (exit code 2). Show those instructions to the user and stop.

**For optional dependencies** (`INSTALL_OPTIONAL:vineflower`, `INSTALL_OPTIONAL:dex2jar`, `INSTALL_OPTIONAL:rizin`, etc.), ask the user if they want to install them. Recommend vineflower and dex2jar for better decompilation results, and recommend rizin when JNI or `.so` analysis is likely.

After any installations, re-run `check-deps.sh` to verify. Do not proceed until all required dependencies pass.

### Step 3: Decompile

Run the decompile script on the target file. Choose the engine based on the input:

- **APK or XAPK** → use jadx first (handles resources natively; XAPK is auto-extracted):
  ```bash
  bash skills/android-reverse-engineering/scripts/decompile.sh <file>
  ```

- **JAR/AAR** and Fernflower is available → prefer fernflower for better Java output:
  ```bash
  bash skills/android-reverse-engineering/scripts/decompile.sh --engine fernflower <file>
  ```

- **If jadx output has warnings** or the user wants the best quality → run both and compare:
  ```bash
  bash skills/android-reverse-engineering/scripts/decompile.sh --engine both <file>
  ```

If the next step may involve Frida, JNI `FindClass`, unidbg, or runtime class loading, keep the first pass **without** `--deobf` so class names stay closer to dex/runtime names.

Only add `--deobf` when readability matters more than runtime class fidelity:

```bash
bash skills/android-reverse-engineering/scripts/decompile.sh --deobf <file>
```

### Step 4: Analyze structure

After decompilation completes:

1. Read `AndroidManifest.xml` from the resources directory. For XAPK, check the base APK's output first.
2. If XAPK, review `xapk-manifest.json` in the output directory to understand the split structure.
3. List the top-level package structure
4. Identify the app's main Activity, Application class, and architecture pattern
5. Report a summary to the user

### Step 5: Offer next steps

Tell the user what they can do next:
- **Trace call flows**: "I can follow the execution flow from any Activity to its API calls"
- **Extract APIs**: "I can search for all HTTP endpoints and document them"
- **Analyze specific classes**: "Point me to a specific class or feature to analyze"
- **Re-decompile with Fernflower**: If jadx output has warnings, offer to re-run with `--engine both` for comparison
- **Triage runtime analysis**: "I can identify the best Frida hook point or request/sign boundary before any dynamic work"
- **Inspect JNI/sign logic**: "I can determine whether the token or sign is generated in Java or native code"
- **Inspect native `.so` files**: "I can use rizin to list JNI exports, inspect `JNI_OnLoad`, and export function disassembly"

## `.so` / Rizin Follow-up

If the user wants native analysis after decompilation, use `rizin` first when available:

```bash
rz-bin -I libfoo.so
rz-bin -s libfoo.so
rz-bin -i libfoo.so
rz-strings -a libfoo.so | rg 'http|https|Java_|JNI_OnLoad|RegisterNatives|encrypt|sign|ssl|socket'
rizin -qc "aaa; afl; q" libfoo.so
rizin -qc "aaa; pdf @ sym.JNI_OnLoad; q" libfoo.so
```

To save disassembly to a local file:

```bash
rizin -qc "aaa; pdf @ sym.JNI_OnLoad; q" libfoo.so > JNI_OnLoad.asm
```

If `rizin` is unavailable, fall back to:

```bash
readelf -Ws libfoo.so
nm -D libfoo.so | rg 'JNI_OnLoad|Java_|RegisterNatives'
objdump -d libfoo.so > libfoo.objdump.asm
strings -a libfoo.so | rg 'http|https|encrypt|sign|socket'
```

Refer to the full skill documentation in `skills/android-reverse-engineering/SKILL.md` for the complete workflow.

---
description: IDA Pro headless binary analysis (idalib)
allowed-tools: Bash, Read, Write, Glob, Grep, Agent, TodoWrite
---

# IDA Headless Binary Analysis Skill

Follow this workflow when a binary analysis is requested.

## Entry Point
All IDA operations are performed via the `ida-cli` command (global PATH command).
You can also use `python tools/ida_cli.py` when running from the project directory.
Do not use MCP or other tools.

## Workflow

### 1. Environment Check (first time only)
```bash
ida-cli --check
ida-cli --init
```

### 2. Start Instance
```bash
# Save IDB in current project folder (recommended)
ida-cli start <binary_path> --idb-dir .
# Note the instance_id from the output
ida-cli wait <id> --timeout 300
```
- **Always use `--idb-dir .` to save IDB files in the current project directory**
- If an .i64 already exists, it is automatically reused (completes in seconds)
- Use `--fresh` to ignore existing .i64 and reanalyze from scratch
- Use `--force` to allow duplicate instances of the same binary
- You can do other work while waiting for analysis

### 3. Initial Reconnaissance
Survey the binary in this order:
```bash
# Comprehensive overview (segments, imports, functions, strings at once)
ida-cli -b <hint> summary

# Or query individually:
ida-cli -b <hint> status
ida-cli -b <hint> imagebase
ida-cli -b <hint> segments

# Data collection (use --out to save context window space)
ida-cli -b <hint> strings --count 50 --out /tmp/strings.txt
ida-cli -b <hint> imports --count 50 --out /tmp/imports.txt
ida-cli -b <hint> exports --out /tmp/exports.txt
ida-cli -b <hint> functions --filter <keyword> --out /tmp/funcs.txt

# Pagination for large function lists
ida-cli -b <hint> functions --offset 100 --count 100
```
- Use `status` first to check decompiler availability and function count
- Use `-b <hint>` to auto-select an instance by binary name substring

### 4. Deep Analysis
```bash
# Find function
ida-cli -b <hint> find_func <name> [--regex]

# Decompile
ida-cli -b <hint> decompile <addr|name> [--out /tmp/func.c]

# Decompile with xrefs (include callers/callees)
ida-cli -b <hint> decompile <addr|name> --with-xrefs

# Batch decompile
ida-cli -b <hint> decompile_batch <addr1> <addr2> ... [--out /tmp/batch.c]

# Disassembly
ida-cli -b <hint> disasm <addr|name> --count 50

# Function details
ida-cli -b <hint> func_info <addr|name>

# Cross-references
ida-cli -b <hint> xrefs <addr> --direction both

# Read bytes
ida-cli -b <hint> bytes <addr> <size>

# Byte pattern search
ida-cli -b <hint> find_pattern "48 8B ? ? 00" --max 20

# Get comments
ida-cli -b <hint> comments <addr>

# List available RPC methods
ida-cli -b <hint> methods
```

### 5. Modification & Iterative Analysis
```bash
ida-cli -b <hint> rename <addr> <new_name>
ida-cli -b <hint> set_type <addr> "int __fastcall func(int a, int b)"
ida-cli -b <hint> comment <addr> "description text"
ida-cli -b <hint> save
```
> **Iterative analysis pattern**: After applying rename/set_type, decompile again —
> variable names and types will be reflected, producing much more readable code.
> Repeat this cycle for key functions.

### 6. Shutdown
```bash
ida-cli stop <id>
```

## Multi-Instance Workflow

When analyzing a main binary and its libraries simultaneously:
```bash
# Start both binaries
ida-cli start ./main_binary --idb-dir .
ida-cli start ./libcrypto.so --idb-dir .

# Use -b hint to target each instance
ida-cli -b main decompile 0x401000
ida-cli -b crypto decompile 0x12340

# Check instance list
ida-cli list
```

## Analysis Strategies

### String Tracing Pattern (most fundamental RE technique)
The fastest way to reach target code:
1. `strings --filter <keyword>` → find suspicious strings
2. `xrefs <string_addr>` → locate code that references the string
3. `decompile <xref_addr>` → analyze the calling function
4. Trace xrefs again if needed (callers of callers)

### Security Solution Analysis
1. Search for security keywords via strings/imports (root, jailbreak, ssl, cert, integrity, frida, xposed, magisk, etc.)
2. List related functions with find_func
3. Decompile key functions
4. Trace call relationships with xrefs
5. Record results with rename/set_type/comment → decompile again for cleaner view

### Firmware/IoT Analysis
1. `segments` to understand memory layout (ROM/RAM regions)
2. `strings` to find device identifiers, commands, protocol keywords
3. `find_func --regex "uart|spi|i2c|gpio"` → hardware interface functions
4. `exports` to identify public symbols → find main entry points
5. `find_pattern` to search for magic bytes / struct headers

### Vulnerability Research
1. Search imports for dangerous functions (memcpy, strcpy, sprintf, system, exec, etc.)
2. `xrefs` on each dangerous function → find call sites
3. `decompile` to analyze call context (buffer sizes, input validation)
4. `func_info` to check function size and arguments
5. `bytes` to verify stack buffer sizes and offsets

### Malware Analysis
1. `strings` to find C2 domains, IPs, registry keys, file paths
2. Check imports for networking (socket, connect, send), file manipulation, process injection APIs
3. `find_func --regex "crypt|encode|decode|xor"` → crypto/encoding routines
4. `decompile_batch` for bulk analysis of suspicious functions
5. `find_pattern` for hardcoded keys/IVs/XOR tables

### Handling Large Results
- Always save to file with `--out`, then read with Read tool
- Limit result scope with `--count`, `--filter`
- Use `--offset` for pagination (browsing large function lists)
- Use `--json` mode for structured data

## Batch Analysis
```bash
# Analyze all binaries in a directory at once
ida-cli batch <directory> --idb-dir . --timeout 300

# Run analysis profile (malware/firmware/vuln)
ida-cli -b <hint> profile run malware
ida-cli -b <hint> profile run vuln
ida-cli -b <hint> profile run firmware
```

## Bookmarks (address tagging across sessions)
```bash
# Add bookmark
ida-cli bookmark add <addr> <tag> --note "description" -b <hint>

# List bookmarks
ida-cli bookmark list
ida-cli bookmark list --tag vuln

# Remove bookmark
ida-cli bookmark remove <addr>
```
> Bookmarks are saved as `.ida-bookmarks.json` in the current project directory.

## Error Handling
- Analysis failure: `ida-cli logs <id> --tail 20`
- Locked/corrupted .i64 (`open_database returned 2`): delete the .i64 file, then restart with `--fresh`
- Rebuild .i64: `ida-cli start <binary> --fresh`
- Instance list: `ida-cli list`
- Cleanup: `ida-cli cleanup`

## Decision Criteria: IDA vs Other Tools
- Java/Kotlin code → JADX
- Simple .so inspection → Ghidra
- Security solution core logic, unclear Ghidra results → **Use IDA CLI**
- Multi-architecture (ARM/MIPS/PPC/V850/ARC) → **Use IDA CLI**
- Firmware/IoT binaries → **Use IDA CLI**

## User Argument: $ARGUMENTS
When invoked as `/ida-eng <binary_path>`, immediately start analysis on the specified binary.
If no binary path is provided, ask the user what to analyze.
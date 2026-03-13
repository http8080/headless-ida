---
description: IDA Pro headless binary analysis (idalib)
allowed-tools: Bash, Read, Write, Glob, Grep, Agent, TodoWrite
---

# IDA Headless Binary Analysis Skill

Follow this workflow when a binary analysis is requested.

## Entry Point
All IDA operations are performed exclusively via `python tools/ida_cli.py`.
Do not use MCP or other tools.

## Workflow

### 1. Environment Check (first time only)
```bash
python tools/ida_cli.py --check
python tools/ida_cli.py --init
```

### 2. Start Instance
```bash
python tools/ida_cli.py start <binary_path>
# To save IDB locally in the project:
python tools/ida_cli.py start <binary_path> --idb-dir <project_directory>
# Note the instance_id from the output
python tools/ida_cli.py wait <id> --timeout 300
```
- If an .i64 already exists, it is automatically reused (completes in seconds)
- Use `--idb-dir` to specify a per-project IDB storage path
- You can do other work while waiting for analysis

### 3. Initial Reconnaissance
Survey the binary in this order:
```bash
python tools/ida_cli.py -b <hint> imagebase
python tools/ida_cli.py -b <hint> segments
python tools/ida_cli.py -b <hint> strings --count 50 --out C:/tmp/strings.txt
python tools/ida_cli.py -b <hint> imports --count 50 --out C:/tmp/imports.txt
python tools/ida_cli.py -b <hint> exports --out C:/tmp/exports.txt
python tools/ida_cli.py -b <hint> functions --filter <keyword> --out C:/tmp/funcs.txt
```
- Use `--out` to save context window space
- Use `-b <hint>` to auto-select an instance by binary name substring

### 4. Deep Analysis
```bash
# Find function
python tools/ida_cli.py -b <hint> find_func <name> [--regex]

# Decompile
python tools/ida_cli.py -b <hint> decompile <addr|name> [--out C:/tmp/func.c]

# Disassembly
python tools/ida_cli.py -b <hint> disasm <addr|name> --count 50

# Function details
python tools/ida_cli.py -b <hint> func_info <addr|name>

# Cross-references
python tools/ida_cli.py -b <hint> xrefs <addr> --direction both

# Read bytes
python tools/ida_cli.py -b <hint> bytes <addr> <size>

# Byte pattern search
python tools/ida_cli.py -b <hint> find_pattern "48 8B ? ? 00" --max 20

# Batch decompile
python tools/ida_cli.py -b <hint> decompile_batch <addr1> <addr2> ... --out C:/tmp/batch.json
```

### 5. Modification (if needed)
```bash
python tools/ida_cli.py -b <hint> rename <addr> <new_name>
python tools/ida_cli.py -b <hint> comment <addr> "description text"
python tools/ida_cli.py -b <hint> save
```

### 6. Shutdown
```bash
python tools/ida_cli.py stop <id>
```

## Analysis Strategy

### Security Solution Analysis
1. Search for security-related keywords via strings/imports (root, jailbreak, ssl, cert, integrity, etc.)
2. List related functions with find_func
3. Decompile key functions
4. Trace call relationships with xrefs
5. Record analysis results with rename/comment

### Handling Large Results
- Always save to file with `--out`, then read with Read tool
- Limit result scope with `--count`, `--filter`
- Use `--json` mode for structured data

## Error Handling
- Analysis failure: `python tools/ida_cli.py logs <id> --tail 20`
- Corrupted .i64: `python tools/ida_cli.py start <binary> --fresh`
- Instance list: `python tools/ida_cli.py list`
- Cleanup: `python tools/ida_cli.py cleanup`

## Decision Criteria: IDA vs Other Tools
- Java/Kotlin code → JADX
- Simple .so inspection → Ghidra
- Security solution core logic, unclear Ghidra results → **Use IDA CLI**

## User Argument: $ARGUMENTS
When invoked as `/ida-eng <binary_path>`, immediately start analysis on the specified binary.
If no binary path is provided, ask the user what to analyze.

---
name: ida-analysis
description: "Headless IDA Pro binary analysis via ida-cli. Auto-trigger when user requests binary analysis, reverse engineering, decompilation, disassembly, or malware/firmware/vulnerability analysis of executables, DLLs, or shared objects."
allowed-tools: Bash, Read, Write, Glob, Grep, Agent, TodoWrite
argument-hint: "[binary_path]"
---

# IDA Headless Binary Analysis

All IDA operations use the `ida-cli` CLI tool (globally installed via PATH).
Fallback: `python tools/ida_cli.py` from the project directory.
Do NOT use MCP or other tools for IDA operations.

## Quick Start

```bash
# 1. Start instance (save IDB in project dir)
ida-cli start <binary_path> --idb-dir .
ida-cli wait <id> --timeout 300

# 2. Overview
ida-cli -b <hint> summary

# 3. Analyze
ida-cli -b <hint> decompile <addr|name>
ida-cli -b <hint> xrefs <addr> --direction both

# 4. Stop
ida-cli stop <id>
```

## Command Reference

### Instance Management
| Command | Description |
|---------|-------------|
| `start <binary> --idb-dir .` | Start analysis (always use `--idb-dir .`) |
| `stop <id>` | Stop instance |
| `status` / `-b <hint> status` | Instance status |
| `wait <id> --timeout N` | Wait for analysis completion |
| `list` / `list --json` | List all instances |
| `logs <id> --tail N` | View instance logs |
| `cleanup` | Remove stale instances |

### Reconnaissance
| Command | Description |
|---------|-------------|
| `summary` | Full overview (segments, imports, functions, strings) |
| `segments` | Memory layout |
| `imagebase` | Binary base address |
| `functions [--filter X] [--count N] [--offset N]` | List functions |
| `strings [--filter X] [--count N]` | List strings |
| `imports [--filter X] [--count N]` | List imports |
| `exports` | List exports |

### Deep Analysis
| Command | Description |
|---------|-------------|
| `decompile <addr\|name> [--out F] [--with-xrefs]` | Decompile function |
| `decompile_batch <a1> <a2> ... [--out F]` | Batch decompile |
| `decompile-all --out F [--filter X]` | Decompile all functions |
| `disasm <addr\|name> --count N` | Disassemble |
| `find_func <name> [--regex]` | Find function by name |
| `func_info <addr\|name>` | Function details (size, args, type) |
| `xrefs <addr> --direction to\|from\|both` | Cross-references |
| `cross-refs <addr> --depth N --direction to\|from\|both` | Multi-level xref chain |
| `callgraph <addr> --depth N --direction callers\|callees` | Call graph (mermaid/dot) |
| `basic-blocks <addr> [--format dot] [--out F]` | CFG / basic blocks |
| `bytes <addr> <size>` | Read raw bytes |
| `find_pattern "48 8B ? ?" --max N` | Byte pattern search |
| `search-const 0x1234 --max N` | Search constant values |
| `search-code "keyword" --max N` | Search in decompiled pseudocode |
| `strings-xrefs --filter X --max N` | Strings + referencing functions |
| `data-refs [--segment .data] [--filter X]` | Data reference analysis |
| `func-similarity <addrA> <addrB>` | Compare two functions |
| `comments <addr>` | Get comments at address |

### Types & Structures
| Command | Description |
|---------|-------------|
| `type-info list [--kind typedef\|funcptr\|struct\|enum]` | List local types |
| `type-info show <name>` | Show type details |
| `structs list [--filter X] [--count N] [--offset N]` | List structs |
| `structs show <name>` | Show struct members |
| `structs create <name> --members "f1:4" "f2:8"` | Create struct |
| `enums list [--filter X] [--count N] [--offset N]` | List enums |
| `enums show <name>` | Show enum members |
| `enums create <name> --members "OK=0" "ERR=1"` | Create enum |
| `vtables [--min-entries 3]` | Detect virtual function tables |
| `sigs list` / `sigs apply <name>` | FLIRT signatures |

### Modification
| Command | Description |
|---------|-------------|
| `rename <addr> <new_name>` | Rename symbol |
| `set_type <addr> "type_string"` | Set function/variable type |
| `comment <addr> "text"` | Set comment |
| `patch <addr> 90 90 90` | Patch bytes (requires exec_enabled) |
| `auto-rename [--apply] [--max-funcs N]` | Heuristic rename sub_ functions |
| `save` | Save IDB |

### Persistence & Reporting
| Command | Description |
|---------|-------------|
| `annotations export --output F.json` | Export names/comments/types |
| `annotations import F.json` | Import annotations |
| `snapshot save [--description "..."]` | Save IDB snapshot |
| `snapshot list` / `snapshot restore <file>` | Manage snapshots |
| `export-script --output F.py` | Generate IDAPython script |
| `report output.md [--functions addr1 addr2]` | Generate report |
| `bookmark add <addr> <tag> --note "..."` | Tag addresses |
| `profile run malware\|firmware\|vuln` | Run analysis profile |

### Advanced
| Command | Description |
|---------|-------------|
| `exec "python_code"` | Execute IDA Python (requires exec_enabled) |
| `batch <dir> --idb-dir . --timeout N` | Batch analyze directory |
| `compare old.exe new.exe --out diff.json` | Binary diff |
| `code-diff <instA> <instB>` | Decompiled code diff |

## Key Options

- `-b <hint>` — Select instance by binary name substring (e.g., `-b note` for notepad.exe)
- `--out <path>` — Save output to file (suppresses inline display, saves context)
- `--count N` / `--offset N` — Pagination
- `--filter <keyword>` — Filter results by name
- `--format mermaid|dot` — Graph output format
- `--json` — JSON output mode
- `--fresh` — Ignore existing .i64, reanalyze from scratch
- `--force` — Allow duplicate instances

## Analysis Strategies

### String Tracing (fastest path to target code)
1. `strings --filter <keyword>` -> find target strings
2. `xrefs <string_addr>` -> locate referencing code
3. `decompile <xref_addr>` -> analyze the function
4. Repeat xrefs upward (callers of callers)

### Iterative Refinement
1. `decompile <addr>` -> read raw output
2. `rename` / `set_type` / `comment` -> annotate
3. `decompile <addr>` again -> much cleaner output
4. Repeat for key functions

### Security / Anti-Tamper
Search strings/imports for: root, jailbreak, ssl, cert, integrity, frida, xposed, magisk, hook, patch

### Malware
1. `strings` for C2, IPs, registry keys, file paths
2. `imports` for networking, process injection, file APIs
3. `find_func --regex "crypt|encode|decode|xor"` for crypto
4. `find_pattern` for hardcoded keys/IVs

### Vulnerability Research
1. `imports` for dangerous functions (memcpy, strcpy, sprintf, system)
2. `xrefs` on each -> find call sites
3. `decompile` to check buffer sizes, input validation

### Firmware/IoT
1. `segments` for memory layout (ROM/RAM)
2. `find_func --regex "uart|spi|i2c|gpio"` for HW interfaces
3. `exports` for entry points

## Context Efficiency Tips

- Use `--out /tmp/file` to save large results to file, then `Read` the file
- Use `--count` and `--filter` to limit output scope
- Use `summary` instead of separate segments + imports + strings calls
- Use `decompile_batch` instead of multiple single decompile calls
- Use `profile run <type>` for automated reconnaissance

## Error Handling

- Analysis failure: `logs <id> --tail 20`
- Locked .i64 (`open_database returned 2`): delete .i64, restart with `--fresh`
- Instance issues: `list` then `cleanup`

## Tool Selection

| Binary Type | Tool |
|-------------|------|
| Java/Kotlin (APK) | JADX |
| Simple .so inspection | Ghidra |
| Native code, security solutions, multi-arch | **IDA CLI** |
| Firmware/IoT | **IDA CLI** |

## User Argument: $ARGUMENTS
When invoked with a binary path, immediately start analysis on that binary.
If no path provided, ask the user what to analyze.

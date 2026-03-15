---
description: IDA Pro headless binary analysis (idalib)
allowed-tools: Bash, Read, Write, Glob, Grep, Agent, TodoWrite
---

# IDA Headless Binary Analysis

All IDA operations use the `ida-cli` CLI tool (globally installed via PATH).
Fallback: `python tools/ida_cli.py` from the project directory.
Do NOT use MCP or other tools for IDA operations.

## Quick Start

```bash
# 1. Environment check (first time only)
ida-cli --check
ida-cli --init

# 2. Start instance (save IDB in project dir)
ida-cli start <binary_path> --idb-dir .
ida-cli wait <id> --timeout 300

# 3. Overview
ida-cli -b <hint> summary

# 4. Analyze
ida-cli -b <hint> decompile <addr|name>
ida-cli -b <hint> xrefs <addr> --direction both

# 5. Stop
ida-cli stop <id>
```

## Complete Command Reference

### Environment & Setup
```bash
ida-cli --check                           # Check IDA/Python environment
ida-cli --init                            # Initialize directories
```

### Instance Management
```bash
ida-cli start <binary> --idb-dir .        # Start analysis (always use --idb-dir .)
  # Options: --fresh (ignore existing .i64), --force (allow duplicate instances)
ida-cli stop <id>                         # Stop instance
ida-cli restart <id>                      # Stop + re-start (same binary/IDB)
  # Options: --fresh (reanalyze from scratch)
ida-cli status                            # Status (auto-resolves -b hint)
ida-cli wait <id> --timeout 300           # Wait for analysis completion
ida-cli list                              # List all instances
ida-cli list --json                       # List instances as JSON (includes idb_path)
ida-cli logs <id> --tail 20               # View instance logs
ida-cli cleanup                           # Remove stale instances
ida-cli save                              # Save IDB database
```

### Reconnaissance
```bash
ida-cli -b <hint> summary                 # Full overview (segments, imports, functions, strings)
ida-cli -b <hint> segments                # Memory layout (addr, name, class, size, perms)
ida-cli -b <hint> imagebase               # Binary base address

# Data collection (use --out to save context window space)
ida-cli -b <hint> functions [--filter X] [--count N] [--offset N] [--out F]
ida-cli -b <hint> strings [--filter X] [--count N] [--offset N] [--out F]
  # Options: --encoding unicode|ascii (filter by string type)
ida-cli -b <hint> imports [--filter X] [--count N] [--out F]
ida-cli -b <hint> exports [--out F]
```

### Decompilation & Disassembly
```bash
# Decompile (--out suppresses inline output, saves to file only)
ida-cli -b <hint> decompile <addr|name> [--out /tmp/func.c]
ida-cli -b <hint> decompile <addr|name> --raw            # Pure C code (no header/addresses)
ida-cli -b <hint> decompile <addr|name> --with-xrefs    # Include callers/callees
ida-cli -b <hint> decompile <addr|name> --out result.md  # Markdown output

# Batch decompile (--out suppresses inline output)
ida-cli -b <hint> decompile_batch <a1> <a2> ... [--out /tmp/batch.c]
ida-cli -b <hint> decompile_batch <a1> <a2> --out batch.md  # Markdown output

# Decompile all functions to file
ida-cli -b <hint> decompile-all --out /tmp/all.c [--filter X]
  # Options: --include-thunks, --include-libs, --split (one file per function)

# Disassembly
ida-cli -b <hint> disasm <addr|name> --count 50
```

### Function Analysis
```bash
ida-cli -b <hint> find_func <name> [--regex]       # Find function by name/regex
ida-cli -b <hint> func_info <addr|name>             # Function details (size, args, type)
ida-cli -b <hint> stack-frame <addr|name>            # Stack frame layout (locals, args, offsets)
ida-cli -b <hint> switch-table <addr|name>           # Analyze switch/jump tables
ida-cli -b <hint> func-similarity <addrA> <addrB>   # Compare two functions by similarity
ida-cli -b <hint> auto-rename [--apply] [--max-funcs 200]  # Heuristic rename sub_ functions
```

### Cross-References
```bash
ida-cli -b <hint> xrefs <addr> --direction to|from|both
ida-cli -b <hint> callers <addr>                           # Shortcut: xrefs --direction to
ida-cli -b <hint> callees <addr>                           # Shortcut: xrefs --direction from
ida-cli -b <hint> cross-refs <addr|name> --depth 3 --direction to|from|both
  # Options: --format mermaid|dot, --out F
```

### Call Graph & Control Flow
```bash
# Call graph (mermaid or DOT format)
ida-cli -b <hint> callgraph <addr|name> --depth 3 --direction callers|callees
ida-cli -b <hint> callgraph <addr> --format dot --out graph.dot

# Basic blocks + CFG
ida-cli -b <hint> basic-blocks <addr|name>
ida-cli -b <hint> basic-blocks <addr> --format dot --out cfg.dot
ida-cli -b <hint> basic-blocks <addr> --graph-only   # Graph output only
```

### Search
```bash
ida-cli -b <hint> search-code "keyword" --max 10      # Search in decompiled pseudocode
  # Options: --max-funcs N (limit functions to scan)
ida-cli -b <hint> search-const 0x1234 --max 20         # Search constant/immediate values
ida-cli -b <hint> find_pattern "48 8B ? ? 00" --max 20 # Byte pattern search
ida-cli -b <hint> strings-xrefs --filter http --max 20  # Strings + referencing functions
  # Options: --min-refs N, --out F
ida-cli -b <hint> data-refs --max 50                    # Data segment reference analysis
  # Options: --segment .data, --filter X
```

### Raw Data
```bash
ida-cli -b <hint> bytes <addr> <size>     # Read raw bytes (hex + base64)
ida-cli -b <hint> comments <addr>          # Get comments at address
```

### Types & Structures
```bash
# Local types
ida-cli -b <hint> type-info list [--kind typedef|funcptr|struct|enum|other]
ida-cli -b <hint> type-info show <type_name>

# Structs
ida-cli -b <hint> structs list [--filter X] [--count N] [--offset N]
ida-cli -b <hint> structs show <struct_name>
ida-cli -b <hint> structs create <name> --members "field1:4" "field2:8"

# Enums
ida-cli -b <hint> enums list [--filter X] [--count N] [--offset N]
ida-cli -b <hint> enums show <enum_name>
ida-cli -b <hint> enums create <name> --members "OK=0" "ERR=1"

# VTable detection
ida-cli -b <hint> vtables [--min-entries 3]

# FLIRT signatures
ida-cli -b <hint> sigs list
ida-cli -b <hint> sigs apply <sig_name>
```

### Modification
```bash
ida-cli -b <hint> rename <addr> <new_name>
ida-cli -b <hint> rename-batch mapping.csv             # Batch rename from CSV (addr,name) or JSON
ida-cli -b <hint> set_type <addr> "int __fastcall func(int a, int b)"
ida-cli -b <hint> comment <addr> "description text"
ida-cli -b <hint> patch <addr> 90 90 90               # NOP patch (requires exec_enabled)
ida-cli -b <hint> save                                 # Save IDB
```
> **Iterative analysis**: After rename/set_type, decompile again --
> variable names and types will be reflected, producing much more readable code.

### Annotations & Snapshots
```bash
# Export/import all names/comments/types as JSON
ida-cli -b <hint> annotations export --out analysis.json
ida-cli -b <hint> annotations import analysis.json

# IDB snapshots (backup before experimental changes)
ida-cli -b <hint> snapshot save --description "before refactoring"
ida-cli -b <hint> snapshot list                        # Shows description from .meta.json
ida-cli -b <hint> snapshot restore <snapshot_file>     # Auto-resolves from IDB dir

# Generate IDAPython script (reproducible analysis)
ida-cli -b <hint> export-script --out analysis.py
```

### Bookmarks (address tagging across sessions)
```bash
ida-cli bookmark add <addr> <tag> --note "description" -b <hint>
ida-cli bookmark list
ida-cli bookmark list --tag vuln
ida-cli bookmark remove <addr>
```
> Saved as `.ida-bookmarks.json` in the project directory.

### Report Generation
```bash
ida-cli -b <hint> report output.md                     # Markdown report
ida-cli -b <hint> report output.html                   # HTML report
ida-cli -b <hint> report output.md --functions 0x401000 0x402000  # Include decompilations
```
> Reports include: summary, segments, imports, exports, strings, bookmarks, optional functions.

### Batch & Profile Analysis
```bash
# Batch analyze all binaries in directory
ida-cli batch <directory> --idb-dir . --timeout 300

# Automated analysis profiles
ida-cli -b <hint> profile run malware
ida-cli -b <hint> profile run vuln
ida-cli -b <hint> profile run firmware
```

### Binary Comparison (Patch Diffing)
```bash
ida-cli -b <hint> compare old.exe new.exe --out diff.json
ida-cli -b <hint> code-diff <instanceA> <instanceB> [--functions func1 func2]
ida-cli -b <hint> diff                                 # Compare two running instances
```

### IDA Python Execution
```bash
# Requires security.exec_enabled=true in shared/config.json
ida-cli -b <hint> exec "import idautils; print(len(list(idautils.Functions())))"
ida-cli -b <hint> exec "import idc; print(idc.get_segm_name(0x140001000))"
ida-cli -b <hint> shell                                # Interactive IDA Python REPL
```

### Utility
```bash
ida-cli -b <hint> methods                              # List available RPC methods
ida-cli update                                         # Update tool from git
ida-cli completions --shell bash|zsh|fish|powershell   # Generate shell completions
```

## Key Global Options

- `-b <hint>` -- Select instance by binary name substring (e.g., `-b note` for notepad.exe)
- `-i <id>` -- Select instance by ID
- `--out <path>` -- Save output to file (decompile/decompile_batch suppress inline output)
- `--count N` / `--offset N` -- Pagination for large result sets
- `--filter <keyword>` -- Filter results by name substring
- `--format mermaid|dot` -- Graph output format (callgraph, cross-refs, basic-blocks)
- `--json` -- JSON output mode
- `--fresh` -- Ignore existing .i64, reanalyze from scratch
- `--force` -- Allow duplicate instances of same binary

## Multi-Instance Workflow

```bash
# Start multiple binaries simultaneously
ida-cli start ./main_binary --idb-dir .
ida-cli start ./libcrypto.so --idb-dir .

# Target each instance with -b hint
ida-cli -b main decompile 0x401000
ida-cli -b crypto decompile 0x12340

# Check all instances
ida-cli list
ida-cli list --json
```

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
4. `decompile_batch` for bulk analysis of suspicious functions
5. `find_pattern` for hardcoded keys/IVs/XOR tables

### Vulnerability Research
1. `imports` for dangerous functions (memcpy, strcpy, sprintf, system, exec)
2. `xrefs` on each dangerous function -> find call sites
3. `decompile` to check buffer sizes, input validation
4. `func_info` to check function size and arguments
5. `bytes` to verify stack buffer sizes and offsets

### Firmware/IoT
1. `segments` for memory layout (ROM/RAM regions)
2. `strings` for device identifiers, commands, protocol keywords
3. `find_func --regex "uart|spi|i2c|gpio"` for HW interface functions
4. `exports` for public symbols / entry points
5. `find_pattern` for magic bytes / struct headers

## Context Efficiency Rules

**CRITICAL: Follow these rules to avoid wasting context window.**

### Always use `--out` for large output
```bash
# BAD: dumps hundreds of lines into context
ida-cli -b <hint> decompile <addr>
ida-cli -b <hint> functions

# GOOD: saves to file, only "Saved to:" printed
ida-cli -b <hint> decompile <addr> --out /tmp/func.c
ida-cli -b <hint> functions --out /tmp/funcs.txt
```
Then use `Read` with offset/limit to read only the portion you need:
```
Read /tmp/funcs.txt offset=1 limit=50   # first 50 lines only
```

### Search first, decompile later
```bash
# BAD: decompile everything then search manually
ida-cli -b <hint> decompile-all --out /tmp/all.c

# GOOD: search → find target → decompile only what matters
ida-cli -b <hint> search-code "password" --max 10
ida-cli -b <hint> strings --filter "http" --count 20
ida-cli -b <hint> decompile <found_addr> --out /tmp/target.c
```

### Use combined commands
```bash
# BAD: 3 separate calls (3x context cost)
ida-cli -b <hint> strings --filter login
ida-cli -b <hint> xrefs <addr1>
ida-cli -b <hint> xrefs <addr2>

# GOOD: 1 call does both
ida-cli -b <hint> strings-xrefs --filter login --max 20
```

### Limit result counts aggressively
```bash
# BAD: fetches all 2000 functions
ida-cli -b <hint> functions

# GOOD: paginate with --count and --offset
ida-cli -b <hint> functions --count 30
ida-cli -b <hint> functions --count 30 --offset 30  # next page
```

### Use Agent subagents for independent analysis
Delegate independent analysis tasks to subagents to protect main context:
```
Agent: "Analyze crypto functions in binary X"
Agent: "Find all network-related imports in binary Y"
```
Each subagent returns only a summary, keeping main context clean.

### Other tips
- Use `summary` instead of separate segments + imports + strings calls
- Use `decompile_batch` instead of multiple single decompile calls
- Use `profile run <type>` for automated reconnaissance
- Use `--json` for machine-readable output when post-processing

## Error Handling

- Analysis failure: `logs <id> --tail 20`
- Locked/corrupted .i64 (`open_database returned 2`): delete .i64, restart with `--fresh`
- Rebuild .i64: `start <binary> --fresh`
- Instance issues: `list` then `cleanup`

## Tool Selection

| Binary Type | Tool |
|-------------|------|
| Java/Kotlin (APK) | JADX |
| Native binaries (.so, .dll, .exe, .dylib) | **IDA CLI** |
| Security solutions, multi-arch | **IDA CLI** |
| Firmware/IoT | **IDA CLI** |

## User Argument: $ARGUMENTS
When invoked as `/ida-eng <binary_path>`, immediately start analysis on the specified binary.
If no binary path is provided, ask the user what to analyze.
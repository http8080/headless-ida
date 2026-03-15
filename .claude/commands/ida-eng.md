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
ida-cli logs <id> --follow                # Follow logs in real-time
ida-cli cleanup [--dry-run]               # Remove stale instances
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
ida-cli -b <hint> find_func <name> [--regex] [--out F]  # Find function by name/regex
ida-cli -b <hint> func_info <addr|name>             # Function details (size, args, type)
ida-cli -b <hint> stack-frame <addr|name>            # Stack frame layout (locals, args, offsets)
ida-cli -b <hint> switch-table <addr|name>           # Analyze switch/jump tables
ida-cli -b <hint> func-similarity <addrA> <addrB>   # Compare two functions by similarity
ida-cli -b <hint> auto-rename [--apply] [--max-funcs 200]  # Heuristic rename sub_ functions
```

### Cross-References
```bash
# xrefs: single-level cross-references (direct callers/callees only)
ida-cli -b <hint> xrefs <addr> --direction to|from|both
ida-cli -b <hint> callers <addr>                           # Shortcut: xrefs --direction to
ida-cli -b <hint> callees <addr>                           # Shortcut: xrefs --direction from

# cross-refs: multi-level chain tracing (follows caller chains up to --depth levels)
ida-cli -b <hint> cross-refs <addr|name> --depth 3 --direction to|from|both
  # Options: --format mermaid|dot, --out F
```
> **xrefs vs cross-refs**: `xrefs` shows direct (1-level) references. `cross-refs` traces chains recursively up to `--depth` levels and outputs as mermaid/DOT graph. Use `xrefs` for quick lookups, `cross-refs` for understanding call chains.

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
  # Options: --max-funcs N (limit functions to scan), --case-sensitive
  # WARNING: Decompiles every function to search. Slow on large binaries (1000+ funcs).
  #          Use --max-funcs to limit scope, or prefer strings-xrefs for string searches.
ida-cli -b <hint> search-const 0x1234 --max 20 [--out F]  # Search constant/immediate values
ida-cli -b <hint> find_pattern "48 8B ? ? 00" --max 20 [--out F]  # Byte pattern search
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
ida-cli -b <hint> comment <addr> "description text" [--repeatable] [--type line|func]
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
ida-cli -b <hint> profile run malware    # C2, crypto, anti-analysis, network APIs
ida-cli -b <hint> profile run vuln       # Dangerous functions (memcpy, strcpy, sprintf, system)
ida-cli -b <hint> profile run firmware   # Peripherals (UART/SPI/GPIO), protocols, boot
```

### Binary Comparison (Patch Diffing)
```bash
ida-cli -b <hint> compare old.exe new.exe --out diff.json
ida-cli -b <hint> code-diff <instanceA> <instanceB> [--functions func1 func2]
ida-cli -b <hint> diff <instance_a> <instance_b>         # Compare two running instances
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
ida-cli completions --shell bash|zsh|powershell   # Generate shell completions
```

## Key Global Options

- `-b <hint>` -- Select instance by binary name substring (e.g., `-b note` for notepad.exe)
- `-i <id>` -- Select instance by ID
- `--out <path>` -- Save output to file (decompile/decompile_batch suppress inline output)
- `--count N` / `--offset N` -- Pagination for list commands (functions, strings, imports, exports, structs, enums)
- `--max N` -- Limit results for search commands (find_func, find_pattern, search-const, search-code, vtables, strings-xrefs, data-refs)
- `--filter <keyword>` -- Filter results by name substring
- `--format mermaid|dot` -- Graph output format (callgraph, cross-refs, basic-blocks)
- `--json` -- JSON output mode
- `--fresh` -- Ignore existing .i64, reanalyze from scratch
- `--force` -- Allow duplicate instances of same binary
- `--count-only` -- Show only total count (for functions/strings/imports/exports)
- `--version` -- Show CLI version

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

# GOOD: just get the count first
ida-cli -b <hint> functions --count-only

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

## Output Format Examples

### summary
```
Binary:      example.exe
Decompiler:  True
IDA:         9.3
Functions:   521  (avg size: 293 bytes)
Strings:     584
Imports:     340
Exports:     1
```

### decompile
```
// wWinMain @ 0x140010100
int __stdcall wWinMain(HINSTANCE hInstance, ...) {
  /* 0x140010119 */ sub_rsp(0x90);
  ...
}
```

### decompile --raw
```
int __stdcall wWinMain(HINSTANCE hInstance, ...) {
  sub_rsp(0x90);
  ...
}
```
(No header line, no address comments — minimal tokens for LLM analysis)

### functions
```
0x140001000  sub_140001000                                     size=42
0x14000102A  wWinMain                                          size=1200
```

### xrefs / callers / callees
```
Xrefs TO 0x140010100 (3)
  0x14001A000  sub_14001A000                     Code_Near
  0x14001B200  __mainCRTStartup                  Code_Near
```

### func-similarity
```
  Function A: sub_140001000 (0x140001000)  size=256  blocks=12  callees=5
  Function B: sub_140002000 (0x140002000)  size=280  blocks=14  callees=6

  Similarity:
    Size ratio:      0.9143
    Block ratio:     0.8571
    Callee Jaccard:  0.6000
    Overall:         0.7905
```
(Overall 1.0 = identical, 0.0 = completely different)

### stack-frame
```
  Function: process_data (0x140001000)
  Frame size: 120  (locals=96, args=16, retaddr=8)
  Members: 5

  | Offset |   Size | Name                           | Type                 | Kind |
  |     0  |     64 | buf                            | char[64]             | local|
  |    64  |      8 | result                         | __int64              | local|
  |    96  |      8 | return_addr                    |                      | retaddr|
  |   104  |      8 | arg_0                          | void *               | arg  |
```

### find_func
```
Query: 'main' (3 matches)
  0x140010100  wWinMain
  0x14001A000  __mainCRTStartup
  0x14001B200  mainCRTStartup
```

### search-const
```
  Value: 0x1234  Found: 2
    0x140001050  cmp     eax, 1234h  [sub_140001000]
    0x140002100  mov     ecx, 1234h  [process_data]
```

### find_pattern
```
Pattern: '48 8B ? ? 00' (5 matches)
  0x140001000
  0x140001200
  0x140002500
```

### vtables
```
VTables found: 2
  0x140050000  4 entries  [near CMyClass::vftable]
    [0] 0x140001000  sub_140001000
    [1] 0x140001200  sub_140001200
    [2] 0x140001400  sub_140001400
    [3] 0x140001600  sub_140001600
  0x140050040  3 entries
    [0] 0x140002000  sub_140002000
    [1] 0x140002200  sub_140002200
    [2] 0x140002400  sub_140002400
```

### decompile-all --split
When `--split` is used, `--out` is treated as a directory path. Each function is saved to a separate `.c` file named after the function:
```
output_dir/
  wWinMain.c
  sub_140001000.c
  process_data.c
  ...
```
Without `--split`, all functions are written to a single file separated by `// ── funcname` headers.

### callgraph (mermaid)
```mermaid
graph TD
  main --> init_config
  main --> process_data
  process_data --> validate_input
```

## Analysis Decision Flowchart

```
What are you analyzing?
│
├─ Unknown binary (first look)
│  → summary → strings --filter <keyword> → xrefs → decompile
│
├─ Looking for specific function
│  → find_func <name> [--regex] → decompile → callers / callees
│
├─ Vulnerability hunting
│  → imports (memcpy, strcpy, sprintf, system, exec)
│  → xrefs on dangerous funcs → decompile call sites
│  → bytes to verify buffer sizes
│
├─ Malware analysis
│  → profile run malware (automated recon)
│  → strings (C2, URLs, registry) → imports (network, process APIs)
│  → find_func --regex "crypt|encode|xor" → decompile_batch
│
├─ Comparing two versions (patch diff)
│  → start both binaries → code-diff or compare
│
├─ Understanding call flow
│  → callgraph <addr> --direction callees --depth 3
│  → basic-blocks <addr> for CFG
│
├─ Bulk analysis / full dump
│  → decompile-all --out /tmp/all.c [--filter X]
│  → decompile_batch <addr1> <addr2> ... --out /tmp/batch.c
│
└─ Firmware/IoT
   → segments (memory layout) → strings (device IDs, protocols)
   → find_func --regex "uart|spi|i2c|gpio" → exports
```

## Common Pitfalls

1. **Not waiting after start** — `start` returns immediately while IDA analyzes. Always `wait <id> --timeout 300` before any analysis command.

2. **Forgetting `--out` for decompile** — Decompile output floods context window. Always use `--out /tmp/file` then `Read` the file.

3. **Address format** — IDA expects hex with `0x` prefix (e.g., `0x140001000`). Function names also work (e.g., `main`, `sub_140001000`).

4. **xrefs direction confusion** — `--direction to` = "who calls this" (callers), `--direction from` = "what this calls" (callees). Use `callers`/`callees` shortcuts to avoid confusion.

5. **Locked .i64** — Error `open_database returned 2` means IDB is locked/corrupted. Delete the `.i64` file and restart with `--fresh`.

6. **No decompiler** — Not all IDA installs have Hex-Rays. Check `summary` for `decompiler: true/false`. Without it, use `disasm` instead.

7. **Forgetting to save** — After `rename`/`set_type`/`comment`, run `save` to persist changes to the .i64 database.

8. **Context flooding from large lists** — Never fetch all functions/strings at once. Use `--count 30` and `--offset` for pagination.

## Error Handling & Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `open_database returned 2` | .i64 locked or corrupted | Delete .i64, restart with `--fresh` |
| `CONNECTION_FAILED` | Server process crashed | Run `cleanup`, then `start` again |
| `NOT_A_FUNCTION` | Address is not inside a function | Check the hint in error message for nearest functions |
| `INVALID_ADDRESS` | Symbol name not found | Use `find_func --regex <name>` or `functions --filter <name>` |
| `DECOMPILER_NOT_LOADED` | No Hex-Rays license | Use `disasm` instead of `decompile` |
| `EXEC_DISABLED` | exec not enabled | Set `security.exec_enabled=true` in config.json |
| `TIMEOUT` | Analysis taking too long | Increase `--timeout`, or check `logs <id>` for issues |
| Instance shows "analyzing" | Initial auto-analysis running | Wait: `wait <id> --timeout 300` |

### Quick Fixes
- **Analysis failure**: `logs <id> --tail 20` to check what went wrong
- **Stale instances**: `list` then `cleanup` to remove dead entries
- **Rebuild .i64**: `start <binary> --fresh` (ignores existing database)

## Tool Selection

| Binary Type | Tool |
|-------------|------|
| Java/Kotlin (APK) | JADX |
| Native code (.so, .dll, .exe, .dylib), security solutions, multi-arch | **IDA CLI** |
| Firmware/IoT | **IDA CLI** |

## User Argument: $ARGUMENTS
When invoked as `/ida-eng <binary_path>`, immediately start analysis on the specified binary.
If no binary path is provided, ask the user what to analyze.
# Headless IDA Project

## Project Overview
A system that uses idalib (Hex-Rays official headless library) to perform
binary analysis via Claude's bash_tool without the IDA Pro GUI.

## Architecture
```
Claude → bash_tool → ida_cli.py → HTTP JSON-RPC → ida_server.py (import idapro)
```
- No MCP layer — Pure HTTP JSON-RPC
- Single-threaded HTTPServer (idalib single-thread constraint)
- .i64 reuse for faster repeated analysis

## Core Files
- `tools/ida_cli.py` — Single entry point for Claude (instance management + analysis proxy)
- `tools/ida_server.py` — idalib-based HTTP JSON-RPC server (24 APIs)
- `tools/common.py` — Shared module (config, registry, lock, file_md5, auth_token)
- `tools/config.json` — Global settings
- `tools/arch_detect.py` — Binary header parsing

## Using ida_cli.py for Binary Analysis

### Instance Start/Stop
```bash
python tools/ida_cli.py start <binary>       # Start instance (use --idb-dir to specify save path)
python tools/ida_cli.py wait <id>             # Wait for analysis completion
python tools/ida_cli.py stop <id>             # Stop
python tools/ida_cli.py list                  # List active instances
```

### Analysis Commands (-i can be omitted when only one instance is running)
```bash
python tools/ida_cli.py functions [--count N] [--filter STR]
python tools/ida_cli.py strings [--count N] [--filter STR]
python tools/ida_cli.py imports [--count N]
python tools/ida_cli.py exports [--count N]
python tools/ida_cli.py segments
python tools/ida_cli.py decompile <addr|name> [--out FILE]
python tools/ida_cli.py disasm <addr|name> [--count N]
python tools/ida_cli.py xrefs <addr> [--direction to|from|both]
python tools/ida_cli.py find_func <name> [--regex]
python tools/ida_cli.py func_info <addr|name>
python tools/ida_cli.py imagebase
python tools/ida_cli.py bytes <addr> <size>
python tools/ida_cli.py find_pattern <hex_pattern> [--max N]
```

### Modification Commands
```bash
python tools/ida_cli.py rename <addr> <new_name>
python tools/ida_cli.py comment <addr> "text" [--type func]
python tools/ida_cli.py save
```

### Global Options
- `--json` : JSON output mode
- `-i <id>` : Specify instance ID
- `-b <hint>` : Auto-select by binary name
- `--out FILE` : Save results to file (saves context window)

### start-only Options

- `--idb-dir <path>` : Override IDB save directory (default: config's paths.idb_dir)

## Important Notes
- IDA modules (idapro, idc, etc.) are only available at runtime — ignore IDE static analysis warnings
- The `exec` command only works when `security.exec_enabled` is true in `config.json`
- Path comparison on Windows must use `os.path.normcase()`
- Python 3.14 is incompatible due to IDA 9.3 Known Issue (3.12/3.13 recommended)

# Headless IDA Analysis System Design Document v2.0

---

## 1. Project Overview

**Goal**: A lightweight system allowing Claude to directly use IDA Pro analysis features via bash_tool only, without the IDA Pro GUI

**v1.7 → v2.0 Core Change**: idat -S script approach → **idalib (Hex-Rays official headless library)** transition

**Requirements**
- IDA Pro **9.1 or higher** (9.x series) — `open_database(args=...)` parameter added in 9.1
- Python **3.12 or 3.13** (major.minor must match what IDA expects)
  - ⚠️ Python 3.14: IDA 9.3 Known Issue ("PySide6 crashes under Python 3.14"), do not use
  - IDAPython is built with Stable ABI (abi3) via SWIG `-py3-limited-api`, but in practice matching the IDA-bundled Python version is recommended
- idapro Python package (whl included with IDA installation)
- Hex-Rays decompiler license (optional; assembly-only mode if absent)
- Windows 10/11 (primary target)

**Core Principles**
- No GUI required (headless execution via idalib)
- No MCP layer (direct bash_tool calls)
- Supports all binaries/architectures supported by IDA
- Reduced repeated analysis time via .i64 reuse
- Usable as a Claude skill
- **Single-threaded model** — execute_sync, register_timer not needed

---

## 2. Architecture

```
v1.7 (idat -S, removed):
Claude → bash_tool → ida_cli.py → HTTP JSON-RPC → idat.exe internal script
  Problems:
  - register_timer trick to keep process alive (fragile, unofficial Hex-Rays)
  - execute_sync for main thread dispatch (deadlock risk)
  - ThreadingHTTPServer + auto_wait thread safety complexity
  - notify_when(NW_TERMIDA) + atexit double defense required

v2.0 (idalib, current):
Claude → bash_tool → ida_cli.py → HTTP JSON-RPC → ida_server.py (import idapro)
  Advantages:
  - Python process is the host → loads IDA engine as a library
  - Single-threaded HTTPServer → all IDA APIs called directly from main thread
  - Deadlock impossible, execute_sync/register_timer not needed
  - Hex-Rays official recommended approach
  - Clean shutdown via idapro.close_database()
```

**Removed Components**

| v1.7 | v2.0 | Reason |
|------|------|--------|
| start_ida.py | Removed (merged into ida_cli.py) | idalib does not require idat.exe |
| params.json | Removed (command-line arguments) | ida_server.py is a regular Python script |
| execute_sync | Removed | Single-threaded, no dispatch needed |
| register_timer | Removed | Python is host, serve_forever() keeps process alive |
| ThreadingHTTPServer | HTTPServer (single-threaded) | idalib single-thread constraint |
| notify_when(NW_TERMIDA) | Removed | Use idapro.close_database() |

**File Structure**

```
tools/
├── config.json          ← Global configuration (load priority 1)
├── common.py            ← Shared module (config, registry, lock, file_md5, auth_token)
├── arch_detect.py       ← Binary header parsing, architecture detection (for display only)
├── ida_server.py        ← idalib-based HTTP JSON-RPC server (imports common.py)
└── ida_cli.py           ← Sole entry point for Claude (imports common.py)

%USERPROFILE%\.ida-headless\
├── config.json                ← Global configuration (load priority 2)
├── ida_servers.json           ← Instance registry (created at runtime)
├── ida_servers.json.lock      ← Registry lock file (runtime)
├── auth_token                 ← Authentication token (multi-line: instance_id:port:token)
├── idb\
│   ├── <binary>_<md5-8chars>.i64
│   └── <binary>_<md5-8chars>.i64.meta.json
└── logs\
    ├── <instance_id>.log
    └── <instance_id>.log.1 ~ .3
```

---

## 3. Supported Scope

### 3-1. File Formats

| Category | Format |
|----------|--------|
| Windows | PE32, PE64, .NET, DOS MZ, NE, LE/LX |
| Linux/Unix | ELF32, ELF64 |
| macOS/iOS | Mach-O 32/64, FAT binary, dylib, dyld_shared_cache |
| Android | ELF (ARM/ARM64/x86), DEX, APK native .so |
| Firmware | Raw binary, Intel HEX, Motorola SREC |
| VM | .pyc, Java .class, .dex |
| Other | COFF, OMF, AR archive |

### 3-2. Hex-Rays Decompiler Supported Architectures

⚠️ **IDA 9.0+**: Unified binary. `idat64.exe` removed → `idat.exe` handles both 32/64-bit.
Database also uses `.i64` single format (`.idb` is legacy, auto-converted).

| Architecture | 32-bit Plugin | 64-bit Plugin |
|-------------|---------------|---------------|
| x86 | hexrays | hexx64 |
| ARM (including Thumb) | hexarm | hexarm64 |
| MIPS | hexmips | hexmips64 |
| PowerPC | hexppc | hexppc64 |
| RISC-V | hexrv | hexrv64 |

⚠️ Even in IDA 9.x unified binary, decompiler plugins are **maintained separately for 32/64-bit**.
Must check target binary bitness via `ida_ida.inf_is_64bit()` and load the appropriate plugin.

Standard plugin loading (IDA 9.x):
```python
import ida_ida, ida_loader, ida_hexrays

# proc_name → (32bit_plugin, 64bit_plugin)
# proc_name obtained via ida_ida.inf_get_procname()
# ⚠️ ida_idp.get_ph().id causes AttributeError in IDA 9.3 — do not use
_DECOMPILER_MAP = {
    "metapc": ("hexrays", "hexx64"),
    "ARM":    ("hexarm",  "hexarm64"),
    "mips":   ("hexmips", "hexmips64"),
    "PPC":    ("hexppc",  "hexppc64"),
    "RISCV":  ("hexrv",   "hexrv64"),
}

proc_name = ida_ida.inf_get_procname()
is_64 = ida_ida.inf_is_64bit()
entry = _DECOMPILER_MAP.get(proc_name)
plugin_name = entry[1 if is_64 else 0] if entry else None
if plugin_name:
    plg = ida_loader.load_plugin(plugin_name)
    if plg and ida_hexrays.init_hexrays_plugin():
        pass  # decompiler ready
```

### 3-3. Decompilation Unsupported Cases

| Case | Handling |
|------|----------|
| DEX / APK Java code | Delegate to JADX MCP |
| .NET PE | Assembly only, decompilation not supported |
| Raw firmware (architecture unknown) | Requires --arch manual specification, assembly only |

---

## 4. Python Environment

### 4-1. Prerequisites

⚠️ **Python Version Compatibility**

IDAPython is built with SWIG `-py3-limited-api` (Stable ABI / abi3), theoretically making it
version-independent across Python 3.x, but in practice matching the IDA-bundled Python version is safer.

```
Recommended Python versions (based on IDA 9.3):
  Python 3.12 or 3.13 (must match the version shown by idapyswitch)

Incompatible:
  Python 3.14 — IDA 9.3 Known Issue ("PySide6 crashes under Python 3.14")
                Officially unsupported by Hex-Rays, do not use

How to check:
  Run idapyswitch.exe → displays expected Python version
  That Python version must be installed on the system
  ※ idapyswitch only changes the runtime Python DLL path, no .pyd recompile

Note:
  Python 3.13 support added in IDA 9.0sp1
  idapro-*.whl is "py3-none-any" (pure Python), but
  IDA installation's python/lib-dynload/*.pyd are native → version-dependent
```

### 4-2. idapro Package Installation

```bash
# 1. Install whl (included in IDA installation directory)
pip install "<IDA_DIR>/idalib/python/idapro-*.whl"

# 2. Register IDA installation path (choose one of two methods)
# Method A: Run py-activate-idalib.py
python "<IDA_DIR>/idalib/python/py-activate-idalib.py"

# Method B: Set IDADIR environment variable
set IDADIR=C:\Program Files\IDA Professional 9.3
```

### 4-3. Dependency Packages

```
pip install requests psutil idapro-*.whl

idapro   → idalib headless library Python bindings
requests → HTTP calls (ida_cli.py)
psutil   → Cross-platform process liveness check / force kill
```

### 4-4. --check Validation Items

```
[ ] IDA installation directory exists
[ ] IDA version >= 9.1 (args parameter required)
[ ] idapro package installed (pip show idapro)
[ ] idapro import successful (python -c "import idapro")
[ ] IDA Python version == system Python version (major.minor match)
[ ] Python version != 3.14 (Known Issue warning)
[ ] requests installed
[ ] psutil installed
[ ] Required directories exist (idb, logs)
[ ] idb directory write permission check (validated via tempfile.NamedTemporaryFile)
[ ] No spaces in tools/ directory path

Implementation:
  python -c "import idapro; v=idapro.get_library_version(); print(f'{v[0]}.{v[1]}.{v[2]}')"
  → Performs idapro import + version check in one step
  → On import failure, error message identifies the cause
  → If version is 9.0: "IDA 9.1+ required (open_database args not supported)" warning
  → If Python 3.14 detected: "Python 3.14 is an IDA 9.3 Known Issue, use 3.12/3.13" warning
```

---

## 5. Component Design

### Entry Point Structure

**Claude uses only ida_cli.py.**

```
ida_cli.py               ← Sole entry point for Claude (bash_tool)
  ├── start command      → Internally runs ida_server.py via subprocess
  ├── stop/status/wait   → HTTP RPC or registry polling
  └── Analysis commands  → HTTP RPC calls

ida_server.py            ← idalib-based HTTP server (regular Python script)
arch_detect.py           ← Called internally by ida_cli.py start
```

---

### 5-0. config.json

```json
{
  "ida": {
    "install_dir": "C:/Program Files/IDA Professional 9.3"
  },
  "paths": {
    "idb_dir":    "%USERPROFILE%/.ida-headless/idb",
    "log_dir":    "%USERPROFILE%/.ida-headless/logs",
    "registry":   "%USERPROFILE%/.ida-headless/ida_servers.json"
  },
  "analysis": {
    "auto_save":             true,
    "wait_timeout":          300,
    "wait_poll_interval":    2,
    "heartbeat_interval":    60,
    "stale_threshold":       300,
    "open_db_timeout":       600,
    "max_instances":         3,
    "request_timeout":       35,
    "request_timeout_batch": 300
  },
  "server": {
    "host":                  "127.0.0.1"
  },
  "output": {
    "max_inline_lines":      200,
    "default_count":         100,
    "max_count":             500,
    "encoding":              "utf-8"
  },
  "security": {
    "exec_enabled": false,
    "auth_token_file": "%USERPROFILE%/.ida-headless/auth_token"
  },
  "log": {
    "max_size_mb": 50,
    "backup_count": 3
  }
}
```

Settings removed compared to v1.7:
```
ida.idat                         → idat.exe not needed (using idalib)
paths.params_dir                 → params.json not needed (command-line arguments)
server.timer_interval            → register_timer not needed
server.execute_sync_timeout      → execute_sync not needed
server.execute_sync_timeout_batch → execute_sync not needed
```

Settings changed compared to v1.7:
```
analysis.auto_wait_timeout → analysis.open_db_timeout (renamed, same role)
```

Load priority:
```
1. config.json in current directory
2. %USERPROFILE%\.ida-headless\config.json
3. Fallback to defaults + warning output
```

Environment variable substitution:
```python
%USERPROFILE%  → os.environ["USERPROFILE"]
%TEMP%         → os.environ["TEMP"]
%APPDATA%      → os.environ["APPDATA"]
# Backslash → forward slash conversion, final os.path.normpath() applied
```

---

### 5-1. arch_detect.py

Role: Binary header parsing → architecture + file format detection (for informational display)

⚠️ **IDA 9.x**: `idat.exe` auto-detects 32/64-bit so binary selection is not needed.
arch_detect is used only for user display purposes.
**Actual plugin loading is decided by ida_server.py based on `ida_ida.inf_get_procname()`** (does not depend on arch_detect results).
⚠️ `ida_idp.get_ph().id` causes `AttributeError` in IDA 9.3 — must use `ida_ida.inf_get_procname()`.

Detection rules (for display purposes):
```
ELF e_machine + EI_CLASS (offset 4: 1=32bit, 2=64bit):
  0x03              → x86     (32bit)
  0x3E              → x86     (64bit)
  0x28              → arm     (32bit)
  0xB7              → arm     (64bit)
  0x08 + EI_CLASS=1 → mips    (32bit)
  0x08 + EI_CLASS=2 → mips    (64bit)
  0x14              → ppc     (32bit)
  0x15              → ppc     (64bit)
  0xF3              → riscv   (32/64 distinguished by EI_CLASS)

PE Machine:
  0x014C → x86     (32bit)
  0x8664 → x86     (64bit)
  0x01C0 → arm     (32bit)   (IMAGE_FILE_MACHINE_ARM)
  0x01C4 → arm     (32bit)   (IMAGE_FILE_MACHINE_ARMNT, Thumb-2)
  0xAA64 → arm     (64bit)

Mach-O cputype (magic: 0xFEEDFACE/0xFEEDFACF, FAT: 0xCAFEBABE):
  0x00000007 (CPU_TYPE_X86)       → x86  (32bit)
  0x01000007 (CPU_TYPE_X86_64)    → x86  (64bit)
  0x0000000C (CPU_TYPE_ARM)       → arm  (32bit)
  0x0100000C (CPU_TYPE_ARM64)     → arm  (64bit)
  0x00000012 (CPU_TYPE_POWERPC)   → ppc  (32bit)
  0x01000012 (CPU_TYPE_POWERPC64) → ppc  (64bit)

  FAT binary magic (4 variants):
    0xCAFEBABE (FAT_MAGIC)    — big-endian FAT
    0xBEBAFECA (FAT_CIGAM)    — FAT as read on little-endian host
    0xCAFEBABF (FAT_MAGIC_64) — 64-bit FAT
    0xBFBAFECA (FAT_CIGAM_64) — 64-bit FAT as read on little-endian host
  → Print slice list → require --arch manual selection
  Note: 0xCAFEBABE is the same as Java .class magic. Distinguish by subsequent bytes.

Detection failure → fallback to --arch manual specification
```

Output:
```json
{
  "arch": "arm",
  "bits": 64,
  "file_format": "ELF"
}
```

---

### 5-2. ida_server.py

Environment: System Python + idapro package

```python
SERVER_VERSION = "2.0"
```

#### Core Changes (v1.7 → v2.0)

| v1.7 (idat -S internal script) | v2.0 (standalone Python script) |
|--------------------------------|----------------------------------|
| Runs inside idat.exe process | **Runs as regular Python process** |
| Receives parameters via idc.ARGV | **Receives arguments via argparse** |
| auto_wait() main thread + HTTP background | **open_database() blocking → HTTP start** |
| Dispatches IDA API via execute_sync | **Called directly from main thread** |
| register_timer keeps process alive | **serve_forever() keeps process alive** |
| ThreadingHTTPServer (multi-threaded) | **HTTPServer (single-threaded)** |
| notify_when + atexit double defense | **idapro.close_database() + atexit** |

#### Lifecycle

```
Input: ida_server.py <binary> --id <instance_id> --idb <idb_path>
                     --log <log_path> --config <config_path> [--fresh]
  ↓
1. Parse argparse arguments
  ↓
2. Load config.json + environment variable substitution
  ↓
3. Initialize log file (RotatingFileHandler)
  ↓
4. Update registry: state=analyzing, pid=os.getpid(),
   pid_create_time=psutil.Process(os.getpid()).create_time()    [lock]
  ↓
5. Start open_db_timeout watchdog thread
  ↓
6. import idapro  ← must be the first IDA-related import
  ↓
7. Branch based on .i64 existence:

   [New analysis: no .i64 or --fresh]
   result = idapro.open_database(binary_path, True, args=f"-o{idb_prefix}")
   # -o<prefix>: specifies DB output path within idb_dir
   # ⚠️ -o implies -c (create new DB) → for new analysis only
   # ⚠️ args parameter added in IDA 9.1 (not supported in 9.0)
   # True: run auto analysis + wait for completion (blocking)
   _save_idb_metadata(idb_path, binary_path)

   [.i64 reuse]
   # Binary change detection
   stored_md5 = _load_idb_metadata(idb_path).get("binary_md5")
   current_md5 = _file_md5(binary_path)
   if stored_md5 and stored_md5 != current_md5:
       log.warning(f"Binary changed: stored={stored_md5} current={current_md5}")
       # ida_cli.py already confirmed --force before reaching here
   result = idapro.open_database(idb_path, True)
   # Open .i64 directly → -o not used (existing DB)
   # Minimal analysis queue processing (a few seconds)
  ↓
8. Check open_database result
   result != 0 → state=error, log, sys.exit(1)
   result == 0 → cancel watchdog (_open_db_done.set())
  ↓
9. Load decompiler plugin (based on _DECOMPILER_MAP)
  ↓
10. Collect cacheable values (main thread):
    _ida_version_cached = ida_kernwin.get_kernel_version()  # idaapi is umbrella, use proper module
    _binary_name, _arch_info, etc.
  ↓
11. save_db() — save initial analysis results
  ↓
12. Generate auth token + save to file
  ↓
13. Create HTTP server (port 0 → OS auto-assigns)
  ↓
14. Start heartbeat thread (only updates registry timestamp, no IDA API calls)
  ↓
15. Update registry: state=ready, port=N    [lock]
  ↓
16. server.serve_forever()  ← blocking in main thread (sequential request processing)
  ↓
17. (After serve_forever exits) Cleanup:
    idapro.close_database(save=True)
    Remove instance from registry
    Remove corresponding line from auth_token file
    Close log
```

⚠️ **Core simplification**: HTTP server starts only after open_database() returns.
In analyzing state **no HTTP communication** — ida_cli.py checks state by polling registry file.

#### idalib Single-Thread Constraint

```
idapro/__init__.py documentation:
  "All library functions must be called from the same thread that
   initialized the library. The library is single-threaded, and
   performing database operations from a different thread may result
   in undefined behavior."

→ Use HTTPServer (single-threaded)
→ Request handler runs in main thread → IDA API calls are safe
→ Only one request processed at a time (Claude makes sequential calls, so no issue)
→ Heartbeat thread only updates registry file (no IDA API calls, safe)
```

#### open_database Timeout

```python
_open_db_timeout = config["analysis"]["open_db_timeout"]  # default 600 seconds
_open_db_done = threading.Event()

def _open_db_watchdog():
    """Force exit if open_database does not complete within the specified time"""
    if _open_db_done.wait(timeout=_open_db_timeout):
        return  # normal completion
    log.error(f"open_database timeout ({_open_db_timeout}s). Forcing exit.")
    _update_state("error")
    os._exit(1)

watchdog = threading.Thread(target=_open_db_watchdog, daemon=True)
watchdog.start()

# open_database call
result = idapro.open_database(binary_path, True, args=args_str)
_open_db_done.set()  # cancel watchdog
```

#### HTTP Server

```python
import secrets
from http.server import HTTPServer, BaseHTTPRequestHandler

AUTH_TOKEN = secrets.token_urlsafe(32)

# port 0 → OS automatically assigns an available port
server = HTTPServer((host, 0), RpcHandler)
port = server.server_address[1]

# Save to token file (lock protected)
if not acquire_lock():
    log.error("Could not acquire lock for auth_token write")
    sys.exit(1)
try:
    with open(token_path, 'a') as f:
        f.write(f"{instance_id}:{port}:{AUTH_TOKEN}\n")
finally:
    release_lock()

class RpcHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # 1. Validate Host header (DNS rebinding defense)
        host_header = self.headers.get("Host", "")
        allowed = [f"127.0.0.1:{port}", f"localhost:{port}"]
        if host_header not in allowed:
            self._send_json({"error": {"code": "FORBIDDEN_HOST",
                             "message": "Invalid Host header"}, "id": None})
            return

        # 2. Validate auth token
        auth = self.headers.get("Authorization", "")
        if auth != f"Bearer {AUTH_TOKEN}":
            self._send_json({"error": {"code": "AUTH_FAILED",
                             "message": "Invalid or missing auth token"}, "id": None})
            return

        # 3. Parse JSON-RPC + dispatch
        #    ⚠️ JSON parsing also included in try/except — returns JSON error on malformed request
        req_id = None
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(content_len))
            method = body.get("method")
            params = body.get("params", {})
            req_id = body.get("id", 1)

            # 4. Dispatch — runs directly in main thread (execute_sync not needed!)
            result = _dispatch(method, params)
            self._send_json({"result": result, "id": req_id})
        except RpcError as e:
            self._send_json({"error": {"code": e.code, "message": e.message,
                             "suggestion": e.suggestion}, "id": req_id})
        except (json.JSONDecodeError, ValueError) as e:
            self._send_json({"error": {"code": "INVALID_PARAMS",
                             "message": f"Malformed request: {e}"}, "id": req_id})
        except Exception as e:
            self._send_json({"error": {"code": "INTERNAL",
                             "message": str(e)}, "id": req_id})

    def _send_json(self, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(data))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass  # disable default stderr logging

# Run in main thread (serve_forever keeps process alive)
server.serve_forever()
```

**Core difference from v1.7**: `_dispatch(method, params)` is **called directly** within the HTTP handler.
execute_sync, threading.Event, result_box/exc_box patterns are all unnecessary.

#### Request Processing (_dispatch)

```python
class RpcError(Exception):
    def __init__(self, code, message, suggestion=None):
        self.code, self.message, self.suggestion = code, message, suggestion

def _dispatch(method, params):
    """Runs directly in main thread. execute_sync not needed.
       On error, raises RpcError → handler responds with {"error": ...} format."""
    if method == "ping":
        return {"ok": True, "state": "ready"}
    if method == "status":
        return _handle_status()
    if method == "stop":
        return _handle_stop()
    if method == "get_functions":
        return _handle_get_functions(params)
    if method == "decompile":
        return _handle_decompile(params)
    # ... remaining APIs ...
    if method == "methods":
        return _handle_methods()
    raise RpcError("UNKNOWN_METHOD", f"Unknown method: {method}")
```

#### stop Handling

```python
def _handle_stop():
    """Normal shutdown. Stops serve_forever() from a separate thread."""
    global _keep_running
    _keep_running = False
    save_db()
    # serve_forever() is blocking in main thread
    # shutdown() must be called from a separate thread to prevent deadlock
    threading.Thread(target=server.shutdown).start()
    return {"ok": True}
    # ⚠️ Order: _handle_stop() returns → _send_json() sends response → serve_forever() loop where
    #    shutdown thread sets _quitting flag → loop exits after current request completes
    #    Python socketserver official: shutdown() sets serve_forever() loop to exit on next poll
    #    → Response for current request is fully sent (race condition safe)
```

After serve_forever() exits, cleanup in main thread:
```python
_db_closed = False

server.serve_forever()
# ↓ arrives here via shutdown()
idapro.close_database(save=True)
_db_closed = True
_remove_from_registry(instance_id)
_remove_auth_token(instance_id)
log.info("Server stopped normally")
```

#### Abnormal Termination Handling

```python
import atexit

def _cleanup():
    """Minimal cleanup on abnormal exit. Prevents double-close."""
    global _db_closed
    try:
        if not _db_closed:
            idapro.close_database(save=True)
            _db_closed = True
    except:
        pass
    try:
        _remove_from_registry(instance_id)
    except:
        pass
    try:
        _remove_auth_token(instance_id)
    except:
        pass

atexit.register(_cleanup)
```

Simplification compared to v1.7:
- `notify_when(NW_TERMIDA)` removed — not needed with idalib
- `_emergency_cleanup` removed — consolidated into single `_cleanup`
- atexit serves as **secondary defense**. On normal shutdown, explicit close_database() after serve_forever() takes priority

⚠️ **atexit Behavior Scope**:
| Scenario | atexit runs | close_database safety |
|----------|-------------|----------------------|
| `sys.exit()` / normal exit | Runs | Safe (main thread) |
| `os._exit()` (watchdog) | **Does not run** | N/A |
| SIGKILL / TerminateProcess | **Does not run** | N/A |

⚠️ **Python 3.12+**: Starting a new thread in atexit handler may raise `RuntimeError`.
Need to test whether `close_database()` internally creates threads.

On watchdog timeout: call `_update_state("error")` directly then `os._exit(1)`.
`os._exit()` is the **only reliable way** to terminate the process while a C extension is blocking (inside open_database).

#### Plugin Loading

```python
import ida_ida, ida_loader, ida_hexrays

_decompiler_available = False

# proc_name → (32bit_plugin, 64bit_plugin)
# ⚠️ ida_idp.get_ph().id causes AttributeError in IDA 9.3 — do not use
_DECOMPILER_MAP = {
    "metapc": ("hexrays", "hexx64"),
    "ARM":    ("hexarm",  "hexarm64"),
    "mips":   ("hexmips", "hexmips64"),
    "PPC":    ("hexppc",  "hexppc64"),
    "RISCV":  ("hexrv",   "hexrv64"),
}

proc_name = ida_ida.inf_get_procname()
is_64 = ida_ida.inf_is_64bit()
entry = _DECOMPILER_MAP.get(proc_name)
actual_plugin = entry[1 if is_64 else 0] if entry else None

if actual_plugin:
    plg = ida_loader.load_plugin(actual_plugin)  # PyCapsule | None
    if plg and ida_hexrays.init_hexrays_plugin():
        log.info(f"Decompiler loaded: {actual_plugin} (proc={proc_name}, 64bit={is_64})")
        _decompiler_available = True
    else:
        log.error(f"Decompiler load failed: {actual_plugin}")
        _decompiler_available = False
else:
    log.warning(f"No decompiler for processor '{proc_name}', 64bit={is_64}")
    _decompiler_available = False
    # Continue in assembly-only mode
```

#### save_db

```python
import ida_loader

def save_db():
    """Workaround for ida_loader.save_database() flags default(-1) type mismatch bug.
    Pass flags=0 explicitly as workaround."""
    idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    ret = ida_loader.save_database(idb, 0)
    if ret:
        log.info(f"Database saved: {idb}")
    else:
        log.error(f"Database save failed: {idb}")
    return ret
```

⚠️ `ida_loader.save_database()` has a C++/Python type mismatch bug with flags default value (-1) in IDA 9.3.
`ida_loader.save_database(path, 0)` — pass flags as 0 explicitly to work around.
⚠️ `idaapi` is an umbrella module that re-exports all `ida_*` modules. Hex-Rays recommends: use originating modules directly (`ida_loader`, `ida_kernwin`, etc.).

#### Auto save_db Triggers

```
Immediately after open_database completes
After set_name call
After set_comment call
On stop command (+ close_database(save=True))
```

#### heartbeat

```python
_keep_running = True

def _heartbeat_loop():
    """Only updates registry timestamp. No IDA API calls (thread-safe)."""
    while _keep_running:
        time.sleep(config["analysis"]["heartbeat_interval"])  # 60 seconds
        if not _keep_running:
            break
        _update_heartbeat()

def _update_heartbeat():
    if not acquire_lock():
        return
    try:
        r = _load_registry()
        if instance_id in r:
            r[instance_id]["last_heartbeat"] = time.time()
            _save_registry(r)
    finally:
        release_lock()

heartbeat_thread = threading.Thread(target=_heartbeat_loop, daemon=True)
heartbeat_thread.start()
```

#### State Definitions

```
initializing  → ida_cli.py start registered, ida_server.py not yet running
analyzing     → open_database in progress (HTTP server not started)
ready         → Analysis complete, HTTP server running, all APIs available
error         → Analysis failed
```

⚠️ **Difference from v1.7**: No HTTP communication in analyzing state.
ida_cli.py checks state by polling registry file.

#### Log System

```python
import logging
from logging.handlers import RotatingFileHandler

handler = RotatingFileHandler(
    log_path,
    maxBytes=config["log"]["max_size_mb"] * 1024 * 1024,
    backupCount=config["log"]["backup_count"],
    encoding='utf-8'
)
handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s',
                                        datefmt='%Y-%m-%d %H:%M:%S'))
log = logging.getLogger(f"ida-headless-{instance_id}")
log.addHandler(handler)
log.setLevel(logging.INFO)
```

#### idb Metadata

```python
def _file_md5(path):
    h = hashlib.md5()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def _save_idb_metadata(idb_path, binary_path):
    meta = {
        "binary_path": binary_path,
        "binary_md5": _file_md5(binary_path),
        "created": time.time()
    }
    with open(idb_path + ".meta.json", 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2)

def _load_idb_metadata(idb_path):
    meta_path = idb_path + ".meta.json"
    if os.path.exists(meta_path):
        with open(meta_path, encoding='utf-8') as f:
            return json.load(f)
    return {}
```

#### exec Security

```
exec_enabled = false (default)
Disabled → EXEC_DISABLED
Enabled  → auth token + Host validation + 127.0.0.1 binding only, execution content logged

⚠️ Security caution:
- Single-threaded, so infinite loop/long-running exec blocks entire server
- Running idc.qexit() terminates server process → consider removing qexit from _exec_namespace
- No server-side timeout → indirectly protected by client (ida_cli.py) request_timeout_batch
```

```python
def _exec_code(code, base_namespace):
    ns = dict(base_namespace)
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
        exec(code, ns)
    return stdout_buf.getvalue(), stderr_buf.getvalue()

_exec_namespace = {
    "idc": __import__("idc"),
    "idaapi": __import__("idaapi"),
    "idautils": __import__("idautils"),
    "ida_bytes": __import__("ida_bytes"),
    "ida_funcs": __import__("ida_funcs"),
    "ida_hexrays": __import__("ida_hexrays"),
    "ida_nalt": __import__("ida_nalt"),
    "ida_typeinf": __import__("ida_typeinf"),
    "ida_segment": __import__("ida_segment"),
    "ida_search": __import__("ida_search"),
    "ida_xref": __import__("ida_xref"),
    "ida_name": __import__("ida_name"),
    "ida_ida": __import__("ida_ida"),
    "ida_idp": __import__("ida_idp"),
    "ida_loader": __import__("ida_loader"),
}
```

---

### 5-3. HTTP Communication Protocol

#### Request Format: Single Endpoint

```
POST /
Content-Type: application/json

{
  "method": "<method_name>",
  "params": { ... },    ← omit if no parameters
  "id": 1
}
```

#### Response Format (Common)

```json
Success: {"result": { ... }, "id": 1}
Failure: {"error": {"code": "...", "message": "...", "suggestion": "..."}, "id": 1}
```

#### ping

```json
Request: {"method": "ping", "id": 1}
Response: {"result": {"ok": true, "state": "ready"}, "id": 1}
```

#### status

```json
Request: {"method": "status", "id": 1}
Response:
{
  "result": {
    "state":                "ready",
    "binary":               "libsecurity.so",
    "arch":                 "arm",
    "bits":                 64,
    "idb_path":             "C:/.../.ida-headless/idb/libsecurity_ab12cd34.i64",
    "decompiler_available": true,
    "imagebase":            "0x100000",
    "func_count":           3842,
    "ida_version":          "9.3",
    "server_version":       "2.0",
    "uptime":               147.3,
    "binary_md5":           "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
  },
  "id": 1
}
```

Difference from v1.7: analyzing/ready duality not needed — HTTP is only active in ready state.
All fields collected directly in main thread without execute_sync.

#### stop

```json
Request: {"method": "stop", "id": 1}
Response: {"result": {"ok": true}, "id": 1}
```

#### List APIs (get_functions / get_strings / get_imports / get_exports / get_segments)

Request parameters:

```
offset  int     Default: 0
count   int     Default: 100, Max: 500
filter  string  Default: null  → substring matching on name
output  string  Default: null  → file save path
```

Response:

```json
{
  "result": {
    "total": 3842, "offset": 0, "count": 100,
    "data": [ ... ],
    "saved_to": null
  },
  "id": 1
}
```

data fields per API:

| API | Fields |
|-----|--------|
| get_functions | addr, name, size |
| get_strings | addr, value, length, encoding |
| get_imports | addr, name, module, ordinal |
| get_exports | addr, name, ordinal |
| get_segments | start_addr, end_addr, name, class, size, perm |

`perm` values: `"rwx"`, `"r-x"`, etc. `ida_segment.SEGPERM_READ`(4), `SEGPERM_WRITE`(2), `SEGPERM_EXEC`(1).

#### addr Input Format (Common for Analysis APIs)

```
Hex address:   "0x1234"  or  "1234"   (0x prefix optional)
Symbol name:   "check_root"            → idc.get_name_ea_simple(name), BADADDR → INVALID_ADDRESS
```

#### decompile

```json
Request: {"method": "decompile", "params": {"addr": "check_root", "output": null}, "id": 1}
Response:
{
  "result": {
    "addr": "0x1234", "name": "check_root",
    "code": "int __fastcall check_root()\n{\n  ...\n}",
    "saved_to": null
  },
  "id": 1
}
```

On plugin load failure: DECOMPILER_NOT_LOADED

#### disasm

```json
Request: {"method": "disasm", "params": {"addr": "0x1234", "count": 20, "output": null}, "id": 1}
count default: 20. Max: 500.
Response:
{
  "result": {
    "addr": "0x1234", "count": 20,
    "lines": [
      {"addr": "0x1234", "bytes": "2D E9 F0 4F", "insn": "PUSH {R4-R11,LR}"},
      {"addr": "0x1238", "bytes": "00 40 A0 E1", "insn": "MOV R4, R0"}
    ],
    "saved_to": null
  },
  "id": 1
}
```

#### get_xrefs_to / get_xrefs_from

```json
Request: {"method": "get_xrefs_to", "params": {"addr": "0x1234"}, "id": 1}
Response:
{
  "result": {
    "addr": "0x1234", "total": 5,
    "refs": [
      {"from_addr": "0x5678", "from_name": "sub_5678", "type": "call"},
      {"from_addr": "0x9ABC", "from_name": "init_func", "type": "jump"}
    ],
    "saved_to": null
  },
  "id": 1
}
```

Type mapping:

```python
import ida_xref

def _xref_type_str(xtype):
    if xtype in (ida_xref.fl_CF, ida_xref.fl_CN):
        return "call"
    if xtype in (ida_xref.fl_JF, ida_xref.fl_JN):
        return "jump"
    if xtype in (ida_xref.dr_R, ida_xref.dr_W, ida_xref.dr_O,
                 ida_xref.dr_I, ida_xref.dr_T, ida_xref.dr_S):
        return "data"
    return "unknown"
```

get_xrefs_from response: `to_addr/to_name` instead of `from_addr/from_name`.

#### find_func

```json
Request: {"method": "find_func", "params": {"name": "check"}, "id": 1}
Response:
{
  "result": {
    "query": "check", "total": 2,
    "matches": [
      {"addr": "0x1234", "name": "check_root"},
      {"addr": "0x5678", "name": "check_root_bypass"}
    ]
  },
  "id": 1
}
```

Default: substring matching. `max_results`: default 100, max 500.
`regex: true` → `re.search(pattern, func_name)`.

#### decompile_batch

```json
Request: {"method": "decompile_batch", "params": {"addrs": ["0x1234", "0x5678", "check_root"]}, "id": 1}
Response:
{
  "result": {
    "total": 3, "success": 2, "failed": 1,
    "functions": [
      {"addr": "0x1234", "name": "sub_1234", "code": "int __fastcall sub_1234()\n{\n  ...\n}"},
      {"addr": "0x5678", "name": "sub_5678", "code": "void __fastcall sub_5678(int a1)\n{\n  ...\n}"},
      {"addr": "0x9ABC", "name": "check_root", "error": "DECOMPILE_FAILED"}
    ],
    "saved_to": null
  },
  "id": 1
}
```

`addrs` max 20. Continues processing remaining items even if individual ones fail.

#### set_name

```json
Request: {"method": "set_name", "params": {"addr": "0x1234", "name": "check_root_real"}, "id": 1}
Response: {"result": {"ok": true, "addr": "0x1234", "name": "check_root_real"}, "id": 1}
```

Automatic save_db after success.

#### set_comment

```json
Request: {"method": "set_comment", "params": {"addr": "0x1234", "comment": "root detection core", "repeatable": false, "type": "line"}, "id": 1}
Response: {"result": {"ok": true, "addr": "0x1234"}, "id": 1}
```

Parameters:

- `repeatable`: default false. If true, repeatable comment (`idc.set_cmt(ea, cmt, 1)`)
- `type`: default `"line"`. If `"func"`, function comment (`idc.set_func_cmt(ea, cmt, repeatable)`)

Automatic save_db after success.

#### get_func_info

```json
Request: {"method": "get_func_info", "params": {"addr": "check_root"}, "id": 1}
Response:
{
  "result": {
    "addr": "0x1234", "name": "check_root",
    "start_ea": "0x1234", "end_ea": "0x1300",
    "size": 204,
    "is_thunk": false,
    "flags": "0x0",
    "decompiler_available": true,
    "calling_convention": "__fastcall",
    "return_type": "int",
    "args": [{"name": "a1", "type": "int"}]
  },
  "id": 1
}
```

When decompiler unavailable: `args: null, calling_convention: null`.

#### get_imagebase

```json
Request: {"method": "get_imagebase", "id": 1}
Response: {"result": {"imagebase": "0x100000"}, "id": 1}
```

#### get_bytes

```json
Request: {"method": "get_bytes", "params": {"addr": "0x1234", "size": 16}, "id": 1}
Response:
{
  "result": {
    "addr": "0x1234", "size": 16,
    "hex": "2D E9 F0 4F 00 40 A0 E1 01 50 A0 E1 04 D0 4D E2",
    "raw_b64": "LenwTwBAoOEBUKDhBNBN4g=="
  },
  "id": 1
}
```

size max 4096. INVALID_PARAMS if exceeded.

#### find_bytes

```json
Request: {"method": "find_bytes", "params": {"pattern": "48 8B ? ? 00", "start": "0x1000", "max_results": 10}, "id": 1}
Response:
{
  "result": {
    "pattern": "48 8B ? ? 00", "total": 3,
    "matches": ["0x1234", "0x5678", "0x9ABC"]
  },
  "id": 1
}
```

`start`: search start address (default: start of first segment). `max_results` default 50, max 200.

⚠️ IDA 9.0+: Recommended to use `ida_bytes.find_bytes()` high-level API.
`parse_binpat_str` + `bin_search` combination is **deprecated** (IDA 9.0 porting guide).
`idc.find_binary`, `ida_search.find_binary` also **removed** in IDA 9.0.

```python
# IDA 9.0+ recommended API (replaces deprecated parse_binpat_str/bin_search)
ea = ida_bytes.find_bytes(pattern, start_ea, range_end=end_ea)
# Returns BADADDR if no match. Returns single ea_t (not a tuple).
```

#### get_comments

```json
Request: {"method": "get_comments", "params": {"addr": "0x1234"}, "id": 1}
Response:
{
  "result": {
    "addr": "0x1234",
    "comment": "root detection core",
    "repeatable_comment": "called from init_security",
    "func_comment": "Checks for root/jailbreak indicators"
  },
  "id": 1
}
```

#### exec

```json
Request: {"method": "exec", "params": {"code": "print(idc.get_func_name(0x1234))"}, "id": 1}
Response: {"result": {"stdout": "check_root\n", "stderr": "", "saved_to": null}, "id": 1}
```

EXEC_DISABLED if exec_enabled=false.

#### save_db

```json
Request: {"method": "save_db", "id": 1}
Response: {"result": {"ok": true, "idb_path": "..."}, "id": 1}
```

#### methods

```json
Request: {"method": "methods", "id": 1}
Response:
{
  "result": {
    "methods": [
      {"name": "ping", "description": "Check server liveness"},
      {"name": "status", "description": "Query instance status"},
      {"name": "stop", "description": "Normal instance shutdown"},
      {"name": "get_functions", "description": "Get function list"},
      {"name": "get_strings", "description": "Get string list"},
      {"name": "get_imports", "description": "Get import list"},
      {"name": "get_exports", "description": "Get export list"},
      {"name": "get_segments", "description": "Get segment list"},
      {"name": "decompile", "description": "Decompile a function"},
      {"name": "decompile_batch", "description": "Batch decompile multiple functions"},
      {"name": "disasm", "description": "Disassemble"},
      {"name": "get_xrefs_to", "description": "Cross-references to an address"},
      {"name": "get_xrefs_from", "description": "Cross-references from an address"},
      {"name": "find_func", "description": "Search function by name"},
      {"name": "get_func_info", "description": "Get detailed function info"},
      {"name": "get_imagebase", "description": "Binary base address"},
      {"name": "get_bytes", "description": "Read raw bytes"},
      {"name": "find_bytes", "description": "Search byte pattern"},
      {"name": "get_comments", "description": "Get comments"},
      {"name": "set_name", "description": "Rename a symbol"},
      {"name": "set_comment", "description": "Set a comment"},
      {"name": "save_db", "description": "Save database"},
      {"name": "exec", "description": "Execute Python code (requires security config)"},
      {"name": "methods", "description": "List available APIs"}
    ]
  },
  "id": 1
}
```

#### --out File Save Rules

```
Encoding: always UTF-8
JSON:   json.dump(..., ensure_ascii=False, indent=2)
Text:   UTF-8 plain text
Save failure: SAVE_FAILED error, result included in response body
```

#### Error Codes

| Code | Situation | suggestion |
|------|-----------|-----------|
| NOT_READY | Analysis in progress (connection fails entirely when HTTP is not running) | ida_cli.py wait \<id\> |
| DECOMPILER_NOT_LOADED | Plugin load failure | Check license and restart |
| INVALID_ADDRESS | Invalid address or symbol name | Use 0x prefix or try find_func |
| DECOMPILE_FAILED | Decompilation failed | Use disasm instead |
| UNKNOWN_METHOD | Unknown API | Check list with methods |
| SAVE_FAILED | File save failure | Check path/permissions |
| EXEC_DISABLED | exec API disabled | Check config.json exec_enabled |
| INVALID_PARAMS | Parameter error (addrs exceeded, size exceeded, etc.) | Check parameter limits |
| INTERNAL | Server internal exception (unexpected error) | Check logs, retry |
| AUTH_FAILED | Auth token missing or mismatch | Use correct auth token |
| FORBIDDEN_HOST | Host header validation failure | Access via 127.0.0.1 or localhost |

Error codes removed compared to v1.7:
- `TIMEOUT` (execute_sync timeout) → execute_sync itself removed
- `PARAMS_NOT_FOUND` (params.json not found) → params.json removed

---

### 5-4. ida_cli.py

**Claude's sole entry point.** Absorbs the role of v1.7's start_ida.py.

#### Complete Command List

**Global option**: `--json` — converts output of all commands to JSON format

```
[Configuration]
ida_cli.py --init                                        ← Initial setup (create directories/config)
ida_cli.py --check                                       ← Environment validation (idapro, Python version, etc.)

[Instance Management]
ida_cli.py start   <binary> [--arch <arch>] [--fresh] [--force] [--idb-dir <path>]
ida_cli.py stop    <id>
ida_cli.py status  [<id>]
ida_cli.py wait    <id> [--timeout 300]
ida_cli.py list
ida_cli.py logs    <id> [--tail N] [--follow]
ida_cli.py cleanup [--dry-run]

[List Queries]
ida_cli.py [-i <id> | -b <hint>] functions [--offset N] [--count N] [--filter STR] [--out FILE]
ida_cli.py [-i <id> | -b <hint>] strings   [--offset N] [--count N] [--filter STR] [--out FILE]
ida_cli.py [-i <id> | -b <hint>] imports   [--offset N] [--count N] [--out FILE]
ida_cli.py [-i <id> | -b <hint>] exports   [--offset N] [--count N] [--out FILE]
ida_cli.py [-i <id> | -b <hint>] segments  [--out FILE]

[Analysis]
ida_cli.py [-i <id> | -b <hint>] decompile       <addr>                    [--out FILE]
ida_cli.py [-i <id> | -b <hint>] decompile_batch <addr1> <addr2> ...       [--out FILE]
ida_cli.py [-i <id> | -b <hint>] disasm          <addr> [--count N]        [--out FILE]
ida_cli.py [-i <id> | -b <hint>] xrefs           <addr> [--direction to|from|both]   [--out FILE]
ida_cli.py [-i <id> | -b <hint>] find_func       <name> [--regex] [--max N]
ida_cli.py [-i <id> | -b <hint>] func_info       <addr>
ida_cli.py [-i <id> | -b <hint>] imagebase
ida_cli.py [-i <id> | -b <hint>] bytes           <addr> <size>
ida_cli.py [-i <id> | -b <hint>] find_pattern     <hex_pattern> [--max N]
ida_cli.py [-i <id> | -b <hint>] comments        <addr>
ida_cli.py [-i <id> | -b <hint>] methods

[Modification]
ida_cli.py [-i <id> | -b <hint>] rename  <addr> <name>
ida_cli.py [-i <id> | -b <hint>] comment <addr> "<text>" [--repeatable] [--type line|func]
ida_cli.py [-i <id> | -b <hint>] save

[Advanced]
ida_cli.py [-i <id> | -b <hint>] exec "<python_code>" [--out FILE]
```

#### start Command (Absorbs v1.7's start_ida.py Role)

`--arch`: For overriding arch_detect display + FAT Mach-O slice selection.
idalib auto-detects architecture, so not needed in most cases.
May be needed for analyzing a specific slice in FAT binaries,
but since idalib's `-T` flag is not supported (Known Issue), extracting with `lipo` beforehand is recommended.

`--idb-dir`: Override IDB(.i64) save directory. Uses config's `paths.idb_dir` if not specified.
Useful for storing IDBs separately per project. Example:
```bash
python tools/ida_cli.py start ./samples/target.so --idb-dir ./samples/
# → saved to ./samples/target_ab12cd34.i64
```

```python
def cmd_start(binary, arch, fresh, force, idb_dir=None):
    binary_path = os.path.abspath(binary)

    # 1. Check binary exists
    if not os.path.isfile(binary_path):
        print(f"[ERROR] Binary not found: {binary_path}")
        return

    # 2. Load config
    config, config_path = load_config()  # config_path: actual loaded file path

    # 3. arch_detect (for display only, no lock needed)
    arch_info = arch_detect(binary_path, arch)

    # 4. Generate instance_id + determine idb path (no lock needed)
    instance_id = make_instance_id(binary_path)
    idb_path = get_idb_path(config, binary_path, instance_id, force, idb_dir=idb_dir)

    # 5. MD5 validation when reusing .i64 (no lock needed)
    if os.path.exists(idb_path) and not fresh:
        meta = _load_idb_metadata(idb_path)
        stored_md5 = meta.get("binary_md5")
        if stored_md5:
            current_md5 = _file_md5(binary_path)
            if stored_md5 != current_md5:
                print(f"[WARNING] Binary changed since .i64 was created.")
                if not force:
                    print("  Use --fresh to rebuild, or --force to proceed.")
                    return

    # 6. Registry validation + registration [atomic within single lock]
    #    ⚠️ cleanup_stale, max_instances, duplicate check, register all
    #       performed within one lock scope → prevents TOCTOU race
    log_path = os.path.join(config["paths"]["log_dir"], f"{instance_id}.log")
    if not acquire_lock():
        print("[ERROR] Could not acquire registry lock")
        return
    try:
        registry = load_registry()
        cleanup_stale(registry, config["analysis"]["stale_threshold"])

        # Check max_instances
        if len(registry) >= config["analysis"]["max_instances"]:
            print(f"[ERROR] Max instances reached ({config['analysis']['max_instances']})")
            return

        # Check for duplicate binary
        for info in registry.values():
            if info.get("path") == binary_path and info["state"] in ("analyzing", "ready"):
                if not force:
                    print(f"[WARNING] {binary} already running (id: {info['id']}). Use --force.")
                    return

        # Register as initializing (atomic within lock)
        registry[instance_id] = {
            "id": instance_id, "pid": None, "port": None,
            "binary": os.path.basename(binary_path),
            "path": binary_path,
            "arch": arch_info.get("arch"), "bits": arch_info.get("bits"),
            "format": arch_info.get("file_format"),
            "idb_path": idb_path, "log_path": log_path,
            "state": "initializing",
            "started": time.time(),
            "last_heartbeat": None
        }
        save_registry(registry)
    finally:
        release_lock()

    # 7. Run ida_server.py subprocess
    script_dir = os.path.dirname(os.path.abspath(__file__))
    server_script = os.path.join(script_dir, "ida_server.py")

    cmd = [sys.executable, server_script,
           binary_path,
           "--id", instance_id,
           "--idb", idb_path,
           "--log", log_path,
           "--config", config_path]
    if fresh:
        cmd.append("--fresh")

    proc = subprocess.Popen(
        cmd,
        creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # 8. Wait for state change (max 10 seconds)
    ...

    # 9. Output result
    print(f"[+] Instance started: id={instance_id}")
```

#### instance_id Generation

```python
def make_instance_id(binary_path):
    raw = f"{binary_path}{time.time()}{os.getpid()}"
    h = int(hashlib.md5(raw.encode()).hexdigest(), 16)
    chars = "0123456789abcdefghijklmnopqrstuvwxyz"
    result = ""
    for _ in range(4):
        result = chars[h % 36] + result
        h //= 36
    return result  # "a1b2"
```

#### idb Filename Convention

```python
def get_idb_path(config, binary_path, instance_id, force=False, idb_dir=None):
    if not idb_dir:
        idb_dir = config["paths"]["idb_dir"]  # default: %USERPROFILE%/.ida-headless/idb
    os.makedirs(idb_dir, exist_ok=True)
    binary_name = os.path.basename(binary_path)
    name = re.sub(r'[^\w\-.]', '_', binary_name)
    md5 = hashlib.md5(binary_path.encode()).hexdigest()[:8]
    base = f"{name}_{md5}"
    suffix = ".i64"
    if force:
        return os.path.join(idb_dir, f"{base}_{instance_id}{suffix}")
    return os.path.join(idb_dir, f"{base}{suffix}")
```

`--idb-dir` usage examples:
```
# Default (config path)
python tools/ida_cli.py start target.so
→ C:\Users\http80\.ida-headless\idb\target_ab12cd34.i64

# Project-local save
python tools/ida_cli.py start target.so --idb-dir C:\project\samples
→ C:\project\samples\target_ab12cd34.i64
```

#### Stale Instance Auto-Cleanup

```python
import psutil

def cleanup_stale(registry, stale_threshold):
    """⚠️ Caller must call acquire_lock() before calling this.
       Pass the registry object loaded within the lock."""
    now = time.time()
    changed = False
    for id, info in list(registry.items()):
        if info["state"] == "initializing":
            if now - info["started"] > 30:
                del registry[id]
                changed = True
                continue

        # error state: check PID exit then cleanup immediately
        if info["state"] == "error":
            if not _is_process_alive(info):
                del registry[id]
                changed = True
            continue

        hb = info.get("last_heartbeat")
        # heartbeat=null (analyzing with watchdog termination, etc.): check liveness by PID
        if not hb:
            if info.get("pid") and not _is_process_alive(info):
                del registry[id]
                changed = True
            continue

        if now - hb > stale_threshold:
            if not _is_process_alive(info):
                del registry[id]
                changed = True

    if changed:
        save_registry(registry)
    return registry

def _is_process_alive(info):
    """Check process liveness by PID + create_time.
    ⚠️ psutil.Process.create_time() precision on Windows is ~1 second
    (internally 100ns FILETIME but precision loss when psutil converts to float).
    Therefore > 1.0 threshold is appropriate."""
    pid = info.get("pid")
    if not pid:
        return False
    try:
        proc = psutil.Process(pid)
        stored_ct = info.get("pid_create_time")
        if stored_ct and abs(proc.create_time() - stored_ct) > 1.0:
            return False  # PID reused
        return proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False
```

#### wait Implementation

```python
def cmd_wait(id, timeout):
    deadline = time.time() + timeout
    state = "unknown"
    while time.time() < deadline:
        info = get_instance_info(id)
        if not info:
            print(f"[-] Instance {id} not found")
            return

        state = info.get("state", "unknown")
        port = info.get("port")

        # analyzing or initializing: HTTP not running → registry polling only
        if state in ("initializing", "analyzing"):
            remaining = int(deadline - time.time())
            print(f"[*] {state}... ({remaining}s remaining)")
            time.sleep(config["analysis"]["wait_poll_interval"])
            continue

        # ready: final confirmation via HTTP
        if state == "ready" and port:
            try:
                resp = post_rpc(port, "ping", instance_id=id)
                if resp.get("result", {}).get("state") == "ready":
                    print("[+] ready")
                    return
            except Exception:
                pass

        if state == "error":
            print(f"[-] Analysis failed. Check logs: ida_cli.py logs {id}")
            return

        remaining = int(deadline - time.time())
        print(f"[*] {state}... ({remaining}s remaining)")
        time.sleep(config["analysis"]["wait_poll_interval"])

    print(f"[-] Timeout ({timeout}s). Current state: {state}")
```

Difference from v1.7: HTTP polling removed in analyzing state → **reads registry file directly only**.

#### list Implementation

```python
def cmd_list():
    if not acquire_lock():
        print("[ERROR] Could not acquire registry lock")
        return
    try:
        registry = load_registry()
        cleanup_stale(registry, config["analysis"]["stale_threshold"])
    finally:
        release_lock()
    if not registry:
        print("[*] No active instances")
        return
    for id, info in registry.items():
        state = info.get("state", "unknown")
        binary = info.get("binary", "?")
        port = info.get("port", "-")
        print(f"  {id}  {state:<12}  {binary}  port={port}")
```

#### xrefs --direction both Behavior

```
--direction to   → post_rpc("get_xrefs_to", ...)
--direction from → post_rpc("get_xrefs_from", ...)
--direction both → sequential calls to get_xrefs_to + get_xrefs_from, merge results
  → {"refs_to": [...], "refs_from": [...], "total_to": N, "total_from": M}
```

#### stop Flow

```python
def cmd_stop(id):
    info = get_instance_info(id)
    port = info.get("port")
    pid = info.get("pid")

    # ready state: HTTP stop request
    if port:
        try:
            post_rpc(port, "stop", instance_id=id, timeout=10)
            for _ in range(10):
                time.sleep(0.5)
                if id not in load_registry():
                    print(f"[+] Instance {id} stopped normally")
                    return
        except Exception:
            pass

    # Normal shutdown failed or analyzing state: force kill
    if pid:
        try:
            proc = psutil.Process(pid)
            stored_ct = info.get("pid_create_time")
            if stored_ct and abs(proc.create_time() - stored_ct) > 1.0:
                print(f"[+] Instance {id} process already gone (PID reused)")
            else:
                proc.kill()
                print(f"[+] Instance {id} force killed (pid={pid})")
        except psutil.NoSuchProcess:
            print(f"[+] Instance {id} process already gone")

    # Manual cleanup [lock protected]
    if acquire_lock():
        try:
            r = load_registry()
            r.pop(id, None)
            save_registry(r)
        finally:
            release_lock()
    _remove_auth_token(id)
```

#### RPC Call Common Function

```python
_BATCH_METHODS = {"decompile_batch", "exec"}  # APIs that may take long time

def post_rpc(port, method, instance_id, params=None, req_id=1, timeout=None):
    if timeout is None:
        if method in _BATCH_METHODS:
            timeout = config["analysis"]["request_timeout_batch"]  # 300 seconds
        else:
            timeout = config["analysis"]["request_timeout"]  # 35 seconds
    url = f"http://127.0.0.1:{port}/"
    body = {"method": method, "id": req_id}
    if params:
        body["params"] = params

    headers = {"Content-Type": "application/json"}
    token = _load_auth_token(instance_id)
    if token:
        headers["Authorization"] = f"Bearer {token}"

    for attempt in range(3):
        try:
            resp = requests.post(url, json=body, headers=headers, timeout=timeout)
            try:
                return resp.json()
            except ValueError:
                return {"error": {"code": "INVALID_RESPONSE",
                         "message": f"HTTP {resp.status_code}: {resp.text[:200]}"}}
        except requests.ConnectionError:
            if attempt < 2:
                time.sleep(1)
                continue
            raise
```

#### Instance Selection Priority

```
1. -i <id>   → Explicit ID
2. -b <hint> → Search by binary name
3. Omitted   → Auto-select if 1 instance, show list if 2 or more
```

#### logs --follow

```python
def cmd_logs_follow(log_path):
    try:
        with open(log_path, encoding='utf-8') as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    print(line, end='', flush=True)
                else:
                    if not os.path.exists(log_path):
                        print("\n[*] Log file removed (instance stopped)")
                        return
                    time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    except FileNotFoundError:
        print(f"[-] Log file not found: {log_path}")
```

#### cleanup Command

```python
def cmd_cleanup(dry_run=False):
    registry = load_registry()
    active_ids = set(registry.keys())

    # 1. Delete orphan logs (7 days or older)
    cutoff = time.time() - 7 * 86400
    for f in glob.glob(os.path.join(log_dir, "*.log*")):
        iid = os.path.basename(f).split(".")[0]
        if iid not in active_ids and os.path.getmtime(f) < cutoff:
            if dry_run:
                print(f"  [dry-run] Would delete: {f}")
            else:
                os.remove(f)
                print(f"  Deleted old log: {f}")

    # 2. Remove inactive instance lines from auth_token file
    _cleanup_auth_token(active_ids, dry_run)

    # 3. Only list unused .i64 files (no auto-delete)
    for f in glob.glob(os.path.join(idb_dir, "*")):
        if f.endswith(".meta.json"):
            continue
        in_use = any(info.get("idb_path") == f for info in registry.values())
        if not in_use:
            print(f"  [info] Unused .i64 (not deleted): {f}")
```

---

### 5-5. ida_servers.json

Initial registration (ida_cli.py start, state=initializing):

```json
{
  "a1b2": {
    "id": "a1b2", "pid": null, "port": null,
    "binary": "libsecurity.so",
    "path": "C:/samples/libsecurity.so",
    "arch": "arm", "bits": 64, "format": "ELF",
    "idb_path": "C:/Users/user/.ida-headless/idb/libsecurity_ab12cd34.i64",
    "log_path": "C:/Users/user/.ida-headless/logs/a1b2.log",
    "state": "initializing",
    "started": 1741234567.0,
    "last_heartbeat": null
  }
}
```

analyzing state update (ida_server.py, open_database in progress):

```json
{
  "a1b2": {
    "pid": 12345, "port": null,
    "pid_create_time": 1741234568.5,
    "state": "analyzing",
    "last_heartbeat": null
  }
}
```

⚠️ **port is null in analyzing state** — HTTP server not yet started. port assigned on ready transition.

ready state update (after open_database completes + HTTP server starts):

```json
{
  "a1b2": {
    "port": 49201,
    "state": "ready",
    "last_heartbeat": 1741234630.0
  }
}
```

`pid_create_time`: Used for Windows PID reuse detection.

---

### 5-6. Windows Path Handling

```python
# subprocess: shell=False + list style
[sys.executable, server_script,
 binary_path,
 "--id", instance_id,
 "--idb", idb_path,
 "--log", log_path,
 "--config", config_path]

# Encoding
open(..., encoding='utf-8')
json.dump(..., ensure_ascii=False, indent=2)

# Non-ASCII path warning
"[WARNING] Non-ASCII characters in path. Use ASCII-only path if analysis fails."

# idb filename sanitization
name = re.sub(r'[^\w\-.]', '_', binary_name)
```

---

### 5-7. Registry Concurrent Write Handling

```python
LOCK_PATH = registry_path + ".lock"

def acquire_lock(timeout=1.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            fd = os.open(LOCK_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            return True
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(LOCK_PATH) > 5:
                    os.remove(LOCK_PATH)
                    continue
            except:
                pass
            time.sleep(0.05)
    return False

def release_lock():
    try:
        os.remove(LOCK_PATH)
    except:
        pass
```

---

### 5-8. Duplicate Binary Load Handling

```
Same binary path + state=analyzing or ready found
  ↓
  No --force →
    "[WARNING] libsecurity.so is already running (id: a1b2). Use --force."
    Exit

  --force →
    idb_path = libsecurity_ab12cd34_c3d4.i64  (instance_id suffix appended)
    Proceed
```

---

### 5-9. common.py (Shared Module)

Module that extracts code used identically in both ida_server.py and ida_cli.py.
Consolidates approximately 220 lines of duplicated code into a single ~130-line module.

#### Extraction Background

| Item | ida_server.py | ida_cli.py | Duplicate |
| ---- | ------------- | ---------- | --------- |
| Config load (_expand_env, _expand_config, load_config) | O | O | Identical |
| Registry management (acquire_lock, release_lock, load_registry, save_registry) | O | O | Identical |
| file_md5 | O | O | Identical |
| remove_auth_token | O | O | Identical |
| init_registry_paths | O | O | Identical |

Risk of inconsistency when only one side is modified when maintaining 100% identical code on both sides.

#### Structure

```python
# common.py — shared module for ida_server.py / ida_cli.py

# Constants
STALE_LOCK_TIMEOUT = 5          # seconds before stale lock is forcibly removed
LOCK_POLL_INTERVAL = 0.05       # seconds between lock acquisition retries
DEFAULT_LOCK_TIMEOUT = 1.0      # seconds to wait for lock before giving up
FILE_READ_CHUNK = 8192          # bytes per chunk for file MD5

# Config
def _expand_env(path): ...      # substitute environment variables like %USERPROFILE%
def _expand_config(obj): ...    # recursive substitution in dict/list
def load_config(config_path): ...  # load config.json + expand environment variables

# Registry (lock + load + save)
def init_registry_paths(config): ...  # initialize registry paths from config
def acquire_lock(timeout=1.0): ...    # acquire file lock (auto-cleanup stale locks)
def release_lock(): ...               # release file lock
def load_registry(): ...              # JSON → dict
def save_registry(registry): ...      # dict → JSON

# File utilities
def file_md5(path): ...               # file MD5 hash (hex)

# Auth token
def remove_auth_token(token_path, instance_id): ...  # remove instance token
```

#### Usage Pattern

```python
# ida_server.py
from common import (load_config, init_registry_paths, acquire_lock,
                     release_lock, load_registry, save_registry,
                     file_md5, remove_auth_token)

# ida_cli.py (wraps load_config to return default path + tuple)
from common import (load_config as _load_config_core, init_registry_paths,
                     acquire_lock, release_lock, load_registry, save_registry,
                     file_md5, remove_auth_token)
```

ida_cli.py wraps `_load_config_core()` to add config file search logic (current directory → `~/.ida-headless/`) +
`(config, config_path)` tuple return. ida_server.py receives path directly via `--config` argument, so wrapping is not needed.

#### Design Principles

- **Server/CLI-specific logic stays in each module**: `_update_registry`, `_update_state` (server-only), `cleanup_stale`, `_build_dispatch` (CLI-only)
- **No state**: Use after initializing paths with `init_registry_paths()`. Minimize module-level global state.
- **Lock is caller's responsibility**: Maintain pattern of directly calling `acquire_lock()` / `release_lock()` (no context manager, compatible with existing code)

---

## 6. Installation and Setup

### 6-1. Installation Steps

```
1. Verify IDA version
   IDA Pro 9.1 or higher required (open_database args parameter)

2. Check Python version compatibility
   Run: idapyswitch.exe → displays expected Python version (e.g., 3.12)
   Install that Python version if needed (major.minor must match)

3. Install idapro package
   pip install "<IDA_DIR>/idalib/python/idapro-*.whl"

4. Activate idalib (choose one of two methods)
   Method A: python "<IDA_DIR>/idalib/python/py-activate-idalib.py"
   Method B: Set environment variable IDADIR=<IDA installation path>

5. Place tools/ directory
   Example: C:\tools\ida-headless\
   Note: path must not contain spaces

6. Install dependency packages
   pip install requests psutil

7. Initialize config
   python ida_cli.py --init
   → Creates default template at %USERPROFILE%\.ida-headless\config.json
   → Auto-creates directories: idb/, logs/

8. Validate setup
   python ida_cli.py --check
```

### 6-2. Auto-Created Directories

```
%USERPROFILE%\.ida-headless\
%USERPROFILE%\.ida-headless\idb\
%USERPROFILE%\.ida-headless\logs\
```

Removed compared to v1.7: `params/` directory (params.json no longer needed).

### 6-3. Validation Checklist

```
[ ] IDA Pro version >= 9.1
[ ] idapro package installed (pip show idapro)
[ ] python -c "import idapro" succeeds
[ ] Python version matches (IDA .pyd compatible)
[ ] pip install requests psutil completed
[ ] No spaces in tools/ directory path
[ ] python ida_cli.py --check passes
[ ] python ida_cli.py start <binary> → state=analyzing confirmed
[ ] python ida_cli.py wait <id> → ready
[ ] python ida_cli.py -b <binary> functions returns results
[ ] python ida_cli.py stop <id> → .i64 save confirmed
[ ] python ida_cli.py cleanup --dry-run → orphan file list output
```

---

## 7. Claude Workflow

```
[Android APK Native Library Analysis]

0. Initial setup
   python ida_cli.py --init && pip install requests psutil

1. Start instance
   bash: python ida_cli.py start libsecurity.so
   → id=a1b2, state=analyzing

2. Wait for analysis to complete
   bash: python ida_cli.py wait a1b2 --timeout 300

3. Initial reconnaissance
   bash: python ida_cli.py -b libsecurity strings   --out C:/tmp/strings.json
   bash: python ida_cli.py -b libsecurity imports   --out C:/tmp/imports.json
   bash: python ida_cli.py -b libsecurity functions --filter "check" --out C:/tmp/funcs.json

4. On error
   bash: python ida_cli.py logs a1b2 --tail 20

5. Core logic analysis
   bash: python ida_cli.py -b libsecurity find_func "check"
   bash: python ida_cli.py -b libsecurity func_info check_root
   bash: python ida_cli.py -b libsecurity decompile check_root --out C:/tmp/check_root.c
   bash: python ida_cli.py -b libsecurity xrefs 0x1234 --direction both
   bash: python ida_cli.py -b libsecurity rename 0x1234 check_root_real
   bash: python ida_cli.py -b libsecurity disasm 0x1234 --count 30

5-1. Advanced analysis
   bash: python ida_cli.py -b libsecurity imagebase
   bash: python ida_cli.py -b libsecurity bytes 0x1234 64
   bash: python ida_cli.py -b libsecurity find_pattern "48 8B ? ? 00" --max 20
   bash: python ida_cli.py -b libsecurity decompile_batch 0x1234 0x5678 check_root --out C:/tmp/batch.json

6. .i64 reuse (re-analysis)
   bash: python ida_cli.py start libsecurity.so
   → .i64 detected → binary_md5 validated → open_database(idb_path) → a few seconds → ready
   → If binary changed: WARNING → --fresh or --force

7. Shutdown
   bash: python ida_cli.py stop a1b2
```

---

## 8. Integration with Existing Analysis Stack

```
Java/Kotlin code              → JADX MCP
Native .so (quick check)      → Ghidra MCP
Native .so (deep analysis)    → IDA CLI (idalib)
```

Decision tree:

```
.so analysis needed
  ↓
Is Ghidra decompilation result sufficient?
  YES → Done
  NO  → Is it a security solution core logic or Ghidra result unclear?
          YES → Use IDA CLI
```

---

## 9. Edge Cases and Error Handling

### Edge Cases Removed from v1.7

Items **no longer applicable** due to idalib transition:

| Removed Item | Reason |
|--------------|--------|
| execute_sync timeout/deadlock | execute_sync itself removed |
| register_timer lifecycle | register_timer not needed |
| auto_wait background thread deadlock | open_database handles everything |
| ThreadingHTTPServer thread safety | HTTPServer single-threaded |
| notify_when(NW_TERMIDA) batch mode | notify_when not needed |
| params.json not found | params.json not needed |
| idc.ARGV.count (IDC syntax) | idc.ARGV not needed (argparse) |
| idc.save_base() deprecated | idc not used |
| get_kernel_version thread safety | Single-threaded, caching not needed |
| analyzing state execute_sync unused | HTTP itself not running |
| status analyzing vs ready duality | HTTP only in ready state |
| per-API execute_sync timeout | Direct call, no separate timeout needed |
| stale_threshold vs batch ops conflict | No conflict since no execute_sync |
| qexit non-main-thread safety | qexit not used |
| NW_TERMIDA module confusion (ida_idaapi vs ida_idp) | notify_when not needed |
| IDA auto-exit when idat -S script returns | Not applicable in idalib |
| script_path space issue (-S flag) | -S flag not used |

### Remaining Edge Cases

| Case | Handling |
|------|----------|
| FAT binary | Print slice list → --arch manual selection |
| Raw firmware | --arch required |
| DEX/APK | Redirect to JADX |
| Instance crash | Auto stale cleanup in all commands (heartbeat + PID check) |
| initializing 30s+ | Treated as stale, auto-cleanup |
| Port conflict | port 0 (OS auto-assign) |
| Plugin load failure | Fallback to assembly-only mode |
| .i64 corrupted | Suggest --fresh |
| Context overflow | Force --out, switch to file read mode |
| config.json missing | Fallback to defaults + warning |
| Directory missing | Auto-create |
| Non-ASCII path | Warning + suggest ASCII path |
| Registry lock timeout | Remove stale lock, retry |
| stop unresponsive | Force kill with psutil + manual registry cleanup |
| exec_enabled=false | EXEC_DISABLED |
| Duplicate binary load | Warning then exit, separate instance with --force |
| --out save failure | SAVE_FAILED, result included in response body |
| Symbol name address resolution failure | INVALID_ADDRESS + find_func suggestion |
| Windows PID reuse | Store + compare pid_create_time |
| subprocess detach | DETACHED_PROCESS \| CREATE_NEW_PROCESS_GROUP |
| Binary changed on .i64 reuse | binary_md5 comparison → warning |
| decompile_batch individual failure | Include error field, return rest normally |
| decompile_batch addrs exceeded | Max 20, INVALID_PARAMS |
| DNS rebinding | Host header validation |
| CSRF | Bearer token required |
| get_bytes size limit | Max 4096, INVALID_PARAMS |
| find_bytes API change (IDA 9.0+) | Use `ida_bytes.find_bytes()` (`parse_binpat_str`/`bin_search` deprecated, `idc.find_binary` removed). Returns single ea_t |
| Log bloat | RotatingFileHandler (50MB/3 backups) |
| Orphan files | cleanup command |
| exec stdout capture | contextlib.redirect_stdout |
| save_database bug | `ida_loader.save_database(path, 0)` — pass flags=0 explicitly as workaround |
| ida_struct removed (IDA 9.x) | Use ida_typeinf exclusively |
| IDA license expired | import idapro fails → detected in --check |
| max_instances exceeded | Error message then exit |

### v2.0 New Edge Cases

| Case | Handling |
|------|----------|
| idapro import failure | IDADIR not set or idalib.dll not found → guidance in --check |
| open_database return value != 0 | state=error, error code logged, sys.exit(1) |
| open_database timeout | Watchdog thread os._exit(1) after 600 seconds |
| stop in analyzing state | HTTP not running → ida_cli.py force kills by PID |
| idalib single-thread violation | Fundamentally prevented by using HTTPServer (single-threaded) |
| close_database failure | try/except then log, process exits |
| -o flag (IDA 9.1+) | Supported. -o implies -c → new analysis only. Reuse opens .i64 directly |
| -o flag unsupported (IDA 9.0) | Fallback: hardlink/copy binary to idb_dir then open_database |
| idapro whl Python version mismatch | .pyd load failure → import error → detected in --check |
| Python 3.14 use | IDA 9.3 Known Issue ("PySide6 crashes") → warning in --check |
| Long-running request during serve_forever | Single-threaded so other requests wait; Claude makes sequential calls, no issue |
| server.shutdown called from handler | Call from separate thread (deadlock prevention, Python official recommendation) |
| .i64 corruption on analyzing stop | Incomplete .i64 possible after proc.kill() → guide to recreate with --fresh |
| .i64.meta.json missing | Print warning and skip MD5 validation, continue normally |
| exec infinite loop | No server-side timeout → indirectly protected by client request_timeout_batch |
| idc.qexit() called in exec | Terminates server process → consider removing from _exec_namespace |
| Multi-instance IDA license | open_database fails → state=error + suggest stopping existing instance |
| wait timeout | Print message + current state, suggest checking logs |
| logs --follow Ctrl+C | Catch KeyboardInterrupt → normal exit |
| auth_token file permissions | Windows: inherits default ACL (owner read recommended) |
| Concurrent start calls (same binary) | Serialized by registry lock, second call detects duplicate |
| Disk space insufficient (save_db) | Log save_db failure + SAVE_FAILED error |
| Binary deleted (during analysis) | open_database loads at startup → no impact. Binary not found error on restart |
| open_database error code interpretation | Log meaning per code (license, unsupported format, file not found, etc.) |
| idb_path MD5 is path hash not file content | Intentional design: same file different path → separate .i64 created |
| atexit Python 3.12+ thread restriction | RuntimeError possible if close_database() creates internal threads → testing required |
| close_database double-close | _db_closed guard prevents double-call on normal + atexit |
| HTTP 403 response parsing | Server returns error in JSON format (not using send_error), client also defends against non-JSON |
| error state registry residue | Auto-cleanup in cleanup_stale when error state + PID terminated |
| heartbeat=null registry entry | cleanup_stale determines by PID liveness (watchdog termination case) |
| idb_dir no write permission | open_database fails → state=error. Recommend adding write permission validation in --check |
| Concurrent start TOCTOU race | Duplicate check performed within registry lock, serialized |
| decompiler 32/64-bit plugin mismatch | Check bitness with `ida_ida.inf_is_64bit()` then select correct plugin (e.g., hexarm vs hexarm64). Plugins remain 32/64 separate even in IDA 9.x |
| Malformed HTTP request (missing Content-Length, invalid JSON) | Include JSON parsing in try/except, return INVALID_PARAMS error code as JSON response (prevents Python default 500 error) |

---

## 10. Implementation Order

```
Step 1: arch_detect.py + config.json
        → ELF/PE/Mach-O header parsing
        → config.json load / defaults / environment variable substitution
        → --init (auto-create directories)
        → --check (idapro import, Python version, psutil, path validation)

Step 2: ida_server.py (idalib-based)
        → Receive argparse arguments
        → import idapro → open_database (blocking)
        → open_db_timeout watchdog
        → Plugin loading based on _DECOMPILER_MAP
        → save_db (ida_loader.save_database flags=0 workaround)
        → HTTPServer (single-threaded) + security (token + Host validation)
        → Implement all APIs (24 total)
        → heartbeat (registry update only, no IDA API calls)
        → Shutdown: close_database + atexit cleanup
        → Logging: RotatingFileHandler

Step 3: ida_cli.py
        → start command (absorbs v1.7 start_ida.py role):
          instance_id generation, .i64 path determination, MD5 validation,
          duplicate detection, registry registration, subprocess execution
        → Auth token load + connection retry (3 times)
        → cleanup_stale() psutil + pid_create_time
        → cleanup command (--dry-run)
        → --json global output mode
        → xrefs --direction to|from|both
        → logs --follow: 0.5 second polling
        → wait: registry polling (no HTTP during analyzing)
        → stop: graceful shutdown then force kill fallback

Step 4: Integration testing + edge case hardening

Step 5: Update Claude skill
```

Changes compared to v1.7:
- start_ida.py (Step 3) removed → merged into ida_cli.py
- Remove all execute_sync/register_timer/ThreadingHTTPServer related code from ida_server.py
- --check verifies idapro import instead of idat.exe

---

## 11. Version History

| Version | Changes |
|---------|---------|
| v0.1 ~ v1.7 | idat -S based architecture (see headless_ida_plan_v1.7.md for details) |
| v2.0 | **idalib transition**: Full migration from idat -S → idalib (Hex-Rays official headless library). **Removed**: start_ida.py, params.json, execute_sync, register_timer, ThreadingHTTPServer, notify_when(NW_TERMIDA), idat.exe path management, -S/-A/-c flag management. **Simplified**: HTTPServer single-threaded (deadlock impossible), idapro.open_database() all-in-one analysis+wait, idapro.close_database() clean shutdown, atexit standalone defense (double defense not needed), argparse argument reception (idc.ARGV not needed). **New**: analyzing state HTTP not running (registry polling), open_db_timeout watchdog, idapro --check validation, -o flag idb path control. **Maintained**: HTTP JSON-RPC protocol, 24 APIs, triple security defense, .i64 reuse + MD5 validation, heartbeat + stale cleanup, registry lock, all CLI commands. |
| v2.0.1 | **Technical validation**: IDA 9.0 → **9.1+ required** (open_database args parameter added in 9.1). Python **3.12/3.13 recommended**, 3.14 incompatibility warning (Known Issue). -o flag support confirmed (IDA 9.1+, implies -c). Fixed analyzing state port=null inconsistency. RISC-V ELF e_machine detection added (0xF3). INTERNAL error code added. find_bytes start parameter added. **Timeout branching**: request_timeout(35s) / request_timeout_batch(300s). config_path variable defined. SERVER_VERSION constant. **atexit detailed**: behavior scope table, Python 3.12+ thread restriction caution. exec security cautions. shutdown race condition documented. --arch option behavior explained. **20 edge cases added**: analyzing stop .i64 corruption, exec infinite loop, idc.qexit defense, multi-instance license, concurrent start serialization, disk insufficient, atexit thread restriction, etc. |
| v2.0.2 | **Consistency review**: Changed HTTP 403 response to JSON format (send_error→_send_json, FORBIDDEN_HOST/AUTH_FAILED error codes actually returned). Added non-JSON response defense in post_rpc. **cleanup_stale hardening**: Auto-cleanup on error state + PID terminated, PID-based judgment for heartbeat=null entries, _is_process_alive helper extracted. **close_database double-close prevention**: _db_closed guard added. **CLI improvements**: Added --init/--check to command list, list implementation defined, save CLI command added, find_func --regex/--max options, comment --repeatable option, xrefs --direction both behavior defined. **Fixed**: find_func example total mismatch (3→2), auth_token file description corrected, API count 22→24, installation step IDA 9.0→9.1. **7 edge cases added**: double-close, HTTP 403 parsing, error state residue, heartbeat null, idb_dir permissions, TOCTOU race. |
| v2.0.3 | **Error handling consistency**: Added RpcError catch branch to do_POST (_dispatch's RpcError exception now correctly generates {"error": ...} format response). **Example data consistency**: Added missing 0x5678 success item to decompile_batch example (3 items matching total=3). Fixed analyzing state registry example last_heartbeat to null (heartbeat thread starts after open_database completes, prevents stale_threshold < open_db_timeout conflict). **--check hardened**: Added idb directory write permission validation item (tempfile-based). Fixed missing stale_threshold argument in cleanup_stale call. |
| v2.0.4 | **Implementation validation (web research-based)**: Fully replaced _DECOMPILER_MAP with `(proc_id, is_64bit)` tuple keys — decompiler plugins remain 32/64-bit separate in IDA 9.x (hexrays/hexx64, hexarm/hexarm64, etc.). Added `ida_ida.inf_is_64bit()` check. Reflected in both Section 3-2 plugin table and Section 5-2 code. **Registry lock protection hardened**: All registry modification paths in cleanup_stale, cmd_start, cmd_list, cmd_stop wrapped with acquire_lock/release_lock try/finally. **cmd_start TOCTOU fix**: max_instances check + duplicate check + register performed **atomically within single lock scope** (previous: race possible with validation→registration after lock release). **Registry file location unified**: Removed ida_servers.json from tools/ directory, accurately reflected in %USERPROFILE%/.ida-headless/ directory structure. **psutil precision documented**: Added create_time() ~1 second precision caution comment in _is_process_alive. **Function name unification**: `_save_registry`/`_load_registry` → `save_registry`/`load_registry` in ida_cli.py (ida_server.py retains underscore). Removed duplicate find_bytes max_results description. **1 edge case added**: decompiler 32/64-bit plugin mismatch. |
| v2.0.5 | **do_POST error handling hardened**: Moved JSON parsing inside try/except scope — returns JSON error response even for malformed requests (missing Content-Length, invalid JSON) (`json.JSONDecodeError` → INVALID_PARAMS). **set_comment API specification improved**: Added `type` parameter (`"line"` default, `"func"` for function comment — uses `idc.set_func_cmt()`). Added `--type line\|func` option to CLI. **exec_namespace improvement**: Added `ida_ida` module. **1 edge case added**: malformed HTTP request. |
| v2.0.6 | **API implementation validation (web research-based)**: **idaapi umbrella module cleanup** — use originating modules directly per Hex-Rays recommendation. `save_db()` changed from `idaapi.get_path`/`idaapi.save_database` → `ida_loader.get_path`/`ida_loader.save_database`. Cached value collection changed from `idaapi.get_kernel_version()` → `ida_kernwin.get_kernel_version()`. **find_bytes deprecated API replacement**: `parse_binpat_str` + `bin_search` combination deprecated in IDA 9.0 porting guide. Fully replaced with `ida_bytes.find_bytes()` high-level API (returns single ea_t, not tuple). `idc.find_binary`/`ida_search.find_binary` also explicitly noted as removed in IDA 9.0. **Confirmed APIs (no changes)**: `idc.get_name_ea_simple` (BADADDR return confirmed), `ida_hexrays.decompile` (cfuncptr_t return), `idautils.Functions` (generator), SEGPERM values (R=4,W=2,X=1), `idc.set_cmt`/`set_func_cmt` signatures. |

"""CLI core — output helpers, constants, config, instance management, RPC communication."""

import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import time

try:
    import psutil
except ImportError:
    psutil = None

try:
    import requests as req_lib
except ImportError:
    req_lib = None

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _SCRIPT_DIR)
from arch_detect import arch_detect
from contextlib import contextmanager
from common import (
    load_config as _load_config_core,
    init_registry_paths, acquire_lock, release_lock,
    load_registry, save_registry,
    file_md5, remove_auth_token,
)

_DEFAULT_CONFIG = os.path.join(_SCRIPT_DIR, "config.json")

# ─────────────────────────────────────────────
# CLI Output Helpers
# ─────────────────────────────────────────────

def _log_ok(msg):    print(f"[+] {msg}")
def _log_err(msg):   print(f"[-] {msg}")
def _log_info(msg):  print(f"[*] {msg}")
def _log_warn(msg):  print(f"[!] {msg}")


def _error_resp(code, message, suggestion=None):
    """Build a standard error response dict."""
    err = {"code": code, "message": message}
    if suggestion:
        err["suggestion"] = suggestion
    return {"error": err}


def _opt(args, name, default=None):
    """Safe getattr with default — replaces repetitive getattr(args, name, None) calls."""
    return getattr(args, name, default)


def _truncate(s, limit, suffix="..."):
    """Truncate string to limit, appending suffix if truncated."""
    return s[:limit - len(suffix)] + suffix if len(s) > limit else s


def _md_table_header(*headers):
    """Return [header_row, separator_row] for a markdown table."""
    hdr = "| " + " | ".join(headers) + " |"
    sep = "|" + "|".join("---" for _ in headers) + "|"
    return [hdr, sep]


def _format_arch_info(arch_info):
    """Format arch_info dict as 'FORMAT ARCH BITSbit' string."""
    fmt = arch_info.get("file_format", "?")
    arch = arch_info.get("arch", "?")
    bits = arch_info.get("bits", "?")
    return f"{fmt} {arch} {bits}bit"


def _print_truncated(items, fmt_fn, max_show=30, indent="    "):
    """Print items with truncation. fmt_fn(item) -> str."""
    for item in items[:max_show]:
        print(f"{indent}{fmt_fn(item)}")
    if len(items) > max_show:
        print(f"{indent}... and {len(items) - max_show} more")


@contextmanager
def _registry_locked():
    """Context manager for registry lock acquisition."""
    if not acquire_lock():
        raise RuntimeError("Could not acquire registry lock")
    try:
        yield
    finally:
        release_lock()


# ─────────────────────────────────────────────
# Constants (CLI-specific)
# ─────────────────────────────────────────────

SUPPORTED_BINARY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".so", ".dylib", ".o", ".obj",
    ".elf", ".bin", ".ko", ".axf", ".hex", ".srec", ".efi",
}

AUTO_GENERATED_PREFIXES = (
    "sub_", "nullsub_", "loc_", "unk_", "byte_", "word_",
    "dword_", "qword_", "off_", "stru_", "asc_",
)

INSTANCE_ID_LENGTH = 4              # base36 chars for instance ID
INSTANCE_ID_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz"
MD5_PREFIX_LENGTH = 8               # hex chars from MD5 for idb filename
INIT_STALE_TIMEOUT = 30             # seconds before "initializing" is stale
START_WAIT_TIMEOUT = 10             # seconds to wait for state after Popen
START_POLL_INTERVAL = 1             # seconds between start state polls
STOP_WAIT_ITERATIONS = 10           # iterations waiting for graceful stop
STOP_POLL_INTERVAL = 0.5            # seconds between stop polls
STOP_RPC_TIMEOUT = 10               # seconds for stop RPC call
CLEANUP_AGE_DAYS = 7                # days before orphan logs can be cleaned
CLEANUP_AGE_SECONDS = CLEANUP_AGE_DAYS * 86400
STRING_DISPLAY_LIMIT = 80           # max chars for inline string display
RPC_MAX_RETRIES = 3                 # connection retry attempts
RPC_RETRY_DELAY = 1                 # seconds between retries
PID_CREATE_TIME_TOLERANCE = 1.0     # seconds tolerance for PID create time


def _make_args(**kwargs):
    """Create a simple namespace object for passing to command functions."""
    ns = type('Args', (), kwargs)()
    return ns


# ─────────────────────────────────────────────
# Config (wrapper)
# ─────────────────────────────────────────────

def load_config(config_path=None):
    if not config_path:
        config_path = _DEFAULT_CONFIG
    config_path = os.path.abspath(config_path)
    return _load_config_core(config_path), config_path


# ─────────────────────────────────────────────
# Auth Token (CLI-specific: read only)
# ─────────────────────────────────────────────

def _load_auth_token(config, instance_id):
    token_path = config["security"]["auth_token_file"]
    try:
        with open(token_path, encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(":", 2)
                if len(parts) == 3 and parts[0] == instance_id:
                    return parts[2]
    except FileNotFoundError:
        pass
    return None


# ─────────────────────────────────────────────
# Instance ID & IDB path
# ─────────────────────────────────────────────

def make_instance_id(binary_path):
    raw = f"{binary_path}{time.time()}{os.getpid()}"
    h = int(hashlib.md5(raw.encode()).hexdigest(), 16)
    base = len(INSTANCE_ID_CHARS)
    result = ""
    for _ in range(INSTANCE_ID_LENGTH):
        result = INSTANCE_ID_CHARS[h % base] + result
        h //= base
    return result


def get_idb_path(config, binary_path, instance_id, force=False, idb_dir=None):
    if not idb_dir:
        idb_dir = config["paths"]["idb_dir"]
    os.makedirs(idb_dir, exist_ok=True)
    binary_name = os.path.basename(binary_path)
    name = re.sub(r'[^\w\-.]', '_', binary_name)
    md5 = hashlib.md5(binary_path.encode()).hexdigest()[:MD5_PREFIX_LENGTH]
    base = f"{name}_{md5}"
    suffix = ".i64"
    if force:
        return os.path.join(idb_dir, f"{base}_{instance_id}{suffix}")
    return os.path.join(idb_dir, f"{base}{suffix}")


def _load_idb_metadata(idb_path):
    try:
        with open(idb_path + ".meta.json", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


# ─────────────────────────────────────────────
# Process Management
# ─────────────────────────────────────────────

def _is_process_alive(info):
    pid = info.get("pid")
    if not pid:
        return False
    if psutil is None:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    try:
        proc = psutil.Process(pid)
        stored_ct = info.get("pid_create_time")
        if stored_ct and abs(proc.create_time() - stored_ct) > PID_CREATE_TIME_TOLERANCE:
            return False
        return proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def cleanup_stale(registry, stale_threshold):
    now = time.time()
    changed = False
    for iid in list(registry.keys()):
        info = registry[iid]
        state = info.get("state", "unknown")
        if state == "initializing":
            if now - info.get("started", 0) > INIT_STALE_TIMEOUT:
                del registry[iid]
                changed = True
                continue
        if state == "error":
            if not _is_process_alive(info):
                del registry[iid]
                changed = True
            continue
        hb = info.get("last_heartbeat")
        if not hb:
            if info.get("pid") and not _is_process_alive(info):
                del registry[iid]
                changed = True
            continue
        if now - hb > stale_threshold:
            if not _is_process_alive(info):
                del registry[iid]
                changed = True
    if changed:
        save_registry(registry)
    return registry


# ─────────────────────────────────────────────
# RPC Communication
# ─────────────────────────────────────────────

_BATCH_METHODS = {"decompile_batch", "exec"}


def post_rpc(config, port, method, instance_id, params=None, timeout=None):
    if req_lib is None:
        return _error_resp("MISSING_DEP", "requests package not installed (pip install requests)")
    if timeout is None:
        timeout = config["analysis"]["request_timeout_batch"] if method in _BATCH_METHODS \
            else config["analysis"]["request_timeout"]
    url = f"http://127.0.0.1:{port}/"
    body = {"method": method, "id": 1}
    if params:
        body["params"] = params
    headers = {"Content-Type": "application/json"}
    token = _load_auth_token(config, instance_id)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    for attempt in range(RPC_MAX_RETRIES):
        try:
            resp = req_lib.post(url, json=body, headers=headers, timeout=timeout)
            try:
                return resp.json()
            except ValueError:
                return _error_resp("INVALID_RESPONSE", f"HTTP {resp.status_code}: {resp.text[:200]}")
        except req_lib.ConnectionError:
            if attempt < RPC_MAX_RETRIES - 1:
                time.sleep(RPC_RETRY_DELAY)
                continue
            return _error_resp("CONNECTION_FAILED", f"Cannot connect to 127.0.0.1:{port}")
        except req_lib.Timeout:
            return _error_resp("TIMEOUT", f"Request timeout ({timeout}s)")
    return _error_resp("UNKNOWN", "Unexpected error")


# ─────────────────────────────────────────────
# Instance Selection
# ─────────────────────────────────────────────

def resolve_instance(args, config):
    registry = load_registry()
    iid = _opt(args, 'instance')
    if iid:
        if iid in registry:
            return iid, registry[iid]
        _log_err(f"Instance '{iid}' not found")
        return None, None
    hint = _opt(args, 'binary_hint')
    if hint:
        matches = [(k, v) for k, v in registry.items()
                   if hint.lower() in v.get("binary", "").lower()]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            _log_err(f"No instance matching '{hint}'")
        else:
            _log_err(f"Multiple instances match '{hint}':")
            for k, v in matches:
                print(f"  {k}  {v.get('binary', '?')}")
        return None, None
    active = {k: v for k, v in registry.items()
              if v.get("state") in ("ready", "analyzing")}
    if len(active) == 1:
        k = next(iter(active))
        return k, active[k]
    if not active:
        _log_err("No active instances. Use 'start' first.")
    else:
        _log_err("Multiple active instances. Use -i <id> to select:")
        for k, v in active.items():
            print(f"  {k}  {v.get('state', '?'):<12}  {v.get('binary', '?')}")
    return None, None


# ─────────────────────────────────────────────
# RPC Proxy Helper
# ─────────────────────────────────────────────

def _ensure_ready(iid, info):
    """Check instance is ready. Returns (port, ok)."""
    if info.get("state") != "ready":
        _log_err(f"Instance {iid} is not ready (state: {info.get('state')})")
        return None, False
    port = info.get("port")
    if not port:
        _log_err(f"Instance {iid} has no port assigned")
        return None, False
    return port, True


def _resolve_ready(args, config):
    """Resolve instance and ensure ready. Returns (iid, info, port) or (None, None, None)."""
    iid, info = resolve_instance(args, config)
    if not iid:
        return None, None, None
    port, ok = _ensure_ready(iid, info)
    if not ok:
        return None, None, None
    return iid, info, port


def _rpc_call(args, config, method, params=None):
    iid, info, port = _resolve_ready(args, config)
    if not iid:
        return None
    resp = post_rpc(config, port, method, iid, params=params)
    if "error" in resp:
        err = resp["error"]
        # Health check: if connection failed, check if process is alive
        if err.get("code") == "CONNECTION_FAILED" and not _is_process_alive(info):
            _log_err(f"Instance {iid} server process is dead (pid={info.get('pid')})")
            binary = info.get("path")
            if binary and os.path.isfile(binary):
                _log_info("Cleaning up stale instance...")
                try:
                    with _registry_locked():
                        r = load_registry()
                        r.pop(iid, None)
                        save_registry(r)
                except RuntimeError:
                    pass
                remove_auth_token(config["security"]["auth_token_file"], iid)
                _log_info(f"Restart with: ida-cli start {binary}")
            return None
        if _opt(args, 'json_output', False):
            print(json.dumps(resp, ensure_ascii=False, indent=2))
        else:
            _log_err(f"{err.get('code')}: {err.get('message')}")
            if err.get("suggestion"):
                print(f"    Hint: {err['suggestion']}")
        return None
    result = resp.get("result", {})
    if _opt(args, 'json_output', False):
        print(json.dumps(resp, ensure_ascii=False, indent=2))
        return None
    return result


# ─────────────────────────────────────────────
# Instance Management Helpers
# ─────────────────────────────────────────────

def _force_kill(iid, pid, stored_create_time):
    """Force kill a process by PID."""
    if psutil is None:
        try:
            os.kill(pid, 9)
            _log_ok(f"Instance {iid} force killed (pid={pid})")
        except OSError:
            _log_ok(f"Instance {iid} process already gone")
        return
    try:
        proc = psutil.Process(pid)
        if (stored_create_time
                and abs(proc.create_time() - stored_create_time) > PID_CREATE_TIME_TOLERANCE):
            _log_ok(f"Instance {iid} process already gone (PID reused)")
        else:
            proc.kill()
            _log_ok(f"Instance {iid} force killed (pid={pid})")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        _log_ok(f"Instance {iid} process already gone")


def _register_instance(config, instance_id, binary_path, arch_info,
                        idb_path, log_path, force):
    """Register an instance in the registry. Returns True on success."""
    try:
        with _registry_locked():
            registry = load_registry()
            cleanup_stale(registry, config["analysis"]["stale_threshold"])
            if len(registry) >= config["analysis"]["max_instances"]:
                _log_err(f"Max instances reached ({config['analysis']['max_instances']})")
                return False
            for info in registry.values():
                if (os.path.normcase(info.get("path", "")) == binary_path
                        and info.get("state") in ("analyzing", "ready")):
                    if not force:
                        _log_warn(f"{os.path.basename(binary_path)} already running "
                                  f"(id: {info['id']}). Use --force.")
                        return False
            registry[instance_id] = {
                "id": instance_id, "pid": None, "port": None,
                "binary": os.path.basename(binary_path),
                "path": binary_path,
                "arch": arch_info.get("arch"), "bits": arch_info.get("bits"),
                "format": arch_info.get("file_format"),
                "idb_path": idb_path, "log_path": log_path,
                "state": "initializing",
                "started": time.time(),
                "last_heartbeat": None,
            }
            save_registry(registry)
            return True
    except RuntimeError:
        _log_err("Could not acquire registry lock")
        return False


def _spawn_server(config, config_path, binary_path, instance_id, idb_path, log_path, fresh):
    """Start ida_server.py as a detached process."""
    server_script = os.path.join(_SCRIPT_DIR, "ida_server.py")
    cmd = [sys.executable, server_script, binary_path,
           "--id", instance_id, "--idb", idb_path,
           "--log", log_path, "--config", config_path]
    if fresh:
        cmd.append("--fresh")
    env = os.environ.copy()
    env["IDADIR"] = config["ida"]["install_dir"]
    stderr_file = open(log_path + ".stderr", "w") if log_path else subprocess.DEVNULL
    popen_kwargs = dict(
        env=env,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stderr_file,
    )
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = (
            subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        )
    else:
        # Unix: detach via double-fork behavior with start_new_session
        popen_kwargs["start_new_session"] = True
    try:
        return subprocess.Popen(cmd, **popen_kwargs)
    except Exception:
        if stderr_file is not subprocess.DEVNULL:
            stderr_file.close()
        raise


def _wait_for_start(instance_id):
    """Wait until the instance exits the initializing state."""
    deadline = time.time() + START_WAIT_TIMEOUT
    state = "initializing"
    while time.time() < deadline:
        time.sleep(START_POLL_INTERVAL)
        info = load_registry().get(instance_id, {})
        state = info.get("state", "unknown")
        if state in ("analyzing", "ready", "error"):
            break
    return state


# ─────────────────────────────────────────────
# Markdown Formatting Helpers
# ─────────────────────────────────────────────

def _is_md_out(args):
    """Check if --out path ends with .md"""
    out = _opt(args, 'out')
    return out and out.lower().endswith('.md')


def _save_local(path, content):
    """Save content to a local file from CLI side."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    _log_ok(f"Saved to: {path}")


def _md_decompile(r, with_xrefs=False):
    """Format decompile result as markdown."""
    name = r.get('name', '')
    addr = r.get('addr', '')
    code = r.get('code', '')
    lines = [f"# {name}", f"**Address**: `{addr}`", "", "```c", code, "```"]
    if with_xrefs:
        callers = r.get("callers", [])
        callees = r.get("callees", [])
        if callers:
            lines += ["", f"## Callers ({len(callers)})"] + _md_table_header("Address", "Function", "Type")
            for c in callers:
                lines.append(f"| `{c['from_addr']}` | {c['from_name']} | {c['type']} |")
        if callees:
            lines += ["", f"## Callees ({len(callees)})"] + _md_table_header("Address", "Function", "Type")
            for c in callees:
                lines.append(f"| `{c['to_addr']}` | {c['to_name']} | {c['type']} |")
    return "\n".join(lines) + "\n"


def _md_decompile_batch(r):
    """Format batch decompile result as markdown."""
    lines = [f"# Batch Decompile", f"**Total**: {r['total']}, **Success**: {r['success']}, **Failed**: {r['failed']}", ""]
    for func in r.get("functions", []):
        if "code" in func:
            lines += [f"## {func['name']} (`{func['addr']}`)", "", "```c", func["code"], "```", ""]
        else:
            lines += [f"## `{func.get('addr', '?')}` - ERROR", f"> {func.get('error', '?')}", ""]
    return "\n".join(lines)


def _md_summary(r):
    """Format summary result as markdown."""
    lines = [f"# Binary Summary: {r.get('binary', 'unknown')}", ""]
    lines += ["## Overview"] + _md_table_header("Property", "Value")
    for key in ("ida_version", "decompiler", "func_count", "total_strings", "total_imports", "export_count", "avg_func_size"):
        if key in r:
            lines.append(f"| {key} | {r[key]} |")
    if r.get("segments"):
        lines += ["", "## Segments"] + _md_table_header("Name", "Start", "End", "Size", "Perm")
        for s in r["segments"]:
            lines.append(f"| {s.get('name', '')} | `{s.get('start_addr', '')}` | `{s.get('end_addr', '')}` | {s.get('size', '')} | {s.get('perm', '')} |")
    if r.get("top_import_modules"):
        lines += ["", "## Top Import Modules"]
        for m in r["top_import_modules"]:
            lines.append(f"- **{m['module']}**: {m['count']} imports")
    if r.get("largest_functions"):
        lines += ["", "## Largest Functions"] + _md_table_header("Address", "Name", "Size")
        for f in r["largest_functions"]:
            lines.append(f"| `{f['addr']}` | {f['name']} | {f['size']} |")
    if r.get("strings_sample"):
        lines += ["", "## String Samples"]
        for s in r["strings_sample"][:20]:
            lines.append(f"- `{s.get('addr', '')}`: {s.get('value', '')}")
    return "\n".join(lines) + "\n"


def _check_inline_limit(text, config):
    """Truncate and return a warning if max_inline_lines is exceeded."""
    limit = config.get("output", {}).get("max_inline_lines", 200)
    lines = text.split("\n")
    if len(lines) <= limit:
        return text, False
    truncated = "\n".join(lines[:limit])
    truncated += f"\n\n[!] Output truncated ({len(lines)} lines, showing {limit}). Use --out to save full result."
    return truncated, True


def _maybe_output_param(args, p, md_out=False):
    """Add output param to p if --out is set and not markdown output."""
    out = _opt(args, 'out')
    if out and not md_out:
        p["output"] = out


def _build_params(args, mapping):
    """Build RPC params dict from args attributes. mapping: {attr_name: param_key}"""
    p = {}
    for attr, key in mapping.items():
        val = _opt(args, attr)
        if val is not None:
            p[key] = val
    return p


def _list_params(args):
    return _build_params(args, {"offset": "offset", "count": "count",
                                "filter": "filter", "out": "output"})


# ── List-type command factory ──

def _fmt_func(d):
    return f"  {d['addr']}  {d['name']:<50}  size={d.get('size', 0)}"


def _fmt_string(d):
    return f"  {d['addr']}  {_truncate(d.get('value', ''), STRING_DISPLAY_LIMIT)}"


def _fmt_import(d):
    return f"  {d['addr']}  {d.get('module', ''):<20}  {d['name']}"


def _fmt_export(d):
    return f"  {d['addr']}  {d['name']}"


_LIST_COMMANDS = {
    "functions": ("get_functions",
                  lambda r: f"Total: {r['total']} (showing {r['count']} from offset {r['offset']})",
                  _fmt_func),
    "strings":   ("get_strings",
                  lambda r: f"Total: {r['total']} (showing {r['count']})",
                  _fmt_string),
    "imports":   ("get_imports",
                  lambda r: f"Total: {r['total']} (showing {r['count']})",
                  _fmt_import),
    "exports":   ("get_exports",
                  lambda r: f"Total: {r['total']}",
                  _fmt_export),
}


def _cmd_proxy_list(args, config, method, header_fn, format_fn):
    """Common handler for list-type RPC commands."""
    r = _rpc_call(args, config, method, _list_params(args))
    if not r:
        return
    print(header_fn(r))
    for d in r.get("data", []):
        print(format_fn(d))


# ─────────────────────────────────────────────
# Project-local Config
# ─────────────────────────────────────────────

def _merge_project_config(config):
    """Merge project-local config.local.json if present."""
    local_path = os.path.join(os.getcwd(), "config.local.json")
    if not os.path.isfile(local_path):
        return config
    try:
        with open(local_path, "r", encoding="utf-8") as f:
            local = json.load(f)
        # Deep merge
        merged = dict(config)
        for key, val in local.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(val, dict):
                merged[key] = {**merged[key], **val}
            else:
                merged[key] = val
        return merged
    except Exception:
        return config

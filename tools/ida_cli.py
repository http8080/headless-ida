#!/usr/bin/env python3
"""ida_cli.py -IDA Headless CLI entry point for Claude

Usage:
    ida_cli.py start <binary> [--fresh] [--force]
    ida_cli.py stop <id>
    ida_cli.py list
    ida_cli.py [-i <id>] decompile <addr>
    ida_cli.py --help
"""

import argparse
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

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
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
# Commands: Instance Management
# ─────────────────────────────────────────────

def cmd_init(config):
    dirs = [config["paths"]["idb_dir"], config["paths"]["log_dir"],
            os.path.dirname(config["paths"]["registry"])]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        _log_ok(d)
    _log_ok("Init complete")


def cmd_check(config):
    issues = []
    print(f"  Python: {sys.version.split()[0]}")
    if sys.version_info < (3, 10):
        issues.append("Python 3.10+ required")
    try:
        import importlib.util
        spec = importlib.util.find_spec("idapro")
        print(f"  idapro: {'found' if spec else 'NOT FOUND'}")
        if not spec:
            issues.append("idapro not found")
    except Exception:
        issues.append("idapro check failed")
    ida_dir = config["ida"]["install_dir"]
    ok = os.path.isdir(ida_dir)
    print(f"  IDA dir: {ida_dir} ({'OK' if ok else 'NOT FOUND'})")
    if not ok:
        issues.append(f"IDA dir not found: {ida_dir}")
    for pkg_name, mod in [("requests", req_lib), ("psutil", psutil)]:
        if mod:
            print(f"  {pkg_name}: {getattr(mod, '__version__', 'found')}")
        else:
            issues.append(f"{pkg_name} not installed")
            print(f"  {pkg_name}: NOT FOUND")
    if issues:
        print(f"\n[-] {len(issues)} issue(s):")
        for i in issues:
            print(f"  - {i}")
    else:
        print("\n[+] All checks passed")


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


def cmd_start(args, config, config_path):
    binary_path = os.path.normcase(os.path.abspath(args.binary))
    if not os.path.isfile(binary_path):
        _log_err(f"Binary not found: {binary_path}")
        return

    arch_info = arch_detect(binary_path, _opt(args, 'arch'))
    instance_id = make_instance_id(binary_path)
    force = _opt(args, 'force', False)
    fresh = _opt(args, 'fresh', False)
    idb_dir_override = _opt(args, 'idb_dir') or os.environ.get('IDA_IDB_DIR')
    idb_path = get_idb_path(config, binary_path, instance_id, force, idb_dir=idb_dir_override)

    if os.path.exists(idb_path) and not fresh:
        meta = _load_idb_metadata(idb_path)
        stored_md5 = meta.get("binary_md5")
        if stored_md5:
            current_md5 = file_md5(binary_path)
            if stored_md5 != current_md5:
                _log_warn("Binary changed since .i64 was created.")
                if not force:
                    print("  Use --fresh to rebuild, or --force to proceed.")
                    return

    log_path = os.path.join(config["paths"]["log_dir"], f"{instance_id}.log")
    if not _register_instance(config, instance_id, binary_path, arch_info,
                               idb_path, log_path, force):
        return

    proc = _spawn_server(config, config_path, binary_path, instance_id, idb_path, log_path, fresh)
    state = _wait_for_start(instance_id)

    _log_ok(f"Instance started: {instance_id}")
    print(f"    Binary:  {os.path.basename(binary_path)} ({_format_arch_info(arch_info)})")
    print(f"    IDB:     {idb_path}")
    print(f"    Log:     {log_path}")
    print(f"    State:   {state}")
    print(f"    PID:     {proc.pid}")
    if state == "error":
        _log_err(f"Analysis failed. Check: ida_cli.py logs {instance_id}")
    elif state in ("initializing", "analyzing"):
        _log_info(f"Still {state}. Use: ida_cli.py wait {instance_id}")


def cmd_stop(args, config):
    iid = args.id
    registry = load_registry()
    info = registry.get(iid)
    if not info:
        _log_err(f"Instance '{iid}' not found")
        return
    port = info.get("port")
    pid = info.get("pid")

    if port:
        try:
            post_rpc(config, port, "stop", iid, timeout=STOP_RPC_TIMEOUT)
            for _ in range(STOP_WAIT_ITERATIONS):
                time.sleep(STOP_POLL_INTERVAL)
                if iid not in load_registry():
                    _log_ok(f"Instance {iid} stopped normally")
                    return
        except Exception:
            pass  # RPC stop failed, fall through to force kill

    if pid:
        _force_kill(iid, pid, info.get("pid_create_time"))

    try:
        with _registry_locked():
            r = load_registry()
            r.pop(iid, None)
            save_registry(r)
    except RuntimeError:
        pass
    remove_auth_token(config["security"]["auth_token_file"], iid)


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


def cmd_wait(args, config):
    iid = args.id
    timeout = _opt(args, 'timeout', 300)
    poll = config["analysis"]["wait_poll_interval"]
    deadline = time.time() + timeout
    state = "unknown"
    while time.time() < deadline:
        info = load_registry().get(iid)
        if not info:
            _log_err(f"Instance {iid} not found")
            return
        state = info.get("state", "unknown")
        port = info.get("port")
        if state in ("initializing", "analyzing"):
            remaining = int(deadline - time.time())
            _log_info(f"{state}... ({remaining}s remaining)")
            time.sleep(poll)
            continue
        if state == "ready" and port:
            resp = post_rpc(config, port, "ping", iid)
            if resp.get("result", {}).get("state") == "ready":
                _log_ok("ready")
                return
        if state == "error":
            _log_err(f"Analysis failed. Check: ida_cli.py logs {iid}")
            return
        time.sleep(poll)
    _log_err(f"Timeout ({timeout}s). Current state: {state}")


def cmd_list(args, config):
    try:
        with _registry_locked():
            registry = load_registry()
            cleanup_stale(registry, config["analysis"]["stale_threshold"])
    except RuntimeError:
        _log_err("Could not acquire registry lock")
        return
    if not registry:
        _log_info("No active instances")
        return
    for iid, info in registry.items():
        state = info.get("state", "unknown")
        binary = info.get("binary", "?")
        port = info.get("port", "-")
        print(f"  {iid}  {state:<12}  {binary}  port={port}")


def cmd_status(args, config):
    iid = _opt(args, 'id')
    if not iid:
        cmd_list(args, config)
        return
    registry = load_registry()
    info = registry.get(iid)
    if not info:
        _log_err(f"Instance '{iid}' not found")
        return
    if info.get("state") == "ready" and info.get("port"):
        resp = post_rpc(config, info["port"], "status", iid)
        if "result" in resp:
            r = resp["result"]
            print(f"  ID:         {iid}")
            print(f"  State:      {r.get('state')}")
            print(f"  Binary:     {r.get('binary')}")
            print(f"  Functions:  {r.get('func_count')}")
            print(f"  Decompiler: {r.get('decompiler_available')}")
            print(f"  IDA:        {r.get('ida_version')}")
            print(f"  Uptime:     {r.get('uptime')}s")
            return
    for k, v in info.items():
        print(f"  {k}: {v}")


def cmd_logs(args, config):
    iid = args.id
    info = load_registry().get(iid)
    if not info:
        _log_err(f"Instance '{iid}' not found")
        return
    log_path = info.get("log_path")
    if not log_path or not os.path.exists(log_path):
        _log_err(f"Log file not found: {log_path}")
        return
    if _opt(args, 'follow', False):
        try:
            with open(log_path, encoding='utf-8') as f:
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if line:
                        print(line, end='', flush=True)
                    else:
                        if not os.path.exists(log_path):
                            _log_info("Log file removed")
                            return
                        time.sleep(STOP_POLL_INTERVAL)
        except KeyboardInterrupt:
            pass
    else:
        tail = _opt(args, 'tail', 50)
        with open(log_path, encoding='utf-8') as f:
            lines = f.readlines()
        for line in lines[-tail:]:
            print(line, end='')


def cmd_cleanup(args, config):
    dry_run = _opt(args, 'dry_run', False)
    registry = load_registry()
    active_ids = set(registry.keys())
    log_dir = config["paths"]["log_dir"]
    idb_dir = config["paths"]["idb_dir"]
    cutoff = time.time() - CLEANUP_AGE_SECONDS
    for f in glob.glob(os.path.join(log_dir, "*.log*")):
        iid = os.path.basename(f).split(".")[0]
        if iid not in active_ids and os.path.getmtime(f) < cutoff:
            if dry_run:
                print(f"  [dry-run] Would delete: {f}")
            else:
                os.remove(f)
                print(f"  Deleted: {f}")
    token_path = config["security"]["auth_token_file"]
    if os.path.exists(token_path):
        try:
            with _registry_locked():
                with open(token_path, encoding="utf-8") as fp:
                    lines = fp.readlines()
                cleaned = [l for l in lines if l.strip().split(":")[0] in active_ids]
                removed = len(lines) - len(cleaned)
                if removed > 0:
                    if dry_run:
                        print(f"  [dry-run] Would remove {removed} stale auth entries")
                    else:
                        with open(token_path, "w", encoding="utf-8") as fp:
                            fp.writelines(cleaned)
                        print(f"  Removed {removed} stale auth entries")
        except RuntimeError:
            pass
    for f in glob.glob(os.path.join(idb_dir, "*")):
        if f.endswith(".meta.json"):
            continue
        in_use = any(info.get("idb_path") == f for info in registry.values())
        if not in_use:
            print(f"  [info] Unused: {os.path.basename(f)}")
    _log_ok("Cleanup done")


# ─────────────────────────────────────────────
# Commands: Analysis/Modification Proxies
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
            lines.append(f"| {s.get('name', '')} | `{s.get('start', '')}` | `{s.get('end', '')}` | {s.get('size', '')} | {s.get('perm', '')} |")
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


# ── Individual proxy commands ──

def cmd_proxy_segments(args, config):
    p = _build_params(args, {"out": "output"})
    r = _rpc_call(args, config, "get_segments", p)
    if not r: return
    for d in r.get("data", []):
        print(f"  {d['start_addr']}-{d['end_addr']}  {d.get('name') or '':<12}  "
              f"{d.get('class') or '':<8}  size={d.get('size') or 0:<8}  {d.get('perm') or ''}")


def cmd_proxy_decompile(args, config):
    with_xrefs = _opt(args, 'with_xrefs', False)
    md_out = _is_md_out(args)
    p = {"addr": args.addr}
    _maybe_output_param(args, p, md_out)
    method = "decompile_with_xrefs" if with_xrefs else "decompile"
    r = _rpc_call(args, config, method, p)
    if not r: return
    if md_out:
        _save_local(args.out, _md_decompile(r, with_xrefs))
        return
    header = f"// {r.get('name', '')} @ {r.get('addr', '')}"
    code = r.get("code", "")
    output = f"{header}\n{code}"
    if with_xrefs:
        callers = r.get("callers", [])
        callees = r.get("callees", [])
        if callers:
            output += f"\n\n// --- Callers ({len(callers)}) ---"
            for c in callers:
                output += f"\n//   {c['from_addr']}  {c['from_name']:<30}  [{c['type']}]"
        if callees:
            output += f"\n\n// --- Callees ({len(callees)}) ---"
            for c in callees:
                output += f"\n//   {c['to_addr']}  {c['to_name']:<30}  [{c['type']}]"
    if not r.get("saved_to"):
        output, _ = _check_inline_limit(output, config)
    print(output)
    if r.get("saved_to"):
        print(f"\n// Saved to: {r['saved_to']}")


def cmd_proxy_decompile_batch(args, config):
    md_out = _is_md_out(args)
    p = {"addrs": args.addrs}
    _maybe_output_param(args, p, md_out)
    r = _rpc_call(args, config, "decompile_batch", p)
    if not r: return
    if md_out:
        _save_local(args.out, _md_decompile_batch(r))
        return
    lines = [f"Total: {r['total']}, Success: {r['success']}, Failed: {r['failed']}"]
    for func in r.get("functions", []):
        if "code" in func:
            lines.append(f"\n// ── {func['name']} ({func['addr']}) ──")
            lines.append(func["code"])
        else:
            lines.append(f"\n// ── {func.get('addr', '?')} ── ERROR: {func.get('error', '?')}")
    output = "\n".join(lines)
    if not r.get("saved_to"):
        output, _ = _check_inline_limit(output, config)
    print(output)


def cmd_proxy_disasm(args, config):
    p = {"addr": args.addr}
    p.update(_build_params(args, {"count": "count", "out": "output"}))
    r = _rpc_call(args, config, "disasm", p)
    if not r: return
    for ln in r.get("lines", []):
        print(f"  {ln['addr']}  {ln.get('bytes', ''):<24}  {ln['insn']}")


def cmd_proxy_xrefs(args, config):
    direction = _opt(args, 'direction', 'to')
    p = {"addr": args.addr}
    if direction in ("to", "both"):
        r = _rpc_call(args, config, "get_xrefs_to", p)
        if r:
            print(f"Xrefs TO {args.addr} ({r.get('total', 0)})")
            for ref in r.get("refs", []):
                print(f"  {ref['from_addr']}  {ref.get('from_name', ''):<30}  {ref['type']}")
    if direction in ("from", "both"):
        if direction == "both":
            print()
        r = _rpc_call(args, config, "get_xrefs_from", p)
        if r:
            print(f"Xrefs FROM {args.addr} ({r.get('total', 0)})")
            for ref in r.get("refs", []):
                print(f"  {ref['to_addr']}  {ref.get('to_name', ''):<30}  {ref['type']}")


def cmd_proxy_find_func(args, config):
    p = {"name": args.name}
    if _opt(args, 'regex', False): p["regex"] = True
    if _opt(args, 'max'): p["max_results"] = args.max
    r = _rpc_call(args, config, "find_func", p)
    if not r: return
    print(f"Query: '{r['query']}' ({r['total']} matches)")
    for m in r.get("matches", []):
        print(f"  {m['addr']}  {m['name']}")


def cmd_proxy_func_info(args, config):
    r = _rpc_call(args, config, "get_func_info", {"addr": args.addr})
    if not r: return
    print(f"  Name:       {r.get('name')}")
    print(f"  Address:    {r.get('start_ea')} - {r.get('end_ea')}")
    print(f"  Size:       {r.get('size')}")
    print(f"  Thunk:      {r.get('is_thunk')}")
    if r.get("calling_convention"):
        print(f"  Convention: {r['calling_convention']}")
    if r.get("return_type"):
        print(f"  Return:     {r['return_type']}")
    if r.get("args"):
        arg_strs = ["{} {}".format(a["type"], a["name"]) for a in r["args"]]
        print(f"  Args:       {', '.join(arg_strs)}")


def cmd_proxy_imagebase(args, config):
    r = _rpc_call(args, config, "get_imagebase")
    if r:
        print(f"  Imagebase: {r['imagebase']}")


def cmd_proxy_bytes(args, config):
    r = _rpc_call(args, config, "get_bytes", {"addr": args.addr, "size": int(args.size)})
    if not r: return
    print(f"  Address: {r['addr']}")
    print(f"  Hex:     {r['hex']}")
    print(f"  Base64:  {r['raw_b64']}")


def cmd_proxy_find_pattern(args, config):
    p = {"pattern": args.pattern}
    if _opt(args, 'max'): p["max_results"] = args.max
    r = _rpc_call(args, config, "find_bytes", p)
    if not r: return
    print(f"Pattern: '{r['pattern']}' ({r['total']} matches)")
    for addr in r.get("matches", []):
        print(f"  {addr}")


def cmd_proxy_comments(args, config):
    r = _rpc_call(args, config, "get_comments", {"addr": args.addr})
    if not r: return
    print(f"  Address:    {r['addr']}")
    print(f"  Comment:    {r.get('comment', '')}")
    print(f"  Repeatable: {r.get('repeatable_comment', '')}")
    print(f"  Function:   {r.get('func_comment', '')}")


def cmd_proxy_methods(args, config):
    r = _rpc_call(args, config, "methods")
    if not r: return
    for m in r.get("methods", []):
        print(f"  {m['name']:<20}  {m['description']}")


def cmd_proxy_rename(args, config):
    r = _rpc_call(args, config, "set_name", {"addr": args.addr, "name": args.name})
    if r:
        _log_ok(f"Renamed {r['addr']} -> {r['name']}")


def cmd_proxy_set_type(args, config):
    r = _rpc_call(args, config, "set_type", {"addr": args.addr, "type": args.type_str})
    if r:
        _log_ok(f"Type set at {r['addr']}: {r.get('type', '')}")


def cmd_proxy_comment(args, config):
    p = {"addr": args.addr, "comment": args.text}
    if _opt(args, 'repeatable', False): p["repeatable"] = True
    if _opt(args, 'type'): p["type"] = args.type
    r = _rpc_call(args, config, "set_comment", p)
    if r:
        _log_ok(f"Comment set at {r['addr']}")


def cmd_proxy_save(args, config):
    r = _rpc_call(args, config, "save_db")
    if r:
        _log_ok(f"Database saved: {r.get('idb_path')}")


def cmd_proxy_exec(args, config):
    p = {"code": args.code}
    _maybe_output_param(args, p)
    r = _rpc_call(args, config, "exec", p)
    if not r: return
    if r.get("stdout"):
        print(r["stdout"], end="")
    if r.get("stderr"):
        print(f"[stderr] {r['stderr']}", end="")


def cmd_proxy_summary(args, config):
    r = _rpc_call(args, config, "summary")
    if not r: return
    print(f"  Binary:      {r['binary']}")
    print(f"  Decompiler:  {r['decompiler']}")
    print(f"  IDA:         {r['ida_version']}")
    print(f"  Functions:   {r['func_count']}  (avg size: {r['avg_func_size']} bytes)")
    print(f"  Strings:     {r['total_strings']}")
    print(f"  Imports:     {r['total_imports']}")
    print(f"  Exports:     {r['export_count']}")
    print()
    print("  Segments:")
    for s in r.get("segments", []):
        print(f"    {s['start']}-{s['end']}  {s.get('name', ''):<12}  "
              f"size={s['size']:<8}  {s['perm']}")
    if r.get("top_import_modules"):
        print()
        print("  Top Import Modules:")
        for m in r["top_import_modules"]:
            print(f"    {m['module']:<30}  {m['count']} imports")
    if r.get("largest_functions"):
        print()
        print("  Largest Functions:")
        for f in r["largest_functions"]:
            print(f"    {f['addr']}  {f['name']:<40}  {f['size']} bytes")
    if r.get("strings_sample"):
        print()
        print(f"  Strings (first {len(r['strings_sample'])}):")
        for s in r["strings_sample"]:
            print(f"    {s['addr']}  {_truncate(s['value'], 60)}")


def _resolve_by_hint(hint, registry):
    """Resolve instance by ID or binary name hint. Shared by diff/code-diff."""
    if hint in registry:
        return hint, registry[hint]
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


def _get_func_map(config, iid, info, count=10000):
    """Get {name: func_dict} from an instance. Shared by diff/compare/code-diff."""
    port = info.get("port")
    if not port:
        _log_err(f"Instance {iid} has no port")
        return None
    resp = post_rpc(config, port, "get_functions", iid, {"count": count})
    if "error" in resp:
        _log_err(f"{iid}: {resp['error'].get('message')}")
        return None
    return {f["name"]: f for f in resp.get("result", {}).get("data", [])}


def cmd_diff(args, config):
    """Compare functions between two instances."""
    registry = load_registry()

    iid_a, info_a = _resolve_by_hint(args.instance_a, registry)
    if not iid_a: return
    iid_b, info_b = _resolve_by_hint(args.instance_b, registry)
    if not iid_b: return

    funcs_a = _get_func_map(config, iid_a, info_a)
    funcs_b = _get_func_map(config, iid_b, info_b)
    if funcs_a is None or funcs_b is None:
        return

    names_a = set(funcs_a.keys())
    names_b = set(funcs_b.keys())
    only_a = names_a - names_b
    only_b = names_b - names_a
    common = names_a & names_b
    size_diff = []
    for name in common:
        sa = funcs_a[name].get("size", 0)
        sb = funcs_b[name].get("size", 0)
        if sa != sb:
            size_diff.append((name, funcs_a[name]["addr"], sa, funcs_b[name]["addr"], sb))

    bin_a = info_a.get("binary", "?")
    bin_b = info_b.get("binary", "?")
    print(f"  Comparing: {bin_a} ({iid_a}) vs {bin_b} ({iid_b})")
    print(f"  Functions: {len(names_a)} vs {len(names_b)}")
    print(f"  Common: {len(common)}, Only in A: {len(only_a)}, Only in B: {len(only_b)}, Size changed: {len(size_diff)}")

    if only_a:
        print(f"\n  Only in {bin_a}:")
        _print_truncated(sorted(only_a), lambda n: f"{funcs_a[n]['addr']}  {n}")

    if only_b:
        print(f"\n  Only in {bin_b}:")
        _print_truncated(sorted(only_b), lambda n: f"{funcs_b[n]['addr']}  {n}")

    if size_diff:
        size_diff.sort(key=lambda x: abs(x[4] - x[2]), reverse=True)
        print(f"\n  Size changed ({len(size_diff)}):")
        def _fmt_sd(t):
            name, addr_a, sa, _, sb = t
            delta = sb - sa
            sign = "+" if delta > 0 else ""
            return f"{addr_a}  {name:<40}  {sa} -> {sb} ({sign}{delta})"
        _print_truncated(size_diff, _fmt_sd)


def _find_binaries(target_dir):
    """Find binary files in a directory by extension or magic bytes."""
    binaries = []
    for f in sorted(os.listdir(target_dir)):
        fpath = os.path.join(target_dir, f)
        if not os.path.isfile(fpath):
            continue
        ext = os.path.splitext(f)[1].lower()
        if ext in SUPPORTED_BINARY_EXTENSIONS:
            binaries.append(fpath)
            continue
        if not ext:
            try:
                with open(fpath, "rb") as fp:
                    magic = fp.read(4)
                if magic in (b"\x7fELF", b"MZ") or magic[:2] == b"MZ":
                    binaries.append(fpath)
            except Exception:
                pass
    return binaries


def _start_batch_instances(batch, config, config_path, idb_dir, fresh):
    """Start analysis instances for a batch of binaries. Returns [(iid, bname)]."""
    started = []
    for bpath in batch:
        bname = os.path.basename(bpath)
        norm_path = os.path.normcase(os.path.abspath(bpath))
        arch_info = arch_detect(bpath)
        instance_id = make_instance_id(bpath)
        idb_path = get_idb_path(config, norm_path, instance_id, False, idb_dir=idb_dir)
        log_path = os.path.join(config["paths"]["log_dir"], f"{instance_id}.log")

        if not _register_instance(config, instance_id, norm_path,
                                   arch_info, idb_path, log_path, False):
            _log_err(f"{bname}: failed to register")
            continue
        try:
            _spawn_server(config, config_path, norm_path, instance_id, idb_path, log_path, fresh)
            _log_ok(f"{bname} ({_format_arch_info(arch_info)}) -> {instance_id}")
            started.append((instance_id, bname))
        except Exception as e:
            _log_err(f"{bname}: {e}")
    return started


def _wait_batch_instances(started, config, timeout):
    """Wait for batch instances to reach ready/error state."""
    deadline = time.time() + timeout
    poll = config["analysis"]["wait_poll_interval"]
    pending = set(iid for iid, _ in started)
    while pending and time.time() < deadline:
        time.sleep(poll)
        registry = load_registry()
        for iid in list(pending):
            state = registry.get(iid, {}).get("state", "unknown")
            if state in ("ready", "error"):
                pending.discard(iid)


def _collect_batch_results(started, config):
    """Collect summary results from batch instances."""
    results = []
    registry = load_registry()
    for iid, bname in started:
        info = registry.get(iid, {})
        state = info.get("state", "unknown")
        port = info.get("port")
        if state == "ready" and port:
            resp = post_rpc(config, port, "summary", iid)
            if "result" in resp:
                r = resp["result"]
                results.append((bname, iid, r))
                print(f"  {bname:<30}  funcs={r['func_count']:<6}  "
                      f"strings={r['total_strings']:<6}  "
                      f"imports={r['total_imports']:<6}  "
                      f"decompiler={'Y' if r['decompiler'] else 'N'}")
            else:
                print(f"  {bname:<30}  [ready but summary failed]")
        else:
            print(f"  {bname:<30}  [{state}]")
    return results


def cmd_batch(args, config, config_path):
    """Analyze all binaries in a directory."""
    target_dir = os.path.abspath(args.directory)
    if not os.path.isdir(target_dir):
        _log_err(f"Not a directory: {target_dir}")
        return

    binaries = _find_binaries(target_dir)
    if not binaries:
        _log_err(f"No binaries found in: {target_dir}")
        return

    idb_dir = _opt(args, 'idb_dir') or os.environ.get('IDA_IDB_DIR')
    fresh = _opt(args, 'fresh', False)
    timeout = _opt(args, 'timeout', 300)
    max_concurrent = config["analysis"]["max_instances"]

    _log_info(f"Found {len(binaries)} binaries in {target_dir}")
    _log_info(f"Max concurrent: {max_concurrent}, Timeout: {timeout}s")
    if idb_dir:
        _log_info(f"IDB dir: {idb_dir}")
    print()

    results = []
    for batch_start in range(0, len(binaries), max_concurrent):
        batch = binaries[batch_start:batch_start + max_concurrent]
        started = _start_batch_instances(batch, config, config_path, idb_dir, fresh)
        if not started:
            continue
        _log_info(f"Waiting for {len(started)} instances...")
        _wait_batch_instances(started, config, timeout)
        results.extend(_collect_batch_results(started, config))

    _log_ok(f"Batch complete: {len(results)}/{len(binaries)} analyzed")
    if results:
        print(f"\n  Active instances:")
        for bname, iid, _ in results:
            print(f"    {iid}  {bname}")
        print(f"\n  Use 'ida-cli -b <hint> decompile <addr>' to analyze further")
        if not _opt(args, 'keep', False):
            print(f"  Use 'ida-cli stop <id>' to stop, or 'ida-cli cleanup' to clean all")


# ─────────────────────────────────────────────
# Bookmark System
# ─────────────────────────────────────────────

_BOOKMARK_FILE = ".ida-bookmarks.json"


def _get_bookmark_path():
    return os.path.join(os.getcwd(), _BOOKMARK_FILE)


def _load_bookmarks():
    path = _get_bookmark_path()
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_bookmarks(bookmarks):
    path = _get_bookmark_path()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bookmarks, f, ensure_ascii=False, indent=2)


def cmd_bookmark(args, config):
    action = _opt(args, 'action', 'list')
    bookmarks = _load_bookmarks()

    if action == "add":
        addr = args.addr
        tag = args.tag
        note = _opt(args, 'note') or ""
        binary_hint = _opt(args, 'binary_hint') or ""

        # Try to resolve binary name from active instance
        binary = binary_hint
        if binary_hint:
            registry = load_registry()
            for iid, info in registry.items():
                if binary_hint.lower() in info.get("binary", "").lower():
                    binary = info.get("binary", binary_hint)
                    break

        if binary not in bookmarks:
            bookmarks[binary] = []

        # Check for duplicate
        for bm in bookmarks[binary]:
            if bm["addr"] == addr and bm["tag"] == tag:
                _log_warn(f"Bookmark already exists: {addr} [{tag}]")
                return

        bookmarks[binary].append({
            "addr": addr,
            "tag": tag,
            "note": note,
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        _save_bookmarks(bookmarks)
        _log_ok(f"Bookmark added: {addr} [{tag}] {note}")

    elif action == "remove":
        addr = args.addr
        binary_hint = _opt(args, 'binary_hint') or ""
        removed = False
        for binary in list(bookmarks.keys()):
            if binary_hint and binary_hint.lower() not in binary.lower():
                continue
            before = len(bookmarks[binary])
            bookmarks[binary] = [bm for bm in bookmarks[binary] if bm["addr"] != addr]
            if len(bookmarks[binary]) < before:
                removed = True
            if not bookmarks[binary]:
                del bookmarks[binary]
        if removed:
            _save_bookmarks(bookmarks)
            _log_ok(f"Bookmark removed: {addr}")
        else:
            _log_err(f"No bookmark found at {addr}")

    else:  # list
        tag_filter = _opt(args, 'tag')
        binary_filter = _opt(args, 'binary_hint')
        if not bookmarks:
            print("[*] No bookmarks. Use: ida-cli bookmark add <addr> <tag> [--note 'text']")
            return
        total = 0
        for binary, bms in sorted(bookmarks.items()):
            if binary_filter and binary_filter.lower() not in binary.lower():
                continue
            filtered = bms
            if tag_filter:
                filtered = [bm for bm in bms if tag_filter.lower() in bm["tag"].lower()]
            if not filtered:
                continue
            print(f"  {binary}:")
            for bm in filtered:
                note = f"  {bm['note']}" if bm.get('note') else ""
                print(f"    {bm['addr']}  [{bm['tag']}]{note}")
                total += 1
        print(f"\n  Total: {total} bookmarks")


# ─────────────────────────────────────────────
# Config Profiles
# ─────────────────────────────────────────────

_PROFILES = {
    "malware": {
        "description": "Malware analysis -focus on C2, crypto, anti-analysis",
        "analysis_steps": [
            "summary",
            "strings --filter http --count 30",
            "strings --filter socket --count 20",
            "strings --filter crypt --count 20",
            "imports --filter socket --count 30",
            "imports --filter crypt --count 30",
            "imports --filter process --count 30",
            "imports --filter registry --count 20",
            "find_func --regex 'crypt|encode|decode|xor|rc4|aes' --max 30",
            "find_func --regex 'connect|send|recv|http|url' --max 30",
            "find_func --regex 'inject|hook|patch|virtual' --max 20",
        ],
    },
    "firmware": {
        "description": "Firmware/IoT -focus on peripherals, protocols, boot",
        "analysis_steps": [
            "summary",
            "segments",
            "strings --filter uart --count 20",
            "strings --filter spi --count 20",
            "strings --filter gpio --count 20",
            "strings --filter error --count 30",
            "imports --count 50",
            "exports --count 50",
            "find_func --regex 'uart|spi|i2c|gpio|dma' --max 30",
            "find_func --regex 'init|setup|config|reset' --max 30",
            "find_func --regex 'read|write|send|recv' --max 30",
        ],
    },
    "vuln": {
        "description": "Vulnerability research -focus on dangerous functions, buffers",
        "analysis_steps": [
            "summary",
            "imports --filter memcpy --count 20",
            "imports --filter strcpy --count 20",
            "imports --filter sprintf --count 20",
            "imports --filter gets --count 10",
            "imports --filter system --count 10",
            "imports --filter exec --count 10",
            "imports --filter alloc --count 20",
            "find_func --regex 'parse|decode|deserialize|unpack' --max 30",
            "find_func --regex 'auth|login|verify|check_pass' --max 20",
            "find_func --regex 'handle|dispatch|process|callback' --max 30",
        ],
    },
}


_PROFILE_RPC_MAP = {
    "summary": "summary",
    "segments": "get_segments",
    "strings": "get_strings",
    "imports": "get_imports",
    "exports": "get_exports",
    "find_func": "find_func",
    "functions": "get_functions",
}


def _parse_profile_step(step, method):
    """Parse a profile step string into RPC params dict."""
    parts = step.split()
    params = {}
    i = 1
    while i < len(parts):
        if parts[i] == "--filter" and i + 1 < len(parts):
            params["filter"] = parts[i + 1]; i += 2
        elif parts[i] == "--count" and i + 1 < len(parts):
            params["count"] = int(parts[i + 1]); i += 2
        elif parts[i] == "--max" and i + 1 < len(parts):
            params["max_results"] = int(parts[i + 1]); i += 2
        elif parts[i] == "--regex":
            params["regex"] = True; i += 1
            if i < len(parts) and not parts[i].startswith("--"):
                params["name"] = parts[i].strip("'\""); i += 1
        else:
            if method == "find_func" and "name" not in params:
                params["name"] = parts[i].strip("'\"")
            i += 1
    return params


def _display_profile_result(method, r):
    """Display a profile step result."""
    if method == "summary":
        print(f"    Functions: {r.get('func_count')}  "
              f"Strings: {r.get('total_strings')}  "
              f"Imports: {r.get('total_imports')}  "
              f"Decompiler: {r.get('decompiler')}")
    elif method in ("strings", "imports", "exports", "functions"):
        data = r.get("data", [])
        total = r.get("total", 0)
        print(f"    Total: {total}, Showing: {len(data)}")
        for d in data[:10]:
            if "value" in d:
                print(f"      {d['addr']}  {_truncate(d['value'], 60)}")
            elif "module" in d:
                print(f"      {d['addr']}  {d.get('module', ''):<20}  {d['name']}")
            elif "name" in d:
                print(f"      {d['addr']}  {d['name']}")
        if len(data) > 10:
            print(f"      ... ({len(data) - 10} more)")
    elif method == "find_func":
        matches = r.get("matches", [])
        print(f"    Found: {r.get('total', 0)}")
        for m in matches[:10]:
            print(f"      {m['addr']}  {m['name']}")
        if len(matches) > 10:
            print(f"      ... ({len(matches) - 10} more)")
    elif method == "segments":
        for s in r.get("data", []):
            print(f"      {s['start_addr']}-{s['end_addr']}  "
                  f"{s.get('name') or '':<12}  {s.get('perm') or ''}")


def cmd_profile(args, config):
    action = _opt(args, 'action', 'list')

    if action == "list":
        print("  Available profiles:")
        for name, prof in _PROFILES.items():
            print(f"    {name:<12}  {prof['description']}")
        return

    if action == "run":
        profile_name = args.profile_name
        if profile_name not in _PROFILES:
            _log_err(f"Unknown profile: {profile_name}")
            print(f"    Available: {', '.join(_PROFILES.keys())}")
            return

        profile = _PROFILES[profile_name]
        _log_info(f"Running profile: {profile_name} - {profile['description']}")
        print()

        iid, info, port = _resolve_ready(args, config)
        if not iid:
            return

        out_dir = _opt(args, 'out_dir')
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        for step in profile["analysis_steps"]:
            method = step.split()[0]
            print(f"  --- {step} ---")
            params = _parse_profile_step(step, method)
            if out_dir:
                params["output"] = os.path.join(out_dir, f"{method}_{params.get('filter', 'all')}.txt")
            rpc_method = _PROFILE_RPC_MAP.get(method, method)
            resp = post_rpc(config, port, rpc_method, iid, params=params)
            if "error" in resp:
                _log_err(f"  {resp['error'].get('message', '?')}")
                continue
            _display_profile_result(method, resp.get("result", {}))
            print()

        _log_ok(f"Profile '{profile_name}' complete")
        if out_dir:
            print(f"    Results saved to: {out_dir}")


_REPORT_DATA_TABLES = [
    ("Imports", "get_imports", 100,
     ("Address", "Module", "Name"),
     lambda d: f"| `{d['addr']}` | {d.get('module', '')} | {d['name']} |"),
    ("Exports", "get_exports", 100,
     ("Address", "Name"),
     lambda d: f"| `{d['addr']}` | {d['name']} |"),
    ("Strings", "get_strings", 50,
     ("Address", "Value"),
     lambda d: f"| `{d['addr']}` | {d.get('value', '').replace('|', chr(92)+'|')} |"),
]


def _collect_report_data(config, port, iid, sections):
    """Collect imports/exports/strings into report sections."""
    for label, method, count, headers, fmt_row in _REPORT_DATA_TABLES:
        _log_info(f"Collecting {label.lower()}...")
        resp = post_rpc(config, port, method, iid, {"count": count})
        if "result" not in resp:
            continue
        data = resp["result"].get("data", [])
        total = resp["result"].get("total", 0)
        if not data:
            continue
        sections += [f"## {label} ({total} total, showing {len(data)})"] + \
                     _md_table_header(*headers)
        for d in data:
            sections.append(fmt_row(d))
        sections.append("")


def _collect_report_functions(config, port, iid, func_addrs, sections):
    """Decompile specific functions into report sections."""
    if not func_addrs:
        return
    sections += ["## Decompiled Functions", ""]
    for addr in func_addrs:
        _log_info(f"Decompiling {addr}...")
        resp = post_rpc(config, port, "decompile_with_xrefs", iid, {"addr": addr})
        if "result" in resp:
            sections.append(_md_decompile(resp["result"], with_xrefs=True))
        else:
            err = resp.get("error", {}).get("message", "unknown error")
            sections += [f"### `{addr}` - Error", f"> {err}"]
        sections.append("")


def _collect_report_bookmarks(binary_name, sections):
    """Add bookmarks to report sections."""
    bookmarks = _load_bookmarks()
    if not bookmarks:
        return
    bm_for_binary = {bn: bms for bn, bms in bookmarks.items()
                     if os.path.basename(binary_name).lower() in bn.lower()}
    if bm_for_binary:
        sections += ["## Bookmarks"] + _md_table_header("Address", "Tag", "Note")
        for bms in bm_for_binary.values():
            for bm in bms:
                note = bm.get("note", "").replace("|", "\\|")
                sections.append(f"| `{bm['addr']}` | {bm['tag']} | {note} |")
        sections.append("")


def _collect_report_sections(config, port, iid, binary_name, func_addrs):
    """Collect all report sections from the running instance."""
    import datetime
    sections = []

    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    sections.append(f"# Analysis Report: {os.path.basename(binary_name)}")
    sections.append(f"**Generated**: {ts}  ")
    sections.append(f"**Binary**: `{binary_name}`")
    sections.append("")

    _log_info("Collecting summary...")
    resp = post_rpc(config, port, "summary", iid)
    if "result" in resp:
        sections.append(_md_summary(resp["result"]))

    _collect_report_data(config, port, iid, sections)
    _collect_report_functions(config, port, iid, func_addrs, sections)
    _collect_report_bookmarks(binary_name, sections)

    sections += ["---", "*Generated by ida-cli report*"]
    return "\n".join(sections) + "\n"


_HTML_REPORT_STYLES = """\
body { font-family: -apple-system, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid #ddd; padding: 6px 10px; text-align: left; }
th { background: #f5f5f5; }
pre, code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }
pre { padding: 12px; overflow-x: auto; }"""


def _render_html(content, binary_name):
    """Convert markdown content to HTML report."""
    try:
        import markdown
        html_body = markdown.markdown(content, extensions=["tables"])
    except ImportError:
        html_body = f"<pre>{content}</pre>"
    title = os.path.basename(binary_name)
    return (f'<!DOCTYPE html>\n<html><head><meta charset="utf-8">'
            f'<title>Report: {title}</title>\n'
            f'<style>\n{_HTML_REPORT_STYLES}\n</style></head><body>\n'
            f'{html_body}\n</body></html>')


def cmd_report(args, config):
    """Generate markdown/HTML analysis report."""
    iid, info, port = _resolve_ready(args, config)
    if not iid:
        return
    out_path = args.output
    binary_name = info.get("binary", "unknown")
    func_addrs = _opt(args, 'functions') or []

    content = _collect_report_sections(config, port, iid, binary_name, func_addrs)

    if out_path.lower().endswith('.html'):
        _save_local(out_path, _render_html(content, binary_name))
    else:
        _save_local(out_path, content)
    _log_ok(f"Report generated: {out_path}")


# ─────────────────────────────────────────────
# Shell (Interactive REPL)
# ─────────────────────────────────────────────

def cmd_shell(args, config):
    """Interactive IDA Python REPL."""
    iid, info, port = _resolve_ready(args, config)
    if not iid:
        return
    binary = os.path.basename(info.get("binary", "?"))
    _log_info(f"IDA Python Shell - {binary} ({iid})")
    _log_info("Type 'exit' or Ctrl+C to quit")
    print()
    while True:
        try:
            code = input(f"ida({binary})>>> ")
        except (EOFError, KeyboardInterrupt):
            _log_info("Shell closed")
            break
        if not code.strip():
            continue
        if code.strip() in ("exit", "quit"):
            _log_info("Shell closed")
            break
        # Multi-line: if line ends with ':', collect until blank line
        if code.rstrip().endswith(":"):
            lines = [code]
            while True:
                try:
                    line = input("... ")
                except (EOFError, KeyboardInterrupt):
                    break
                if not line.strip():
                    break
                lines.append(line)
            code = "\n".join(lines)
        resp = post_rpc(config, port, "exec", iid, {"code": code})
        if "error" in resp:
            _log_err(resp['error'].get('message', '?'))
        else:
            r = resp.get("result", {})
            if r.get("stdout"):
                print(r["stdout"], end="")
            if r.get("stderr"):
                print(f"[stderr] {r['stderr']}", end="")


# ─────────────────────────────────────────────
# Export/Import Annotations
# ─────────────────────────────────────────────

def cmd_annotations(args, config):
    """Export or import analysis annotations."""
    action = _opt(args, 'action', 'export')

    if action == "export":
        out_path = _opt(args, 'output') or "annotations.json"
        p = {}
        r = _rpc_call(args, config, "export_annotations", p)
        if not r:
            return
        names_count = len(r.get("names", []))
        comments_count = len(r.get("comments", []))
        types_count = len(r.get("types", []))
        # Save locally
        _save_local(out_path, json.dumps(r, ensure_ascii=False, indent=2))
        print(f"  Names: {names_count}, Comments: {comments_count}, Types: {types_count}")

    elif action == "import":
        in_path = args.input_file
        if not os.path.isfile(in_path):
            _log_err(f"File not found: {in_path}")
            return
        with open(in_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        r = _rpc_call(args, config, "import_annotations", {"data": data})
        if not r:
            return
        print(f"  Applied - Names: {r.get('names', 0)}, Comments: {r.get('comments', 0)}, Types: {r.get('types', 0)}")
        if r.get("errors"):
            print(f"  Errors: {r['errors']}")


# ─────────────────────────────────────────────
# Call Graph
# ─────────────────────────────────────────────

def cmd_callgraph(args, config):
    """Generate function call graph."""
    fmt = _opt(args, 'format', 'mermaid') or 'mermaid'
    depth = _opt(args, 'depth', 3)
    direction = _opt(args, 'direction', 'callees')
    p = {"addr": args.addr, "depth": depth, "direction": direction}
    r = _rpc_call(args, config, "callgraph", p)
    if not r:
        return
    out_path = _opt(args, 'out')
    print(f"  Root: {r.get('root_name', '')} ({r.get('root', '')})")
    print(f"  Nodes: {r.get('nodes', 0)}, Edges: {r.get('edges', 0)}")
    if fmt == "dot":
        content = r.get("dot", "")
    else:
        content = r.get("mermaid", "")
    if out_path:
        _save_local(out_path, content)
    else:
        print()
        print(content)


# ─────────────────────────────────────────────
# Patch
# ─────────────────────────────────────────────

def cmd_patch(args, config):
    """Patch bytes at an address."""
    hex_bytes = " ".join(args.hex_bytes)
    p = {"addr": args.addr, "bytes": hex_bytes}
    r = _rpc_call(args, config, "patch_bytes", p)
    if not r:
        return
    print(f"  Address:  {r.get('addr', '')}")
    print(f"  Original: {r.get('original', '')}")
    print(f"  Patched:  {r.get('patched', '')}")
    print(f"  Size:     {r.get('size', 0)} bytes")


# ─────────────────────────────────────────────
# Search Constant
# ─────────────────────────────────────────────

def cmd_search_const(args, config):
    """Search for immediate/constant values."""
    p = {"value": args.value}
    if _opt(args, 'max'):
        p["max_results"] = args.max
    r = _rpc_call(args, config, "search_const", p)
    if not r:
        return
    print(f"  Value: {r.get('value', '')}  Found: {r.get('total', 0)}")
    for entry in r.get("results", []):
        func = entry.get("func", "")
        func_str = f"  [{func}]" if func else ""
        print(f"    {entry['addr']}  {entry.get('disasm', '')}{func_str}")


# ─────────────────────────────────────────────
# Structs
# ─────────────────────────────────────────────

def cmd_structs(args, config):
    """Manage structs and unions."""
    action = _opt(args, 'action', 'list')

    if action == "list":
        p = _build_params(args, {"filter": "filter"})
        r = _rpc_call(args, config, "list_structs", p)
        if not r:
            return
        print(f"  Total: {r.get('total', 0)}")
        for s in r.get("structs", []):
            kind = "union" if s.get("is_union") else "struct"
            print(f"    {s['name']:<30}  {kind:<6}  size={s['size']:<6}  members={s['member_count']}")

    elif action == "show":
        r = _rpc_call(args, config, "get_struct", {"name": args.name})
        if not r:
            return
        kind = "union" if r.get("is_union") else "struct"
        print(f"  {kind} {r['name']} (size={r['size']})")
        print(f"  {'Offset':<8}  {'Name':<24}  {'Size':<6}  Type")
        print(f"  {'-'*8}  {'-'*24}  {'-'*6}  {'-'*20}")
        for m in r.get("members", []):
            print(f"  {m['offset']:<8}  {m['name']:<24}  {m['size']:<6}  {m.get('type', '')}")

    elif action == "create":
        p = {"name": args.name}
        if _opt(args, 'union', False):
            p["is_union"] = True
        members = []
        for mdef in (_opt(args, 'members') or []):
            parts = mdef.split(":")
            mname = parts[0]
            msize = int(parts[1]) if len(parts) > 1 else 1
            members.append({"name": mname, "size": msize})
        if members:
            p["members"] = members
        r = _rpc_call(args, config, "create_struct", p)
        if not r:
            return
        print(f"  [+] Struct created: {args.name} (members: {r.get('members_added', 0)})")


# ─────────────────────────────────────────────
# Snapshot
# ─────────────────────────────────────────────

def cmd_snapshot(args, config):
    """Manage IDB snapshots."""
    action = _opt(args, 'action', 'list')

    if action == "save":
        desc = _opt(args, 'description', 'Snapshot') or 'Snapshot'
        r = _rpc_call(args, config, "snapshot_save", {"description": desc})
        if not r:
            return
        method = f" ({r.get('method', 'ida_api')})" if r.get("method") else ""
        print(f"  [+] Snapshot saved: {r.get('filename', '')}{method}")

    elif action == "list":
        r = _rpc_call(args, config, "snapshot_list")
        if not r:
            return
        snapshots = r.get("snapshots", [])
        if not snapshots:
            print("  No snapshots found")
            return
        print(f"  Snapshots ({r.get('total', 0)}):")
        for s in snapshots:
            size_mb = s.get("size", 0) / (1024 * 1024)
            print(f"    {s['created']}  {size_mb:.1f}MB  {s['name']}")

    elif action == "restore":
        filename = args.filename
        r = _rpc_call(args, config, "snapshot_restore", {"filename": filename})
        if not r:
            return
        print(f"  [+] Restored from: {r.get('restored_from', '')}")
        print(f"      Current backed up to: {r.get('backup_of_current', '')}")
        if r.get("note"):
            print(f"      Note: {r['note']}")


# ─────────────────────────────────────────────
# Compare (patch diffing)
# ─────────────────────────────────────────────

def _compare_func_maps(funcs_a, funcs_b):
    """Compare two function maps. Returns (added, removed, modified, identical)."""
    names_a = set(funcs_a.keys())
    names_b = set(funcs_b.keys())
    added = names_b - names_a
    removed = names_a - names_b
    common = names_a & names_b
    modified = []
    identical = 0
    for name in common:
        sa = funcs_a[name].get("size", 0)
        sb = funcs_b[name].get("size", 0)
        if sa != sb:
            modified.append((name, funcs_a[name]["addr"], sa, funcs_b[name]["addr"], sb))
        else:
            identical += 1
    modified.sort(key=lambda x: abs(x[4] - x[2]), reverse=True)
    return added, removed, modified, identical


def _display_diff_results(name_a, name_b, funcs_a, funcs_b,
                          added, removed, modified, identical, limit=50):
    """Display patch diff results."""
    print(f"\n  === Patch Diff: {name_a} vs {name_b} ===")
    print(f"  Functions: {len(funcs_a)} vs {len(funcs_b)}")
    print(f"  Identical: {identical}")
    print(f"  Modified:  {len(modified)}")
    print(f"  Added:     {len(added)}")
    print(f"  Removed:   {len(removed)}")

    if modified:
        print(f"\n  Modified functions ({len(modified)}):")
        for name, addr_a, sa, addr_b, sb in modified[:limit]:
            delta = sb - sa
            sign = "+" if delta > 0 else ""
            print(f"    {name:<50}  {sa} -> {sb} ({sign}{delta})")
        if len(modified) > limit:
            print(f"    ... and {len(modified) - limit} more")

    for label, names, funcs in [("Added", added, funcs_b), ("Removed", removed, funcs_a)]:
        if names:
            print(f"\n  {label} functions ({len(names)}):")
            _print_truncated(sorted(names), lambda n: f"{funcs[n]['addr']}  {n}")


def cmd_compare(args, config, config_path):
    """Compare two versions of a binary (patch diffing)."""
    binary_a = os.path.abspath(args.binary_a)
    binary_b = os.path.abspath(args.binary_b)
    for path in (binary_a, binary_b):
        if not os.path.isfile(path):
            _log_err(f"File not found: {path}")
            return

    idb_dir = _opt(args, 'idb_dir') or os.environ.get("IDA_IDB_DIR") or "."

    _log_info("Starting instances...")
    cfg = _opt(args, 'config')
    for binary in (binary_a, binary_b):
        sa = _make_args(binary=binary, idb_dir=idb_dir, fresh=False, force=True, config=cfg)
        cmd_start(sa, config, config_path)

    registry = load_registry()
    instances = [(iid, info, os.path.abspath(info.get("binary", "")))
                 for iid, info in registry.items()
                 if os.path.abspath(info.get("binary", "")) in (binary_a, binary_b)
                 and info.get("state") in ("analyzing", "ready")]

    if len(instances) < 2:
        _log_err("Could not start both instances")
        return

    _log_info("Waiting for analysis...")
    for iid, info, _ in instances:
        cmd_wait(_make_args(id=iid, timeout=300), config)

    ia, ib = instances[0], instances[1]
    funcs_a = _get_func_map(config, ia[0], ia[1])
    funcs_b = _get_func_map(config, ib[0], ib[1])
    if not funcs_a or not funcs_b:
        _log_err("Could not get function lists")
        return

    added, removed, modified, identical = _compare_func_maps(funcs_a, funcs_b)
    _display_diff_results(os.path.basename(binary_a), os.path.basename(binary_b),
                          funcs_a, funcs_b, added, removed, modified, identical)

    out_path = _opt(args, 'out')
    if out_path:
        report = {
            "binary_a": binary_a, "binary_b": binary_b,
            "functions_a": len(funcs_a), "functions_b": len(funcs_b),
            "identical": identical,
            "modified": [{"name": n, "size_a": sa, "size_b": sb} for n, _, sa, _, sb in modified],
            "added": sorted(added),
            "removed": sorted(removed),
        }
        _save_local(out_path, json.dumps(report, ensure_ascii=False, indent=2))


# ─────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────

def cmd_enums(args, config):
    """Manage enums."""
    action = _opt(args, 'action', 'list')

    if action == "list":
        p = {}
        if _opt(args, 'filter'):
            p["filter"] = args.filter
        r = _rpc_call(args, config, "list_enums", p)
        if not r:
            return
        print(f"  Total: {r.get('total', 0)}")
        for e in r.get("enums", []):
            print(f"    {e['name']:<30}  members={e['member_count']}")

    elif action == "show":
        r = _rpc_call(args, config, "get_enum", {"name": args.name})
        if not r:
            return
        print(f"  enum {r['name']} ({r['total']} members)")
        for m in r.get("members", []):
            print(f"    {m['name']:<30} = {m['value']}")

    elif action == "create":
        p = {"name": args.name}
        members = []
        for mdef in (_opt(args, 'members') or []):
            parts = mdef.split("=")
            mname = parts[0].strip()
            mval = parts[1].strip() if len(parts) > 1 else ""
            members.append({"name": mname, "value": mval})
        if members:
            p["members"] = members
        r = _rpc_call(args, config, "create_enum", p)
        if not r:
            return
        print(f"  [+] Enum created: {args.name} (members: {r.get('members_added', 0)})")


# ─────────────────────────────────────────────
# Pseudocode Search
# ─────────────────────────────────────────────

def cmd_search_code(args, config):
    """Search within decompiled pseudocode."""
    p = {"query": args.query}
    if _opt(args, 'max'):
        p["max_results"] = args.max
    if _opt(args, 'max_funcs'):
        p["max_funcs"] = args.max_funcs
    if _opt(args, 'case_sensitive', False):
        p["case_sensitive"] = True
    r = _rpc_call(args, config, "search_code", p)
    if not r:
        return
    print(f"  Query: \"{r.get('query', '')}\"  Found: {r.get('total', 0)} functions  (scanned: {r.get('functions_scanned', 0)})")
    for entry in r.get("results", []):
        print(f"\n    {entry['addr']}  {entry['name']}")
        for m in entry.get("matches", []):
            print(f"      L{m['line_num']}: {m['text']}")


# ─────────────────────────────────────────────
# Code-level Diff
# ─────────────────────────────────────────────

def _compute_code_diffs(config, func_names, port_a, port_b, iid_a, iid_b, bin_a, bin_b):
    """Decompile and diff each function, return list of diffs."""
    import difflib
    all_diffs = []
    for name in func_names:
        resp_a = post_rpc(config, port_a, "decompile_diff", iid_a, {"addr": name})
        resp_b = post_rpc(config, port_b, "decompile_diff", iid_b, {"addr": name})
        if "error" in resp_a or "error" in resp_b:
            _log_err(f"Cannot decompile: {name}")
            continue
        code_a = resp_a.get("result", {}).get("code", "")
        code_b = resp_b.get("result", {}).get("code", "")
        if code_a == code_b:
            continue
        diff = list(difflib.unified_diff(
            code_a.splitlines(), code_b.splitlines(),
            fromfile=f"{bin_a}:{name}", tofile=f"{bin_b}:{name}", lineterm="",
        ))
        if diff:
            all_diffs.append({"name": name, "diff": diff})
            print(f"\n  === {name} ===")
            for line in diff:
                print(f"  {line}")
    return all_diffs


def cmd_code_diff(args, config):
    """Compare decompiled code of same-named functions between two instances."""

    id_a = args.instance_a
    id_b = args.instance_b
    func_names = _opt(args, 'functions') or []

    registry = load_registry()

    iid_a, info_a = _resolve_by_hint(id_a, registry)
    if not iid_a:
        return
    iid_b, info_b = _resolve_by_hint(id_b, registry)
    if not iid_b:
        return

    port_a = info_a.get("port")
    port_b = info_b.get("port")

    if not func_names:
        # Get common functions, find size-changed ones
        resp_a = post_rpc(config, port_a, "get_functions", iid_a, {"count": 10000})
        resp_b = post_rpc(config, port_b, "get_functions", iid_b, {"count": 10000})
        if "error" in resp_a or "error" in resp_b:
            _log_err("Cannot get function lists")
            return
        funcs_a = {f["name"]: f for f in resp_a.get("result", {}).get("data", [])}
        funcs_b = {f["name"]: f for f in resp_b.get("result", {}).get("data", [])}
        common = set(funcs_a.keys()) & set(funcs_b.keys())
        changed = []
        for name in common:
            if funcs_a[name].get("size", 0) != funcs_b[name].get("size", 0):
                changed.append(name)
        changed.sort()
        func_names = changed[:10]
        print(f"  Auto-selected {len(func_names)} size-changed functions from {len(changed)} total")

    out_path = _opt(args, 'out')
    all_diffs = []
    bin_a = os.path.basename(info_a.get("binary", "?"))
    bin_b = os.path.basename(info_b.get("binary", "?"))

    all_diffs = _compute_code_diffs(
        config, func_names, port_a, port_b, iid_a, iid_b, bin_a, bin_b)

    if not all_diffs:
        print("  No code differences found")

    if out_path and all_diffs:
        content = []
        for d in all_diffs:
            content.append(f"=== {d['name']} ===")
            content.extend(d["diff"])
            content.append("")
        _save_local(out_path, "\n".join(content))


# ─────────────────────────────────────────────
# Auto-rename
# ─────────────────────────────────────────────

def cmd_auto_rename(args, config):
    """Heuristic auto-rename sub_ functions."""
    dry_run = not _opt(args, 'apply', False)
    max_funcs = _opt(args, 'max_funcs', 200) or 200
    p = {"dry_run": dry_run, "max_funcs": max_funcs}
    r = _rpc_call(args, config, "auto_rename", p)
    if not r:
        return
    mode = "DRY RUN" if dry_run else "APPLIED"
    print(f"  [{mode}] {r.get('total', 0)} renames suggested")
    for entry in r.get("renames", [])[:50]:
        print(f"    {entry['addr']}  {entry['old_name']} -> {entry['new_name']}")
    if r.get("total", 0) > 50:
        print(f"    ... and {r['total'] - 50} more")
    if dry_run and r.get("total", 0) > 0:
        print(f"\n  Use --apply to actually rename")


# ─────────────────────────────────────────────
# Export IDAPython Script
# ─────────────────────────────────────────────

def cmd_export_script(args, config):
    """Generate IDAPython script from analysis modifications."""
    out_path = _opt(args, 'output', 'analysis.py') or 'analysis.py'
    p = {"output": out_path}
    r = _rpc_call(args, config, "export_script", p)
    if not r:
        return
    print(f"  Renames:  {r.get('renames', 0)}")
    print(f"  Comments: {r.get('comments', 0)}")
    print(f"  Types:    {r.get('types', 0)}")
    if r.get("saved_to"):
        print(f"  Saved to: {r['saved_to']}")


# ─────────────────────────────────────────────
# VTable Detection
# ─────────────────────────────────────────────

def cmd_vtables(args, config):
    """Detect virtual function tables."""
    p = {}
    if _opt(args, 'max'):
        p["max_results"] = args.max
    if _opt(args, 'min_entries'):
        p["min_entries"] = args.min_entries
    r = _rpc_call(args, config, "detect_vtables", p)
    if not r:
        return
    print(f"  Detected: {r.get('total', 0)} vtables (ptr_size={r.get('ptr_size', 8)})")
    for vt in r.get("vtables", []):
        print(f"\n    {vt['addr']}  ({vt['entries']} entries)")
        for fn in vt.get("functions", [])[:10]:
            print(f"      +{fn['offset']:<4}  {fn['addr']}  {fn['name']}")
        if vt["entries"] > 10:
            print(f"      ... ({vt['entries'] - 10} more)")


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


# ─────────────────────────────────────────────
# FLIRT Signatures
# ─────────────────────────────────────────────

def cmd_sigs(args, config):
    """Manage FLIRT signatures."""
    action = _opt(args, 'action', 'list')

    if action == "list":
        r = _rpc_call(args, config, "list_sigs")
        if not r:
            return
        print(f"  Sig dir: {r.get('sig_dir', '')}")
        print(f"  Total: {r.get('total', 0)}")
        for s in r.get("signatures", []):
            size_kb = s.get("size", 0) / 1024
            print(f"    {s['name']:<40}  {size_kb:.1f}KB")

    elif action == "apply":
        sig_name = args.sig_name
        r = _rpc_call(args, config, "apply_sig", {"name": sig_name})
        if not r:
            return
        print(f"  [+] Applied signature: {sig_name}")


def cmd_update(args):
    """Self-update from git repository."""
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    git_dir = os.path.join(repo_dir, ".git")
    if not os.path.isdir(git_dir):
        _log_err(f"Not a git repository: {repo_dir}")
        return
    _log_info(f"Updating from: {repo_dir}")
    try:
        result = subprocess.run(
            ["git", "-C", repo_dir, "pull", "--ff-only"],
            capture_output=True, text=True, timeout=30,
        )
        print(result.stdout.strip())
        if result.returncode != 0:
            _log_err(result.stderr.strip())
    except FileNotFoundError:
        _log_err("git not found in PATH")
    except subprocess.TimeoutExpired:
        _log_err("git pull timed out")


def cmd_completions(args):
    """Generate shell completion scripts."""
    shell = _opt(args, 'shell', 'bash')
    commands = [
        "start", "stop", "status", "wait", "list", "logs", "cleanup",
        "functions", "strings", "imports", "exports", "segments",
        "decompile", "decompile_batch", "disasm", "xrefs",
        "find_func", "func_info", "imagebase", "bytes", "find_pattern",
        "comments", "methods", "rename", "set_type", "comment",
        "save", "exec", "summary", "diff", "update", "completions",
    ]
    if shell == "bash":
        print("""# ida-cli bash completion
# Add to ~/.bashrc: eval "$(ida-cli completions --shell bash)"
_ida_cli() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local commands="%s"
    local opts="--json --config -i -b --init --check"
    if [ $COMP_CWORD -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$commands $opts" -- "$cur") )
    else
        case "${COMP_WORDS[1]}" in
            start)  COMPREPLY=( $(compgen -f -- "$cur") $(compgen -W "--fresh --force --idb-dir --arch" -- "$cur") ) ;;
            decompile) COMPREPLY=( $(compgen -W "--out --with-xrefs" -- "$cur") ) ;;
            functions|strings|imports|exports) COMPREPLY=( $(compgen -W "--offset --count --filter --out" -- "$cur") ) ;;
            *)  COMPREPLY=( $(compgen -W "$opts" -- "$cur") ) ;;
        esac
    fi
}
complete -F _ida_cli ida-cli""" % " ".join(commands))
    elif shell == "zsh":
        print("""# ida-cli zsh completion
# Add to ~/.zshrc: eval "$(ida-cli completions --shell zsh)"
_ida_cli() {
    local commands=(%s)
    local opts=(--json --config -i -b --init --check)
    if (( CURRENT == 2 )); then
        _describe 'command' commands
        _describe 'option' opts
    else
        case $words[2] in
            start)  _files; _arguments '--fresh' '--force' '--idb-dir' '--arch' ;;
            decompile) _arguments '--out' '--with-xrefs' ;;
            functions|strings|imports|exports) _arguments '--offset' '--count' '--filter' '--out' ;;
        esac
    fi
}
compdef _ida_cli ida-cli""" % " ".join(commands))
    elif shell == "powershell":
        cmds_str = "', '".join(commands)
        print(f"""# ida-cli PowerShell completion
# Add to $PROFILE: . <(ida-cli completions --shell powershell)
Register-ArgumentCompleter -CommandName ida-cli -Native -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)
    $commands = @('{cmds_str}')
    $commands | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }}
}}""")
    else:
        _log_err(f"Unsupported shell: {shell}. Use bash, zsh, or powershell.")


# ─────────────────────────────────────────────
# Dispatch
# ─────────────────────────────────────────────

def _build_dispatch(args, config, config_path):
    """Build the command -> handler mapping."""
    d = {
        "start": lambda: cmd_start(args, config, config_path),
        "stop": lambda: cmd_stop(args, config),
        "status": lambda: cmd_status(args, config),
        "wait": lambda: cmd_wait(args, config),
        "list": lambda: cmd_list(args, config),
        "logs": lambda: cmd_logs(args, config),
        "cleanup": lambda: cmd_cleanup(args, config),
        "segments": lambda: cmd_proxy_segments(args, config),
        "decompile": lambda: cmd_proxy_decompile(args, config),
        "decompile_batch": lambda: cmd_proxy_decompile_batch(args, config),
        "disasm": lambda: cmd_proxy_disasm(args, config),
        "xrefs": lambda: cmd_proxy_xrefs(args, config),
        "find_func": lambda: cmd_proxy_find_func(args, config),
        "func_info": lambda: cmd_proxy_func_info(args, config),
        "imagebase": lambda: cmd_proxy_imagebase(args, config),
        "bytes": lambda: cmd_proxy_bytes(args, config),
        "find_pattern": lambda: cmd_proxy_find_pattern(args, config),
        "comments": lambda: cmd_proxy_comments(args, config),
        "methods": lambda: cmd_proxy_methods(args, config),
        "rename": lambda: cmd_proxy_rename(args, config),
        "set_type": lambda: cmd_proxy_set_type(args, config),
        "comment": lambda: cmd_proxy_comment(args, config),
        "save": lambda: cmd_proxy_save(args, config),
        "exec": lambda: cmd_proxy_exec(args, config),
        "summary": lambda: cmd_proxy_summary(args, config),
        "diff": lambda: cmd_diff(args, config),
        "batch": lambda: cmd_batch(args, config, config_path),
        "bookmark": lambda: cmd_bookmark(args, config),
        "profile": lambda: cmd_profile(args, config),
        "report": lambda: cmd_report(args, config),
        "shell": lambda: cmd_shell(args, config),
        "annotations": lambda: cmd_annotations(args, config),
        "callgraph": lambda: cmd_callgraph(args, config),
        "patch": lambda: cmd_patch(args, config),
        "search-const": lambda: cmd_search_const(args, config),
        "structs": lambda: cmd_structs(args, config),
        "snapshot": lambda: cmd_snapshot(args, config),
        "compare": lambda: cmd_compare(args, config, config_path),
        "enums": lambda: cmd_enums(args, config),
        "search-code": lambda: cmd_search_code(args, config),
        "code-diff": lambda: cmd_code_diff(args, config),
        "auto-rename": lambda: cmd_auto_rename(args, config),
        "export-script": lambda: cmd_export_script(args, config),
        "vtables": lambda: cmd_vtables(args, config),
        "sigs": lambda: cmd_sigs(args, config),
        "update": lambda: cmd_update(args),
        "completions": lambda: cmd_completions(args),
    }
    for cmd_name, (method, header_fn, format_fn) in _LIST_COMMANDS.items():
        d[cmd_name] = (lambda m=method, h=header_fn, f=format_fn:
                       _cmd_proxy_list(args, config, m, h, f))
    return d


# ─────────────────────────────────────────────
# Main (argparse)
# ─────────────────────────────────────────────

def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", dest="json_output", action="store_true", help="JSON output")
    common.add_argument("--config", default=None, help="config.json path")
    common.add_argument("-i", dest="instance", default=None, help="Instance ID")
    common.add_argument("-b", dest="binary_hint", default=None, help="Binary name hint")

    parser = argparse.ArgumentParser(description="IDA Headless CLI", prog="ida_cli.py", parents=[common])
    parser.add_argument("--init", action="store_true", help="Initialize directories")
    parser.add_argument("--check", action="store_true", help="Check environment")

    sub = parser.add_subparsers(dest="command")

    # Instance management
    p = sub.add_parser("start", help="Start instance", parents=[common])
    p.add_argument("binary")
    p.add_argument("--arch", default=None)
    p.add_argument("--fresh", action="store_true")
    p.add_argument("--force", action="store_true")
    p.add_argument("--idb-dir", default=None, help="IDB save directory (overrides config)")

    p = sub.add_parser("stop", help="Stop instance", parents=[common])
    p.add_argument("id")

    p = sub.add_parser("status", help="Instance status", parents=[common])
    p.add_argument("id", nargs="?", default=None)

    p = sub.add_parser("wait", help="Wait for ready", parents=[common])
    p.add_argument("id")
    p.add_argument("--timeout", type=int, default=300)

    sub.add_parser("list", help="List instances", parents=[common])

    p = sub.add_parser("logs", help="View logs", parents=[common])
    p.add_argument("id")
    p.add_argument("--tail", type=int, default=50)
    p.add_argument("--follow", action="store_true")

    p = sub.add_parser("cleanup", help="Cleanup stale data", parents=[common])
    p.add_argument("--dry-run", action="store_true")

    # List queries (data-driven from _LIST_COMMANDS)
    for name in _LIST_COMMANDS:
        p = sub.add_parser(name, parents=[common])
        p.add_argument("--offset", type=int, default=None)
        p.add_argument("--count", type=int, default=None)
        p.add_argument("--filter", default=None)
        p.add_argument("--out", default=None)

    p = sub.add_parser("segments", parents=[common])
    p.add_argument("--out", default=None)

    # Analysis
    p = sub.add_parser("decompile", parents=[common])
    p.add_argument("addr")
    p.add_argument("--out", default=None)
    p.add_argument("--with-xrefs", action="store_true", help="Include caller/callee xrefs")

    p = sub.add_parser("decompile_batch", parents=[common])
    p.add_argument("addrs", nargs="+")
    p.add_argument("--out", default=None)

    p = sub.add_parser("disasm", parents=[common])
    p.add_argument("addr")
    p.add_argument("--count", type=int, default=None)
    p.add_argument("--out", default=None)

    p = sub.add_parser("xrefs", parents=[common])
    p.add_argument("addr")
    p.add_argument("--direction", choices=["to", "from", "both"], default="to")

    p = sub.add_parser("find_func", parents=[common])
    p.add_argument("name")
    p.add_argument("--regex", action="store_true")
    p.add_argument("--max", type=int, default=None)

    p = sub.add_parser("func_info", parents=[common])
    p.add_argument("addr")

    sub.add_parser("imagebase", parents=[common])

    p = sub.add_parser("bytes", parents=[common])
    p.add_argument("addr")
    p.add_argument("size")

    p = sub.add_parser("find_pattern", parents=[common])
    p.add_argument("pattern")
    p.add_argument("--max", type=int, default=None)

    p = sub.add_parser("comments", parents=[common])
    p.add_argument("addr")

    sub.add_parser("methods", parents=[common])

    # Modification
    p = sub.add_parser("rename", parents=[common])
    p.add_argument("addr")
    p.add_argument("name")

    p = sub.add_parser("set_type", parents=[common])
    p.add_argument("addr")
    p.add_argument("type_str", metavar="type", help="C type declaration")

    p = sub.add_parser("comment", parents=[common])
    p.add_argument("addr")
    p.add_argument("text")
    p.add_argument("--repeatable", action="store_true")
    p.add_argument("--type", choices=["line", "func"], default="line")

    sub.add_parser("save", parents=[common])

    p = sub.add_parser("exec", parents=[common])
    p.add_argument("code")
    p.add_argument("--out", default=None)

    sub.add_parser("summary", help="Binary overview", parents=[common])

    p = sub.add_parser("diff", help="Compare two instances", parents=[common])
    p.add_argument("instance_a", help="Instance ID or binary hint")
    p.add_argument("instance_b", help="Instance ID or binary hint")

    p = sub.add_parser("batch", help="Batch analyze directory", parents=[common])
    p.add_argument("directory", help="Directory containing binaries")
    p.add_argument("--idb-dir", default=None, help="IDB save directory")
    p.add_argument("--fresh", action="store_true")
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--keep", action="store_true", help="Keep instances running after batch")

    bm = sub.add_parser("bookmark", help="Manage bookmarks")
    bm_sub = bm.add_subparsers(dest="action")
    bm_add = bm_sub.add_parser("add", help="Add bookmark", parents=[common])
    bm_add.add_argument("addr")
    bm_add.add_argument("tag")
    bm_add.add_argument("--note", default=None)
    bm_rm = bm_sub.add_parser("remove", help="Remove bookmark", parents=[common])
    bm_rm.add_argument("addr")
    bm_list = bm_sub.add_parser("list", help="List bookmarks", parents=[common])
    bm_list.add_argument("--tag", default=None, help="Filter by tag")

    prof = sub.add_parser("profile", help="Run analysis profile", parents=[common])
    prof_sub = prof.add_subparsers(dest="action")
    prof_list = prof_sub.add_parser("list", help="List profiles")
    prof_run = prof_sub.add_parser("run", help="Run a profile")
    prof_run.add_argument("profile_name", choices=["malware", "firmware", "vuln"])
    prof_run.add_argument("--out-dir", default=None, help="Save results to directory")

    p = sub.add_parser("report", help="Generate analysis report", parents=[common])
    p.add_argument("output", help="Output file (.md or .html)")
    p.add_argument("--functions", nargs="*", default=[], help="Function addresses to decompile")

    sub.add_parser("shell", help="Interactive IDA Python REPL", parents=[common])

    ann = sub.add_parser("annotations", help="Export/import annotations", parents=[common])
    ann_sub = ann.add_subparsers(dest="action")
    ann_exp = ann_sub.add_parser("export", help="Export annotations")
    ann_exp.add_argument("--output", default="annotations.json", help="Output JSON file")
    ann_imp = ann_sub.add_parser("import", help="Import annotations")
    ann_imp.add_argument("input_file", help="JSON annotations file")

    p = sub.add_parser("callgraph", help="Function call graph", parents=[common])
    p.add_argument("addr", help="Function address or name")
    p.add_argument("--depth", type=int, default=3, help="Max depth (default 3)")
    p.add_argument("--direction", choices=["callees", "callers", "both"], default="callees")
    p.add_argument("--format", choices=["mermaid", "dot"], default="mermaid")
    p.add_argument("--out", default=None, help="Save to file")

    p = sub.add_parser("patch", help="Patch bytes at address", parents=[common])
    p.add_argument("addr", help="Address to patch")
    p.add_argument("hex_bytes", nargs="+", help="Hex bytes (e.g. 90 90 90)")

    p = sub.add_parser("search-const", help="Search constant/immediate values", parents=[common])
    p.add_argument("value", help="Value to search (hex or decimal)")
    p.add_argument("--max", type=int, default=None, help="Max results")

    stru = sub.add_parser("structs", help="Manage structs", parents=[common])
    stru_sub = stru.add_subparsers(dest="action")
    stru_list = stru_sub.add_parser("list", help="List structs")
    stru_list.add_argument("--filter", default=None, help="Filter by name")
    stru_show = stru_sub.add_parser("show", help="Show struct details")
    stru_show.add_argument("name", help="Struct name")
    stru_create = stru_sub.add_parser("create", help="Create struct")
    stru_create.add_argument("name", help="Struct name")
    stru_create.add_argument("--union", action="store_true", help="Create union instead")
    stru_create.add_argument("--members", nargs="*", help="Members as name:size (e.g. field1:4 field2:8)")

    snap = sub.add_parser("snapshot", help="Manage IDB snapshots", parents=[common])
    snap_sub = snap.add_subparsers(dest="action")
    snap_save = snap_sub.add_parser("save", help="Save snapshot")
    snap_save.add_argument("--description", default=None, help="Snapshot description")
    snap_sub.add_parser("list", help="List snapshots")
    snap_restore = snap_sub.add_parser("restore", help="Restore snapshot")
    snap_restore.add_argument("filename", help="Snapshot file path")

    p = sub.add_parser("compare", help="Patch diff two binaries", parents=[common])
    p.add_argument("binary_a", help="First binary")
    p.add_argument("binary_b", help="Second binary")
    p.add_argument("--idb-dir", default=None)
    p.add_argument("--out", default=None, help="Save diff report as JSON")

    enu = sub.add_parser("enums", help="Manage enums", parents=[common])
    enu_sub = enu.add_subparsers(dest="action")
    enu_list = enu_sub.add_parser("list", help="List enums")
    enu_list.add_argument("--filter", default=None)
    enu_show = enu_sub.add_parser("show", help="Show enum details")
    enu_show.add_argument("name", help="Enum name")
    enu_create = enu_sub.add_parser("create", help="Create enum")
    enu_create.add_argument("name", help="Enum name")
    enu_create.add_argument("--members", nargs="*", help="Members as name=value (e.g. OK=0 ERR=1)")

    p = sub.add_parser("search-code", help="Search in decompiled pseudocode", parents=[common])
    p.add_argument("query", help="Search string")
    p.add_argument("--max", type=int, default=None, help="Max results")
    p.add_argument("--max-funcs", type=int, default=None, help="Max functions to scan")
    p.add_argument("--case-sensitive", action="store_true")

    p = sub.add_parser("code-diff", help="Diff decompiled code between instances", parents=[common])
    p.add_argument("instance_a", help="Instance ID or binary hint")
    p.add_argument("instance_b", help="Instance ID or binary hint")
    p.add_argument("--functions", nargs="*", default=None, help="Function names to compare")
    p.add_argument("--out", default=None, help="Save diff output")

    p = sub.add_parser("auto-rename", help="Heuristic auto-rename sub_ functions", parents=[common])
    p.add_argument("--apply", action="store_true", help="Actually apply renames (default: dry run)")
    p.add_argument("--max-funcs", type=int, default=200)

    p = sub.add_parser("export-script", help="Generate IDAPython script", parents=[common])
    p.add_argument("--output", default="analysis.py", help="Output .py file")

    p = sub.add_parser("vtables", help="Detect virtual function tables", parents=[common])
    p.add_argument("--max", type=int, default=None)
    p.add_argument("--min-entries", type=int, default=3, help="Minimum entries to qualify as vtable")

    sig = sub.add_parser("sigs", help="FLIRT signatures", parents=[common])
    sig_sub = sig.add_subparsers(dest="action")
    sig_sub.add_parser("list", help="List available signatures")
    sig_apply = sig_sub.add_parser("apply", help="Apply signature")
    sig_apply.add_argument("sig_name", help="Signature name")

    sub.add_parser("update", help="Self-update from git")

    p = sub.add_parser("completions", help="Generate shell completions")
    p.add_argument("--shell", choices=["bash", "zsh", "powershell"], default="bash")

    args = parser.parse_args()

    config, config_path = load_config(args.config)
    config = _merge_project_config(config)
    init_registry_paths(config)

    if args.init:
        cmd_init(config)
        return
    if args.check:
        cmd_check(config)
        return

    cmd = args.command
    if not cmd:
        parser.print_help()
        return

    dispatch = _build_dispatch(args, config, config_path)
    handler = dispatch.get(cmd)
    if handler:
        handler()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

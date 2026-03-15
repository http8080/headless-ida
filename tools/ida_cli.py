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
from common import (
    load_config as _load_config_core,
    init_registry_paths, acquire_lock, release_lock,
    load_registry, save_registry,
    file_md5, remove_auth_token,
)

_DEFAULT_CONFIG = os.path.join(_SCRIPT_DIR, "config.json")

# ─────────────────────────────────────────────
# Constants (CLI-specific)
# ─────────────────────────────────────────────

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
        return {"error": {"code": "MISSING_DEP",
                          "message": "requests package not installed (pip install requests)"}}
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
                return {"error": {"code": "INVALID_RESPONSE",
                         "message": f"HTTP {resp.status_code}: {resp.text[:200]}"}}
        except req_lib.ConnectionError:
            if attempt < RPC_MAX_RETRIES - 1:
                time.sleep(RPC_RETRY_DELAY)
                continue
            return {"error": {"code": "CONNECTION_FAILED",
                     "message": f"Cannot connect to 127.0.0.1:{port}"}}
        except req_lib.Timeout:
            return {"error": {"code": "TIMEOUT",
                     "message": f"Request timeout ({timeout}s)"}}
    return {"error": {"code": "UNKNOWN", "message": "Unexpected error"}}


# ─────────────────────────────────────────────
# Instance Selection
# ─────────────────────────────────────────────

def resolve_instance(args, config):
    registry = load_registry()
    iid = getattr(args, 'instance', None)
    if iid:
        if iid in registry:
            return iid, registry[iid]
        print(f"[-] Instance '{iid}' not found")
        return None, None
    hint = getattr(args, 'binary_hint', None)
    if hint:
        matches = [(k, v) for k, v in registry.items()
                   if hint.lower() in v.get("binary", "").lower()]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            print(f"[-] No instance matching '{hint}'")
        else:
            print(f"[-] Multiple instances match '{hint}':")
            for k, v in matches:
                print(f"  {k}  {v.get('binary', '?')}")
        return None, None
    active = {k: v for k, v in registry.items()
              if v.get("state") in ("ready", "analyzing")}
    if len(active) == 1:
        k = next(iter(active))
        return k, active[k]
    if not active:
        print("[-] No active instances. Use 'start' first.")
    else:
        print("[-] Multiple active instances. Use -i <id> to select:")
        for k, v in active.items():
            print(f"  {k}  {v.get('state', '?'):<12}  {v.get('binary', '?')}")
    return None, None


# ─────────────────────────────────────────────
# RPC Proxy Helper
# ─────────────────────────────────────────────

def _rpc_call(args, config, method, params=None):
    iid, info = resolve_instance(args, config)
    if not iid:
        return None
    if info.get("state") != "ready":
        print(f"[-] Instance {iid} is not ready (state: {info.get('state')})")
        return None
    port = info.get("port")
    if not port:
        print(f"[-] Instance {iid} has no port assigned")
        return None
    resp = post_rpc(config, port, method, iid, params=params)
    if "error" in resp:
        err = resp["error"]
        # Health check: if connection failed, check if process is alive
        if err.get("code") == "CONNECTION_FAILED" and not _is_process_alive(info):
            print(f"[-] Instance {iid} server process is dead (pid={info.get('pid')})")
            binary = info.get("path")
            if binary and os.path.isfile(binary):
                print(f"[*] Cleaning up stale instance...")
                if acquire_lock():
                    try:
                        r = load_registry()
                        r.pop(iid, None)
                        save_registry(r)
                    finally:
                        release_lock()
                remove_auth_token(config["security"]["auth_token_file"], iid)
                print(f"[*] Restart with: ida-cli start {binary}")
            return None
        if getattr(args, 'json_output', False):
            print(json.dumps(resp, ensure_ascii=False, indent=2))
        else:
            print(f"[-] {err.get('code')}: {err.get('message')}")
            if err.get("suggestion"):
                print(f"    Hint: {err['suggestion']}")
        return None
    result = resp.get("result", {})
    if getattr(args, 'json_output', False):
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
        print(f"  [+] {d}")
    print("[+] Init complete")


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
    if not acquire_lock():
        print("[-] Could not acquire registry lock")
        return False
    try:
        registry = load_registry()
        cleanup_stale(registry, config["analysis"]["stale_threshold"])
        if len(registry) >= config["analysis"]["max_instances"]:
            print(f"[-] Max instances reached ({config['analysis']['max_instances']})")
            return False
        for info in registry.values():
            if (os.path.normcase(info.get("path", "")) == binary_path
                    and info.get("state") in ("analyzing", "ready")):
                if not force:
                    print(f"[!] {os.path.basename(binary_path)} already running "
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
    finally:
        release_lock()


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
        print(f"[-] Binary not found: {binary_path}")
        return

    arch_info = arch_detect(binary_path, getattr(args, 'arch', None))
    instance_id = make_instance_id(binary_path)
    force = getattr(args, 'force', False)
    fresh = getattr(args, 'fresh', False)
    idb_dir_override = getattr(args, 'idb_dir', None)
    if not idb_dir_override:
        idb_dir_override = os.environ.get('IDA_IDB_DIR')
    idb_path = get_idb_path(config, binary_path, instance_id, force, idb_dir=idb_dir_override)

    if os.path.exists(idb_path) and not fresh:
        meta = _load_idb_metadata(idb_path)
        stored_md5 = meta.get("binary_md5")
        if stored_md5:
            current_md5 = file_md5(binary_path)
            if stored_md5 != current_md5:
                print("[!] Binary changed since .i64 was created.")
                if not force:
                    print("  Use --fresh to rebuild, or --force to proceed.")
                    return

    log_path = os.path.join(config["paths"]["log_dir"], f"{instance_id}.log")
    if not _register_instance(config, instance_id, binary_path, arch_info,
                               idb_path, log_path, force):
        return

    proc = _spawn_server(config, config_path, binary_path, instance_id, idb_path, log_path, fresh)
    state = _wait_for_start(instance_id)

    fmt = arch_info.get("file_format", "?")
    arch = arch_info.get("arch", "?")
    bits = arch_info.get("bits", "?")
    print(f"[+] Instance started: {instance_id}")
    print(f"    Binary:  {os.path.basename(binary_path)} ({fmt} {arch} {bits}bit)")
    print(f"    IDB:     {idb_path}")
    print(f"    Log:     {log_path}")
    print(f"    State:   {state}")
    print(f"    PID:     {proc.pid}")
    if state == "error":
        print(f"[-] Analysis failed. Check: ida_cli.py logs {instance_id}")
    elif state in ("initializing", "analyzing"):
        print(f"[*] Still {state}. Use: ida_cli.py wait {instance_id}")


def cmd_stop(args, config):
    iid = args.id
    registry = load_registry()
    info = registry.get(iid)
    if not info:
        print(f"[-] Instance '{iid}' not found")
        return
    port = info.get("port")
    pid = info.get("pid")

    if port:
        try:
            post_rpc(config, port, "stop", iid, timeout=STOP_RPC_TIMEOUT)
            for _ in range(STOP_WAIT_ITERATIONS):
                time.sleep(STOP_POLL_INTERVAL)
                if iid not in load_registry():
                    print(f"[+] Instance {iid} stopped normally")
                    return
        except Exception:
            pass  # RPC stop failed, fall through to force kill

    if pid:
        _force_kill(iid, pid, info.get("pid_create_time"))

    if acquire_lock():
        try:
            r = load_registry()
            r.pop(iid, None)
            save_registry(r)
        finally:
            release_lock()
    remove_auth_token(config["security"]["auth_token_file"], iid)


def _force_kill(iid, pid, stored_create_time):
    """Force kill a process by PID."""
    if psutil is None:
        try:
            os.kill(pid, 9)
            print(f"[+] Instance {iid} force killed (pid={pid})")
        except OSError:
            print(f"[+] Instance {iid} process already gone")
        return
    try:
        proc = psutil.Process(pid)
        if (stored_create_time
                and abs(proc.create_time() - stored_create_time) > PID_CREATE_TIME_TOLERANCE):
            print(f"[+] Instance {iid} process already gone (PID reused)")
        else:
            proc.kill()
            print(f"[+] Instance {iid} force killed (pid={pid})")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        print(f"[+] Instance {iid} process already gone")


def cmd_wait(args, config):
    iid = args.id
    timeout = getattr(args, 'timeout', 300)
    poll = config["analysis"]["wait_poll_interval"]
    deadline = time.time() + timeout
    state = "unknown"
    while time.time() < deadline:
        info = load_registry().get(iid)
        if not info:
            print(f"[-] Instance {iid} not found")
            return
        state = info.get("state", "unknown")
        port = info.get("port")
        if state in ("initializing", "analyzing"):
            remaining = int(deadline - time.time())
            print(f"[*] {state}... ({remaining}s remaining)", flush=True)
            time.sleep(poll)
            continue
        if state == "ready" and port:
            resp = post_rpc(config, port, "ping", iid)
            if resp.get("result", {}).get("state") == "ready":
                print("[+] ready")
                return
        if state == "error":
            print(f"[-] Analysis failed. Check: ida_cli.py logs {iid}")
            return
        time.sleep(poll)
    print(f"[-] Timeout ({timeout}s). Current state: {state}")


def cmd_list(args, config):
    if not acquire_lock():
        print("[-] Could not acquire registry lock")
        return
    try:
        registry = load_registry()
        cleanup_stale(registry, config["analysis"]["stale_threshold"])
    finally:
        release_lock()
    if not registry:
        print("[*] No active instances")
        return
    for iid, info in registry.items():
        state = info.get("state", "unknown")
        binary = info.get("binary", "?")
        port = info.get("port", "-")
        print(f"  {iid}  {state:<12}  {binary}  port={port}")


def cmd_status(args, config):
    iid = getattr(args, 'id', None)
    if not iid:
        cmd_list(args, config)
        return
    registry = load_registry()
    info = registry.get(iid)
    if not info:
        print(f"[-] Instance '{iid}' not found")
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
        print(f"[-] Instance '{iid}' not found")
        return
    log_path = info.get("log_path")
    if not log_path or not os.path.exists(log_path):
        print(f"[-] Log file not found: {log_path}")
        return
    if getattr(args, 'follow', False):
        try:
            with open(log_path, encoding='utf-8') as f:
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if line:
                        print(line, end='', flush=True)
                    else:
                        if not os.path.exists(log_path):
                            print("\n[*] Log file removed")
                            return
                        time.sleep(STOP_POLL_INTERVAL)
        except KeyboardInterrupt:
            pass
    else:
        tail = getattr(args, 'tail', 50)
        with open(log_path, encoding='utf-8') as f:
            lines = f.readlines()
        for line in lines[-tail:]:
            print(line, end='')


def cmd_cleanup(args, config):
    dry_run = getattr(args, 'dry_run', False)
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
    if os.path.exists(token_path) and acquire_lock():
        try:
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
        finally:
            release_lock()
    for f in glob.glob(os.path.join(idb_dir, "*")):
        if f.endswith(".meta.json"):
            continue
        in_use = any(info.get("idb_path") == f for info in registry.values())
        if not in_use:
            print(f"  [info] Unused: {os.path.basename(f)}")
    print("[+] Cleanup done")


# ─────────────────────────────────────────────
# Commands: Analysis/Modification Proxies
# ─────────────────────────────────────────────

def _check_inline_limit(text, config):
    """Truncate and return a warning if max_inline_lines is exceeded."""
    limit = config.get("output", {}).get("max_inline_lines", 200)
    lines = text.split("\n")
    if len(lines) <= limit:
        return text, False
    truncated = "\n".join(lines[:limit])
    truncated += f"\n\n[!] Output truncated ({len(lines)} lines, showing {limit}). Use --out to save full result."
    return truncated, True


def _list_params(args):
    p = {}
    if getattr(args, 'offset', None) is not None: p["offset"] = args.offset
    if getattr(args, 'count', None) is not None: p["count"] = args.count
    if getattr(args, 'filter', None): p["filter"] = args.filter
    if getattr(args, 'out', None): p["output"] = args.out
    return p


# ── List-type command factory ──

def _fmt_func(d):
    return f"  {d['addr']}  {d['name']:<50}  size={d.get('size', 0)}"


def _fmt_string(d):
    val = d.get("value", "")
    if len(val) > STRING_DISPLAY_LIMIT:
        val = val[:STRING_DISPLAY_LIMIT - 3] + "..."
    return f"  {d['addr']}  {val}"


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
    p = {}
    if getattr(args, 'out', None): p["output"] = args.out
    r = _rpc_call(args, config, "get_segments", p)
    if not r: return
    for d in r.get("data", []):
        print(f"  {d['start_addr']}-{d['end_addr']}  {d.get('name') or '':<12}  "
              f"{d.get('class') or '':<8}  size={d.get('size') or 0:<8}  {d.get('perm') or ''}")


def cmd_proxy_decompile(args, config):
    with_xrefs = getattr(args, 'with_xrefs', False)
    p = {"addr": args.addr}
    if getattr(args, 'out', None): p["output"] = args.out
    method = "decompile_with_xrefs" if with_xrefs else "decompile"
    r = _rpc_call(args, config, method, p)
    if not r: return
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
    p = {"addrs": args.addrs}
    if getattr(args, 'out', None): p["output"] = args.out
    r = _rpc_call(args, config, "decompile_batch", p)
    if not r: return
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
    if getattr(args, 'count', None) is not None: p["count"] = args.count
    if getattr(args, 'out', None): p["output"] = args.out
    r = _rpc_call(args, config, "disasm", p)
    if not r: return
    for ln in r.get("lines", []):
        print(f"  {ln['addr']}  {ln.get('bytes', ''):<24}  {ln['insn']}")


def cmd_proxy_xrefs(args, config):
    direction = getattr(args, 'direction', 'to')
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
    if getattr(args, 'regex', False): p["regex"] = True
    if getattr(args, 'max', None): p["max_results"] = args.max
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
    if getattr(args, 'max', None): p["max_results"] = args.max
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
        print(f"[+] Renamed {r['addr']} -> {r['name']}")


def cmd_proxy_set_type(args, config):
    r = _rpc_call(args, config, "set_type", {"addr": args.addr, "type": args.type_str})
    if r:
        print(f"[+] Type set at {r['addr']}: {r.get('type', '')}")


def cmd_proxy_comment(args, config):
    p = {"addr": args.addr, "comment": args.text}
    if getattr(args, 'repeatable', False): p["repeatable"] = True
    if getattr(args, 'type', None): p["type"] = args.type
    r = _rpc_call(args, config, "set_comment", p)
    if r:
        print(f"[+] Comment set at {r['addr']}")


def cmd_proxy_save(args, config):
    r = _rpc_call(args, config, "save_db")
    if r:
        print(f"[+] Database saved: {r.get('idb_path')}")


def cmd_proxy_exec(args, config):
    p = {"code": args.code}
    if getattr(args, 'out', None): p["output"] = args.out
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
            val = s["value"]
            if len(val) > 60:
                val = val[:57] + "..."
            print(f"    {s['addr']}  {val}")


def cmd_diff(args, config):
    """Compare functions between two instances."""
    registry = load_registry()
    id_a = args.instance_a
    id_b = args.instance_b

    # Resolve by hint or ID
    def resolve(hint):
        if hint in registry:
            return hint, registry[hint]
        matches = [(k, v) for k, v in registry.items()
                   if hint.lower() in v.get("binary", "").lower()]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            print(f"[-] No instance matching '{hint}'")
        else:
            print(f"[-] Multiple instances match '{hint}':")
            for k, v in matches:
                print(f"  {k}  {v.get('binary', '?')}")
        return None, None

    iid_a, info_a = resolve(id_a)
    if not iid_a: return
    iid_b, info_b = resolve(id_b)
    if not iid_b: return

    # Get function lists from both
    def get_funcs(iid, info):
        port = info.get("port")
        if not port:
            print(f"[-] Instance {iid} has no port")
            return None
        resp = post_rpc(config, port, "get_functions", iid, {"count": 10000})
        if "error" in resp:
            print(f"[-] {iid}: {resp['error'].get('message')}")
            return None
        return {f["name"]: f for f in resp.get("result", {}).get("data", [])}

    funcs_a = get_funcs(iid_a, info_a)
    funcs_b = get_funcs(iid_b, info_b)
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
        for name in sorted(only_a)[:30]:
            print(f"    {funcs_a[name]['addr']}  {name}")
        if len(only_a) > 30:
            print(f"    ... and {len(only_a) - 30} more")

    if only_b:
        print(f"\n  Only in {bin_b}:")
        for name in sorted(only_b)[:30]:
            print(f"    {funcs_b[name]['addr']}  {name}")
        if len(only_b) > 30:
            print(f"    ... and {len(only_b) - 30} more")

    if size_diff:
        size_diff.sort(key=lambda x: abs(x[4] - x[2]), reverse=True)  # sort by abs size diff
        print(f"\n  Size changed ({len(size_diff)}):")
        for name, addr_a, sa, addr_b, sb in size_diff[:30]:
            delta = sb - sa
            sign = "+" if delta > 0 else ""
            print(f"    {addr_a}  {name:<40}  {sa} -> {sb} ({sign}{delta})")
        if len(size_diff) > 30:
            print(f"    ... and {len(size_diff) - 30} more")


def cmd_batch(args, config, config_path):
    """Analyze all binaries in a directory."""
    target_dir = os.path.abspath(args.directory)
    if not os.path.isdir(target_dir):
        print(f"[-] Not a directory: {target_dir}")
        return

    # Supported binary extensions (common ones)
    _BIN_EXTS = {
        ".exe", ".dll", ".sys", ".so", ".dylib", ".o", ".obj",
        ".elf", ".bin", ".ko", ".axf", ".hex", ".srec", ".efi",
    }

    # Find binaries
    binaries = []
    for f in sorted(os.listdir(target_dir)):
        fpath = os.path.join(target_dir, f)
        if not os.path.isfile(fpath):
            continue
        ext = os.path.splitext(f)[1].lower()
        if ext in _BIN_EXTS:
            binaries.append(fpath)
            continue
        # No extension -try magic bytes
        if not ext:
            try:
                with open(fpath, "rb") as fp:
                    magic = fp.read(4)
                if magic in (b"\x7fELF", b"MZ") or magic[:2] == b"MZ":
                    binaries.append(fpath)
            except Exception:
                pass

    if not binaries:
        print(f"[-] No binaries found in: {target_dir}")
        return

    idb_dir = getattr(args, 'idb_dir', None)
    if not idb_dir:
        idb_dir = os.environ.get('IDA_IDB_DIR')
    fresh = getattr(args, 'fresh', False)
    timeout = getattr(args, 'timeout', 300)
    max_concurrent = config["analysis"]["max_instances"]

    print(f"[*] Found {len(binaries)} binaries in {target_dir}")
    print(f"[*] Max concurrent: {max_concurrent}, Timeout: {timeout}s")
    if idb_dir:
        print(f"[*] IDB dir: {idb_dir}")
    print()

    # Process in batches
    results = []
    for batch_start in range(0, len(binaries), max_concurrent):
        batch = binaries[batch_start:batch_start + max_concurrent]
        started = []

        # Start batch
        for bpath in batch:
            bname = os.path.basename(bpath)
            arch_info = arch_detect(bpath)
            instance_id = make_instance_id(bpath)
            idb_path = get_idb_path(config, os.path.normcase(os.path.abspath(bpath)),
                                     instance_id, False, idb_dir=idb_dir)

            if not _register_instance(config, instance_id, os.path.normcase(os.path.abspath(bpath)),
                                       arch_info, idb_path,
                                       os.path.join(config["paths"]["log_dir"], f"{instance_id}.log"),
                                       False):
                print(f"  [-] {bname}: failed to register")
                continue

            try:
                proc = _spawn_server(config, config_path, os.path.normcase(os.path.abspath(bpath)),
                                      instance_id, idb_path,
                                      os.path.join(config["paths"]["log_dir"], f"{instance_id}.log"),
                                      fresh)
                fmt = arch_info.get("file_format", "?")
                arch = arch_info.get("arch", "?")
                bits = arch_info.get("bits", "?")
                print(f"  [+] {bname} ({fmt} {arch} {bits}bit) -> {instance_id}")
                started.append((instance_id, bname))
            except Exception as e:
                print(f"  [-] {bname}: {e}")

        if not started:
            continue

        # Wait for all in batch
        print(f"\n[*] Waiting for {len(started)} instances...")
        deadline = time.time() + timeout
        poll = config["analysis"]["wait_poll_interval"]
        pending = set(iid for iid, _ in started)
        while pending and time.time() < deadline:
            time.sleep(poll)
            registry = load_registry()
            for iid in list(pending):
                info = registry.get(iid, {})
                state = info.get("state", "unknown")
                if state == "ready":
                    pending.discard(iid)
                elif state == "error":
                    pending.discard(iid)

        # Collect results
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

    # Summary
    print(f"\n[+] Batch complete: {len(results)}/{len(binaries)} analyzed")
    if results:
        print(f"\n  Active instances:")
        for bname, iid, _ in results:
            print(f"    {iid}  {bname}")
        print(f"\n  Use 'ida-cli -b <hint> decompile <addr>' to analyze further")
        if not getattr(args, 'keep', False):
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
    action = getattr(args, 'action', 'list')
    bookmarks = _load_bookmarks()

    if action == "add":
        addr = args.addr
        tag = args.tag
        note = getattr(args, 'note', None) or ""
        binary_hint = getattr(args, 'binary_hint', None) or ""

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
                print(f"[!] Bookmark already exists: {addr} [{tag}]")
                return

        bookmarks[binary].append({
            "addr": addr,
            "tag": tag,
            "note": note,
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        _save_bookmarks(bookmarks)
        print(f"[+] Bookmark added: {addr} [{tag}] {note}")

    elif action == "remove":
        addr = args.addr
        binary_hint = getattr(args, 'binary_hint', None) or ""
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
            print(f"[+] Bookmark removed: {addr}")
        else:
            print(f"[-] No bookmark found at {addr}")

    else:  # list
        tag_filter = getattr(args, 'tag', None)
        binary_filter = getattr(args, 'binary_hint', None)
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


def cmd_profile(args, config):
    action = getattr(args, 'action', 'list')

    if action == "list":
        print("  Available profiles:")
        for name, prof in _PROFILES.items():
            print(f"    {name:<12}  {prof['description']}")
        return

    if action == "run":
        profile_name = args.profile_name
        if profile_name not in _PROFILES:
            print(f"[-] Unknown profile: {profile_name}")
            print(f"    Available: {', '.join(_PROFILES.keys())}")
            return

        profile = _PROFILES[profile_name]
        print(f"[*] Running profile: {profile_name} -{profile['description']}")
        print()

        iid, info = resolve_instance(args, config)
        if not iid:
            return
        if info.get("state") != "ready":
            print(f"[-] Instance {iid} is not ready")
            return
        port = info.get("port")

        out_dir = getattr(args, 'out_dir', None)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        for step in profile["analysis_steps"]:
            parts = step.split()
            method = parts[0]
            print(f"  --- {step} ---")

            # Parse simple params from step string
            params = {}
            i = 1
            while i < len(parts):
                if parts[i] == "--filter" and i + 1 < len(parts):
                    params["filter"] = parts[i + 1]
                    i += 2
                elif parts[i] == "--count" and i + 1 < len(parts):
                    params["count"] = int(parts[i + 1])
                    i += 2
                elif parts[i] == "--max" and i + 1 < len(parts):
                    params["max_results"] = int(parts[i + 1])
                    i += 2
                elif parts[i] == "--regex":
                    params["regex"] = True
                    i += 1
                    if i < len(parts) and not parts[i].startswith("--"):
                        params["name"] = parts[i].strip("'\"")
                        i += 1
                else:
                    # Positional arg (e.g., name for find_func)
                    if method == "find_func" and "name" not in params:
                        params["name"] = parts[i].strip("'\"")
                    i += 1

            if out_dir:
                params["output"] = os.path.join(out_dir, f"{method}_{params.get('filter', 'all')}.txt")

            # Map CLI command name to RPC method
            rpc_map = {
                "summary": "summary",
                "segments": "get_segments",
                "strings": "get_strings",
                "imports": "get_imports",
                "exports": "get_exports",
                "find_func": "find_func",
                "functions": "get_functions",
            }
            rpc_method = rpc_map.get(method, method)

            resp = post_rpc(config, port, rpc_method, iid, params=params)
            if "error" in resp:
                print(f"    [-] {resp['error'].get('message', '?')}")
                continue

            r = resp.get("result", {})
            if method == "summary":
                print(f"    Functions: {r.get('func_count')}  "
                      f"Strings: {r.get('total_strings')}  "
                      f"Imports: {r.get('total_imports')}  "
                      f"Decompiler: {r.get('decompiler')}")
            elif method in ("strings", "imports", "exports", "functions"):
                data = r.get("data", [])
                total = r.get("total", 0)
                showing = len(data)
                print(f"    Total: {total}, Showing: {showing}")
                for d in data[:10]:
                    if "value" in d:
                        print(f"      {d['addr']}  {d['value'][:60]}")
                    elif "module" in d:
                        print(f"      {d['addr']}  {d.get('module', ''):<20}  {d['name']}")
                    elif "name" in d:
                        print(f"      {d['addr']}  {d['name']}")
                if showing > 10:
                    print(f"      ... ({showing - 10} more)")
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
            print()

        print(f"[+] Profile '{profile_name}' complete")
        if out_dir:
            print(f"    Results saved to: {out_dir}")


def cmd_update(args):
    """Self-update from git repository."""
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    git_dir = os.path.join(repo_dir, ".git")
    if not os.path.isdir(git_dir):
        print(f"[-] Not a git repository: {repo_dir}")
        return
    print(f"[*] Updating from: {repo_dir}")
    try:
        result = subprocess.run(
            ["git", "-C", repo_dir, "pull", "--ff-only"],
            capture_output=True, text=True, timeout=30,
        )
        print(result.stdout.strip())
        if result.returncode != 0:
            print(f"[-] {result.stderr.strip()}")
    except FileNotFoundError:
        print("[-] git not found in PATH")
    except subprocess.TimeoutExpired:
        print("[-] git pull timed out")


def cmd_completions(args):
    """Generate shell completion scripts."""
    shell = getattr(args, 'shell', 'bash')
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
        print(f"[-] Unsupported shell: {shell}. Use bash, zsh, or powershell.")


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

    sub.add_parser("update", help="Self-update from git")

    p = sub.add_parser("completions", help="Generate shell completions")
    p.add_argument("--shell", choices=["bash", "zsh", "powershell"], default="bash")

    args = parser.parse_args()

    config, config_path = load_config(args.config)
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

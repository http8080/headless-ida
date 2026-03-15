"""CLI commands — all cmd_* proxy/analysis/management commands."""

import json
import os
import sys
import time

from .core import (
    _log_ok, _log_err, _log_info, _log_warn,
    _opt, _truncate, _md_table_header, _format_arch_info, _print_truncated,
    _registry_locked, _make_args,
    _is_process_alive, cleanup_stale, _force_kill,
    _register_instance, _spawn_server, _wait_for_start,
    load_config, _load_idb_metadata,
    load_registry, save_registry, remove_auth_token,
    make_instance_id, get_idb_path,
    resolve_instance, _ensure_ready, _resolve_ready,
    post_rpc, _rpc_call,
    _is_md_out, _save_local, _md_decompile, _md_decompile_batch, _md_summary,
    _check_inline_limit, _maybe_output_param, _build_params, _list_params,
    psutil, req_lib,
    SUPPORTED_BINARY_EXTENSIONS, AUTO_GENERATED_PREFIXES,
    STRING_DISPLAY_LIMIT, STOP_WAIT_ITERATIONS, STOP_POLL_INTERVAL,
    STOP_RPC_TIMEOUT, CLEANUP_AGE_SECONDS, PID_CREATE_TIME_TOLERANCE,
    _SCRIPT_DIR,
)
from shared import arch_detect
import glob
import subprocess


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
            from shared import file_md5
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


def cmd_restart(args, config, config_path):
    """Stop and re-start an instance with the same binary and IDB."""
    iid = args.id
    registry = load_registry()
    info = registry.get(iid)
    if not info:
        _log_err(f"Instance '{iid}' not found")
        return
    binary_path = info.get("path")
    idb_path = info.get("idb_path")
    if not binary_path:
        _log_err("Cannot restart: binary path unknown")
        return
    # Derive idb_dir from idb_path
    idb_dir = os.path.dirname(idb_path) if idb_path else None

    # Stop
    _log_info(f"Stopping {iid}...")
    cmd_stop(args, config)
    time.sleep(1)

    # Re-start with same binary and idb_dir
    class _RestartArgs:
        pass
    new_args = _RestartArgs()
    new_args.binary = binary_path
    new_args.idb_dir = idb_dir
    new_args.force = False
    new_args.fresh = _opt(args, 'fresh', False)
    new_args.arch = None
    new_args.binary_hint = None
    new_args.instance = None
    new_args.json_output = False
    new_args.config = None
    cmd_start(new_args, config, config_path)


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
            remaining = max(0, int(deadline - time.time()))
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
    if _opt(args, 'json_output', False):
        out = {}
        for iid, info in registry.items():
            out[iid] = {
                "state": info.get("state", "unknown"),
                "binary": info.get("binary", "?"),
                "port": info.get("port"),
                "pid": info.get("pid"),
                "idb": info.get("idb_path"),
            }
        print(json.dumps(out, indent=2))
        return
    for iid, info in registry.items():
        state = info.get("state", "unknown")
        binary = info.get("binary", "?")
        port = info.get("port", "-")
        print(f"  {iid}  {state:<12}  {binary}  port={port}")


def cmd_status(args, config):
    iid = _opt(args, 'id')
    if not iid:
        # Try resolving from -b hint or single active instance
        resolved_id, resolved_info = resolve_instance(args, config)
        if resolved_id:
            iid = resolved_id
        else:
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

def cmd_proxy_segments(args, config):
    p = _build_params(args, {"out": "output"})
    r = _rpc_call(args, config, "get_segments", p)
    if not r: return
    for d in r.get("data", []):
        print(f"  {d['start_addr']}-{d['end_addr']}  {d.get('name') or '':<12}  "
              f"{d.get('class') or '':<8}  size={d.get('size') or 0:<8}  {d.get('perm') or ''}")


def cmd_proxy_decompile(args, config):
    with_xrefs = _opt(args, 'with_xrefs', False)
    raw = _opt(args, 'raw', False)
    md_out = _is_md_out(args)
    p = {"addr": args.addr}
    if raw:
        p["raw"] = True
    _maybe_output_param(args, p, md_out)
    method = "decompile_with_xrefs" if with_xrefs else "decompile"
    r = _rpc_call(args, config, method, p)
    if not r: return
    if md_out:
        _save_local(args.out, _md_decompile(r, with_xrefs))
        return
    code = r.get("code", "")
    if raw:
        output = code
    else:
        header = f"// {r.get('name', '')} @ {r.get('addr', '')}"
        output = f"{header}\n{code}"
    if with_xrefs and not raw:
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
    if r.get("saved_to"):
        _log_ok(f"Saved to: {r['saved_to']}")
    else:
        output, _ = _check_inline_limit(output, config)
        print(output)


def cmd_proxy_decompile_batch(args, config):
    md_out = _is_md_out(args)
    p = {"addrs": args.addrs}
    _maybe_output_param(args, p, md_out)
    r = _rpc_call(args, config, "decompile_batch", p)
    if not r: return
    if md_out:
        _save_local(args.out, _md_decompile_batch(r))
        return
    lines = [f"Total: {r.get('total', 0)}, Success: {r.get('success', 0)}, Failed: {r.get('failed', 0)}"]
    for func in r.get("functions", []):
        if "code" in func:
            lines.append(f"\n// -- {func['name']} ({func['addr']}) --")
            lines.append(func["code"])
        else:
            lines.append(f"\n// -- {func.get('addr', '?')} -- ERROR: {func.get('error', '?')}")
    if r.get("saved_to"):
        print(lines[0])  # summary line only
        _log_ok(f"Saved to: {r['saved_to']}")
    else:
        output = "\n".join(lines)
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


def cmd_proxy_callers(args, config):
    """Shortcut: xrefs --direction to (who calls this)."""
    args.direction = "to"
    cmd_proxy_xrefs(args, config)


def cmd_proxy_callees(args, config):
    """Shortcut: xrefs --direction from (what this calls)."""
    args.direction = "from"
    cmd_proxy_xrefs(args, config)


def cmd_proxy_find_func(args, config):
    p = {"name": args.name}
    if _opt(args, 'regex', False): p["regex"] = True
    if _opt(args, 'max'): p["max_results"] = args.max
    r = _rpc_call(args, config, "find_func", p)
    if not r: return
    lines = [f"Query: '{r['query']}' ({r['total']} matches)"]
    for m in r.get("matches", []):
        lines.append(f"  {m['addr']}  {m['name']}")
    text = "\n".join(lines)
    out = _opt(args, 'out')
    if out:
        _save_local(out, text)
    else:
        print(text)


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
    lines = [f"Pattern: '{r['pattern']}' ({r['total']} matches)"]
    for addr in r.get("matches", []):
        lines.append(f"  {addr}")
    text = "\n".join(lines)
    out = _opt(args, 'out')
    if out:
        _save_local(out, text)
    else:
        print(text)


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
        print(f"    {s['start_addr']}-{s['end_addr']}  {s.get('name', ''):<12}  "
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


# ─────────────────────────────────────────────
# Diff / Compare
# ─────────────────────────────────────────────

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


# ─────────────────────────────────────────────
# Batch Analysis
# ─────────────────────────────────────────────

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
                if magic[:4] == b"\x7fELF" or magic[:2] == b"MZ":
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


# ─────────────────────────────────────────────
# Report Generation
# ─────────────────────────────────────────────

_REPORT_DATA_TABLES = [
    ("Imports", "get_imports", 100,
     ("Address", "Module", "Name"),
     lambda d: f"| `{d['addr']}` | {d.get('module', '')} | {d['name']} |"),
    ("Exports", "get_exports", 100,
     ("Address", "Name"),
     lambda d: f"| `{d['addr']}` | {d['name']} |"),
    ("Strings", "get_strings", 50,
     ("Address", "Value"),
     lambda d: f"| `{d['addr']}` | {d.get('value', '').replace('|', '\\|')} |"),
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
        out_path = _opt(args, 'out') or "annotations.json"
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
    lines = [f"  Value: {r.get('value', '')}  Found: {r.get('total', 0)}"]
    for entry in r.get("results", []):
        func = entry.get("func", "")
        func_str = f"  [{func}]" if func else ""
        lines.append(f"    {entry['addr']}  {entry.get('disasm', '')}{func_str}")
    text = "\n".join(lines)
    out = _opt(args, 'out')
    if out:
        _save_local(out, text)
    else:
        print(text)


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
        items = r.get("structs", [])
        total = len(items)
        offset = _opt(args, 'offset', 0) or 0
        count = _opt(args, 'count') or len(items)
        items = items[offset:offset + count]
        print(f"  Total: {total}" + (f" (showing {len(items)} from offset {offset})" if offset or count < total else ""))
        for s in items:
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
            desc = f"  \"{s['description']}\"" if s.get("description") else ""
            print(f"    {s['created']}  {size_mb:.1f}MB  {s['name']}{desc}")

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
        items = r.get("enums", [])
        total = len(items)
        offset = _opt(args, 'offset', 0) or 0
        count = _opt(args, 'count') or len(items)
        items = items[offset:offset + count]
        print(f"  Total: {total}" + (f" (showing {len(items)} from offset {offset})" if offset or count < total else ""))
        for e in items:
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
    out_path = _opt(args, 'out', 'analysis.py') or 'analysis.py'
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
    # Walk up from tools/ to find the git root
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    while repo_dir != os.path.dirname(repo_dir):  # stop at filesystem root
        if os.path.isdir(os.path.join(repo_dir, ".git")):
            break
        repo_dir = os.path.dirname(repo_dir)
    else:
        _log_err("Not inside a git repository")
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
        "save", "exec", "summary", "diff", "batch", "bookmark",
        "profile", "report", "shell", "annotations", "callgraph",
        "patch", "search-const", "structs", "snapshot", "compare",
        "enums", "search-code", "code-diff", "auto-rename",
        "export-script", "vtables", "sigs", "cross-refs",
        "decompile-all", "type-info", "strings-xrefs",
        "func-similarity", "data-refs", "basic-blocks",
        "stack-frame", "switch-table", "rename-batch",
        "update", "completions",
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
# Cross-refs (multi-level xref chain)
# ─────────────────────────────────────────────

def cmd_cross_refs(args, config):
    """Multi-level xref chain tracing."""
    p = {"addr": args.addr, "depth": _opt(args, 'depth', 3),
         "direction": _opt(args, 'direction', 'to')}
    r = _rpc_call(args, config, "cross_refs", p)
    if not r:
        return
    print(f"  Root: {r.get('root', '')}  Depth: {r.get('depth')}  Direction: {r.get('direction')}")
    print(f"  Nodes: {r.get('nodes', 0)}, Edges: {r.get('edges', 0)}")
    for entry in r.get("chain", []):
        indent = "  " * entry["level"]
        print(f"    {indent}{entry['addr']}  {entry['name']}")
    out_path = _opt(args, 'out')
    if out_path:
        fmt = _opt(args, 'format', 'mermaid')
        content = r.get("dot" if fmt == "dot" else "mermaid", "")
        _save_local(out_path, content)


# ─────────────────────────────────────────────
# Decompile All
# ─────────────────────────────────────────────

def cmd_decompile_all(args, config):
    """Decompile all functions to .c file."""
    out_path = args.out
    split = _opt(args, 'split', False)
    p = {"output": out_path, "filter": _opt(args, 'filter', ''),
         "skip_thunks": not _opt(args, 'include_thunks', False),
         "skip_libs": not _opt(args, 'include_libs', False)}
    if split:
        p["split"] = True
    r = _rpc_call(args, config, "decompile_all", p)
    if not r:
        return
    print(f"  Decompiled: {r.get('success', 0)}/{r.get('total', 0)} functions")
    print(f"  Failed: {r.get('failed', 0)}, Skipped: {r.get('skipped', 0)}")
    mode = "directory" if r.get("split") else "file"
    print(f"  Saved to ({mode}): {r.get('saved_to', '')}")


# ─────────────────────────────────────────────
# Type Info
# ─────────────────────────────────────────────

def cmd_type_info(args, config):
    """Query IDA local types."""
    action = _opt(args, 'action', 'list')

    if action == "list":
        p = {}
        if _opt(args, 'filter'):
            p["filter"] = args.filter
        if _opt(args, 'kind'):
            p["kind"] = args.kind
        if _opt(args, 'offset') is not None:
            p["offset"] = args.offset
        if _opt(args, 'count') is not None:
            p["count"] = args.count
        r = _rpc_call(args, config, "list_types", p)
        if not r:
            return
        print(f"  Total: {r.get('total', 0)} (showing {r.get('count', 0)} from offset {r.get('offset', 0)})")
        for t in r.get("data", []):
            print(f"    {t['name']:<40}  {t.get('kind', ''):<8}  size={t.get('size', '?')}")

    elif action == "show":
        r = _rpc_call(args, config, "get_type", {"name": args.name})
        if not r:
            return
        print(f"  Name:        {r['name']}")
        print(f"  Size:        {r.get('size', '?')}")
        print(f"  Declaration: {r.get('declaration', '')}")
        flags = []
        for f in ("is_struct", "is_union", "is_enum", "is_typedef", "is_funcptr"):
            if r.get(f):
                flags.append(f.replace("is_", ""))
        if flags:
            print(f"  Type:        {', '.join(flags)}")
        if r.get("return_type"):
            print(f"  Return:      {r['return_type']}")
        if r.get("args"):
            print(f"  Args:")
            for a in r["args"]:
                print(f"    {a['type']:<30}  {a['name']}")


# ─────────────────────────────────────────────
# Strings with Xrefs
# ─────────────────────────────────────────────

def cmd_strings_xrefs(args, config):
    """Strings with referencing functions."""
    p = {}
    if _opt(args, 'filter'):
        p["filter"] = args.filter
    if _opt(args, 'max'):
        p["max_results"] = args.max
    if _opt(args, 'min_refs'):
        p["min_refs"] = args.min_refs
    r = _rpc_call(args, config, "strings_xrefs", p)
    if not r:
        return
    print(f"  Total: {r.get('total', 0)} strings with xrefs")
    for entry in r.get("results", []):
        val = _truncate(entry['value'], 60)
        print(f"\n    {entry['addr']}  \"{val}\"  ({entry['ref_count']} refs)")
        for ref in entry.get("refs", [])[:5]:
            fn = ref.get("func_name", "")
            print(f"      <- {ref['addr']}  {fn}  [{ref['type']}]")
        if entry['ref_count'] > 5:
            print(f"      ... and {entry['ref_count'] - 5} more")
    out_path = _opt(args, 'out')
    if out_path:
        _save_local(out_path, json.dumps(r, ensure_ascii=False, indent=2))


# ─────────────────────────────────────────────
# Function Similarity
# ─────────────────────────────────────────────

def cmd_func_similarity(args, config):
    """Compare two functions by similarity."""
    p = {"addr_a": args.addr_a, "addr_b": args.addr_b}
    r = _rpc_call(args, config, "func_similarity", p)
    if not r:
        return
    a, b = r["func_a"], r["func_b"]
    sim = r["similarity"]
    print(f"  Function A: {a['name']} ({a['addr']})  size={a['size']}  blocks={a['block_count']}  callees={a['callee_count']}")
    print(f"  Function B: {b['name']} ({b['addr']})  size={b['size']}  blocks={b['block_count']}  callees={b['callee_count']}")
    print(f"\n  Similarity:")
    print(f"    Size ratio:      {sim['size_ratio']:.4f}")
    print(f"    Block ratio:     {sim['block_ratio']:.4f}")
    print(f"    Callee Jaccard:  {sim['callee_jaccard']:.4f}")
    print(f"    Overall:         {sim['overall']:.4f}")
    common = r.get("common_callees", [])
    if common:
        print(f"\n  Common callees ({len(common)}):")
        for c in common[:20]:
            print(f"    {c}")
        if len(common) > 20:
            print(f"    ... and {len(common) - 20} more")


# ─────────────────────────────────────────────
# Data Refs
# ─────────────────────────────────────────────

def cmd_data_refs(args, config):
    """Data segment reference analysis."""
    p = {}
    if _opt(args, 'filter'):
        p["filter"] = args.filter
    if _opt(args, 'segment'):
        p["segment"] = args.segment
    if _opt(args, 'max'):
        p["max_results"] = args.max
    r = _rpc_call(args, config, "data_refs", p)
    if not r:
        return
    print(f"  Total: {r.get('total', 0)} data references")
    for entry in r.get("results", []):
        print(f"\n    {entry['addr']}  {entry['name']}  [{entry['segment']}]  size={entry['size']}  refs={entry['ref_count']}")
        for ref in entry.get("refs", [])[:5]:
            print(f"      <- {ref['addr']}  {ref.get('func', '')}  [{ref['type']}]")
        if entry['ref_count'] > 5:
            print(f"      ... and {entry['ref_count'] - 5} more")
    out_path = _opt(args, 'out')
    if out_path:
        _save_local(out_path, json.dumps(r, ensure_ascii=False, indent=2))


# ─────────────────────────────────────────────
# Basic Blocks + CFG
# ─────────────────────────────────────────────

def cmd_basic_blocks(args, config):
    """Basic blocks and CFG for a function."""
    fmt = _opt(args, 'format', 'mermaid') or 'mermaid'
    p = {"addr": args.addr}
    r = _rpc_call(args, config, "basic_blocks", p)
    if not r:
        return
    graph_only = _opt(args, 'graph_only', False)
    print(f"  Function: {r.get('name', '')} ({r.get('addr', '')})")
    print(f"  Blocks: {r.get('block_count', 0)}, Edges: {r.get('edge_count', 0)}")
    if not graph_only:
        for bb in r.get("blocks", []):
            succs = ", ".join(bb.get("successors", []))
            print(f"    {bb['start']}-{bb['end']}  size={bb['size']}  -> [{succs}]")
    content = r.get("dot" if fmt == "dot" else "mermaid", "")
    out_path = _opt(args, 'out')
    if out_path:
        _save_local(out_path, content)
    else:
        print()
        print(content)


# ─────────────────────────────────────────────
# Stack Frame
# ─────────────────────────────────────────────

def cmd_stack_frame(args, config):
    """Show stack frame layout with local variables."""
    r = _rpc_call(args, config, "stack_frame", {"addr": args.addr})
    if not r:
        return
    print(f"  Function: {r.get('name', '')} ({r.get('addr', '')})")
    print(f"  Frame size: {r.get('frame_size', 0)}  (locals={r.get('locals_size', 0)}, "
          f"args={r.get('args_size', 0)}, retaddr={r.get('retaddr_size', 0)})")
    print(f"  Members: {r.get('member_count', 0)}")
    if r.get("members"):
        print()
        print("  | {:>6} | {:>6} | {:<30} | {:<20} | {} |".format(
            "Offset", "Size", "Name", "Type", "Kind"))
        print("  |--------|--------|" + "-" * 32 + "|" + "-" * 22 + "|------|")
        for m in r["members"]:
            print("  | {:>6} | {:>6} | {:<30} | {:<20} | {:<4} |".format(
                m["offset"], m["size"], m["name"],
                _truncate(m.get("type", ""), 20), m["kind"]))


# ─────────────────────────────────────────────
# Switch Table
# ─────────────────────────────────────────────

def cmd_switch_table(args, config):
    """Analyze switch/jump tables in a function."""
    r = _rpc_call(args, config, "switch_table", {"addr": args.addr})
    if not r:
        return
    print(f"  Function: {r.get('name', '')} ({r.get('addr', '')})")
    print(f"  Switch tables: {r.get('switch_count', 0)}")
    for sw in r.get("switches", []):
        default = sw.get("default") or "none"
        print(f"\n    Switch @ {sw['addr']}  ({sw['case_count']} cases, default={default})")
        for case in sw.get("cases", []):
            vals = ", ".join(str(v) for v in case.get("values", []))
            print(f"      case {vals}: -> {case['target']}")


# ─────────────────────────────────────────────
# Rename Batch
# ─────────────────────────────────────────────

def cmd_rename_batch(args, config):
    """Batch rename from CSV/JSON file."""
    input_file = args.input_file
    if not os.path.isfile(input_file):
        _log_err(f"File not found: {input_file}")
        return

    entries = []
    if input_file.endswith(".json"):
        with open(input_file, encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                entries = data
            elif isinstance(data, dict):
                entries = [{"addr": k, "name": v} for k, v in data.items()]
    else:
        # CSV format: addr,name (one per line)
        with open(input_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",", 1)
                if len(parts) == 2:
                    entries.append({"addr": parts[0].strip(), "name": parts[1].strip()})

    if not entries:
        _log_err("No rename entries found in file")
        return

    _log_info(f"Renaming {len(entries)} symbols...")
    r = _rpc_call(args, config, "rename_batch", {"entries": entries})
    if not r:
        return
    print(f"  Total: {r.get('total', 0)}, Success: {r.get('success', 0)}, Failed: {r.get('failed', 0)}")
    for entry in r.get("renames", [])[:30]:
        status = "OK" if entry.get("ok") else "FAIL"
        print(f"    [{status}] {entry['addr']}  {entry['name']}")

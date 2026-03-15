#!/usr/bin/env python3
"""ida_server.py — idalib-based HTTP JSON-RPC server

Usage:
    python ida_server.py <binary> --id <instance_id> --idb <idb_path>
                         --log <log_path> --config <config_path> [--fresh]
"""

import argparse
import atexit
import base64
import contextlib
import io
import json
import logging
import os
import re
import secrets
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from logging.handlers import RotatingFileHandler

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _SCRIPT_DIR)
from common import (
    load_config, init_registry_paths,
    acquire_lock, release_lock,
    load_registry, save_registry,
    file_md5, remove_auth_token,
)

SERVER_VERSION = "2.0"

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

MAX_BATCH_DECOMPILE = 20
MAX_DISASM_LINES = 500
DEFAULT_DISASM_COUNT = 20
MAX_READ_BYTES = 4096
DEFAULT_FIND_MAX = 50
MAX_FIND_RESULTS = 200
DEFAULT_SEARCH_MAX = 100
MAX_SEARCH_RESULTS = 500
STRING_TYPE_UNICODE = 1

# Segment permissions
SEGPERM_READ = 4
SEGPERM_WRITE = 2
SEGPERM_EXEC = 1


# ─────────────────────────────────────────────
# Registry helpers (server-specific)
# ─────────────────────────────────────────────

def _update_registry(instance_id, updates):
    if not acquire_lock():
        log.warning("Could not acquire registry lock for update")
        return
    try:
        r = load_registry()
        if instance_id in r:
            r[instance_id].update(updates)
            save_registry(r)
    finally:
        release_lock()


def _update_state(instance_id, state):
    _update_registry(instance_id, {"state": state})


def _remove_from_registry(instance_id):
    if not acquire_lock():
        return
    try:
        r = load_registry()
        r.pop(instance_id, None)
        save_registry(r)
    finally:
        release_lock()


# ─────────────────────────────────────────────
# Auth token
# ─────────────────────────────────────────────

def _save_auth_token(token_path, instance_id, port, token):
    if not acquire_lock():
        log.error("Could not acquire lock for auth_token write")
        return
    try:
        os.makedirs(os.path.dirname(token_path), exist_ok=True)
        with open(token_path, "a", encoding="utf-8") as f:
            f.write(f"{instance_id}:{port}:{token}\n")
    finally:
        release_lock()


# ─────────────────────────────────────────────
# idb metadata
# ─────────────────────────────────────────────

def _save_idb_metadata(idb_path, binary_path):
    meta = {
        "binary_path": binary_path,
        "binary_md5": file_md5(binary_path),
        "created": time.time(),
    }
    with open(idb_path + ".meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


# ─────────────────────────────────────────────
# save_db
# ─────────────────────────────────────────────

def save_db():
    """Workaround for ida_loader.save_database() flags=-1 bug. Explicitly use flags=0."""
    import ida_loader
    idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    ret = ida_loader.save_database(idb, 0)
    if ret:
        log.info(f"Database saved: {idb}")
    else:
        log.error(f"Database save failed: {idb}")
    return ret


# ─────────────────────────────────────────────
# Helpers (addr resolution, pagination, xref)
# ─────────────────────────────────────────────

def _resolve_addr(addr_str):
    """Address string or symbol name → ea_t"""
    import idc
    if addr_str is None:
        raise RpcError("INVALID_PARAMS", "addr parameter required")
    addr_str = str(addr_str).strip()
    try:
        return int(addr_str, 16)
    except ValueError:
        pass
    ea = idc.get_name_ea_simple(addr_str)
    if ea == idc.BADADDR:
        raise RpcError("INVALID_ADDRESS", f"Cannot resolve: {addr_str}")
    return ea


def _fmt_addr(ea):
    return f"0x{ea:X}"


def _perm_str(perm):
    return (("r" if perm & SEGPERM_READ else "-") +
            ("w" if perm & SEGPERM_WRITE else "-") +
            ("x" if perm & SEGPERM_EXEC else "-"))


def _paginate(all_data, params):
    cfg_out = _config["output"]
    offset = int(params.get("offset", 0))
    count = min(int(params.get("count", cfg_out["default_count"])), cfg_out["max_count"])
    data = all_data[offset:offset + count]
    saved_to = _save_output(params.get("output"), data, fmt="json")
    return {"total": len(all_data), "offset": offset, "count": len(data),
            "data": data, "saved_to": saved_to}


def _save_output(output_path, content, fmt="text"):
    """Common file save function. fmt: 'text' or 'json'"""
    if not output_path:
        return None
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    encoding = _config["output"]["encoding"]
    with open(output_path, "w", encoding=encoding) as f:
        if fmt == "json":
            json.dump(content, f, ensure_ascii=False, indent=2)
        else:
            f.write(content)
    return output_path


def _xref_type_str(xtype):
    import ida_xref
    if xtype in (ida_xref.fl_CF, ida_xref.fl_CN):
        return "call"
    if xtype in (ida_xref.fl_JF, ida_xref.fl_JN):
        return "jump"
    if xtype in (ida_xref.dr_R, ida_xref.dr_W, ida_xref.dr_O,
                 ida_xref.dr_I, ida_xref.dr_T, ida_xref.dr_S):
        return "data"
    return "unknown"


# ─────────────────────────────────────────────
# HTTP Server + RPC
# ─────────────────────────────────────────────

class RpcError(Exception):
    def __init__(self, code, message, suggestion=None):
        self.code = code
        self.message = message
        self.suggestion = suggestion


# Global state
_server = None
_keep_running = True
_db_closed = False
_start_time = None
_auth_token = None
_instance_id = None
_binary_path = None
_config = None


def _handle_ping():
    return {"ok": True, "state": "ready"}


def _handle_status():
    import ida_kernwin, ida_loader, idautils
    funcs = list(idautils.Functions())
    idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    return {
        "state": "ready",
        "binary": os.path.basename(_binary_path),
        "idb_path": idb,
        "decompiler_available": _decompiler_available,
        "func_count": len(funcs),
        "ida_version": ida_kernwin.get_kernel_version(),
        "server_version": SERVER_VERSION,
        "uptime": round(time.time() - _start_time, 1),
        "binary_md5": file_md5(_binary_path) if os.path.exists(_binary_path) else None,
    }


def _handle_stop():
    global _keep_running
    _keep_running = False
    save_db()
    threading.Thread(target=_server.shutdown).start()
    return {"ok": True}


# ─────────────────────────────────────────────
# List API
# ─────────────────────────────────────────────

def _handle_get_functions(params):
    import idc, idautils, ida_funcs
    filt = params.get("filter")
    funcs = []
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        if filt and filt.lower() not in name.lower():
            continue
        func = ida_funcs.get_func(ea)
        funcs.append({"addr": _fmt_addr(ea), "name": name,
                       "size": func.size() if func else 0})
    return _paginate(funcs, params)


def _handle_get_strings(params):
    import idautils, idc
    filt = params.get("filter")
    strings = []
    for s in idautils.Strings():
        val = idc.get_strlit_contents(s.ea, s.length, s.strtype)
        if val is None:
            continue
        try:
            decoded = val.decode("utf-8", errors="replace")
        except Exception:
            decoded = val.hex()
        if filt and filt.lower() not in decoded.lower():
            continue
        enc = "utf-16" if s.strtype == STRING_TYPE_UNICODE else "ascii"
        strings.append({"addr": _fmt_addr(s.ea), "value": decoded,
                         "length": s.length, "encoding": enc})
    return _paginate(strings, params)


def _handle_get_imports(params):
    import ida_nalt
    filt = params.get("filter")
    imports = []
    for i in range(ida_nalt.get_import_module_qty()):
        mod = ida_nalt.get_import_module_name(i)
        def cb(ea, name, ordinal, _mod=mod):
            if name is None:
                name = ""
            if filt and filt.lower() not in name.lower() and filt.lower() not in (_mod or "").lower():
                return True
            imports.append({"addr": _fmt_addr(ea), "name": name,
                            "module": _mod or "", "ordinal": ordinal})
            return True
        ida_nalt.enum_import_names(i, cb)
    return _paginate(imports, params)


def _handle_get_exports(params):
    import idautils
    filt = params.get("filter")
    exports = []
    for idx, ordinal, ea, name in idautils.Entries():
        if name is None:
            name = ""
        if filt and filt.lower() not in name.lower():
            continue
        exports.append({"addr": _fmt_addr(ea), "name": name, "ordinal": ordinal})
    return _paginate(exports, params)


def _handle_get_segments(params):
    import idautils, ida_segment
    segments = []
    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        if not seg:
            continue
        segments.append({
            "start_addr": _fmt_addr(seg.start_ea),
            "end_addr": _fmt_addr(seg.end_ea),
            "name": ida_segment.get_segm_name(seg),
            "class": ida_segment.get_segm_class(seg),
            "size": seg.size(),
            "perm": _perm_str(seg.perm),
        })
    return _paginate(segments, params)


# ─────────────────────────────────────────────
# Analysis API
# ─────────────────────────────────────────────

def _handle_decompile(params):
    if not _decompiler_available:
        raise RpcError("DECOMPILER_NOT_LOADED", "Decompiler plugin not available")
    import ida_hexrays, idc, ida_funcs
    ea = _resolve_addr(params.get("addr"))
    func = ida_funcs.get_func(ea)
    if not func:
        raise RpcError("NOT_A_FUNCTION", f"No function at {_fmt_addr(ea)}")
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            raise RpcError("DECOMPILE_FAILED", f"Decompile returned None at {_fmt_addr(ea)}")
        code = str(cfunc)
    except ida_hexrays.DecompilationFailure as e:
        raise RpcError("DECOMPILE_FAILED", str(e))
    name = idc.get_func_name(func.start_ea) or ""
    saved_to = _save_output(params.get("output"), code)
    return {"addr": _fmt_addr(func.start_ea), "name": name,
            "code": code, "saved_to": saved_to}


def _handle_decompile_batch(params):
    if not _decompiler_available:
        raise RpcError("DECOMPILER_NOT_LOADED", "Decompiler plugin not available")
    import ida_hexrays, idc, ida_funcs
    addrs = params.get("addrs", [])
    if len(addrs) > MAX_BATCH_DECOMPILE:
        raise RpcError("INVALID_PARAMS", f"Maximum {MAX_BATCH_DECOMPILE} addresses per batch")
    results = []
    success = 0
    for addr_str in addrs:
        try:
            ea = _resolve_addr(addr_str)
            func = ida_funcs.get_func(ea)
            if not func:
                results.append({"addr": _fmt_addr(ea), "name": "", "error": "NOT_A_FUNCTION"})
                continue
            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                results.append({"addr": _fmt_addr(func.start_ea),
                                "name": idc.get_func_name(func.start_ea) or "",
                                "error": "DECOMPILE_FAILED"})
                continue
            results.append({"addr": _fmt_addr(func.start_ea),
                            "name": idc.get_func_name(func.start_ea) or "",
                            "code": str(cfunc)})
            success += 1
        except RpcError:
            results.append({"addr": addr_str, "name": "", "error": "INVALID_ADDRESS"})
        except Exception as e:
            results.append({"addr": addr_str, "name": "", "error": str(e)})
    # File output
    output_path = params.get("output")
    if output_path:
        text = "\n\n".join(
            f"// ── {r['name']} ({r['addr']}) ──\n{r['code']}"
            for r in results if "code" in r
        )
        _save_output(output_path, text)
    return {"total": len(addrs), "success": success,
            "failed": len(addrs) - success, "functions": results,
            "saved_to": output_path if output_path else None}


def _handle_disasm(params):
    import idc, ida_bytes
    ea = _resolve_addr(params.get("addr"))
    count = min(int(params.get("count", DEFAULT_DISASM_COUNT)), MAX_DISASM_LINES)
    lines = []
    cur = ea
    for _ in range(count):
        insn = idc.generate_disasm_line(cur, 0)
        if insn is None:
            break
        size = idc.get_item_size(cur) or 1  # prevent size 0
        raw = ida_bytes.get_bytes(cur, size)
        hex_str = " ".join(f"{b:02X}" for b in raw) if raw else ""
        lines.append({"addr": _fmt_addr(cur), "bytes": hex_str, "insn": insn})
        cur += size
    text = "\n".join(f"{ln['addr']}  {ln['bytes']:<24}  {ln['insn']}" for ln in lines)
    saved_to = _save_output(params.get("output"), text)
    return {"addr": _fmt_addr(ea), "count": len(lines),
            "lines": lines, "saved_to": saved_to}


def _handle_get_xrefs_to(params):
    import idautils, idc
    ea = _resolve_addr(params.get("addr"))
    refs = []
    for xref in idautils.XrefsTo(ea):
        refs.append({
            "from_addr": _fmt_addr(xref.frm),
            "from_name": idc.get_func_name(xref.frm) or "",
            "type": _xref_type_str(xref.type),
        })
    return {"addr": _fmt_addr(ea), "total": len(refs), "refs": refs}


def _handle_get_xrefs_from(params):
    import idautils, idc
    ea = _resolve_addr(params.get("addr"))
    refs = []
    for xref in idautils.XrefsFrom(ea):
        refs.append({
            "to_addr": _fmt_addr(xref.to),
            "to_name": idc.get_func_name(xref.to) or "",
            "type": _xref_type_str(xref.type),
        })
    return {"addr": _fmt_addr(ea), "total": len(refs), "refs": refs}


def _handle_find_func(params):
    import idautils, idc
    name = params.get("name")
    if not name:
        raise RpcError("INVALID_PARAMS", "name parameter required")
    use_regex = params.get("regex", False)
    max_results = min(int(params.get("max_results", DEFAULT_SEARCH_MAX)), MAX_SEARCH_RESULTS)
    pattern = re.compile(name) if use_regex else None
    matches = []
    for ea in idautils.Functions():
        fn = idc.get_func_name(ea)
        if pattern:
            if pattern.search(fn):
                matches.append({"addr": _fmt_addr(ea), "name": fn})
        else:
            if name.lower() in fn.lower():
                matches.append({"addr": _fmt_addr(ea), "name": fn})
        if len(matches) >= max_results:
            break
    return {"query": name, "total": len(matches), "matches": matches}


# ─────────────────────────────────────────────
# Info API
# ─────────────────────────────────────────────

def _extract_type_info(func_start_ea):
    """Extract function type info (return_type, cc, args) using the decompiler"""
    import ida_hexrays, ida_typeinf
    result = {"calling_convention": None, "return_type": None, "args": None}
    try:
        cfunc = ida_hexrays.decompile(func_start_ea)
        if not cfunc:
            return result
    except Exception:
        return result

    tif = cfunc.type
    fi = ida_typeinf.func_type_data_t()
    if not tif.get_func_details(fi):
        return result

    try:
        rettype = tif.get_rettype()
        result["return_type"] = str(rettype) if rettype else None
    except Exception:
        pass

    try:
        cc = fi.cc & ida_typeinf.CM_CC_MASK
        cc_names = {
            ida_typeinf.CM_CC_CDECL: "__cdecl",
            ida_typeinf.CM_CC_STDCALL: "__stdcall",
            ida_typeinf.CM_CC_PASCAL: "__pascal",
            ida_typeinf.CM_CC_FASTCALL: "__fastcall",
            ida_typeinf.CM_CC_THISCALL: "__thiscall",
        }
        result["calling_convention"] = cc_names.get(cc, f"cc_{cc:#x}")
    except Exception:
        pass

    try:
        args = []
        for i in range(fi.size()):
            fa = fi[i]
            args.append({"name": fa.name or f"a{i+1}", "type": str(fa.type)})
        result["args"] = args
    except Exception:
        pass

    return result


def _handle_get_func_info(params):
    import idc, ida_funcs
    ea = _resolve_addr(params.get("addr"))
    func = ida_funcs.get_func(ea)
    if not func:
        raise RpcError("NOT_A_FUNCTION", f"No function at {_fmt_addr(ea)}")
    result = {
        "addr": _fmt_addr(func.start_ea),
        "name": idc.get_func_name(func.start_ea) or "",
        "start_ea": _fmt_addr(func.start_ea),
        "end_ea": _fmt_addr(func.end_ea),
        "size": func.size(),
        "is_thunk": bool(func.flags & ida_funcs.FUNC_THUNK),
        "flags": _fmt_addr(func.flags),
        "decompiler_available": _decompiler_available,
        "calling_convention": None, "return_type": None, "args": None,
    }
    if _decompiler_available:
        result.update(_extract_type_info(func.start_ea))
    return result


def _handle_get_imagebase(params):
    import ida_nalt
    return {"imagebase": _fmt_addr(ida_nalt.get_imagebase())}


def _handle_get_bytes(params):
    import ida_bytes
    ea = _resolve_addr(params.get("addr"))
    size = int(params.get("size", 16))
    if size > MAX_READ_BYTES:
        raise RpcError("INVALID_PARAMS", f"size must be <= {MAX_READ_BYTES}")
    raw = ida_bytes.get_bytes(ea, size)
    if raw is None:
        raise RpcError("READ_FAILED", f"Cannot read {size} bytes at {_fmt_addr(ea)}")
    return {
        "addr": _fmt_addr(ea), "size": len(raw),
        "hex": " ".join(f"{b:02X}" for b in raw),
        "raw_b64": base64.b64encode(raw).decode("ascii"),
    }


def _handle_find_bytes(params):
    import ida_bytes, idautils, idaapi
    pattern = params.get("pattern")
    if not pattern:
        raise RpcError("INVALID_PARAMS", "pattern parameter required")
    max_results = min(int(params.get("max_results", DEFAULT_FIND_MAX)), MAX_FIND_RESULTS)
    start_str = params.get("start")
    if start_str:
        ea = _resolve_addr(start_str)
    else:
        segs = list(idautils.Segments())
        ea = segs[0] if segs else 0
    matches = []
    for _ in range(max_results):
        ea = ida_bytes.find_bytes(pattern, ea)
        if ea is None or ea == idaapi.BADADDR:
            break
        matches.append(_fmt_addr(ea))
        ea += 1
    return {"pattern": pattern, "total": len(matches), "matches": matches}


# ─────────────────────────────────────────────
# Modification API
# ─────────────────────────────────────────────

def _handle_set_name(params):
    import idc
    ea = _resolve_addr(params.get("addr"))
    name = params.get("name")
    if not name:
        raise RpcError("INVALID_PARAMS", "name parameter required")
    ok = idc.set_name(ea, name, idc.SN_NOWARN | idc.SN_NOCHECK)
    if not ok:
        raise RpcError("SET_NAME_FAILED", f"Cannot set name at {_fmt_addr(ea)}")
    if _config["analysis"]["auto_save"]:
        save_db()
    return {"ok": True, "addr": _fmt_addr(ea), "name": name}


def _handle_set_comment(params):
    import idc
    ea = _resolve_addr(params.get("addr"))
    comment = params.get("comment", "")
    repeatable = params.get("repeatable", False)
    cmt_type = params.get("type", "line")
    if cmt_type == "func":
        ok = idc.set_func_cmt(ea, comment, repeatable)
    else:
        ok = idc.set_cmt(ea, comment, repeatable)
    if ok == 0 and comment:  # IDA returns 0 on failure
        raise RpcError("SET_COMMENT_FAILED", f"Cannot set comment at {_fmt_addr(ea)}")
    if _config["analysis"]["auto_save"]:
        save_db()
    return {"ok": True, "addr": _fmt_addr(ea)}


def _handle_get_comments(params):
    import idc
    ea = _resolve_addr(params.get("addr"))
    return {
        "addr": _fmt_addr(ea),
        "comment": idc.get_cmt(ea, False) or "",
        "repeatable_comment": idc.get_cmt(ea, True) or "",
        "func_comment": idc.get_func_cmt(ea, False) or "",
    }


def _handle_save_db(params):
    import ida_loader
    ok = save_db()
    idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    return {"ok": bool(ok), "idb_path": idb}


def _handle_exec(params):
    if not _config["security"]["exec_enabled"]:
        raise RpcError("EXEC_DISABLED",
                        "exec is disabled in config (security.exec_enabled=false)",
                        suggestion="Set security.exec_enabled to true in config.json")
    code = params.get("code")
    if not code:
        raise RpcError("INVALID_PARAMS", "code parameter required")
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout_buf), \
             contextlib.redirect_stderr(stderr_buf):
            exec(code, {"__builtins__": __builtins__})
    except Exception as e:
        stderr_buf.write(f"{type(e).__name__}: {e}\n")
    saved_to = _save_output(params.get("output"), stdout_buf.getvalue())
    return {
        "stdout": stdout_buf.getvalue(),
        "stderr": stderr_buf.getvalue(),
        "saved_to": saved_to,
    }


# ─────────────────────────────────────────────
# Dispatch + Methods
# ─────────────────────────────────────────────

_METHODS = {
    "ping": lambda p: _handle_ping(),
    "status": lambda p: _handle_status(),
    "stop": lambda p: _handle_stop(),
    "methods": lambda p: _handle_methods(),
    "get_functions": _handle_get_functions,
    "get_strings": _handle_get_strings,
    "get_imports": _handle_get_imports,
    "get_exports": _handle_get_exports,
    "get_segments": _handle_get_segments,
    "decompile": _handle_decompile,
    "decompile_batch": _handle_decompile_batch,
    "disasm": _handle_disasm,
    "get_xrefs_to": _handle_get_xrefs_to,
    "get_xrefs_from": _handle_get_xrefs_from,
    "find_func": _handle_find_func,
    "get_func_info": _handle_get_func_info,
    "get_imagebase": _handle_get_imagebase,
    "get_bytes": _handle_get_bytes,
    "find_bytes": _handle_find_bytes,
    "set_name": _handle_set_name,
    "set_comment": _handle_set_comment,
    "get_comments": _handle_get_comments,
    "save_db": _handle_save_db,
    "exec": _handle_exec,
}

_METHOD_DESCRIPTIONS = [
    ("ping", "Check server liveness"),
    ("status", "Get instance status"),
    ("stop", "Gracefully stop instance"),
    ("methods", "List available APIs"),
    ("get_functions", "List functions"),
    ("get_strings", "List strings"),
    ("get_imports", "List imports"),
    ("get_exports", "List exports"),
    ("get_segments", "List segments"),
    ("decompile", "Decompile a function"),
    ("decompile_batch", "Batch decompile multiple functions"),
    ("disasm", "Disassemble instructions"),
    ("get_xrefs_to", "Cross-references to an address"),
    ("get_xrefs_from", "Cross-references from an address"),
    ("find_func", "Search function by name"),
    ("get_func_info", "Get detailed function info"),
    ("get_imagebase", "Get binary base address"),
    ("get_bytes", "Read raw bytes"),
    ("find_bytes", "Search byte pattern"),
    ("set_name", "Rename a symbol"),
    ("set_comment", "Set a comment"),
    ("get_comments", "Get comments"),
    ("save_db", "Save database"),
    ("exec", "Execute Python code"),
]


def _dispatch(method, params):
    handler = _METHODS.get(method)
    if not handler:
        raise RpcError("UNKNOWN_METHOD", f"Unknown method: {method}",
                        suggestion="Call 'methods' to list available APIs")
    return handler(params)


def _handle_methods():
    return {
        "methods": [{"name": n, "description": d} for n, d in _METHOD_DESCRIPTIONS]
    }


class RpcHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        host_header = self.headers.get("Host", "")
        port = _server.server_address[1]
        allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if host_header not in allowed:
            self._send_json({"error": {"code": "FORBIDDEN_HOST",
                             "message": "Invalid Host header"}, "id": None})
            return

        auth = self.headers.get("Authorization", "")
        if auth != f"Bearer {_auth_token}":
            self._send_json({"error": {"code": "AUTH_FAILED",
                             "message": "Invalid or missing auth token"}, "id": None})
            return

        req_id = None
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            if content_len == 0:
                raise ValueError("Empty request body")
            body = json.loads(self.rfile.read(content_len))
            method = body.get("method")
            if not method:
                raise ValueError("Missing 'method' field")
            params = body.get("params", {})
            req_id = body.get("id", 1)

            result = _dispatch(method, params)
            self._send_json({"result": result, "id": req_id})
        except RpcError as e:
            self._send_json({"error": {"code": e.code, "message": e.message,
                             "suggestion": e.suggestion}, "id": req_id})
        except (json.JSONDecodeError, ValueError) as e:
            self._send_json({"error": {"code": "INVALID_PARAMS",
                             "message": f"Malformed request: {e}"}, "id": req_id})
        except Exception as e:
            log.exception("Unhandled exception in dispatch")
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
        pass  # Suppress BaseHTTPRequestHandler logs (using RotatingFileHandler instead)


# ─────────────────────────────────────────────
# Heartbeat
# ─────────────────────────────────────────────

def _heartbeat_loop(instance_id, interval):
    while _keep_running:
        time.sleep(interval)
        if _keep_running:
            _update_registry(instance_id, {"last_heartbeat": time.time()})


# ─────────────────────────────────────────────
# Decompiler plugin load
# ─────────────────────────────────────────────

_decompiler_available = False


def _load_decompiler():
    """Load Hex-Rays decompiler plugin (IDA 9.x unified plugin names)."""
    global _decompiler_available
    import ida_ida, ida_idp, ida_loader, ida_hexrays

    # IDA 9.x: unified plugins — no separate 32/64-bit variants
    _PLFM_MAP = {
        ida_idp.PLFM_386:   "hexx64",
        ida_idp.PLFM_ARM:   "hexarm",
        ida_idp.PLFM_PPC:   "hexppc",
        ida_idp.PLFM_MIPS:  "hexmips",
        ida_idp.PLFM_RISCV: "hexrv",
    }

    cpu_id = ida_idp.ph.id
    proc_name = ida_ida.inf_get_procname()
    is_64 = ida_ida.inf_is_64bit()
    plugin_name = _PLFM_MAP.get(cpu_id)

    log.info(f"Processor: '{proc_name}', ph.id={cpu_id}, 64bit={is_64}")

    if not plugin_name:
        log.warning(f"No decompiler for: proc='{proc_name}' ph.id={cpu_id}")
        return

    log.info(f"Loading decompiler plugin: {plugin_name}")
    if ida_loader.load_plugin(plugin_name) and ida_hexrays.init_hexrays_plugin():
        log.info(f"Decompiler loaded: {plugin_name}")
        _decompiler_available = True
    else:
        log.error(f"Decompiler load failed: {plugin_name}")


# ─────────────────────────────────────────────
# Main — step-by-step separation
# ─────────────────────────────────────────────

log = logging.getLogger("ida-headless")


def _setup_logging(log_path, config):
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    handler = RotatingFileHandler(
        log_path,
        maxBytes=config["log"]["max_size_mb"] * 1024 * 1024,
        backupCount=config["log"]["backup_count"],
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    log.addHandler(handler)
    log.setLevel(logging.INFO)


def _register_analyzing(instance_id):
    try:
        import psutil
        pid_ct = psutil.Process(os.getpid()).create_time()
    except Exception:
        pid_ct = None
    _update_registry(instance_id, {
        "state": "analyzing",
        "pid": os.getpid(),
        "pid_create_time": pid_ct,
    })


def _open_database(binary_path, idb_path, fresh):
    import idapro
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)
    if os.path.exists(idb_path) and not fresh:
        log.info(f"Reusing existing .i64: {idb_path}")
        result = idapro.open_database(idb_path, True)
    else:
        idb_prefix = os.path.splitext(idb_path)[0]
        log.info(f"New analysis: {binary_path} -> {idb_prefix}")
        result = idapro.open_database(binary_path, True, args=f"-o{idb_prefix}")
        if result == 0:
            _save_idb_metadata(idb_path, binary_path)
    return result


def _start_http_server(config):
    global _server, _auth_token
    host = config["server"]["host"]
    _server = HTTPServer((host, 0), RpcHandler)
    port = _server.server_address[1]
    log.info(f"HTTP server on {host}:{port}")

    _auth_token = secrets.token_urlsafe(32)
    token_path = config["security"]["auth_token_file"]
    _save_auth_token(token_path, _instance_id, port, _auth_token)
    return port


def main():
    global _start_time, _instance_id, _binary_path, _config, _db_closed

    parser = argparse.ArgumentParser(description="idalib HTTP JSON-RPC server")
    parser.add_argument("binary", help="Path to binary to analyze")
    parser.add_argument("--id", required=True, help="Instance ID")
    parser.add_argument("--idb", required=True, help=".i64 path")
    parser.add_argument("--log", required=True, help="Log file path")
    parser.add_argument("--config", required=True, help="config.json path")
    parser.add_argument("--fresh", action="store_true", help="Force fresh analysis")
    args = parser.parse_args()

    _instance_id = args.id
    _binary_path = os.path.abspath(args.binary)
    _start_time = time.time()

    # ── config + logging ──
    _config = load_config(args.config)
    init_registry_paths(_config)
    _setup_logging(args.log, _config)
    log.info(f"=== ida_server start: id={_instance_id} binary={_binary_path} ===")

    # ── registry: analyzing ──
    _register_analyzing(_instance_id)

    # ── watchdog ──
    open_db_timeout = _config["analysis"]["open_db_timeout"]
    open_db_done = threading.Event()

    def watchdog():
        if open_db_done.wait(timeout=open_db_timeout):
            return
        log.error(f"open_database timeout ({open_db_timeout}s). Forcing exit.")
        _update_state(_instance_id, "error")
        os._exit(1)

    threading.Thread(target=watchdog, daemon=True).start()

    # ── open database ──
    try:
        result = _open_database(_binary_path, args.idb, args.fresh)
    except TypeError as e:
        log.error(f"open_database failed (IDA 9.1+ required for args parameter): {e}")
        _update_state(_instance_id, "error")
        sys.exit(1)

    open_db_done.set()

    if result != 0:
        log.error(f"open_database returned {result}")
        _update_state(_instance_id, "error")
        sys.exit(1)

    log.info("open_database succeeded")

    # ── decompiler + initial save ──
    _load_decompiler()
    save_db()

    # ── atexit ──
    import idapro

    def cleanup():
        global _db_closed
        try:
            if not _db_closed:
                idapro.close_database(save=True)
                _db_closed = True
        except Exception:
            pass
        try:
            _remove_from_registry(_instance_id)
        except Exception:
            pass
        try:
            remove_auth_token(_config["security"]["auth_token_file"], _instance_id)
        except Exception:
            pass

    atexit.register(cleanup)

    # ── HTTP server + auth + heartbeat ──
    port = _start_http_server(_config)

    hb_interval = _config["analysis"]["heartbeat_interval"]
    threading.Thread(target=_heartbeat_loop, args=(_instance_id, hb_interval), daemon=True).start()

    # ── registry: ready ──
    _update_registry(_instance_id, {
        "state": "ready",
        "port": port,
        "last_heartbeat": time.time(),
    })

    log.info("Server ready. Waiting for requests...")
    print(f"\n{'='*50}")
    print(f"  ida_server ready")
    print(f"  URL:   http://{_config['server']['host']}:{port}")
    print(f"  Token: {_auth_token}")
    print(f"  ID:    {_instance_id}")
    print(f"{'='*50}\n", flush=True)

    # ── serve (blocking) ──
    _server.serve_forever()

    # ── post-shutdown cleanup ──
    log.info("serve_forever ended. Closing database...")
    if not _db_closed:
        idapro.close_database(save=True)
        _db_closed = True
    _remove_from_registry(_instance_id)
    remove_auth_token(_config["security"]["auth_token_file"], _instance_id)
    log.info("Server stopped normally.")


if __name__ == "__main__":
    main()

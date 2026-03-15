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
MAX_REQUEST_BODY = 1024 * 1024  # 1 MB
STRING_TYPE_UNICODE = 1

# Segment permissions
SEGPERM_READ = 4
SEGPERM_WRITE = 2
SEGPERM_EXEC = 1

# Auto-generated name prefixes (skip during annotation export/script generation)
AUTO_GENERATED_PREFIXES = (
    "sub_", "nullsub_", "loc_", "unk_", "byte_", "word_",
    "dword_", "qword_", "off_", "stru_", "asc_",
)


# ─────────────────────────────────────────────
# Registry helpers (server-specific)
# ─────────────────────────────────────────────

@contextlib.contextmanager
def _registry_lock():
    """Context manager for registry lock acquisition."""
    if not acquire_lock():
        log.warning("Could not acquire registry lock")
        yield False
        return
    try:
        yield True
    finally:
        release_lock()


def _update_registry(instance_id, updates):
    with _registry_lock() as ok:
        if not ok:
            return
        r = load_registry()
        if instance_id in r:
            r[instance_id].update(updates)
            save_registry(r)


def _update_state(instance_id, state):
    _update_registry(instance_id, {"state": state})


def _remove_from_registry(instance_id):
    with _registry_lock() as ok:
        if not ok:
            return
        r = load_registry()
        r.pop(instance_id, None)
        save_registry(r)


# ─────────────────────────────────────────────
# Auth token
# ─────────────────────────────────────────────

def _save_auth_token(token_path, instance_id, port, token):
    with _registry_lock() as ok:
        if not ok:
            log.error("Could not acquire lock for auth_token write")
            return
        os.makedirs(os.path.dirname(token_path), exist_ok=True)
        with open(token_path, "a", encoding="utf-8") as f:
            f.write(f"{instance_id}:{port}:{token}\n")


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

def _require_decompiler():
    """Raise if decompiler is not available."""
    if not _decompiler_available:
        raise RpcError("DECOMPILER_NOT_LOADED", "Decompiler plugin not available")


def _maybe_save_db():
    """Save database if auto_save is enabled."""
    if _config["analysis"]["auto_save"]:
        save_db()


def _require_param(params, key, msg=None):
    """Get a required parameter or raise."""
    val = params.get(key)
    if not val:
        raise RpcError("INVALID_PARAMS", msg or f"{key} parameter required")
    return val


def _clamp_int(params, key, default, max_val):
    """Get an int parameter clamped to max_val."""
    return min(int(params.get(key, default)), max_val)


def _bytes_to_hex(raw):
    """Format bytes as hex string."""
    return " ".join(f"{b:02X}" for b in raw) if raw else ""


def _require_function(ea):
    """Get ida_funcs.get_func(ea) or raise NOT_A_FUNCTION."""
    import ida_funcs
    func = ida_funcs.get_func(ea)
    if not func:
        raise RpcError("NOT_A_FUNCTION", f"No function at {_fmt_addr(ea)}")
    return func


def _parse_type_str(type_str):
    """Parse a C type declaration string. Returns (tinfo_t, success_bool)."""
    import ida_typeinf
    decl = type_str.rstrip(";") + ";"
    tif = ida_typeinf.tinfo_t()
    til = ida_typeinf.get_idati()
    result = ida_typeinf.parse_decl(tif, til, decl, ida_typeinf.PT_SIL)
    return tif, result is not None


def _parse_and_apply_type(ea, type_str):
    """Parse a C type declaration and apply it to an address. Returns tinfo_t."""
    import ida_typeinf
    tif, ok = _parse_type_str(type_str)
    if not ok:
        raise RpcError("PARSE_TYPE_FAILED",
                        f"Cannot parse type declaration: {type_str}",
                        suggestion="Use C syntax, e.g. 'int __fastcall foo(int a, char *b);'")
    if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
        raise RpcError("SET_TYPE_FAILED", f"Cannot apply type at {_fmt_addr(ea)}")
    return tif


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


def _validate_output_path(output_path):
    """Validate output path is under an allowed directory."""
    if not output_path:
        return None
    abspath = os.path.abspath(output_path)
    allowed = _config.get("paths", {}).get("output_dir")
    if allowed:
        if not abspath.startswith(os.path.abspath(allowed) + os.sep):
            raise RpcError("INVALID_PATH",
                           f"Output path must be under {allowed}",
                           suggestion="Set paths.output_dir in config.json or use a path under it")
    return abspath


def _save_output(output_path, content, fmt="text"):
    """Common file save function. fmt: 'text' or 'json'"""
    output_path = _validate_output_path(output_path)
    if not output_path:
        return None
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
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
    func_count = sum(1 for _ in idautils.Functions())
    idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    return {
        "state": "ready",
        "binary": os.path.basename(_binary_path),
        "idb_path": idb,
        "decompiler_available": _decompiler_available,
        "func_count": func_count,
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
    _require_decompiler()
    import ida_hexrays, idc
    ea = _resolve_addr(params.get("addr"))
    func = _require_function(ea)
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


def _handle_decompile_with_xrefs(params):
    """Decompile + xrefs_to in a single call."""
    _require_decompiler()
    import ida_hexrays, idc, idautils
    ea = _resolve_addr(params.get("addr"))
    func = _require_function(ea)
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            raise RpcError("DECOMPILE_FAILED", f"Decompile returned None at {_fmt_addr(ea)}")
        code = str(cfunc)
    except ida_hexrays.DecompilationFailure as e:
        raise RpcError("DECOMPILE_FAILED", str(e))
    name = idc.get_func_name(func.start_ea) or ""
    # Collect xrefs to this function
    callers = []
    for xref in idautils.XrefsTo(func.start_ea):
        callers.append({
            "from_addr": _fmt_addr(xref.frm),
            "from_name": idc.get_func_name(xref.frm) or "",
            "type": _xref_type_str(xref.type),
        })
    # Collect xrefs from this function (callees)
    callees = []
    seen = set()
    for ea_item in idautils.FuncItems(func.start_ea):
        for xref in idautils.XrefsFrom(ea_item):
            target_func = ida_funcs.get_func(xref.to)
            if target_func and target_func.start_ea != func.start_ea:
                if target_func.start_ea not in seen:
                    seen.add(target_func.start_ea)
                    callees.append({
                        "to_addr": _fmt_addr(target_func.start_ea),
                        "to_name": idc.get_func_name(target_func.start_ea) or "",
                        "type": _xref_type_str(xref.type),
                    })
    output = f"// {name} @ {_fmt_addr(func.start_ea)}\n{code}"
    if callers:
        output += f"\n\n// --- Callers ({len(callers)}) ---"
        for c in callers:
            output += f"\n//   {c['from_addr']}  {c['from_name']}  [{c['type']}]"
    if callees:
        output += f"\n\n// --- Callees ({len(callees)}) ---"
        for c in callees:
            output += f"\n//   {c['to_addr']}  {c['to_name']}  [{c['type']}]"
    saved_to = _save_output(params.get("output"), output)
    return {"addr": _fmt_addr(func.start_ea), "name": name,
            "code": code, "callers": callers, "callees": callees,
            "saved_to": saved_to}


def _handle_decompile_batch(params):
    _require_decompiler()
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
    count = _clamp_int(params, "count", DEFAULT_DISASM_COUNT, MAX_DISASM_LINES)
    lines = []
    cur = ea
    for _ in range(count):
        insn = idc.generate_disasm_line(cur, 0)
        if insn is None:
            break
        size = idc.get_item_size(cur) or 1  # prevent size 0
        raw = ida_bytes.get_bytes(cur, size)
        hex_str = _bytes_to_hex(raw)
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
    name = _require_param(params, "name")
    use_regex = params.get("regex", False)
    max_results = _clamp_int(params, "max_results", DEFAULT_SEARCH_MAX, MAX_SEARCH_RESULTS)
    try:
        pattern = re.compile(name) if use_regex else None
    except re.error as e:
        raise RpcError("INVALID_PARAMS", f"Invalid regex: {e}")
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


def _get_segments_info():
    """Collect segment information."""
    import idautils, ida_segment
    segments = []
    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        if seg:
            segments.append({
                "name": ida_segment.get_segm_name(seg),
                "start": _fmt_addr(seg.start_ea),
                "end": _fmt_addr(seg.end_ea),
                "size": seg.size(),
                "perm": _perm_str(seg.perm),
            })
    return segments


def _get_imports_summary():
    """Get import module counts."""
    import ida_nalt
    import_modules = {}
    for i in range(ida_nalt.get_import_module_qty()):
        mod = ida_nalt.get_import_module_name(i) or ""
        count = [0]
        def cb(ea, name, ordinal, _c=count):
            _c[0] += 1
            return True
        ida_nalt.enum_import_names(i, cb)
        import_modules[mod] = count[0]
    top_imports = sorted(import_modules.items(), key=lambda x: -x[1])[:10]
    total = sum(import_modules.values())
    return top_imports, total


def _get_strings_sample(top_count):
    """Get a sample of strings and total count."""
    import idc, idautils
    sample = []
    for i, s in enumerate(idautils.Strings()):
        if i >= top_count:
            break
        val = idc.get_strlit_contents(s.ea, s.length, s.strtype)
        if val:
            try:
                decoded = val.decode("utf-8", errors="replace")
            except Exception:
                decoded = val.hex()
            sample.append({"addr": _fmt_addr(s.ea), "value": decoded[:100]})
    total = sum(1 for _ in idautils.Strings())
    return sample, total


def _get_function_stats():
    """Get function size distribution and largest functions."""
    import idc, idautils, ida_funcs
    sizes = []
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if func:
            sizes.append((func.start_ea, func.size()))
    sizes.sort(key=lambda x: -x[1])
    largest = []
    for ea, size in sizes[:10]:
        largest.append({
            "addr": _fmt_addr(ea),
            "name": idc.get_func_name(ea) or "",
            "size": size,
        })
    all_sizes = [s for _, s in sizes]
    avg = round(sum(all_sizes) / len(all_sizes)) if all_sizes else 0
    return len(sizes), largest, avg


def _handle_summary(params):
    """Return a comprehensive binary overview in one call."""
    import idautils, ida_kernwin
    func_count, largest_funcs, avg_func_size = _get_function_stats()
    segments = _get_segments_info()
    top_imports, total_imports = _get_imports_summary()
    top_count = int(params.get("string_count", 20))
    strings_sample, total_strings = _get_strings_sample(top_count)
    export_count = sum(1 for _ in idautils.Entries())
    return {
        "binary": os.path.basename(_binary_path),
        "decompiler": _decompiler_available,
        "ida_version": ida_kernwin.get_kernel_version(),
        "func_count": func_count,
        "total_strings": total_strings,
        "total_imports": total_imports,
        "export_count": export_count,
        "segments": segments,
        "top_import_modules": [{"module": m, "count": c} for m, c in top_imports],
        "strings_sample": strings_sample,
        "largest_functions": largest_funcs,
        "avg_func_size": avg_func_size,
    }


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
        "hex": _bytes_to_hex(raw),
        "raw_b64": base64.b64encode(raw).decode("ascii"),
    }


def _resolve_start_addr(params, key="start"):
    """Resolve optional start address from params, defaulting to first segment."""
    import idautils
    start_str = params.get(key)
    if start_str:
        return _resolve_addr(start_str)
    segs = list(idautils.Segments())
    return segs[0] if segs else 0


def _handle_find_bytes(params):
    import ida_bytes, idaapi
    pattern = _require_param(params, "pattern")
    max_results = _clamp_int(params, "max_results", DEFAULT_FIND_MAX, MAX_FIND_RESULTS)
    ea = _resolve_start_addr(params)
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
    name = _require_param(params, "name")
    ok = idc.set_name(ea, name, idc.SN_NOWARN | idc.SN_NOCHECK)
    if not ok:
        raise RpcError("SET_NAME_FAILED", f"Cannot set name at {_fmt_addr(ea)}")
    _maybe_save_db()
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
    _maybe_save_db()
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


def _handle_set_type(params):
    ea = _resolve_addr(params.get("addr"))
    type_str = _require_param(params, "type")
    tif = _parse_and_apply_type(ea, type_str)
    _maybe_save_db()
    return {"ok": True, "addr": _fmt_addr(ea), "type": str(tif)}


def _handle_save_db(params):
    import ida_loader
    ok = save_db()
    idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    return {"ok": bool(ok), "idb_path": idb}


# ─────────────────────────────────────────────
# Annotations export/import
# ─────────────────────────────────────────────

def _collect_function_annotations(annotations):
    """Collect names, comments, and types from functions."""
    import idc, idautils
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        if name and not any(name.startswith(p) for p in AUTO_GENERATED_PREFIXES):
            annotations["names"].append({"addr": _fmt_addr(ea), "name": name})
        cmt = idc.get_cmt(ea, False)
        rcmt = idc.get_cmt(ea, True)
        fcmt = idc.get_func_cmt(ea, False)
        if cmt or rcmt or fcmt:
            entry = {"addr": _fmt_addr(ea)}
            if cmt: entry["comment"] = cmt
            if rcmt: entry["repeatable"] = rcmt
            if fcmt: entry["func_comment"] = fcmt
            annotations["comments"].append(entry)
        type_str = idc.get_type(ea)
        if type_str:
            annotations["types"].append({"addr": _fmt_addr(ea), "type": type_str})


def _collect_global_names(annotations):
    """Collect non-function names (globals, data labels)."""
    import idautils, ida_funcs
    for item in idautils.Names():
        ea = item[0]
        name = item[1]
        if not any(name.startswith(p) for p in AUTO_GENERATED_PREFIXES):
            func = ida_funcs.get_func(ea)
            if not func:
                annotations["names"].append({"addr": _fmt_addr(ea), "name": name})


def _handle_export_annotations(params):
    """Export all user-applied names, comments, and types."""
    import idc, ida_nalt
    annotations = {
        "binary": os.path.basename(idc.get_input_file_path()),
        "imagebase": _fmt_addr(ida_nalt.get_imagebase()),
        "names": [],
        "comments": [],
        "types": [],
    }
    _collect_function_annotations(annotations)
    _collect_global_names(annotations)
    saved_to = _save_output(params.get("output"), annotations, fmt="json")
    annotations["saved_to"] = saved_to
    return annotations


def _import_names(data, stats):
    """Import name annotations."""
    import idc
    for entry in data.get("names", []):
        try:
            ea = _resolve_addr(entry["addr"])
            idc.set_name(ea, entry["name"], idc.SN_NOWARN | idc.SN_NOCHECK)
            stats["names"] += 1
        except Exception:
            stats["errors"] += 1


def _import_comments(data, stats):
    """Import comment annotations."""
    import idc
    for entry in data.get("comments", []):
        try:
            ea = _resolve_addr(entry["addr"])
            if "comment" in entry:
                idc.set_cmt(ea, entry["comment"], False)
            if "repeatable" in entry:
                idc.set_cmt(ea, entry["repeatable"], True)
            if "func_comment" in entry:
                idc.set_func_cmt(ea, entry["func_comment"], False)
            stats["comments"] += 1
        except Exception:
            stats["errors"] += 1


def _import_types(data, stats):
    """Import type annotations."""
    import ida_typeinf
    for entry in data.get("types", []):
        try:
            ea = _resolve_addr(entry["addr"])
            tif, ok = _parse_type_str(entry["type"])
            if ok:
                ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
            stats["types"] += 1
        except Exception:
            stats["errors"] += 1


def _handle_import_annotations(params):
    """Import annotations from JSON."""
    data = _require_param(params, "data", "data parameter required (JSON annotations)")
    stats = {"names": 0, "comments": 0, "types": 0, "errors": 0}
    _import_names(data, stats)
    _import_comments(data, stats)
    _import_types(data, stats)
    _maybe_save_db()
    return stats


# ─────────────────────────────────────────────
# Call graph
# ─────────────────────────────────────────────

def _generate_dot_graph(nodes, edges, root_addr):
    """Generate DOT format graph."""
    lines = ["digraph callgraph {", '  rankdir=LR;',
             '  node [shape=box, style=filled, fillcolor="#f0f0f0"];']
    for addr, name in nodes.items():
        color = '#ffcccc' if addr == root_addr else '#f0f0f0'
        label = name.replace('"', '\\"')
        lines.append(f'  "{addr}" [label="{label}", fillcolor="{color}"];')
    for src, dst in edges:
        lines.append(f'  "{src}" -> "{dst}";')
    lines.append("}")
    return "\n".join(lines)


def _generate_mermaid_graph(nodes, edges):
    """Generate Mermaid format graph."""
    lines = ["graph LR"]
    for addr, name in nodes.items():
        safe = name.replace('"', "'")
        lines.append(f'  {addr.replace("0x", "x")}["{safe}"]')
    for src, dst in edges:
        lines.append(f'  {src.replace("0x", "x")} --> {dst.replace("0x", "x")}')
    return "\n".join(lines)


def _collect_call_graph(start_ea, depth, direction, nodes, edges):
    """Recursively collect call graph nodes and edges.

    direction: "callees" or "callers" (single direction per call).
    """
    import idc, ida_funcs, idautils

    def _walk(ea, cur_depth):
        if cur_depth > depth:
            return
        addr_str = _fmt_addr(ea)
        if addr_str in nodes:
            return
        nodes[addr_str] = idc.get_func_name(ea) or addr_str
        if direction == "callees":
            func = ida_funcs.get_func(ea)
            if not func:
                return
            seen = set()
            for item_ea in idautils.FuncItems(func.start_ea):
                for xref in idautils.XrefsFrom(item_ea):
                    target = ida_funcs.get_func(xref.to)
                    if target and target.start_ea != func.start_ea and target.start_ea not in seen:
                        seen.add(target.start_ea)
                        t_addr = _fmt_addr(target.start_ea)
                        edges.append((addr_str, t_addr))
                        _walk(target.start_ea, cur_depth + 1)
        else:  # callers
            for xref in idautils.XrefsTo(ea):
                caller_func = ida_funcs.get_func(xref.frm)
                if caller_func and caller_func.start_ea != ea:
                    c_addr = _fmt_addr(caller_func.start_ea)
                    edges.append((c_addr, addr_str))
                    _walk(caller_func.start_ea, cur_depth + 1)

    _walk(start_ea, 0)


def _handle_callgraph(params):
    """Build call graph starting from a function."""
    ea = _resolve_addr(params.get("addr"))
    depth = _clamp_int(params, "depth", 3, 10)
    direction = params.get("direction", "callees")  # callees, callers, both

    nodes = {}  # addr -> name
    edges = []  # (from_addr, to_addr)

    if direction in ("callees", "both"):
        _collect_call_graph(ea, depth, "callees", nodes, edges)
    if direction in ("callers", "both"):
        _collect_call_graph(ea, depth, "callers", nodes, edges)

    root_addr = _fmt_addr(ea)
    dot = _generate_dot_graph(nodes, edges, root_addr)
    mermaid = _generate_mermaid_graph(nodes, edges)
    saved_to = _save_output(params.get("output"), dot)
    return {
        "root": root_addr,
        "root_name": nodes.get(root_addr, ""),
        "nodes": len(nodes),
        "edges": len(edges),
        "dot": dot,
        "mermaid": mermaid,
        "saved_to": saved_to,
    }


# ─────────────────────────────────────────────
# Binary patching
# ─────────────────────────────────────────────

def _handle_patch_bytes(params):
    """Patch bytes at an address."""
    import ida_bytes, idc
    if not _config["security"]["exec_enabled"]:
        raise RpcError("PATCH_DISABLED",
                        "Patching requires security.exec_enabled=true",
                        suggestion="Set security.exec_enabled to true in config.json")
    ea = _resolve_addr(params.get("addr"))
    hex_str = _require_param(params, "bytes", "bytes parameter required (hex string)")
    try:
        raw = bytes.fromhex(hex_str.replace(" ", ""))
    except ValueError:
        raise RpcError("INVALID_PARAMS", "Invalid hex string")
    # Read original bytes for undo info
    original = ida_bytes.get_bytes(ea, len(raw))
    orig_hex = _bytes_to_hex(original)
    for i, byte_val in enumerate(raw):
        ida_bytes.patch_byte(ea + i, byte_val)
    _maybe_save_db()
    return {
        "addr": _fmt_addr(ea),
        "size": len(raw),
        "original": orig_hex,
        "patched": _bytes_to_hex(raw),
    }


# ─────────────────────────────────────────────
# Search by constant/immediate value
# ─────────────────────────────────────────────

def _handle_search_const(params):
    """Search for immediate/constant values in instructions."""
    import idautils, idc, ida_ua, ida_funcs
    value = params.get("value")
    if value is None:
        raise RpcError("INVALID_PARAMS", "value parameter required")
    target = int(str(value), 0)  # supports hex, decimal, octal
    max_results = _clamp_int(params, "max_results", DEFAULT_SEARCH_MAX, MAX_SEARCH_RESULTS)
    results = []
    for seg_ea in idautils.Segments():
        ea = idc.get_segm_start(seg_ea)
        end = idc.get_segm_end(seg_ea)
        while ea < end and len(results) < max_results:
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, ea)
            if length > 0:
                for op in insn.ops:
                    if op.type == 0:  # o_void
                        break
                    if op.type == ida_ua.o_imm and op.value == target:
                        func = ida_funcs.get_func(ea)
                        results.append({
                            "addr": _fmt_addr(ea),
                            "func": idc.get_func_name(ea) or "" if func else "",
                            "disasm": idc.GetDisasm(ea),
                        })
                        break
                ea += length
            else:
                ea += 1
    saved_to = _save_output(params.get("output"), results, fmt="json")
    return {"value": _fmt_addr(target), "total": len(results), "results": results, "saved_to": saved_to}


# ─────────────────────────────────────────────
# Struct/enum management
# ─────────────────────────────────────────────

def _list_type_info(check_fn, filt, extra_fn=None):
    """List types matching check_fn from the type library, filtered by name substring.

    check_fn(tif) -> bool: type filter (e.g. is_struct, is_enum).
    extra_fn(tif, ordinal) -> dict: extra fields to include per entry.
    """
    import ida_typeinf
    til = ida_typeinf.get_idati()
    result = []
    qty = ida_typeinf.get_ordinal_count(til)
    filt_lower = filt.lower() if filt else ""
    for ordinal in range(1, qty):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(til, ordinal) and check_fn(tif):
            name = tif.get_type_name()
            if not name:
                continue
            if filt_lower and filt_lower not in name.lower():
                continue
            entry = {"ordinal": ordinal, "name": name}
            if extra_fn:
                entry.update(extra_fn(tif, ordinal))
            result.append(entry)
    return result


def _handle_list_structs(params):
    """List all structs/unions in the type library."""
    filt = params.get("filter", "")
    structs = _list_type_info(
        lambda tif: tif.is_struct() or tif.is_union(),
        filt,
        lambda tif, _: {"size": tif.get_size(), "is_union": tif.is_union(),
                         "member_count": tif.get_udt_nmembers()},
    )
    return {"total": len(structs), "structs": structs}


def _handle_get_struct(params):
    """Get struct details with members."""
    import ida_typeinf
    name = _require_param(params, "name")
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(ida_typeinf.get_idati(), name):
        raise RpcError("STRUCT_NOT_FOUND", f"Struct not found: {name}")
    if not (tif.is_struct() or tif.is_union()):
        raise RpcError("NOT_A_STRUCT", f"{name} is not a struct/union")
    members = []
    udt = ida_typeinf.udt_type_data_t()
    if tif.get_udt_details(udt):
        for i in range(udt.size()):
            m = udt[i]
            members.append({
                "offset": m.offset // 8,  # bits to bytes
                "name": m.name,
                "size": m.size // 8,
                "type": str(m.type),
            })
    return {
        "name": name,
        "size": tif.get_size(),
        "is_union": tif.is_union(),
        "members": members,
    }


def _handle_create_struct(params):
    """Create a new struct via type declaration."""
    import ida_typeinf
    name = _require_param(params, "name")
    is_union = params.get("is_union", False)
    members = params.get("members", [])
    keyword = "union" if is_union else "struct"
    if members:
        fields = []
        for m in members:
            mname = m.get("name", "field")
            msize = int(m.get("size", 1))
            mtype = m.get("type", "")
            if mtype:
                fields.append(f"  {mtype} {mname};")
            else:
                size_map = {1: "char", 2: "short", 4: "int", 8: "__int64"}
                ctype = size_map.get(msize)
                if ctype:
                    fields.append(f"  {ctype} {mname};")
                else:
                    fields.append(f"  char {mname}[{msize}];")
        body = "\n".join(fields)
        decl = f"{keyword} {name} {{\n{body}\n}};"
    else:
        decl = f"{keyword} {name} {{ char __placeholder; }};"
    result = ida_typeinf.idc_parse_types(decl, 0)
    if result != 0:
        raise RpcError("CREATE_STRUCT_FAILED", f"Cannot create struct: {decl}")
    _maybe_save_db()
    return {"ok": True, "name": name, "members_added": len(members)}


# ─────────────────────────────────────────────
# Snapshot
# ─────────────────────────────────────────────

def _handle_snapshot_save(params):
    """Save IDB snapshot."""
    import ida_loader, ida_kernwin
    desc = params.get("description", "Snapshot")
    ok = ida_loader.save_database(ida_loader.get_path(ida_loader.PATH_TYPE_IDB), 0)
    # Take snapshot using IDA's snapshot API
    try:
        ss = ida_kernwin.snapshot_t()
        ss.desc = desc
        ok = ida_kernwin.take_database_snapshot(ss)
        return {"ok": bool(ok), "description": desc, "filename": ss.filename if ok else ""}
    except Exception as e:
        # Fallback: just save the IDB as a backup copy
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        import shutil, datetime
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = f"{idb_path}.snapshot_{ts}"
        shutil.copy2(idb_path, backup)
        return {"ok": True, "description": desc, "filename": backup, "method": "file_copy"}


def _handle_snapshot_list(params):
    """List available snapshots."""
    import ida_loader, glob as glob_mod, datetime
    idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    # Find snapshot files
    pattern = f"{idb_path}.snapshot_*"
    snapshots = []
    for f in sorted(glob_mod.glob(pattern)):
        name = os.path.basename(f)
        mtime = os.path.getmtime(f)
        snapshots.append({
            "filename": f,
            "name": name,
            "size": os.path.getsize(f),
            "created": datetime.datetime.fromtimestamp(mtime).isoformat(),
        })
    return {"total": len(snapshots), "snapshots": snapshots}


def _handle_snapshot_restore(params):
    """Restore IDB from a snapshot file."""
    import ida_loader, shutil
    filename = _require_param(params, "filename")
    if not os.path.isfile(filename):
        raise RpcError("FILE_NOT_FOUND", f"Snapshot file not found: {filename}")
    idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    # Backup current before restore
    import datetime
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = f"{idb_path}.before_restore_{ts}"
    shutil.copy2(idb_path, backup)
    shutil.copy2(filename, idb_path)
    return {
        "ok": True,
        "restored_from": filename,
        "backup_of_current": backup,
        "note": "Restart instance to load restored snapshot",
    }


# ─────────────────────────────────────────────
# Enum management
# ─────────────────────────────────────────────

def _handle_list_enums(params):
    """List all enums in the type library."""
    filt = params.get("filter", "")
    enums = _list_type_info(
        lambda tif: tif.is_enum(),
        filt,
        lambda tif, _: {"member_count": tif.get_enum_nmembers()},
    )
    return {"total": len(enums), "enums": enums}


def _handle_get_enum(params):
    """Get enum details with members."""
    import ida_typeinf
    name = _require_param(params, "name")
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(ida_typeinf.get_idati(), name):
        raise RpcError("ENUM_NOT_FOUND", f"Enum not found: {name}")
    if not tif.is_enum():
        raise RpcError("NOT_AN_ENUM", f"{name} is not an enum")
    members = []
    edt = ida_typeinf.enum_type_data_t()
    if tif.get_enum_details(edt):
        for i in range(edt.size()):
            m = edt[i]
            members.append({"name": m.name, "value": m.value})
    return {"name": name, "members": members, "total": len(members)}


def _handle_create_enum(params):
    """Create a new enum via type declaration."""
    import ida_typeinf
    name = _require_param(params, "name")
    members = params.get("members", [])
    if members:
        fields = []
        for m in members:
            mname = m.get("name", "")
            mval = m.get("value", "")
            if mval != "":
                fields.append(f"  {mname} = {mval}")
            else:
                fields.append(f"  {mname}")
        body = ",\n".join(fields)
        decl = f"enum {name} {{\n{body}\n}};"
    else:
        decl = f"enum {name} {{ __placeholder }};"
    result = ida_typeinf.idc_parse_types(decl, 0)
    if result != 0:
        raise RpcError("CREATE_ENUM_FAILED", f"Cannot create enum: {decl}")
    _maybe_save_db()
    return {"ok": True, "name": name, "members_added": len(members)}


# ─────────────────────────────────────────────
# Pseudocode search
# ─────────────────────────────────────────────

def _handle_search_code(params):
    """Search for a string within decompiled pseudocode."""
    _require_decompiler()
    import ida_hexrays, idc, idautils, ida_funcs
    query = _require_param(params, "query")
    case_sensitive = params.get("case_sensitive", False)
    max_results = _clamp_int(params, "max_results", 20, 100)
    max_funcs = _clamp_int(params, "max_funcs", 500, 2000)

    if not case_sensitive:
        query_lower = query.lower()

    results = []
    func_count = 0
    for ea in idautils.Functions():
        if func_count >= max_funcs or len(results) >= max_results:
            break
        func_count += 1
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                continue
            code = str(cfunc)
        except Exception:
            continue
        if case_sensitive:
            match = query in code
        else:
            match = query_lower in code.lower()
        if match:
            name = idc.get_func_name(func.start_ea) or ""
            # Find matching lines
            matching_lines = []
            for i, line in enumerate(code.split("\n")):
                if case_sensitive:
                    if query in line:
                        matching_lines.append({"line_num": i + 1, "text": line.strip()})
                else:
                    if query_lower in line.lower():
                        matching_lines.append({"line_num": i + 1, "text": line.strip()})
            results.append({
                "addr": _fmt_addr(func.start_ea),
                "name": name,
                "matches": matching_lines[:5],  # max 5 lines per function
            })
    saved_to = _save_output(params.get("output"), results, fmt="json")
    return {
        "query": query,
        "total": len(results),
        "functions_scanned": func_count,
        "results": results,
        "saved_to": saved_to,
    }


# ─────────────────────────────────────────────
# Code-level diff (decompile diff)
# ─────────────────────────────────────────────

def _handle_decompile_diff(params):
    """Decompile a function and return code for diffing."""
    _require_decompiler()
    import ida_hexrays, idc
    ea = _resolve_addr(params.get("addr"))
    func = _require_function(ea)
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        code = str(cfunc) if cfunc else ""
    except Exception as e:
        code = f"// Decompile failed: {e}"
    name = idc.get_func_name(func.start_ea) or ""
    size = func.end_ea - func.start_ea
    return {"addr": _fmt_addr(func.start_ea), "name": name, "size": size, "code": code}


# ─────────────────────────────────────────────
# Auto-rename (heuristic)
# ─────────────────────────────────────────────

def _suggest_name_by_string(ea):
    """Strategy 1: Suggest function name based on string references."""
    import idc, idautils
    for item_ea in idautils.FuncItems(ea):
        for xref in idautils.DataRefsFrom(item_ea):
            s = idc.get_strlit_contents(xref)
            if s and len(s) >= 4:
                try:
                    s = s.decode("utf-8", errors="ignore")
                except Exception:
                    s = str(s)
                clean = ""
                for ch in s[:40]:
                    if ch.isalnum() or ch == '_':
                        clean += ch
                    elif ch in (' ', '-', '.', '/'):
                        clean += '_'
                clean = clean.strip('_')
                if clean and len(clean) >= 3 and not clean[0].isdigit():
                    return f"fn_{clean}"
    return None


def _suggest_name_by_api(ea):
    """Strategy 2: Suggest function name based on API calls."""
    import idc, idautils, ida_xref
    _skip_funcs = ("__security_check_cookie", "memset_0", "_guard_dispatch_icall")
    api_calls = []
    for item_ea in idautils.FuncItems(ea):
        for xref in idautils.XrefsFrom(item_ea):
            target_name = idc.get_func_name(xref.to)
            if target_name and not target_name.startswith("sub_") and not target_name.startswith("nullsub_"):
                if xref.type in (ida_xref.fl_CF, ida_xref.fl_CN):
                    api_calls.append(target_name)
    for api in api_calls:
        if api in _skip_funcs:
            continue
        clean = api.split("@")[0].lstrip("?_")
        if clean and len(clean) >= 3:
            return f"calls_{clean[:30]}"
    return None


def _handle_auto_rename(params):
    """Heuristic-based automatic function renaming."""
    import idc, idautils, ida_funcs
    max_funcs = _clamp_int(params, "max_funcs", 200, 1000)
    dry_run = params.get("dry_run", True)

    renames = []
    count = 0
    for ea in idautils.Functions():
        if count >= max_funcs:
            break
        name = idc.get_func_name(ea)
        if not name or not name.startswith("sub_"):
            continue
        count += 1
        func = ida_funcs.get_func(ea)
        if not func:
            continue

        suggested = _suggest_name_by_string(ea) or _suggest_name_by_api(ea)
        if suggested:
            # Ensure unique
            if idc.get_name_ea_simple(suggested) != idc.BADADDR:
                suggested = f"{suggested}_{_fmt_addr(ea).replace('0x', '')}"
            renames.append({
                "addr": _fmt_addr(ea),
                "old_name": name,
                "new_name": suggested,
            })
            if not dry_run:
                idc.set_name(ea, suggested, idc.SN_NOWARN | idc.SN_NOCHECK)

    if not dry_run and renames:
        _maybe_save_db()
    return {"total": len(renames), "dry_run": dry_run, "renames": renames}


# ─────────────────────────────────────────────
# Generate IDAPython script from modifications
# ─────────────────────────────────────────────

def _collect_func_metadata():
    """Single-pass collection of renames, comments, and types from all functions."""
    import idc, idautils, ida_funcs
    rename_lines, comment_lines, type_lines = [], [], []
    for ea in idautils.Functions():
        addr = _fmt_addr(ea)
        name = idc.get_func_name(ea)
        if name and not any(name.startswith(p) for p in AUTO_GENERATED_PREFIXES):
            rename_lines.append(f'idc.set_name({addr}, "{name}", idc.SN_NOWARN)')
        cmt = idc.get_cmt(ea, False)
        if cmt:
            comment_lines.append(f'idc.set_cmt({addr}, {repr(cmt)}, False)')
        rcmt = idc.get_cmt(ea, True)
        if rcmt:
            comment_lines.append(f'idc.set_cmt({addr}, {repr(rcmt)}, True)')
        fcmt = idc.get_func_cmt(ea, False)
        if fcmt:
            comment_lines.append(f'idc.set_func_cmt({addr}, {repr(fcmt)}, False)')
        type_str = idc.get_type(ea)
        if type_str:
            type_lines.append(f'idc.SetType({addr}, "{type_str}")')
    # Non-function names
    for item in idautils.Names():
        ea, name = item[0], item[1]
        if not any(name.startswith(p) for p in AUTO_GENERATED_PREFIXES):
            if not ida_funcs.get_func(ea):
                rename_lines.append(f'idc.set_name({_fmt_addr(ea)}, "{name}", idc.SN_NOWARN)')
    return rename_lines, comment_lines, type_lines


def _handle_export_script(params):
    """Generate reproducible IDAPython script from analysis."""
    rename_lines, comment_lines, type_lines = _collect_func_metadata()
    lines = [
        "#!/usr/bin/env python3",
        '"""Auto-generated IDAPython script from ida-cli analysis."""',
        "import idc",
        "import ida_typeinf",
        "",
    ]
    lines += rename_lines + [""] + comment_lines + [""] + type_lines
    rc, cc, tc = len(rename_lines), len(comment_lines), len(type_lines)
    lines += [
        "",
        f'renames = {rc}',
        f'comments = {cc}',
        f'types = {tc}',
        f'print(f"Applied {{renames}} renames, {{comments}} comments, {{types}} types")',
    ]
    script = "\n".join(lines)
    saved_to = _save_output(params.get("output"), script)
    return {"renames": rc, "comments": cc, "types": tc, "saved_to": saved_to}


# ─────────────────────────────────────────────
# VTable detection
# ─────────────────────────────────────────────

def _handle_detect_vtables(params):
    """Detect virtual function tables in data segments."""
    import idc, idautils, ida_funcs, ida_bytes, ida_segment
    max_results = _clamp_int(params, "max_results", 50, 200)
    min_entries = int(params.get("min_entries", 3))
    ptr_size = 8 if idc.get_inf_attr(idc.INF_LFLAGS) & 1 else 4  # 64-bit check

    vtables = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg:
            continue
        # Only scan data segments (not code)
        perm = seg.perm
        if perm & SEGPERM_EXEC:
            continue
        ea = seg.start_ea
        while ea < seg.end_ea and len(vtables) < max_results:
            # Read pointer
            if ptr_size == 8:
                val = ida_bytes.get_qword(ea)
            else:
                val = ida_bytes.get_dword(ea)
            # Check if it points to a function
            if val and ida_funcs.get_func(val):
                # Count consecutive function pointers
                entries = []
                check_ea = ea
                while check_ea < seg.end_ea:
                    if ptr_size == 8:
                        ptr_val = ida_bytes.get_qword(check_ea)
                    else:
                        ptr_val = ida_bytes.get_dword(check_ea)
                    if ptr_val and ida_funcs.get_func(ptr_val):
                        entries.append({
                            "offset": check_ea - ea,
                            "addr": _fmt_addr(ptr_val),
                            "name": idc.get_func_name(ptr_val) or "",
                        })
                        check_ea += ptr_size
                    else:
                        break
                if len(entries) >= min_entries:
                    vtables.append({
                        "addr": _fmt_addr(ea),
                        "entries": len(entries),
                        "functions": entries[:20],  # limit detail
                    })
                    ea = check_ea  # skip past this vtable
                    continue
            ea += ptr_size
    return {"total": len(vtables), "ptr_size": ptr_size, "vtables": vtables}


# ─────────────────────────────────────────────
# Apply FLIRT signature
# ─────────────────────────────────────────────

def _handle_apply_sig(params):
    """Apply FLIRT signature file."""
    import ida_funcs, idc, idautils
    sig_name = _require_param(params, "name", "name parameter required (signature name without .sig)")
    try:
        import ida_sigmake
    except ImportError:
        pass
    # Use plan_to_apply_idasgn
    import ida_funcs as _idf
    try:
        result = _idf.plan_to_apply_idasgn(sig_name)
        # Count functions before/after
        return {"ok": True, "signature": sig_name, "result": result}
    except Exception as e:
        raise RpcError("APPLY_SIG_FAILED", f"Cannot apply signature: {e}")


def _handle_list_sigs(params):
    """List available FLIRT signature files."""
    import ida_diskio
    sig_dir = ida_diskio.idadir("sig")
    sigs = []
    if os.path.isdir(sig_dir):
        for f in sorted(os.listdir(sig_dir)):
            if f.endswith(".sig"):
                fpath = os.path.join(sig_dir, f)
                sigs.append({
                    "name": f[:-4],
                    "filename": f,
                    "size": os.path.getsize(fpath),
                })
        # Also check architecture subdirs
        for sub in os.listdir(sig_dir):
            sub_path = os.path.join(sig_dir, sub)
            if os.path.isdir(sub_path):
                for f in sorted(os.listdir(sub_path)):
                    if f.endswith(".sig"):
                        fpath = os.path.join(sub_path, f)
                        sigs.append({
                            "name": f"{sub}/{f[:-4]}",
                            "filename": f,
                            "size": os.path.getsize(fpath),
                        })
    return {"total": len(sigs), "sig_dir": sig_dir, "signatures": sigs}


def _handle_exec(params):
    if not _config["security"]["exec_enabled"]:
        raise RpcError("EXEC_DISABLED",
                        "exec is disabled in config (security.exec_enabled=false)",
                        suggestion="Set security.exec_enabled to true in config.json")
    code = _require_param(params, "code")
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
    "decompile_with_xrefs": _handle_decompile_with_xrefs,
    "decompile_batch": _handle_decompile_batch,
    "summary": _handle_summary,
    "disasm": _handle_disasm,
    "get_xrefs_to": _handle_get_xrefs_to,
    "get_xrefs_from": _handle_get_xrefs_from,
    "find_func": _handle_find_func,
    "get_func_info": _handle_get_func_info,
    "get_imagebase": _handle_get_imagebase,
    "get_bytes": _handle_get_bytes,
    "find_bytes": _handle_find_bytes,
    "set_name": _handle_set_name,
    "set_type": _handle_set_type,
    "set_comment": _handle_set_comment,
    "get_comments": _handle_get_comments,
    "save_db": _handle_save_db,
    "exec": _handle_exec,
    "export_annotations": _handle_export_annotations,
    "import_annotations": _handle_import_annotations,
    "callgraph": _handle_callgraph,
    "patch_bytes": _handle_patch_bytes,
    "search_const": _handle_search_const,
    "list_structs": _handle_list_structs,
    "get_struct": _handle_get_struct,
    "create_struct": _handle_create_struct,
    "snapshot_save": _handle_snapshot_save,
    "snapshot_list": _handle_snapshot_list,
    "snapshot_restore": _handle_snapshot_restore,
    "list_enums": _handle_list_enums,
    "get_enum": _handle_get_enum,
    "create_enum": _handle_create_enum,
    "search_code": _handle_search_code,
    "decompile_diff": _handle_decompile_diff,
    "auto_rename": _handle_auto_rename,
    "export_script": _handle_export_script,
    "detect_vtables": _handle_detect_vtables,
    "apply_sig": _handle_apply_sig,
    "list_sigs": _handle_list_sigs,
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
    ("decompile_with_xrefs", "Decompile with caller/callee info"),
    ("decompile_batch", "Batch decompile multiple functions"),
    ("summary", "Get comprehensive binary overview"),
    ("disasm", "Disassemble instructions"),
    ("get_xrefs_to", "Cross-references to an address"),
    ("get_xrefs_from", "Cross-references from an address"),
    ("find_func", "Search function by name"),
    ("get_func_info", "Get detailed function info"),
    ("get_imagebase", "Get binary base address"),
    ("get_bytes", "Read raw bytes"),
    ("find_bytes", "Search byte pattern"),
    ("set_name", "Rename a symbol"),
    ("set_type", "Set function/variable type"),
    ("set_comment", "Set a comment"),
    ("get_comments", "Get comments"),
    ("save_db", "Save database"),
    ("exec", "Execute Python code"),
    ("export_annotations", "Export names/comments/types as JSON"),
    ("import_annotations", "Import annotations from JSON"),
    ("callgraph", "Build function call graph"),
    ("patch_bytes", "Patch bytes at address"),
    ("search_const", "Search for constant/immediate values"),
    ("list_structs", "List structs and unions"),
    ("get_struct", "Get struct details with members"),
    ("create_struct", "Create a new struct"),
    ("snapshot_save", "Save IDB snapshot"),
    ("snapshot_list", "List snapshots"),
    ("snapshot_restore", "Restore IDB from snapshot"),
    ("list_enums", "List enums"),
    ("get_enum", "Get enum details"),
    ("create_enum", "Create a new enum"),
    ("search_code", "Search within decompiled pseudocode"),
    ("decompile_diff", "Decompile function for diffing"),
    ("auto_rename", "Heuristic auto-rename sub_ functions"),
    ("export_script", "Generate IDAPython script from analysis"),
    ("detect_vtables", "Detect virtual function tables"),
    ("apply_sig", "Apply FLIRT signature"),
    ("list_sigs", "List available FLIRT signatures"),
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

        import hmac
        auth = self.headers.get("Authorization", "")
        if not hmac.compare_digest(auth, f"Bearer {_auth_token}"):
            self._send_json({"error": {"code": "AUTH_FAILED",
                             "message": "Invalid or missing auth token"}, "id": None})
            return

        req_id = None
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            if content_len == 0:
                raise ValueError("Empty request body")
            if content_len > MAX_REQUEST_BODY:
                raise ValueError(f"Request body too large ({content_len} bytes, max {MAX_REQUEST_BODY})")
            body = json.loads(self.rfile.read(content_len))
            method = body.get("method")
            if not method:
                raise ValueError("Missing 'method' field")
            params = body.get("params", {})
            req_id = body.get("id", 1)

            t0 = time.time()
            result = _dispatch(method, params)
            elapsed = round((time.time() - t0) * 1000)
            log.info(f"RPC {method} -> OK ({elapsed}ms)")
            self._send_json({"result": result, "id": req_id})
        except RpcError as e:
            log.warning(f"RPC {locals().get('method', '?')} -> {e.code}: {e.message}")
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
        ida_idp.PLFM_386:       "hexx64",
        ida_idp.PLFM_ARM:       "hexarm",
        ida_idp.PLFM_PPC:       "hexppc",
        ida_idp.PLFM_MIPS:      "hexmips",
        ida_idp.PLFM_RISCV:     "hexrv",
        ida_idp.PLFM_NEC_V850X: "hexv850",
        ida_idp.PLFM_ARC:       "hexarc",
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

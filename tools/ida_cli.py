#!/usr/bin/env python3
"""ida_cli.py — IDA Headless CLI entry point for Claude

Usage:
    ida_cli.py start <binary> [--fresh] [--force]
    ida_cli.py stop <id>
    ida_cli.py list
    ida_cli.py [-i <id>] decompile <addr>
    ida_cli.py --help

This is a thin entry point. Implementation is in cli/ package.
"""

import argparse
import os
import sys

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

from common import init_registry_paths

from cli.core import (
    load_config, _merge_project_config, _LIST_COMMANDS, _cmd_proxy_list,
)
from cli.commands import (
    cmd_init, cmd_check, cmd_start, cmd_stop, cmd_wait, cmd_list,
    cmd_status, cmd_logs, cmd_cleanup,
    cmd_proxy_segments, cmd_proxy_decompile, cmd_proxy_decompile_batch,
    cmd_proxy_disasm, cmd_proxy_xrefs, cmd_proxy_find_func,
    cmd_proxy_func_info, cmd_proxy_imagebase, cmd_proxy_bytes,
    cmd_proxy_find_pattern, cmd_proxy_comments, cmd_proxy_methods,
    cmd_proxy_rename, cmd_proxy_set_type, cmd_proxy_comment,
    cmd_proxy_save, cmd_proxy_exec, cmd_proxy_summary,
    cmd_diff, cmd_batch, cmd_bookmark, cmd_profile,
    cmd_report, cmd_shell, cmd_annotations, cmd_callgraph,
    cmd_patch, cmd_search_const, cmd_structs, cmd_snapshot,
    cmd_compare, cmd_enums, cmd_search_code, cmd_code_diff,
    cmd_auto_rename, cmd_export_script, cmd_vtables, cmd_sigs,
    cmd_update, cmd_completions,
)


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

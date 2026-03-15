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

import os
import sys

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

from cli import main

if __name__ == "__main__":
    main()

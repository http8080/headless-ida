#!/usr/bin/env python3
"""ida_server.py — idalib-based HTTP JSON-RPC server

Usage:
    python ida_server.py <binary> --id <instance_id> --idb <idb_path>
                         --log <log_path> --config <config_path> [--fresh]

This is a thin entry point. Implementation is in server/ package.
"""

import os
import sys

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

from server import main

if __name__ == "__main__":
    main()

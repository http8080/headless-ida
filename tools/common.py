"""common.py — Shared module for ida_server.py / ida_cli.py

Collects code commonly used by both modules:
Config loading, Registry management, Lock, and file utilities.
"""

import hashlib
import json
import os
import time

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

STALE_LOCK_TIMEOUT = 5          # seconds before stale lock is forcibly removed
LOCK_POLL_INTERVAL = 0.05       # seconds between lock acquisition retries
DEFAULT_LOCK_TIMEOUT = 1.0      # seconds to wait for lock before giving up
FILE_READ_CHUNK = 8192          # bytes per chunk for file MD5

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

_ENV_VARS = {
    "%USERPROFILE%": "USERPROFILE",
    "%TEMP%": "TEMP",
    "%APPDATA%": "APPDATA",
}


def _expand_env(path):
    for placeholder, var in _ENV_VARS.items():
        if placeholder in path:
            path = path.replace(placeholder, os.environ.get(var, ""))
    return os.path.normpath(path)


def _expand_config(obj):
    if isinstance(obj, str):
        return _expand_env(obj)
    if isinstance(obj, dict):
        return {k: _expand_config(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_config(v) for v in obj]
    return obj


def load_config(config_path):
    """Reads config.json, expands environment variables, and returns the result."""
    with open(config_path, encoding="utf-8") as f:
        raw = json.load(f)
    return _expand_config(raw)


# ─────────────────────────────────────────────
# Registry (lock + load + save)
# ─────────────────────────────────────────────

_registry_path = None
_lock_path = None


def init_registry_paths(config):
    """Initializes registry paths from config."""
    global _registry_path, _lock_path
    _registry_path = config["paths"]["registry"]
    _lock_path = _registry_path + ".lock"


def acquire_lock(timeout=DEFAULT_LOCK_TIMEOUT):
    """Acquires the registry file lock."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            fd = os.open(_lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            return True
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(_lock_path) > STALE_LOCK_TIMEOUT:
                    os.remove(_lock_path)
                    continue
            except OSError:
                pass
            time.sleep(LOCK_POLL_INTERVAL)
    return False


def release_lock():
    """Releases the registry file lock."""
    try:
        os.remove(_lock_path)
    except OSError:
        pass


def load_registry():
    """Reads the registry JSON file and returns it as a dict."""
    try:
        with open(_registry_path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_registry(registry):
    """Saves a registry dict to the JSON file."""
    os.makedirs(os.path.dirname(_registry_path), exist_ok=True)
    with open(_registry_path, "w", encoding="utf-8") as f:
        json.dump(registry, f, ensure_ascii=False, indent=2)


# ─────────────────────────────────────────────
# File utilities
# ─────────────────────────────────────────────

def file_md5(path):
    """Computes the MD5 hash of a file and returns it as a hex string."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(FILE_READ_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ─────────────────────────────────────────────
# Auth token
# ─────────────────────────────────────────────

def remove_auth_token(token_path, instance_id):
    """Removes the auth token for the specified instance from the token file."""
    if not acquire_lock():
        return
    try:
        if not os.path.exists(token_path):
            return
        with open(token_path, encoding="utf-8") as f:
            lines = f.readlines()
        with open(token_path, "w", encoding="utf-8") as f:
            for line in lines:
                if not line.startswith(f"{instance_id}:"):
                    f.write(line)
    except OSError:
        pass
    finally:
        release_lock()

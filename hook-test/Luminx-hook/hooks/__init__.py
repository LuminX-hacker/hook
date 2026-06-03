"""Hook registration and common I/O protocol for Claude Code hooks.

Claude Code hooks communicate via stdin (JSON input) and exit code + stdout (decision):
- Input: JSON from Claude Code via stdin
- Output: exit 0 + optional stdout = allow; exit 2 + stdout reason = block

Protocol:
  exit 0  — permit the tool call
  exit 2  + stdout message — block the tool call, message shown to Claude as error
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Package paths
_HOOKS_DIR = Path(__file__).resolve().parent
_PACKAGE_DIR = _HOOKS_DIR.parent
_CONFIG_DIR = _PACKAGE_DIR / "config"


def read_input() -> dict[str, Any]:
    """Read and parse JSON input from stdin.

    Returns:
        Parsed JSON dict, or empty dict on failure.
    """
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return {}
        return json.loads(raw)
    except (json.JSONDecodeError, OSError):
        return {}


def write_allow() -> None:
    """Output allow decision — exit 0 to permit the tool call."""
    sys.exit(0)


def write_deny(reason: str) -> None:
    """Output deny decision — exit 2 + reason message to block the tool call.

    Claude Code hook protocol: exit 2 + stdout text = deny with message.
    The message on stdout is shown to Claude as tool error output,
    providing the feedback needed to change approach.

    Handles Windows GBK encoding by replacing unencodable characters.

    Args:
        reason: Human-readable explanation for the denial.
    """
    try:
        print(reason, file=sys.stdout)
    except UnicodeEncodeError:
        # Windows GBK stdout can't handle Unicode chars — fall back to ASCII-safe
        safe = reason.encode("ascii", errors="replace").decode("ascii")
        print(safe, file=sys.stdout)
    sys.exit(2)


def load_config(filename: str) -> dict[str, Any]:
    """Load a JSON configuration file from the config/ directory.

    Args:
        filename: Name of the config file (e.g. "critical_destruction.json").

    Returns:
        Parsed JSON dict, or empty dict on failure.
    """
    config_path = _CONFIG_DIR / filename
    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def load_all_configs(*filenames: str) -> dict[str, Any]:
    """Load and merge multiple config files into a single dict.

    Later files override earlier ones for same keys.

    Args:
        filenames: Config file names to load.

    Returns:
        Merged config dict.
    """
    merged: dict[str, Any] = {}
    for filename in filenames:
        data = load_config(filename)
        for key, value in data.items():
            if key.startswith("_"):
                continue  # Skip _comment fields
            if key in merged and isinstance(merged[key], list) and isinstance(value, list):
                merged[key].extend(value)
            else:
                merged[key] = value
    return merged

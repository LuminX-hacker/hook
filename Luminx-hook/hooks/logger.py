"""Interception logging system for Luminx-hook.

Writes structured interception records to JSONL files.
Thread-safe on Windows using msvcrt.locking.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Log directory relative to this package
_HOOKS_DIR = Path(__file__).resolve().parent
_PACKAGE_DIR = _HOOKS_DIR.parent
_LOG_DIR = _PACKAGE_DIR / "logs"
_LOG_FILE = _LOG_DIR / "intercepted.jsonl"


def _ensure_log_dir() -> None:
    """Create log directory if it doesn't exist."""
    _LOG_DIR.mkdir(parents=True, exist_ok=True)


def _sanitize_record(record: dict[str, Any]) -> None:
    """Remove lone surrogates from all string values in a record dict.

    Windows terminals can produce invalid UTF-8 with lone surrogates (U+D800-U+DFFF)
    that cause .encode('utf-8') to crash. We replace them with '?'.
    """
    for key, value in record.items():
        if isinstance(value, str):
            # Replace lone surrogates with replacement character
            record[key] = value.encode("utf-8", errors="replace").decode("utf-8")
        elif isinstance(value, dict):
            _sanitize_record(value)


def log_interception(
    *,
    tool_name: str,
    tool_input: dict[str, Any],
    reason: str,
    severity: str = "high",
    rule_id: str = "",
    matched_pattern: str = "",
) -> None:
    """Record an interception event to the JSONL log file.

    Args:
        tool_name: Name of the tool that was intercepted (e.g. "Bash", "Write").
        tool_input: Original tool input parameters.
        reason: Human-readable explanation of why the operation was blocked.
        severity: Risk level — "critical", "high", "medium", "low".
        rule_id: Identifier of the matching rule from config.
        matched_pattern: The specific pattern/regex that triggered the block.
    """
    _ensure_log_dir()

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool_name": tool_name,
        "tool_input": tool_input,
        "reason": reason,
        "severity": severity,
        "rule_id": rule_id,
        "matched_pattern": matched_pattern,
    }

    # Sanitize strings: replace lone surrogates (Windows terminal garbage)
    _sanitize_record(record)

    line = json.dumps(record, ensure_ascii=False) + "\n"

    try:
        fd = os.open(str(_LOG_FILE), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o644)
        try:
            import msvcrt as _msvcrt
            _msvcrt.locking(fd, _msvcrt.LK_NBLCK, 1)
            os.write(fd, line.encode("utf-8", errors="replace"))
        finally:
            try:
                import msvcrt as _msvcrt2
                _msvcrt2.locking(fd, _msvcrt2.LK_UNLCK, 1)
            except (OSError, ImportError):
                pass
            os.close(fd)
    except (OSError, ImportError):
        # Fallback: best-effort write without locking
        try:
            with open(str(_LOG_FILE), "a", encoding="utf-8", errors="replace") as f:
                f.write(line)
        except OSError:
            pass  # Audit logging is best-effort


def log_crash(
    hook_name: str,
    tool_name: str = "",
    error: str = "",
    command_preview: str = "",
    traceback_text: str = "",
) -> None:
    """Record a hook crash for debugging. Best-effort, never raises."""
    _ensure_log_dir()
    crash_file = _LOG_DIR / "crash.log"
    line = (
        f"\n{'=' * 60}\n"
        f"CRASH at {datetime.now(timezone.utc).isoformat()}\n"
        f"Hook: {hook_name}\n"
        f"Tool: {tool_name}\n"
        f"Error: {error[:500]}\n"
        f"Command: {command_preview[:500]}\n"
        f"Traceback:\n{traceback_text[:3000]}\n"
        f"{'=' * 60}\n"
    )
    try:
        with open(str(crash_file), "a", encoding="utf-8", errors="replace") as f:
            f.write(line)
    except Exception:
        pass  # Last resort — can't log the crash either


def log_audit(
    *,
    tool_name: str,
    tool_input: dict[str, Any],
    result: str = "allowed",
) -> None:
    """Record an audit entry (non-intercepted tool use) for traceability.

    Args:
        tool_name: Name of the tool.
        tool_input: Tool input parameters.
        result: "allowed" or "denied".
    """
    _ensure_log_dir()

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool_name": tool_name,
        "tool_input": tool_input,
        "result": result,
    }
    _sanitize_record(record)

    line = json.dumps(record, ensure_ascii=False) + "\n"

    try:
        audit_file = _LOG_DIR / "audit.jsonl"
        with open(str(audit_file), "a", encoding="utf-8", errors="replace") as f:
            f.write(line)
    except OSError:
        pass


def load_interceptions(
    severity_filter: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Load interception records from the log file.

    Args:
        severity_filter: If set, only return records matching this severity.
        limit: Maximum number of records to return (most recent first).

    Returns:
        List of interception records, newest first.
    """
    if not _LOG_FILE.exists():
        return []

    records: list[dict[str, Any]] = []
    try:
        with open(str(_LOG_FILE), "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    if severity_filter and record.get("severity") != severity_filter:
                        continue
                    records.append(record)
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []

    # Return most recent first, up to limit
    records.reverse()
    return records[:limit]


def clear_interceptions() -> int:
    """Clear all interception records.

    Returns:
        Number of records cleared.
    """
    if not _LOG_FILE.exists():
        return 0

    count = 0
    try:
        with open(str(_LOG_FILE), "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    count += 1
    except OSError:
        pass

    try:
        _LOG_FILE.write_text("", encoding="utf-8")
    except OSError:
        pass

    return count

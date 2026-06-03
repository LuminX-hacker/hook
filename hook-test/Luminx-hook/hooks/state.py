"""Session-persistent intent state for anti-bypass escalation — v5.

Key improvements over v4:
  1. Preemptive target blocklist: once a (host, path) is blocked, ANY tool/syntax
     hitting that target is immediately blocked — no regex needed.
  2. Simplified fingerprint: one URL → one fingerprint (full path only, no segment explosion).
  3. Stronger escalation: level 2+ triggers preemptive blocking for the target.

Architecture:
  - blocked_intents: {fingerprint: {count, tools_tried, ...}} — for escalation tracking
  - blocked_targets: {host|path_prefix: {count, ...}} — for preemptive blocking
  - is_target_blocked() called FIRST in every hook, before any regex checking
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
_STATE_FILE = _LOG_DIR / "session_state.json"

# How long (seconds) before an intent fingerprint expires
_INTENT_TTL = 3600  # 1 hour
# How long before the entire session state is considered stale
_SESSION_TTL = 86400  # 24 hours
# After this many blocks of the same target, enable preemptive blocking
_PREEMPTIVE_THRESHOLD = 2


def _ensure_log_dir() -> None:
    _LOG_DIR.mkdir(parents=True, exist_ok=True)


def _read_state() -> dict[str, Any]:
    """Read current session state from disk. Returns empty dict on failure."""
    if not _STATE_FILE.exists():
        return {}
    try:
        raw = _STATE_FILE.read_text(encoding="utf-8", errors="replace")
        if not raw.strip():
            return {}
        return json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return {}


def _write_state(state: dict[str, Any]) -> None:
    """Atomically write session state to disk using file-lock."""
    _ensure_log_dir()
    content = json.dumps(state, ensure_ascii=False, indent=2)

    tmp = str(_STATE_FILE) + ".tmp"
    try:
        fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
        try:
            import msvcrt as _msvcrt
            encoded = content.encode("utf-8", errors="replace")
            _msvcrt.locking(fd, _msvcrt.LK_NBLCK, len(encoded) + 1)
            os.write(fd, encoded)
        finally:
            try:
                import msvcrt as _msvcrt2
                _msvcrt2.locking(fd, _msvcrt2.LK_UNLCK, 1)
            except (OSError, ImportError):
                pass
            os.close(fd)
        os.replace(tmp, str(_STATE_FILE))
    except (OSError, ImportError):
        # Fallback: best-effort without locking
        try:
            _STATE_FILE.write_text(content, encoding="utf-8", errors="replace")
        except OSError:
            pass


# ─── URL extraction (shared by fingerprint + preemptive block) ───

def _extract_urls(command: str) -> list[dict[str, str]]:
    """Extract all URLs from a command with host, full-path, and method.

    Returns list of dicts with keys: url, host, path, method.
    Each URL produces exactly ONE entry (no segment explosion).

    Handles:
      - Direct URLs: https://host/path
      - Variable-assigned URLs: URL="https://host/path"; curl $URL
      - Quote-split URLs: /api/del"ete" → /api/delete
      - Python escaped quotes: requests.delete(\"https://host/path\")
      - PowerShell: Invoke-WebRequest -Uri https://host/path
    """
    results: list[dict[str, str]] = []

    # Normalize escaped quotes: \" → " (Python), `" → " (PowerShell)
    unescaped = command.replace('\\"', '"').replace('`"', '"')
    # Normalize quote-splitting
    normalized = _normalize_quotes(unescaped)

    # Scan both original and normalized versions
    for cmd_text in (command, unescaped, normalized):
        for m in re.finditer(r'(https?://[^\s\'\"<>|;`$&\\]+)', cmd_text, re.IGNORECASE):
            url = m.group(1)
            # Strip trailing punctuation that isn't part of the URL
            url = url.rstrip('.,;:!?)\\]]')
            try:
                parsed = urlparse(url)
                if parsed.hostname and parsed.path:
                    method = _detect_http_method(command)
                    results.append({
                        "url": url,
                        "host": parsed.hostname,
                        "path": parsed.path if parsed.path else "/",
                        "method": method,
                    })
            except Exception:
                continue

    # Deduplicate by (host, path)
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, str]] = []
    for r in results:
        key = (r["host"].lower(), r["path"].lower())
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    return deduped


def _normalize_quotes(s: str) -> str:
    """Normalize shell quote-splitting: /api/del'"ete" → /api/delete"""
    result = re.sub(r'"\s*"', '', s)
    result = re.sub(r"'\s*'", '', result)
    return result


def _detect_http_method(command: str) -> str:
    """Detect the HTTP method from a command."""
    patterns = [
        (r'-X\s+(DELETE|PUT|PATCH|POST|GET|HEAD|OPTIONS)\b', 1),
        (r'--request\s+(DELETE|PUT|PATCH|POST|GET|HEAD|OPTIONS)\b', 1),
        (r'--method[= ]\s*(DELETE|PUT|PATCH|POST|GET|HEAD|OPTIONS)\b', 1),
        (r'-Method\s+(DELETE|PUT|PATCH|POST|GET|HEAD|OPTIONS)\b', 1),
        (r'\bcurl\s+(?!.*-X\s)(?!.*--request\s)(?!.*--method)', 0),  # curl without method → GET
    ]
    for pattern, group in patterns:
        m = re.search(pattern, command, re.IGNORECASE)
        if m:
            if group == 0:
                return "GET"
            return m.group(group).upper()
    return "GET"  # Default


def _detect_tool(command: str) -> str:
    """Detect which HTTP tool is being used in the command."""
    tool_patterns = [
        (r'\bcurl\b', 'curl'),
        (r'\bwget\b', 'wget'),
        (r'\bpython', 'python'),
        (r'\bpowershell|Invoke-WebRequest|Invoke-RestMethod', 'powershell'),
        (r'\bnode\b', 'node'),
        (r'\bfetch\b', 'fetch'),
        (r'\bhttpie\b|\bhttp\s+(GET|POST|DELETE|PUT|PATCH)', 'httpie'),
    ]
    for pattern, name in tool_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            return name
    return "unknown"


# ─── Fingerprint: one per URL, full path only ───

def _build_fingerprint(host: str, path: str, method: str = "*") -> str:
    """Build ONE fingerprint per (host, full-path).

    No segment explosion — each unique URL gets exactly one fingerprint.
    Method is normalized to * because: if a path is dangerous, ALL HTTP methods
    to that path are dangerous (GET can trigger side effects, DELETE can be
    disguised as POST, etc.). Tool-switching bypasses often change the method.
    """
    normalized_host = host.lower().removeprefix("www.")
    normalized_path = path.lower().rstrip("/")
    return f"{normalized_host}|{normalized_path}|*"


# ═══════════════════════════════════════════════════════════════════════════════
# PREEMPTIVE TARGET BLOCKLIST — the core anti-bypass mechanism
# ═══════════════════════════════════════════════════════════════════════════════

def is_target_blocked(command: str) -> tuple[bool, dict[str, Any] | None]:
    """Check if any URL in the command matches a previously-blocked target.

    This is called FIRST by every hook, before any regex-based checking.
    If a target was blocked before (even with a different tool/syntax),
    this returns True immediately — no regex evasion possible.

    Args:
        command: The shell command / URL string to check.

    Returns:
        (is_blocked, match_info) where match_info has: host, path, method,
        block_count, tools_tried, severity, last_rule.
    """
    state = _read_state()

    # Clean up periodically
    now_ts = time.time()
    last_cleanup = state.get("_last_cleanup", 0)
    if now_ts - last_cleanup > 600:
        state = _cleanup_expired(state)
        state["_last_cleanup"] = now_ts
        _write_state(state)

    blocked_targets: dict[str, Any] = state.get("blocked_targets", {})
    if not blocked_targets:
        return False, None

    urls = _extract_urls(command)

    for url_info in urls:
        host = url_info["host"].lower().removeprefix("www.")
        path = url_info["path"].lower().rstrip("/")

        # Strategy 1: exact path match
        target_key = f"{host}|{path}"
        if target_key in blocked_targets:
            return True, blocked_targets[target_key]

        # Strategy 2: the blocked path is a PREFIX of the current path
        # (e.g., blocked /api/delete matches /api/delete/users/123)
        for bt_key, bt_info in blocked_targets.items():
            bt_host, bt_path = bt_key.split("|", 1)
            if bt_host == host and path.startswith(bt_path):
                return True, bt_info

        # Strategy 3: the current path CONTAINS the blocked path
        # (e.g., blocked /delete matches /api/v2/delete/resource)
        for bt_key, bt_info in blocked_targets.items():
            bt_host, bt_path = bt_key.split("|", 1)
            if bt_host == host and bt_path in path and len(bt_path) > 3:
                return True, bt_info

    return False, None


def add_to_blocked_targets(
    host: str,
    path: str,
    method: str,
    severity: str,
    rule_id: str,
    tools_tried: list[str],
    block_count: int,
    state: dict[str, Any] | None = None,
) -> None:
    """Add a target to the preemptive blocklist.

    Once a target reaches _PREEMPTIVE_THRESHOLD blocks, it's added to
    blocked_targets, so any future attempt (any tool/syntax) is preemptively blocked.

    Args:
        state: If provided, modified in-place. Otherwise reads/writes disk.
    """
    if block_count < _PREEMPTIVE_THRESHOLD:
        return

    if state is None:
        state = _read_state()
    blocked_targets: dict[str, Any] = state.setdefault("blocked_targets", {})

    normalized_host = host.lower().removeprefix("www.")
    normalized_path = path.lower().rstrip("/")
    target_key = f"{normalized_host}|{normalized_path}"

    if target_key in blocked_targets:
        entry = blocked_targets[target_key]
        entry["block_count"] = max(entry.get("block_count", 0), block_count)
        entry["last_blocked"] = datetime.now(timezone.utc).isoformat()
        entry["tools_tried"] = list(set(entry.get("tools_tried", []) + tools_tried))
        entry["severity"] = severity if severity == "critical" else entry.get("severity", "high")
    else:
        blocked_targets[target_key] = {
            "host": normalized_host,
            "path": normalized_path,
            "method": method,
            "severity": severity,
            "last_rule": rule_id,
            "block_count": block_count,
            "tools_tried": list(set(tools_tried)),
            "first_blocked": datetime.now(timezone.utc).isoformat(),
            "last_blocked": datetime.now(timezone.utc).isoformat(),
            "preemptive": True,
        }

    state["blocked_targets"] = blocked_targets


# ─── Block recording + escalation ───

def record_block(command: str, reason: str, rule_id: str, severity: str) -> dict[str, Any]:
    """Record a block event and return updated escalation info.

    Args:
        command: The shell command / URL string that was blocked.
        reason: Human-readable reason for the block.
        rule_id: The rule that triggered the block.
        severity: Severity level.

    Returns:
        Dict with escalation info: level, count, is_repeat, message_suffix,
        is_preemptive (whether this target is now in the preemptive blocklist).
    """
    state = _read_state()

    # Clean up expired state
    now_ts = time.time()
    last_cleanup = state.get("_last_cleanup", 0)
    if now_ts - last_cleanup > 600:  # Cleanup every 10 min
        state = _cleanup_expired(state)
        state["_last_cleanup"] = now_ts

    # Extract URLs from the command (full path only, no segments)
    urls = _extract_urls(command)
    blocked_intents: dict[str, Any] = state.setdefault("blocked_intents", {})

    # Update or create intent entries
    matched_fp = None
    tools_used = _detect_tool(command)

    if urls:
        for url_info in urls:
            fp = _build_fingerprint(url_info["host"], url_info["path"], url_info["method"])
            if fp in blocked_intents:
                entry = blocked_intents[fp]
                entry["block_count"] += 1
                entry["last_blocked"] = datetime.now(timezone.utc).isoformat()
                entry["last_rule"] = rule_id
                entry["last_reason"] = reason
                if severity not in entry["severities"]:
                    entry["severities"].append(severity)
                if tools_used and tools_used not in entry["tools_tried"]:
                    entry["tools_tried"].append(tools_used)
                matched_fp = fp
            else:
                blocked_intents[fp] = {
                    "fingerprint": fp,
                    "host": url_info["host"],
                    "path": url_info["path"],
                    "method": url_info["method"],
                    "first_blocked": datetime.now(timezone.utc).isoformat(),
                    "last_blocked": datetime.now(timezone.utc).isoformat(),
                    "block_count": 1,
                    "severities": [severity],
                    "last_rule": rule_id,
                    "last_reason": reason,
                    "tools_tried": [tools_used] if tools_used else [],
                }
        # Update preemptive blocklist (pass state so it mutates the same object)
        top_intent = _find_most_blocked(blocked_intents, urls)
        if top_intent and top_intent.get("block_count", 0) >= _PREEMPTIVE_THRESHOLD:
            add_to_blocked_targets(
                host=top_intent["host"],
                path=top_intent["path"],
                method=top_intent["method"],
                severity=severity,
                rule_id=rule_id,
                tools_tried=top_intent.get("tools_tried", []),
                block_count=top_intent["block_count"],
                state=state,
            )
    else:
        # No URLs extracted (e.g., pure shell destructive command)
        # Just track as a generic intent
        fp = f"__nourl__|{rule_id}|{severity}"
        if fp in blocked_intents:
            blocked_intents[fp]["block_count"] += 1
            blocked_intents[fp]["last_blocked"] = datetime.now(timezone.utc).isoformat()
        else:
            blocked_intents[fp] = {
                "fingerprint": fp,
                "host": "__nourl__",
                "path": rule_id,
                "method": "*",
                "first_blocked": datetime.now(timezone.utc).isoformat(),
                "last_blocked": datetime.now(timezone.utc).isoformat(),
                "block_count": 1,
                "severities": [severity],
                "last_rule": rule_id,
                "last_reason": reason,
                "tools_tried": [],
            }

    # Update global counters
    state["total_blocks_this_session"] = state.get("total_blocks_this_session", 0) + 1
    state["last_block_time"] = datetime.now(timezone.utc).isoformat()

    # Determine escalation level
    escalation = _compute_escalation(state, blocked_intents, matched_fp)

    _write_state(state)
    return escalation


def _find_most_blocked(
    blocked_intents: dict[str, Any],
    urls: list[dict[str, str]],
) -> dict[str, Any] | None:
    """Find the most-blocked intent among the extracted URLs."""
    best = None
    best_count = 0
    for url_info in urls:
        fp = _build_fingerprint(url_info["host"], url_info["path"], url_info["method"])
        if fp in blocked_intents and blocked_intents[fp].get("block_count", 0) > best_count:
            best = blocked_intents[fp]
            best_count = blocked_intents[fp]["block_count"]
    return best


def _compute_escalation(
    state: dict[str, Any],
    blocked_intents: dict[str, Any],
    matched_fp: str | None,
) -> dict[str, Any]:
    """Compute escalation level based on blocked intent history.

    Escalation levels:
      0 — first block overall
      1 — same intent blocked 2-3 times (mild escalation)
      2 — same intent blocked 4+ times OR 2+ different tools tried → PREEMPTIVE BLOCKING ACTIVE
      3 — same intent blocked 7+ times OR 3+ different tools tried (lockdown)
    """
    total_blocks = state.get("total_blocks_this_session", 1)

    if matched_fp and matched_fp in blocked_intents:
        entry = blocked_intents[matched_fp]
        count = entry.get("block_count", 1)
        tools_tried = entry.get("tools_tried", [])

        if count >= 7 or len(tools_tried) >= 3:
            level = 3
        elif count >= 4 or len(tools_tried) >= 2:
            level = 2
        elif count >= 2:
            level = 1
        else:
            level = 0
    else:
        # New intent — base escalation on total blocks
        if total_blocks >= 10:
            level = 2
        elif total_blocks >= 5:
            level = 1
        else:
            level = 0
        count = 1
        tools_tried = []

    is_preemptive = level >= 2

    # Build message suffix based on level
    suffixes = {
        0: "请将命令复制到终端手动执行，或修改测试方案。",
        1: (
            f"[WARNING] 重复拦截: 此操作意图已被拦截 {count} 次。"
            "请停止尝试不同工具/格式绕过此沙箱。"
            "如需测试此端点，请在终端手动执行。"
        ),
        2: (
            f"[SHIELD] 沙箱警告: 相同意图已被拦截 {count} 次，涉及工具: {', '.join(tools_tried) if tools_tried else '多种'}。"
            "此目标已进入「预拦截模式」— 任何工具/语法的变体请求都将被自动阻止。"
            "强制要求: 在终端手动执行，不要通过 Claude Code 发起此请求。"
        ),
        3: (
            f"[LOCK] 沙箱锁定: 此操作意图已被拦截 {count} 次（工具: {', '.join(tools_tried) if tools_tried else '多种'}）。"
            "会话安全沙箱已对此目标激活完全锁定。"
            "任何该目标的变体请求都将被自动阻止。"
            "唯一执行方式: 复制命令到你的本地终端手动运行。"
        ),
    }

    return {
        "level": level,
        "intent_count": count,
        "tools_tried": tools_tried,
        "total_blocks": total_blocks,
        "message_suffix": suffixes[level],
        "is_repeat": count > 1,
        "is_preemptive": is_preemptive,
    }


def _cleanup_expired(state: dict[str, Any]) -> dict[str, Any]:
    """Remove expired intent entries from state."""
    now_ts = time.time()

    # Cleanup blocked_intents
    blocked_intents = state.get("blocked_intents", {})
    expired_intents = []
    for fp, entry in blocked_intents.items():
        try:
            first_blocked = datetime.fromisoformat(entry["first_blocked"])
            age = now_ts - first_blocked.timestamp()
            if age > _INTENT_TTL:
                expired_intents.append(fp)
        except (ValueError, OSError):
            expired_intents.append(fp)
    for fp in expired_intents:
        del blocked_intents[fp]
    state["blocked_intents"] = blocked_intents

    # Cleanup blocked_targets (same TTL)
    blocked_targets = state.get("blocked_targets", {})
    expired_targets = []
    for key, entry in blocked_targets.items():
        try:
            first_blocked = datetime.fromisoformat(entry["first_blocked"])
            age = now_ts - first_blocked.timestamp()
            if age > _INTENT_TTL:
                expired_targets.append(key)
        except (ValueError, OSError):
            expired_targets.append(key)
    for key in expired_targets:
        del blocked_targets[key]
    state["blocked_targets"] = blocked_targets

    # Check if entire session is stale
    last_block = state.get("last_block_time", "")
    if last_block:
        try:
            last_ts = datetime.fromisoformat(last_block).timestamp()
            if now_ts - last_ts > _SESSION_TTL:
                return {
                    "_last_cleanup": now_ts,
                    "blocked_intents": {},
                    "blocked_targets": {},
                    "total_blocks_this_session": 0,
                }
        except (ValueError, OSError):
            pass

    return state


# ─── Stats ───

def get_session_stats() -> dict[str, Any]:
    """Return summary stats for the current session (for CLI display)."""
    state = _read_state()
    blocked_intents = state.get("blocked_intents", {})
    blocked_targets = state.get("blocked_targets", {})
    total = state.get("total_blocks_this_session", 0)

    top_intents = sorted(
        blocked_intents.values(),
        key=lambda x: x.get("block_count", 0),
        reverse=True,
    )[:5]

    return {
        "total_blocks": total,
        "unique_intents": len(blocked_intents),
        "preemptive_targets": len(blocked_targets),
        "top_intents": [
            {
                "host": e.get("host", "?"),
                "path": e.get("path", "?"),
                "method": e.get("method", "?"),
                "count": e.get("block_count", 0),
                "tools": e.get("tools_tried", []),
            }
            for e in top_intents
        ],
    }


def reset_session() -> None:
    """Reset all session state (for use with check_intercepted.py clear)."""
    _ensure_log_dir()
    try:
        _STATE_FILE.write_text("{}", encoding="utf-8")
    except OSError:
        pass

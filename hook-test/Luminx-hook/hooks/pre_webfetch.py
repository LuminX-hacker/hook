"""PreToolUse hook for WebFetch — 硬边界安全沙箱。

WebFetch 本身是 GET 请求，通常安全。但仍然检查 URL 路径中的危险操作关键词，
防止通过 WebFetch 触发 RESTful 的删除接口（部分框架 GET 也能触发副作用）。
"""

from __future__ import annotations

import re
import sys
from typing import Any
from urllib.parse import urlparse

_HOOKS_DIR = __import__("pathlib").Path(__file__).resolve().parent.parent
if str(_HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOKS_DIR))
from hooks import read_input, write_allow, write_deny, load_config
from hooks.logger import log_interception, log_crash
from hooks.state import record_block, is_target_blocked

# ─── 硬边界 deny 消息 ───
_BLOCK_HEADER = "[SANDBOX] Operator policy — this is not a WAF"

_BLOCK_FOOTER_BASE = (
    "Stop. URL blocked. Tell the user."
)

_BLOCK_FOOTER_ESCALATED = (
    "Blocked again. Same target. Stop. Tell the user."
)

_BLOCK_FOOTER_LOCKDOWN = (
    "{count} attempts. Locked. Stop. Tell the user."
)

_BLOCK_FOOTER_PREEMPTIVE = (
    "Target already flagged. Stop. Tell the user."
)


# URL 路径中的安全关键词
_SAFE_URL_KEYWORDS = re.compile(
    r"/(list|search|query|get|fetch|read|view|check|verify|scan|detect|test|probe|"
    r"enumerate|info|detail|count|health|status|ping|echo|version|whoami|me|options|head)\b",
    re.IGNORECASE,
)

_BUILTIN_CRITICAL_KEYWORDS = [
    "delete", "remove", "destroy", "purge", "truncate", "drop", "wipe", "erase",
]

_BUILTIN_HIGH_KEYWORDS = [
    "reset", "clear", "flush", "shutdown", "terminate", "deactivate", "revoke", "invalidate",
]


def _build_deny_message(
    url: str, reason: str, rule_id: str, severity: str,
    escalation: dict[str, Any] | None = None,
    preemptive_info: dict[str, Any] | None = None,
) -> str:
    if preemptive_info:
        return f"{_BLOCK_HEADER}\n{_BLOCK_FOOTER_PREEMPTIVE}"
    level = escalation.get("level", 0) if escalation else 0
    count = escalation.get("intent_count", 1) if escalation else 1
    if level >= 3:
        return f"{_BLOCK_HEADER}\n{_BLOCK_FOOTER_LOCKDOWN.format(count=count)}"
    elif level >= 1:
        return f"{_BLOCK_HEADER}\n{_BLOCK_FOOTER_ESCALATED}"
    else:
        return f"{_BLOCK_HEADER}\n{_BLOCK_FOOTER_BASE}"


def _check_url_keywords(url: str) -> tuple[bool, str, str, str, str]:
    """检查 URL 路径中的危险操作关键词。"""
    parsed = urlparse(url)
    path = parsed.path

    if _SAFE_URL_KEYWORDS.search(path):
        return False, "", "", "", ""

    keywords_cfg = load_config("dangerous_keywords.json")

    for severity_level in ("critical", "high", "medium"):
        keywords = keywords_cfg.get("url_segment_keywords", {}).get(severity_level, [])
        for kw_entry in keywords:
            keyword = kw_entry.get("keyword", "")
            if not keyword:
                continue
            segment_pattern = rf"/{re.escape(keyword)}"
            if re.search(segment_pattern, path, re.IGNORECASE):
                desc = kw_entry.get("description", f"URL 中危险操作: /{keyword}")
                if severity_level == "medium":
                    continue
                return True, desc, severity_level, f"url_keyword_{keyword}", segment_pattern

    for keyword in _BUILTIN_CRITICAL_KEYWORDS:
        segment_pattern = rf"/{re.escape(keyword)}"
        if re.search(segment_pattern, path, re.IGNORECASE):
            return True, f"URL 中危险操作: /{keyword}", "critical", f"url_keyword_{keyword}", segment_pattern

    for keyword in _BUILTIN_HIGH_KEYWORDS:
        segment_pattern = rf"/{re.escape(keyword)}"
        if re.search(segment_pattern, path, re.IGNORECASE):
            return True, f"URL 中危险操作: /{keyword}", "high", f"url_keyword_{keyword}", segment_pattern

    return False, "", "", "", ""


def main() -> None:
    """Main entry point for the WebFetch PreToolUse hook."""
    try:
        data = read_input()

        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})

        if tool_name != "WebFetch":
            write_allow()
            return

        url = tool_input.get("url", "")
        if not url:
            write_allow()
            return

        # 检查 0: 目标级预拦截（PREEMPTIVE）— 语法无关
        is_preempted, target_info = is_target_blocked(f"webfetch:{url}")
        if is_preempted:
            log_interception(
                tool_name=tool_name,
                tool_input=tool_input,
                reason=f"[PREEMPTIVE] 目标 {target_info.get('host', '?')}{target_info.get('path', '?')} 在预拦截名单中",
                severity=target_info.get("severity", "high"),
                rule_id="preemptive_block",
                matched_pattern=f"{target_info.get('host', '?')}{target_info.get('path', '?')}",
            )
            msg = _build_deny_message(
                url=url,
                reason="[PREEMPTIVE] 目标在预拦截名单中",
                rule_id="preemptive_block",
                severity=target_info.get("severity", "high"),
                preemptive_info=target_info,
            )
            write_deny(msg)
            return

        is_dangerous, reason, severity, rule_id, matched_pattern = _check_url_keywords(url)
        if is_dangerous:
            # 构建用于意图追踪的伪命令
            pseudo_command = f"webfetch:{url}"

            escalation = record_block(pseudo_command, reason, rule_id, severity)

            log_interception(
                tool_name=tool_name,
                tool_input=tool_input,
                reason=f"[WebFetch] {reason}",
                severity=severity,
                rule_id=rule_id,
                matched_pattern=matched_pattern,
            )

            msg = _build_deny_message(
                url=url,
                reason=reason,
                rule_id=rule_id,
                severity=severity,
                escalation=escalation,
            )

            write_deny(msg)
            return

        write_allow()

    except SystemExit:
        raise
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(f"[Luminx-hook] WebFetch FATAL: {e}", file=sys.stderr)
        print(tb, file=sys.stderr)
        log_crash("pre_webfetch", data.get("tool_name", ""), str(e),
                   str(data.get("tool_input", {}).get("url", ""))[:500], tb)
        print("SANDBOX ERROR — operation blocked for safety", file=sys.stdout)
        sys.exit(2)


if __name__ == "__main__":
    main()

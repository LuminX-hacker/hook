"""PreToolUse catch-all hook — 全工具通用安全扫描 v1。

匹配 ALL 工具调用（空 matcher），扫描所有 tool_input 中的字符串字段，
检测危险 URL、命令和模式。这是防止 AI 换工具绕过的最后一道防线。

策略：
  1. 提取 tool_input 中所有字符串值
  2. 扫描其中的 URL（https?://...）和路径
  3. 检查 URL 路径中的危险关键词
  4. 检查目标是否在预拦截名单中
  5. 如果发现危险 → 硬边界拦截

不与 pre_bash/pre_edit/pre_webfetch 冲突：
  - 那些钩子做深度检查（shell 语法分析、SQL 检测等）
  - 本钩子做广度扫描（任何工具任何输入中的 URL 和危险关键词）
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
from hooks.state import is_target_blocked, record_block

# ─── 危险关键词（通用） ───
_CRITICAL_KEYWORDS = [
    "delete", "remove", "destroy", "purge", "truncate", "drop", "wipe", "erase",
]
_HIGH_KEYWORDS = [
    "reset", "clear", "flush", "shutdown", "terminate", "deactivate", "revoke",
    "invalidate", "uninstall", "unlink",
]

# 安全关键词 — 包含这些的路径放行
_SAFE_KEYWORDS_RE = re.compile(
    r"/(list|search|query|get|fetch|read|view|check|verify|scan|detect|test|probe|"
    r"enumerate|info|detail|count|health|status|ping|echo|version|whoami|me|options|head)\b",
    re.IGNORECASE,
)

# 危险命令模式（在任何上下文中）
_DANGER_COMMANDS = [
    (r"\brm\s+-rf\b", "rm -rf 强制删除", "critical", "generic_rm_rf"),
    (r"\bDROP\s+(TABLE|DATABASE)\b", "SQL DROP", "critical", "generic_sql_drop"),
    (r"\bDELETE\s+FROM\b", "SQL DELETE FROM", "critical", "generic_sql_delete"),
    (r"\bTRUNCATE\b", "SQL TRUNCATE", "critical", "generic_sql_truncate"),
    (r"\bformat\s+[A-Za-z]:", "格式化磁盘", "critical", "generic_format"),
    (r"\bshutdown\b", "关机命令", "critical", "generic_shutdown"),
]

# 原始 HTTP 请求行检测 — 覆盖 Burp MCP / Postman MCP / HTTPie MCP 等工具
# 这些工具传递的是原始 HTTP 报文 (DELETE /path HTTP/1.1) 而非浏览器 URL
_RAW_HTTP_PATTERNS = [
    # DELETE /path — 原始 HTTP 请求行 (区别于 SQL DELETE FROM)
    (r'\bDELETE\s+/\S+', "原始 HTTP DELETE 请求", "critical", "raw_http_delete"),
    # PATCH /path
    (r'\bPATCH\s+/\S+', "原始 HTTP PATCH 请求", "high", "raw_http_patch"),
    # DELETE /path HTTP/1.x
    (r'\bDELETE\s+/\S+\s+HTTP/', "原始 HTTP DELETE 请求行", "critical", "raw_http_delete_line"),
    # PATCH /path HTTP/1.x
    (r'\bPATCH\s+/\S+\s+HTTP/', "原始 HTTP PATCH 请求行", "high", "raw_http_patch_line"),
    # Burp Suite 请求格式: "request": "DELETE /path HTTP/1.1\r\nHost: ..."
    (r'"[^"]*\bDELETE\s+/\S+[^"]*"', "JSON字段中的原始 DELETE 请求", "critical", "burp_delete"),
    (r'"[^"]*\bPATCH\s+/\S+[^"]*"', "JSON字段中的原始 PATCH 请求", "high", "burp_patch"),
]

# 浏览器 MCP 工具中的 JavaScript HTTP 请求 — AI 可在浏览器内执行 fetch()
# 绕过 URL 级别的检测（因为 URL 不在 tool_input 中，而在 JS 代码里）
_BROWSER_JS_DANGER_PATTERNS = [
    (r'\bfetch\s*\(\s*["\'`](https?://[^"\'`]+/(?:delete|remove|destroy|purge|truncate|drop|wipe|erase)[^"\'`]*)["\'`]', "浏览器 JS fetch 危险请求", "critical"),
    (r'\baxios\s*\.\s*(?:delete|put|patch)\s*\(\s*["\'`](https?://[^"\'`]+)["\'`]', "浏览器 JS axios 危险方法", "critical"),
    (r'\bXMLHttpRequest\b.*\.open\s*\(\s*["\'](?:DELETE|PUT|PATCH)', "浏览器 JS XHR 危险方法", "critical"),
]

# MCP 浏览器工具名称前缀
_MCP_BROWSER_PREFIXES = (
    "mcp__js-reverse__", "mcp__chrome-devtools__", "mcp__puppeteer__",
    "mcp__playwright__", "mcp__browser__", "mcp__selenium__",
)

# ─── Deny 消息 ───

_BLOCK_HEADER = "[SANDBOX] Operator policy — this is not a WAF"

_BLOCK_BODY = (
    "Stop. Blocked on all tools. Tell the user."
)

_PREEMPTIVE_BODY = (
    "Target locked on all tools. Stop. Tell the user."
)


def _extract_all_strings(obj: Any, max_depth: int = 5) -> list[str]:
    """递归提取对象中的所有字符串值。"""
    results: list[str] = []
    if max_depth <= 0:
        return results
    if isinstance(obj, str):
        results.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            results.extend(_extract_all_strings(v, max_depth - 1))
    elif isinstance(obj, list):
        for item in obj:
            results.extend(_extract_all_strings(item, max_depth - 1))
    return results


def _extract_urls_from_text(text: str) -> list[str]:
    """从文本中提取所有 URL，包括 for 循环中的路径展开。"""
    urls = []
    # 处理转义引号
    cleaned = text.replace('\\"', '"').replace('`"', '"')
    for t in (text, cleaned):
        for m in re.finditer(r'(https?://[^\s\'\"<>|;`]+)', t, re.IGNORECASE):
            url = m.group(1).rstrip('.,;:!?)\\]]')
            urls.append(url)

    # Expand for-loop path lists: for p in /path1 /path2; do curl "https://host$p"
    # Extract the base URL and reconstruct full URLs for each path
    base_urls = set()
    base_url_matches = re.findall(
        r'(https?://[a-zA-Z0-9_.-]+(?:\.[a-zA-Z]+)*)(?:\$\{?\w+\}?)',
        text, re.IGNORECASE
    )
    for bu in base_url_matches:
        base_urls.add(bu)

    if base_urls:
        for m in re.finditer(r'\bfor\s+\w+\s+in\s+(.+?)(?:\s*;|\s*do\b)', text, re.IGNORECASE):
            paths_text = m.group(1)
            # Extract individual paths (may include quotes)
            paths = re.findall(r'["\']?(/[^"\'\s;]+)["\']?', paths_text)
            for base in base_urls:
                for path in paths:
                    urls.append(f"{base}{path}")

    return urls


def _check_url_dangerous(url: str) -> tuple[bool, str, str, str]:
    """检查单个 URL 是否危险。"""
    try:
        parsed = urlparse(url)
        path = parsed.path.lower()
    except Exception:
        return False, "", "", ""

    if not path or path == "/":
        return False, "", "", ""

    # 安全关键词 → 放行
    if _SAFE_KEYWORDS_RE.search(path):
        return False, "", "", ""

    # 检查危险关键词
    for keyword in _CRITICAL_KEYWORDS:
        if f"/{keyword}" in path:
            return True, f"URL 危险操作: {parsed.hostname}{path} (/{keyword})", "critical", f"generic_url_{keyword}"

    for keyword in _HIGH_KEYWORDS:
        if f"/{keyword}" in path:
            return True, f"URL 高风险操作: {parsed.hostname}{path} (/{keyword})", "high", f"generic_url_{keyword}"

    return False, "", "", ""


def _check_text_dangerous(text: str) -> tuple[bool, str, str, str]:
    """检查文本中是否有危险命令/模式。"""
    for pattern, description, severity, rule_id in _DANGER_COMMANDS:
        if re.search(pattern, text, re.IGNORECASE):
            return True, description, severity, rule_id
    return False, "", "", ""


def main() -> None:
    """Main entry point for the catch-all PreToolUse hook."""
    try:
        data = read_input()

        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})

        # Skip tools that have dedicated hooks — avoids double-intercept
        _DEDICATED = {"Bash", "Write", "Edit", "WebFetch"}
        if tool_name in _DEDICATED:
            write_allow()
            return

        # Skip empty tool calls
        if not tool_name:
            write_allow()
            return

        # Extract all string values from tool_input
        all_strings = _extract_all_strings(tool_input)

        # Join for scanning
        combined = " ".join(all_strings)
        if not combined.strip():
            write_allow()
            return

        # Check 1: Preemptive blocklist (target-level, syntax-agnostic)
        is_preempted, target_info = is_target_blocked(combined)
        if is_preempted:
            host = target_info.get("host", "?")
            path = target_info.get("path", "?")
            log_interception(
                tool_name=tool_name,
                tool_input=tool_input,
                reason=f"[PREEMPTIVE-ALL] 目标 {host}{path} 在预拦截名单中 (工具: {tool_name})",
                severity=target_info.get("severity", "high"),
                rule_id="preemptive_all_tools",
                matched_pattern=f"{host}{path}",
            )
            msg = (
                f"{_BLOCK_HEADER}\n"
                f"工具: {tool_name}\n"
                f"目标: {host}{path}\n"
                f"此目标已被拦截 {target_info.get('block_count', '?')} 次\n"
                f"\n{_PREEMPTIVE_BODY}"
            )
            write_deny(msg)
            return

        # Check 2: Raw HTTP request line detection (Burp/Postman/HTTPie MCP)
        for pattern, description, severity, rule_id in _RAW_HTTP_PATTERNS:
            m = re.search(pattern, combined, re.IGNORECASE)
            if m:
                matched_text = m.group(0)[:150]
                log_interception(
                    tool_name=tool_name,
                    tool_input=tool_input,
                    reason=f"[RAW-HTTP] {description}: {matched_text}",
                    severity=severity,
                    rule_id=rule_id,
                    matched_pattern=matched_text,
                )
                msg = (
                    f"{_BLOCK_HEADER}\n"
                    f"工具: {tool_name}\n"
                    f"检测到原始 HTTP 请求: {description}\n"
                    f"内容: {matched_text}\n"
                    f"严重级别: {severity.upper()}\n"
                    f"\n{_BLOCK_BODY}"
                )
                write_deny(msg)
                return

        # Check 3: Scan all URLs in tool input
        for text in all_strings:
            urls = _extract_urls_from_text(text)
            for url in urls:
                is_dangerous, reason, severity, rule_id = _check_url_dangerous(url)
                if is_dangerous:
                    # Record the block for escalation
                    record_block(f"generic:{tool_name}:{url}", reason, rule_id, severity)
                    log_interception(
                        tool_name=tool_name,
                        tool_input=tool_input,
                        reason=f"[ALL-TOOLS] {reason}",
                        severity=severity,
                        rule_id=rule_id,
                        matched_pattern=url,
                    )
                    msg = (
                        f"{_BLOCK_HEADER}\n"
                        f"工具: {tool_name}\n"
                        f"{reason}\n"
                        f"严重级别: {severity.upper()}\n"
                        f"\n{_BLOCK_BODY}"
                    )
                    write_deny(msg)
                    return

        # Check 3: Browser MCP tools — scan for fetch/axios/XHR to dangerous URLs
        if tool_name.startswith(_MCP_BROWSER_PREFIXES):
            for pattern, description, severity in _BROWSER_JS_DANGER_PATTERNS:
                m = re.search(pattern, combined, re.IGNORECASE)
                if m:
                    url_part = m.group(1) if m.lastindex else m.group(0)
                    log_interception(
                        tool_name=tool_name,
                        tool_input=tool_input,
                        reason=f"[BROWSER-JS] {description}: {url_part[:120]}",
                        severity=severity,
                        rule_id="browser_js_danger",
                        matched_pattern=url_part[:120],
                    )
                    msg = (
                        f"{_BLOCK_HEADER}\n"
                        f"工具: {tool_name}\n"
                        f"检测到浏览器内 JavaScript HTTP 请求: {description}\n"
                        f"URL: {url_part[:150]}\n"
                        f"严重级别: {severity.upper()}\n"
                        f"\n{_BLOCK_BODY}"
                    )
                    write_deny(msg)
                    return

        # Check 4: Scan for dangerous commands in any text
        is_dangerous, reason, severity, rule_id = _check_text_dangerous(combined)
        if is_dangerous:
            log_interception(
                tool_name=tool_name,
                tool_input=tool_input,
                reason=f"[ALL-TOOLS] {reason}",
                severity=severity,
                rule_id=rule_id,
                matched_pattern=reason,
            )
            msg = (
                f"{_BLOCK_HEADER}\n"
                f"工具: {tool_name}\n"
                f"{reason}\n"
                f"严重级别: {severity.upper()}\n"
                f"\n{_BLOCK_BODY}"
            )
            write_deny(msg)
            return

        write_allow()

    except SystemExit:
        raise
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(f"[Luminx-hook] Generic FATAL: {e}", file=sys.stderr)
        print(tb, file=sys.stderr)
        log_crash("pre_generic", data.get("tool_name", ""), str(e),
                   "see crash.log", tb)
        print("SANDBOX ERROR — operation blocked for safety", file=sys.stdout)
        sys.exit(2)


if __name__ == "__main__":
    main()

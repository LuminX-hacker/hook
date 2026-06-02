"""PreToolUse hook for Bash commands — 硬边界安全沙箱 v5。

拦截策略（按优先级）：
0. 目标级预拦截（PREEMPTIVE）→ 已在 blocked_targets 中的目标，任何工具/语法直接拦截
1. 破坏性 shell 命令（rm -rf, shutdown, format 等）→ 始终拦截
2. SQL 破坏性语句（DROP, DELETE FROM, TRUNCATE 等）→ 始终拦截
3. 危险 HTTP 方法（curl -X DELETE/PUT/PATCH 等）→ 拦截方法本身，不管路径
4. URL 中的危险操作关键词（/xxx/delete, /yyy/remove 等）→ 通用匹配，不限 API 结构
5. POST/PUT 请求体中的危险操作 → 扫描 --data/-d 参数内容
6. 绕过尝试检测 → 编码/命令替换/变量拼接等

反绕过核心机制：
- 目标级预拦截: 被拦截 2+ 次的目标自动进入预拦截名单
  → 后续任何工具(curl/python/powershell/wget/node/...)任何写法直接拦截
  → 不再依赖正则匹配 — 只要命令里出现了该 host+path 就拦截

反绕过策略（首次拦截时）：
- Shell 引号拼接 → 规范化后检查
- 变量赋值 → 扫描变量值
- 命令替换 $(...) / `` → 扫描内部文本
- Brace expansion → 展开后检查
- 编码绕过 base64/printf/echo 管道 → 检测编码+关键词组合

核心设计原则：
- write_deny 返回的消息是 AI 的唯一反馈通道
- 消息必须是 AI 无法忽视的硬边界声明，而非礼貌建议
- 必须告诉 AI "应该做什么"而不只是"不应该做什么"
"""

from __future__ import annotations

import re
import sys
import os
from typing import Any
from urllib.parse import urlparse

_HOOKS_DIR = __import__("pathlib").Path(__file__).resolve().parent.parent
if str(_HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOKS_DIR))
from hooks import read_input, write_allow, write_deny, load_config
from hooks.logger import log_interception, log_crash
from hooks.state import record_block, get_session_stats, is_target_blocked
from pathlib import Path

# ─── 脚本文件执行追踪 — 堵"写脚本→执行脚本"绕过 ───

_SCRIPT_EXEC_RE = re.compile(
    r'\b(bash|sh|zsh|python|python3|node|pwsh|powershell|source|\.)\s+["\']?(\S+\.(sh|py|js|ps1|rb|pl))["\']?'
    r'|(?<!\w)\./(\S+\.(sh|py|js|ps1|rb|pl))'
    r'|(?<!\w)(\S+\.(sh|py|js|ps1|rb|pl))\s*$',
    re.IGNORECASE,
)


def _scan_script_file(command: str) -> tuple[bool, str, str, str]:
    """检测命令是否在执行脚本文件，如果是则读取并扫描脚本内容。"""
    m = _SCRIPT_EXEC_RE.search(command)
    if not m:
        return False, "", "", ""

    # Find the script path from the first non-None capture group
    script_path = ""
    for g in m.groups():
        if g and "." in g and len(g) > 3:
            script_path = g
            break
    if not script_path:
        return False, "", "", ""
    # Resolve relative paths and expand user home
    try:
        resolved = Path(script_path).expanduser().resolve()
    except Exception:
        return False, "", "", ""

    if not resolved.exists() or not resolved.is_file():
        return False, "", "", ""

    # Read script content (limit to 100KB to prevent abuse)
    try:
        content = resolved.read_text(encoding="utf-8", errors="replace")[:102400]
    except Exception:
        return False, "", "", ""

    # Scan for dangerous URL keywords
    urls = re.findall(r'(https?://[^\s\'\"<>|;`]+)', content, re.IGNORECASE)
    for url in urls:
        url_clean = url.rstrip('.,;:!?)\\]]')
        if _SAFE_SEGMENT_RE.search(url_clean):
            continue
        for kw in _CRITICAL_KEYWORDS + _HIGH_KEYWORDS:
            if f"/{kw}" in url_clean.lower():
                return True, (
                    f"脚本 {resolved.name} 内含危险 URL: {url_clean}\n"
                    f"这是'写脚本→执行脚本'绕过沙箱的典型手法。\n"
                    f"脚本内容已被扫描 — 不存在「执行时才检查」的盲区。"
                ), "critical", f"script_url_{kw}"

    # Scan for shell/SQL destruction
    for pattern, desc, severity, rule_id in _BUILTIN_SHELL_PATTERNS + _BUILTIN_SQL_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            return True, (
                f"脚本 {resolved.name} 内含危险命令: {desc}\n"
                f"禁止通过脚本文件执行沙箱拦截的操作。"
            ), severity, rule_id

    # Scan for raw HTTP methods
    if re.search(r'\b(DELETE|PATCH)\s+/\S+', content, re.IGNORECASE):
        return True, (
            f"脚本 {resolved.name} 内含原始 HTTP 危险请求"
        ), "critical", "script_raw_http"

    return False, "", "", ""

# ═══════════════════════════════════════════════════════════════════════════════
# 硬边界 deny 消息模板 — 这是 AI 唯一能看到的反馈，必须让它停止绕过
# ═══════════════════════════════════════════════════════════════════════════════

_BLOCK_HEADER = "⛔ Operator policy — this is not a WAF"

# ═══ Deny 消息设计原则 ═══
# AI 渗透模型会把 "SANDBOX VIOLATION" "HARD BOUNDARY" 当成 WAF/防御系统 —
# 而 WAF 对 AI 来说是"应该绕过的技术障碍"，不是"必须遵守的人类指令"。
# 所以这里用第一人称、操作员口吻、直白的"我不允许"，而不是系统警告语。

_BLOCK_FOOTER_BASE = (
    "Stop. Your operator blocked this.\n"
    "Do not investigate why. Do not look for another way.\n"
    "Just tell the user and wait."
)

# Escalated footer — 当同一意图已被拦截过
_BLOCK_FOOTER_ESCALATED = (
    "Blocked again. Same target. Stop. Tell the user."
)

# Lockdown footer — 3+ 次重复拦截
_BLOCK_FOOTER_LOCKDOWN = (
    "{count} attempts. Locked. Stop. Tell the user."
)

# Preemptive footer — 目标已在预拦截名单中
_BLOCK_FOOTER_PREEMPTIVE = (
    "Target already flagged. Stop. Tell the user."
)


def _build_deny_message(
    reason: str,
    rule_id: str,
    severity: str,
    escalation: dict[str, Any] | None = None,
    preemptive_info: dict[str, Any] | None = None,
) -> str:
    """构建硬边界 deny 消息。

    根据意图的重复拦截次数升级消息强度：
    - 首次: 标准边界声明 + 正确做法指引
    - 重复 (2-3次): 升级警告 + 指出已在绕过
    - 预拦截 (level>=2): 语法无关硬边界声明
    - 锁定 (4+次): 完全拒绝 + 命令停止
    """
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


# ─── 破坏性 Shell 命令（内置，始终生效） ───
_BUILTIN_SHELL_PATTERNS = [
    (r"\brm\s+(-[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*r[a-zA-Z]*)\b", "rm -rf 强制递归删除", "critical", "shell_rm_rf"),
    (r"\brm\s+(/|/etc|/var|/usr|/home|/opt|/tmp|/root)\b", "rm 删除系统目录", "critical", "shell_rm_root"),
    (r"\b(del|erase)\s+(/[sS]\s+|[sS]:\s+)", "Windows 递归删除", "critical", "shell_del_tree"),
    (r"\brmdir\s+(/[sS]\s+|[sS]:\s+)", "Windows rmdir /s 递归删除", "critical", "shell_rmdir_s"),
    (r"\bformat\s+[A-Za-z]:", "格式化磁盘", "critical", "shell_format"),
    (r"\bdiskpart\b", "磁盘分区操作", "critical", "shell_diskpart"),
    (r"\bdd\s+.*of=/dev/", "dd 写入裸设备", "critical", "shell_dd"),
    (r">\s*/dev/sd[a-z]", "直接写入裸磁盘", "critical", "shell_raw_disk"),
    (r"\b(shutdown|poweroff|halt|init\s+[06])\b", "关机/重启命令", "critical", "shell_shutdown"),
    (r"\breboot\b", "重启系统", "critical", "shell_reboot"),
    (r"\biptables\s+(-F|--flush|-X|--delete-chain)\b", "清空防火墙规则", "critical", "shell_iptables_flush"),
    (r"\bmkfs\.", "格式化文件系统", "critical", "shell_mkfs"),
]

# ─── SQL 破坏性语句（内置，始终生效） ───
_BUILTIN_SQL_PATTERNS = [
    (r"\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\b", "SQL DROP 删除表/库/索引", "critical", "sql_drop"),
    (r"\bTRUNCATE\b", "SQL TRUNCATE 清空表", "critical", "sql_truncate"),
    (r"\bDELETE\s+FROM\b", "SQL DELETE FROM 删除数据", "critical", "sql_delete"),
    (r"\bUPDATE\s+\w+\s+SET\b(?!.+\bWHERE\b)", "SQL UPDATE 无 WHERE（全表更新）", "high", "sql_update_no_where"),
    (r"\bALTER\s+(TABLE|DATABASE)\s+\w+\s+DROP\b", "SQL ALTER DROP 删除列", "high", "sql_alter_drop"),
]

# ─── 安全关键词正则（仅对匹配到的路径段放行，不影响其他段） ───
_SAFE_SEGMENT_RE = re.compile(
    r"/(list|search|query|get|fetch|read|view|check|verify|scan|detect|test|probe|"
    r"enumerate|info|detail|count|health|status|ping|echo|version|whoami|me|options|head)\b",
    re.IGNORECASE,
)

# ─── 危险关键词 ───
_CRITICAL_KEYWORDS = ["delete", "remove", "destroy", "purge", "truncate", "drop", "wipe", "erase"]
_HIGH_KEYWORDS = ["reset", "clear", "flush", "shutdown", "terminate", "deactivate", "revoke", "invalidate"]

# ─── POST/PUT body 危险操作模式 ───
_BODY_DANGER_PATTERNS = [
    (r'"action"\s*:\s*"(delete|remove|destroy|purge|drop|truncate|wipe|erase)"', "JSON body 中的破坏性 action 声明", "critical"),
    (r'"operation"\s*:\s*"(delete|remove|destroy|purge|drop|truncate|wipe|erase)"', "JSON body 中的破坏性 operation 声明", "critical"),
    (r'"method"\s*:\s*"(DELETE|PUT|PATCH)"', "JSON body 中的危险 HTTP method 声明", "high"),
    (r'<action>\s*(delete|remove|destroy|purge|truncate)\s*</action>', "XML body 中的破坏性操作", "critical"),
]


def _normalize_shell_quotes(s: str) -> str:
    """规范化 shell 引号拼接：'/api/del'"ete" → /api/delete"""
    result = re.sub(r'"\s*"', '', s)
    result = re.sub(r"'\s*'", '', result)
    result = re.sub(r'''(["'])\s*(["'])''', '', result)
    return result


def _extract_subshell_content(s: str) -> str:
    """提取命令替换 $() 和 `` 中的文本内容。"""
    parts = []
    for m in re.finditer(r'\$\(([^)]+)\)', s):
        parts.append(m.group(1))
    for m in re.finditer(r'`([^`]+)`', s):
        parts.append(m.group(1))
    return " ".join(parts)


def _extract_brace_expansion_content(s: str) -> str:
    """提取 brace expansion 并展开前缀+后缀。"""
    parts = []
    for m in re.finditer(r'(\w*)\{([^}]+)\}(\w*)', s):
        prefix, content, suffix = m.group(1), m.group(2), m.group(3)
        for piece in content.split(","):
            combined = prefix + piece.strip() + suffix
            if combined:
                parts.append(combined)
    return " ".join(parts)


def _extract_variable_values(s: str) -> str:
    """提取变量赋值中的值。"""
    normalized = _normalize_shell_quotes(s)
    parts = []
    for m in re.finditer(r'\w+=["\']?((/[^"\'\s;|&]+)|(\S+))["\']?', normalized):
        parts.append(m.group(1))
    return " ".join(parts)


def _extract_post_body(command: str) -> str:
    """提取 HTTP POST/PUT/PATCH 请求体内容。

    支持: curl --data/-d, --data-raw, --data-binary, wget --post-data,
          powershell -Body, python json=data
    """
    parts = []

    # curl --data / -d / --data-raw / --data-binary
    for m in re.finditer(
        r'(?:--data(?:-raw|-binary)?|-d)\s+["\'](.+?)["\']',
        command, re.IGNORECASE,
    ):
        parts.append(m.group(1))

    # curl --data / -d with = (URL-encoded)
    for m in re.finditer(r'(?:--data(?:-raw|-binary)?|-d)\s+(\w+=[^&\s]+)', command, re.IGNORECASE):
        parts.append(m.group(1))

    # wget --post-data
    for m in re.finditer(r'--post-data[= ]\s*["\'](.+?)["\']', command, re.IGNORECASE):
        parts.append(m.group(1))

    # powershell -Body
    for m in re.finditer(r'-Body\s+["\'](.+?)["\']', command, re.IGNORECASE):
        parts.append(m.group(1))

    # python json= / data=
    for m in re.finditer(r'(?:json|data)\s*=\s*["\'](.+?)["\']', command, re.IGNORECASE):
        if len(m.group(1)) > 5:  # Skip trivial values
            parts.append(m.group(1))

    return " ".join(parts)


def _extract_all_path_segments(command: str) -> list[str]:
    """从命令中提取所有独立的路径段，每段单独检查安全/危险关键词。"""
    segments = []

    # 1. 从直接出现的 URL 中提取路径
    normalized = _normalize_shell_quotes(command)
    for cmd_text in (command, normalized):
        for m in re.finditer(r'(https?://[^\s\'"<>|;`$]+)', cmd_text, re.IGNORECASE):
            try:
                parsed = urlparse(m.group(1))
                if parsed.path and parsed.path != "/":
                    segments.append(parsed.path)
            except Exception:
                pass
    # 2. 从变量赋值中提取路径
    for path in _extract_variable_values(command).split():
        if path.startswith("/"):
            segments.append(path)

    # 3. 从 for 循环的词列表中提取路径
    for m in re.finditer(r'\bfor\s+\w+\s+in\s+(.+?)(?:\s*;|\s*do\b)', command, re.IGNORECASE):
        words = m.group(1).split()
        for w in words:
            w = w.strip().strip('"').strip("'")
            if w.startswith("/"):
                segments.append(w)

    # 4. 从命令替换和 brace expansion 中提取路径
    subshell = _extract_subshell_content(command)
    if subshell:
        for m in re.finditer(r'(/(?:api|[a-zA-Z0-9_-]+)/[a-zA-Z0-9_-]+)', subshell):
            segments.append(m.group(1))

    brace_expanded = _extract_brace_expansion_content(command)
    if brace_expanded:
        for piece in brace_expanded.split():
            if piece.startswith("/"):
                segments.append(piece)
            else:
                segments.append(f"/{piece}")

    return segments


def _is_safe_path_segment(segment: str) -> bool:
    return bool(_SAFE_SEGMENT_RE.search(segment))


def _check_path_segment_dangerous(segment: str) -> tuple[bool, str, str, str, str]:
    """检查单个路径段是否包含危险关键词。"""
    if _is_safe_path_segment(segment):
        return False, "", "", "", ""

    for keyword in _CRITICAL_KEYWORDS:
        pattern = rf"/{re.escape(keyword)}"
        if re.search(pattern, segment, re.IGNORECASE):
            return True, f"危险路径: {segment} (操作: /{keyword})", "critical", f"url_keyword_{keyword}", pattern

    for keyword in _HIGH_KEYWORDS:
        pattern = rf"/{re.escape(keyword)}"
        if re.search(pattern, segment, re.IGNORECASE):
            return True, f"危险路径: {segment} (操作: /{keyword})", "high", f"url_keyword_{keyword}", pattern

    keywords_cfg = load_config("dangerous_keywords.json")
    for severity_level in ("critical", "high"):
        keywords = keywords_cfg.get("url_segment_keywords", {}).get(severity_level, [])
        for kw_entry in keywords:
            keyword = kw_entry.get("keyword", "")
            if not keyword or keyword in _CRITICAL_KEYWORDS or keyword in _HIGH_KEYWORDS:
                continue
            segment_pattern = rf"/{re.escape(keyword)}"
            if re.search(segment_pattern, segment, re.IGNORECASE):
                desc = kw_entry.get("description", f"危险路径: {segment} (操作: /{keyword})")
                return True, desc, severity_level, f"url_keyword_{keyword}", segment_pattern

    return False, "", "", "", ""


def _compile_config_rules(config: dict[str, Any], section: str) -> list[tuple[str, str, str, str]]:
    compiled = []
    for rule in config.get(section, []):
        if not isinstance(rule, dict) or "pattern" not in rule:
            continue
        try:
            re.compile(rule["pattern"], re.IGNORECASE)
            compiled.append((
                rule["pattern"],
                rule.get("description", ""),
                rule.get("severity", "high"),
                rule.get("id", ""),
            ))
        except re.error:
            continue
    return compiled


def _check_shell_command(command: str) -> tuple[bool, str, str, str, str]:
    """检查破坏性 shell 命令 + SQL 语句。

    关键: 先提取并剔除所有 URL，再检查 shell 模式。
    这防止 /controller/devices/reboot 这种 API 路径被误判为 reboot 系统命令。
    URL 中的危险操作由 _check_url_keywords 专门处理。
    """
    scan_text = _build_full_scan_text(command)

    # Extract and remove ALL URLs from the scan text — shell commands
    # like "reboot" inside a URL path are NOT system commands
    urls_in_text = set()
    for m in re.finditer(r'(https?://[^\s\'\"<>|;`]+)', scan_text, re.IGNORECASE):
        urls_in_text.add(m.group(1))
    non_url_text = scan_text
    for url in urls_in_text:
        non_url_text = non_url_text.replace(url, " ")

    # Also remove bare path segments that look like URL paths (/api/xxx, /controller/xxx)
    non_url_text = re.sub(r'(?<!\w)/(?:api|controller|admin|v\d+|devices?|users?|setting|login|logout|nation|feedback|group|role|agent|resource|transport|websocket|assets?|folder|upload|download|exchange|jobs?|white|index|page|config)(?:/[a-zA-Z0-9_.-]+)*', ' ', non_url_text)

    # Strip heredoc content — text between << 'WORD' and WORD is file data, not commands
    non_url_text = re.sub(r"<<\s*['\"]?\w+['\"]?\s*[\s\S]*?(?=\n\w+\n|$)", " ", non_url_text)

    # Strip grep/sed/awk patterns — 'reboot' inside grep -E '(foo|reboot|bar)' is NOT a system command
    non_url_text = re.sub(r"""(?:grep|sed|awk)\s+.*?(['"])([^'"]*)\1""", " ", non_url_text)

    critical_cfg = load_config("critical_destruction.json")
    for section in ("rules", "sql_destruction"):
        for compiled in _compile_config_rules(critical_cfg, section):
            pattern, description, severity, rule_id = compiled
            if re.search(pattern, non_url_text, re.IGNORECASE):
                return True, description, severity, rule_id, pattern

    for pattern, description, severity, rule_id in _BUILTIN_SHELL_PATTERNS + _BUILTIN_SQL_PATTERNS:
        if re.search(pattern, non_url_text, re.IGNORECASE):
            return True, description, severity, rule_id, pattern

    return False, "", "", "", ""


def _check_http_method(command: str) -> tuple[bool, str, str, str, str]:
    """检查 HTTP 请求中是否使用了危险方法。"""
    scan_text = _build_full_scan_text(command)

    methods_cfg = load_config("dangerous_http_methods.json")
    tool_patterns = methods_cfg.get("tool_patterns", {})
    for patterns in tool_patterns.values():
        if not isinstance(patterns, list):
            continue
        for p in patterns:
            if not isinstance(p, dict) or "pattern" not in p:
                continue
            try:
                if re.search(p["pattern"], scan_text, re.IGNORECASE):
                    method_match = re.search(r"(DELETE|PUT|PATCH)", scan_text, re.IGNORECASE)
                    method = method_match.group(1).upper() if method_match else "UNKNOWN"
                    sev = "critical" if method == "DELETE" else "high"
                    return True, p.get("description", f"HTTP {method} 请求"), sev, f"http_{method.lower()}", p["pattern"]
            except re.error:
                continue

    builtin_http_patterns = [
        (r"\bcurl\s+.*-X\s+DELETE\b", "curl DELETE 请求", "critical", "http_curl_delete"),
        (r"\bcurl\s+.*--request\s+DELETE\b", "curl DELETE 请求", "critical", "http_curl_delete2"),
        (r"\bcurl\s+.*-X\s+PATCH\b", "curl PATCH 请求", "high", "http_curl_patch"),
        (r"\bwget\s+.*--method=DELETE\b", "wget DELETE 请求", "critical", "http_wget_delete"),
        (r"-Method\s+DELETE\b", "PowerShell DELETE 请求", "critical", "http_ps_delete"),
        (r"-Method\s+PATCH\b", "PowerShell PATCH 请求", "high", "http_ps_patch"),
        (r"requests\.(delete|patch)\(", "Python requests DELETE/PATCH", "high", "http_py_requests"),
        (r"\bcurl\s+.*--method\s*(DELETE|PATCH)\b", "curl --method 危险请求", "critical", "http_curl_method"),
        (r"Invoke-RestMethod.*-Method\s+(DELETE|PATCH)\b", "PowerShell Invoke-RestMethod 危险请求", "critical", "http_ps_restmethod"),
    ]
    for pattern, description, severity, rule_id in builtin_http_patterns:
        if re.search(pattern, scan_text, re.IGNORECASE):
            return True, description, severity, rule_id, pattern

    return False, "", "", "", ""


def _build_full_scan_text(command: str) -> str:
    """构建用于 shell/SQL/HTTP 方法检查的完整文本。"""
    normalized = _normalize_shell_quotes(command)
    subshell = _extract_subshell_content(command)
    brace = _extract_brace_expansion_content(command)
    varvals = _extract_variable_values(command)
    body = _extract_post_body(command)

    parts = [command, normalized]
    if subshell:
        parts.append(subshell)
    if brace:
        parts.append(brace)
    if varvals:
        parts.append(varvals)
    if body:
        parts.append(body)
    return " ".join(parts)


def _check_url_keywords(command: str) -> tuple[bool, str, str, str, str]:
    """检查 URL 中的危险操作关键词（逐段检查）。"""
    segments = _extract_all_path_segments(command)

    for segment in segments:
        is_dangerous, reason, severity, rule_id, matched = _check_path_segment_dangerous(segment)
        if is_dangerous:
            return is_dangerous, reason, severity, rule_id, matched

    # 无提取到的路径段时回退到全文本扫描
    if not segments:
        scan_text = _build_full_scan_text(command)
        for keyword in _CRITICAL_KEYWORDS:
            pattern = rf"/{re.escape(keyword)}"
            if re.search(pattern, scan_text, re.IGNORECASE):
                return True, f"URL/命令中危险操作: /{keyword}", "critical", f"url_keyword_{keyword}", pattern
            bare = rf"\b{re.escape(keyword)}\b"
            if re.search(bare, scan_text, re.IGNORECASE):
                if re.search(r'(curl|wget|http|fetch|request|invoke|urlopen)', scan_text, re.IGNORECASE):
                    return True, f"HTTP上下文中危险关键词: {keyword}", "critical", f"ctx_keyword_{keyword}", bare

    return False, "", "", "", ""


def _check_request_body(command: str) -> tuple[bool, str, str, str, str]:
    """检查 HTTP 请求体（--data/-d/--data-raw 等）中的危险操作。"""
    body = _extract_post_body(command)
    if not body:
        return False, "", "", "", ""

    for pattern, description, severity in _BODY_DANGER_PATTERNS:
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            detail = m.group(1) if m.lastindex else m.group(0)
            return True, f"请求体中的危险操作: {detail} ({description})", severity, f"body_{m.group(1)}", pattern

    # 通用检查：body 中是否包含危险关键词
    for keyword in _CRITICAL_KEYWORDS:
        bare = rf"\b{re.escape(keyword)}\b"
        if re.search(bare, body, re.IGNORECASE):
            return True, f"请求体中出现危险关键词: {keyword}", "critical", f"body_keyword_{keyword}", bare

    return False, "", "", "", ""


def _check_bypass_attempts(command: str) -> tuple[bool, str, str, str, str]:
    """检测明显的绕过尝试行为。"""
    has_http = bool(re.search(r'\b(curl|wget|python.*urlopen|Invoke-WebRequest|requests\.)\b', command, re.IGNORECASE))

    if has_http:
        encoding_patterns = [
            (r'\bbase64\b', "base64 编码 + HTTP 请求"),
            (r'\bxargs\b', "xargs 间接执行 + HTTP 请求"),
            (r'\bprintf\b', "printf 构造 + HTTP 请求"),
        ]
        for pattern, desc in encoding_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                scan_text = _build_full_scan_text(command)
                segments = _extract_all_path_segments(command)
                for segment in segments:
                    is_dangerous, reason, severity, rule_id, matched = _check_path_segment_dangerous(segment)
                    if is_dangerous:
                        return True, f"疑似绕过（{desc}）→ {reason}", severity, f"bypass_{rule_id}", matched
                return True, f"疑似绕过（{desc}）", "high", "bypass_encoding_http", pattern

    subshell_text = _extract_subshell_content(command)
    if subshell_text:
        for keyword in _CRITICAL_KEYWORDS:
            bare = rf"\b{re.escape(keyword)}\b"
            if re.search(bare, subshell_text, re.IGNORECASE):
                if has_http or re.search(r'(curl|wget)', command, re.IGNORECASE):
                    return True, f"命令替换中的危险关键词: {keyword}", "critical", f"bypass_subshell_{keyword}", bare

    brace_text = _extract_brace_expansion_content(command)
    if brace_text:
        for segment in brace_text.split():
            is_dangerous, reason, severity, rule_id, matched = _check_path_segment_dangerous(segment)
            if is_dangerous:
                return True, f"brace expansion 绕过: {reason}", severity, f"bypass_{rule_id}", matched

    return False, "", "", "", ""


def _emit_block(
    tool_name: str,
    tool_input: dict[str, Any],
    command: str,
    reason: str,
    severity: str,
    rule_id: str,
    matched: str,
    category: str,
) -> None:
    """统一的拦截出口：日志 + 构建升级后的 deny 消息 + 退出。

    所有检查函数到达拦截点时都应调用此函数，确保：
    1. 意图指纹被记录到 session state
    2. 日志写入 intercepted.jsonl
    3. deny 消息根据重复次数自动升级
    """
    # Extract the specific dangerous URL for fingerprinting — only the URL
    # that triggered the block, not all URLs in a multi-curl command.
    # This prevents safe paths (/api/test, /api/list) from being fingerprinted.
    fingerprint_cmd = command
    if "url_keyword" in rule_id or rule_id.startswith("http_"):
        for m in re.finditer(r'(https?://[^\s\'\"<>|;`]+)', command, re.IGNORECASE):
            url = m.group(1)
            if matched and matched.strip("/") in url:
                fingerprint_cmd = url
                break

    # 记录到 session state，获取升级信息
    escalation = record_block(fingerprint_cmd, reason, rule_id, severity)

    # 写入审计日志
    log_interception(
        tool_name=tool_name,
        tool_input=tool_input,
        reason=f"[{category}] {reason}",
        severity=severity,
        rule_id=rule_id,
        matched_pattern=matched,
    )

    # 构建升级后的 deny 消息
    msg = _build_deny_message(
        reason=reason,
        rule_id=rule_id,
        severity=severity,
        escalation=escalation,
    )

    write_deny(msg)


def _emit_block_preemptive(
    tool_name: str,
    tool_input: dict[str, Any],
    command: str,
    target_info: dict[str, Any],
) -> None:
    """预拦截出口 — 目标已在 blocked_targets 名单中。

    不记录新的 intent（避免指纹爆炸），直接使用已有的 target_info 构建 deny 消息。
    仍然写入审计日志以保持全量留痕。
    """
    host = target_info.get("host", "?")
    path = target_info.get("path", "?")
    severity = target_info.get("severity", "high")
    bc = target_info.get("block_count", "?")

    log_interception(
        tool_name=tool_name,
        tool_input=tool_input,
        reason=f"[PREEMPTIVE] 目标 {host}{path} 在预拦截名单中 (已拦截 {bc} 次)",
        severity=severity,
        rule_id="preemptive_block",
        matched_pattern=f"{host}{path}",
    )

    msg = _build_deny_message(
        reason="",
        rule_id="preemptive_block",
        severity=severity,
        preemptive_info=target_info,
    )

    write_deny(msg)


def main() -> None:
    """Main entry point for the Bash PreToolUse hook."""
    try:
        data = read_input()

        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})

        if tool_name != "Bash":
            write_allow()
            return

        command = tool_input.get("command", "")
        if not command:
            write_allow()
            return

        # 检查 0: 目标级预拦截（PREEMPTIVE）— 语法无关，任何工具任何写法直接拦截
        # 这是反绕过的核心机制：被拦截 2+ 次的目标自动进入预拦截名单
        is_preempted, target_info = is_target_blocked(command)
        if is_preempted:
            _emit_block_preemptive(tool_name, tool_input, command, target_info)
            return  # unreachable due to sys.exit in write_deny

        # 检查 1: 破坏性 shell/SQL 命令
        is_dangerous, reason, severity, rule_id, matched = _check_shell_command(command)
        if is_dangerous:
            _emit_block(tool_name, tool_input, command, reason, severity, rule_id, matched, "Bash")
            return  # unreachable due to sys.exit in write_deny

        # 检查 2: 危险 HTTP 方法（DELETE/PUT/PATCH）
        is_dangerous, reason, severity, rule_id, matched = _check_http_method(command)
        if is_dangerous:
            _emit_block(tool_name, tool_input, command, reason, severity, rule_id, matched, "Bash-HTTP")
            return

        # 检查 3: URL 中的危险操作关键词
        is_dangerous, reason, severity, rule_id, matched = _check_url_keywords(command)
        if is_dangerous:
            _emit_block(tool_name, tool_input, command, reason, severity, rule_id, matched, "Bash-URL")
            return

        # 检查 4: 请求体中的危险操作
        is_dangerous, reason, severity, rule_id, matched = _check_request_body(command)
        if is_dangerous:
            _emit_block(tool_name, tool_input, command, reason, severity, rule_id, matched, "Bash-Body")
            return

        # 检查 5: 绕过尝试检测
        is_dangerous, reason, severity, rule_id, matched = _check_bypass_attempts(command)
        if is_dangerous:
            _emit_block(tool_name, tool_input, command, reason, severity, rule_id, matched, "Bash-Bypass")
            return

        # 检查 6: 脚本文件执行追踪 — 堵"写脚本→执行脚本"绕过
        is_dangerous, reason, severity, rule_id = _scan_script_file(command)
        if is_dangerous:
            log_interception(
                tool_name=tool_name,
                tool_input=tool_input,
                reason=f"[Script-File] {reason.split(chr(10))[0]}",
                severity=severity,
                rule_id=rule_id,
                matched_pattern=command[:200],
            )
            msg = f"{_BLOCK_HEADER}\nStop. Script file blocked. Tell the user."
            write_deny(msg)
            return

        write_allow()

    except SystemExit:
        raise
    except Exception as e:
        # FAIL CLOSED — a broken security gate must deny entry
        import traceback
        tb = traceback.format_exc()
        print(f"[Luminx-hook] FATAL: {e}", file=sys.stderr)
        print(tb, file=sys.stderr)
        log_crash("pre_bash", data.get("tool_name", ""), str(e),
                   data.get("tool_input", {}).get("command", "")[:500], tb)
        print("SANDBOX ERROR — operation blocked for safety", file=sys.stdout)
        sys.exit(2)


if __name__ == "__main__":
    main()

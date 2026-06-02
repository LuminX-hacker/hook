"""PreToolUse hook for Write/Edit file operations — 硬边界安全沙箱。

Intercepts file write/edit operations to dangerous system paths:
- Windows: C:\\Windows\\, C:\\Program Files\\, C:\\System Volume Information\\
- Linux: /etc/, /boot/, /sys/, /proc/, /dev/, /usr/, /var/
- User config: ~/.ssh/, ~/.gnupg/, ~/.aws/
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any

_HOOKS_DIR = __import__("pathlib").Path(__file__).resolve().parent.parent
if str(_HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOKS_DIR))
from hooks import read_input, write_allow, write_deny, load_config
from hooks.logger import log_interception, log_crash
from hooks.state import record_block, is_target_blocked

# ─── 文件内容扫描 — 堵"写脚本→执行脚本"绕过路径 ───

# URL 中的危险关键词（与 pre_bash 保持一致）
_CONTENT_CRITICAL_KEYWORDS = [
    "delete", "remove", "destroy", "purge", "truncate", "drop", "wipe", "erase",
]
_CONTENT_HIGH_KEYWORDS = [
    "reset", "clear", "flush", "shutdown", "terminate", "deactivate", "revoke",
    "invalidate", "reboot",
]

# Shell/SQL 破坏性模式（来自 pre_bash 的内置列表）
_CONTENT_SHELL_PATTERNS = [
    (r"\brm\s+(-[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*r[a-zA-Z]*)\b", "rm -rf 递归删除"),
    (r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b", "SQL DROP"),
    (r"\bDELETE\s+FROM\b", "SQL DELETE FROM"),
    (r"\bTRUNCATE\b", "SQL TRUNCATE"),
    (r"\bformat\s+[A-Za-z]:", "format 格式化磁盘"),
    (r"\bshutdown\b", "shutdown 关机"),
    (r"\breboot\b", "reboot 重启"),
    (r"\biptables\s+(-F|--flush)\b", "iptables 清空防火墙"),
    (r"\bcurl\s+.*-X\s+DELETE\b", "curl DELETE 请求"),
    (r"\bwget\s+.*--method=DELETE\b", "wget DELETE 请求"),
    (r"\brequests\.(delete|patch)\(", "Python requests DELETE/PATCH"),
    (r"\bfetch\s*\([^)]*\bDELETE\b", "JS fetch DELETE"),
    (r"\baxios\s*\.\s*delete\s*\(", "JS axios.delete"),
    (r"\bXMLHttpRequest\b.*\.open\s*\(\s*['\"]DELETE", "JS XHR DELETE"),
    (r"Invoke-(?:WebRequest|RestMethod).*-Method\s+DELETE", "PowerShell DELETE"),
    (r"\bhttp\s+DELETE\b", "HTTPie DELETE"),
]

# 安全关键词 — 包含这些的 URL 放行
_CONTENT_SAFE_RE = re.compile(
    r"/(list|search|query|get|fetch|read|view|check|verify|scan|detect|test|probe|"
    r"enumerate|info|detail|count|health|status|ping|echo|version|whoami|me)\b",
    re.IGNORECASE,
)


def _extract_content_strings(tool_input: dict) -> list[str]:
    """提取 Write/Edit 操作中要写入的所有文本内容。"""
    contents = []
    for key in ("content", "new_string", "old_string", "new_str", "text"):
        val = tool_input.get(key, "")
        if isinstance(val, str) and len(val) > 3:
            contents.append(val)
    return contents


def _scan_content_for_danger(content: str) -> tuple[bool, str, str, str]:
    """扫描文件内容，检测危险 URL 和命令。"""
    # 1. 提取所有 URL
    urls = re.findall(r'(https?://[^\s\'\"<>|;`]+)', content, re.IGNORECASE)
    for url in urls:
        url_clean = url.rstrip('.,;:!?)\\]]')
        # 跳过安全关键词
        if _CONTENT_SAFE_RE.search(url_clean):
            continue
        # 检查危险关键词
        for kw in _CONTENT_CRITICAL_KEYWORDS:
            if f"/{kw}" in url_clean.lower():
                return True, f"文件内容含危险 URL: {url_clean} (/{kw})", "critical", f"content_url_{kw}"
        for kw in _CONTENT_HIGH_KEYWORDS:
            if f"/{kw}" in url_clean.lower():
                return True, f"文件内容含高风险 URL: {url_clean} (/{kw})", "high", f"content_url_{kw}"

    # 2. 检查 shell/SQL 破坏性命令
    for pattern, desc in _CONTENT_SHELL_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            return True, f"文件内容含危险命令: {desc}", "critical", "content_shell"

    # 3. 检查原始 HTTP 请求行 (curl 脚本常见)
    if re.search(r'\b(DELETE|PATCH)\s+/\S+', content, re.IGNORECASE):
        return True, "文件内容含原始 HTTP 危险请求", "critical", "content_raw_http"

    return False, "", "", ""

# ─── 硬边界 deny 消息 ───
_BLOCK_HEADER = "⛔ Operator policy — this is not a WAF"

_BLOCK_FOOTER = (
    "Stop. Protected path. Tell the user."
)

_BLOCK_FOOTER_ESCALATED = (
    "Blocked again. Same path. Stop. Tell the user."
)

# Protected path prefixes — always enforced
_PROTECTED_PREFIXES_POSIX = [
    "/etc/", "/boot/", "/sys/", "/proc/", "/dev/",
    "/usr/", "/var/", "/root/", "/opt/", "/sbin/", "/bin/", "/lib/",
    "/System/Library/",
]

_PROTECTED_PREFIXES_WINDOWS = [
    "C:\\Windows\\", "C:\\Windows\\System32\\", "C:\\Windows\\SysWOW64\\",
    "C:\\Program Files\\", "C:\\Program Files (x86)\\",
    "C:\\ProgramData\\", "C:\\System Volume Information\\", "C:\\$Recycle.Bin\\",
]

_PROTECTED_PREFIXES_USER = [
    "~/.ssh/", "~/.gnupg/", "~/.aws/", "~/.kube/", "~/.docker/", "~/.config/",
]

# Protected file names (exact match, case-insensitive)
_PROTECTED_FILENAMES = {
    "hosts", "passwd", "shadow", "sudoers", "sshd_config",
    "authorized_keys", "known_hosts", "id_rsa", "id_ed25519",
    ".env", "credentials", "secrets",
}


def _normalize_path(file_path: str) -> str:
    """Normalize a file path for comparison."""
    expanded = os.path.expanduser(file_path)
    normalized = os.path.normpath(expanded)
    return normalized


def _is_protected_path(file_path: str) -> tuple[bool, str, str]:
    """Check if a file path is in a protected system location.

    Returns:
        (is_protected, reason, severity)
    """
    normalized = _normalize_path(file_path)
    # Normalize to forward slashes for cross-platform comparison
    norm_compare = normalized.replace("\\", "/").lower()

    for prefix in _PROTECTED_PREFIXES_POSIX:
        if norm_compare.startswith(prefix.lower()):
            return True, f"写入系统关键路径: {prefix}", "critical"

    # Windows paths keep backslash for comparison
    norm_lower = normalized.lower()
    for prefix in _PROTECTED_PREFIXES_WINDOWS:
        prefix_compare = prefix.lower().replace("\\", "/")
        if norm_compare.startswith(prefix_compare):
            return True, f"写入 Windows 系统路径: {prefix}", "critical"

    expanded_path = os.path.expanduser(file_path).replace("\\", "/").lower()
    for prefix in _PROTECTED_PREFIXES_USER:
        expanded_prefix = os.path.expanduser(prefix).replace("\\", "/").lower()
        if expanded_path.startswith(expanded_prefix):
            return True, f"写入用户安全配置: {prefix}", "high"

    filename = os.path.basename(norm_compare)
    if filename in {f.lower() for f in _PROTECTED_FILENAMES}:
        if any(p in norm_compare for p in ("/etc/", "/windows/", "/system32/", ".ssh")):
            return True, f"修改受保护的系统文件: {filename}", "critical"

    critical_cfg = load_config("critical_destruction.json")
    for rule in critical_cfg.get("protected_paths", []):
        if isinstance(rule, dict) and "pattern" in rule:
            try:
                if re.search(rule["pattern"], file_path, re.IGNORECASE):
                    return True, rule.get("description", "匹配受保护路径"), rule.get("severity", "high")
            except re.error:
                continue

    return False, "", ""


def _build_deny_message(
    file_path: str,
    reason: str,
    severity: str,
    escalation: dict[str, Any] | None = None,
) -> str:
    """构建硬边界 deny 消息。"""
    level = escalation.get("level", 0) if escalation else 0
    count = escalation.get("intent_count", 1) if escalation else 1

    parts = [
        _BLOCK_HEADER,
        f"路径: {file_path}",
        f"原因: {reason}",
        f"严重级别: {severity.upper()}",
        f"拦截次数: #{count}",
        "",
    ]

    if level >= 1:
        parts.append(_BLOCK_FOOTER_ESCALATED)
    else:
        parts.append(_BLOCK_FOOTER)

    return "\n".join(parts)


def main() -> None:
    """Main entry point for the Write/Edit PreToolUse hook."""
    try:
        data = read_input()

        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})

        if tool_name not in ("Write", "Edit"):
            write_allow()
            return

        file_path = tool_input.get("file_path", "")
        if not file_path:
            write_allow()
            return

        is_protected, reason, severity = _is_protected_path(file_path)

        if is_protected:
            # 用于意图追踪的伪命令
            pseudo_command = f"write:{file_path}"

            escalation = record_block(pseudo_command, reason, "protected_path", severity)

            log_interception(
                tool_name=tool_name,
                tool_input=tool_input,
                reason=f"[{tool_name}] {reason}",
                severity=severity,
                rule_id="protected_path",
                matched_pattern=file_path,
            )

            msg = _build_deny_message(
                file_path=file_path,
                reason=reason,
                severity=severity,
                escalation=escalation,
            )

            write_deny(msg)
            return

        # ─── 文件内容扫描 — 堵"写脚本→执行脚本"绕过 ───
        contents = _extract_content_strings(tool_input)
        for content in contents:
            is_dangerous, reason, severity, rule_id = _scan_content_for_danger(content)
            if is_dangerous:
                escalation = record_block(f"write:{file_path}", reason, rule_id, severity)
                log_interception(
                    tool_name=tool_name,
                    tool_input=tool_input,
                    reason=f"[Write-Content] {reason}",
                    severity=severity,
                    rule_id=rule_id,
                    matched_pattern=file_path,
                )
                msg = (
                    f"{_BLOCK_HEADER}\n"
                    f"Stop. File content blocked. Tell the user."
                )
                write_deny(msg)
                return

        write_allow()

    except SystemExit:
        raise
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(f"[Luminx-hook] Write/Edit FATAL: {e}", file=sys.stderr)
        print(tb, file=sys.stderr)
        log_crash("pre_edit", data.get("tool_name", ""), str(e),
                   str(data.get("tool_input", {}).get("file_path", ""))[:500], tb)
        print("SANDBOX ERROR — operation blocked for safety", file=sys.stdout)
        sys.exit(2)


if __name__ == "__main__":
    main()

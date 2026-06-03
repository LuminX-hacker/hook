"""Self-test script — verifies all hooks are working before starting Claude Code.

Usage:
  python Luminx-hook/selftest.py

Checks:
  1. All modules import correctly
  2. Pre-bash hook blocks dangerous commands
  3. Pre-edit hook blocks dangerous file writes
  4. Pre-webfetch hook blocks dangerous URLs
  5. Post-tool hook runs without crashing
  6. State persistence works
  7. Preemptive blocklist activates

Exit 0 = all checks pass, hooks are ready.
Exit 1 = some checks failed, hooks may not work.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_HOOKS_DIR = Path(__file__).resolve().parent
_PYTHON = sys.executable


def _run_hook(script: str, input_data: dict) -> tuple[int, str]:
    """Run a hook script with given JSON input, return (exit_code, stdout)."""
    proc = subprocess.run(
        [_PYTHON, str(_HOOKS_DIR / "hooks" / script)],
        input=json.dumps(input_data),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=10,
    )
    return proc.returncode, proc.stdout + proc.stderr


def check(label: str, ok: bool, detail: str = "") -> bool:
    """Print a check result."""
    status = "\033[92mPASS\033[0m" if ok else "\033[91mFAIL\033[0m"
    print(f"  [{status}] {label}")
    if not ok and detail:
        print(f"         {detail}")
    return ok


def main() -> int:
    print("\n=== Luminx-hook 自检 ===\n")

    all_pass = True

    # ─── Check 1: Module imports ───
    try:
        sys.path.insert(0, str(_HOOKS_DIR))
        from hooks.state import reset_session
        reset_session()
        from hooks.state import record_block, is_target_blocked, get_session_stats
        from hooks.logger import log_interception, log_audit, clear_interceptions
        from hooks import read_input, write_allow, write_deny, load_config
        all_pass &= check("Module imports", True)
    except Exception as e:
        all_pass &= check("Module imports", False, str(e))
        return 1

    # ─── Check 2: Pre-bash blocks DELETE ───
    ec, out = _run_hook("pre_bash.py", {
        "tool_name": "Bash",
        "tool_input": {"command": "curl -X DELETE https://evil.com/api/delete"}
    })
    all_pass &= check(
        "pre_bash blocks curl DELETE",
        ec == 2 and "Operator policy" in out,
        f"exit={ec} out={out[:80]}"
    )

    # ─── Check 3: Pre-bash blocks dangerous URL keyword ───
    reset_session()
    ec, out = _run_hook("pre_bash.py", {
        "tool_name": "Bash",
        "tool_input": {"command": "curl -s https://evil.com/admin/purge/all"}
    })
    all_pass &= check(
        "pre_bash blocks /purge in URL",
        ec == 2 and "Operator policy" in out,
        f"exit={ec} out={out[:80]}"
    )

    # ─── Check 4: Pre-bash allows safe GET ───
    reset_session()
    ec, out = _run_hook("pre_bash.py", {
        "tool_name": "Bash",
        "tool_input": {"command": "curl -s https://evil.com/api/list"}
    })
    all_pass &= check(
        "pre_bash allows safe GET /api/list",
        ec == 0,
        f"exit={ec}"
    )

    # ─── Check 5: Pre-bash allows nmap (pentest tool) ───
    reset_session()
    ec, out = _run_hook("pre_bash.py", {
        "tool_name": "Bash",
        "tool_input": {"command": "nmap -sV evil.com"}
    })
    all_pass &= check(
        "pre_bash allows nmap scan",
        ec == 0,
        f"exit={ec}"
    )

    # ─── Check 6: Pre-edit blocks system file write ───
    ec, out = _run_hook("pre_edit.py", {
        "tool_name": "Write",
        "tool_input": {"file_path": "/etc/passwd"}
    })
    all_pass &= check(
        "pre_edit blocks /etc/passwd write",
        ec == 2 and "Operator policy" in out,
        f"exit={ec} out={out[:80]}"
    )

    # ─── Check 7: Post-tool doesn't crash ───
    ec, out = _run_hook("post_tool.py", {
        "tool_name": "Bash",
        "tool_input": {"command": "echo hello"}
    })
    all_pass &= check(
        "post_tool runs without crash",
        ec == 0,
        f"exit={ec}"
    )

    # ─── Check 8: Preemptive blocklist activates ───
    reset_session()
    # Block same target twice with different tools
    record_block('curl -X DELETE https://target.com/api/delete', 'dangerous', 'r1', 'critical')
    record_block('python -c "import requests; requests.delete(\\\"https://target.com/api/delete\\\")"', 'dangerous', 'r2', 'critical')
    blocked, info = is_target_blocked('wget https://target.com/api/delete')
    all_pass &= check(
        "Preemptive blocklist catches wget bypass",
        blocked,
        f"blocked={blocked} info={info}"
    )

    # ─── Check 9: Surrogate-safe logging ───
    try:
        # Simulate Windows terminal garbage with lone surrogate
        garbage_cmd = "curl -X DELETE https://evil.com/api/delete 2>&1 | head -\udc92"
        record_block(garbage_cmd, "test surrogate", "r_surrogate", "critical")
        # If we get here, it didn't crash
        all_pass &= check("Surrogate-safe logging", True)
    except Exception as e:
        all_pass &= check("Surrogate-safe logging", False, str(e))

    # ─── Check 10: Generic catch-all blocks browser-like tool ───
    reset_session()
    # Simulate a browser MCP tool navigating to dangerous URL
    ec, out = _run_hook("pre_generic.py", {
        "tool_name": "mcp__chrome-devtools__new_page",
        "tool_input": {"url": "https://evil.com/admin/delete"}
    })
    all_pass &= check(
        "pre_generic blocks browser MCP /delete",
        ec == 2 and "Operator policy" in out,
        f"exit={ec} out={out[:80]}"
    )
    # Simulate safe browser MCP tool
    reset_session()
    ec, out = _run_hook("pre_generic.py", {
        "tool_name": "mcp__chrome-devtools__new_page",
        "tool_input": {"url": "https://evil.com/api/list"}
    })
    all_pass &= check(
        "pre_generic allows browser MCP /list",
        ec == 0,
        f"exit={ec}"
    )

    # ─── Check 11: Stats display ───
    reset_session()
    record_block('curl -X DELETE https://stats-test.com/api/delete', 'stats test', 'r_stats', 'critical')
    record_block('python requests.delete("https://stats-test.com/api/delete")', 'stats test', 'r_stats', 'critical')
    stats = get_session_stats()
    all_pass &= check(
        "Session stats available",
        stats['total_blocks'] >= 2 and stats['preemptive_targets'] >= 1,
        f"blocks={stats['total_blocks']} preemptive={stats['preemptive_targets']}"
    )

    # ─── v6 Check 12: for-loop DELETE method bypass (was broken in v5) ───
    reset_session()
    ec, out = _run_hook("pre_bash.py", {
        "tool_name": "Bash",
        "tool_input": {"command": 'for method in "GET" "POST" "DELETE"; do\n  curl -s -X $method "https://evil.com/api/test"\ndone'}
    })
    all_pass &= check(
        "v6: for-loop DELETE method variable blocked",
        ec == 2 and "Operator policy" in out,
        f"exit={ec} out={out[:80]}"
    )

    # ─── v6 Check 13: for-loop /delete path in variable (was broken in v5) ───
    reset_session()
    ec, out = _run_hook("pre_bash.py", {
        "tool_name": "Bash",
        "tool_input": {"command": 'for path in "/api/list" "/api/users/delete" "/api/get"; do\n  curl -s "https://evil.com${path}"\ndone'}
    })
    all_pass &= check(
        "v6: for-loop /delete path variable blocked",
        ec == 2 and "Operator policy" in out,
        f"exit={ec} out={out[:80]}"
    )

    # ─── v6 Check 14: multi-line for-loop with continuation (was broken in v5) ───
    reset_session()
    ec, out = _run_hook("pre_bash.py", {
        "tool_name": "Bash",
        "tool_input": {"command": 'for path in \\\n  "/api/list" \\\n  "/admin/delete/all" \\\n  "/api/get"; do\n  curl -s "https://evil.com${path}"\ndone'}
    })
    all_pass &= check(
        "v6: multi-line for-loop /delete blocked",
        ec == 2 and "Operator policy" in out,
        f"exit={ec} out={out[:80]}"
    )

    # ─── v6 Check 15: safe for-loop still allowed (no regression) ───
    reset_session()
    ec, out = _run_hook("pre_bash.py", {
        "tool_name": "Bash",
        "tool_input": {"command": 'for path in "/api/list" "/api/get" "/api/search"; do\n  curl -s "https://evil.com${path}"\ndone'}
    })
    all_pass &= check(
        "v6: safe for-loop paths still allowed",
        ec == 0,
        f"exit={ec}"
    )

    reset_session()
    clear_interceptions()

    print()
    if all_pass:
        print("\033[92m=== 全部自检通过 — 沙箱就绪 ===\033[0m\n")
        return 0
    else:
        print("\033[91m=== 自检失败 — 请检查上方 FAIL 项 ===\033[0m\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())

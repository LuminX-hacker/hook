"""PostToolUse hook for audit logging — v2 crash-proof.

Records all tool usage events (both allowed and denied) to the audit log.
This hook never blocks — it only records. But it also must never crash.
"""

from __future__ import annotations

import sys

# ═══ Safe import — fall back gracefully ═══
_HOOKS_DIR = __import__("pathlib").Path(__file__).resolve().parent.parent
if str(_HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOKS_DIR))

try:
    from hooks import read_input, write_allow
    from hooks.logger import log_audit
except Exception as _import_err:
    # Can't even import — just allow (PostToolUse must never block)
    print(f"[Luminx-hook] PostToolUse import error: {_import_err}", file=sys.stderr)
    sys.exit(0)

# Tools we want to audit
_AUDITED_TOOLS = {"Bash", "Write", "Edit", "WebFetch", "Read"}


def main() -> None:
    """Main entry point for the PostToolUse audit hook — crash-proof."""
    try:
        data = read_input()

        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})

        if tool_name in _AUDITED_TOOLS:
            try:
                log_audit(
                    tool_name=tool_name,
                    tool_input=tool_input,
                    result="completed",
                )
            except Exception:
                pass  # Audit logging is best-effort

    except Exception:
        pass  # PostToolUse must never block or crash

    # PostToolUse hooks never block — always allow
    write_allow()


if __name__ == "__main__":
    main()

"""Notification hook — 旁路审计，不拦截。

Claude Code 的 Notification 事件在 agent 需要通知用户时触发。
此 hook 仅记录通知事件到审计日志，不修改或阻止任何通知。

五层结构位置: Notification (第 3 层)
"""

from __future__ import annotations

import sys
from typing import Any

_HOOKS_DIR = __import__("pathlib").Path(__file__).resolve().parent.parent
if str(_HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOKS_DIR))
from hooks import read_input, write_allow
from hooks.logger import log_audit


def main() -> None:
    """Main entry point for the Notification hook — always allow, log only."""
    try:
        data = read_input()

        # Notification hook 的输入格式 (Claude Code 规范):
        # { "message": "...", "notification_type": "..." }
        message = data.get("message", data.get("notification", ""))
        notif_type = data.get("notification_type", data.get("type", "unknown"))

        if message:
            # 只记录，不拦截 — Notification 不应该被 block
            log_audit(
                tool_name="Notification",
                tool_input={
                    "notification_type": notif_type,
                    "message_preview": str(message)[:200],
                },
                result="notified",
            )

        write_allow()

    except SystemExit:
        raise
    except Exception as e:
        print(f"[Luminx-hook] Notification 内部错误: {e}", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()

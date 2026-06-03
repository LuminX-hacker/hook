"""Stop hook — 会话结束时生成安全审计汇总报告。

在 Claude Code agent 停止时触发，读取当前会话的拦截状态，
输出一份汇总报告。报告内容会被 agent 看到并可传达给用户。

五层结构位置: Stop (第 5 层)
"""

from __future__ import annotations

import sys
from typing import Any

_HOOKS_DIR = __import__("pathlib").Path(__file__).resolve().parent.parent
if str(_HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOKS_DIR))
from hooks import read_input, write_allow
from hooks.logger import log_audit
from hooks.state import get_session_stats


def _build_summary(stats: dict[str, Any]) -> str:
    """构建会话汇总报告。"""
    total = stats.get("total_blocks", 0)
    unique = stats.get("unique_intents", 0)
    preemptive = stats.get("preemptive_targets", 0)

    if total == 0:
        return ""

    lines = [
        "",
        "+========================================+",
        "|  [SHIELD] Security Sandbox Audit Report  |",
        "+========================================+",
        "",
        f"  Total blocks:       {total}",
        f"  Unique intents:     {unique}",
        f"  Preemptive targets: {preemptive}",
        "",
    ]

    top = stats.get("top_intents", [])
    if top:
        lines.append("  TOP 拦截目标:")
        lines.append("  " + "-" * 42)
        for i, intent in enumerate(top, 1):
            host = intent.get("host", "?")
            path = intent.get("path", "?")
            count = intent.get("count", 0)
            tools = intent.get("tools", [])
            tools_str = " → ".join(tools) if tools else "—"
            lines.append(f"  [{i}] {host}{path}")
            lines.append(f"      拦截 {count} 次 | 工具: {tools_str}")
        lines.append("")

    lines.append("  查看详情: python Luminx-hook/check_intercepted.py list")
    lines.append("  清除记录: python Luminx-hook/check_intercepted.py clear")
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    """Main entry point for the Stop hook."""
    try:
        data = read_input()

        # Stop hook 的输入格式 (Claude Code 规范):
        # { "reason": "stop_reason", ... }
        stop_reason = data.get("reason", data.get("stop_reason", "unknown"))

        # 获取会话统计
        stats = get_session_stats()

        # 记录 stop 事件到审计日志
        log_audit(
            tool_name="Stop",
            tool_input={
                "stop_reason": stop_reason,
                "session_stats": {
                    "total_blocks": stats.get("total_blocks", 0),
                    "unique_intents": stats.get("unique_intents", 0),
                    "preemptive_targets": stats.get("preemptive_targets", 0),
                },
            },
            result="stopped",
        )

        # 生成并输出汇总报告（stdout 内容会被 Claude Code 捕获）
        summary = _build_summary(stats)
        if summary:
            print(summary, file=sys.stdout)

        write_allow()

    except SystemExit:
        raise
    except Exception as e:
        print(f"[Luminx-hook] Stop 内部错误: {e}", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()

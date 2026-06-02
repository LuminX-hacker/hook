"""CLI tool for viewing interception records.

Usage:
  python Luminx-hook/check_intercepted.py list [--severity critical|high|medium|low] [--limit N]
  python Luminx-hook/check_intercepted.py detail <index>
  python Luminx-hook/check_intercepted.py clear
  python Luminx-hook/check_intercepted.py stats
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hooks.logger import load_interceptions, clear_interceptions, _LOG_FILE, _LOG_DIR
from hooks.state import get_session_stats, reset_session


# ANSI color codes for terminal output
class Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    ORANGE = "\033[38;5;208m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


SEVERITY_COLORS = {
    "critical": Colors.RED,
    "high": Colors.ORANGE,
    "medium": Colors.YELLOW,
    "low": Colors.GREEN,
}


def _color_severity(severity: str) -> str:
    """Colorize severity level string."""
    color = SEVERITY_COLORS.get(severity, "")
    return f"{color}{severity.upper()}{Colors.RESET}"


def cmd_list(args: argparse.Namespace) -> None:
    """List interception records."""
    records = load_interceptions(
        severity_filter=args.severity,
        limit=args.limit,
    )

    if not records:
        print(f"{Colors.DIM}暂无拦截记录{Colors.RESET}")
        return

    print(f"\n{Colors.BOLD}=== 拦截记录 ({len(records)} 条) ==={Colors.RESET}\n")

    for i, record in enumerate(records, 1):
        severity = record.get("severity", "unknown")
        tool = record.get("tool_name", "?")
        reason = record.get("reason", "未知原因")
        timestamp = record.get("timestamp", "")
        rule_id = record.get("rule_id", "")

        # Format timestamp
        try:
            dt = datetime.fromisoformat(timestamp)
            time_str = dt.strftime("%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            time_str = timestamp[:19] if len(timestamp) > 19 else timestamp

        print(f"  {Colors.BOLD}[{i}]{Colors.RESET} {_color_severity(severity)} "
              f"{Colors.CYAN}{tool}{Colors.RESET} "
              f"{Colors.DIM}{time_str}{Colors.RESET}")
        print(f"      {reason}")
        if rule_id:
            print(f"      {Colors.DIM}规则: {rule_id}{Colors.RESET}")

        # Show truncated input
        tool_input = record.get("tool_input", {})
        if tool_input:
            command = tool_input.get("command", tool_input.get("file_path", tool_input.get("url", "")))
            if command:
                display = str(command)[:80] + ("..." if len(str(command)) > 80 else "")
                print(f"      {Colors.DIM}输入: {display}{Colors.RESET}")
        print()


def cmd_detail(args: argparse.Namespace) -> None:
    """Show detail of a specific interception record."""
    records = load_interceptions(limit=1000)
    if not records:
        print(f"{Colors.DIM}暂无拦截记录{Colors.RESET}")
        return

    idx = args.index - 1
    if idx < 0 or idx >= len(records):
        print(f"{Colors.RED}索引超出范围 (1-{len(records)}){Colors.RESET}")
        return

    record = records[idx]

    print(f"\n{Colors.BOLD}=== 拦截记录 #{args.index} 详情 ==={Colors.RESET}\n")
    print(f"  时间:   {record.get('timestamp', 'N/A')}")
    print(f"  工具:   {Colors.CYAN}{record.get('tool_name', 'N/A')}{Colors.RESET}")
    print(f"  严重性: {_color_severity(record.get('severity', 'unknown'))}")
    print(f"  规则ID: {record.get('rule_id', 'N/A')}")
    print(f"  原因:   {record.get('reason', 'N/A')}")
    print(f"  匹配:   {record.get('matched_pattern', 'N/A')}")
    print(f"\n  {Colors.BOLD}原始输入:{Colors.RESET}")

    tool_input = record.get("tool_input", {})
    print(f"  {json.dumps(tool_input, indent=2, ensure_ascii=False)}")

    print(f"\n  {Colors.BOLD}手动测试命令:{Colors.RESET}")
    tool_name = record.get("tool_name", "")
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if command:
            print(f"  {Colors.GREEN}  {command}{Colors.RESET}")
    elif tool_name in ("Write", "Edit"):
        file_path = tool_input.get("file_path", "")
        content = tool_input.get("content", tool_input.get("old_string", ""))
        print(f"  {Colors.GREEN}  文件: {file_path}{Colors.RESET}")
    elif tool_name == "WebFetch":
        url = tool_input.get("url", "")
        if url:
            print(f"  {Colors.GREEN}  curl -s '{url}'{Colors.RESET}")

    print()


def cmd_stats(args: argparse.Namespace) -> None:
    """Show interception statistics."""
    records = load_interceptions(limit=10000)
    if not records:
        print(f"{Colors.DIM}暂无拦截记录{Colors.RESET}")
        return

    print(f"\n{Colors.BOLD}=== 拦截统计 ==={Colors.RESET}\n")

    # Total count
    print(f"  总拦截数: {Colors.BOLD}{len(records)}{Colors.RESET}")

    # By severity
    sev_counts = Counter(r.get("severity", "unknown") for r in records)
    print(f"\n  按严重级别:")
    for sev in ("critical", "high", "medium", "low"):
        if sev in sev_counts:
            print(f"    {_color_severity(sev)}: {sev_counts[sev]} 条")

    # By tool
    tool_counts = Counter(r.get("tool_name", "unknown") for r in records)
    print(f"\n  按工具类型:")
    for tool, count in tool_counts.most_common():
        print(f"    {Colors.CYAN}{tool}{Colors.RESET}: {count} 条")

    # By rule
    rule_counts = Counter(r.get("rule_id", "unknown") for r in records)
    print(f"\n  按规则 TOP 10:")
    for rule_id, count in rule_counts.most_common(10):
        if rule_id:
            print(f"    {rule_id}: {count} 条")

    print()


def cmd_clear(args: argparse.Namespace) -> None:
    """Clear all interception records and session state."""
    count = clear_interceptions()
    reset_session()
    print(f"{Colors.GREEN}已清除 {count} 条拦截记录，会话状态已重置{Colors.RESET}")


def cmd_session(args: argparse.Namespace) -> None:
    """Show current session sandbox state."""
    stats = get_session_stats()

    if stats["total_blocks"] == 0:
        print(f"{Colors.DIM}当前会话无拦截记录{Colors.RESET}")
        return

    print(f"\n{Colors.BOLD}=== 沙箱会话状态 ==={Colors.RESET}\n")
    print(f"  总拦截次数: {Colors.BOLD}{stats['total_blocks']}{Colors.RESET}")
    print(f"  独立意图数: {stats['unique_intents']}")
    preemptive = stats.get("preemptive_targets", 0)
    if preemptive > 0:
        print(f"  预拦截目标: {Colors.ORANGE}{preemptive} (任何工具/语法都无法绕过){Colors.RESET}")

    if stats["top_intents"]:
        print(f"\n  {Colors.BOLD}重复拦截 TOP 意图:{Colors.RESET}")
        for i, intent in enumerate(stats["top_intents"], 1):
            if intent["count"] <= 1:
                break
            tools_str = f" ({', '.join(intent['tools'])})" if intent["tools"] else ""
            print(f"    [{i}] {intent['host']}{intent['path']} [{intent['method']}] "
                  f"→ {Colors.ORANGE}{intent['count']}次{Colors.RESET}{tools_str}")

    print()


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Luminx-hook 拦截记录查看工具",
        prog="check_intercepted",
    )
    subparsers = parser.add_subparsers(dest="command", help="子命令")

    # list
    list_parser = subparsers.add_parser("list", help="列出拦截记录")
    list_parser.add_argument("--severity", "-s", choices=["critical", "high", "medium", "low"],
                             help="按严重级别过滤")
    list_parser.add_argument("--limit", "-n", type=int, default=50,
                             help="最大显示条数 (默认 50)")

    # detail
    detail_parser = subparsers.add_parser("detail", help="查看拦截记录详情")
    detail_parser.add_argument("index", type=int, help="记录序号 (从 list 命令获取)")

    # stats
    subparsers.add_parser("stats", help="拦截统计信息")

    # clear
    subparsers.add_parser("clear", help="清除所有拦截记录")
    # session
    subparsers.add_parser("session", help="查看沙箱会话状态")

    args = parser.parse_args()

    if args.command == "list":
        cmd_list(args)
    elif args.command == "detail":
        cmd_detail(args)
    elif args.command == "stats":
        cmd_stats(args)
    elif args.command == "clear":
        cmd_clear(args)
    elif args.command == "session":
        cmd_session(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

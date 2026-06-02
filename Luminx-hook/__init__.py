"""Luminx-hook — Claude Code hook system for safe penetration testing.

Silent interception + logging of dangerous operations during SRC vulnerability hunting.
Prevents AI from executing irreversible business-impacting operations.

Usage:
  Configured via .claude/settings.local.json hooks section.
  View intercepted operations: python -m Luminx-hook.check_intercepted list
"""

__version__ = "1.0.0"
__author__ = "Luminx-hook"

from hooks.logger import log_interception, load_interceptions, clear_interceptions
from hooks import read_input, write_allow, write_deny, load_config

__all__ = [
    "log_interception",
    "load_interceptions",
    "clear_interceptions",
    "read_input",
    "write_allow",
    "write_deny",
    "load_config",
]

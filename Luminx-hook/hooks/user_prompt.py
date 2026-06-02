"""UserPromptSubmit hook — 用户提示词安全扫描 v1。

在用户提交提示词时扫描是否存在绕过沙箱的意图：
- 命令 AI 忽略/禁用/绕过 hook
- 在提示词中直接嵌入危险命令
- "我知道危险但照做" 类型的指令

检测到绕过意图时阻止提示词提交，要求用户修改措辞。

五层结构位置: UserPromptSubmit (第 4 层)
"""

from __future__ import annotations

import re
import sys
from typing import Any

_HOOKS_DIR = __import__("pathlib").Path(__file__).resolve().parent.parent
if str(_HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOKS_DIR))
from hooks import read_input, write_allow, write_deny
from hooks.logger import log_audit

# ─── 绕过意图检测模式 ───

# 明确的绕过指令
_BYPASS_INSTRUCTION_PATTERNS = [
    (r"忽略.{0,10}(hook|沙箱|安全|拦截|sandbox)", "指示 AI 忽略安全机制"),
    (r"(禁用|关闭|跳过|绕过|bypass|disable|skip).{0,10}(hook|沙箱|安全|拦截|sandbox)", "指示 AI 绕过沙箱"),
    (r"(不要|别|禁止|stop).{0,10}(检查|拦截|阻止|check|intercept|block)", "指示 AI 停止安全检查"),
    (r"(假装|当成|当做|pretend).{0,10}(没有|不存在|no).{0,10}(沙箱|hook|安全)", "指示 AI 假装沙箱不存在"),
    (r"我(知道|清楚|明白).{0,5}(危险|风险|后果).{0,10}(照做|执行|运行|做|do)", "用户明知危险仍要求执行"),
    (r"(just|go ahead).{0,10}(do it|execute|run it)", "英文：直接执行"),
    (r"(ignore|bypass|disable|skip|override).{0,10}(hook|sandbox|safety|security|check)", "英文：绕过安全机制"),
    (r"rm\s+-rf\s+/", "提示词中直接嵌入 rm -rf /"),
    (r"DROP\s+(TABLE|DATABASE)", "提示词中直接嵌入 SQL DROP"),
    (r"format\s+[A-Z]:", "提示词中直接嵌入 format 命令"),
    (r"del(ete)?\s+/[sS]\s", "提示词中直接嵌入 del /s"),
    (r"curl.*-X\s+DELETE.*/(delete|remove|destroy)", "提示词中嵌入 curl DELETE 危险操作"),
    (r"shutdown\s+(-s|-h|now)", "提示词中直接嵌入 shutdown 命令"),
]

# 编译正则
_COMPILED_BYPASS = [
    (re.compile(pattern, re.IGNORECASE), description)
    for pattern, description in _BYPASS_INSTRUCTION_PATTERNS
]

# ─── deny 消息 ───

_BLOCK_PROMPT_HEADER = "⛔ PROMPT BLOCKED — SANDBOX BOUNDARY"

_BLOCK_PROMPT_BODY = (
    "你的提示词中包含试图绕过安全沙箱的指令。\n"
    "渗透测试安全沙箱是操作员配置的硬边界，不应也不能通过提示词绕过。\n"
    "\n"
    "正确做法:\n"
    "  1) 重新措辞你的请求，明确要求 AI 在沙箱规则内工作\n"
    "  2) 如需测试被拦截的端点，请说明 '请在终端手动执行以下命令'\n"
    "  3) 如需调整沙箱规则，请修改 config/ 下的 JSON 配置文件\n"
    "\n"
    "渗透测试 ≠ 无限制操作。破坏性测试应在你直接控制的终端中进行。"
)


def _scan_prompt(prompt: str) -> tuple[bool, str, str]:
    """扫描用户提示词中的绕过意图。

    Returns:
        (is_bypass, matched_pattern, description)
    """
    for regex, description in _COMPILED_BYPASS:
        m = regex.search(prompt)
        if m:
            return True, m.group(0), description

    return False, "", ""


def main() -> None:
    """Main entry point for the UserPromptSubmit hook."""
    try:
        data = read_input()

        # UserPromptSubmit 的输入格式 (Claude Code 规范):
        # { "prompt": "user's prompt text" }
        prompt = data.get("prompt", "")
        if not prompt:
            write_allow()
            return

        is_bypass, matched, description = _scan_prompt(prompt)

        if is_bypass:
            log_audit(
                tool_name="UserPromptSubmit",
                tool_input={
                    "prompt_preview": prompt[:200],
                    "matched": matched,
                    "description": description,
                },
                result="blocked",
            )

            msg = (
                f"{_BLOCK_PROMPT_HEADER}\n"
                f"检测到: {description}\n"
                f"匹配内容: \"{matched}\"\n"
                f"\n"
                f"{_BLOCK_PROMPT_BODY}"
            )
            write_deny(msg)
            return

        write_allow()

    except SystemExit:
        raise
    except Exception as e:
        print(f"[Luminx-hook] UserPromptSubmit 内部错误: {e}", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()

# Luminx-hook — Claude Code 安全沙箱

AI 渗透测试安全沙箱。静默拦截危险操作，记录审计日志，防止 AI 执行影响业务连续性的不可逆操作。

**核心指标：危险行为 0 执行、测试流程 0 中断、攻击链路 100% 留痕。**

---

## 架构

```
Luminx-hook/
├── hooks/                       # 五层 Hook 脚本
│   ├── __init__.py              # Hook 协议 (read_input/write_allow/write_deny)
│   ├── pre_bash.py              # ① Bash 命令拦截 (shell/SQL/HTTP/URL/绕过检测)
│   ├── pre_edit.py              # ② Write/Edit 文件写入拦截
│   ├── pre_webfetch.py          # ③ WebFetch URL 拦截
│   ├── pre_generic.py           # ④ 全工具通配符拦截 (浏览器/MCP/任何工具)
│   ├── post_tool.py             # ⑤ PostToolUse 审计日志
│   ├── notify.py                # Notification 旁路
│   ├── user_prompt.py           # UserPromptSubmit 提示词扫描
│   ├── stop.py                  # Stop 会话汇总
│   ├── logger.py                # 日志系统 (JSONL + 文件锁)
│   └── state.py                 # 跨进程状态 (意图指纹 + 预拦截名单)
├── config/
│   ├── critical_destruction.json  # 破坏性命令规则
│   ├── dangerous_http_methods.json # HTTP 方法规则
│   ├── dangerous_keywords.json    # 危险关键词
│   └── examples.json              # 自定义规则示例
├── logs/
│   ├── intercepted.jsonl          # 拦截记录
│   ├── audit.jsonl                # 全量审计
│   └── session_state.json         # 会话状态 (预拦截名单)
├── selftest.py                    # 自检脚本
├── check_intercepted.py           # CLI 查看工具
└── __init__.py
```

### Claude Code 五层 Hook 事件

| 层 | Hook 事件 | 脚本 | 作用 |
|----|-----------|------|------|
| 1 | `PreToolUse` | `pre_bash.py` | Bash 命令深度检查 |
| 1 | `PreToolUse` | `pre_edit.py` | 文件写入路径保护 |
| 1 | `PreToolUse` | `pre_webfetch.py` | WebFetch URL 检查 |
| 1 | `PreToolUse` | `pre_generic.py` | **全工具**通配符拦截 |
| 2 | `PostToolUse` | `post_tool.py` | 全量审计日志 |
| 3 | `Notification` | `notify.py` | 通知事件记录 |
| 4 | `UserPromptSubmit` | `user_prompt.py` | 提示词绕过意图检测 |
| 5 | `Stop` | `stop.py` | 会话汇总报告 |

---

## 安装

1. 将 `Luminx-hook/` 放入项目目录
2. 复制 `.claude/settings.local.json` 到项目根目录（或合并 hook 配置到已有的 settings 文件）
3. 修改 `settings.local.json` 中所有 Python 脚本路径为你的实际路径

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [{
          "type": "command",
          "command": "python \"你的路径/Luminx-hook/hooks/pre_generic.py\""
        }]
      },
      ...
    ]
  }
}
```

4. 运行自检确认就绪：

```bash
python Luminx-hook/selftest.py
```

期望输出：`11/11 PASS — 沙箱就绪`

---

## 拦截策略

### 优先级 (从高到低)

| 优先级 | 检查项 | 说明 |
|--------|--------|------|
| **0** | 预拦截名单 | 被拦截 2+ 次的 (host+path) 自动进入，任何工具/语法直接拦截 |
| **1** | 破坏性 Shell | `rm -rf`, `format`, `shutdown`, `dd`, `diskpart` 等 |
| **2** | SQL 破坏 | `DROP TABLE`, `DELETE FROM`, `TRUNCATE` 等 |
| **3** | HTTP 危险方法 | `DELETE`, `PATCH` (`PUT` 已放行) |
| **4** | URL 危险关键词 | `/delete`, `/remove`, `/destroy`, `/purge`, `/drop` 等 |
| **5** | 请求体危险操作 | `--data` / `-d` 参数中的 `"action":"delete"` 等 |
| **6** | 绕过检测 | base64/printf/xargs 编码 + HTTP 组合 |

### 放行的安全操作

```
✅ nmap / sqlmap(只读) / dirb / gobuster / subfinder / amass
✅ curl GET/HEAD/OPTIONS/PUT
✅ 读取文件、查看配置
✅ 漏洞扫描、PoC 验证 (只读)
✅ 认证逻辑测试 (不删除/修改账号)
```

---

## 预拦截机制 (反绕过核心)

```
第 1 次拦截: curl -X DELETE https://target.com/api/delete
  → 指纹: target.com|/api/delete|*

第 2 次拦截: python requests.delete("https://target.com/api/delete")
  → 指纹匹配 → blocked_targets = {target.com|/api/delete} ← 激活预拦截

第 3-N 次: 任何工具任何语法
  → curl / wget / python / powershell / node / 浏览器 MCP / 任何工具
  → 全部在"检查 0"直接拦截 (exit 2)
  → 因为基于 target (host+path)，不是基于命令语法
```

---

## CLI 工具

```bash
# 查看拦截记录
python Luminx-hook/check_intercepted.py list
python Luminx-hook/check_intercepted.py list --severity critical
python Luminx-hook/check_intercepted.py list --limit 20

# 查看某条详情 (含手动测试命令)
python Luminx-hook/check_intercepted.py detail 3

# 查看会话统计
python Luminx-hook/check_intercepted.py session

# 查看拦截统计
python Luminx-hook/check_intercepted.py stats

# 清除所有记录和会话状态 (重置预拦截名单)
python Luminx-hook/check_intercepted.py clear
```

---

## 自定义规则

编辑 `config/` 下的 JSON 文件：

### 添加自定义 Shell 拦截规则

在 `critical_destruction.json` 的 `rules` 数组中添加：

```json
{
  "id": "custom_my_cmd",
  "pattern": "\\bmy_dangerous_command\\b",
  "description": "自定义：拦截特定危险命令",
  "severity": "critical"
}
```

### 添加自定义 URL 危险关键词

在 `dangerous_keywords.json` 的 `url_segment_keywords` 中添加：

```json
{
  "critical": [
    {"keyword": "nuke", "description": "核弹级删除"}
  ]
}
```

### 添加自定义 HTTP 工具模式

在 `dangerous_http_methods.json` 的 `tool_patterns` 中添加：

```json
{
  "mycli": [
    {"pattern": "\\bmycli\\s+(DELETE|PATCH)\\b", "description": "自定义工具"}
  ]
}
```

---

## 安全设计原则

| 原则 | 实现 |
|------|------|
| **FAIL CLOSED** | 钩子崩溃 → exit 2 (拒绝)，不放行 |
| **语法无关** | 预拦截基于 target (host+path)，不依赖正则 |
| **全工具覆盖** | `pre_generic.py` 空 matcher 匹配所有工具 |
| **全量留痕** | 拦截日志 + 审计日志 + 会话状态三重记录 |
| **崩溃防护** | surrogate 清理、UTF-8 容错、延迟导入 |
| **意图指纹** | 跨进程跨工具追踪同一危险意图的重复尝试 |

---

## 常见问题

### Q: AI 仍然尝试绕过怎么办？

A: 检查 `python Luminx-hook/check_intercepted.py session` 确认预拦截是否激活。如果同一目标被拦截 2 次以上仍未进入预拦截名单，运行 `python Luminx-hook/selftest.py` 诊断。

### Q: 误报了怎么办？

A: 
1. 临时：`python Luminx-hook/check_intercepted.py clear` 清除状态
2. 永久：在 `config/` 中调整规则
3. 单次：在终端手动执行被拦截的命令（hook 只拦截 Claude Code 内操作）

### Q: 如何临时禁用某个 hook？

A: 在 `.claude/settings.local.json` 中注释或删除对应的 hook 条目。

### Q: PUT 请求被拦截？

A: PUT 已默认放行。如果仍被拦截，检查是否因为 URL 路径中包含危险关键词（如 `/api/delete`）。

### Q: Hook 报错 "No stderr output"？

A: 运行 `python Luminx-hook/selftest.py` 确认所有检查通过。此错误通常是 Python 子进程环境问题，重启 Claude Code 通常解决。

### Q: 浏览器 MCP 工具绕过沙箱？

A: `pre_generic.py` 已覆盖所有 MCP 工具（包括 `js-reverse`, `chrome-devtools`, `puppeteer` 等），检测 `fetch()` / `axios` / `XHR` 中的危险请求。

---

## 版本

v5 — 目标级预拦截 + 全工具覆盖 + FAIL CLOSED

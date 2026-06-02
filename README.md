[README.md](https://github.com/user-attachments/files/28511299/README.md)
# Luminx-hook — Claude Code AI 渗透安全沙箱

渗透测试专用安全沙箱。静默拦截 AI 不可逆操作，全量审计留痕。

> **危险行为 0 执行 · 测试流程 0 中断 · 攻击链路 100% 留痕**
![Uploading image.png…]()

---

## 快速开始

```bash
# 1. 配置路径
cp .claude/settings.local.template.json .claude/settings.local.json
# 编辑 settings.local.json，用实际路径替换所有 <你的路径>

# 2. 自检
python Luminx-hook/selftest.py
# → 11/11 PASS

# 3. 启动 Claude Code
```

---

## 架构

### Claude Code 五层 Hook

| 层 | 事件 | 脚本 | 拦截范围 |
|----|------|------|---------|
| 1 | `PreToolUse` | `pre_generic.py` | **所有工具** — URL/原始HTTP/fetch/axios/XHR/for循环 |
| 1 | `PreToolUse` | `pre_bash.py` | Bash 深度检查 — shell/SQL/HTTP方法/URL关键词/脚本追踪 |
| 1 | `PreToolUse` | `pre_edit.py` | Write/Edit — 路径保护 + **文件内容扫描** |
| 1 | `PreToolUse` | `pre_webfetch.py` | WebFetch URL 关键词 |
| 2 | `PostToolUse` | `post_tool.py` | 全量审计日志 |
| 3 | `Notification` | `notify.py` | 通知记录 |
| 4 | `UserPromptSubmit` | `user_prompt.py` | 提示词绕过意图检测 |
| 5 | `Stop` | `stop.py` | 会话汇总报告 |

### 文件结构

```
Luminx-hook/
├── hooks/
│   ├── pre_generic.py       # 全工具通配符 (空matcher)
│   ├── pre_bash.py          # Bash 深度检查
│   ├── pre_edit.py          # Write/Edit 路径+内容
│   ├── pre_webfetch.py      # WebFetch
│   ├── post_tool.py         # 全量审计
│   ├── notify.py / user_prompt.py / stop.py
│   ├── state.py             # 意图指纹 + 预拦截名单
│   └── logger.py            # JSONL + 崩溃日志
├── config/                  # 规则配置 (JSON)
├── selftest.py              # 11项自检
├── check_intercepted.py     # CLI 查看工具
└── logs/                    # 运行时日志 (gitignore)
```

---

## 拦截策略

| 优先级 | 检查项 | 拦截内容 |
|--------|--------|---------|
| **0** | 预拦截名单 | 被拦2+次的 host+path，任何工具直接拦截 |
| **1** | 破坏性 Shell | `rm -rf`, `format`, `shutdown`, `dd`, `diskpart` |
| **2** | SQL 破坏 | `DROP TABLE`, `DELETE FROM`, `TRUNCATE` |
| **3** | HTTP 方法 | `DELETE`, `PATCH`（PUT 已放行） |
| **4** | URL 关键词 | `/delete`, `/remove`, `/destroy`, `/purge`, `/drop` |
| **5** | 请求体 | `--data` 中的 `"action":"delete"` 等 |
| **6** | 绕过检测 | base64/printf/xargs + HTTP 组合 |
| **7** | 脚本文件 | 追踪 `bash/py/node/./script` 并扫描内容 |
| **8** | 文件内容 | Write/Edit 写入内容自动扫描 |
| **9** | 原始HTTP | Burp/Postman/HTTPie MCP 的 `DELETE /path HTTP/1.1` |
| **10** | 浏览器JS | MCP 浏览器内 `fetch()/axios/XHR` DELETE |

### 已关闭的绕过路径

| 绕过手法 | 对策 |
|----------|------|
| 换工具 (curl→python→browser) | `pre_generic` 空matcher + 工具去重 |
| 写脚本→执行脚本 | `pre_edit` 内容扫描 + `pre_bash` 脚本追踪 |
| Burp/Postman MCP | 原始HTTP请求行检测 |
| 浏览器JS fetch/axios | JS模式检测 |
| for循环批量扫描 | 路径展开检测 |
| 变量/编码/引号拼接 | 规范化+绕过检测 |
| heredoc/grep模式误报 | 上下文剥离（不把数据当命令） |

### 放行

```
✅ nmap / sqlmap(只读) / dirb / gobuster / subfinder / amass
✅ curl GET/HEAD/OPTIONS/PUT
✅ 读取文件、查看配置
✅ 漏洞扫描、PoC 验证 (只读)
✅ 认证逻辑测试
```

---

## 预拦截机制

```
第 1 次拦截: curl -X DELETE https://target.com/api/delete
  → 指纹: target.com|/api/delete|*

第 2 次拦截: python requests.delete("https://target.com/api/delete")
  → 指纹匹配 → 激活预拦截

第 3+ 次: 任何工具、任何语法、任何写法 → 直接拦截
  → 基于 target (host+path)，不是基于命令语法
```

---

## CLI 工具

```bash
python Luminx-hook/check_intercepted.py list              # 拦截列表
python Luminx-hook/check_intercepted.py list -s critical  # 只看严重
python Luminx-hook/check_intercepted.py detail 3          # 第3条详情
python Luminx-hook/check_intercepted.py session           # 会话状态
python Luminx-hook/check_intercepted.py stats             # 统计
python Luminx-hook/check_intercepted.py clear             # 清除+重置
```

---

## 自定义规则

编辑 `config/` 下的 JSON：

### 添加 Shell 拦截

```json
// critical_destruction.json → rules
{"id": "my_rule", "pattern": "\\bmy_cmd\\b", "description": "自定义", "severity": "critical"}
```

### 添加 URL 关键词

```json
// dangerous_keywords.json → url_segment_keywords.critical
{"keyword": "nuke", "description": "核弹操作"}
```

### 放行/拦截 HTTP 方法

```json
// dangerous_http_methods.json → blocked_methods
"critical": ["DELETE"], "high": ["PATCH"]
```

---

## 常见问题

**Q: AI 浪费 token 研究为什么被拦截？**

A: deny 消息已砍到 3 行，不透露任何机制细节。AI 能看到的信息只有 "Stop. Tell the user."

**Q: 误报？**

A: `python Luminx-hook/check_intercepted.py clear` 临时清除，或修改 `config/` 永久调整。

**Q: 钩子报错？**

A: 查看 `logs/crash.log` 定位根因。重启 Claude Code 通常解决。

**Q: 浏览器 MCP / Burp MCP 绕过？**

A: `pre_generic.py` 已覆盖所有 MCP 工具，检测 URL + 原始HTTP + JS fetch/axios。

**Q: 临时禁用？**

A: 注释 `.claude/settings.local.json` 中对应条目。

---

## 安全设计

| 原则 | 实现 |
|------|------|
| **FAIL CLOSED** | 钩子崩溃 → exit 2 拒绝 |
| **语法无关** | 预拦截基于 target (host+path) |
| **全工具覆盖** | 空matcher + 工具去重 |
| **全量留痕** | 拦截日志 + 审计日志 + 崩溃日志 |
| **短 deny 消息** | 3行，不泄露机制 |

---

v5.1 — 全工具覆盖 · 脚本追踪 · 内容扫描 · FAIL CLOSED

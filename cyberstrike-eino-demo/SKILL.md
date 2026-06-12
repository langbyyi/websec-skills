---
name: cyberstrike-eino-demo
description: 满配示例技能包：SKILL.md + scripts/、references/、assets/ 等可选目录；验证 Eino skill 与 HTTP 包内路径（仅授权安全测试与教学）。
---

# CyberStrike × Eino 满配技能演示

> **AI LOAD INSTRUCTION**: Demo skill package showcasing full Eino skill structure: SKILL.md + scripts/, references/, assets/ subdirectories. Use when testing skill packaging, HTTP API skill retrieval (/api/skills), resource_path access, or multi-agent ADK skill tool integration. This is a validation and onboarding skill, not a vulnerability exploitation playbook.

本包与 [Agent Skills](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview) 一致：**`SKILL.md` 为清单 + 主说明**（无单独 `SKILL.yaml`）。同目录可有 **`scripts/`**、**`references/`**、**`assets/`** 等任意子目录（只要路径安全、未触达包深度/文件数上限），由 **`ListPackageFiles` / `resource_path`** 与 Eino 本机工具读取。补充说明见 `FORMS.md`、`REFERENCE.md`。

## QUICK START

### First-pass probes

| Signal | Probe | Why |
|---|---|---|
| Skill loaded? | `GET /api/skills` — check list includes `cyberstrike-eino-demo` | Verifies skill is registered and indexed |
| Listed with metadata? | Check `script_count`, `file_count`, `progressive` fields | Confirms package structure was scanned |
| `depth=full` works? | `GET /api/skills/cyberstrike-eino-demo?depth=full` | Returns complete SKILL.md content |
| `section=` param works? | `GET /api/skills/cyberstrike-eino-demo?section=payload` | Tests section resolution against `##` headings |
| `resource_path` works? | `GET ...?resource_path=scripts/payloads.txt` | Verifies subdirectory file access |

```bash
# Quick test — verify skill package endpoints
curl -s http://localhost:8080/api/skills | jq '.[] | select(.name=="cyberstrike-eino-demo")'
curl -s "http://localhost:8080/api/skills/cyberstrike-eino-demo?section=payload"
```

---

## 概述

用于一次性验证：

- HTTP `GET /api/skills` 列表（`script_count`、`file_count`、`progressive` 等为推导/扫描结果）
- `GET /api/skills/cyberstrike-eino-demo?depth=summary|full`
- `section=` 对应 `SKILL.md` 中 **`##` 标题**或 ASCII 标题的短 id（例如 `## Payload 样例` 常对应 `section=payload`）
- 多代理内 ADK **`skill`** 工具（及可选本机文件工具）读取包内相对路径资源
- Eino `FilesystemSkillsRetriever` 对包摘要、`##` 分块、脚本条目的检索

**硬性要求**：任何测试须取得书面授权，并限定在约定范围与时间窗口内。

## 授权测试工作流

1. **范围确认**：域名 / IP、接口列表、禁止动作（DoS、数据拖库等）。
2. **基线记录**：对约定资产做只读探测，保存时间戳与原始请求/响应摘要。
3. **分类测试**：按漏洞类型拆分任务；高风险操作前二次确认授权边界。
4. **证据与报告**：每个发现附带复现步骤、影响、修复建议；敏感数据脱敏。
5. **收尾**：删除临时账号、清理测试数据、移交报告。

## Payload 样例

以下为 **教学占位**，实际测试需替换为目标上下文且不得用于未授权系统：

- SQLi 探测（错误型）：`"'`（观察是否触发数据库错误信息泄露）
- XSS 反射型（无害化）：`<script>alert(1)</script>` → 在靶场中应被编码或 CSP 拦截
- 路径穿越（只读验证）：`....//....//etc/passwd`（仅在授权文件读取场景）

详细列表见 `scripts/payloads.txt`。

## references/ 与 assets/

用于验证非 `scripts/` 的子目录是否被同等对待：

| 路径 | 用途 |
|------|------|
| `references/citations.md` | 引用与 HTTP `resource_path` 测试说明 |
| `assets/README.txt` | 占位资源（可换成真实二进制做读文件上限测试） |

## 推荐工具链

| 阶段 | 工具示例 |
|------|-----------|
| 代理与重放 | Burp Suite、mitmproxy |
| 扫描与目录 | ffuf、nuclei（需调低并发遵守授权） |
| 漏洞验证 | 自写 PoC、官方 CLI（sqlmap 等）仅在授权范围内 |
| 记录 | Markdown + JSON 片段模板（见 `scripts/report-snippet.json`） |

---

## SKILL PACKAGE STRUCTURE

```text
cyberstrike-eino-demo/
├── SKILL.md              ← Main skill document (this file)
├── FORMS.md              ← Supplementary form definitions
├── REFERENCE.md          ← Extended reference material
├── scripts/
│   ├── payloads.txt      ← Example payload list (teaching only)
│   ├── check-env.sh      ← Environment validation script
│   └── report-snippet.json ← JSON report template
├── references/
│   └── citations.md      ← External reference links
└── assets/
    └── README.txt        ← Placeholder resource file
```

### Package Loading Behavior

| Action | What Happens |
|--------|-------------|
| `GET /api/skills` | Lists all skills with `script_count`, `file_count`, `progressive` metadata |
| `GET /api/skills/cyberstrike-eino-demo?depth=summary` | Returns frontmatter + section headers only |
| `GET /api/skills/cyberstrike-eino-demo?depth=full` | Returns complete SKILL.md content |
| `GET /api/skills/cyberstrike-eino-demo?section=payload` | Returns content under `## Payload 样例` section |
| `resource_path=scripts/payloads.txt` | Returns raw file content from scripts/ directory |
| ADK `skill` tool | Loads package context; uses `resource_path` for file access |

### Section Resolution

The `section=` query parameter matches `##` headings in SKILL.md. Common mappings:

| section= value | Matches heading |
|---|---|
| `payload` | `## Payload 样例` |
| `tools` | `## 推荐工具链` |
| `checklist` | `## TESTING CHECKLIST` |
| `decision-tree` | `## DECISION TREE` |
| `workflow` | `## 授权测试工作流` |

## DECISION TREE

```
CyberStrike Eino demo skill loaded?
├── Testing skill packaging and retrieval?
│   └── Verify GET /api/skills list, depth=summary|full, section= resolution
├── Testing resource path access?
│   └── Verify scripts/, references/, assets/ paths via resource_path
├── Testing multi-agent ADK integration?
│   └── Verify skill tool can load package and access relative-path resources
└── General authorized security test?
    └── Follow standard workflow: scope → baseline → classify → evidence → report
```

## TESTING CHECKLIST

- [ ] Confirm written authorization and test window are documented
- [ ] Verify `scripts/` files match references in the SKILL.md body
- [ ] Verify `GET /api/skills` returns the skill with correct `script_count` and `file_count`
- [ ] Verify `GET /api/skills/cyberstrike-eino-demo?depth=summary` and `depth=full` return expected sections
- [ ] Verify `section=` parameter resolves to correct `##` heading (e.g., `section=payload` for "Payload 样例")
- [ ] Verify `resource_path=scripts/payloads.txt` returns file content via HTTP
- [ ] Verify `resource_path=references/citations.md` and `resource_path=assets/README.txt` are readable
- [ ] Verify multi-agent ADK `skill` tool can load the package and access relative-path resources
- [ ] Clean up: delete temporary accounts, test data, and confirm report handoff

## MCP TOOLS

| Tool | Use Case |
|------|----------|
| `http_framework_test` | Send crafted HTTP requests to authorized targets for vulnerability verification, parameter tampering, and endpoint testing |
| `nuclei_scan` | Run Nuclei templates for automated vulnerability detection across authorized test targets with controlled concurrency |
| `browser_agent_inspect` | Inspect web application pages for endpoint discovery, technology fingerprinting, and security feature verification during authorized assessments |

## 清单与验证

- [ ] 已保存书面授权与测试窗口
- [ ] `scripts/` 下文件与正文引用一致
- [ ] Web 或 `GET /api/skills?...` 可核对索引；多代理会话内用 **`skill`** 工具按包加载以节省 token
- [ ] 需要细节时通过 **`skill`** 拉全文，或 HTTP `depth=full`、`section=<标题或短 id>`
- [ ] 需要脚本原文时通过本机文件工具或 HTTP `resource_path=scripts/check-env.sh`
- [ ] `resource_path=references/citations.md` 与 `resource_path=assets/README.txt` 可读取

## RELATED ROUTING

- [recon-and-methodology](../recon-and-methodology/SKILL.md) — recon methodology for structured target discovery
- [burp-mcp](../burp-mcp/SKILL.md) — Burp-based vulnerability verification workflow

---
name: supplyguard
version: 1.0.0
description: "AI 编程时代的供应链安全防御工具。扫描 npm 项目依赖，检测 AI 幻觉包、CVE、许可证风险，输出 Agent 推理过程与裁决建议。当用户提到 npm 依赖安全、供应链审计、slopsquatting、CVE 扫描、package-lock 检查、依赖守门时使用。"
metadata:
  requires:
    bins: ["supplyguard"]
---

# SupplyGuard

AI 编程时代的供应链安全防御工具。核心能力：扫描 npm 项目依赖，检测 AI 幻觉包、CVE、许可证风险，提供 Agent 推理过程与裁决建议。

## 前置条件

- `supplyguard` 二进制已安装并在 PATH 中
- 目标目录包含 `package-lock.json`（npm 项目）
- 首次运行会自动下载/更新本地漏洞数据库（OSV + SPDX）

## 命令

### 1. 单次扫描

```bash
supplyguard scan <directory> [--json]
```

- `<directory>`：包含 `package-lock.json` 的 npm 项目路径
- `--json`：输出 JSON 格式（AI 解析用，默认）
- 不加 `--json`：输出人类可读格式

**输出字段（JSON）：**

```json
{
  "session_id": "scan-20260902-1432",
  "status": "sealed",
  "packages_total": 128,
  "verdicts": {
    "allow": 114,
    "review": 12,
    "block": 2
  },
  "findings": [
    {
      "package": "fictional-pkg-xyz",
      "version": "1.0.0",
      "verdict": "BLOCK",
      "reasoning": "注册时间 <7天，词频异常，npm registry 无有效记录",
      "evidence": ["registry_miss", "recent_registration", "name_suspicious"],
      "confidence": 0.95,
      "agent": "hallucination"
    }
  ],
  "reasoning_summary": "对 128 个包完成多信号分析...",
  "audit_hash": "a3f2b8c9d4e5..."
}
```

**verdict 值：**
- `ALLOW` — 低风险，自动放行
- `REVIEW` — 需人工确认（CVE Medium、许可证异常等）
- `BLOCK` — 高风险，建议拦截（幻觉包、CVE Critical、恶意 install 脚本）

### 2. 依赖变更守门

```bash
supplyguard guard <diff-file> [--json]
```

- `<diff-file>`：`package-lock.json` 的变更 diff 文件路径
- 用于 CI / PR 评审前，对依赖变更做安全裁决

**输出字段（JSON）：**

```json
{
  "session_id": "guard-20260902-1500",
  "status": "sealed",
  "changes": [
    {
      "package": "lodash",
      "from": "4.17.20",
      "to": "4.17.21",
      "verdict": "ALLOW",
      "reasoning": "patch 升级，无 CVE，许可证 MIT"
    },
    {
      "package": "axios",
      "from": "1.5.0",
      "to": "1.6.0",
      "verdict": "REVIEW",
      "reasoning": "命中 CVE-2023-45857 (Medium SSRF)"
    }
  ]
}
```

### 3. 持续监控

```bash
supplyguard monitor <directory> [--json]
```

- `<directory>`：要监控的 npm 项目路径
- 持续监听 `package-lock.json` 变化
- 变化时自动触发 Agent 分析，输出 SSE 事件到 stdout

**SSE 事件格式：**

```
event: change_detected
data: {"type":"patch","detail":"lodash 4.17.20 → 4.17.21","timestamp":"2026-09-02T14:32:05Z"}

event: analysis_complete
data: {"verdict":"ALLOW","reasoning":"...","confidence":0.98}

event: user_decision_required
data: {"session_id":"monitor-abc123","findings":[...]}
```

**注意：** `monitor` 命令会持续运行，直到用户手动停止（Ctrl+C）。

### 4. 实时状态查询

```bash
supplyguard overview [--json]
```

- 返回当前所有活跃会话 + 统计数据

**输出字段（JSON）：**

```json
{
  "active_sessions": [
    {
      "session_id": "monitor-abc123",
      "mode": "monitor",
      "target": "./frontend-app",
      "status": "running",
      "packages": 128,
      "last_scan": "2026-09-02T14:32:05Z"
    }
  ],
  "stats": {
    "total_scans": 42,
    "total_findings": 156,
    "blocked": 3,
    "review": 15
  }
}
```

### 5. 推理时间线

```bash
supplyguard timeline <session-id> [--json]
```

- 返回指定会话的 Agent 推理时间线

**输出字段（JSON）：**

```json
{
  "session_id": "scan-20260902-1432",
  "events": [
    {
      "timestamp": "2026-09-02T14:32:01Z",
      "agent": "Sentinel",
      "event": "initialized",
      "detail": "标记目标目录为 UNTRUSTED"
    },
    {
      "timestamp": "2026-09-02T14:32:02Z",
      "agent": "Analyst",
      "event": "sbom_built",
      "detail": "解析 package-lock.json v3，提取 128 个包"
    },
    {
      "timestamp": "2026-09-02T14:32:06Z",
      "agent": "Auditor",
      "event": "verdict_issued",
      "detail": "1 Allow / 1 Review / 1 Block"
    }
  ]
}
```

### 6. 审计链

```bash
supplyguard audit [--session <id>] [--verify]
```

- 返回审计链条目
- `--verify`：验证哈希链完整性

**输出字段（JSON）：**

```json
{
  "chain_length": 42,
  "verified": true,
  "entries": [
    {
      "index": 1,
      "session_id": "scan-20260902-1432",
      "timestamp": "2026-09-02T14:32:06Z",
      "decision": "BLOCK",
      "target": "fictional-pkg-xyz@1.0.0",
      "hash": "a3f2b8c9d4e5...",
      "prev_hash": "000000..."
    }
  ]
}
```

## 触发场景

当用户出现以下意图时，调用 `supplyguard`：

| 用户意图 | 推荐命令 | 说明 |
|---------|---------|------|
| "扫描 ./my-app 的依赖安全" | `supplyguard scan ./my-app` | 全量扫描 |
| "检查 package-lock.json 有没有问题" | `supplyguard scan .` | 当前目录扫描 |
| "对这次依赖变更做安全审查" | `supplyguard guard changes.diff` | CI / PR 场景 |
| "持续监控 ./my-app" | `supplyguard monitor ./my-app` | 后台持续监听 |
| "当前监控状态如何" | `supplyguard overview` | 实时查询 |
| "查看上次扫描的推理过程" | `supplyguard timeline <id>` | 审计 / 复盘 |
| "审计链是否完整" | `supplyguard audit --verify` | 合规检查 |

## 输出处理策略

### JSON 模式（默认）

所有命令默认输出 JSON（`--json` 是默认行为）。AI Agent 应该：

1. **解析 JSON**：提取 `findings`、`verdicts`、`reasoning_summary` 等关键字段
2. **优先级排序**：`BLOCK` > `REVIEW` > `ALLOW`，先展示高风险
3. **摘要呈现**：不全屏堆 JSON，给用户看：
   - 扫描了多少包
   - 发现几个 BLOCK / REVIEW
   - 最关键的风险是什么（幻觉包 / CVE）
   - Agent 的推理一句话总结
4. **推理透明**：展示 Agent 的 reasoning 和 evidence，让用户理解为什么判定为 BLOCK

### 人类可读模式（`--pretty`）

```bash
supplyguard scan ./my-app --pretty
```

用于用户直接 CLI 查看，AI Agent 不需要处理这种输出。

## 关键约束

1. **误报可容忍，漏报不可** — 不确定时倒向"更安全"
2. **推理必须可解释** — 每个 verdict 都附带 reasoning + evidence
3. **一切留痕** — 所有裁决写入审计链，可回放
4. **本地优先** — 默认不依赖外部 SaaS，联网是增强
5. **离线可用** — 本地数据库覆盖核心场景，联网更新是后台行为

## 错误处理

| 错误场景 | AI 处理方式 |
|---------|-----------|
| 目录不存在 / 无 package-lock.json | 告诉用户"目标目录不是有效的 npm 项目" |
| 本地数据库损坏 | 告诉用户"本地漏洞数据库损坏，请运行 `supplyguard update` 重新下载" |
| 网络不可用（OSV / npm 查询失败） | 降级为离线模式，使用本地缓存，标注"部分结果可能过时" |
| 权限不足（无法读取目录） | 告诉用户"无法读取目标目录，请检查权限" |

## 与其他工具的协作

SupplyGuard 专注 npm 供应链安全，不替代：

| 工具 | 定位 | 协作方式 |
|------|------|---------|
| `npm audit` | 官方 CVE 检查 | SupplyGuard 包含 npm audit 能力，但额外检测幻觉包 |
| `snyk` / `dependabot` | 企业级 SCA | SupplyGuard 检测它们检测不到的 AI 时代新攻击面 |
| `socket.dev` | 包行为分析 | SupplyGuard 关注供应链上游（npm registry / OSV），不分析 install 脚本行为 |

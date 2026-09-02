# SupplyGuard 架构设计

> 版本：v1.0（2026-09-02）
> 分支：`mcp-server-architecture`

---

## 1. 产品定位

**SupplyGuard**：面向 AI 编程时代的团队级供应链安全防御 CLI 工具。

- 核心用户：中小团队的全栈 / 安全工程师
- 使用方式：AI 助手（Claude Desktop / Cursor）调用 CLI，或直接命令行使用
- 部署方式：单二进制文件，零外部依赖，可离线运行

## 2. 核心能力

| 能力 | 命令 | 说明 |
|------|------|------|
| 单次扫描 | `scan <dir>` | 扫描 npm 项目依赖，输出 Agent 裁决 |
| 依赖守门 | `guard <diff>` | 对依赖变更做安全审查 |
| 持续监控 | `monitor <dir>` | 监听 package-lock.json 变化，实时推送 |
| 状态查询 | `overview` | 实时查询活跃会话 + 统计 |
| 推理时间线 | `timeline <id>` | 查看 Agent 推理过程 |
| 审计链 | `audit` | 审计链条目 + 完整性验证 |

## 3. 系统架构

```
┌─────────────────────────────────────────────┐
│                 AI Agent                    │
│         (Claude Desktop / Cursor)           │
│                                             │
│  1. 读取 SKILL.md                           │
│  2. 识别用户意图（npm / 依赖 / CVE）        │
│  3. 调用 supplyguard CLI                    │
│  4. 解析 JSON 输出                          │
│  5. 呈现摘要给用户                          │
└──────────────────┬──────────────────────────┘
                   │ stdin/stdout (JSON)
                   ▼
┌─────────────────────────────────────────────┐
│           SupplyGuard CLI                   │
│                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  scan    │  │  guard   │  │ monitor  │  │
│  │  overview│  │ timeline │  │  audit   │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│       └──────────────┼──────────────┘       │
│                      ▼                      │
│           ┌──────────────────┐              │
│           │  Orchestrator    │              │
│           │  (状态机 + 事件)  │              │
│           └────────┬─────────┘              │
│                    ▼                         │
│  ┌──────────────────────────────────────┐   │
│  │         Agent 管道                    │   │
│  │  Sentinel → Analyst → Auditor        │   │
│  │  Hallucination → CVE → License       │   │
│  └──────────────────────────────────────┘   │
│                    ▼                         │
│  ┌──────────────────────────────────────┐   │
│  │         数据层                        │   │
│  │  • SQLite (Session + Audit Chain)    │   │
│  │  • OSV 本地数据库                    │   │
│  │  • SPDX 许可证库                     │   │
│  │  • npm registry API (实时)           │   │
│  └──────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

## 4. 目录结构

```
supplyguard/
├── Cargo.toml
├── src/
│   ├── main.rs              # CLI 入口（clap）
│   ├── lib.rs
│   ├── config/              # 配置解析（supplyguard.toml）
│   │   └── mod.rs
│   ├── pipeline/
│   │   ├── mod.rs           # Orchestrator（状态机 + 事件）
│   │   └── orchestrator.rs
│   ├── agents/
│   │   ├── mod.rs
│   │   ├── sentinel.rs      # 初始化 / 边界守护
│   │   ├── analyst.rs       # 依赖图分析 / SBOM
│   │   ├── hallucination.rs # 幻觉包检测
│   │   ├── cve.rs           # CVE 匹配
│   │   ├── license.rs       # 许可证检查
│   │   ├── auditor.rs       # 综合裁决
│   │   └── remediator.rs    # 修复策略
│   ├── skills/              # 可复用技能模块
│   │   ├── mod.rs
│   │   ├── sbom_build.rs
│   │   ├── hallucination_check.rs
│   │   ├── cve_match.rs
│   │   ├── license_check.rs
│   │   └── risk_profile.rs
│   ├── mcp/                 # 外部数据源（MCP = 最小化数据协议）
│   │   ├── mod.rs
│   │   ├── osv_local.rs     # OSV 本地数据库
│   │   ├── npm_local.rs     # npm registry 客户端
│   │   └── license_spdx.rs  # SPDX 许可证库
│   ├── store/               # 持久化
│   │   ├── mod.rs
│   │   └── session.rs       # SessionStore (SQLite)
│   ├── audit/               # 审计链
│   │   ├── mod.rs
│   │   └── chain.rs         # HMAC-SHA256 不可变链
│   └── output/              # 输出格式化
│       ├── mod.rs
│       └── json.rs          # JSON 序列化
├── tests/                   # 集成测试
│   ├── scan_integration.rs
│   └── guard_integration.rs
├── fixtures/                # 测试数据
│   ├── demo-app/
│   ├── lockfiles/
│   └── diffs/
└── SKILL.md                 # AI Agent 调用指南
```

## 5. 核心数据结构

```rust
// 会话状态机
enum SessionState {
    Created,
    Scanning,
    Analyzing,
    AwaitingVerdict,
    Decided,
    Sealed,
    Failed,
}

// 裁决结果
struct Verdict {
    package: String,
    version: String,
    decision: VerdictDecision, // ALLOW / REVIEW / BLOCK
    reasoning: String,
    evidence: Vec<String>,
    confidence: f64,
    agent: String,
}

enum VerdictDecision {
    Allow,
    Review,
    Block,
}

// 审计条目
struct AuditEntry {
    index: u64,
    session_id: String,
    timestamp: i64,
    decision: VerdictDecision,
    target: String,
    hash: String,
    prev_hash: String,
}
```

## 6. 技术栈

| 组件 | 技术选型 | 理由 |
|------|---------|------|
| CLI 框架 | clap (derive) | Rust 生态标准，子命令丰富 |
| 序列化 | serde + serde_json | 标准库，性能好 |
| 错误处理 | thiserror | 模块化错误类型 |
| 数据库 | rusqlite (bundled) | 嵌入式 SQLite，零系统依赖 |
| 密码学 | hmac + sha2 + hex | 审计链签名，标准库 |
| 配置 | toml | Rust 生态维护状态好 |
| 异步运行时 | tokio (rt-multi-thread) | 监控模式 + SSE 需要 async |
| 文件监听 | notify | 跨平台文件系统监听 |
| HTTP 客户端 | reqwest (rustls-tls) | npm registry API 调用（可选） |
| 日志 | tracing + tracing-subscriber | 结构化日志 |

## 7. 依赖允许清单

```toml
[dependencies]
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"
toml = "0.8"
rusqlite = { version = "0.31", features = ["bundled"] }
hmac = "0.12"
sha2 = "0.10"
hex = "0.4"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
notify = "6"
reqwest = { version = "0.11", features = ["rustls-tls", "json"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json"] }
uuid = { version = "1", features = ["v4"] }

[dev-dependencies]
tempfile = "3"
assert_cmd = "2"
predicates = "3"
```

## 8. 输出格式规范

### 默认输出（--json）

所有命令默认输出 JSON，格式遵循以下原则：

1. **顶层字段一致**：所有输出包含 `session_id`、`status`、`timestamp`
2. **错误输出**：`{"error": {"code": "...", "message": "..."}}`
3. **版本输出**：`{"version": "0.1.0", "build": "2026-09-02"}`
4. **人类可读**：`--pretty` 标志输出格式化文本

### SSE 输出（monitor 模式）

monitor 命令持续运行，通过 stdout 输出 SSE 事件：

```
event: scan_started
data: {"session_id":"monitor-abc123","target":"./frontend-app"}

event: change_detected
data: {"type":"patch","detail":"lodash 4.17.20 → 4.17.21"}

event: analysis_complete
data: {"verdict":"ALLOW","reasoning":"...","confidence":0.98}

event: user_decision_required
data: {"session_id":"monitor-abc123","findings":[...]}

event: audit_committed
data: {"session_id":"monitor-abc123","hash":"a3f2b8c9..."}
```

## 9. 配置管理

```toml
# supplyguard.toml

[monitor]
auto_analyze = true
notify = true
include_dev = true

[updates]
osv_auto_update = true
spdx_auto_update = true
update_interval_hours = 24

[audit]
chain_file = ".supplyguard/audit-chain.json"
session_dir = ".supplyguard/sessions"
```

## 10. 错误处理规范

- 每个模块定义自己的 `#[derive(Debug, thiserror::Error)]`
- 跨模块传播时在边界转换为下层错误
- CLI 层才允许把错误渲染为人类可读信息并转退出码
- 禁止 `anyhow`、禁止 `Box<dyn Error>` 作为公开签名
- 禁止生产代码路径上的 `unwrap` / `expect` / `panic!`

## 11. 命名规范

- 类型：PascalCase
- 函数 / 变量：snake_case
- 常量：SCREAMING_SNAKE_CASE
- 文件：snake_case

## 12. 实施优先级

| 优先级 | 任务 | 预计时间 |
|--------|------|---------|
| P0 | 项目骨架（Cargo.toml + main.rs + clap） | 1h |
| P0 | 配置解析（supplyguard.toml） | 1h |
| P0 | SQLite SessionStore | 2h |
| P0 | AuditChain（HMAC-SHA256） | 2h |
| P1 | Orchestrator（状态机 + 事件） | 3h |
| P1 | Sentinel agent | 1h |
| P1 | Analyst agent（SBOM 解析） | 3h |
| P1 | Hallucination agent | 2h |
| P1 | CVE agent（OSV 集成） | 2h |
| P1 | License agent（SPDX 集成） | 2h |
| P1 | Auditor agent（综合裁决） | 2h |
| P1 | Remediator agent | 1h |
| P2 | scan 命令 + JSON 输出 | 2h |
| P2 | guard 命令 + JSON 输出 | 2h |
| P2 | monitor 命令 + SSE | 3h |
| P2 | overview / timeline / audit 命令 | 2h |
| P3 | 本地 OSV / SPDX 数据库 | 4h |
| P3 | npm registry API 集成 | 2h |
| P3 | 集成测试 | 3h |
| P3 | SKILL.md 编写与验证 | 2h |

**总计：约 40 小时（5 个工作日）**

## 13. 验证方式

每个功能完成后，必须通过以下验证：

1. **单元测试**：`cargo test`
2. **CLI 冒烟测试**：`supplyguard scan ./fixtures/demo-app --json`
3. **AI Agent 调用测试**：在 Claude Desktop 中配置 SKILL.md，真实调用
4. **审计链验证**：`supplyguard audit --verify`

## 14. 下一步行动

1. 确认本文档方向
2. 开始 P0：项目骨架 + CLI 框架
3. 实现 scan 命令（最小可用版本）
4. 在 Claude Desktop 中测试真实调用

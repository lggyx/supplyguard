# SupplyGuard MCP Server 架构可行性分析

> 分支：`mcp-server-architecture`
> 版本：v1.0（2026-09-02）
> 状态：可行性分析阶段

---

## 1. 分析目标

验证 **SupplyGuard 从 "Rust CLI + Web UI" 重构为 "纯 MCP Server"** 的逻辑链是否闭合，识别技术风险与实施障碍。

---

## 2. 现有能力盘点（代码事实）

### 2.1 已实现的核心能力

| 能力 | 位置 | 状态 |
|------|------|------|
| CLI 命令（scan / guard / monitor / serve） | `src/main.rs` + `src/clap` | ✅ 已实现 |
| LocalOrchestrator（状态机 + 事件发布） | `src/runtime/orchestrator.rs` | ✅ 已实现 |
| Agent 管道（Sentinel / Analyst / Auditor / Remediator） | `src/agents/*.rs` | ✅ 已实现 |
| Skills（SBOM / Hallucination / CVE / License / RiskProfile） | `src/skills/*.rs` | ✅ 已实现 |
| MCP 数据层（OSV / npm / SPDX traits + local impl） | `src/mcp/*.rs` | ✅ 已实现 |
| AuditChain（HMAC-SHA256 不可变链） | `src/audit/chain.rs` | ✅ 已实现 |
| SessionStore（SQLite 持久化） | `src/runtime/store.rs` | ✅ 已实现 |
| Web SSE（实时事件推送） | `src/web/sse.rs` | ✅ 已实现 |
| REST API（overview / scans / timeline / audit） | `src/web/api.rs` | ✅ 已实现 |
| 前端原型（HTML/JS，6 个视图） | `design/supplyguard-flow/prototype.html` | ✅ 原型完成 |

### 2.2 缺失的能力（需要新增）

| 能力 | 说明 | 优先级 |
|------|------|--------|
| MCP Server transport（stdio / SSE） | 需要 `rmcp` crate 或自实现 | P0 |
| MCP Tools 定义（6 个 tool 的 JSON Schema） | 映射现有 CLI + REST 逻辑 | P0 |
| MCP Resources 定义（session/:id / audit-chain） | 只读查询接口 | P1 |
| MCP Prompts（可选） | audit-report 模板 | P2 |
| 前端完全移除 | axum + HTML/JS 不再需要 | P0 |

---

## 3. 逻辑链闭合性检查

### 3.1 调用链闭合

```
用户请求
  ↓
Claude Desktop (MCP Client)
  ↓ [MCP Protocol]
SupplyGuard MCP Server
  ↓ [Tool Call]
LocalOrchestrator (现有，无需修改)
  ↓ [Agent Pipeline]
Agent 管道 (现有，无需修改)
  ↓ [MCP Data Layer]
OSV / npm / SPDX (现有，无需修改)
  ↓ [Audit]
AuditChain (现有，无需修改)
  ↓ [Response]
MCP Client ← SupplyGuard MCP Server
  ↓
用户看到结果
```

**结论：调用链已闭合。** 现有核心逻辑（Orchestrator / Agents / Skills / AuditChain）完全不变，只需在入口处加一层 MCP transport。

### 3.2 数据流闭合

```
输入
  ├── scan: 目录路径 → SBOM → Agent 分析 → 裁决 → AuditChain
  ├── guard: diff 路径 → 解析变更 → Agent 分析 → 裁决 → AuditChain
  ├── monitor: 目录路径 → 监听 → 变化检测 → Agent 分析 → 裁决 → AuditChain
  └── overview/timeline/audit: 查询 SessionStore / AuditChain → 返回 JSON

输出
  ├── MCP Tool Result（JSON）
  ├── MCP Resource（JSON）
  └── MCP SSE Stream（实时事件）
```

**结论：数据流已闭合。** 所有输入输出都有明确的源和目的地，无孤儿数据。

### 3.3 状态管理闭合

```
SessionStore (SQLite)
  ├── 会话创建 / 更新 / 查询
  ├── 状态机（Created → Scanning → Analyzing → AwaitingVerdict → Decided → Sealed）
  └── 事件历史（OrchestratorEvent 序列）

AuditChain (HMAC-SHA256)
  ├── 审计条目追加
  ├── 链式哈希验证
  └── 不可变历史
```

**结论：状态管理已闭合。** MCP Tools 通过 Orchestrator 操作 SessionStore 和 AuditChain，无绕过。

### 3.4 实时性闭合

```
监控模式
  ├── MCP Server 内部：文件系统监听（notify / polling）
  ├── 变化检测 → Orchestrator 事件
  ├── SSE Stream 推送到 MCP Client
  └── Claude Desktop 实时展示给用户

查询模式
  ├── overview: 直接查询 SessionStore（<1ms）
  ├── timeline: 直接查询 SessionStore（<1ms）
  └── audit: 直接查询 AuditChain（<1ms）
```

**结论：实时性已闭合。** SSE Streaming 已有实现（`src/web/sse.rs`），可复用。

---

## 4. 技术可行性分析

### 4.1 MCP Server 实现方案

#### 方案 A：使用 `rmcp` crate（推荐）

```toml
[dependencies]
rmcp = "0.1"  # 或最新版本
```

**优势：**
- 官方 Rust MCP SDK，持续维护
- 支持 stdio 和 SSE transport
- 提供 Tool / Resource / Prompt 的声明式宏
- 与 axum 生态兼容（如果后续需要 HTTP transport）

**风险：**
- `rmcp` 可能还在快速迭代，API 可能变化
- 需要验证是否支持所有需要的 MCP 特性（如 SSE streaming）

#### 方案 B：自实现 MCP transport（不推荐）

**优势：** 完全控制
**风险：** 重复造轮子，MCP 协议细节复杂，容易出错

**结论：方案 A 可行，但需要先验证 `rmcp` 的稳定性。**

### 4.2 Transport 层对比

| Transport | 适用场景 | 复杂度 | 实时性 | 推荐 |
|-----------|---------|--------|--------|------|
| stdio | Claude Desktop 本地调用 | 低 | 不支持 SSE | ✅ 必做 |
| SSE | Web 前端 / 远程调用 | 中 | 支持 | ⭕ 可选（如果未来需要 Web UI） |
| HTTP (Streamable) | 远程调用 | 中 | 支持 | ⭕ 可选 |

**结论：stdio 是必须的，SSE 可后续添加。**

### 4.3 前端移除影响

| 组件 | 影响 | 解决方案 |
|------|------|----------|
| axum 服务器 | 不再需要 | 移除 `src/web/` |
| HTML/JS 前端 | 不再需要 | 保留 prototype.html 作为设计参考，从代码中移除 |
| SSE 事件流 | MCP Server 内部仍需要 | 将 `src/web/sse.rs` 的逻辑移到 MCP transport 层 |

**结论：前端移除无功能影响，只影响演示方式（从 Web UI 改为 AI 对话）。**

---

## 5. 潜在风险与缓解

### 5.1 高风险

| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|----------|
| `rmcp` crate API 不稳定 | 需要频繁重构 | 中 | 先做 POC（Proof of Concept），验证 API 稳定性再全面迁移 |
| MCP Client（Claude Desktop）对 SSE 支持有限 | 监控模式实时推送可能无法实现 | 低 | 降级为轮询 `overview` tool（<1s 延迟可接受） |

### 5.2 中风险

| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|----------|
| stdio transport 的性能瓶颈 | 大量 SSE 事件可能阻塞 | 低 | 异步处理，使用 `tokio::sync::mpsc` 缓冲事件 |
| 会话状态在多个 MCP Client 间共享 | 数据一致性 | 低 | SessionStore 已用 SQLite，天然支持多进程访问 |

### 5.3 低风险

| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|----------|
| 依赖 crate 增加（rmcp） | 二进制体积增大 | 低 | rmcp 是轻量级 crate，影响可忽略 |
| 测试覆盖需要调整 | 现有测试针对 CLI/Web | 中 | 新增 MCP integration tests，保留 CLI 测试 |

---

## 6. 实施步骤（建议）

### Phase 1：MCP Server POC（1-2 天）

1. 创建 `src/mcp_server.rs`，实现最基础的 `scan` tool
2. 验证 `rmcp` crate 的 stdio transport 可用性
3. 在 Claude Desktop 中配置并测试真实调用

### Phase 2：完整 Tools 映射（2-3 天）

1. 实现 6 个 MCP Tools（scan / guard / monitor / overview / timeline / audit）
2. 实现 2 个 MCP Resources（session/:id / audit-chain）
3. 保留 CLI 命令（`supplyguard scan` 等）作为独立入口

### Phase 3：SSE Streaming（1-2 天）

1. 将 `src/web/sse.rs` 的逻辑迁移到 MCP transport
2. 验证监控模式的实时推送
3. 处理 Claude Desktop 的 SSE 支持限制

### Phase 4：测试与文档（1 天）

1. 新增 MCP integration tests
2. 编写 Claude Desktop 配置文档
3. 更新 `PROMPT.md`（如果需要）

### Phase 5：清理（1 天）

1. 移除 `src/web/`（axum + HTML/JS）
2. 移除 `ui/` 目录
3. 更新 `Cargo.toml`（移除 axum / rust-embed 等依赖）

---

## 7. 逻辑链闭合性总结

| 检查项 | 状态 | 说明 |
|--------|------|------|
| 调用链 | ✅ 闭合 | 用户 → Claude → MCP Server → Orchestrator → Agents → 数据层 → 审计链 |
| 数据流 | ✅ 闭合 | 所有输入输出有明确来源和目的地 |
| 状态管理 | ✅ 闭合 | SessionStore + AuditChain 已实现，无孤儿状态 |
| 实时性 | ✅ 闭合 | SSE Streaming 已有实现，可复用 |
| 错误处理 | ✅ 闭合 | 现有 `thiserror` 错误链可复用 |
| 持久化 | ✅ 闭合 | SQLite + HMAC-SHA256 审计链已实现 |
| 配置管理 | ✅ 闭合 | `supplyguard.toml` 已实现 |
| 权限控制 | ⭕ 待验证 | MCP 层是否需要额外的权限控制（如文件系统访问） |

**总体结论：逻辑链已基本闭合，可以开始实施。主要风险是 `rmcp` crate 的稳定性，建议先做 POC 验证。**

---

## 8. 待决策事项

1. **是否保留 CLI 命令？**
   - 建议：保留。MCP Server 和 CLI 共享 Orchestrator，零额外成本。
   - 命令：`supplyguard scan/monitor/guard`（CLI） + `supplyguard mcp`（MCP Server）

2. **是否支持 SSE transport？**
   - 建议：Phase 1 只做 stdio，Phase 3 再添加 SSE。
   - 理由：Claude Desktop 目前只支持 stdio，SSE 是未来扩展。

3. **是否保留 Web UI？**
   - 建议：移除。Claude Desktop 是更好的交互界面。
   - 保留 prototype.html 作为设计参考，但不进入代码库。

4. **MCP Prompts 是否需要？**
   - 建议：Phase 4 再考虑。核心功能不需要 Prompt，Prompt 是锦上添花。

---

## 9. 下一步行动

1. **立即行动**：验证 `rmcp` crate 的可用性（查看 crates.io / GitHub）
2. **本周内**：完成 Phase 1 POC，在 Claude Desktop 中跑通 `scan` tool
3. **下周**：根据 POC 结果决定是否全面迁移

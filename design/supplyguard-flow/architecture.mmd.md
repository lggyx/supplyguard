# SupplyGuard 项目流程与调用链路

> 版本：v1.0（2026-09-02）

---

## 1. 开发工作流（Design → Code → Deploy）

```mermaid
flowchart TD
    Start[项目启动] --> Requirements[需求分析<br/>PROMPT.md + refactor-prompts.md]
    Requirements --> Design[设计阶段<br/>Mermaid 流程图<br/>prototype.html 原型]
    Design --> Decision{决策门<br/>docs/decisions.md}
    Decision -->|通过| Milestone[里程碑规划<br/>S1-S4 分阶段交付]
    Decision -->|修改| Requirements

    Milestone --> Implement[实现阶段<br/>Rust 代码开发]
    Implement --> Test[测试阶段<br/>单元测试 + 集成测试]
    Test --> RuntimeVerify[运行时验证<br/>真实调用 + 浏览器门禁]
    RuntimeVerify --> Commit[GPG 签名提交]
    Commit --> Deploy[部署<br/>单二进制分发]

    Deploy -->|下一个功能| Milestone

    style Decision fill:#ff6b6b
    style RuntimeVerify fill:#ffd93d
    style Commit fill:#6bcf7f
```

---

## 2. SupplyGuard 功能模块依赖图

```mermaid
flowchart TB
    subgraph "CLI 层 (clap)"
        CLI_scan[scan]
        CLI_guard[guard]
        CLI_monitor[monitor]
        CLI_serve[serve]
    end

    subgraph "MCP Server 层 (新增)"
        MCP_Server[MCP Server<br/>rmcp crate]
        MCP_Tools[MCP Tools<br/>scan / guard / monitor<br/>overview / timeline / audit]
        MCP_Resources[MCP Resources<br/>session/:id<br/>audit-chain]
        MCP_Prompts[MCP Prompts<br/>audit-report]
    end

    subgraph "编排层 (LocalOrchestrator)"
        Orchestrator[状态机 + 事件发布]
        SessionStore[会话存储<br/>SQLite]
        AuditChain[审计链<br/>HMAC-SHA256]
    end

    subgraph "Agent 层"
        Sentinel[Sentinel]
        Analyst[Analyst]
        Hallucination[Hallucination Agent]
        CVE[CVE Agent]
        License[License Agent]
        Auditor[Auditor]
        Remediator[Remediator]
    end

    subgraph "技能层 (Skills)"
        SbomBuild[SBOM 构建]
        HallCheck[幻觉包检测]
        CveMatch[CVE 匹配]
        LicenseCheck[许可证检查]
        RiskProfile[风险画像]
    end

    subgraph "MCP 数据层"
        OSV[OSV 本地数据库]
        NPM[npm registry API]
        LicenseDB[SPDX 许可证库]
    end

    CLI_scan --> Orchestrator
    CLI_guard --> Orchestrator
    CLI_monitor --> Orchestrator
    CLI_serve --> MCP_Server

    MCP_Server --> MCP_Tools
    MCP_Server --> MCP_Resources
    MCP_Server --> MCP_Prompts

    MCP_Tools --> Orchestrator
    MCP_Resources --> SessionStore
    MCP_Resources --> AuditChain

    Orchestrator --> Sentinel
    Orchestrator --> Auditor
    Orchestrator --> Remediator
    Orchestrator --> SessionStore
    Orchestrator --> AuditChain

    Sentinel --> SbomBuild
    Analyst --> SbomBuild
    Hallucination --> HallCheck
    CVE --> CveMatch
    License --> LicenseCheck
    Auditor --> RiskProfile

    CveMatch --> OSV
    SbomBuild --> NPM
    LicenseCheck --> LicenseDB
```

---

## 3. MCP 调用链路（完整生命周期）

```mermaid
sequenceDiagram
    participant User as 用户
    participant Claude as Claude Desktop<br/>(MCP Client)
    participant MCP as SupplyGuard<br/>MCP Server
    participant Orchestrator as LocalOrchestrator
    participant Agent as Agent 管道
    participant MCP_Data as MCP 数据层
    participant Audit as 审计链

    User->>Claude: "帮我扫描 ./frontend-app 的依赖"
    Claude->>MCP: 调用 scan tool<br/>{"path": "./frontend-app"}
    MCP->>Orchestrator: 创建会话 (SessionState::Created)
    Orchestrator->>Agent: Sentinel 初始化
    Agent->>MCP_Data: 读取 package-lock.json
    MCP_Data-->>Agent: 返回依赖图
    Agent->>Orchestrator: SBOM 构建完成
    Orchestrator->>MCP: 发布 ScanProgress 事件
    MCP-->>Claude: SSE 流推送进度<br/>"SBOM 构建完成，128 个包"

    Orchestrator->>Agent: 并行启动 Hallucination + CVE + License
    Agent->>MCP_Data: 查询 OSV / npm registry / SPDX
    MCP_Data-->>Agent: 返回风险记录
    Agent->>Orchestrator: 分析完成
    Orchestrator->>MCP: 发布 ScanProgress 事件
    MCP-->>Claude: SSE 流推送<br/>"发现 1 个幻觉包，1 个 CVE"

    Orchestrator->>Agent: Auditor 综合裁决
    Agent->>Orchestrator: 返回裁决结果<br/>(ALLOW / REVIEW / BLOCK)
    Orchestrator->>Audit: 写入审计链
    Audit-->>Orchestrator: 审计哈希 a3f2b8c9...
    Orchestrator->>MCP: 发布 ScanCompleted 事件
    MCP-->>Claude: 返回最终结果<br/>"128 个包：114 ALLOW, 12 REVIEW, 2 BLOCK"

    Claude->>User: 展示结果 + 推理过程
    User->>Claude: "确认 BLOCK 那个幻觉包"
    Claude->>MCP: 调用 overview tool<br/>查询当前状态
    MCP->>Orchestrator: 获取会话列表
    Orchestrator-->>MCP: 返回活跃会话
    MCP-->>Claude: 返回状态 JSON

    Note over Claude,MCP: 监控模式下持续监听
    MCP-->>Claude: SSE 推送变化事件<br/>"检测到 lodash 4.17.20 → 4.17.21"
    Claude->>User: 通知用户有新变化
```

---

## 4. MCP Tools 定义（API 契约）

```mermaid
flowchart LR
    subgraph "MCP Tools"
        scan[scan<br/>输入: path, include_dev<br/>输出: session_id, status]
        guard[guard<br/>输入: diff_path<br/>输出: session_id, verdicts]
        monitor[monitor<br/>输入: path, auto_analyze, notify<br/>输出: session_id, status<br/>实时推送: SSE]
        overview[overview<br/>输入: 无<br/>输出: sessions[], stats]
        timeline[timeline<br/>输入: session_id<br/>输出: events[]]
        audit[audit<br/>输入: session_id?<br/>输出: chain[], verified]
    end

    subgraph "调用场景"
        S1[用户: "扫描 ./my-app"]
        S2[用户: "对 diff 做守门"]
        S3[用户: "监控 ./my-app 目录"]
        S4[用户: "当前状态如何"]
        S5[用户: "查看上次扫描详情"]
        S6[用户: "审计链是否完整"]
    end

    S1 --> scan
    S2 --> guard
    S3 --> monitor
    S4 --> overview
    S5 --> timeline
    S6 --> audit
```

---

## 5. MCP Resources 定义（数据查询）

```mermaid
flowchart TB
    subgraph "MCP Resources"
        R1[session/:id<br/>会话详情<br/>包含: sbom, verdicts, reasoning]
        R2[audit-chain<br/>完整审计链<br/>包含: entries[], hash_verified]
    end

    subgraph "查询方式"
        Q1[MCP Resource Read<br/>session/scan-20260902-1432]
        Q2[MCP Resource Read<br/>audit-chain]
    end

    Q1 --> R1
    Q2 --> R2

    subgraph "返回示例"
        E1[{
  "session_id": "scan-20260902-1432",
  "state": "sealed",
  "packages": 128,
  "verdicts": {
    "allow": 114,
    "review": 12,
    "block": 2
  },
  "reasoning": "...",
  "audit_hash": "a3f2b8c9..."
}]
        E2[{
  "chain_length": 42,
  "entries": [...],
  "verified": true,
  "last_hash": "c9f5d3e1..."
}]
    end

    R1 --> E1
    R2 --> E2
```

---

## 6. 部署架构（MCP Server 模式）

```mermaid
flowchart TB
    subgraph "用户环境"
        Claude[Claude Desktop<br/>MCP Client]
        Cursor[Cursor<br/>MCP Client]
        Windsurf[Windsurf<br/>MCP Client]
    end

    subgraph "本地进程"
        MCP_Server[SupplyGuard MCP Server<br/>单二进制文件<br/>supplyguard mcp]
        subgraph "Server 内部"
            Tools[MCP Tools 层]
            Orchestrator[LocalOrchestrator]
            Agent[Agent 管道]
            Storage[SQLite<br/>审计链 + 会话]
        end
    end

    subgraph "外部数据源"
        OSV[OSV 数据库]
        NPM[npm registry]
        SPDX[SPDX 许可证库]
    end

    Claude -->|stdio / SSE| MCP_Server
    Cursor -->|stdio / SSE| MCP_Server
    Windsurf -->|stdio / SSE| MCP_Server

    MCP_Server --> Tools
    Tools --> Orchestrator
    Orchestrator --> Agent
    Orchestrator --> Storage

    Agent --> OSV
    Agent --> NPM
    Agent --> SPDX
```

---

## 7. 状态查询实时性保证

```mermaid
flowchart LR
    subgraph "查询方式"
        Q1[overview tool<br/>实时查询当前状态]
        Q2[timeline tool<br/>查询会话推理过程]
        Q3[audit tool<br/>查询审计链完整性]
        Q4[session/:id resource<br/>读取会话详情]
    end

    subgraph "数据来源"
        D1[SessionStore<br/>SQLite 内存缓存]
        D2[AuditChain<br/>内存索引]
        D3[Orchestrator<br/>活跃会话状态机]
    end

    Q1 --> D1
    Q1 --> D3
    Q2 --> D1
    Q3 --> D2
    Q4 --> D1

    subgraph "实时性保证"
        T1[< 1ms<br/>内存查询]
        T2[持久化<br/>SQLite WAL 模式]
        T3[事件驱动<br/>状态变更立即可见]
    end

    D1 --> T1
    D2 --> T2
    D3 --> T3
```

---

## 8. 对比：旧架构 vs 新架构

```mermaid
flowchart TB
    subgraph "旧架构（原型）"
        Old_CLI[CLI 命令]
        Old_Web[axum Web 服务器]
        Old_UI[HTML/JS 前端]
        Old_SSE[SSE 事件流]

        Old_CLI --> Old_Web
        Old_Web --> Old_SSE
        Old_Web --> Old_UI
    end

    subgraph "新架构（MCP Server）"
        New_CLI[CLI 命令]
        New_MCP[MCP Server]
        New_Tools[MCP Tools]
        New_Resources[MCP Resources]

        New_CLI --> Orchestrator
        New_MCP --> New_Tools
        New_MCP --> New_Resources
        New_Tools --> Orchestrator
    end

    subgraph "优势"
        A1[一次实现，多端使用]
        A2[AI 原生集成]
        A3[零前端维护]
        A4[标准协议，生态兼容]
        A5[事件驱动，实时推送]
    end

    Old_UI -.->|替换为| Claude_UI[Claude Desktop / Cursor]
    Old_SSE -.->|升级为| MCP_SSE[MCP Streaming]

    Claude_UI --> New_MCP
    MCP_SSE --> New_MCP
```

---

## 9. 实施路线图

```mermaid
flowchart LR
    Phase1[Phase 1<br/>MCP Server 基础<br/>• 添加 rmcp crate<br/>• 实现 6 个 MCP Tools<br/>• 映射现有 CLI 逻辑]
    Phase2[Phase 2<br/>MCP Resources<br/>• session/:id<br/>• audit-chain<br/>• 实时查询接口]
    Phase3[Phase 3<br/>SSE Streaming<br/>• 监控模式实时推送<br/>• 扫描进度推送<br/>• 审计事件推送]
    Phase4[Phase 4<br/>测试 + 文档<br/>• MCP 集成测试<br/>• Claude Desktop 配置<br/>• SKILL.md 编写]

    Phase1 --> Phase2 --> Phase3 --> Phase4

    style Phase1 fill:#6bcf7f
    style Phase2 fill:#ffd93d
    style Phase3 fill:#ffa500
    style Phase4 fill:#4ecdc4
```

---

## 10. 用户使用场景示例

```mermaid
flowchart TD
    U1[用户: "帮我扫描 ./my-app 的依赖安全"] --> Claude1[Claude 调用 scan tool]
    Claude1 --> Result1[Claude 展示 Agent 推理过程<br/>+ 裁决建议]
    Result1 --> User_Decision1[用户确认 BLOCK 幻觉包]
    User_Decision1 --> Audit1[写入审计链]

    U2[用户: "持续监控 ./my-app"] --> Claude2[Claude 调用 monitor tool]
    Claude2 --> Monitor_Start[监控启动]
    Monitor_Start -->|检测到变化| Alert[Claude 推送通知]
    Alert --> User_Review[用户审查推理]
    User_Review --> User_Decision2[用户裁决]
    User_Decision2 --> Audit2[写入审计链]

    U3[用户: "查看审计链是否完整"] --> Claude3[Claude 调用 audit tool]
    Claude3 --> Verify[返回 chain + verified: true]

    U4[用户: "上次扫描的推理过程"] --> Claude4[Claude 调用 timeline tool]
    Claude4 --> Timeline[返回时间线事件]
```

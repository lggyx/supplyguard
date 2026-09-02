# SupplyGuard 业务流程图

> 版本：v1.0（2026-09-02）
> 说明：以下图表覆盖所有核心业务流程，可用 Mermaid 渲染器（如 VS Code Mermaid Preview、GitHub、Mermaid Live Editor）查看。

---

## 1. 产品总览架构

```mermaid
graph TB
    subgraph "入口模式"
        Monitor[MONITOR<br/>持续监控目录]
        Scan[SCAN<br/>单次全量扫描]
        Guard[GUARD<br/>依赖变更守门]
    end

    subgraph "Agent 管道"
        Sentinel[Sentinel<br/>初始化/边界守护]
        Analyst[Analyst<br/>依赖图分析]
        Hallucination[Hallucination Agent<br/>幻觉包检测]
        CVE[CVE Agent<br/>漏洞匹配]
        License[License Agent<br/>许可证检查]
        Auditor[Auditor<br/>综合裁决]
        Remediator[Remediator<br/>修复策略]
    end

    subgraph "输出层"
        UserDecision[用户裁决<br/>ALLOW / REVIEW / BLOCK]
        AuditChain[审计链<br/>不可变哈希链]
        Timeline[时间线<br/>推理过程回放]
        Report[导出报告<br/>JSON / SARIF]
    end

    Monitor --> Sentinel
    Scan --> Sentinel
    Guard --> Sentinel

    Sentinel --> Analyst
    Analyst --> Hallucination
    Analyst --> CVE
    Analyst --> License
    Hallucination --> Auditor
    CVE --> Auditor
    License --> Auditor
    Auditor --> UserDecision
    UserDecision --> AuditChain
    AuditChain --> Timeline
    AuditChain --> Report
    Auditor --> Remediator
```

---

## 2. 监控模式流程（3 步）

```mermaid
flowchart LR
    S1[Step 1/3<br/>输入监控目录<br/>./frontend-app] -->|NEXT| S2[Step 2/3<br/>配置监控参数<br/>• 含 devDependencies<br/>• 自动触发 Agent<br/>• 变化时发送通知]
    S2 -->|START| S3[Step 3/3<br/>监控运行中<br/>监听 package-lock.json]
    S3 -->|检测到变化| Alert{变化类型}
    Alert -->|patch 升级| Patch[ALLOW<br/>低风险自动放行]
    Alert -->|CVE 风险| CVE_Risk[REVIEW<br/>需人工确认]
    Alert -->|幻觉包| Halluc[BLOCK<br/>极高风险拦截]
    Patch -->|写入| Audit1[审计链]
    CVE_Risk -->|用户裁决| Audit1
    Halluc -->|用户裁决| Audit1
    Audit1 --> Complete[完成确认<br/>Session ID + 审计哈希]
    Complete -->|继续监控| S3
    S3 -->|停止| End[■ 已停止]
```

---

## 3. 单次扫描流程（4 步）

```mermaid
flowchart LR
    S1[Step 1/4<br/>输入项目目录<br/>./frontend-app] -->|NEXT| S2[Step 2/4<br/>确认扫描范围<br/>• 含 devDependencies]
    S2 -->|START SCAN| S3[Step 3/4<br/>Agent 分析中<br/>Sentinel → Analyst →<br/>Hallucination → CVE → License → Auditor]
    S3 -->|分析完成| S4[Step 4/4<br/>Agent 推理结果<br/>+ 您的裁决]
    S4 -->|逐条裁决| Decision{用户决策}
    Decision -->|ALLOW| Allow[允许<br/>低风险包]
    Decision -->|REVIEW| Review[待人工确认<br/>CVE / 许可证]
    Decision -->|BLOCK| Block[拦截<br/>幻觉包 / 高风险]
    Allow -->|提交| Audit[写入审计链]
    Review -->|确认后| Audit
    Block -->|确认后| Audit
    Audit --> Complete[完成确认面板<br/>Session ID + 审计哈希]
    Complete -->|查看审计链| AuditView[审计链视图]
    Complete -->|返回总览| Overview[总览仪表]
```

---

## 4. 守门模式流程（4 步）

```mermaid
flowchart LR
    S1[Step 1/4<br/>上传变更 Diff<br/>./diffs/change.diff] -->|PARSE| S2[Step 2/4<br/>变更包识别<br/>从 diff 解析新增/变更/移除]
    S2 -->|ANALYZE| S3[Step 3/4<br/>Agent 分析中<br/>Sentinel → Analyst →<br/>Hallucination → License → Auditor]
    S3 -->|分析完成| S4[Step 4/4<br/>Agent 推理结果<br/>+ 您的最终确认]
    S4 -->|CONFIRM| Audit[写入审计链]
    S4 -->|FORCE BLOCK| ForceBlock[强制拦截所有]
    ForceBlock --> Audit
    Audit --> Complete[完成确认]
```

---

## 5. Agent 管道详解

```mermaid
flowchart LR
    Input[输入<br/>package-lock.json / diff] --> Sentinel

    subgraph "Agent 管道"
        Sentinel[Sentinel<br/>• 初始化会话<br/>• 标记 UNTRUSTED<br/>• 剥离零宽字符]
        Analyst[Analyst<br/>• 解析依赖图<br/>• 提取版本变更<br/>• 构建 SBOM]
        Hallucination[Hallucination Agent<br/>• 词频异常检测<br/>• 注册时间 <7天<br/>• registry 记录缺失<br/>• slopsquatting 识别]
        CVE[CVE Agent<br/>• OSV 本地缓存<br/>• npm registry API<br/>• CVE 匹配]
        License[License Agent<br/>• SPDX 许可证检查<br/>• 商业合规性]
        Auditor[Auditor<br/>• 综合多信号<br/>• 置信度评估<br/>• 生成裁决建议]
        Remediator[Remediator<br/>• 修复策略生成<br/>• 版本推荐<br/>• 替代方案]
    end

    Sentinel --> Analyst
    Analyst --> Hallucination
    Analyst --> CVE
    Analyst --> License
    Hallucination --> Auditor
    CVE --> Auditor
    License --> Auditor
    Auditor -->|Agent 建议| Verdict[裁决输出<br/>ALLOW / REVIEW / BLOCK]
    Verdict -->|用户确认| User[用户决策]
    User -->|提交| AuditChain[审计链<br/>不可变哈希链]
    Auditor -->|需要修复| Remediator
    Remediator --> Report[修复报告]
```

---

## 6. 审计链结构

```mermaid
flowchart LR
    Entry1[审计条目 #1<br/>Session: scan-20260902-1432<br/>Hash: a3f2b8c9d4e5...<br/>Decision: Block<br/>Target: fictional-pkg-xyz@1.0.0] -->|链式哈希| Entry2[审计条目 #2<br/>Session: scan-20260902-1432<br/>Hash: b7e4c1d2f8a9...<br/>Decision: Review<br/>Target: axios@1.6.0]
    Entry2 -->|链式哈希| Entry3[审计条目 #3<br/>Session: scan-20260902-1115<br/>Hash: c9f5d3e1b7a2...<br/>Decision: Allow<br/>Target: ./api-server]
    Entry3 -->|链式哈希| Entry4[审计条目 #4<br/>...]
    Entry1 -->|VERIFIED| Verify1[✓ 哈希验证通过]
    Entry2 -->|VERIFIED| Verify2[✓ 哈希验证通过]
    Entry3 -->|VERIFIED| Verify3[✓ 哈希验证通过]
```

---

## 7. 状态机（Session 生命周期）

```mermaid
stateDiagram-v2
    [*] --> Created: 创建会话
    Created --> Scanning: 开始扫描
    Created --> Monitoring: 开始监控
    Scanning --> Analyzing: SBOM 构建完成
    Analyzing --> AwaitingVerdict: Agent 分析完成
    AwaitingVerdict --> Decided: 用户裁决
    Decided --> Sealed: 写入审计链
    Sealed --> [*]: 会话结束
    Monitoring --> Monitoring: 监听中（等待变化）
    Monitoring --> Analyzing: 检测到依赖变化
    Analyzing --> AwaitingVerdict: Agent 分析完成
    AwaitingVerdict --> Decided: 用户裁决
    Decided --> Monitoring: 继续监控
    Decided --> Sealed: 停止监控
```

---

## 8. 时间线视图（推理过程回放）

```mermaid
flowchart LR
    TL[时间线视图<br/>timeline &lt;id&gt;] --> E1[14:32:01<br/>Sentinel: 初始化<br/>标记 UNTRUSTED]
    E1 --> E2[14:32:02<br/>SBOM 构建<br/>解析 128 个包]
    E2 --> E3[14:32:03<br/>Hallucination Agent<br/>发现虚构包]
    E3 --> E4[14:32:04<br/>CVE Agent<br/>命中 CVE-2023-45857]
    E4 --> E5[14:32:05<br/>License Agent<br/>全部合规]
    E5 --> E6[14:32:06<br/>Auditor: 综合裁决<br/>1 Allow / 1 Review / 1 Block]
    E6 --> E7[14:32:06<br/>Audit Chain<br/>写入审计链]
```

---

## 9. 完整用户旅程

```mermaid
flowchart TD
    Start[用户打开 SupplyGuard] --> Mode{选择模式}
    Mode -->|持续防护| Monitor[MONITOR<br/>指定目录 → 配置 → 监听]
    Mode -->|单次扫描| Scan[SCAN<br/>指定目录 → 扫描范围 → Agent 分析 → 裁决]
    Mode -->|变更守门| Guard[GUARD<br/>上传 Diff → 解析变更 → Agent 分析 → 裁决]

    Monitor -->|检测到变化| AutoAnalysis[Agent 自动分析]
    AutoAnalysis --> UserReview1[用户审查推理]
    Scan --> AgentAnalysis[Agent 管道分析]
    Guard --> AgentAnalysis
    AgentAnalysis --> UserReview2[用户审查推理]

    UserReview1 --> Decision{用户裁决}
    UserReview2 --> Decision

    Decision -->|ALLOW| Allow[允许]
    Decision -->|REVIEW| Review[待人工确认]
    Decision -->|BLOCK| Block[拦截]

    Allow --> Commit[写入审计链]
    Review -->|确认| Commit
    Block -->|确认| Commit

    Commit --> Complete[完成确认<br/>Session ID + 哈希]
    Complete -->|查看审计链| AuditView[审计链视图<br/>哈希链验证]
    Complete -->|查看时间线| TimelineView[时间线视图<br/>推理过程回放]
    Complete -->|继续监控| Monitor
    Complete -->|返回总览| Overview[总览仪表]
```

---

## 10. 技术架构（后端）

```mermaid
flowchart TB
    subgraph "CLI 层"
        CLI[clap 子命令<br/>scan / guard / serve]
    end

    subgraph "Web 层"
        Axum[axum 服务器]
        SSE[SSE 事件流]
        REST[REST API<br/>/api/overview<br/>/api/scans<br/>/api/scans/:id<br/>/api/scans/:id/timeline<br/>/api/audit]
    end

    subgraph "编排层"
        Orchestrator[LocalOrchestrator<br/>状态机 + 事件发布]
    end

    subgraph "Agent 层"
        Sentinel
        Analyst
        Hallucination
        CVE
        License
        Auditor
        Remediator
    end

    subgraph "技能层"
        SbomBuild[SBOM 构建]
        HallCheck[幻觉包检测]
        CveMatch[CVE 匹配]
        LicenseCheck[许可证检查]
        RiskProfile[风险画像]
    end

    subgraph "MCP 层"
        OSV[OSV 本地数据库]
        NPM[npm registry API]
        LicenseDB[SPDX 许可证库]
    end

    subgraph "存储层"
        AuditChain[审计链<br/>HMAC-SHA256]
        SessionStore[会话存储<br/>SQLite]
    end

    CLI --> Orchestrator
    Axum --> REST
    REST --> Orchestrator
    SSE --> Orchestrator
    Orchestrator --> Sentinel
    Orchestrator --> Auditor
    Orchestrator --> Remediator
    Orchestrator --> AuditChain
    Orchestrator --> SessionStore

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

## 使用说明

1. **在线查看**：复制任意 Mermaid 代码块到 [Mermaid Live Editor](https://mermaid.live)
2. **VS Code**：安装 [Mermaid Preview](https://marketplace.visualstudio.com/items?itemName=bierner.markdown-mermaid) 扩展
3. **GitHub**：直接渲染（需文件名以 `.mmd` 或 `.md` 结尾，并启用 Mermaid 支持）

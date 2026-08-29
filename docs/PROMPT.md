# SupplyGuard 项目开发 Prompt

> **用途**：本文件是 SupplyGuard 项目的开发提示词与协作约定。在与 AI 结对开发时，将本文件（或其内容）作为系统提示词 / 上下文提供；对人类贡献者，它同等地定义了本项目的开发规则。
>
> **状态**：v0.1 草案，内容以与项目维护者的后续交流为准，会持续修订。

---

## 1. 项目身份

**SupplyGuard** 是一个面向 AI 编程时代的多 Agent 供应链安全防御系统。它解决两个时刻的问题：

- **守门时刻（proactive）**：PR / 依赖变更引入新依赖时，拦截危险依赖——包括 AI 幻觉包（slopsquatting）、恶意脚本、license 冲突、维护者异常。
- **响应时刻（reactive）**：上游 CVE / 恶意包披露时，自动完成全库影响面评估、批量缓解 PR、处置留痕。

两个时刻共享同一引擎：依赖图与 SBOM、包风险画像、修复策略生成、审计与知识沉淀。

本项目的差异化记忆点：**AI 编程时代的新攻击面**（LLM 幻觉包抢注）+ **从告警到闭环修复的最后一公里**。它不是又一个扫描告警工具，而是能分析、决策、修复、审计的完整闭环。

## 2. 当前状态（务必基于事实开发）

- 可运行骨架：Python 3.10+，`uv` 管理依赖，pytest 测试。
- 已实现的 Skill：`hallucination-check`、`cve-match`、`risk-profile`、`sbom-build`、`license-check`。
- 审计日志：append-only + HMAC 签名哈希链（`src/supplyguard/audit/`）。
- 安全：prompt-injection 检测 + 零宽字符剥离（`src/supplyguard/security/`，洋葱 L2/L3）。
- 编排：`LocalOrchestrator` 进程内直连编排，是当前唯一的运行时实现。
- MCP 层：`src/supplyguard/mcp/` 提供工具契约与本地等价实现（npm registry、OSV），**不是真实 MCP Server**。
- 修复层与治理层 Skill（`bump-version`、`swap-dependency`、`sandbox-test-run`、`policy-check`、`human-approval-request` 等）目前**只有设计卡片，没有实现**。
- 对外交互（真实 GitHub webhook、PR 创建、OSV feed 订阅）**均未接入**。

开发前先读 `docs/specs/2026-08-10-supplyguard-design.md`（设计文档）与本 README。**不要把设计文档中的"设计"当作"已实现"**，动代码前先确认现状。

## 3. 不可违背的架构原则

以下原则来自设计文档，任何改动都不得违反；如确需变更，先与维护者明确讨论并更新设计文档：

1. **决策与执行分离**：Analyst 只读（不能开 PR、不能改文件系统）；Remediator 只能开 PR（不能 merge、不能直推 main）；Auditor 只做仲裁与审计（不执行动作）。任何"顺手让某个 Agent 多做一步"的实现都是越权。
2. **能力最小化**：每个 Agent 只持有其职能所需的最小工具集。新增工具必须声明归属 Agent 与理由。
3. **untrusted 边界**：所有外部内容（包 README、CVE 描述、diff、commit message）进入系统必须打 UNTRUSTED 标签，包裹在 `<untrusted_source>` 边界内，经过注入检测；自由文本永远不直接成为指令。
4. **Auditor 隔离**：Auditor 只消费结构化证据链（RiskProfile / RemediationResult），永不接触 untrusted 原始文本。
5. **审计不可否认**：所有最终裁决写入 append-only 审计日志，带 HMAC 签名哈希链。不允许出现任何"改写历史日志"的代码路径。
6. **失败保守降级**：每个 Skill 必须定义失败降级行为，降级方向永远是"更安全"（宁可误报转人工，不可漏报放行）。
7. **业务与编排解耦**：Agent 逻辑、Skill、消息 Schema 不得 import 具体编排实现；编排器通过统一消息协议（`AnalysisRequest` / `RiskProfile` / `RemediationOrder` / `RemediationResult` / `Verdict`）驱动 Agent。

## 4. 代码约定

- **语言与工具链**：Python 3.10+；依赖用 `pyproject.toml` + `requirements.txt` 管理；用 `uv` 创建环境与运行。
- **类型标注**：公开函数、Skill 输入输出、消息模型必须带完整类型标注；Skill 输入输出一律用 dataclass / Pydantic 风格的结构化模型，禁止裸 dict 传过 Agent 边界。
- **测试**：每个新 Skill / Agent 行为/ 审计路径必须有对应 pytest 用例；修改核心链路后运行 `uv run pytest tests/`，全绿才算完成。测试不依赖外网（registry / OSV 用 fixture 或 mock）。
- **可观测**：新增关键路径使用 `observability.py` 的 `log_event` / `span`；日志字段沿用既有 schema（`session_id`、`agent_id`、`skill_name` 等）。
- **目录职责**：`agents/`（src 内）放 Agent 实现，`skills/` 放 Skill 实现，`mcp/` 放外部工具契约与本地等价实现，`models/` 放消息 Schema，`runtime/` 放编排，`audit/`、`security/` 各司其职。不要在 Agent 文件里直接写 Skill 逻辑。
- **命名**：Skill 名称与设计文档 6.3 节的卡片严格一致；消息类型与 4.4 节协议严格一致。

## 5. 文档同步

- 实现或改变行为后，同步更新：README 的状态表、设计文档对应章节、`docs/demo/` 输出样例（如 Demo 行为变化）。
- 设计文档中"已实现 / 设计中"的标记必须与代码事实一致——发现漂移时，以代码事实为准修正文档。
- 每个新 Skill 落地时，在设计文档 6.3 节补充或核对卡片（输入、输出、调用条件、失败处理、安全边界、复用价值）。

## 6. 安全红线（对本项目自身的要求）

- 本项目的代码也会被别人审计：不引入未审计的网络调用；新增外部请求必须走 `mcp/` 层契约并有失败降级。
- 不在代码中硬编码密钥 / token；配置一律走本地 YAML 或环境变量，并在 `.gitignore` 中挡住真实配置。
- Demo 与测试数据中的恶意样本只使用虚构包名与脱敏内容，不收录真实可用的攻击载荷。

## 7. 优先级排序

当前路线图（按顺序推进，详见设计文档第 9 节）：

1. 补齐剩余 Skill 实现（信号层 → 验证层 → 修复层 → 治理层）
2. 真实外部集成：GitHub webhook / PR 创建、OSV feed 增量订阅
3. 响应模式端到端（零日 CVE 全库影响面评估 + 批量缓解）
4. 数据层迁移 PostgreSQL、OpenTelemetry 接入、容器化执行沙箱（洋葱 L6）
5. 单机自托管分发形态

做任何新工作时，先确认它在路线图上的位置；跳跃式加功能前先与维护者对齐。

## 8. 待定决策（不要擅自拍板）

以下事项维护者尚未最终决定，涉及这些的实现工作先停下来讨论：

- 分布式运行时选型（当前仅 LocalOrchestrator；是否引入成熟多 Agent 框架待定）
- LLM 供应商与调用方式（云端 API / 本地模型；成本、延迟、合规）
- v1 生态扩展顺序（npm 之外何时接入 PyPI / Maven）
- 开源协议（倾向 Apache-2.0，未定）
- 数据库迁移 PostgreSQL 的时间点

## 9. 协作方式

- 改动前先陈述计划（改哪些文件、为什么、如何验证），获得确认后动手。
- 小步提交：一个主题一个提交，提交信息说清"做了什么、为什么"。
- 交付时如实报告：测试结果、未覆盖的部分、与设计文档的偏差。
- 对本 prompt 的修改意见直接改本文件并在提交说明中标注，最终以维护者审阅为准。

# SupplyGuard 开发主 Prompt

> **用途**：本文件是 SupplyGuard 唯一的开发约束文档（边界要求全集）。任何 AI 会话或人类贡献者参与开发前必须完整加载本文件。引导流程使用子 Prompt：`docs/PROMPT_BOOTSTRAP.md`。
>
> **效力**：流程、边界、工作流问题以本文件为准；领域设计问题以 `docs/specs/` 设计文档为准；两者冲突或本文件未覆盖时，停止并向维护者确认，不得自行裁决。修改本文件必须在提交说明中显式标注，且经维护者确认。
>
> **版本**：v2.0（2026-08-29）。相对 v1.0（Python 版）的重大变更见 §2。

---

## 1. 项目身份与使命

**SupplyGuard**：面向 AI 编程时代的多 Agent 供应链安全防御系统。

- **守门时刻（proactive）**：依赖变更进入代码库前，拦截危险依赖——AI 幻觉包（slopsquatting）、恶意脚本、license 冲突、维护者异常。
- **响应时刻（reactive）**：上游 CVE / 恶意包披露后，自动完成影响面评估与批量缓解（v2 范围，见 §6）。
- 两个时刻共享同一引擎：依赖图与 SBOM、包风险画像、修复策略、审计与沉淀。

**差异化记忆点**：AI 编程时代的新攻击面（LLM 幻觉包抢注）+ 从告警到闭环处置的最后一公里。它不是又一个扫描告警工具，而是能分析、裁决、审计的完整闭环。

## 2. 重大变更声明（v2.0）

以下变更是维护者已拍板的方向，执行时不再质疑、不再回头：

| # | 变更 | 旧 | 新 | 理由 |
| --- | --- | --- | --- | --- |
| 1 | 实现语言 | Python 3.10+ / uv | **Rust（cargo 独占）** | 性能、单二进制分发、内存安全契合安全工具定位 |
| 2 | v1 范围 | 双入口并行铺开 | **收敛为守门模式本地闭环**，响应模式整体后移到 v2 | 先把一条链路做穿做实，而不是两条都半成品 |
| 3 | Skill 数量 | 13 个全景清单 | **v1 必做 6 个**，其余进 backlog | 与收敛后的 v1 范围对齐 |
| 4 | LLM 依赖 | 默认参与决策 | **可选组件**：trait 抽象 + 规则引擎为默认实现，v1 可零 LLM 运行 | 可测试、可离线、成本可控 |
| 5 | Agent 形态 | 预留外部多 Agent 框架 | **角色行为 + 自研 LocalOrchestrator**，不引入任何外部多 Agent 框架 | 业务内聚，避免框架锁定 |
| 6 | 配置格式 | YAML | **TOML（`supplyguard.toml`）** | Rust 生态维护状态更好 |

## 3. 技术栈边界

- **工具链**：Rust stable（rustup 管理），edition 2024，MSRV **1.85**。构建、测试、lint、格式化全部通过 cargo，禁止引入任何其他包管理器或构建系统。
- **依赖允许清单**（清单外新增：必须先向维护者说明理由并获批准，批准前不得动工）：

| crate | 用途 | 引入时机 |
| --- | --- | --- |
| `serde` / `serde_json` | 消息模型序列化、JSON 报告 | M0 |
| `thiserror` | 模块错误类型 | M0 |
| `toml` | `supplyguard.toml` 配置解析 | M0 |
| `clap` | CLI（derive 风格） | M0 |
| `hmac` / `sha2` / `hex` | 审计链签名与指纹 | M1 |
| `rusqlite`（bundled feature） | 审计与状态存储（SQLite） | M1 |
| `tracing` / `tracing-subscriber`（json feature） | 结构化日志与 span | M3 |
| `reqwest`（rustls-tls）+ `tokio` | mcp 层 HTTP 客户端 | M4 |
| `tempfile` / `assert_cmd` / `predicates`（dev） | 测试 | 按需 |

- **异步边界**：核心（models / skills / agents / runtime / audit / security）保持同步；异步只允许出现在 M4 的 mcp HTTP 实现及其调用的 runtime 适配处。
- **依赖卫生**：新增依赖前查维护状态与下载量；定期运行 `cargo audit`；`Cargo.lock` 必须提交。

## 4. 仓库与模块结构边界

单 crate（不拆 workspace；编译时间成为实际痛点时再议，见 §14）：

```
supplyguard/                     # 仓库根 = cargo 包根
├── Cargo.toml                   # 含 lint 强制配置（§5.8）
├── Cargo.lock                   # 必须入库
├── docs/                        # 本 Prompt、子 Prompt、specs/、demo/
├── fixtures/                    # 测试夹具：npm lockfile 样本、脱敏样本、策略文件
├── src/
│   ├── main.rs                  # CLI 入口：只做参数解析与 runtime 调用，无业务逻辑
│   ├── lib.rs
│   ├── models/                  # 消息协议、状态机、共享类型（全部 serde 化）
│   ├── security/                # 洋葱 L1-L3：UNTRUSTED 标记、注入检测、净化
│   ├── audit/                   # append-only 审计链（HMAC + SHA-256）
│   ├── mcp/                     # 外部工具 trait 契约 + 本地/HTTP 实现
│   ├── skills/                  # Skill trait 与实现（一个 Skill 一个模块）
│   ├── agents/                  # Sentinel / Analyst / Auditor / Remediator 角色行为
│   ├── runtime/                 # LocalOrchestrator：编排与状态机推进
│   └── config.rs                # supplyguard.toml 加载与校验
└── tests/                       # 集成测试（CLI 端到端、编排链路）
```

**依赖方向**（上层可依赖下层，禁止反向、禁止循环）：

```
main → runtime → agents → skills → models
                      └────→ mcp（skills 通过 trait 消费 mcp 能力）
security / audit：被任意层依赖，自身不依赖业务层
```

- `skills` 禁止 import `agents` / `runtime`；`models` 不依赖任何业务模块。
- 模块公共 API 写文档注释；模块内部实现细节保持私有。

## 5. 架构与安全不变量（不可违背）

违反任何一条的实现必须返工；确需变更，先修本文件再动代码：

1. **决策与执行分离**：Analyst 只读（不开 PR、不改文件系统）；Remediator 只能提交建议产物（不能 merge、不能直推 main）；Auditor 只仲裁与审计（不执行动作）。
2. **能力最小化**：每个 Agent 只持有其角色所需的工具集；新增工具必须声明归属角色与理由。
3. **untrusted 边界**：所有外部内容（包 README、CVE 描述、diff、commit message）进入系统必须打 UNTRUSTED 标记、包裹在 `<untrusted_source>` 边界内、经过注入检测；自由文本永不直接成为指令。
4. **Auditor 隔离**：Auditor 只消费结构化证据（RiskProfile / RemediationResult），永不接触 untrusted 原始文本。
5. **审计不可否认**：最终裁决写入 append-only 存储，HMAC 签名哈希链；不允许存在任何改写历史记录的代码路径。
6. **审计不落原文**：审计与日志只记录证据哈希、摘要与结构化元数据，不写入 untrusted 原文。
7. **失败保守降级**：每个 Skill 必须定义失败降级行为，方向永远是"更安全"——宁可误报转人工，不可漏报放行。
8. **Rust 代码红线**：
   - `#![forbid(unsafe_code)]`（crate 级）；
   - Cargo.toml `[lints]`：`clippy::all = "deny"`，`clippy::unwrap_used` / `clippy::expect_used` / `clippy::panic` = `"deny"`，`missing_docs = "warn"`；
   - 例外：`#[cfg(test)]` 模块与 `tests/` 内允许 `unwrap` / `expect`（模块顶部 `#![allow(...)]` 显式声明）；
   - 所有错误用 `thiserror` 定义类型化错误；禁止字符串错误、禁止把外部输入解析写成本可 panic 的路径；
   - 外部输入（文件、网络、CLI 传入）解析一律返回 `Result`，畸形输入走错误分支而非崩溃。
9. **外部访问收敛**：一切网络请求只允许发生在 `mcp` 层实现内部；其余模块直接发起网络请求即为违规。

## 6. v1 范围边界与非目标

**v1 做（in scope）**：

- 生态：**仅 npm**（`package.json` / `package-lock.json` v1/v2/v3）。
- 交互形态：**本地 CLI**——`supplyguard scan <dir>`（扫描本地项目）与 `supplyguard guard --diff <file>`（对依赖变更做守门裁决），输出结构化报告（JSON + Markdown）。
- Skill（6 个）：`sbom-build`、`hallucination-check`、`cve-match`、`license-check`、`risk-profile`（规则引擎版）、`audit-log-write`。
- Agent：4 角色齐全（Sentinel / Analyst / Auditor / Remediator），但 Remediator 在 v1 只产出建议文本与报告，不产出真实 PR。
- 洋葱层：L1-L3 完整实现（security 模块），L4-L7 以设计与代码结构体现（能力按角色授予、Auditor 隔离、审计链），完整执行沙箱不做。
- 存储：本地 SQLite（rusqlite）+ 文件型报告。

**v1 不做（非目标，出现相关需求一律转入 backlog 并告知维护者）**：

- 响应模式（CVE feed 订阅、影响面批量评估、批量缓解）——v2
- GitHub / GitLab webhook、真实 PR 创建与评论——M4 起按 §14 待定决策执行
- PyPI / Maven 生态
- 完整执行沙箱（洋葱 L6 容器化）
- 多租户、SSO、服务化部署、SDK 化
- 修复层 Skill（`bump-version`、`swap-dependency`、`quarantine-package`、`sandbox-test-run`）
- 信号层剩余 Skill（`maintainer-profile`、`reachability-scan`）与治理层剩余（`policy-check`、`evidence-verify`、`human-approval-request`）

## 7. 里程碑

按序推进，跳跃前必须与维护者对齐。每个里程碑由若干"单元"组成，单元即六步循环（§8）的粒度。

| 里程碑 | 内容 | 关键单元 |
| --- | --- | --- |
| **M0 工作区引导** | Rust 骨架落地 + Python 退役 | ① cargo init + edition/lints 配置 + 一键检查脚本（fmt/clippy/test）；② `models` 消息协议与状态机移植（serde）；③ CLI 骨架（clap，子命令占位）；④ **专门提交删除 Python 实现**（`src/supplyguard/`、`tests/`、`pyproject.toml`、`requirements.txt`、`uv.lock`）；⑤ README 与设计文档同步为 Rust 现实 |
| **M1 安全与审计地基** | 洋葱 L1-L3 + 审计链 | ① security：UNTRUSTED 标记与净化（零宽字符、异常编码）；② security：注入检测（语料驱动）；③ audit：SQLite append-only + HMAC 链 + 篡改检测 |
| **M2 守门本地闭环** | v1 核心价值 | ① fixtures（npm lockfile v1/v2/v3、损坏样本、脱敏恶意样本）；② skills 逐个落地：sbom-build → hallucination-check → cve-match → license-check → risk-profile（规则引擎）；③ agents 四角色行为 + runtime 编排；④ CLI `scan` / `guard` 端到端 |
| **M3 可观测与报告** | 可运维性 | ① tracing JSON 日志 + span 接入全链路；② 守门报告输出（JSON + Markdown） |
| **M4 真实集成** | 对接真实世界 | ① mcp HTTP：npm registry、OSV（trait + mock 测试 + `#[ignore]` 真网测试）；② GitHub 集成（方式待 §14 决策后执行） |
| **M5（v2）响应模式** | 第二入口 | CVE feed 增量消费 → 影响面评估 → 批量处置报告（启动前需维护者重新确认范围） |

## 8. 开发工作流边界：六步循环（强制）

**每个功能单元必须完整走完以下六步，顺序固定，不得合并、不得跳步。** 一个循环 = 一个 git 提交。

| 步 | 名称 | 要求 |
| --- | --- | --- |
| 1 | **编写功能** | 只实现本单元约定内容，不夹带范围外改动；遵守 §4 结构与 §5 红线。动工前先向维护者陈述本单元计划（改哪些文件、边界是什么、如何验证）。 |
| 2 | **编写测试样例** | 覆盖：正常路径、边界条件（空 / 畸形 / 超大输入）、失败与降级路径；外部 IO 一律 fixture / mock（§9）。 |
| 3 | **测试** | `cargo test`、`cargo clippy --all-targets -- -D warnings`、`cargo fmt --check` 全部通过；任一失败回到第 1 步修复，禁止放宽断言或 lint 来"变绿"。 |
| 4 | **逻辑验证** | 对照需求逐条自查并输出结论清单：输入输出是否符合约定；错误分支是否完整；边界条件行为；本单元是否破坏 §5 任何一条不变量。 |
| 5 | **逻辑交叉检验** | 换独立视角复核，至少包含：(a) 从规格独立推导预期输出，与实现实际输出比对；(b) 审查测试断言的是"规格行为"还是"实现细节"；(c) 对抗视角——以攻击者 / 误用者身份构造反例尝试击穿；(d) 与设计文档及相邻模块的契约一致性。发现矛盾即回到第 1 步。 |
| 6 | **git 提交** | Conventional Commits（§10）；提交正文包含：本单元范围、验证与交叉检验结论摘要、遗留问题。 |

**单元粒度**：一个 Skill / 一个模块 / 一个行为切片；单个循环的 diff 以 ≤ ~400 行为宜，超了就先拆分。

**禁止事项**：

- 禁止跨单元批量推进后一次性提交；
- 禁止测试红灯提交（唯一例外：revert 提交）；
- 禁止用"先提交再补测试"的方式工作；
- 提交后发现的缺陷：新开一个循环走完六步，以 `fix` 提交修复，禁止悄悄 amend 已推送历史；
- 每个单元完成即视为其 Definition of Done：六步全过 + 文档同步（§11）。

## 9. 测试边界

- **分层**：纯逻辑用模块内 `#[cfg(test)]`；CLI 与编排链路用 `tests/` 集成测试；外部 HTTP 一律走 trait + mock 实现，真网测试标记 `#[ignore]` 并挂独立 feature。
- **必测清单**（没有对应测试即视为未完成）：
  - 每个 Skill 的正常 / 边界 / 失败降级三条路径；
  - 解析器：npm lockfile v1/v2/v3 fixture、损坏文件、空文件、字段缺失；
  - 审计链：篡改任一字节后校验必须失败；
  - 注入检测：语料表驱动（含零宽字符、指令伪装、编码绕过）；
  - 状态机：非法迁移必须被拒绝；
  - CLI：错误输入的退出码与错误信息。
- **测试环境**：禁止网络访问；禁止依赖本机全局状态；临时目录用 `tempfile`。
- 不追求覆盖率数字指标，但 §9 必测清单是硬边界。

## 10. Git 提交边界

- 格式：`type(scope): summary`，type ∈ feat / fix / test / docs / refactor / chore，scope = 模块名；正文说明"做了什么 / 为什么 / 验证结论"。
- 一个六步循环一个提交；`Cargo.lock` 变更随对应功能提交，不单独漂移。
- 禁止提交：测试红灯、密钥与凭据、真实攻击载荷、（M0 之后）任何 Python / uv 残留。
- 提交信息或正文中出现对本 Prompt / 设计文档的修改必须显式标注。

## 11. 文档同步边界

- **README**：安装（cargo）、运行、项目状态表——M0 起与代码事实保持一致；状态表区分"已实现 / 设计中 / backlog"。
- **设计文档**（`docs/specs/`）：架构级变更（消息协议、模块结构、Skill 行为）落地后同步；"已实现 / 设计中"标记以代码事实为准，发现漂移必须修正。
- **demo 输出**（`docs/demo/`）：行为变化时更新对应样例。
- 文档同步包含在单元的 Definition of Done 内，不允许"代码先行、文档欠账"。

## 12. 安全红线（对本项目自身）

- 密钥与凭据只经环境变量或未入库的本地配置传入；`.gitignore` 必须持续覆盖。
- 恶意样本只用虚构包名与脱敏内容，不收录真实可用攻击载荷。
- 日志与审计不落 untrusted 原文（§5.6）。
- 网络调用只存在于 mcp 层（§5.9）；新依赖过 `cargo audit`。

## 13. 现状与迁移边界（Rust 化起始事实）

- **事实**：仓库当前是 Python 实现（uv 管理，44 个测试通过），作为**行为与设计参考**；Rust 实现尚未开始；README 与设计文档仍描述 Python 现状；`docs/demo/` 输出是有效的行为参考样例。
- **迁移原则**：**不逐行移植**。以本文件 §2/§6 的新设定为准重新实现；Python 代码在 M0 的专门提交中删除（删除前先读取需要参考的行为）；`docs/` 全部保留。
- 删除 Python 后若发现某个行为细节无处可考，以设计文档为准；设计文档也没有的，按 §15 提问。

## 14. 待定决策（禁止擅自拍板）

以下事项维护者尚未决定。涉及它们的实现工作，先给出带权衡的建议、等确认后再动工：

1. **LLM 供应商与启用时机**：v1 默认规则引擎；何时、以何种供应商接入 LLM trait 的真实实现。
2. **GitHub 集成形态**：GitHub App / PAT + API / 仅本地 CLI——影响 M4 的认证与权限设计。
3. **crate 拆分**：单 crate 何时拆 workspace。
4. **存储演进**：SQLite 之后何时、是否迁移 PostgreSQL。
5. **开源协议**（当前倾向 Apache-2.0，未定）。
6. **响应模式（M5）的详细范围**。

## 15. 缺口与冲突处理

- 本 Prompt 与设计文档冲突：流程/边界以本 Prompt 为准，领域设计以设计文档为准；无法归类或实质矛盾的，**停下来问维护者**。
- 本 Prompt 未覆盖的新情况：先提出处理建议，获批后执行，并把结论补进本文件对应章节。
- 任何"看起来需要违反 §5 不变量才能实现"的需求：视为需求本身有问题，停下来讨论，而不是绕过不变量。

## 16. 协作方式

- 计划先行：每个单元动工前陈述计划（§8.1）。
- 诚实交付：每个循环结束时如实报告——改动范围、测试结果、验证与交叉检验结论、遗留问题；不报"大概通过了"。
- 小步推进：一个循环一个提交，拒绝大批量交付。
- 对本文件的任何修改：单独提交、显式标注、等待维护者审阅。

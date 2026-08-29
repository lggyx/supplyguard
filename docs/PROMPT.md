# SupplyGuard 开发主 Prompt

> **用途**：本文件是 SupplyGuard 唯一的开发约束文档（边界要求全集）。任何 AI 会话或人类贡献者参与开发前必须完整加载本文件。引导流程使用子 Prompt：`docs/PROMPT_BOOTSTRAP.md`。
>
> **效力**：流程、边界、工作流问题以本文件为准；领域设计问题以 `docs/specs/` 设计文档为准；两者冲突或本文件未覆盖时，按 §14 的默认值处理并在报告中标注，无法默认的停下来问维护者。修改本文件必须在提交说明中显式标注，且经维护者确认。
>
> **版本**：v2.1（2026-08-29）。v2.1 变更：新增 4 小时冲刺计划（§7）、Web 可视化（§6.1 等）、待定决策默认值（§14）；v2.0 变更（Python → Rust 等）见 §2。

---

## 1. 项目身份与使命

**SupplyGuard**：面向 AI 编程时代的多 Agent 供应链安全防御系统。

- **守门时刻（proactive）**：依赖变更进入代码库前，拦截危险依赖——AI 幻觉包（slopsquatting）、恶意脚本、license 冲突、维护者异常。
- **响应时刻（reactive）**：上游 CVE / 恶意包披露后，自动完成影响面评估与批量缓解（冲刺后路线图，见 §7.3）。
- 两个时刻共享同一引擎：依赖图与 SBOM、包风险画像、修复策略、审计与沉淀。

**差异化记忆点**：AI 编程时代的新攻击面（LLM 幻觉包抢注）+ 从告警到闭环处置的最后一公里。它不是又一个扫描告警工具，而是能分析、裁决、审计的完整闭环。

## 2. 重大变更声明

以下变更是维护者已拍板的方向，执行时不再质疑、不再回头：

| # | 变更 | 旧 | 新 | 理由 |
| --- | --- | --- | --- | --- |
| 1 | 实现语言 | Python 3.10+ / uv | **Rust（cargo 独占）** | 性能、单二进制分发、内存安全契合安全工具定位 |
| 2 | v1 范围 | 双入口并行铺开 | **收敛为守门模式本地闭环**，响应模式后移 | 先把一条链路做穿做实 |
| 3 | Skill 数量 | 13 个全景清单 | **冲刺期必做 6 个**，其余进 backlog | 与收敛后的范围对齐 |
| 4 | LLM 依赖 | 默认参与决策 | **可选组件**：trait 抽象 + 规则引擎为默认实现，可零 LLM 运行 | 可测试、可离线、成本可控 |
| 5 | Agent 形态 | 预留外部多 Agent 框架 | **角色行为 + 自研 LocalOrchestrator**，不引入外部框架 | 业务内聚，避免框架锁定 |
| 6 | 配置格式 | YAML | **TOML（`supplyguard.toml`）** | Rust 生态维护状态更好 |
| 7 | 可视化 | 无 | **内置 Web 控制台**（§6.1，axum + 内嵌零构建前端） | 结果可感知，产品可演示 |
| 8 | 交付节奏 | 无限期演进 | **4 小时冲刺交付可运行版本**（§7），后续迭代另议 | 可运行优先于功能完备 |

## 3. 技术栈边界

- **工具链**：Rust stable（rustup 管理），edition 2024，MSRV **1.85**。构建、测试、lint、格式化全部通过 cargo，禁止引入任何其他包管理器或构建系统。
- **依赖允许清单**（清单外新增：必须先向维护者说明理由并获批准；时间受限的自主执行中改为"采用 §14 默认值并在报告标注"）：

| crate | 用途 | 引入阶段 |
| --- | --- | --- |
| `serde` / `serde_json` | 消息模型序列化、JSON 报告 | S1 |
| `thiserror` | 模块错误类型 | S1 |
| `toml` | `supplyguard.toml` 配置解析 | S1 |
| `clap` | CLI（derive 风格） | S1 |
| `hmac` / `sha2` / `hex` | 审计链签名与指纹 | S2 |
| `rusqlite`（bundled） | 审计与状态存储（SQLite） | S2 |
| `axum` | Web 控制台服务端 | S4 |
| `tokio`（macros + rt-multi-thread） | axum 运行时 | S4 |
| `rust-embed` | 内嵌静态 UI 资源 | S4 |
| `tracing` / `tracing-subscriber`（json） | 结构化日志与 span | S5 |
| `reqwest`（rustls-tls） | mcp 层 HTTP 客户端 | 冲刺后 M4 |
| dev：`tempfile` / `assert_cmd` / `predicates` | 测试 | S1 / S3 |
| dev：`tower`（util）+ `http-body-util` | axum 路由冒烟测试 | S4 |

- **异步边界**：models / skills / agents / runtime / audit / security 保持同步；异步只允许出现在 axum（web）与 mcp HTTP 实现的边界处。
- **前端约束**：**禁止引入 Node / npm / 任何前端构建工具链**。前端为原生 ES Modules + 手写 CSS + vendored 轻量库（见 §6.1）；vendored 第三方文件提交入库并在文件头注明来源与协议。
- **依赖卫生**：新增依赖前查维护状态与下载量；`Cargo.lock` 必须提交；冲刺收尾前运行一次 `cargo audit`。

## 4. 仓库与模块结构边界

单 crate（不拆 workspace；编译时间成为实际痛点时再议，见 §14）：

```
supplyguard/                     # 仓库根 = cargo 包根
├── Cargo.toml                   # 含 lint 强制配置（§5.8）
├── Cargo.lock                   # 必须入库
├── docs/                        # 本 Prompt、子 Prompt、specs/、demo/
├── fixtures/                    # 测试夹具：npm lockfile 样本、脱敏样本、策略文件
├── ui/                          # Web 静态资源（内嵌进二进制）
│   ├── index.html               # 单页仪表盘
│   ├── assets/                  # css / js（原生 ES Modules，手写设计系统）
│   └── vendor/                  # vendored 第三方库（注明来源与协议）
├── src/
│   ├── main.rs                  # CLI 入口：参数解析 + 子命令分发（scan / guard / serve），无业务逻辑
│   ├── lib.rs
│   ├── models/                  # 消息协议、状态机、共享类型（全部 serde 化）
│   ├── security/                # 洋葱 L1-L3：UNTRUSTED 标记、注入检测、净化
│   ├── audit/                   # append-only 审计链（HMAC + SHA-256）
│   ├── mcp/                     # 外部工具 trait 契约 + 本地/HTTP 实现
│   ├── skills/                  # Skill trait 与实现（一个 Skill 一个模块）
│   ├── agents/                  # Sentinel / Analyst / Auditor / Remediator 角色行为
│   ├── runtime/                 # LocalOrchestrator：编排与状态机推进
│   ├── web/                     # axum 路由、SSE、静态资源挂载（只调 runtime，不含业务规则）
│   └── config.rs                # supplyguard.toml 加载与校验
└── tests/                       # 集成测试（CLI 端到端、编排链路、web 冒烟）
```

**依赖方向**（上层可依赖下层，禁止反向、禁止循环）：

```
main → web → runtime → agents → skills → models
                  └────→ mcp（skills 通过 trait 消费 mcp 能力）
security / audit：被任意层依赖，自身不依赖业务层
```

- `skills` 禁止 import `agents` / `runtime` / `web`；`models` 不依赖任何业务模块；`web` 不写业务规则，只做编排结果的展示与触发。
- 模块公共 API 写文档注释；模块内部实现细节保持私有。

## 5. 架构与安全不变量（不可违背）

违反任何一条的实现必须返工；确需变更，先修本文件再动代码：

1. **决策与执行分离**：Analyst 只读（不开 PR、不改文件系统）；Remediator 只能提交建议产物（不能 merge、不能直推 main）；Auditor 只仲裁与审计（不执行动作）。
2. **能力最小化**：每个 Agent 只持有其角色所需的工具集；新增工具必须声明归属角色与理由。
3. **untrusted 边界**：所有外部内容（包 README、CVE 描述、diff、commit message）进入系统必须打 UNTRUSTED 标记、包裹在 `<untrusted_source>` 边界内、经过注入检测；自由文本永不直接成为指令。
4. **Auditor 隔离**：Auditor 只消费结构化证据（RiskProfile / RemediationResult），永不接触 untrusted 原始文本。
5. **审计不可否认**：最终裁决写入 append-only 存储，HMAC 签名哈希链；不允许存在任何改写历史记录的代码路径。
6. **审计不落原文**：审计、日志与 Web 展示只使用证据哈希、摘要与结构化元数据，不出现 untrusted 原文。
7. **失败保守降级**：每个 Skill 必须定义失败降级行为，方向永远是"更安全"——宁可误报转人工，不可漏报放行。
8. **Rust 代码红线**：
   - `#![forbid(unsafe_code)]`（crate 级）；
   - Cargo.toml `[lints]`：`clippy::all = "deny"`，`clippy::unwrap_used` / `clippy::expect_used` / `clippy::panic` = `"deny"`，`missing_docs = "warn"`；
   - 例外：`#[cfg(test)]` 模块与 `tests/` 内允许 `unwrap` / `expect`（模块顶部 `#![allow(...)]` 显式声明）；
   - 所有错误用 `thiserror` 定义类型化错误；禁止字符串错误；外部输入（文件、网络、CLI 传入）解析一律返回 `Result`，畸形输入走错误分支而非崩溃。
9. **外部访问收敛**：一切网络请求只允许发生在 `mcp` 层实现内部与 web 服务端的监听套接字；其余模块直接发起网络请求即为违规。
10. **Web 层边界**：默认只监听 `127.0.0.1:7878`（可经配置/CLI 覆盖，但拒绝 `0.0.0.0` 作为默认值）；API 面最小化——只读查询 + 触发 scan / guard，不提供任何写仓库能力；UI 与 API 不承载密钥；不引入鉴权（本地单用户定位），文档注明"如需远程访问，自行套反代 + 鉴权"。

## 6. v1 范围边界与非目标

**v1 做（in scope）**：

- 生态：**仅 npm**（`package.json` / `package-lock.json` v1/v2/v3）。
- 交互形态：**本地 CLI**——`supplyguard scan <dir>`（扫描本地项目）与 `supplyguard guard --diff <file>`（对依赖变更做守门裁决），输出结构化报告（JSON + Markdown）。
- Skill（6 个）：`sbom-build`、`hallucination-check`、`cve-match`、`license-check`、`risk-profile`（规则引擎版）、`audit-log-write`。
- Agent：4 角色齐全（Sentinel / Analyst / Auditor / Remediator），但 Remediator 在 v1 只产出建议文本与报告，不产出真实 PR。
- 洋葱层：L1-L3 完整实现（security 模块），L4-L7 以代码结构体现（能力按角色授予、Auditor 隔离、审计链），完整执行沙箱不做。
- 存储：本地 SQLite（rusqlite）+ 文件型报告。
- **Web 可视化**：§6.1 的 Web 控制台最小完整版。

### 6.1 Web 可视化要求（硬性规格）

**形态与架构**

- axum 服务端 + `rust-embed` 将 `ui/` 内嵌进单一二进制；`supplyguard serve` 一键启动，默认 `127.0.0.1:7878`。
- 单页仪表盘，四个视图：**总览**（风险计数、最近扫描列表）、**扫描详情**（依赖清单 + 各信号结果）、**裁决时间线**（状态机流转可视化）、**审计链**（哈希链逐条校验状态展示）。
- 实时性：SSE 推送增量更新，**禁止整页刷新轮询**；连接断开有提示与自动重连；请求失败有错误态。

**质感要求（逐条验收，不是口号）**

- 默认**深色主题**；全部视觉参数收敛为 CSS 设计令牌（custom properties：色板 / 圆角 / 阴影 / 间距 / 字号阶梯），禁止散落魔法值。
- 全局过渡动画 150–250ms ease-out；微交互覆盖 hover / active / focus-visible；动画只做 transform / opacity，保证 60fps 丝滑。
- 布局：左侧导航 + 主区卡片式分区；间距节奏统一；系统字体栈（Inter / 系统中文黑体 fallback）。
- **三态齐备**：每个数据视图必须有空态、加载态、错误态的设计，不允许白屏或布局跳动（骨架屏占位）。
- 图表：vendored ECharts，暗色主题，配色取自设计令牌；图表容器尺寸变化平滑过渡。
- 首屏本地渲染即可用（内嵌资源无外链依赖）；交互响应无感知延迟（本地服务，目标 < 50ms）。

**工程与安全**

- 零 Node 工具链：原生 ES Modules + 轻量响应式库（Alpine.js 或 petite-vue，vendored）；vendored 文件头部注明来源与协议（Alpine MIT / ECharts Apache-2.0）；下载不可用时回退为纯手写零依赖实现。
- 遵守 §5.10 Web 层边界。

**v1 不做（非目标，出现相关需求一律转入 backlog 并告知维护者）**：

- 响应模式（CVE feed 订阅、影响面批量评估、批量缓解）
- GitHub / GitLab webhook、真实 PR 创建与评论（冲刺后 M4，方式见 §14）
- PyPI / Maven 生态
- 完整执行沙箱（洋葱 L6 容器化）
- 多租户、SSO、服务化部署、远程访问、Web 鉴权、SDK 化
- 修复层 Skill（`bump-version`、`swap-dependency`、`quarantine-package`、`sandbox-test-run`）
- 信号层剩余 Skill（`maintainer-profile`、`reachability-scan`）与治理层剩余（`policy-check`、`evidence-verify`、`human-approval-request`）
- 纯 Rust 前端框架（Leptos / Dioxus / Yew）、SSR 框架、Node 工具链——见 §14 待定决策

## 7. 4 小时冲刺计划（强制时间盒）

**总预算 240 分钟，高强度连续执行。** 时间盒优先于功能完备：到点收尾，宁可裁剪范围，不可降级质量（§7.2）。

### 7.1 阶段表

| 阶段 | 时间窗 | 内容 | 阶段交付 |
| --- | --- | --- | --- |
| **S1** | 0:00–0:25 | M0 工作区引导：cargo 骨架 + edition/lints + 一键检查脚本；`models` 消息协议与状态机；CLI 骨架（scan/guard/serve 占位）；**专门提交删除 Python 实现**（`src/supplyguard/`、`tests/`、`pyproject.toml`、`requirements.txt`、`uv.lock`）；README 同步为 Rust 现实 | 全绿灯 Rust 骨架 |
| **S2** | 0:25–1:05 | M1 安全与审计：security（UNTRUSTED 标记 + 净化 + 注入检测语料）；audit（SQLite append-only + HMAC 链 + 篡改检测） | 安全与审计地基可用 |
| **S3** | 1:05–2:25 | M2 守门闭环：fixtures（lockfile v1/v2/v3、损坏与脱敏样本）→ skills（sbom-build → hallucination-check → cve-match → license-check → risk-profile）→ agents 四角色 + runtime 编排 → CLI `scan` / `guard` 端到端 | 守门模式本地闭环可运行 |
| **S4** | 2:25–3:20 | W1 Web 可视化：axum + rust-embed + 四视图仪表盘 + SSE（按 §6.1 规格验收） | `serve` 一键起丝滑仪表盘 |
| **S5** | 3:20–3:45 | 收缩版 M3：tracing JSON 日志；端到端演示数据（fixtures 项目样例）；README 快速开始（clone → cargo run 三条命令内跑起来） | 全流程可演示 |
| **S6** | 3:45–4:00 | 收尾：终检全绿（test/clippy/fmt）、`cargo audit`、推送、最终报告（§16） | 干净交付 |

### 7.2 检查点与裁剪阶梯

**检查点**：S1 末（0:25）、S3 末（2:25）、S4 末（3:20）。任一检查点实际进度落后 > 10 分钟，立即按以下阶梯裁剪下一档，并在最终报告标注：

1. S5 收缩：tracing 降为 console 日志；
2. S4 降级：可视化降为**只读报告页**（保留深色主题 + 设计令牌 + 表格与时间线，去 SSE 与图表）；
3. `license-check` 降级为 stub（保守策略：未知 → review，不误放行）；
4. `hallucination-check` 降级为离线相似度（不做 registry 在线查询，保守判定 + 建议人工复核）。

**底线（不得再裁，必须交付）**：`scan` + `sbom-build` + `hallucination-check` + `cve-match` + `guard` CLI 端到端 + 最小 Web 报告页。

**永不裁剪**：六步循环（§8）、§5 全部不变量、测试全绿、**可运行优先原则**——任何时刻仓库必须处于可 build、可 test 状态；功能未完成也不允许破坏绿灯。

### 7.3 冲刺后路线图（本次不执行，仅备忘）

- **M4 真实集成**：mcp HTTP（npm registry、OSV，mock 测试 + `#[ignore]` 真网测试）；GitHub 集成（方式按 §14 决策）。
- **M5 响应模式（v2）**：CVE feed 增量消费 → 影响面评估 → 批量处置报告（启动前需维护者重新确认范围）。

## 8. 开发工作流边界：六步循环（强制）

**每个功能单元必须完整走完以下六步，顺序固定，不得合并、不得跳步。** 一个循环 = 一个 git 提交。

| 步 | 名称 | 要求 |
| --- | --- | --- |
| 1 | **编写功能** | 只实现本单元约定内容，不夹带范围外改动；遵守 §4 结构与 §5 红线。动工前先在回复中完成方案推演：输入输出、边界条件、失败路径、涉及的不变量——推演清楚再写码（高强度思考用在这里，不耗在返工上）。 |
| 2 | **编写测试样例** | 覆盖：正常路径、边界条件（空 / 畸形 / 超大输入）、失败与降级路径；外部 IO 一律 fixture / mock（§9）。 |
| 3 | **测试** | `cargo test`、`cargo clippy --all-targets -- -D warnings`、`cargo fmt --check` 全部通过；任一失败回到第 1 步修复，禁止放宽断言或 lint 来"变绿"。 |
| 4 | **逻辑验证** | 对照需求逐条自查并输出结论清单：输入输出是否符合约定；错误分支是否完整；边界条件行为；本单元是否破坏 §5 任何一条不变量。 |
| 5 | **逻辑交叉检验** | 换独立视角复核，至少包含：(a) 从规格独立推导预期输出，与实现实际输出比对；(b) 审查测试断言的是"规格行为"还是"实现细节"；(c) 对抗视角——以攻击者 / 误用者身份构造反例尝试击穿；(d) 与设计文档及相邻模块的契约一致性。发现矛盾即回到第 1 步。 |
| 6 | **git 提交** | Conventional Commits（§10）；提交正文包含：本单元范围、验证与交叉检验结论摘要、遗留问题。 |

**单元粒度**：一个 Skill / 一个模块 / 一个行为切片；单个循环的 diff 以 ≤ ~400 行为宜。**时间压力下允许把单元切得更小（甚至单函数级），但六步顺序、红灯禁令、不变量检查一项都不许省。**

**禁止事项**：

- 禁止跨单元批量推进后一次性提交；
- 禁止测试红灯提交（唯一例外：revert 提交）；
- 禁止"先提交再补测试"；
- 提交后发现的缺陷：新开一个循环走完六步，以 `fix` 提交修复，禁止悄悄 amend 已推送历史；
- 每个单元完成即 Definition of Done：六步全过 + 文档同步（§11）。

## 9. 测试边界

- **分层**：纯逻辑用模块内 `#[cfg(test)]`；CLI 与编排链路用 `tests/` 集成测试；web 路由用 `tower::ServiceExt::oneshot` 冒烟测试（启动、200、JSON 结构、SSE 端点存在性）；外部 HTTP 一律 trait + mock，真网测试标记 `#[ignore]` 并挂独立 feature。
- **必测清单**（没有对应测试即视为未完成）：
  - 每个 Skill 的正常 / 边界 / 失败降级三条路径；
  - 解析器：npm lockfile v1/v2/v3 fixture、损坏文件、空文件、字段缺失；
  - 审计链：篡改任一字节后校验必须失败；
  - 注入检测：语料表驱动（零宽字符、指令伪装、编码绕过）；
  - 状态机：非法迁移必须被拒绝；
  - CLI：错误输入的退出码与错误信息；
  - Web：四视图 API 的冒烟测试与错误态。
- **测试环境**：禁止网络访问；禁止依赖本机全局状态；临时目录用 `tempfile`。
- 不追求覆盖率数字指标，但本节必测清单是硬边界。

## 10. Git 提交边界

- 格式：`type(scope): summary`，type ∈ feat / fix / test / docs / refactor / chore，scope = 模块名；正文说明"做了什么 / 为什么 / 验证结论"。
- 一个六步循环一个提交；`Cargo.lock` 变更随对应功能提交，不单独漂移。
- **每个阶段（S1–S6）结束推送一次 `main`；冲刺收尾必须推送。** 禁止提交：测试红灯、密钥与凭据、真实攻击载荷、（S1 之后）任何 Python / uv 残留。
- 提交信息或正文中出现对本 Prompt / 设计文档的修改必须显式标注。

## 11. 文档同步边界

- **README**：安装（cargo）、运行、项目状态表——S1 起与代码事实保持一致；状态表区分"已实现 / 设计中 / backlog"；**必须包含"三条命令内跑起来"的快速开始**（clone → 依赖 → `cargo run`）。
- **设计文档**（`docs/specs/`）：架构级变更（消息协议、模块结构、Skill 行为、Web 架构）落地后同步；"已实现 / 设计中"标记以代码事实为准，发现漂移必须修正。
- **demo 输出**（`docs/demo/`）：行为变化时更新对应样例。
- 文档同步包含在单元的 Definition of Done 内；冲刺模式下允许压缩为"行为变更的文档在所属阶段内补齐"。

## 12. 安全红线（对本项目自身）

- 密钥与凭据只经环境变量或未入库的本地配置传入；`.gitignore` 必须持续覆盖。
- 恶意样本只用虚构包名与脱敏内容，不收录真实可用攻击载荷。
- 审计、日志与 Web 展示不落 untrusted 原文（§5.6）。
- 网络调用只存在于 mcp 层与 web 监听（§5.9）；Web 默认仅本地监听（§5.10）；新依赖过 `cargo audit`。

## 13. 现状与迁移边界（Rust 化起始事实）

- **事实**：仓库当前是 Python 实现（uv 管理，44 个测试通过），作为**行为与设计参考**；Rust 实现尚未开始；README 与设计文档仍描述 Python 现状；`docs/demo/` 输出是有效的行为参考样例。
- **迁移原则**：**不逐行移植**。以本文件 §2/§6 的新设定为准重新实现；Python 代码在 S1 的专门提交中删除（删除前先读取需要参考的行为）；`docs/` 全部保留。
- 删除 Python 后若发现某个行为细节无处可考，以设计文档为准；设计文档也没有的，按 §14 默认值处理并标注。

## 14. 待定决策与默认值

以下事项维护者尚未最终决定。**同步协作时**：先给带权衡的建议、等确认再动工；**4 小时冲刺的自主执行中**：直接采用下表默认值推进，并在最终报告"默认值采用清单"中逐条标注。

| # | 决策 | 默认值（冲刺期采用） | 备选 |
| --- | --- | --- | --- |
| 1 | LLM 供应商与启用时机 | v1 纯规则引擎，LLM trait 留接口不接实现 | 云端 API / 本地模型 |
| 2 | GitHub 集成形态 | 不做（M4 前）；届时倾向 PAT + REST 起步 | GitHub App / webhook |
| 3 | 前端技术 | 原生 ES Modules + vendored Alpine.js + ECharts（§6.1） | Leptos / Dioxus 纯 Rust 前端（v2 再议） |
| 4 | crate 拆分 | 单 crate | workspace 多 crate |
| 5 | 存储演进 | SQLite（rusqlite bundled） | PostgreSQL |
| 6 | 开源协议 | README 标注"待定"，不写协议文件 | Apache-2.0 |
| 7 | Web 监听地址默认值 | 127.0.0.1:7878，拒绝 0.0.0.0 默认 | 显式配置才允许改 |

## 15. 缺口与冲突处理

- 本 Prompt 与设计文档冲突：流程/边界以本 Prompt 为准，领域设计以设计文档为准；无法归类或实质矛盾的，按 §14 之外的情况**停下来问维护者**（冲刺期：采用最保守的可行方案并标注）。
- 本 Prompt 未覆盖的新情况：提出处理建议，获批后执行（冲刺期：保守默认 + 标注），并把结论补进本文件对应章节。
- 任何"看起来需要违反 §5 不变量才能实现"的需求：视为需求本身有问题，停下来讨论（冲刺期：裁剪该需求），而不是绕过不变量。

## 16. 协作方式与交付报告

- 计划先行：每个单元动工前完成方案推演（§8.1）。
- 诚实交付：每个循环结束时如实报告——改动范围、测试结果、验证与交叉检验结论、遗留问题；不报"大概通过了"。
- 小步推进：一个循环一个提交；每个阶段结束推送。
- **最终交付报告**（冲刺收尾必出）：各阶段实际耗时 vs 预算；完成 / 裁剪单元清单；测试与 lint 结果；默认值采用清单；运行方式（`scan` / `guard` / `serve` 三条命令）；遗留问题与建议的下一冲刺目标。
- 对本文件的任何修改：单独提交、显式标注、等待维护者审阅。

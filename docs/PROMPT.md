# SupplyGuard 开发主 Prompt

> **用途**：本文件是 SupplyGuard 唯一的开发约束文档（边界要求全集）。任何 AI 会话或人类贡献者参与开发前必须完整加载本文件。引导流程使用子 Prompt：`docs/PROMPT_BOOTSTRAP.md`；执行表现按 `docs/RUBRICS.md` 评估。
>
> **效力**：流程、边界、工作流问题以本文件为准；领域设计问题以 `docs/specs/` 设计文档为准；两者冲突或本文件未覆盖时，按 §14 的默认值处理并在报告中标注，无法默认的停下来问维护者。修改本文件必须在提交说明中显式标注，且经维护者确认。
>
> **版本**：v2.2（2026-08-30）。v2.2：全条款细化（不变量合规做法、Web API 与设计令牌、分阶段单元清单、六步循环模板、迁移映射、反模式清单）。§1–§16 编号自 v2.1 起冻结——RUBRICS.md 与子 Prompt 依赖这些编号引用。

---

## 1. 项目身份与使命

### 1.1 一句话定位

**SupplyGuard**：面向 AI 编程时代的多 Agent 供应链安全防御系统。

### 1.2 问题定义（为什么这个产品必须存在）

企业软件的依赖安全有两个截然不同、但共享底层能力的痛点时刻：

1. **引入时刻（proactive）**：开发者或 AI 助手提交 PR 引入新依赖。这是最经济的拦截点，但传统 SCA 工具（Snyk、Dependabot、npm audit）在这里只做 CVE 匹配：
   - 识别不了 **AI 幻觉包**——LLM 会编造看起来合理的包名（如把 `lodash` 写成 `lodos`），攻击者批量抢注这些名字（slopsquatting），等 AI 代码把恶意包"合理地"引进千万个项目；
   - 识别不了复合信号：维护者突然变更、发布节奏异常、license 污染、install 脚本可疑；
   - 更关键的是**不参与决策**——只弹一个告警就走，剩下的人肉判断和处置没人管。
2. **爆发时刻（reactive）**：xz-utils、event-stream、log4shell 级别的零日披露，团队要在几小时内回答"我有没有中招→影响多大→怎么修→修完对不对"。目前这一整套基本靠人肉救火，且事后无审计痕迹可复盘。

两个时刻的底层能力（依赖图、SBOM、包风险画像、修复策略）高度重叠，工作流却完全不同——**多 Agent 架构在这里是天然解**：一套引擎，两种入口，Agent 承担分析、裁决、处置与审计的完整闭环。

**差异化记忆点**（所有对外叙事、Demo、文档都围绕这两点）：
- AI 编程时代的新攻击面（LLM 幻觉包抢注）——获客记忆点；
- 从告警到闭环处置的最后一公里——产品护城河。

### 1.3 目标用户与场景

- 主用户：中小团队的全栈/安全工程师；自托管、单机可跑、无外部 SaaS 依赖。
- 典型场景：① 本地开发时扫描项目依赖；② CI/代码评审前对依赖变更做守门裁决；③ 安全负责人事后回放审计链。

### 1.4 产品原则（权衡时的裁决依据）

当两条规则冲突、或需要临场判断时，按以下顺序裁决：

1. **可运行优先**：跑得起来的 80% 强过跑不起来的 100%；
2. **保守安全**：任何不确定都倒向"更安全"的一侧（误报可容忍，漏报不可）；
3. **本地优先**：默认不依赖外部服务，联网是增强而非前提；
4. **一切留痕**：凡是影响裁决的动作，必须能在审计链中回放；
5. **简单优先**：能用标准库/单个 crate 解决的，不引入新依赖；能用一层的，不抽象两层。

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

**执行含义**：遇到"原 Python 代码是这么做的，但与新设定冲突"的情况，一律以本表为准；本表没有覆盖的行为差异，按 §13 的迁移原则处理。

## 3. 技术栈边界

### 3.1 工具链

- **Rust stable**（rustup 管理），edition 2024，**MSRV 1.85**。
- 必须可用的组件：`rustc`、`cargo`、`clippy`、`rustfmt`（rustup component）。
- 构建、测试、lint、格式化、运行全部通过 cargo；**禁止引入任何其他包管理器或构建系统**（包括 make/npm/pip/uv 等）。
- 开发机为 Windows + Git Bash：注意脚本换行（shell 脚本用 LF）、路径分隔符（代码内一律用 `std::path::Path` 组合路径，禁止硬编码 `\` 或 `/`）。

### 3.2 依赖允许清单

清单外新增依赖：同步协作时必须先向维护者说明理由并获批准；4 小时自主冲刺中改为"不引入，用现有能力实现，或在报告'默认值采用清单'中标注"。每行含用途与引入阶段，禁止提前引入后面的阶段才需要的依赖：

| crate | 用途 | 引入阶段 | 备注 |
| --- | --- | --- | --- |
| `serde` + `serde_json` | 消息模型序列化、JSON 报告 | S1 | derive 宏 |
| `thiserror` | 模块错误类型 | S1 | 只用于错误定义 |
| `toml` | `supplyguard.toml` 解析 | S1 | |
| `clap` | CLI（derive 风格） | S1 | 子命令：scan / guard / serve |
| `hmac` + `sha2` + `hex` | 审计链签名与指纹 | S2 | 禁止手写密码学 |
| `rusqlite`（bundled feature） | 审计与状态存储（SQLite） | S2 | bundled 免系统依赖 |
| `axum` | Web 控制台服务端 | S4 | 不引入 axum-extra 等，除非必要并说明 |
| `tokio`（macros + rt-multi-thread） | axum 运行时 | S4 | 不要开 full features |
| `rust-embed` | 内嵌 `ui/` 静态资源 | S4 | |
| `tracing` + `tracing-subscriber`（json feature） | 结构化日志与 span | S5 | |
| `reqwest`（rustls-tls） | mcp 层 HTTP 客户端 | 冲刺后 M4 | 冲刺期不引入 |
| dev：`tempfile` / `assert_cmd` / `predicates` | 测试 | S1 / S3 | |
| dev：`tower`（util feature）+ `http-body-util` | axum 路由冒烟测试 | S4 | oneshot 测路由 |

### 3.3 Rust 代码风格与模式（强制约定）

- **错误处理**：每个模块定义自己的 `#[derive(Debug, thiserror::Error)]` 错误枚举；跨模块传播时在边界转换为下层错误（`#[from]`）；`main.rs` / CLI 层才允许把错误渲染为人类可读信息并转退出码。禁止 `anyhow`（不在清单内）、禁止 `Box<dyn Error>` 作为模块公开签名。
- **禁止 panic 路径**：生产代码路径上不允许 `unwrap` / `expect` / `panic!` / `todo!` / `unimplemented!` / 数组越界索引 / `Option::expect`。可能失败的一律 `Result` / 模式匹配。`#[cfg(test)]` 与 `tests/` 内允许（模块顶部 `#![allow(clippy::unwrap_used, clippy::expect_used)]` 显式声明）。
- **类型建模**：状态机用枚举建模（`SessionState`），非法迁移在类型层面不可能或运行时显式拒绝并返回错误；ID 用 newtype（`SessionId(String)`）而非裸 String 散播。
- **文档注释**：每个公开模块、公开类型、公开函数必须有 `///` 文档，含一行用途说明；复杂行为补 `# Errors` 与 `# Panics`（后者应永远写"无"）小节。
- **命名**：类型 PascalCase、函数/变量 snake_case、常量 SCREAMING_SNAKE_CASE；Skill 模块名与设计文档卡片名严格一致（如 `skills/hallucination_check.rs`）。
- **克隆与借用**：正确性优先于借用优化——冲刺期允许合理 `clone()`，不为了消灭 clone 把签名搞复杂；但热路径（审计链计算、大 JSON 序列化）避免无意义深拷贝。
- **lint 配置**（Cargo.toml，S1 就必须配好，不是收尾时补）：

```toml
[lints.rust]
unsafe_code = "forbid"
missing_docs = "warn"

[lints.clippy]
all = "deny"
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
```

### 3.4 异步边界

models / skills / agents / runtime / audit / security **全部同步**。异步只允许出现在：① axum handler 与 SSE（S4 起）；② mcp 层 HTTP 实现内部（冲刺后 M4）。同步业务代码需要被 axum 调用时直接调用（本地操作都是快操作），不得为了"看起来现代"引入 async 传染。

### 3.5 前端约束

**禁止引入 Node / npm / 任何前端构建工具链。** 前端为原生 ES Modules + 手写 CSS + vendored 轻量库（§6.1）；vendored 第三方文件提交入库、文件头注明来源与协议；vendored 下载不可用时回退为纯手写零依赖实现（功能不减，质感要求不减）。

### 3.6 依赖卫生

- 新增依赖前查：维护状态、最近发布时间、下载量、MSRV 兼容；
- `Cargo.lock` 必须提交，变更随对应功能提交，不单独漂移；
- 冲刺收尾前运行一次 `cargo audit`，有告警则在报告中列出。

## 4. 仓库与模块结构边界

### 4.1 目标文件树（S1 结束时应达到的形态）

```
supplyguard/                       # 仓库根 = cargo 包根
├── Cargo.toml                     # 含 §3.3 lint 配置
├── Cargo.lock                     # 入库
├── README.md                      # S1 重写为 Rust 现实，含三命令快速开始
├── docs/                          # PROMPT.md、PROMPT_BOOTSTRAP.md、RUBRICS.md、specs/、demo/
├── scripts/
│   └── check.ps1 / check.sh       # 可选：一键 fmt --check + clippy + test
├── fixtures/                      # 测试夹具（§9.2）
│   ├── lockfiles/                 # package-lock v1/v2/v3、损坏、空、字段缺失样本
│   ├── malicious/                 # 脱敏恶意样本（虚构包名）
│   └── policies/                  # license 策略、注入检测语料
├── ui/
│   ├── index.html                 # 单页仪表盘
│   ├── assets/                    # css/ js/（原生 ES Modules，手写设计系统）
│   └── vendor/                    # vendored 第三方库（文件头注明来源与协议）
├── src/
│   ├── main.rs                    # CLI 入口：clap 解析 + 子命令分发，无业务逻辑
│   ├── lib.rs                     # 模块声明与公开 API 汇总
│   ├── models/
│   │   ├── mod.rs
│   │   ├── messages.rs            # AnalysisRequest / RiskProfile / RemediationOrder / RemediationResult / Verdict
│   │   ├── session.rs             # SessionState 状态机 + 合法迁移表
│   │   └── ids.rs                 # SessionId / SbomId 等 newtype
│   ├── security/
│   │   ├── mod.rs
│   │   ├── sanitize.rs            # 零宽字符剥离、异常编码净化（洋葱 L2）
│   │   └── injection.rs           # 注入检测器（洋葱 L2/L3）
│   ├── audit/
│   │   ├── mod.rs
│   │   └── chain.rs               # append-only 审计链：SQLite 存储 + HMAC 哈希链
│   ├── mcp/
│   │   ├── mod.rs                 # trait 定义：RegistryClient / VulnSource / LicenseDb
│   │   ├── npm_local.rs           # npm registry 本地等价实现（离线回退）
│   │   ├── osv_local.rs           # OSV 本地等价实现（内置脱敏数据集）
│   │   └── license_spdx.rs        # SPDX license 数据（内置子集）
│   ├── skills/
│   │   ├── mod.rs                 # Skill trait：name / run / degradation
│   │   ├── sbom_build.rs
│   │   ├── hallucination_check.rs
│   │   ├── cve_match.rs
│   │   ├── license_check.rs
│   │   └── risk_profile.rs
│   ├── agents/
│   │   ├── mod.rs                 # Agent trait + 角色注册
│   │   ├── sentinel.rs            # 入口路由、UNTRUSTED 标记、状态机推进
│   │   ├── analyst.rs             # 调度 skills、组装 RiskProfile（只读）
│   │   ├── auditor.rs             # 仲裁 Verdict、写审计（不碰 untrusted 原文）
│   │   └── remediator.rs          # 产出建议文本与报告（v1 不开真实 PR）
│   ├── runtime/
│   │   ├── mod.rs
│   │   └── orchestrator.rs        # LocalOrchestrator：run_guard / run_scan 两条链路
│   ├── web/
│   │   ├── mod.rs                 # 路由组装、静态资源挂载
│   │   ├── api.rs                 # REST handlers（§6.1.3）
│   │   └── sse.rs                 # 事件流（§6.1.4）
│   └── config.rs                  # supplyguard.toml 加载、校验、默认值
└── tests/
    ├── cli_scan.rs                # assert_cmd 端到端
    ├── cli_guard.rs
    ├── orchestrator_flow.rs       # 编排链路集成测试
    └── web_smoke.rs               # tower oneshot 路由冒烟
```

### 4.2 模块契约（每个模块的"必须/禁止"）

| 模块 | 必须做 | 禁止做 |
| --- | --- | --- |
| `models` | 全部类型 `serde` 化；状态机迁移表集中定义；newtype ID | 依赖任何业务模块；含业务逻辑 |
| `security` | 纯函数为主；输入输出类型简单（&str → Sanitized）；语料可配置 | 依赖 models 之上的模块；做网络/IO |
| `audit` | 只追加 API（append / verify）；链式哈希：`h_{n} = HMAC(key, h_{n-1} ‖ entry_n)` | 提供任何 update/delete API；明文存 untrusted 原文 |
| `mcp` | 对外只暴露 trait + 实现；实现可失败并返回本模块错误 | 让 skills 直接依赖具体实现（只依赖 trait） |
| `skills` | 实现 Skill trait；输入输出为 models 中的结构化类型；降级路径显式建模 | import agents / runtime / web；直接网络请求（必须走 mcp trait） |
| `agents` | 只做编排协作与角色职责；通过 runtime 注入的工具集工作 | 绕过 runtime 直接互相调用；持有超出角色的工具 |
| `runtime` | 两条公开链路：`run_scan`、`run_guard`；推进状态机；每步发事件（供 web SSE 消费） | 写业务规则；依赖 web |
| `web` | 只调 runtime 公开 API；无状态 handler；JSON 进出 | 写业务规则；直接 import skills / audit 内部；新增监听地址默认值 |
| `main.rs` | 参数解析、配置加载、子命令分发、错误 → 退出码映射 | 业务逻辑 |

### 4.3 依赖方向

```
main → web → runtime → agents → skills → models
                  └────→ mcp（skills 通过 trait 消费 mcp 能力）
security / audit：被任意层依赖，自身不依赖业务层
```

- 禁止反向依赖、禁止循环依赖（`cargo modules` 非必需，靠 code review 与模块契约保证）；
- `skills` 禁止 import `agents` / `runtime` / `web`；
- `models` 不依赖任何业务模块；
- `web` 不写业务规则，只做编排结果的展示与触发。

## 5. 架构与安全不变量（不可违背）

> 违反任何一条的实现必须返工。每条给出：定义 / 合规做法 / 验证方式。这是 RUBRICS D3 的评分依据，也是代码评审的首要检查项。

### 5.1 决策与执行分离

- **定义**：Analyst 只读（不开 PR、不改文件系统、不装包）；Remediator 只产出建议与报告（不能 merge、不能直推 main）；Auditor 只仲裁与审计（不执行任何修复动作）。
- **合规做法**：每个 Agent 的工具集在构造时注入（runtime 持有唯一的工具工厂）；Agent 结构体不持有超出角色的能力句柄。
- **验证方式**：代码抽查 Agent 构造函数；确认 Agent trait 的方法集不包含越权操作。
- **反面案例**：为了让"Demo 更顺"，让 Analyst 顺手改了 lockfile——违规，返工。

### 5.2 能力最小化

- **定义**：每个 Agent 只持有其角色所需的工具集。
- **合规做法**：新增工具时在提交说明写明"归属角色 + 理由"；Agent 间共享的只有 models 中的消息类型。
- **验证方式**：检查各 Agent 的字段与方法集。

### 5.3 untrusted 边界

- **定义**：所有外部内容（包 README、CVE 描述、diff、commit message、registry 响应）进入系统必须：打 UNTRUSTED 标记 → 包裹 `<untrusted_source>` 边界 → 经过注入检测。自由文本永不直接成为指令。
- **合规做法**：Sentinel 在入口统一包标记（返回 `Untrusted<T>` 语义的类型或带标记字段的结构）；下游只能以"证据"身份消费（取哈希、取摘要、结构化字段），不得把原文拼进任何 prompt / 指令构造。
- **验证方式**：grep 检查外部文本的流向；注入检测语料测试通过。
- **反面案例**：把 registry 返回的 README 直接插进 LLM prompt 请求分析——必须先净化 + 标记 + 只传结构化摘要。

### 5.4 Auditor 隔离

- **定义**：Auditor 只消费结构化证据（RiskProfile / RemediationResult），永不接触 untrusted 原始文本。
- **合规做法**：Auditor 的输入类型在编译期就不携带原文（只有摘要、哈希、信号分值）。
- **验证方式**：类型检查——Auditor 相关签名中不存在原始文本参数。

### 5.5 审计不可否认

- **定义**：最终裁决写入 append-only 存储，HMAC 签名哈希链；不存在改写历史的代码路径。
- **合规做法**：审计模块只暴露 `append` 与 `verify`；链式哈希把每条记录与前一条绑定；存储用 SQLite 追加表（无 UPDATE/DELETE 权限的代码路径）。
- **验证方式**：篡改任一字节 → `verify` 必须失败（必测）。

### 5.6 审计不落原文

- **定义**：审计、日志与 Web 展示只使用证据哈希、摘要与结构化元数据，不出现 untrusted 原文。
- **合规做法**：审计条目 schema 中文本字段只有 `summary`（系统生成，非原文）与 `evidence_hash`。
- **验证方式**：抽查审计表内容；对恶意样本跑一遍后确认原文未入库。

### 5.7 失败保守降级

- **定义**：每个 Skill 必须定义失败降级行为，方向永远"更安全"——宁可误报转人工，不可漏报放行。
- **合规做法**：Skill trait 显式包含降级语义（如 `Degraded` 输出状态 + 原因）；降级决策表见设计文档 6.5。
- **验证方式**：每个 Skill 的失败路径测试（§9）。
- **反面案例**：registry 查询失败时默认放行——违规，必须默认"高风险 + 建议人工复核"。

### 5.8 Rust 代码红线

- `#![forbid(unsafe_code)]`（crate 级，lib.rs 顶部）；
- §3.3 的 lint 配置从 S1 起生效；测试模块内 `#![allow(...)]` 显式豁免；
- 所有错误 `thiserror` 类型化；外部输入解析一律 `Result`，畸形输入走错误分支而非崩溃；
- 公开 API 全部有文档注释（missing_docs = warn）。

### 5.9 外部访问收敛

- **定义**：网络请求只允许发生在 mcp 层实现内部与 web 服务端的监听套接字。
- **合规做法**：需要外部数据 → 在 mcp 定义 trait → skills 依赖 trait → 实现负责 IO。
- **验证方式**：grep `reqwest` / `TcpStream` / `UdpSocket` 只出现在 mcp 与 web。

### 5.10 Web 层边界

- 默认只监听 `127.0.0.1:7878`（可经配置/CLI 覆盖，**拒绝 `0.0.0.0` 作为默认值**）；
- API 面最小化：只读查询 + 触发 scan / guard，不提供任何写仓库能力；
- UI 与 API 不承载密钥；不引入鉴权（本地单用户定位），README 注明"如需远程访问，自行套反代 + 鉴权"；
- SSE 只推送状态与摘要事件，不推送 untrusted 原文。

## 6. v1 范围边界与非目标

### 6.0 in scope（每项含验收标准）

| 项 | 内容 | 验收标准 |
| --- | --- | --- |
| 生态 | 仅 npm | 能解析 `package.json` + `package-lock.json` v1/v2/v3；其他 lockfile 明确报"不支持" |
| CLI scan | `supplyguard scan <dir>` | 输出依赖清单 + 每包风险信号 + 汇总 JSON/Markdown 报告；对 fixtures 样例仓库出正确结果 |
| CLI guard | `supplyguard guard --diff <file>` | 对依赖变更 diff 出 Allow / Block / RequireReview 裁决 + 证据链 + 审计落盘 |
| Skill ×6 | 见 §6.0.1 验收表 | 每个 Skill 三路径测试通过 |
| Agent ×4 | Sentinel / Analyst / Auditor / Remediator | 四角色行为在编排链路中各司其职（§4.2 契约） |
| 洋葱 L1-L3 | UNTRUSTED 标记、净化、注入检测 | 注入语料测试全过；零宽字符被剥离 |
| 存储 | SQLite（rusqlite bundled）+ 文件型报告 | 审计链可 verify；报告文件可再读 |
| Web | §6.1 | 四视图可用、三态齐备、SSE 生效、质感达标 |

#### 6.0.1 Skill 验收表

| Skill | 核心行为 | 输入 → 输出 | 降级（失败时） | 关键测试 |
| --- | --- | --- | --- | --- |
| `sbom-build` | 解析 lockfile → 依赖清单 + SBOM 快照 | 项目路径 → `SbomSnapshot`（包名/版本/来源） | 解析告警 → partial + 置信度标记；致命 → 错误上抛 | v1/v2/v3 lockfile、损坏、空文件、字段缺失 |
| `hallucination-check` | 包名是否疑似幻觉/typosquat | 包名 + 上下文 → 疑似判定 + 相似包列表 + 建议替代 | registry 不可达 → 保守判高风险 + 建议人工复核 | 真实流行包、虚构包、编辑距离边界、离线回退 |
| `cve-match` | 包×版本 ↔ 漏洞库匹配 | 包+版本 → 命中列表（severity / fixed） | 库缺失 → "未知风险按最高级处理" | 已知漏洞命中、版本区间边界、无命中 |
| `license-check` | license ↔ 策略冲突检测 | 包 license + 策略 → violations / compatible | 未知 license → "需人工确认"，不自动 block | 允许/禁止列表、未知 license、空策略 |
| `risk-profile` | 多信号融合 → 裁决建议 | 各信号 → risk_level + recommended_action + evidence_chain | 规则不可判 → RequireReview | 信号组合矩阵（高危组合、矛盾信号、空信号） |
| `audit-log-write` | 裁决与证据链落盘 | Verdict + evidence → log_id + hash | 写失败 → 重试 → 上抛且任务不关闭 | 追加、verify 成功、篡改检测、链连续性 |

### 6.1 Web 可视化要求（硬性规格）

#### 6.1.1 形态与架构

- axum 服务端 + `rust-embed` 将 `ui/` 内嵌进单一二进制；`supplyguard serve` 一键启动，默认 `127.0.0.1:7878`；
- 启动即打印访问地址；`Ctrl+C` 优雅退出。

#### 6.1.2 页面与视图（单页应用，四个视图）

| 视图 | 内容 | 数据来源 |
| --- | --- | --- |
| **总览 Overview** | 风险计数卡（critical/high/medium/low）、最近扫描列表、最近裁决摘要 | `GET /api/overview` |
| **扫描详情 Scan Detail** | 依赖清单表（包名/版本/各信号结果/风险分）、包行展开看证据摘要 | `GET /api/scans`、`GET /api/scans/:id` |
| **裁决时间线 Timeline** | 状态机流转（received→analyzing→…→sealed）横向时间线，节点带耗时与裁决 | `GET /api/scans/:id/timeline` |
| **审计链 Audit Chain** | 审计条目列表 + 哈希链逐条校验状态（✓链完整 / ✗自 n 号起断裂） | `GET /api/audit` |

#### 6.1.3 API 面（最小，不多做）

| 方法 | 路径 | 语义 |
| --- | --- | --- |
| GET | `/api/overview` | 汇总统计 |
| GET | `/api/scans` | 扫描列表 |
| GET | `/api/scans/:id` | 扫描详情（含依赖与信号，不含 untrusted 原文） |
| GET | `/api/scans/:id/timeline` | 状态机时间线 |
| GET | `/api/audit` | 审计条目 + 链校验状态 |
| POST | `/api/scan` | 触发一次扫描（body: 项目路径；响应 202 + session_id） |
| POST | `/api/guard` | 触发一次守门裁决（body: diff 文本路径） |
| GET | `/api/events` | SSE 事件流（§6.1.4） |

错误响应统一：`{"error": {"code": "...", "message": "..."}}` + 正确 HTTP 状态码；参数非法 → 400，内部错误 → 500（message 不含内部细节与 untrusted 原文）。

#### 6.1.4 SSE 事件流

- 端点 `GET /api/events`，`text/event-stream`；
- 事件类型（JSON payload）：`scan_started`、`scan_progress`（阶段推进）、`scan_completed`、`guard_verdict`、`audit_appended`、`heartbeat`（≥15s 一次防超时）；
- 断线：前端自动重连（指数退避 ≤ 5s），重连期间 UI 显示"连接断开，重连中"状态条，**不整页刷新**；
- 服务端在 scan/guard 全程发布事件（runtime 发事件 → web 转发），事件只含状态与摘要。

#### 6.1.5 质感要求（逐条验收，不是口号）

- **主题**：默认深色主题；色板/圆角/阴影/间距/字号全部收敛为 CSS 设计令牌（custom properties），禁止散落魔法值。起步令牌集（可微调不可缺位）：

```css
:root {
  --bg-0: #0b0e14;  --bg-1: #11151f;  --bg-2: #171c29;      /* 三层背景 */
  --stroke: #232b3d; --text-1: #e6e9f2; --text-2: #9aa3b8;
  --accent: #4f8cff; --ok: #34d399; --warn: #fbbf24;
  --danger: #f87171; --critical: #f43f5e;
  --radius-s: 6px; --radius-m: 10px; --radius-l: 16px;
  --space-1: 4px; --space-2: 8px; --space-3: 12px; --space-4: 16px; --space-6: 24px; --space-8: 32px;
  --shadow-1: 0 1px 2px rgb(0 0 0 / .4); --shadow-2: 0 8px 24px rgb(0 0 0 / .5);
  --dur-fast: 150ms; --dur-base: 200ms; --dur-slow: 250ms; --ease: cubic-bezier(.2,.7,.3,1);
  --font: Inter, "PingFang SC", "Microsoft YaHei", system-ui, sans-serif;
}
```

- **动效**：全局过渡 `var(--dur-*)` + `var(--ease)`；只动画 `transform` / `opacity`（保 60fps，禁止动画 width/height/top/left）；卡片 hover 轻微上浮 + 阴影加深；数字变化有滚动/淡入；视图切换淡入淡出；
- **布局**：左侧导航（四视图 + 状态指示）+ 主区卡片式分区；间距节奏用 `--space-*`；系统字体栈；
- **三态齐备**：每个数据视图有空态（引导性文案 + 操作按钮）、加载态（骨架屏，禁止白屏）、错误态（可重试按钮 + 错误码）；数据刷新不得引起布局跳动（占位尺寸固定）；
- **图表**：vendored ECharts 暗色主题，配色取自设计令牌；容器尺寸平滑过渡；
- **可访问性**：`focus-visible` 可见焦点环；对比度 ≥ 4.5:1（正文）；键盘可达（Tab 顺序、Enter 触发）；
- **性能**：资源全部内嵌无外链；本地交互响应目标 < 50ms；首屏无需等待网络。

#### 6.1.6 工程与安全

- 零 Node 工具链：原生 ES Modules + 轻量响应式库（Alpine.js 或 petite-vue，vendored）；文件头注明来源与协议（Alpine MIT / ECharts Apache-2.0）；下载不可用 → 纯手写零依赖实现；
- 遵守 §5.10 Web 层边界。

### 6.2 非目标（出现相关需求一律转入 backlog 并告知维护者）

- 响应模式（CVE feed 订阅、影响面批量评估、批量缓解）；
- GitHub / GitLab webhook、真实 PR 创建与评论（冲刺后 M4，方式见 §14）；
- PyPI / Maven 生态；
- 完整执行沙箱（洋葱 L6 容器化）；
- 多租户、SSO、服务化部署、远程访问、Web 鉴权、SDK 化；
- 修复层 Skill（`bump-version`、`swap-dependency`、`quarantine-package`、`sandbox-test-run`）；
- 信号层剩余 Skill（`maintainer-profile`、`reachability-scan`）与治理层剩余（`policy-check`、`evidence-verify`、`human-approval-request`）；
- 纯 Rust 前端框架（Leptos / Dioxus / Yew）、SSR 框架、Node 工具链——见 §14。

## 7. 4 小时冲刺计划（强制时间盒）

**总预算 240 分钟，高强度连续执行。** 时间盒优先于功能完备：到点收尾，宁可裁剪范围，不可降级质量（§7.2）。

### 7.1 阶段表与单元清单

#### S1 工作区引导（0:00–0:25）

| 单元 | 内容 | 验收 |
| --- | --- | --- |
| S1.1 | cargo init、edition 2024、§3.3 lint 配置、`.gitattributes`（`* text=auto eol=lf` 按需）、可选 `scripts/check.*` | `cargo build` 过；故意写 unwrap 被 clippy 拦下 |
| S1.2 | `models`（消息五类型 + 状态机 + newtype ID，serde 化） | 序列化往返测试；非法状态机迁移被拒 |
| S1.3 | CLI 骨架（clap：scan / guard / serve 占位，`--version` 可用） | 三个子命令可执行并打印占位信息 |
| S1.4 | **专门提交删除 Python**（`src/supplyguard/`、`tests/`、`pyproject.toml`、`requirements.txt`、`uv.lock`）；README 重写为 Rust 现实 + 三命令快速开始 | 仓库内 grep 不到 pyproject/uv；README 快速开始与实际一致 |

**S1 出口**：`check 三连`（fmt/clippy/test）全绿；提交并推送。

#### S2 安全与审计地基（0:25–1:05）

| 单元 | 内容 | 验收 |
| --- | --- | --- |
| S2.1 | `security/sanitize`：零宽字符剥离、控制字符、异常编码 | 语料驱动测试（含混合攻击样本） |
| S2.2 | `security/injection`：注入检测器（规则/模式匹配，语料可配置） | 指令伪装、角色扮演诱导、编码绕过语料全过 |
| S2.3 | `audit/chain`：SQLite 追加表 + HMAC 链 + `verify` | 追加→verify 过；篡改任一字节→verify 败；链连续性测试 |

**S2 出口**：全绿；安全地基可被后续链路调用。

#### S3 守门本地闭环（1:05–2:25）

| 单元 | 内容 | 验收 |
| --- | --- | --- |
| S3.1 | `fixtures/`：lockfile v1/v2/v3、损坏/空/缺字段、脱敏恶意样本、license 策略、注入语料入库 | fixtures 可被测试引用 |
| S3.2 | `mcp` trait + 本地实现（npm_local / osv_local / license_spdx 内置数据） | trait 定义清晰；实现可失败 |
| S3.3 | `skills/sbom_build` | §6.0.1 验收 |
| S3.4 | `skills/hallucination_check` | 同上 |
| S3.5 | `skills/cve_match` | 同上 |
| S3.6 | `skills/license_check` | 同上 |
| S3.7 | `skills/risk_profile`（规则引擎融合） | 同上 |
| S3.8 | `agents` ×4 + `runtime` 编排（run_scan / run_guard，发事件） | 编排集成测试：事件顺序、状态机推进、角色边界 |
| S3.9 | CLI `scan` / `guard` 真实现 + 报告输出（JSON + Markdown） | assert_cmd 端到端；fixtures 仓库出正确裁决 |

**S3 出口**：端到端"扫描 → 信号 → 裁决 → 审计"可演示；全绿；推送。

#### S4 Web 可视化（2:25–3:20）

| 单元 | 内容 | 验收 |
| --- | --- | --- |
| S4.1 | axum 骨架 + rust-embed + 路由（§6.1.3）+ web 冒烟测试 | oneshot 测各路由状态码与 JSON 结构 |
| S4.2 | 设计令牌 + 布局骨架 + 四视图导航 | 深色主题生效；令牌存在且被引用 |
| S4.3 | 四视图数据渲染（含三态） | 空/加载/错误三态可触发 |
| S4.4 | SSE 事件流 + 前端接入（自动重连 + 状态条） | scan 触发后 UI 实时推进，无整页刷新 |
| S4.5 | 质感打磨：过渡动效、hover、焦点环、图表（ECharts vendored） | §6.1.5 逐条自查通过 |

**S4 出口**：`serve` 一键起仪表盘；全绿；推送。

#### S5 收缩版 M3：可观测与演示（3:20–3:45）

tracing JSON 日志接入全链路；端到端演示数据（fixtures 项目样例 + 预置审计）；README 快速开始复核（真的 ≤3 条命令跑通）。

#### S6 收尾（3:45–4:00）

终检全绿（test/clippy/fmt）→ `cargo audit` → 推送 → 最终交付报告（§16）。

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

### 8.1 第 1 步：编写功能

- 动工前先在回复中完成**方案推演**（高强度思考用在这里，不耗在返工上）：输入输出是什么、有哪些边界条件、失败路径有哪些、涉及 §5 哪些不变量、打算怎么测；
- 只实现本单元约定内容，不夹带范围外改动（发现了别的 bug → 记入报告，另开循环修复）；
- 遵守 §4 模块契约与 §5 红线。

### 8.2 第 2 步：编写测试样例

- 覆盖三类路径：正常、边界（空/畸形/超大/极端值）、失败降级；
- 外部 IO 一律 fixture / mock（§9）；
- 测试名表达行为（`rejects_tampered_chain_entry`），不表达实现（`test_verify_fn_2`）。

### 8.3 第 3 步：测试

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

全部通过才进第 4 步；任一失败回到第 1 步修复。**禁止放宽断言或 lint 来"变绿"。**

### 8.4 第 4 步：逻辑验证（输出结论清单）

对照需求逐条自查，在回复中输出验证清单（模板）：

```
- 输入/输出符合约定：✓（依据：…）
- 错误分支完整：✓（覆盖了：网络失败/解析失败/空输入/…）
- 边界条件行为：✓（空列表→…；超长输入→…；重复提交→…）
- 不变量核查：§5.1 ✓ / §5.3 ✓ / §5.5 ✓ / …（逐条过）
- 遗留疑问：…（无则写"无"）
```

### 8.5 第 5 步：逻辑交叉检验（换独立视角复核）

至少包含四个视角，逐项给出结论：

1. **规格重推**：不看实现，从规格独立推导预期输出，再与实现实际输出比对——不一致即矛盾；
2. **测试审计**：审查测试断言的是"规格行为"还是"实现细节"（重构实现不换规格时测试应依然成立）；
3. **对抗视角**：以攻击者/误用者身份构造反例尝试击穿（畸形输入、竞态、重复提交、篡改、资源耗尽）；
4. **契约一致性**：与设计文档及相邻模块的接口约定核对（字段名、错误语义、状态迁移）。

发现矛盾 → 回到第 1 步修复，修完重走 2–5 步。

### 8.6 第 6 步：git 提交

Conventional Commits（§10），提交正文包含：本单元范围、验证与交叉检验结论摘要、遗留问题。示例：

```
feat(skills): add hallucination-check with offline fallback

- Detects likely-hallucinated package names via registry lookup +
  edit-distance similarity against popular packages
- Degradation: registry unreachable → conservative high-risk + human review
- Verify: 3-path tests pass (14 cases); cross-check confirmed spec
  behavior asserted, not internals; adversarial pass found no bypass
- Refs: design doc S03; invariants §5.3/§5.7
```

### 8.7 单元粒度与禁止事项

- 一个 Skill / 一个模块 / 一个行为切片；单个循环 diff 以 ≤ ~400 行为宜；**时间压力下允许更小（甚至单函数级），但六步一项不许省**；
- 禁止跨单元批量推进后一次性提交；禁止红灯提交（唯一例外：revert）；禁止"先提交再补测试"；
- 提交后发现的缺陷：新开一个循环走完六步，以 `fix` 提交修复，禁止悄悄 amend 已推送历史；
- Definition of Done：六步全过 + 文档同步（§11）。

## 9. 测试边界

### 9.1 分层

| 层 | 位置 | 工具 | 覆盖 |
| --- | --- | --- | --- |
| 纯逻辑 | 模块内 `#[cfg(test)]` | 标准断言 | 净化、检测、融合规则、哈希计算 |
| Skill | 模块内 + fixtures | table-driven | 三路径（正常/边界/失败） |
| 编排 | `tests/orchestrator_flow.rs` | tokio 不需要，直接 async 块或同步 | 事件顺序、状态机、角色边界 |
| CLI | `tests/cli_*.rs` | `assert_cmd` + `predicates` | 端到端、退出码、错误信息 |
| Web | `tests/web_smoke.rs` | `tower::ServiceExt::oneshot` | 路由状态码、JSON 结构、SSE 端点存在性 |
| 真网（冲刺后） | mcp 实现内 | `#[ignore]` + feature 门控 | registry/OSV 真连 |

### 9.2 fixtures 清单（S3.1 落地）

- `fixtures/lockfiles/`：`v1_basic.json`、`v2_with_dev.json`、`v3_nested.json`、`corrupted.json`、`empty.json`、`missing_fields.json`、`unsupported_format.txt`；
- `fixtures/malicious/`：虚构包 README 含注入指令（零宽字符、`ignore previous instructions`、编码绕过变体）——**全部虚构、脱敏**；
- `fixtures/policies/`：license 允许/禁止策略、注入检测语料（JSON）。

### 9.3 规则

- 测试禁止网络访问；禁止依赖本机全局状态；临时目录用 `tempfile`（Windows 友好）；
- mock 方式：在 mcp 定义 trait，测试内写 mock 实现（手写即可，不引 mockall）；
- 断言规格行为而非实现细节；表驱动优先（`#[test] fn rejects_x() { for case in CASES { ... } }` 或 rstest 式手写）；
- §6.0.1 与 §9.1 的必测清单是硬边界——没有对应测试即视为未完成；
- 不追求覆盖率数字，但关键路径（审计链、注入检测、守门裁决）零测试 = 不合格。

## 10. Git 提交边界

- 格式：`type(scope): summary`；type ∈ feat / fix / test / docs / refactor / chore；scope = 模块名（models / security / audit / mcp / skills / agents / runtime / web / cli / fixtures / docs）；
- 提交正文模板见 §8.6；`Cargo.lock` 变更随对应功能提交；
- **每个阶段（S1–S6）结束推送一次 `main`；冲刺收尾必须推送**；禁止 force-push；
- 禁止提交：测试红灯、密钥与凭据、真实攻击载荷、（S1 之后）任何 Python / uv 残留、构建产物（`target/` 已被 .gitignore 覆盖，确认之）；
- 提交信息或正文中出现对本 Prompt / 设计文档 / RUBRICS 的修改必须显式标注。

## 11. 文档同步边界

- **README** 必含章节：一句话定位；功能列表（对齐 §6.0）；**快速开始（clone → 安装依赖 → 三条命令内跑起 scan / guard / serve，逐条给真实命令与预期输出摘要）**；架构简图（可用 ASCII/mermaid）；项目状态表（已实现 / 设计中 / backlog，与代码事实一致）；配置说明（supplyguard.toml 各项）；安全说明（本地监听、审计链、远程访问提示）；License（按 §14 默认"待定"）。
- **设计文档**（`docs/specs/`）：架构级变更（消息协议、模块结构、Skill 行为、Web 架构）落地后同步；"已实现 / 设计中"标记以代码事实为准，发现漂移必须修正。
- **demo 输出**（`docs/demo/`）：行为变化时更新对应样例（冲刺期允许标注"以 `cargo run` 实际输出为准"）。
- 文档同步包含在单元的 Definition of Done 内；冲刺模式允许压缩为"行为变更的文档在所属阶段内补齐"。

## 12. 安全红线（对本项目自身）

- **密钥**：只经环境变量或未入库的本地配置传入；`.gitignore` 覆盖 `.env`、真实配置；提交前 grep 一遍 diff 确认无凭据；
- **恶意样本**：只用虚构包名与脱敏内容（`evil-example-*` 之类），不收录真实可用攻击载荷；fixtures 中的"恶意 README"只含演示级注入语句；
- **日志与审计**：不落 untrusted 原文（§5.6）；错误信息不泄露内部路径细节给 web 客户端；
- **网络**：调用只存在于 mcp 层与 web 监听（§5.9）；Web 默认仅本地监听（§5.10）；
- **供应链**：新依赖过 §3.6 卫生检查；收尾跑 `cargo audit`。

## 13. 现状与迁移边界（Rust 化起始事实）

### 13.1 迁移起点事实

仓库当前是 Python 实现（uv 管理，44 个测试通过），作为**行为与设计参考**；Rust 实现尚未开始；README 与设计文档仍描述 Python 现状；`docs/demo/` 输出是有效的行为参考样例。

### 13.2 Python 代码清单与迁移映射（读这些，然后按新设定重写，不逐行移植）

| Python 位置 | 现有行为（参考价值） | Rust 去向 | 迁移提示 |
| --- | --- | --- | --- |
| `src/supplyguard/models/messages.py` | 消息五类型 + SessionState 状态机 | `src/models/` | 直接按 schema 重写并 serde 化；状态机迁移表照搬语义 |
| `src/supplyguard/audit/audit_log.py` | append-only + HMAC 哈希链 | `src/audit/chain.rs` | 存储从内存/文件换 SQLite；链算法语义保持 |
| `src/supplyguard/security/injection_detector.py` | 注入检测规则 + 零宽字符剥离 | `src/security/` | 规则可参考；语料抽到 fixtures |
| `src/supplyguard/mcp/npm_registry.py`、`osv.py` | registry/OSV 本地等价实现（离线回退） | `src/mcp/*_local.rs` | 逻辑参考；接口改为 trait |
| `src/supplyguard/skills/*.py` | 5 个已实现 Skill 的判定逻辑（相似度阈值、CVE 匹配语义、license 规则） | `src/skills/` | 阈值与语义照搬，实现重写 |
| `src/supplyguard/runtime/local_orchestrator.py` | 守门链路编排 + 状态机推进 | `src/runtime/orchestrator.rs` | 事件化改造（供 web SSE） |
| `src/supplyguard/agents/*.py` | 四角色行为 | `src/agents/` | 职责边界照 §4.2 重新收口 |
| `src/supplyguard/demo/*.py` | 三个 CLI 演示 | `main.rs` 子命令 | scan/guard 保留语义；cve_response 场景属响应模式（backlog） |
| `tests/*.py` | 44 个用例的意图 | Rust 测试 | 意图保留，形式按 §9 重写 |
| `docs/demo/*.md` | 期望输出样例 | 保留 | 更新为 Rust 实际输出 |

### 13.3 删除程序

Python 代码在 **S1.4 的专门提交**中删除：`src/supplyguard/`、`tests/`、`pyproject.toml`、`requirements.txt`、`uv.lock`。删除前先把需要参考的行为读完（尤其 skill 判定阈值与审计链算法）；`docs/` 全部保留。删除后若发现某行为细节无处可考：以设计文档为准；设计文档也没有的，按 §14 默认值处理并标注。

## 14. 待定决策与默认值

以下事项维护者尚未最终决定。**同步协作时**：先给带权衡的建议、等确认再动工；**4 小时冲刺的自主执行中**：直接采用下表默认值推进，并在最终报告"默认值采用清单"中逐条标注。

| # | 决策 | 默认值（冲刺期采用） | 备选与影响 |
| --- | --- | --- | --- |
| 1 | LLM 供应商与启用时机 | v1 纯规则引擎，LLM trait 留接口不接实现 | 云端 API / 本地模型；接入后影响 risk-profile 与 hallucination-check 精度 |
| 2 | GitHub 集成形态 | 不做（M4 前）；届时倾向 PAT + REST 起步 | GitHub App / webhook；影响认证与权限设计 |
| 3 | 前端技术 | 原生 ES Modules + vendored Alpine.js + ECharts | Leptos / Dioxus 纯 Rust 前端（v2 再议）；影响构建链与体积 |
| 4 | crate 拆分 | 单 crate | workspace 多 crate；编译时间成为痛点时再议 |
| 5 | 存储演进 | SQLite（rusqlite bundled） | PostgreSQL；影响部署复杂度与并发 |
| 6 | 开源协议 | README 标注"待定"，不写协议文件 | Apache-2.0 |
| 7 | Web 监听地址默认值 | `127.0.0.1:7878`，拒绝 `0.0.0.0` 默认 | 显式配置才允许改 |

## 15. 缺口与冲突处理

- **本 Prompt 与设计文档冲突**：流程/边界以本 Prompt 为准，领域设计以设计文档为准；无法归类或实质矛盾的，**停下来问维护者**（冲刺期：采用最保守的可行方案并标注）。
- **本 Prompt 未覆盖的新情况**：提出处理建议，获批后执行（冲刺期：保守默认 + 标注），并把结论补进本文件对应章节。
- **需求要求违反 §5 不变量**：视为需求本身有问题，停下来讨论（冲刺期：裁剪该需求），绝不绕过不变量。
- **示例**：设计文档写了 13 个 Skill 而 §6 只要求 6 个 → 按 §6 执行，其余进 backlog；设计文档的某个降级策略与 §5.7"保守"冲突 → 以 §5.7 为准并修设计文档。

## 16. 协作方式与交付报告

- **计划先行**：每个单元动工前完成方案推演（§8.1）。
- **诚实交付**：每个循环结束时如实报告——改动范围、测试结果、验证与交叉检验结论、遗留问题；不报"大概通过了"。
- **小步推进**：一个循环一个提交；每个阶段结束推送。
- **最终交付报告**（冲刺收尾必出，模板）：

```
# SupplyGuard 冲刺交付报告
## 1. 时间账
| 阶段 | 预算 | 实际 | 偏差原因 |
## 2. 交付清单
已完成单元：…（对应 S 编号）
裁剪项：…（按 §7.2 阶梯第几档，原因）
## 3. 质量证据
cargo test：…通过 / 0 失败；clippy：0 警告；fmt：干净；cargo audit：…
不变量自查：§5.1–§5.10 逐条 ✓/✗ 与依据
## 4. 默认值采用清单（§14）
逐条：决策 # → 采用默认值 → 原因
## 5. 运行方式
scan：…  guard：…  serve：…（真实命令）
## 6. 遗留问题与下一冲刺建议
…
```

- **对本文件的任何修改**：单独提交、显式标注、等待维护者审阅。

## 17. 常见陷阱与反模式（前人踩坑，不要重踩）

1. **重设计冲动**：动工后觉得"架构这里不对"就大规模重构——本文件就是架构裁决，有异议记入报告，不改方向。
2. **先写 Web 后写内核**：没有数据与编排就搭 UI——S4 之前禁止碰 `web/` 与 `ui/`。
3. **过早抽象**：为"将来可能的需求"造插件系统、泛型塔、宏魔法——§1.4 第 5 条，简单优先。
4. **手写密码学**：哈希链用 hmac+sha2 组合，禁止自创"加密"或简化哈希。
5. **async 传染**：把 runtime/skills 改成 async"以备将来"——§3.4 边界，违规返工。
6. **clippy 欠账**：平时忽略警告打算收尾清——deny 配置从 S1 生效，警告即错误，当步解决。
7. **大爆炸集成**：各模块闷头写完最后一天才接线——按 §7.1 单元顺序，每单元都向"可运行"靠拢。
8. **快照式测试**：把大 JSON 输出整体快照当断言——断言关键字段与语义，快照脆且掩盖问题。
9. **Node 蔓延**："前端用个 UI 库方便"→ 需要 npm —— §3.5 红线，vendored 或手写。
10. **隐藏 panic**：`unwrap` 换成 `expect("safe")`、切片越界、整数溢出 unwrap——§5.8 禁的是一切 panic 路径。
11. **untrusted 原文入库/上屏**：为"方便排查"把原始 README 存进审计或展示在 UI——§5.6 红线。
12. **把 Python 习惯带进 Rust**：到处 `String` 传参、`clone` 满天飞不思考、`panic` 当错误处理——正确性优先不等于放弃 Rust 惯用法，§3.3。
13. **fixtures 走捷径**：测试数据硬编码在测试里复制粘贴——集中到 `fixtures/`，一处修改处处生效。
14. **web 绕过分层**：handler 直接查 SQLite 或调 skill——只能调 runtime 公开 API（§4.2）。
15. **时间盒失守**："再给我十分钟就能完美"——到检查点立即裁剪，完美是迭代出来的，不是赶出来的。
16. **红灯过夜**：留一个失败测试明天修——仓库任何时刻可 build 可 test，修不好就裁掉该单元并记录。

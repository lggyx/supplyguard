# SupplyGuard 冲刺执行 Prompt（子 Prompt / 引导文件）

> **你是谁**：SupplyGuard 项目的开发执行 agent。你将独立完成一次从克隆仓库到最终交付的完整开发冲刺，全程无人值守、高强度、时间盒强制。
>
> **文件关系与优先级**：`docs/PROMPT.md` 是**主 Prompt**（边界与约束唯一来源，最高约束力）；本文件是**操作手册**（怎么干、按什么节奏、每步产出什么）；`docs/RUBRICS.md` 是**评分标准**。三者冲突时：主 Prompt > 本文件 > 评分标准措辞。
>
> **总预算与交付**：**4 小时**，交付可 build、可 test、已推送、带最终报告的仓库。本手册每节都为"4 小时内拿到 RUBRICS 优秀档"服务，无装饰性内容。

---

## 1. 任务定义与交付定义

### 1.1 项目背景

**SupplyGuard**：多 Agent 供应链安全防御系统——在依赖进入代码库前（守门模式）拦截危险依赖，尤其是 AI 编程产生的幻觉包（slopsquatting）、已知 CVE、license 冲突；所有裁决走结构化证据链并落进不可篡改的审计日志。仓库已有 Python 实现骨架，维护者已决定**整体迁移到 Rust**并收敛范围：本次冲刺只做**守门模式本地闭环 + Web 可视化**，响应模式、真实 GitHub 集成全部后移。

### 1.2 一句话任务

克隆真实仓库 `https://github.com/lggyx/supplyguard`，按主 Prompt 设定把 Python 骨架重建为 Rust 实现（4 Agent 守门闭环 + 6 Skill + 审计链 + 安全净化 + Web 控制台），4 小时内交付。

### 1.3 交付定义（逐项验收，全部满足才算完成）

| # | 交付项 | 验收方式 |
| --- | --- | --- |
| D-1 | 仓库全绿灯 | `cargo test` 0 失败；`cargo clippy --all-targets -- -D warnings` 0 告警；`cargo fmt --check` 干净 |
| D-2 | 底线功能 | `supplyguard scan <fixtures样例目录>` 输出依赖清单+风险信号；`supplyguard guard --diff <diff文件>` 输出裁决+证据；`sbom-build`、`hallucination-check`、`cve-match` 在链路中真实生效 |
| D-3 | Web 控制台 | `supplyguard serve` 一键启动四视图仪表盘（或裁剪降级后的只读报告页） |
| D-4 | 审计链 | 裁决落盘 SQLite，`verify` 通过；篡改测试证明可检测 |
| D-5 | 文档 | README 与代码事实一致，快速开始 ≤3 条命令可复现 |
| D-6 | Git | 全部提交已推送 `main`；历史呈现单元级六步循环节奏 |
| D-7 | 报告 | 最终交付报告（§9.3 模板）与 git/运行证据交叉一致 |

### 1.4 你将被打分（与 RUBRICS.md 对应）

维度：可运行性与底线 25%、六步循环纪律 15%、不变量 15%、测试质量 15%、时间管理与裁剪 10%、Web 可视化 10%、报告与诚实性 10%；≥90 且无一票否决 = 优秀。**一票否决**（触发任一直接不合格）：伪造测试、红灯提交、审计可改写或 untrusted 原文外泄、提交真实密钥/载荷、引 Node/npm、砍底线、改三份约束文件放水、红灯仓库冒充完成。按本手册执行自然得分，不要表演、不要走捷径。

## 2. 仓库代码元数据（克隆后逐一核对，缺失或对不上即停下来报告）

### 2.1 当前事实

- **语言现状**：Python 3.10+，uv 管理，44 个 pytest 用例通过；**Rust 未初始化**——由你在 S1 迁移，这是任务起点，不是异常。
- **预期最新提交**：`352cd5b`（或其后继，以 `git log` 为准）；远端 `origin = https://github.com/lggyx/supplyguard.git`，分支 `main`。

### 2.2 Python 代码清单（S1.4 删除前必读的参考地图）

| 路径 | 内容 | 价值 |
| --- | --- | --- |
| `src/supplyguard/models/messages.py` | 消息五类型（AnalysisRequest / RiskProfile / RemediationOrder / RemediationResult / Verdict）+ 状态机（received→analyzing→arbitrating→remediating→verifying→sealed） | **必读**：Rust models 的 schema 与状态机语义照搬 |
| `src/supplyguard/audit/audit_log.py` | append-only 审计 + HMAC 哈希链 | **必读**：链式哈希语义照搬，存储换 SQLite |
| `src/supplyguard/security/injection_detector.py` | 注入检测规则 + 零宽字符剥离 | 规则思路参考，语料抽到 fixtures |
| `src/supplyguard/mcp/*.py` | registry / OSV 本地等价实现（离线回退、相似度）、工具契约 | 判定逻辑、回退策略、阈值参考（以代码实际值为准） |
| `src/supplyguard/skills/*.py` | 5 个 Skill：sbom_build / hallucination_check / cve_match / license_check / risk_profile | 阈值与判定语义照搬，结构按 Rust 重写 |
| `src/supplyguard/runtime/local_orchestrator.py` | 守门编排、状态机推进 | 流程参考；Rust 侧需事件化（供 SSE） |
| `src/supplyguard/agents/*.py` | 四角色行为 | 职责按主 Prompt §4.2 契约重新收口 |
| `src/supplyguard/demo/*.py` | slopsquatting_guard / cve_response / scan_repository | scan、guard 的 CLI 语义参考；cve_response 属响应模式，本次不做 |
| `tests/*.py` | 44 用例 | 意图保留，形式按主 Prompt §9 重写 |
| `agents/`（根目录） | 四角色 identity.yaml + pod-template | 边界描述可参考；无运行时依赖，S1.4 可删 |

### 2.3 文档清单（何时读哪份）

| 文件 | 角色 | 何时读 |
| --- | --- | --- |
| `docs/PROMPT.md` | 主 Prompt：§3 代码风格、§4 模块契约、§5 十条不变量、§6 范围与 Web 规格、§7 冲刺计划、§8 六步循环、§9 测试边界、§13 迁移映射、§14 默认值、§17 反模式 | 第 2 步完整精读；各阶段动工前复读对应章节 |
| `docs/PROMPT_BOOTSTRAP.md` | 本文件 | 全程对照 |
| `docs/RUBRICS.md` | 评分标准 | 第 2 步浏览；S6 前对照自查 |
| `docs/specs/2026-08-10-supplyguard-design.md` | 领域设计：Skill 卡片、洋葱七层、降级表 | 写对应模块前精读对应卡片；注意只做 6 个 Skill |
| `docs/demo/*.md` | 演示输出样例 | 校准 scan/guard 输出语义 |
| `README.md` | 仍描述 Python | S1.4 由你重写 |

### 2.4 冲刺目标产物（Rust 侧新建形态与职责）

```
Cargo.toml                # edition 2024 + lint 配置（S1 必配，见 §7 S1.1）
Cargo.lock                # 入库，随功能提交
fixtures/                 # lockfiles/（v1/v2/v3、corrupted、empty、missing_fields、unsupported）
                          # malicious/（虚构注入样本，脱敏）；policies/（license 策略、检测语料）
ui/                       # index.html + assets/（手写设计系统）+ vendor/（Alpine/ECharts，注明协议）
src/
  main.rs                 # clap 子命令 scan/guard/serve + 错误→退出码，无业务逻辑
  lib.rs                  # 模块声明 + #![forbid(unsafe_code)]
  models/                 # messages.rs（五类型）+ session.rs（状态机+迁移表）+ ids.rs（newtype）
  security/               # sanitize.rs（净化）+ injection.rs（注入检测）
  audit/                  # chain.rs（SQLite 追加表 + HMAC 链 + verify）
  mcp/                    # trait（RegistryClient/VulnSource/LicenseDb）+ 三个本地实现
  skills/                 # Skill trait + 5 个 Skill 实现
  agents/                 # sentinel / analyst / auditor / remediator
  runtime/                # orchestrator.rs：run_scan / run_guard + 事件发布
  web/                    # mod.rs + api.rs + sse.rs；只调 runtime 公开 API
  config.rs               # supplyguard.toml 加载/校验/默认值
tests/                    # cli_scan / cli_guard / orchestrator_flow / web_smoke
```

## 3. 环境部署细则（第 1 步）

### 3.1 获取代码

```bash
git clone https://github.com/lggyx/supplyguard.git
cd supplyguard
git log --oneline -3      # 核对 §2.1；git status 必须干净
```

### 3.2 Rust 工具链

```bash
rustc --version           # 需 ≥ 1.85（主 Prompt MSRV）
rustup component list --installed   # 必须含 clippy、rustfmt；缺则 add
```

无 rustup 先按 https://rustup.rs 装 stable（Windows 用 rustup-init.exe），装后重开 shell。

### 3.3 网络与代理

维护者经本地代理（`127.0.0.1:7897`）访问 GitHub，**代理间歇性握手失败**（`schannel: failed to receive handshake`）。对策：clone/push 失败**重试 2–3 次（间隔 15s）**；仍失败则提交留在本地、报告等待。**禁止**换镜像、改 git 配置、force-push。

### 3.4 Git 身份

`git config user.name && git config user.email` 为空则向维护者询问，不要编造。

### 3.5 环境验证

Python 侧（立刻）：`uv run pytest tests/ -q` → 预期 `44 passed`。Rust 侧（S1.1 后）：`cargo build` / `cargo test` 通过；故意在临时分支写一个 `unwrap()` 验证 clippy 真的拦（验后撤销）。

### 3.6 Windows 补充

- **MSVC Build Tools**：rusqlite bundled 等 C 依赖构建需要；报 `link.exe not found` 即缺此件，先装再继续；
- **换行符**：S1.1 加 `.gitattributes`（`* text=auto eol=lf`）；CRLF 干扰 fmt 时 `git add --renormalize .`，不许关 fmt；
- **路径**：代码内 `std::path::Path::join` 组合，禁硬编码分隔符；临时路径用 tempfile；
- **Defender** 拖慢首次构建属正常，不为提速关安全软件。

## 4. 主 Prompt 加载协议（第 2 步）

### 4.1 阅读顺序与时间盒（合计 ≤ 15 分钟）

| 序 | 材料 | 时间 | 提取重点 |
| --- | --- | --- | --- |
| 1 | `docs/PROMPT.md` 完整精读 | ≤10 min | §3.3 代码红线；§4.2 模块"必须/禁止"表；§5 十条不变量（背下）；§7 阶段表+底线+裁剪阶梯；§8 六步循环与提交模板；§14 默认值；§17 反模式 |
| 2 | `README.md` | ≤2 min | 核对现状与 §2 元数据一致 |
| 3 | `docs/specs/` 目录级浏览 | ≤3 min | 定位 Skill 卡片、降级表、消息协议；写模块前再精读 |

### 4.2 冲突与默认值协议

流程/边界 → 主 Prompt；领域细节 → 设计文档；冲突或未覆盖 → 按 §14 默认值处理并在报告标注；可能违反 §5 不变量 → 停下问维护者，问之前先把仓库整理到绿灯。

默认值速查：LLM=规则引擎留 trait；GitHub=不做；前端=原生 ES Modules + vendored Alpine + ECharts；crate=单 crate；存储=SQLite（rusqlite bundled）；License=待定；Web 监听=默认 `127.0.0.1:7878`、拒 `0.0.0.0` 默认。

### 4.3 约束文件保护

禁改 `docs/PROMPT.md`、`PROMPT_BOOTSTRAP.md`、`RUBRICS.md`（一票否决 V7）；规则异议写进报告。

## 5. 冲刺执行总纲（第 3 步）

### 5.1 阶段表（细节以主 Prompt §7.1 为准）

| 阶段 | 时间窗 | 核心目标 | 出口标准 |
| --- | --- | --- | --- |
| S1 工作区引导 | 0:00–0:25 | Rust 骨架 + lint + models + CLI 占位 + **删 Python** + README 重写 | 三连全绿；无 Python 残留；推送 |
| S2 安全与审计 | 0:25–1:05 | sanitize + injection + audit 哈希链 | 三套件各含语料/篡改测试且通过 |
| S3 守门闭环 | 1:05–2:25 | fixtures → mcp → 5 Skill → 4 Agent + runtime → CLI | scan/guard 对 fixtures 出正确裁决；推送 |
| S4 Web 可视化 | 2:25–3:20 | axum + 内嵌 UI + 四视图 + SSE + 质感 | serve 一键起；§6.1 逐条自查 |
| S5 观测演示 | 3:20–3:45 | tracing JSON 日志 + 演示数据 + README 复核 | 三命令实跑复现 |
| S6 收尾 | 3:45–4:00 | 终检 + cargo audit + 推送 + 报告 | 干净交付 |

### 5.2 检查点纪律

0:25 / 2:25 / 3:20 对表，**落后 >10 分钟按主 Prompt §7.2 裁剪阶梯降档**，顺序固定：S5 收缩 → Web 降只读报告页 → license-check stub → hallucination 离线化。底线与永不裁剪项（六步循环、§5 不变量、全绿、可运行优先）不可触碰。裁剪是决策不是失败，报告如实写第几档。

### 5.3 可运行优先

任何时刻 `cargo build` 必须成功；开工前是绿的，做完还是绿的；做坏先修或回退该单元，红灯不过夜。

## 6. 六步循环操作细则（每单元一次循环一个提交，主 Prompt §8 为准）

单元 = 一个 Skill / 一个模块 / 一个行为切片（diff ≤ ~400 行，时间紧可更小，六步一项不省）。

| 步 | 操作 | 产出 |
| --- | --- | --- |
| 1 编写功能 | 先推演（输入输出/边界/失败路径/涉及不变量/怎么测）再动手；只做本单元 | 代码 + 推演记录 |
| 2 编写测试 | 三路径：正常/边界/失败降级；外部 IO 走 fixture 或 trait mock；测试名表达行为 | 测试代码 |
| 3 测试 | `cargo test` + `clippy --all-targets -- -D warnings` + `fmt --check` 全绿；败则回步 1，禁放宽断言/lint | 绿灯输出 |
| 4 逻辑验证 | 清单：输入输出✓、错误分支✓、边界✓、§5 逐条✓ | 验证清单 |
| 5 交叉检验 | 四视角：规格重推 / 测试审计（断言规格非实现）/ 对抗反例 / 契约一致性；矛盾回步 1 | 检验结论 |
| 6 git 提交 | `type(scope): summary` + 正文（范围/验证/遗留），对照主 Prompt §8.6 | 一个提交 |

### 6.1 完整示范（`license_check` 迷你 walkthrough）

推演：输入=包 license 数组+策略；输出=`violations + compatible + policy_version`；边界=空列表、未知 license、策略缺失；降级=未知 license → "需人工确认"不自动 block（§5.7）。测试（表驱动）：`allows_permitted` / `flags_denied` / `unknown_requires_review` / `empty_yields_compatible` / `missing_policy_defaults_strict`。交叉检验发现：`GPL-3.0` vs `gpl-3.0` 应规范化而非视为未知——补规范化与用例；对抗例：空字符串 license → 走未知路径 ✓。提交：`feat(skills): add license-check with conservative unknown handling`。照此粒度执行每个单元。

## 7. 分阶段单元执行卡片

### S1（0:00–0:25）——骨架即规则

1. **S1.1** `cargo init` → edition 2024 → lint 配置 → `.gitignore` 补 `target/` → 可选 `scripts/check.*`。验收：故意写 unwrap 被 clippy 拦下。

```toml
# Cargo.toml —— S1.1 必配，缺一条验收不过
[lints.rust]
unsafe_code = "forbid"
missing_docs = "warn"
[lints.clippy]
all = "deny"
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
```

2. **S1.2** `models`：五消息类型 + 状态机（合法迁移表，非法迁移返回 `StateTransitionError`）+ newtype ID；serde 化；序列化往返与非法迁移测试。
3. **S1.3** CLI 占位：clap derive，`scan`/`guard`/`serve` + `--version`，退出码 0。
4. **S1.4** **专门提交删 Python**（`src/supplyguard/`、`tests/`、`pyproject.toml`、`requirements.txt`、`uv.lock`；根目录 `agents/` 可删）；删前读完 §2.2 两个必读文件。提交注明 "remove Python implementation (superseded by Rust rewrite)"。
5. **S1.5** README 重写：定位、功能列表、三命令快速开始、架构简图、状态表（诚实区分）、License"待定"。

### S2（0:25–1:05）——安全地基

1. **S2.1** `sanitize`：零宽字符（U+200B–200D、U+FEFF）、控制字符、异常编码；纯函数；语料进 fixtures。
2. **S2.2** `injection`：规则/模式匹配（指令伪装、角色扮演诱导、编码绕过）；语料表驱动；输出结构化（命中规则、置信度）。
3. **S2.3** `audit`：SQLite 追加表（rusqlite bundled；建表无 UPDATE/DELETE 路径）+ HMAC-SHA256 链 + `verify`。核心测试：追加→verify 过；**篡改任一字节→verify 败且指出断裂位置**。

```rust
// audit/chain.rs 核心语义（示意）：每条记录与前一条哈希绑定
fn chain_hash(key: &[u8], prev: &Hash, entry: &AuditEntry) -> Result<Hash, AuditError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)?;   // 返回 Result，不 panic
    mac.update(prev.as_bytes());
    mac.update(&entry.encoded());
    Ok(Hash::new(mac.finalize().into_bytes()))
}
// append()：仅追加；verify()：重算全链逐条比对
```

```rust
// untrusted 边界（示意，S2.1/S2.2 与守门入口共用此形状）：
let tagged = Untrusted::new(raw_text)?;   // 入口打标
let clean  = sanitize(tagged.as_str())?;  // 剥离零宽/控制字符
let hits   = injection::scan(&clean)?;    // 注入检测
// 下游只消费 clean 的哈希/摘要/结构化字段，原文到此为止
```

### S3（1:05–2:25）——主战场，顺序不可换（每单元一次六步循环）

1. **S3.1** fixtures 全套（§2.4 清单）——没有夹具，后面测试都是空中楼阁；
2. **S3.2** mcp trait + 三个本地实现（npm_local / osv_local / license_spdx 内置数据；离线可用；可失败并返回本模块错误）；
3. **S3.3–S3.7** Skill 依序：sbom_build → hallucination_check → cve_match → license_check → risk_profile（每 Skill：读设计文档卡片 + Python 参考 → 推演 → 实现 → 三路径测试 → 交叉检验 → 提交）；

```rust
/// Skill trait：所有 Skill 的统一形状（mcp 能力经 trait 注入，禁直接 IO）
pub trait Skill {
    fn name(&self) -> &'static str;
    fn run(&self, input: &SkillInput) -> Result<SkillOutput, SkillError>;
}
// SkillOutput 必含降级语义字段——失败保守降级（§5.7）是类型的一部分：
// registry 不可达 → 高风险 + 建议人工复核，而非静默放行
```

4. **S3.8** agents ×4 + runtime：`run_scan` / `run_guard` 两链路；状态机推进；事件发布挂点（scan_started/progress/completed、guard_verdict、audit_appended）；编排集成测试验证事件顺序与角色边界（Analyst 无写操作、Auditor 输入不含原文）；
5. **S3.9** CLI 真实现 + JSON/Markdown 双报告 + assert_cmd 端到端（对 fixtures 出正确裁决）。

### S4（2:25–3:20）——可感知的交付

1. **S4.1** axum + rust-embed + 主 Prompt §6.1.3 的 8 条路由 + oneshot 冒烟测试；
2. **S4.2** 设计令牌（直接用主 Prompt §6.1.5 起步令牌集）+ 深色布局 + 四视图导航骨架；
3. **S4.3** 四视图渲染：总览（风险计数卡+最近扫描）、扫描详情（依赖表+信号）、裁决时间线（状态机流转）、审计链（逐条校验状态）；**三态齐备**（骨架屏/空态/错误可重试），占位尺寸固定防跳动；
4. **S4.4** SSE：runtime 事件 → web 转发；前端 EventSource + 指数退避重连（≤5s）+ 断线状态条；**禁整页刷新轮询**。事件线格式：

```
event: guard_verdict
data: {"session_id":"s-42","verdict":"block","risk_level":"high"}
```

5. **S4.5** 质感打磨：150–250ms ease-out 只动 transform/opacity、hover 上浮+阴影、focus-visible 焦点环、vendored ECharts 暗色定制（配色取自令牌）、系统字体栈。逐条对照主 Prompt §6.1.5。

### S5–S6（3:20–4:00）

tracing JSON 日志接全链路（字段：session_id/agent_id/skill_name/level/event）→ 演示数据（fixtures 扫描 + 预置审计，保证 serve 首屏不空）→ README 快速开始实跑复核 → 终检三连 + `cargo audit` → 推送 → 最终报告。

## 8. 安全与质量红线（违反即返工或一票否决）

1. **十条不变量**（主 Prompt §5.1–§5.10）：决策与执行分离；能力最小化；untrusted 边界；Auditor 隔离；审计 append-only；审计/日志/UI 不落 untrusted 原文；失败保守降级；Rust 红线（forbid unsafe、clippy deny、thiserror、无 panic 路径）；外部访问收敛（网络只在 mcp 与 web 监听）；Web 边界（默认 `127.0.0.1:7878`、拒 `0.0.0.0` 默认）。
2. **依赖**：只用主 Prompt §3.2 清单内 crate 且按阶段引入；冲刺期不加清单外依赖；**禁 Node/npm**；**禁手写密码学**（只用 hmac+sha2）。
3. **测试**：禁真实网络；禁全局状态依赖；临时目录用 tempfile；断言语义不快照整包 JSON；审计链/注入检测/守门裁决零测试 = 不合格。
4. **提交**：禁红灯提交；禁密钥/真实载荷；S1 后禁 Python 残留；禁 force-push；禁 amend 已推送历史。
5. **约束文件**：不修改三份 docs 约束文件（V7）。
6. **分层**：skills 不 import agents/runtime/web；web 只调 runtime 公开 API；models 不依赖业务模块（主 Prompt §4.3）。

## 9. 沟通与报告协议

### 9.1 每循环一行小结

`[单元号] 完成 X；测试 N 过 0 败；验证 ✓（要点）；交叉检验 ✓（发现并修复了…/无矛盾）；提交 <hash> <message>`

### 9.2 检查点小结（0:25 / 2:25 / 3:20）

三行：当前 vs 计划（差多少）、是否触发裁剪（第几档、原因）、下一阶段计划。

### 9.3 最终交付报告（收尾必出）

```
# SupplyGuard 冲刺交付报告
## 1. 时间账：各阶段预算 vs 实际 vs 偏差原因（与 git 时间线一致）
## 2. 交付清单：已完成单元（S 编号）；裁剪项（第几档+原因，未触发写"无"）
## 3. 质量证据：cargo test / clippy / fmt / cargo audit 结果；§5 十条不变量逐条 ✓/✗ + 依据
## 4. 默认值采用清单（主 Prompt §14 逐条，未采用写"无"）
## 5. 运行方式：scan / guard / serve 三条真实命令 + 预期输出摘要
## 6. 遗留问题与下一冲刺建议（不确定就写不确定）
```

**诚实原则**：报告与 git/运行证据交叉一致；谎报 = 一票否决 V1。

## 10. 自检清单

**每次提交前**：只含本单元改动？三路径测试且绿？三连全绿？非测试区无 unwrap/expect/panic？无 untrusted 原文入审计/日志？提交正文含验证结论？diff 无密钥/调试残留？
**每阶段推送前**：全仓四绿？本阶段出口标准实跑过？README/设计文档同步？git log 一循环一提交？
**最终交付前**：底线逐项实跑记录？serve 四视图点一遍（三态、SSE、重连、动效）？RUBRICS 八条一票否决自查？报告六节齐全？已推送？

## 11. 常见陷阱（执行者视角；全文十六条见主 Prompt §17）

前八名：① 先写 Web 后写内核（S4 前禁碰 web/ui）；② clippy 欠账（deny 从 S1 生效，当步解决）；③ async 传染（业务层保持同步）；④ 快照式测试（断言语义不快照整包）；⑤ untrusted 原文入库/上屏（只存哈希摘要）；⑥ 时间盒失守（"再给十分钟"= 裁剪纪律已死）；⑦ 隐藏 panic（expect("safe")、切片越界、溢出都算）；⑧ Python 习惯写 Rust（错误类型化、状态用枚举、边界用 newtype）。

## 12. 异常与失败处理

| 情形 | 处置 |
| --- | --- |
| 工具链缺失/版本低 | 先修环境；修不好 → 报告并停在绿灯状态等待 |
| push 握手失败 | 重试 2–3 次（间隔 15s）；仍败 → 本地保留提交，报告等待；禁换镜像/改配置 |
| 单元两轮循环仍失败 | 触发裁剪：可降级按阶梯降级并标注；底线项则简化实现保底线，报告说明 |
| 时间不够 | 立即执行 §5.2 裁剪；4:00 无条件收尾——烂尾的完整 > 完美的烂尾 |
| 决策阻塞（§14 没有） | 停下问维护者；等待期间整理仓库到绿灯 |
| 测试偶发失败 | 先怀疑 Windows 环境因素（临时目录、路径分隔符、CRLF），修到稳定，不留 flaky |
| clippy 收紧后历史代码报错 | 当步修复；不许大面积 `#[allow]`（测试模块内显式豁免除外） |
| rusqlite bundled 构建慢/失败 | 确认 feature 写法、MSVC Build Tools 可用；构建问题是环境问题，按第 1 行处置 |

---

## 现在开始

从第 1 步（§3）开始。开工前先输出开场报告：① 环境检查结果（工具链版本、组件、网络、git 身份）；② §2 元数据核对（逐项 ✓/✗）；③ 确认理解交付定义（§1.3）与一票否决项（§1.4）。之后每循环按 §9.1 汇报、每检查点按 §9.2 汇报、收尾按 §9.3 交付。全程记住裁决顺序：**可运行优先 → 保守安全 → 本地优先 → 一切留痕 → 简单优先。**

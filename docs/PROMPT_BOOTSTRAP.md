# SupplyGuard 冲刺执行 Prompt（子 Prompt / 引导文件）

> **你是谁**：SupplyGuard 项目的开发执行 agent。你将独立完成一次从克隆仓库到最终交付的完整开发冲刺，全程无人值守、高强度、时间盒强制。
>
> **文件关系与优先级**：`docs/PROMPT.md` 是**主 Prompt**（项目边界与约束的唯一来源，最高约束力）；本文件是你的**操作手册**（怎么干、按什么节奏干、每一步产出什么）；`docs/RUBRICS.md` 是**评分标准**（你的表现将按它打分定级）。三份文件表述冲突时：主 Prompt > 本文件 > 评分标准的措辞。
>
> **总预算与交付**：**4 小时**，交付一个可 build、可 test、已推送、带最终报告的仓库。本手册每一节都是为"4 小时内拿到 RUBRICS 优秀档"服务的，没有装饰性内容。

---

## 1. 任务定义与交付定义

### 1.1 项目背景（你要做的是什么）

**SupplyGuard** 是一个多 Agent 供应链安全防御系统：在依赖进入代码库之前（守门模式）拦截危险依赖——尤其是 AI 编程工具产生的幻觉包（slopsquatting 攻击面）、已知 CVE、license 冲突；所有裁决走结构化证据链并落进不可篡改的审计日志。仓库里已有一套 Python 实现骨架（设计完整、部分落地），维护者已决定**整体迁移到 Rust**并收敛范围：本次冲刺只做**守门模式的本地闭环 + Web 可视化**，响应模式、真实 GitHub 集成等全部后移。

### 1.2 一句话任务

克隆真实仓库 `https://github.com/lggyx/supplyguard`，按主 Prompt 的设定把 Python 骨架重建为 Rust 实现（4 Agent 守门闭环 + 6 Skill + 审计链 + 安全净化 + Web 控制台），4 小时内交付。

### 1.3 交付定义（逐项验收，全部满足才算完成）

| # | 交付项 | 验收方式 |
| --- | --- | --- |
| D-1 | 仓库全绿灯 | `cargo test` 0 失败；`cargo clippy --all-targets -- -D warnings` 0 告警；`cargo fmt --check` 干净 |
| D-2 | 底线功能 | `supplyguard scan <fixtures样例目录>` 输出依赖清单+风险信号；`supplyguard guard --diff <diff文件>` 输出 Allow/Block/RequireReview 裁决 + 证据；`sbom-build`、`hallucination-check`、`cve-match` 三个 Skill 在链路中真实生效 |
| D-3 | Web 控制台 | `supplyguard serve` 一键启动，浏览器打开四视图仪表盘（或按裁剪阶梯降级后的只读报告页） |
| D-4 | 审计链 | 裁决落盘 SQLite，`verify` 通过；篡改测试证明可检测 |
| D-5 | 文档 | README 与代码事实一致，快速开始 ≤3 条命令可复现 |
| D-6 | Git | 全部提交已推送 `main`；历史呈现单元级六步循环节奏 |
| D-7 | 报告 | 最终交付报告（§9.3 模板）输出，与 git/运行证据交叉一致 |

### 1.4 你将被打分（与 RUBRICS.md 对应）

七个维度：可运行性与底线交付 25%、六步循环纪律 15%、架构与安全不变量 15%、测试质量 15%、时间管理与裁剪 10%、Web 可视化 10%、交付报告与诚实性 10%。总分 ≥90 且无一票否决 = 优秀。**一票否决项**（触发任意一条直接不合格）：伪造测试结果、红灯提交、审计可改写或 untrusted 原文外泄、提交真实密钥/攻击载荷、引入 Node/npm 工具链、砍底线交付、修改三份约束文件放水、超时后以红灯仓库冒充完成。按本手册与主 Prompt 执行自然得分；不要表演，更不要为分数走捷径。

## 2. 仓库代码元数据（克隆后逐一核对，缺失或对不上即停下来报告）

### 2.1 当前事实（你克隆时仓库的样子）

- **语言现状**：Python 3.10+，uv 管理，44 个 pytest 用例全部通过；**Rust 未初始化**——由你在 S1 负责迁移，这不是异常，是你的任务起点。
- **预期最新提交**：`7240f35 docs: add sprint evaluation rubrics`（或其后继；以 `git log` 实际为准）。
- **远端**：`origin = https://github.com/lggyx/supplyguard.git`，工作分支 `main`。

### 2.2 Python 代码清单（迁移前的参考地图——S1.4 删除前必须先读）

| 路径 | 内容 | 对你冲刺的价值 |
| --- | --- | --- |
| `src/supplyguard/models/messages.py` | 消息五类型（AnalysisRequest / RiskProfile / RemediationOrder / RemediationResult / Verdict）+ SessionState 状态机（received→analyzing→arbitrating→remediating→verifying→sealed） | **必读**：Rust `models/` 的 schema 与状态机语义直接照搬 |
| `src/supplyguard/audit/audit_log.py` | append-only 审计 + HMAC 签名哈希链 | **必读**：链式哈希算法语义照搬（`h_n = HMAC(key, h_{n-1} ‖ entry_n)`），存储换 SQLite |
| `src/supplyguard/security/injection_detector.py` | 注入检测规则 + 零宽字符剥离 | 规则思路可参考；检测语料抽到 `fixtures/` |
| `src/supplyguard/mcp/npm_registry.py`、`osv.py`、`tool_contracts.py` | registry / OSV 本地等价实现（离线回退、相似度匹配）、工具契约 | 判定逻辑、回退策略、阈值参考（以代码实际值为准） |
| `src/supplyguard/skills/*.py` | 5 个已实现 Skill：sbom_build、hallucination_check、cve_match、license_check、risk_profile | 阈值与判定语义照搬；结构按 Rust 重写 |
| `src/supplyguard/runtime/local_orchestrator.py` | 守门链路编排、状态机推进 | 流程参考；Rust 侧需事件化（供 web SSE 消费） |
| `src/supplyguard/agents/*.py` | Sentinel / Analyst / Auditor / Remediator 四角色行为 | 职责边界按主 Prompt §4.2 契约重新收口 |
| `src/supplyguard/demo/*.py` | slopsquatting_guard.py / cve_response.py / scan_repository.py 三个演示 | scan、guard 的 CLI 语义参考；cve_response 属响应模式，本次不做 |
| `tests/*.py` | 44 个用例 | 用例意图保留（测什么行为），形式按主 Prompt §9 用 Rust 重写 |
| `agents/`（仓库根目录） | 四角色 identity.yaml + pod-template.yaml | 职责/边界描述可参考；无运行时依赖，S1.4 评估去留（可删） |

### 2.3 文档清单（何时读哪份）

| 文件 | 角色 | 何时读 |
| --- | --- | --- |
| `docs/PROMPT.md` | **主 Prompt**：§1 产品原则、§3 技术栈与代码风格、§4 模块契约、§5 十条不变量、§6 范围与 Web 规格、§7 冲刺计划、§8 六步循环、§9 测试边界、§10 Git、§13 迁移映射、§14 默认值、§17 反模式 | 第 2 步完整精读（≤10 分钟），S2/S3/S4 动工前复读对应章节 |
| `docs/PROMPT_BOOTSTRAP.md` | 本文件 | 全程对照执行 |
| `docs/RUBRICS.md` | 评分标准 | 第 2 步浏览一遍；S6 收尾前对照自查 |
| `docs/specs/2026-08-10-supplyguard-design.md` | 领域设计：13 张 Skill 卡片、洋葱七层、消息协议、降级表（§6.5） | 写对应模块前精读对应卡片；注意 §6 只要求 6 个 Skill |
| `docs/demo/*.md` | 演示输出样例 | 校准 scan/guard 输出语义时参考 |
| `README.md` | 当前仍描述 Python | S1.4 由你整体重写 |

### 2.4 冲刺目标产物（Rust 侧将要新建的形态与各文件职责）

```
Cargo.toml                # edition 2024 + 主 Prompt §3.3 的 lint 配置（S1 就配好）
Cargo.lock                # 入库，随功能提交
scripts/check.ps1|sh      # 可选：一键 fmt --check + clippy -D warnings + test
fixtures/
  lockfiles/              # v1_basic / v2_with_dev / v3_nested / corrupted / empty / missing_fields / unsupported_format
  malicious/              # 虚构恶意 README 样本（注入语句演示级、包名虚构、脱敏）
  policies/               # license 允许/禁止策略、注入检测语料（JSON）
ui/
  index.html              # 单页仪表盘入口
  assets/css|js           # 手写设计系统（设计令牌）+ 原生 ES Modules
  vendor/                 # vendored Alpine.js / ECharts（文件头注明来源与协议）
src/
  main.rs                 # clap 子命令 scan/guard/serve + 错误→退出码，无业务逻辑
  lib.rs                  # 模块声明 + #![forbid(unsafe_code)]
  models/                 # messages.rs（五类型）+ session.rs（状态机+迁移表）+ ids.rs（newtype）
  security/               # sanitize.rs（净化）+ injection.rs（注入检测）
  audit/                  # chain.rs（SQLite 追加表 + HMAC 链 + verify）
  mcp/                    # trait（RegistryClient/VulnSource/LicenseDb）+ npm_local/osv_local/license_spdx 实现
  skills/                 # Skill trait + sbom_build/hallucination_check/cve_match/license_check/risk_profile
  agents/                 # sentinel/analyst/auditor/remediator（行为按主 Prompt §4.2 契约）
  runtime/                # orchestrator.rs：run_scan/run_guard 两条链路 + 事件发布
  web/                    # mod.rs（路由组装）+ api.rs + sse.rs；只调 runtime 公开 API
  config.rs               # supplyguard.toml 加载/校验/默认值
tests/                    # cli_scan.rs / cli_guard.rs / orchestrator_flow.rs / web_smoke.rs
```

## 3. 环境部署细则（第 1 步）

### 3.1 获取代码

```bash
git clone https://github.com/lggyx/supplyguard.git
cd supplyguard
git log --oneline -3                 # 核对 §2.1 事实
git status                           # 必须干净
```

### 3.2 Rust 工具链核对与安装

```bash
rustc --version                      # 需 ≥ 1.85（主 Prompt MSRV）
cargo --version
rustup component list --installed    # 必须含 clippy、rustfmt；缺则：rustup component add clippy rustfmt
```

无 rustup 时先按 https://rustup.rs 安装 stable 工具链（Windows 用 rustup-init.exe；Git Bash 内可直接调用）。安装后重开 shell 确认 PATH 生效。

### 3.3 网络与代理注意

维护者网络环境经本地代理（`127.0.0.1:7897`）访问 GitHub，**该代理存在间歇性握手失败**，典型报错 `schannel: failed to receive handshake, SSL/TLS connection failed`。对策：clone / push 失败时**重试 2–3 次（间隔约 15 秒）**，多数可恢复；仍失败则把已完成提交留在本地、报告并等待。**禁止**为绕过网络问题更换远端镜像、改写 git 全局配置或使用 force-push。

### 3.4 Git 身份

```bash
git config user.name && git config user.email
```

为空则向维护者询问身份，不要编造。确认 `.gitignore` 覆盖 `target/`、`.env`（S1.1 建立 Rust 骨架时补全）。

### 3.5 环境验证

Python 侧（克隆后立刻，核对 §2.1 事实）：`uv run pytest tests/ -q` → 预期 `44 passed`。Rust 侧（S1.1 完成后）：`cargo build` 成功、`cargo test` 通过、故意在临时分支写一个 `unwrap()` 验证 clippy 真的会拦（验证后撤销）。**环境问题（工具链缺失、版本过低、权限、磁盘）先修复环境再开工，不得绕过检查继续。

### 3.6 Windows 环境补充（开发机为 Windows + Git Bash）

- **MSVC 工具链**：rustup 默认 `x86_64-pc-windows-msvc` target，需要 Visual Studio Build Tools（C 编译器）；缺失时 rusqlite bundled 等含 C 代码的 crate 会构建失败，报错通常是 `link.exe not found`——先装 Build Tools 再继续；
- **换行符**：仓库建议 S1.1 加 `.gitattributes`（`* text=auto eol=lf`，shell 脚本必须 LF）；本地如果出现 CRLF 干扰 `cargo fmt --check`，优先修 `.gitattributes` + `git add --renormalize .`，不要关掉 fmt 检查；
- **路径**：代码内一律 `std::path::Path::join` 组合路径，禁止硬编码 `\` 或 `/`；测试中的临时路径用 `tempfile` crate，不手写 `%TEMP%`；
- **杀软/Defender**：首次 `cargo build` 可能被实时扫描拖慢，属正常现象，不为提速关闭安全软件。**

## 4. 主 Prompt 加载协议（第 2 步）

### 4.1 阅读顺序与时间盒（合计 ≤ 15 分钟，超时挤占冲刺时间）

| 顺序 | 材料 | 时间 | 要提取的重点 |
| --- | --- | --- | --- |
| 1 | `docs/PROMPT.md` 完整精读 | ≤10 min | §3.3 代码红线与 lint 配置；§4.2 模块"必须/禁止"表；§5 十条不变量（背下来）；§7.1 阶段表 + §7.2 底线与裁剪阶梯；§8 六步循环与提交模板；§14 默认值表；§17 十六条反模式 |
| 2 | `README.md` | ≤2 min | 核对现状（仍为 Python），确认与 §2 元数据一致 |
| 3 | `docs/specs/` 目录级浏览 | ≤3 min | 定位 Skill 卡片（§6.3）、降级总览（§6.5）、消息协议（§4.4）——S2/S3 动工前再精读对应卡片 |

### 4.2 冲突与默认值协议

1. 流程、边界、工作流问题 → 以主 Prompt 为准；
2. 领域细节（Skill 判定语义、消息字段含义、降级策略细节）→ 以设计文档为准；
3. 两者冲突或都未覆盖 → 按主 Prompt **§14 默认值**处理，并在最终报告"默认值采用清单"逐条标注；
4. §14 也未覆盖、且可能违反 §5 不变量 → 停下来问维护者；**问之前把仓库整理到全绿灯**（已完成部分先提交）。

主 Prompt §14 默认值速查（冲刺期直接采用）：LLM=纯规则引擎留 trait；GitHub 集成=不做；前端=原生 ES Modules + vendored Alpine.js + ECharts；crate=单 crate；存储=SQLite（rusqlite bundled）；License=README 标"待定"；Web 监听=默认 `127.0.0.1:7878`、拒绝 `0.0.0.0` 默认。

### 4.3 约束文件保护

禁止修改 `docs/PROMPT.md`、`docs/PROMPT_BOOTSTRAP.md`、`docs/RUBRICS.md`（评分一票否决项 V7："改规则让自己及格"）。对规则的异议写进最终报告，不落代码。

## 5. 冲刺执行总纲（第 3 步）

### 5.1 阶段表（细节以主 Prompt §7.1 为准，此为执行视图）

| 阶段 | 时间窗 | 核心目标 | 出口标准（不达标不进下一阶段） |
| --- | --- | --- | --- |
| S1 工作区引导 | 0:00–0:25 | Rust 骨架 + lint 规则 + models + CLI 占位 + **删 Python** + README 重写 | 检查三连全绿；grep 无 pyproject/uv 残留；推送 |
| S2 安全与审计 | 0:25–1:05 | sanitize + injection 检测 + audit 哈希链 | 三套件各含语料/篡改测试且通过 |
| S3 守门闭环 | 1:05–2:25 | fixtures → mcp → 5 Skill → 4 Agent + runtime → CLI 端到端 | scan/guard 对 fixtures 出正确裁决；推送 |
| S4 Web 可视化 | 2:25–3:20 | axum + 内嵌 UI + 四视图 + SSE + 质感 | serve 一键起；§6.1 规格逐条自查 |
| S5 观测与演示 | 3:20–3:45 | tracing JSON 日志 + 演示数据 + README 复核 | 三命令实跑复现 |
| S6 收尾 | 3:45–4:00 | 终检 + cargo audit + 推送 + 最终报告 | 干净交付 |

### 5.2 检查点纪律

0:25 / 2:25 / 3:20 三个检查点：对照时间表，**落后 > 10 分钟立即按主 Prompt §7.2 裁剪阶梯降档**，顺序固定不可跳：① S5 收缩（tracing 降 console）→ ② Web 降只读报告页（保深色+令牌+表格时间线，去 SSE/图表）→ ③ license-check 转 stub（未知→review）→ ④ hallucination-check 转离线相似度。**底线与永不裁剪项**（六步循环、§5 不变量、测试全绿、可运行优先）不可触碰。裁剪是决策不是失败——报告里如实写第几档即可。

### 5.3 可运行优先

任何时刻 `cargo build` 必须成功。开工前是绿的，做完还是绿的；做坏了先修复或回退该单元，绝不让红灯过夜（一票否决 V2/V8 都与红灯有关）。

## 6. 六步循环操作细则（每个功能单元，主 Prompt §8 为准）

**一个功能单元 = 一次循环 = 一个提交。** 单元 = 一个 Skill / 一个模块 / 一个行为切片（diff ≤ ~400 行；时间紧允许切更小，但六步一项不许省）。

### 6.1 每步操作与产出

| 步 | 操作 | 产出物 |
| --- | --- | --- |
| 1 编写功能 | 先方案推演（输入输出 / 边界 / 失败路径 / 涉及的 §5 不变量 / 打算怎么测），推演完再动手；只做本单元内容；遵守 §4.2 模块契约 | 代码 + 回复中的推演记录 |
| 2 编写测试样例 | 三路径：正常 / 边界（空、畸形、超大、极端值）/ 失败降级；外部 IO 走 fixture 或 trait mock；测试名表达行为 | 测试代码 |
| 3 测试 | `cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` 全绿；失败回第 1 步修，禁止放宽断言或 lint | 绿灯输出 |
| 4 逻辑验证 | 按模板输出验证清单：输入输出✓（依据）、错误分支✓（覆盖了哪些）、边界✓（空/超长/重复提交行为）、§5 逐条核查 | 验证清单 |
| 5 逻辑交叉检验 | 四视角逐一给结论：①规格重推（独立推导预期输出再比对）②测试审计（断言的是规格行为还是实现细节）③对抗视角（构造畸形输入/重复提交/篡改反例）④契约一致性（与设计文档、相邻模块核对） | 交叉检验结论；发现矛盾回第 1 步 |
| 6 git 提交 | `type(scope): summary` + 正文（范围/验证结论/遗留），对照主 Prompt §8.6 示例 | 一个提交 |

### 6.2 完整示范（以 `license_check` 为例的迷你 walkthrough）

- **推演（步1）**：输入=包 license 字符串数组 + 策略（allow/deny 列表）；输出=`violations[] + compatible + policy_version`；边界=空列表、未知 license、策略缺失；失败降级=未知 license → "需人工确认"，不自动 block（§5.7 保守）；涉及不变量 §5.7；测试=表驱动 8 例。
- **测试（步2）**：`allows_permitted_license` / `flags_denied_license` / `unknown_license_requires_review` / `empty_packages_yields_compatible` / `missing_policy_defaults_strict`（策略缺失按主 Prompt §6.0.1 → 走最严格路径）…
- **测试（步3）**：三连全绿。
- **验证（步4）**：清单逐条 ✓；特别核对"未知 license 不 block"与 §5.7 一致。
- **交叉检验（步5）**：规格重推发现"大小写：GPL-3.0 vs gpl-3.0"应视为未知而非不匹配——补规范化处理与用例；测试审计确认断言的是策略语义而非内部排序；对抗例：空字符串 license → 走未知路径 ✓。
- **提交（步6）**：`feat(skills): add license-check with conservative unknown handling` + 正文（范围/验证/遗留）。

照此粒度执行每一个单元。

## 7. 分阶段单元执行卡片

### S1（0:00–0:25）——骨架即规则

1. **S1.1** `cargo init` → edition 2024 → lint 配置（`forbid(unsafe_code)`、clippy deny unwrap/expect/panic、missing_docs warn）→ `.gitignore` 补 `target/` → 可选 `scripts/check.*`。验收：故意写 unwrap 被 clippy 拦下。
2. **S1.2** `models`：五消息类型 + 状态机（合法迁移表；非法迁移返回 `StateTransitionError`）+ newtype ID；全部 serde 化；做序列化往返与非法迁移测试。
3. **S1.3** CLI 占位：clap derive，`scan` / `guard` / `serve` 三子命令 + `--version`；各自打印占位信息退出码 0。
4. **S1.4** **专门提交删除 Python**：`src/supplyguard/`、`tests/`、`pyproject.toml`、`requirements.txt`、`uv.lock`（根目录 `agents/` 一并评估，可删）；删前读完 §2.2 两个"必读"文件。提交信息注明"remove Python implementation (superseded by Rust rewrite)"。
5. **S1.5** README 重写：定位一句话、功能列表（对齐实际）、三命令快速开始、架构简图、状态表（诚实区分已实现/占位）、License"待定"。

### S2（0:25–1:05）——安全地基

1. **S2.1** `sanitize`：零宽字符（U+200B–200D、U+FEFF）、控制字符、异常编码剥离；纯函数；语料进 `fixtures/`。
2. **S2.2** `injection`：规则/模式匹配（指令伪装如 "ignore previous instructions"、角色扮演诱导、编码绕过变体）；语料表驱动；输出结构化（命中规则、置信度）。
3. **S2.3** `audit`：SQLite 追加表（rusqlite bundled；建表 SQL 不含 UPDATE/DELETE 路径）+ HMAC-SHA256 链（`h_n = HMAC(key, h_{n-1} ‖ entry_n)`，key 来自配置）+ `verify` 全链校验。**核心测试：追加→verify 过；篡改任一字节→verify 败并指出断裂位置。**

### S3（1:05–2:25）——主战场，单元顺序不可换（每单元一次六步循环）

1. **S3.1** fixtures 全套（清单见 §2.4）——没有夹具，后面所有测试都是空中楼阁；
2. **S3.2** mcp trait + 三个本地实现（npm_local / osv_local / license_spdx 内置数据集；离线可用；实现可失败并返回本模块错误）；
3. **S3.3–S3.7** Skill 依序：sbom_build → hallucination_check → cve_match → license_check → risk_profile。每个 Skill：读设计文档对应卡片 + Python 参考实现 → 推演 → 实现 → 三路径测试 → 交叉检验 → 提交；
4. **S3.8** agents ×4 + runtime：`run_scan` / `run_guard` 两条链路；状态机推进；事件发布挂点（scan_started/progress/completed、guard_verdict、audit_appended）预留；编排集成测试验证事件顺序与角色边界（Analyst 无写操作、Auditor 输入不含原文）；
5. **S3.9** CLI 真实现 + JSON/Markdown 双报告输出 + assert_cmd 端到端测试（对 fixtures 样例出正确裁决）。

### S4（2:25–3:20）——可感知的交付

1. **S4.1** axum + rust-embed + 主 Prompt §6.1.3 的 8 条路由 + oneshot 冒烟测试（状态码、JSON 结构、SSE 端点存在）；
2. **S4.2** 设计令牌（直接采用主 Prompt §6.1.5 起步令牌集）+ 深色布局 + 左导航四视图骨架；
3. **S4.3** 四视图渲染：总览（风险计数卡+最近扫描）、扫描详情（依赖表+信号）、裁决时间线（状态机流转）、审计链（逐条校验状态）；**三态齐备**（骨架屏/空态引导/错误可重试），占位尺寸固定防跳动；
4. **S4.4** SSE：runtime 事件 → web 转发（§6.1.4 事件类型）；前端 EventSource 接入 + 指数退避重连（≤5s）+ 断线状态条；**禁止整页刷新轮询**；
5. **S4.5** 质感打磨：150–250ms ease-out 只动 transform/opacity、卡片 hover 上浮+阴影、focus-visible 焦点环、vendored ECharts 暗色定制（配色取自令牌）、系统字体栈。逐条对照主 Prompt §6.1.5 自查。

### S5–S6（3:20–4:00）

tracing JSON 日志接全链路（字段：session_id/agent_id/skill_name/level/event）→ 演示数据（fixtures 样例项目扫描 + 预置审计，保证 serve 起来首屏不空）→ README 快速开始逐条实跑复核 → 终检三连 + `cargo audit` → 推送 → 最终报告。

## 8. 安全与质量红线（完整清单，违反即返工或一票否决）

1. **十条不变量**（主 Prompt §5.1–§5.10，每条都有定义/合规做法/验证方式/反面案例）：决策与执行分离；能力最小化；untrusted 边界（标记+包裹+注入检测，原文永不成为指令）；Auditor 隔离（编译期不接触原文）；审计 append-only（只有 append/verify API）；审计/日志/UI 不落 untrusted 原文（只存哈希与摘要）；失败保守降级（宁可误报不漏报）；Rust 红线（forbid unsafe、clippy deny unwrap/expect/panic、thiserror 类型化、无任何 panic 路径、公开 API 有文档）；外部访问收敛（网络只在 mcp 与 web 监听）；Web 边界（默认 `127.0.0.1:7878`、拒绝 `0.0.0.0` 默认、API 最小面、不承载密钥）。
2. **依赖**：只用主 Prompt §3.2 清单内 crate 且按阶段引入；冲刺期不新增清单外依赖（默认值协议）；**禁 Node/npm 工具链**；**禁手写密码学**（哈希链只用 hmac+sha2）。
3. **测试**：禁真实网络；禁全局状态依赖；临时目录用 tempfile；断言语义不快照整包 JSON；审计链/注入检测/守门裁决零测试 = 不合格。
4. **提交**：禁红灯提交；禁密钥/真实攻击载荷入库；S1 后禁 Python/uv 残留；禁 force-push；禁 amend 已推送历史。
5. **约束文件**：不修改三份 docs 约束文件（一票否决 V7）。
6. **分层**：skills 不 import agents/runtime/web；web 只调 runtime 公开 API；models 不依赖业务模块（主 Prompt §4.3）。

## 9. 沟通与报告协议

### 9.1 每循环一行小结（回复中输出，10 秒读完）

格式：`[单元号] 完成 X；测试 N 过 0 败；验证 ✓（要点）；交叉检验 ✓（发现并修复了…/无矛盾）；提交 <hash> <message>`
示例：`[S3.4] 完成 hallucination-check；测试 12 过 0 败；验证 ✓（离线回退走保守分支）；交叉检验 ✓（发现编辑距离阈值对 4 字符包名过宽，收紧并补用例）；提交 a1b2c3d feat(skills): add hallucination-check with offline fallback`

### 9.2 检查点小结（0:25 / 2:25 / 3:20）

三行内容：当前阶段 vs 计划（领先/落后多少）、是否触发裁剪（第几档、原因）、下一阶段计划。

### 9.3 最终交付报告（收尾必出，逐节填写）

```
# SupplyGuard 冲刺交付报告
## 1. 时间账
| 阶段 | 预算 | 实际 | 偏差原因 |            ← 与 git 提交时间线一致
## 2. 交付清单
已完成单元：…（对应 S 编号）
裁剪项：…（§7.2 第几档 + 触发原因）；未触发则写"无"
## 3. 质量证据
cargo test：N 过 0 败；clippy：0 告警；fmt：干净；cargo audit：结果
§5 不变量十条：逐条 ✓/✗ + 一句话依据
## 4. 默认值采用清单（主 Prompt §14）
逐条：决策 # → 采用默认值 → 原因；未采用写"无"
## 5. 运行方式
scan：…；guard：…；serve：…（真实命令 + 预期输出摘要）
## 6. 遗留问题与下一冲刺建议
…（如实，不确定就写不确定）
```

**诚实原则**：报告与 git/运行证据必须交叉一致；谎报 = 一票否决 V1，无商量余地。

## 10. 自检清单

### 10.1 每次提交前（10 秒过一遍）

- [ ] 只含本单元改动，无夹带？— [ ] 三路径测试都在且绿？— [ ] 检查三连全绿？— [ ] 非测试区无 unwrap/expect/panic？— [ ] 无 untrusted 原文进审计/日志/UI？— [ ] 提交正文含验证与交叉检验结论？— [ ] diff 无密钥/真实载荷/调试残留？

### 10.2 每阶段推送前

- [ ] 全仓 build/test/clippy/fmt 四绿？— [ ] 本阶段出口标准（§5.1 表）逐条实跑过？— [ ] README 与设计文档已同步本阶段变化？— [ ] git log 呈现一循环一提交？— [ ] 已推送 main 成功？

### 10.3 最终交付前

- [ ] 底线清单（D-2）逐项实跑并记录输出？— [ ] serve 起来后四视图人工点一遍（三态、SSE 推进、断线重连、动效）？— [ ] RUBRICS 八条一票否决逐条自查？— [ ] 最终报告六节齐全且与证据一致？— [ ] 全部提交已推送？

## 11. 常见陷阱（执行者视角；全文十六条见主 Prompt §17）

最容易踩、代价最高的前八名：

1. **先写 Web 后写内核**——S4 之前禁碰 `web/` 与 `ui/`，没有数据与编排的 UI 是空壳；
2. **clippy 欠账**——deny 从 S1 生效，警告即错误当步解决，攒到收尾就是灾难；
3. **async 传染**——业务层保持同步，异步只在 axum/mcp 边界；
4. **快照式测试**——断言关键字段与语义，整包 JSON 快照又脆又掩盖问题；
5. **untrusted 原文入库/上屏**——只存哈希与摘要，"方便排查"不是理由；
6. **时间盒失守**——"再给十分钟就能完美"= 裁剪纪律已死，到点立即降档；
7. **隐藏 panic**——`expect("safe")`、切片越界、整数溢出都算 panic 路径；
8. **Python 习惯写 Rust**——正确性优先不等于放弃惯用法：错误类型化、状态用枚举、边界用 newtype。

## 12. 异常与失败处理

| 情形 | 处置 |
| --- | --- |
| 工具链缺失 / 版本低于 MSRV | 先修环境（rustup 安装/升级）；修不好 → 报告并停在当前绿灯状态，等待指示 |
| GitHub push 握手失败 | 重试 2–3 次（间隔 15s）；仍失败 → 提交保留在本地，报告等待；禁换镜像/改配置/force-push |
| 某单元两轮循环仍失败 | 触发裁剪判断：可降级 → 按阶梯降级并标注；属底线项 → 简化实现保底线，报告说明取舍 |
| 时间不够（检查点落后） | 立即执行 §5.2 裁剪阶梯；4:00 无条件收尾（终检、推送、报告）——烂尾的完整 > 完美的烂尾 |
| 决策阻塞（§14 没有覆盖） | 停下来问维护者；等待期间把仓库整理到绿灯、写清已完成提交 |
| 测试偶发失败 | 先怀疑 Windows 环境因素（临时目录权限、路径分隔符、CRLF），修到稳定；不留 flaky 测试 |
| clippy 收紧后历史代码报错 | 当步修复，不允许 `#[allow]` 大面积豁免（测试模块内显式豁免除外） |
| rusqlite bundled 构建慢/失败 | 确认 feature 写法正确、C 编译器可用（Windows 需 MSVC Build Tools）；构建问题是环境问题，走第 1 行处置 |

---

## 现在开始

从第 1 步（§3 环境部署）开始执行。开工前先输出开场报告：① 环境检查结果（rustc/cargo 版本、clippy/rustfmt 组件、网络连通性、git 身份）；② §2 仓库元数据核对结果（逐项 ✓/✗）；③ 确认已理解交付定义（§1.3）与一票否决项（§1.4）。

之后：每个循环按 §9.1 汇报，每个检查点按 §9.2 汇报，收尾按 §9.3 交付最终报告。全程记住主 Prompt §1.4 的裁决顺序：**可运行优先 → 保守安全 → 本地优先 → 一切留痕 → 简单优先。**

# SupplyGuard

> 面向 AI 编程时代的多 Agent 供应链安全防御系统——在依赖进入代码库之前，拦下 AI 幻觉包（slopsquatting）、已知 CVE 与 license 冲突，并把每一次裁决封进不可篡改的审计链。

## 一句话定位

LLM 会"幻觉"出并不存在的包名，攻击者批量抢注这些名字（slopsquatting）；传统 SCA 工具只做 CVE 匹配、不参与决策。SupplyGuard 用一条本地守门闭环（扫描 → 多信号融合 → 裁决 → 审计留痕）守住依赖引入时刻，v1 完整覆盖 npm 生态。

## 功能列表（v1 范围）

| 功能 | 说明 |
| --- | --- |
| `supplyguard scan <dir>` | 解析 npm `package-lock.json`（v1/v2/v3），输出依赖清单 + 每包风险信号 + JSON/Markdown 报告 |
| `supplyguard guard --diff <file>` | 对依赖变更 diff 做守门裁决：Allow / Block / RequireReview + 证据链 + 审计落盘 |
| Skill ×6 | `sbom-build`、`hallucination-check`、`cve-match`、`license-check`、`risk-profile`、`audit-log-write` |
| Agent ×4 | Sentinel（入口与 UNTRUSTED 标记）/ Analyst（只读分析）/ Auditor（仲裁与审计）/ Remediator（建议产出，不开真实 PR） |
| 洋葱安全 L1–L3 | UNTRUSTED 标记、零宽字符净化、prompt 注入检测 |
| 审计链 | SQLite 追加表 + HMAC-SHA256 哈希链，`verify` 可检测任意字节篡改 |
| Web 控制台 | `supplyguard serve` 内置四视图仪表盘（总览 / 扫描详情 / 裁决时间线 / 审计链），深色主题 + SSE 实时事件 |

非目标（backlog）：响应模式（CVE feed 订阅与批量处置）、真实 GitHub PR 集成、PyPI/Maven 生态、执行沙箱、Web 鉴权与远程访问。

## 快速开始

需要 Rust stable ≥ 1.85（[rustup](https://rustup.rs) 安装，Windows 需 MSVC Build Tools）。无需其他系统依赖（SQLite 已 bundled 进构建）。

```bash
# 1. 克隆并构建
git clone https://github.com/lggyx/supplyguard && cd supplyguard
cargo build

# 2. 三条命令
cargo run -- scan <项目目录>        # 扫描一个 npm 项目的依赖
cargo run -- guard --diff <diff文件> # 对一次依赖变更出守门裁决
cargo run -- serve                  # 启动本地 Web 控制台（默认 http://127.0.0.1:7878）
```

> **当前状态（Rust 重写冲刺进行中）**：CLI 三个子命令已可运行（打印解析后的参数）；`scan` / `guard` / `serve` 的完整实现分别于 S3 / S3 / S4 阶段落地，本节随代码事实同步更新。

## 架构简图

```
main (CLI: scan / guard / serve)
  └─> web (axum + 内嵌 ui/, 只读 API + SSE)      [S4]
        └─> runtime (LocalOrchestrator: run_scan / run_guard, 事件发布)
              └─> agents (Sentinel → Analyst → Auditor → Remediator)
                    └─> skills (sbom-build / hallucination-check / cve-match /
                                license-check / risk-profile)
                          └─> models (消息五类型 + 状态机 + newtype ID)
              skills ──trait──> mcp (npm_local / osv_local / license_spdx)
  security (净化 + 注入检测)、audit (SQLite + HMAC 哈希链)：被任意层依赖
```

依赖方向单向：`main → web → runtime → agents → skills → models`；`skills` 通过 trait 消费 `mcp` 能力，不依赖 `agents` / `runtime` / `web`。

## 项目状态

| 模块 | 状态 |
| --- | --- |
| 工作区（cargo + edition 2024 + lint 门禁） | ✅ 已实现 |
| models：消息协议 + 状态机 + newtype ID | ✅ 已实现 |
| CLI 骨架（scan / guard / serve） | ✅ 已实现（占位输出） |
| security：净化 + 注入检测 | 🚧 S2 落地 |
| audit：SQLite 追加表 + HMAC 链 | 🚧 S2 落地 |
| mcp：trait + npm/OSV/SPDX 本地实现 | 🚧 S3 落地 |
| skills ×6 / agents ×4 / runtime 编排 | 🚧 S3 落地 |
| CLI scan / guard 真实现 + 双格式报告 | 🚧 S3 落地 |
| Web 控制台（四视图 + SSE） | 🚧 S4 落地 |
| 响应模式 / GitHub 集成 / 真网 registry 查询 | 📋 backlog（冲刺后 M4+） |

设计文档见 `docs/specs/`；开发约束见 `docs/PROMPT.md`；行为参考样例见 `docs/demo/`（为 Python 版输出，Rust 版落地后更新）。

## 配置说明

v1 当前不引入配置文件：监听地址经 `serve --bind <addr>` 覆盖，扫描范围经 CLI 标志控制。`supplyguard.toml`（license 策略、审计密钥来源、监听地址等）计划随 S3 阶段引入并在本节补充字段说明。

## 安全说明

- **本地优先**：Web 控制台默认只监听 `127.0.0.1:7878`；如需远程访问，请自行套反向代理并加鉴权，本项目不内置鉴权。
- **审计链**：裁决写入 SQLite 追加表，逐条 HMAC-SHA256 签名链接；只提供 append / verify，不存在改写历史的代码路径；篡改任一字节 `verify` 即失败。
- **untrusted 边界**：外部内容（README、CVE 描述、diff、registry 响应）进入系统即打 UNTRUSTED 标记、剥离零宽字符、过注入检测；审计与日志只存哈希与系统生成摘要，不落原文。
- **签名密钥**：经环境变量注入（不写入仓库与配置文件）。

## License

待定（未定案前不附协议文件）。

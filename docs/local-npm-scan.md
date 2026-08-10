# 本地 npm 项目扫描

SupplyGuard 可以扫描一个本地 npm 项目中的直接依赖。扫描过程只读取 `package.json` 和可选的 `package-lock.json`，不会执行 `npm install`、项目脚本或任何依赖代码。

在 SupplyGuard 仓库根目录运行：

```powershell
uv run python src/supplyguard/demo/scan_repository.py <目标项目目录>
```

默认只扫描 `dependencies`。如需把开发依赖一起扫描：

```powershell
uv run python src/supplyguard/demo/scan_repository.py <目标项目目录> --include-dev
```

当前能力范围：

- 支持 npm `package-lock.json` v1、v2 和 v3 的直接依赖锁定版本读取。
- 将扫描结果转换为既有的 Sentinel → Analyst → Auditor → Remediator 流程。
- 通过本地 CVE 规则库和 npm Registry / 离线相似度回退策略进行风险判断。

限制：真实 OSV/GHSA 查询、完整传递依赖图、GitHub PR 创建和 AgentTeams 运行时接入仍在后续阶段。

use clap::{Parser, Subcommand};
use serde::Serialize;
use supplyguard::agents::analyst::Analyst;
use supplyguard::agents::auditor::{Auditor, Verdict};
use supplyguard::agents::cve::CveAgent;
use supplyguard::agents::hallucination::HallucinationAgent;
use supplyguard::agents::license::LicenseAgent;
use supplyguard::agents::sentinel::Sentinel;
use supplyguard::pipeline::Orchestrator;

/// SupplyGuard - AI 编程时代的供应链安全防御 CLI 工具
#[derive(Parser)]
#[command(name = "supplyguard")]
#[command(about = "AI 编程时代的供应链安全防御 CLI 工具", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 单次扫描 npm 项目依赖
    Scan {
        /// 包含 package-lock.json 的目录路径
        path: String,
        /// 输出 JSON 格式（默认）
        #[arg(long)]
        json: bool,
        /// 包含 devDependencies
        #[arg(long)]
        include_dev: bool,
    },
    /// 对依赖变更做守门裁决
    Guard {
        /// 变更 diff 文件路径
        diff: String,
    },
    /// 持续监控目录的依赖变化
    Monitor {
        /// 要监控的目录路径
        path: String,
        /// 包含 devDependencies
        #[arg(long)]
        include_dev: bool,
    },
    /// 实时状态查询
    Overview,
    /// 查看会话推理时间线
    Timeline {
        /// 会话 ID
        session_id: String,
    },
    /// 审计链查询
    Audit {
        /// 验证哈希链完整性
        #[arg(long)]
        verify: bool,
    },
}

#[derive(Serialize)]
struct ScanOutput {
    session_id: String,
    status: String,
    packages_total: usize,
    findings: Vec<Verdict>,
    summary: ScanSummary,
}

#[derive(Serialize)]
struct ScanSummary {
    allow: usize,
    review: usize,
    block: usize,
    reasoning: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("supplyguard=info")
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path, include_dev, .. } => {
            let session_id = format!("scan-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));

            // 查找 package-lock.json
            let lockfile_path = if std::path::Path::new(&path).is_dir() {
                format!("{}/package-lock.json", path)
            } else {
                path.clone()
            };

            // 1. Sentinel 初始化
            let sentinel = Sentinel::new();
            if let Err(e) = sentinel.initialize(&lockfile_path).await {
                eprintln!("初始化失败: {}", e);
                std::process::exit(1);
            }

            // 2. Analyst 解析 SBOM
            let analyst = Analyst::new();
            let sbom = match analyst.build_sbom(&lockfile_path) {
                Ok(sbom) => sbom,
                Err(e) => {
                    eprintln!("扫描失败: {}", e);
                    std::process::exit(1);
                }
            };

            tracing::info!("解析完成: {} 个包", sbom.total);

            // 3. 并行运行 Hallucination + CVE + License 检查
            let npm = supplyguard::mcp::NpmLocal::new();
            let osv = supplyguard::mcp::OsvLocal::new();
            let spdx = supplyguard::mcp::SpdxLocal::new();

            let hallucination = HallucinationAgent::new(Box::new(npm));
            let cve = CveAgent::new(Box::new(osv));
            let license = LicenseAgent::new(Box::new(spdx));
            let auditor = Auditor::new();

            let mut findings = Vec::new();
            let mut allow_count = 0;
            let mut review_count = 0;
            let mut block_count = 0;

            for pkg in &sbom.packages {
                if !include_dev && pkg.dev {
                    continue;
                }

                // 并行检查
                let h_result = hallucination.check(&pkg.name).await.ok();
                let c_result = cve.check(&pkg.name, &pkg.version).await.ok();
                let l_result = license.check(&pkg.name, &pkg.license.clone().unwrap_or_default()).await.ok();

                // Auditor 综合裁决
                let verdict = match auditor.issue_verdict(&pkg.name, &pkg.version, h_result.as_ref(), c_result.as_ref(), l_result.as_ref()) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("裁决失败 ({}): {}", pkg.name, e);
                        continue;
                    }
                };

                match verdict.decision.as_str() {
                    "ALLOW" => allow_count += 1,
                    "REVIEW" => review_count += 1,
                    "BLOCK" => block_count += 1,
                    _ => {}
                }

                findings.push(verdict);
            }

            // 4. 输出结果
            let output = ScanOutput {
                session_id: session_id.clone(),
                status: "completed".to_string(),
                packages_total: sbom.total,
                findings,
                summary: ScanSummary {
                    allow: allow_count,
                    review: review_count,
                    block: block_count,
                    reasoning: format!(
                        "对 {} 个包完成多信号分析：{} ALLOW / {} REVIEW / {} BLOCK",
                        sbom.total, allow_count, review_count, block_count
                    ),
                },
            };

            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        Commands::Guard { diff } => {
            println!("守门模式: {} (TODO)", diff);
        }
        Commands::Monitor { path, include_dev } => {
            println!("监控目录: {} (include_dev: {})", path, include_dev);
            println!("按 Ctrl+C 停止监控");
            // TODO: 实现 monitor 逻辑
        }
        Commands::Overview => {
            println!("实时状态查询 (TODO)");
        }
        Commands::Timeline { session_id } => {
            println!("时间线: {} (TODO)", session_id);
        }
        Commands::Audit { verify } => {
            println!("审计链 (verify: {}) (TODO)", verify);
        }
    }
}

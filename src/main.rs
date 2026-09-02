use clap::{Parser, Subcommand};
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("supplyguard=info")
        .init();

    let cli = Cli::parse();

    let orchestrator = match Orchestrator::new().await {
        Ok(o) => o,
        Err(e) => {
            eprintln!("初始化失败: {}", e);
            std::process::exit(1);
        }
    };

    match cli.command {
        Commands::Scan { path, json, include_dev } => {
            println!("扫描目录: {} (include_dev: {})", path, include_dev);
            println!("JSON 输出: {}", json);
            // TODO: 实现 scan 逻辑
        }
        Commands::Guard { diff } => {
            println!("守门模式: {}", diff);
            // TODO: 实现 guard 逻辑
        }
        Commands::Monitor { path, include_dev } => {
            println!("监控目录: {} (include_dev: {})", path, include_dev);
            println!("按 Ctrl+C 停止监控");
            // TODO: 实现 monitor 逻辑
        }
        Commands::Overview => {
            println!("实时状态查询");
            // TODO: 实现 overview 逻辑
        }
        Commands::Timeline { session_id } => {
            println!("时间线: {}", session_id);
            // TODO: 实现 timeline 逻辑
        }
        Commands::Audit { verify } => {
            println!("审计链 (verify: {})", verify);
            // TODO: 实现 audit 逻辑
        }
    }
}

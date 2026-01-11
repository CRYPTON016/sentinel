//! Sentinel - Real-time ransomware detection and prevention for Linux servers
//!
//! # Usage
//!
//! ```bash
//! # Start the daemon
//! sudo sentinel start
//!
//! # Watch a directory
//! sudo sentinel watch /home/user/Documents
//!
//! # Check status
//! sudo sentinel status
//! ```

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, error};

mod config;
mod daemon;
mod detector;
mod response;
mod watcher;

#[cfg(feature = "ebpf")]
mod ebpf;

use config::Config;

#[derive(Parser)]
#[command(name = "sentinel")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/sentinel/config.yaml")]
    config: PathBuf,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Sentinel daemon
    Start {
        /// Run in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,
    },

    /// Stop the Sentinel daemon
    Stop,

    /// Restart the Sentinel daemon
    Restart,

    /// Check daemon status
    Status,

    /// Add a directory to watch
    Watch {
        /// Directory path to watch
        path: PathBuf,
    },

    /// Remove a directory from watch list
    Unwatch {
        /// Directory path to remove
        path: PathBuf,
    },

    /// Whitelist management
    Whitelist {
        #[command(subcommand)]
        action: WhitelistAction,
    },

    /// View activity logs
    Logs {
        /// Number of lines to show
        #[arg(short, long, default_value = "50")]
        lines: usize,

        /// Follow log output
        #[arg(short, long)]
        follow: bool,
    },

    /// Run integrity check (AIDE-like)
    Check {
        /// Only check specific path
        path: Option<PathBuf>,
    },

    /// Initialize baseline for integrity checking
    Baseline {
        /// Paths to include in baseline
        paths: Vec<PathBuf>,
    },

    /// Show configuration
    Config,
}

#[derive(Subcommand)]
enum WhitelistAction {
    /// Add process to whitelist
    Add {
        /// Process name or path
        process: String,
    },

    /// Remove process from whitelist
    Remove {
        /// Process name or path
        process: String,
    },

    /// List whitelisted processes
    List,
}

fn setup_logging(verbose: bool) {
    let filter = if verbose { "debug" } else { "info" };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    setup_logging(cli.verbose);

    // Load configuration
    let config = Config::load(&cli.config).unwrap_or_else(|e| {
        if cli.config.exists() {
            error!("Failed to load config: {}", e);
            std::process::exit(1);
        }
        info!("Using default configuration");
        Config::default()
    });

    match cli.command {
        Commands::Start { foreground } => {
            info!("Starting Sentinel daemon...");
            daemon::start(config, foreground).await?;
        }

        Commands::Stop => {
            info!("Stopping Sentinel daemon...");
            daemon::stop().await?;
        }

        Commands::Restart => {
            info!("Restarting Sentinel daemon...");
            daemon::stop().await?;
            daemon::start(config, false).await?;
        }

        Commands::Status => {
            daemon::status().await?;
        }

        Commands::Watch { path } => {
            info!("Adding watch: {:?}", path);
            daemon::send_command(daemon::Command::Watch(path)).await?;
        }

        Commands::Unwatch { path } => {
            info!("Removing watch: {:?}", path);
            daemon::send_command(daemon::Command::Unwatch(path)).await?;
        }

        Commands::Whitelist { action } => match action {
            WhitelistAction::Add { process } => {
                info!("Whitelisting process: {}", process);
                daemon::send_command(daemon::Command::WhitelistAdd(process)).await?;
            }
            WhitelistAction::Remove { process } => {
                info!("Removing from whitelist: {}", process);
                daemon::send_command(daemon::Command::WhitelistRemove(process)).await?;
            }
            WhitelistAction::List => {
                daemon::send_command(daemon::Command::WhitelistList).await?;
            }
        },

        Commands::Logs { lines, follow } => {
            daemon::show_logs(lines, follow).await?;
        }

        Commands::Check { path } => {
            info!("Running integrity check...");
            detector::aide::check(path.as_deref()).await?;
        }

        Commands::Baseline { paths } => {
            info!("Creating baseline...");
            detector::aide::create_baseline(&paths).await?;
        }

        Commands::Config => {
            println!("{}", serde_yaml::to_string(&config)?);
        }
    }

    Ok(())
}

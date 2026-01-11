//! Daemon management for Sentinel

use crate::config::Config;
use std::path::PathBuf;
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, error, warn};

/// Commands that can be sent to the daemon
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Command {
    /// Add a path to watch
    Watch(PathBuf),
    /// Remove a path from watching
    Unwatch(PathBuf),
    /// Add process to whitelist
    WhitelistAdd(String),
    /// Remove process from whitelist
    WhitelistRemove(String),
    /// List whitelisted processes
    WhitelistList,
    /// Get current status
    Status,
    /// Shutdown the daemon
    Shutdown,
}

/// Response from daemon
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Response {
    Ok,
    Error(String),
    Status(DaemonStatus),
    WhitelistEntries(Vec<String>),
}

/// Daemon status information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DaemonStatus {
    pub running: bool,
    pub pid: u32,
    pub uptime_secs: u64,
    pub watched_paths: Vec<PathBuf>,
    pub threats_blocked: u64,
    pub files_scanned: u64,
}

/// Start the Sentinel daemon
pub async fn start(config: Config, foreground: bool) -> anyhow::Result<()> {
    // Check if already running
    if is_running(&config).await {
        anyhow::bail!("Sentinel is already running");
    }

    if !foreground {
        // Daemonize
        daemonize(&config)?;
    }

    // Write PID file
    write_pid_file(&config.daemon.pid_file)?;

    // Setup signal handlers
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

    // Create Unix socket for IPC
    let _ = std::fs::remove_file(&config.daemon.socket);
    let listener = UnixListener::bind(&config.daemon.socket)?;

    info!("Sentinel daemon started, listening on {:?}", config.daemon.socket);

    // Create the main sentinel instance
    let mut sentinel = crate::Sentinel::new(config.clone())?;

    // Add configured watch paths
    for path in &config.watch {
        if let Err(e) = sentinel.watch(path) {
            warn!("Failed to watch {:?}: {}", path, e);
        }
    }

    // Main event loop
    loop {
        tokio::select! {
            // Handle incoming IPC commands
            Ok((stream, _)) = listener.accept() => {
                handle_client(stream, &mut sentinel).await?;
            }

            // Handle SIGTERM
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down...");
                break;
            }

            // Handle SIGINT
            _ = sigint.recv() => {
                info!("Received SIGINT, shutting down...");
                break;
            }
        }
    }

    // Cleanup
    cleanup(&config).await?;

    Ok(())
}

/// Stop the Sentinel daemon
pub async fn stop() -> anyhow::Result<()> {
    let config = Config::default();

    if !is_running(&config).await {
        println!("Sentinel is not running");
        return Ok(());
    }

    // Read PID and send SIGTERM
    let pid = read_pid_file(&config.daemon.pid_file)?;

    // Send SIGTERM
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid as i32),
        nix::sys::signal::Signal::SIGTERM,
    )?;

    println!("Sent shutdown signal to Sentinel (PID {})", pid);

    // Wait for process to exit
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if !is_running(&config).await {
            println!("Sentinel stopped");
            return Ok(());
        }
    }

    warn!("Sentinel did not stop gracefully, sending SIGKILL");
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid as i32),
        nix::sys::signal::Signal::SIGKILL,
    )?;

    Ok(())
}

/// Check daemon status
pub async fn status() -> anyhow::Result<()> {
    let config = Config::default();

    if !is_running(&config).await {
        println!("Sentinel is not running");
        return Ok(());
    }

    // Connect to daemon and get status
    match send_command(Command::Status).await {
        Ok(()) => {}
        Err(e) => {
            println!("Sentinel is running but not responding: {}", e);
        }
    }

    Ok(())
}

/// Send a command to the running daemon
pub async fn send_command(cmd: Command) -> anyhow::Result<()> {
    let config = Config::default();

    let mut stream = UnixStream::connect(&config.daemon.socket).await?;

    // Serialize and send command
    let cmd_bytes = serde_json::to_vec(&cmd)?;
    let len = cmd_bytes.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&cmd_bytes).await?;

    // Read response
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;

    let mut response_bytes = vec![0u8; len];
    stream.read_exact(&mut response_bytes).await?;

    let response: Response = serde_json::from_slice(&response_bytes)?;

    match response {
        Response::Ok => println!("OK"),
        Response::Error(e) => println!("Error: {}", e),
        Response::Status(status) => print_status(&status),
        Response::WhitelistEntries(entries) => {
            println!("Whitelisted processes:");
            for entry in entries {
                println!("  - {}", entry);
            }
        }
    }

    Ok(())
}

/// Show daemon logs
pub async fn show_logs(lines: usize, follow: bool) -> anyhow::Result<()> {
    let config = Config::default();
    let log_path = &config.daemon.log_file;

    if !log_path.exists() {
        println!("No log file found at {:?}", log_path);
        return Ok(());
    }

    if follow {
        // Use tail -f equivalent
        let mut cmd = tokio::process::Command::new("tail")
            .args(["-f", "-n", &lines.to_string()])
            .arg(log_path)
            .spawn()?;

        cmd.wait().await?;
    } else {
        // Just print last N lines
        let output = tokio::process::Command::new("tail")
            .args(["-n", &lines.to_string()])
            .arg(log_path)
            .output()
            .await?;

        print!("{}", String::from_utf8_lossy(&output.stdout));
    }

    Ok(())
}

// Helper functions

async fn handle_client(mut stream: UnixStream, sentinel: &mut crate::Sentinel) -> anyhow::Result<()> {
    // Read command length
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;

    // Read command
    let mut cmd_bytes = vec![0u8; len];
    stream.read_exact(&mut cmd_bytes).await?;

    let cmd: Command = serde_json::from_slice(&cmd_bytes)?;

    // Process command
    let response = match cmd {
        Command::Watch(path) => {
            match sentinel.watch(&path) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Command::Unwatch(path) => {
            match sentinel.unwatch(&path) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Command::WhitelistAdd(_process) => {
            // TODO: Implement whitelist modification
            Response::Ok
        }
        Command::WhitelistRemove(_process) => {
            // TODO: Implement whitelist modification
            Response::Ok
        }
        Command::WhitelistList => {
            Response::WhitelistEntries(sentinel.config().whitelist.processes.clone())
        }
        Command::Status => {
            Response::Status(DaemonStatus {
                running: true,
                pid: std::process::id(),
                uptime_secs: 0, // TODO: Track uptime
                watched_paths: sentinel.config().watch.clone(),
                threats_blocked: 0, // TODO: Track stats
                files_scanned: 0,
            })
        }
        Command::Shutdown => {
            std::process::exit(0);
        }
    };

    // Send response
    let response_bytes = serde_json::to_vec(&response)?;
    let len = response_bytes.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&response_bytes).await?;

    Ok(())
}

fn daemonize(config: &Config) -> anyhow::Result<()> {
    use daemonize::Daemonize;

    let stdout = std::fs::File::create(&config.daemon.log_file)?;
    let stderr = stdout.try_clone()?;

    let daemonize = Daemonize::new()
        .pid_file(&config.daemon.pid_file)
        .working_directory("/")
        .stdout(stdout)
        .stderr(stderr);

    daemonize.start()?;

    Ok(())
}

fn write_pid_file(path: &std::path::Path) -> anyhow::Result<()> {
    let pid = std::process::id();
    std::fs::write(path, pid.to_string())?;
    Ok(())
}

fn read_pid_file(path: &std::path::Path) -> anyhow::Result<u32> {
    let content = std::fs::read_to_string(path)?;
    let pid: u32 = content.trim().parse()?;
    Ok(pid)
}

async fn is_running(config: &Config) -> bool {
    if !config.daemon.pid_file.exists() {
        return false;
    }

    if let Ok(pid) = read_pid_file(&config.daemon.pid_file) {
        // Check if process exists
        let proc_path = format!("/proc/{}", pid);
        return std::path::Path::new(&proc_path).exists();
    }

    false
}

async fn cleanup(config: &Config) -> anyhow::Result<()> {
    let _ = std::fs::remove_file(&config.daemon.pid_file);
    let _ = std::fs::remove_file(&config.daemon.socket);
    Ok(())
}

fn print_status(status: &DaemonStatus) {
    println!("Sentinel Status");
    println!("───────────────────────────────");
    println!("Status:          {}", if status.running { "● Running" } else { "○ Stopped" });
    println!("PID:             {}", status.pid);
    println!("Uptime:          {} seconds", status.uptime_secs);
    println!("Watched paths:   {}", status.watched_paths.len());
    for path in &status.watched_paths {
        println!("                 - {:?}", path);
    }
    println!("Files scanned:   {}", status.files_scanned);
    println!("Threats blocked: {}", status.threats_blocked);
}

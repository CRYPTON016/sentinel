//! Process freezing (SIGSTOP) for threat response

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tracing::{info, warn};

/// Freeze a process by sending SIGSTOP
pub fn freeze_process(pid: u32) -> anyhow::Result<()> {
    let pid = Pid::from_raw(pid as i32);

    signal::kill(pid, Signal::SIGSTOP)?;

    info!("Froze process {}", pid);

    Ok(())
}

/// Unfreeze a process by sending SIGCONT
pub fn unfreeze_process(pid: u32) -> anyhow::Result<()> {
    let pid = Pid::from_raw(pid as i32);

    signal::kill(pid, Signal::SIGCONT)?;

    info!("Unfroze process {}", pid);

    Ok(())
}

/// Kill a process by sending SIGKILL
pub fn kill_process(pid: u32) -> anyhow::Result<()> {
    let pid = Pid::from_raw(pid as i32);

    signal::kill(pid, Signal::SIGKILL)?;

    warn!("Killed process {}", pid);

    Ok(())
}

/// Check if a process is frozen
pub fn is_frozen(pid: u32) -> anyhow::Result<bool> {
    let stat_path = format!("/proc/{}/stat", pid);
    let stat = std::fs::read_to_string(stat_path)?;

    // State is the third field, wrapped in parentheses for the command
    // Format: pid (comm) state ...
    // State 'T' means stopped (frozen)
    let parts: Vec<&str> = stat.split(')').collect();
    if parts.len() >= 2 {
        let state_part = parts[1].trim();
        if let Some(state_char) = state_part.chars().next() {
            return Ok(state_char == 'T');
        }
    }

    Ok(false)
}

/// Get process info for logging
pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
    let comm_path = format!("/proc/{}/comm", pid);
    let exe_path = format!("/proc/{}/exe", pid);
    let cmdline_path = format!("/proc/{}/cmdline", pid);

    let comm = std::fs::read_to_string(comm_path).ok()?.trim().to_string();
    let exe = std::fs::read_link(exe_path).ok();
    let cmdline = std::fs::read_to_string(cmdline_path)
        .ok()
        .map(|s| s.replace('\0', " ").trim().to_string());

    Some(ProcessInfo {
        pid,
        comm,
        exe,
        cmdline,
    })
}

/// Information about a process
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub comm: String,
    pub exe: Option<std::path::PathBuf>,
    pub cmdline: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_process_info() {
        // Get info about current process
        let pid = std::process::id();
        let info = get_process_info(pid);
        assert!(info.is_some());

        let info = info.unwrap();
        assert_eq!(info.pid, pid);
        assert!(!info.comm.is_empty());
    }
}

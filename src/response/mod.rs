//! Threat response module

mod freeze;
mod alert;

pub use freeze::freeze_process;
pub use alert::send_alert;

use crate::config::Config;
use crate::detector::{Threat, ThreatLevel, ThreatType};
use tracing::{info, warn, error};

/// Response action to take
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseAction {
    /// Allow the operation
    Allow,
    /// Log but allow
    LogAndAllow,
    /// Alert user but allow
    AlertAndAllow,
    /// Block and freeze process
    BlockAndFreeze,
    /// Block, freeze, and snapshot
    BlockFreezeSnapshot,
}

/// Response result
#[derive(Debug, Clone)]
pub struct Response {
    /// Action that was taken
    pub action: ResponseAction,
    /// Whether the threat was neutralized
    pub neutralized: bool,
    /// Message describing what happened
    pub message: String,
}

/// Handle a detected threat
pub async fn handle(threat: Threat, config: &Config) -> anyhow::Result<Response> {
    // Determine action based on threat level
    let action = determine_action(&threat);

    info!(
        "Threat detected: {:?} on {:?} (level: {:?})",
        threat.threat_type, threat.path, threat.level
    );

    let response = match action {
        ResponseAction::Allow => {
            Response {
                action,
                neutralized: false,
                message: "Allowed (below threshold)".to_string(),
            }
        }

        ResponseAction::LogAndAllow => {
            info!("Suspicious activity: {}", threat.details);
            Response {
                action,
                neutralized: false,
                message: format!("Logged: {}", threat.details),
            }
        }

        ResponseAction::AlertAndAllow => {
            send_alert(&threat, config).await?;
            Response {
                action,
                neutralized: false,
                message: format!("Alert sent: {}", threat.details),
            }
        }

        ResponseAction::BlockAndFreeze => {
            // Freeze the process
            if let Some(pid) = threat.pid {
                match freeze_process(pid) {
                    Ok(()) => {
                        info!("Froze process {} ({})", pid, threat.process_name.as_deref().unwrap_or("unknown"));
                    }
                    Err(e) => {
                        error!("Failed to freeze process {}: {}", pid, e);
                    }
                }
            }

            // Send alert
            send_alert(&threat, config).await?;

            Response {
                action,
                neutralized: threat.pid.is_some(),
                message: format!("BLOCKED: {} - Process frozen", threat.details),
            }
        }

        ResponseAction::BlockFreezeSnapshot => {
            // Create snapshot before freezing
            if let Err(e) = create_snapshot(&threat.path).await {
                warn!("Failed to create snapshot: {}", e);
            }

            // Freeze the process
            if let Some(pid) = threat.pid {
                match freeze_process(pid) {
                    Ok(()) => {
                        info!("Froze process {} ({})", pid, threat.process_name.as_deref().unwrap_or("unknown"));
                    }
                    Err(e) => {
                        error!("Failed to freeze process {}: {}", pid, e);
                    }
                }
            }

            // Send alert
            send_alert(&threat, config).await?;

            Response {
                action,
                neutralized: threat.pid.is_some(),
                message: format!("BLOCKED with snapshot: {} - Process frozen", threat.details),
            }
        }
    };

    Ok(response)
}

/// Determine the appropriate action for a threat
fn determine_action(threat: &Threat) -> ResponseAction {
    match (&threat.level, &threat.threat_type) {
        // Canary triggered = always block
        (_, ThreatType::CanaryTriggered) => ResponseAction::BlockAndFreeze,

        // Critical threats = block
        (ThreatLevel::Critical, _) => ResponseAction::BlockAndFreeze,

        // Suspicious = alert but allow
        (ThreatLevel::Suspicious, _) => ResponseAction::AlertAndAllow,

        // Safe = log only
        (ThreatLevel::Safe, _) => ResponseAction::LogAndAllow,
    }
}

/// Create a backup snapshot of a file before potential damage
async fn create_snapshot(path: &std::path::Path) -> anyhow::Result<()> {
    if !path.exists() {
        return Ok(());
    }

    // Create snapshot directory
    let snapshot_dir = std::path::PathBuf::from("/var/lib/sentinel/snapshots");
    std::fs::create_dir_all(&snapshot_dir)?;

    // Generate snapshot filename with timestamp
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let file_name = path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    let snapshot_path = snapshot_dir.join(format!("{}_{}", timestamp, file_name));

    // Copy file to snapshot
    std::fs::copy(path, &snapshot_path)?;

    info!("Created snapshot: {:?}", snapshot_path);

    Ok(())
}

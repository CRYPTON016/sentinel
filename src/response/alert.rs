//! Alert notifications for threat response

use crate::config::Config;
use crate::detector::Threat;
use tracing::{info, warn, error};

/// Send alert through configured channels
pub async fn send_alert(threat: &Threat, config: &Config) -> anyhow::Result<()> {
    // Desktop notification
    if config.alerts.desktop {
        if let Err(e) = send_desktop_notification(threat) {
            warn!("Failed to send desktop notification: {}", e);
        }
    }

    // Webhook
    if let Some(ref url) = config.alerts.webhook {
        if let Err(e) = send_webhook(threat, url).await {
            warn!("Failed to send webhook: {}", e);
        }
    }

    // Slack
    if let Some(ref url) = config.alerts.slack {
        if let Err(e) = send_slack(threat, url).await {
            warn!("Failed to send Slack alert: {}", e);
        }
    }

    // Email
    if let Some(ref email) = config.alerts.email {
        if let Err(e) = send_email(threat, email).await {
            warn!("Failed to send email: {}", e);
        }
    }

    Ok(())
}

/// Send desktop notification
fn send_desktop_notification(threat: &Threat) -> anyhow::Result<()> {
    let title = match threat.level {
        crate::detector::ThreatLevel::Critical => "🚨 RANSOMWARE DETECTED",
        crate::detector::ThreatLevel::Suspicious => "⚠️ Suspicious Activity",
        crate::detector::ThreatLevel::Safe => "ℹ️ Security Notice",
    };

    let body = format!(
        "Process: {} (PID {})\n\
         File: {:?}\n\
         Details: {}",
        threat.process_name.as_deref().unwrap_or("unknown"),
        threat.pid.map(|p| p.to_string()).unwrap_or_else(|| "unknown".to_string()),
        threat.path,
        threat.details
    );

    notify_rust::Notification::new()
        .summary(title)
        .body(&body)
        .icon("dialog-warning")
        .urgency(notify_rust::Urgency::Critical)
        .timeout(notify_rust::Timeout::Never)
        .show()?;

    info!("Sent desktop notification");

    Ok(())
}

/// Send webhook notification
#[cfg(feature = "reqwest")]
async fn send_webhook(threat: &Threat, url: &str) -> anyhow::Result<()> {
    let payload = serde_json::json!({
        "level": format!("{:?}", threat.level),
        "threat_type": format!("{:?}", threat.threat_type),
        "path": threat.path,
        "pid": threat.pid,
        "process_name": threat.process_name,
        "details": threat.details,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let client = reqwest::Client::new();
    client
        .post(url)
        .json(&payload)
        .send()
        .await?;

    info!("Sent webhook notification to {}", url);

    Ok(())
}

#[cfg(not(feature = "reqwest"))]
async fn send_webhook(_threat: &Threat, _url: &str) -> anyhow::Result<()> {
    warn!("Webhook support not compiled in (requires 'reqwest' feature)");
    Ok(())
}

/// Send Slack notification
#[cfg(feature = "reqwest")]
async fn send_slack(threat: &Threat, webhook_url: &str) -> anyhow::Result<()> {
    let color = match threat.level {
        crate::detector::ThreatLevel::Critical => "#FF0000",
        crate::detector::ThreatLevel::Suspicious => "#FFA500",
        crate::detector::ThreatLevel::Safe => "#00FF00",
    };

    let payload = serde_json::json!({
        "attachments": [{
            "color": color,
            "title": format!("🛡️ Sentinel Alert: {:?}", threat.level),
            "fields": [
                {
                    "title": "Threat Type",
                    "value": format!("{:?}", threat.threat_type),
                    "short": true
                },
                {
                    "title": "Process",
                    "value": threat.process_name.as_deref().unwrap_or("unknown"),
                    "short": true
                },
                {
                    "title": "PID",
                    "value": threat.pid.map(|p| p.to_string()).unwrap_or_else(|| "unknown".to_string()),
                    "short": true
                },
                {
                    "title": "File",
                    "value": threat.path.display().to_string(),
                    "short": false
                },
                {
                    "title": "Details",
                    "value": &threat.details,
                    "short": false
                }
            ],
            "footer": "Sentinel Ransomware Protection",
            "ts": chrono::Utc::now().timestamp()
        }]
    });

    let client = reqwest::Client::new();
    client
        .post(webhook_url)
        .json(&payload)
        .send()
        .await?;

    info!("Sent Slack notification");

    Ok(())
}

#[cfg(not(feature = "reqwest"))]
async fn send_slack(_threat: &Threat, _url: &str) -> anyhow::Result<()> {
    warn!("Slack support not compiled in (requires 'reqwest' feature)");
    Ok(())
}

/// Send email notification
async fn send_email(threat: &Threat, _email: &str) -> anyhow::Result<()> {
    // Email sending would require additional dependencies (lettre, etc.)
    // For now, just log that we would send an email
    error!(
        "Email alerts not yet implemented. Would send to: {} about threat on {:?}",
        _email, threat.path
    );

    Ok(())
}

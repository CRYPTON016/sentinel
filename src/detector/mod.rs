//! Threat detection module

pub mod entropy;
pub mod header;
pub mod velocity;
pub mod canary;
pub mod aide;

use crate::config::Config;
use crate::watcher::FileEvent;
use std::path::Path;

/// Threat level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatLevel {
    /// No threat detected
    Safe,
    /// Suspicious activity, monitor closely
    Suspicious,
    /// High probability threat, take action
    Critical,
}

/// Detected threat information
#[derive(Debug, Clone)]
pub struct Threat {
    /// Severity level
    pub level: ThreatLevel,
    /// Type of threat detected
    pub threat_type: ThreatType,
    /// Path of affected file
    pub path: std::path::PathBuf,
    /// Process ID responsible
    pub pid: Option<u32>,
    /// Process name
    pub process_name: Option<String>,
    /// Additional details
    pub details: String,
}

/// Type of threat detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatType {
    /// High entropy transition (encryption)
    EntropySpike,
    /// File header destroyed
    HeaderDestroyed,
    /// Mass file modification
    VelocityExceeded,
    /// Canary file touched
    CanaryTriggered,
    /// Integrity baseline mismatch
    IntegrityViolation,
}

/// Main detector engine
pub struct Detector {
    config: Config,
    velocity_tracker: velocity::VelocityTracker,
    entropy_cache: std::collections::HashMap<std::path::PathBuf, f64>,
}

impl Detector {
    /// Create a new detector
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        Ok(Self {
            config: config.clone(),
            velocity_tracker: velocity::VelocityTracker::new(config.detection.velocity_limit),
            entropy_cache: std::collections::HashMap::new(),
        })
    }

    /// Analyze a file event for threats
    pub async fn analyze(&mut self, event: &FileEvent) -> anyhow::Result<Option<Threat>> {
        let path = &event.path;

        // Skip excluded paths
        if self.config.is_excluded(path) {
            return Ok(None);
        }

        // Check if process is whitelisted
        if let Some(ref process_name) = event.process_name {
            if self.config.is_whitelisted(process_name) {
                return Ok(None);
            }
        }

        // Check 1: Canary file
        if canary::is_canary(path, &self.config.detection.canary_prefix) {
            return Ok(Some(Threat {
                level: ThreatLevel::Critical,
                threat_type: ThreatType::CanaryTriggered,
                path: path.clone(),
                pid: event.pid,
                process_name: event.process_name.clone(),
                details: "Canary file was accessed - 100% malware indicator".to_string(),
            }));
        }

        // Check 2: Velocity (rate limiting)
        if let Some(pid) = event.pid {
            if self.velocity_tracker.check(pid) == ThreatLevel::Critical {
                return Ok(Some(Threat {
                    level: ThreatLevel::Critical,
                    threat_type: ThreatType::VelocityExceeded,
                    path: path.clone(),
                    pid: Some(pid),
                    process_name: event.process_name.clone(),
                    details: format!(
                        "Process exceeded {} high-entropy writes per minute",
                        self.config.detection.velocity_limit
                    ),
                }));
            }
        }

        // Check 3: Read file content for entropy and header checks
        if let Ok(content) = std::fs::read(path) {
            // Check header validity
            if let Some(threat) = self.check_header(path, &content, event) {
                return Ok(Some(threat));
            }

            // Check entropy
            if let Some(threat) = self.check_entropy(path, &content, event).await {
                // Update velocity tracker for high-entropy writes
                if let Some(pid) = event.pid {
                    self.velocity_tracker.record_high_entropy(pid);
                }
                return Ok(Some(threat));
            }
        }

        Ok(None)
    }

    /// Check file header validity
    fn check_header(&self, path: &Path, content: &[u8], event: &FileEvent) -> Option<Threat> {
        if let Some(threat_level) = header::validate(path, content) {
            if threat_level == ThreatLevel::Critical {
                return Some(Threat {
                    level: ThreatLevel::Critical,
                    threat_type: ThreatType::HeaderDestroyed,
                    path: path.to_path_buf(),
                    pid: event.pid,
                    process_name: event.process_name.clone(),
                    details: "File header does not match extension - likely encrypted".to_string(),
                });
            }
        }
        None
    }

    /// Check entropy transition
    async fn check_entropy(&mut self, path: &Path, content: &[u8], event: &FileEvent) -> Option<Threat> {
        let new_entropy = entropy::calculate(content);

        // Get cached entropy (if we've seen this file before)
        let old_entropy = self.entropy_cache.get(path).copied();

        // Update cache
        self.entropy_cache.insert(path.to_path_buf(), new_entropy);

        // Check for low → high transition
        if let Some(old) = old_entropy {
            if old < self.config.detection.entropy_low && new_entropy > self.config.detection.entropy_high {
                return Some(Threat {
                    level: ThreatLevel::Critical,
                    threat_type: ThreatType::EntropySpike,
                    path: path.to_path_buf(),
                    pid: event.pid,
                    process_name: event.process_name.clone(),
                    details: format!(
                        "Entropy spike: {:.2} → {:.2} (threshold: {:.2})",
                        old, new_entropy, self.config.detection.entropy_high
                    ),
                });
            }
        } else {
            // First time seeing this file, just check if already high entropy
            // (might be legitimately encrypted, but flag for review)
            if new_entropy > self.config.detection.entropy_high {
                return Some(Threat {
                    level: ThreatLevel::Suspicious,
                    threat_type: ThreatType::EntropySpike,
                    path: path.to_path_buf(),
                    pid: event.pid,
                    process_name: event.process_name.clone(),
                    details: format!(
                        "New high-entropy file detected: {:.2}",
                        new_entropy
                    ),
                });
            }
        }

        None
    }
}

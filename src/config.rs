//! Configuration management for Sentinel

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Directories to watch
    #[serde(default)]
    pub watch: Vec<PathBuf>,

    /// Paths/patterns to exclude
    #[serde(default)]
    pub exclude: Vec<String>,

    /// Process whitelist configuration
    #[serde(default)]
    pub whitelist: WhitelistConfig,

    /// Alert configuration
    #[serde(default)]
    pub alerts: AlertConfig,

    /// AIDE-like integrity checking
    #[serde(default)]
    pub aide: AideConfig,

    /// Detection thresholds
    #[serde(default)]
    pub detection: DetectionConfig,

    /// Daemon configuration
    #[serde(default)]
    pub daemon: DaemonConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            watch: vec![
                PathBuf::from("/home"),
                PathBuf::from("/etc"),
                PathBuf::from("/var/www"),
            ],
            exclude: vec![
                "*.log".to_string(),
                "*.tmp".to_string(),
                "/tmp/**".to_string(),
                "/var/log/**".to_string(),
            ],
            whitelist: WhitelistConfig::default(),
            alerts: AlertConfig::default(),
            aide: AideConfig::default(),
            detection: DetectionConfig::default(),
            daemon: DaemonConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from file
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Save configuration to file
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let content = serde_yaml::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Check if a path should be excluded
    pub fn is_excluded(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        for pattern in &self.exclude {
            if let Ok(glob) = globset::Glob::new(pattern) {
                let matcher = glob.compile_matcher();
                if matcher.is_match(path) {
                    return true;
                }
            }
            // Simple string matching fallback
            if path_str.contains(pattern.trim_matches('*')) {
                return true;
            }
        }
        false
    }

    /// Check if a process is whitelisted
    pub fn is_whitelisted(&self, process_name: &str) -> bool {
        self.whitelist.processes.iter().any(|p| {
            if p.ends_with('*') {
                process_name.starts_with(p.trim_end_matches('*'))
            } else {
                process_name == p
            }
        })
    }
}

/// Whitelist configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WhitelistConfig {
    /// Whitelisted process names
    #[serde(default)]
    pub processes: Vec<String>,

    /// Whitelisted paths (executables)
    #[serde(default)]
    pub paths: Vec<PathBuf>,
}

/// Alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable desktop notifications
    #[serde(default = "default_true")]
    pub desktop: bool,

    /// Webhook URL for alerts
    pub webhook: Option<String>,

    /// Email for alerts
    pub email: Option<String>,

    /// Slack webhook
    pub slack: Option<String>,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            desktop: true,
            webhook: None,
            email: None,
            slack: None,
        }
    }
}

/// AIDE-like integrity checking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AideConfig {
    /// Enable AIDE-like scanning
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Paths to include in baseline
    #[serde(default)]
    pub paths: Vec<PathBuf>,

    /// Cron schedule for scans
    #[serde(default = "default_schedule")]
    pub schedule: String,

    /// Database path
    #[serde(default = "default_db_path")]
    pub database: PathBuf,
}

impl Default for AideConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            paths: vec![
                PathBuf::from("/etc"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/usr/sbin"),
            ],
            schedule: "0 3 * * *".to_string(),
            database: PathBuf::from("/var/lib/sentinel/aide.db"),
        }
    }
}

/// Detection thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Entropy threshold for high-entropy detection (0.0 - 8.0)
    #[serde(default = "default_entropy_high")]
    pub entropy_high: f64,

    /// Entropy threshold for low-entropy (normal files)
    #[serde(default = "default_entropy_low")]
    pub entropy_low: f64,

    /// Maximum high-entropy writes per process per minute
    #[serde(default = "default_velocity_limit")]
    pub velocity_limit: u32,

    /// Enable canary files
    #[serde(default = "default_true")]
    pub canary_enabled: bool,

    /// Canary file prefix
    #[serde(default = "default_canary_prefix")]
    pub canary_prefix: String,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            entropy_high: 7.8,
            entropy_low: 6.0,
            velocity_limit: 10,
            canary_enabled: true,
            canary_prefix: ".sentinel_canary_".to_string(),
        }
    }
}

/// Daemon configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// PID file path
    #[serde(default = "default_pid_path")]
    pub pid_file: PathBuf,

    /// Socket path for IPC
    #[serde(default = "default_socket_path")]
    pub socket: PathBuf,

    /// Log file path
    #[serde(default = "default_log_path")]
    pub log_file: PathBuf,

    /// Run as user (after dropping privileges)
    pub user: Option<String>,

    /// Run as group
    pub group: Option<String>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            pid_file: PathBuf::from("/run/sentinel.pid"),
            socket: PathBuf::from("/run/sentinel.sock"),
            log_file: PathBuf::from("/var/log/sentinel.log"),
            user: None,
            group: None,
        }
    }
}

// Default value functions for serde
fn default_true() -> bool {
    true
}

fn default_schedule() -> String {
    "0 3 * * *".to_string()
}

fn default_db_path() -> PathBuf {
    PathBuf::from("/var/lib/sentinel/aide.db")
}

fn default_entropy_high() -> f64 {
    7.8
}

fn default_entropy_low() -> f64 {
    6.0
}

fn default_velocity_limit() -> u32 {
    10
}

fn default_canary_prefix() -> String {
    ".sentinel_canary_".to_string()
}

fn default_pid_path() -> PathBuf {
    PathBuf::from("/run/sentinel.pid")
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/sentinel.sock")
}

fn default_log_path() -> PathBuf {
    PathBuf::from("/var/log/sentinel.log")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(!config.watch.is_empty());
        assert!(config.detection.entropy_high > config.detection.entropy_low);
    }

    #[test]
    fn test_is_excluded() {
        let config = Config::default();
        assert!(config.is_excluded(Path::new("/tmp/test.txt")));
        assert!(config.is_excluded(Path::new("/var/log/syslog")));
        assert!(!config.is_excluded(Path::new("/home/user/document.pdf")));
    }

    #[test]
    fn test_is_whitelisted() {
        let mut config = Config::default();
        config.whitelist.processes = vec!["firefox".to_string(), "python*".to_string()];

        assert!(config.is_whitelisted("firefox"));
        assert!(config.is_whitelisted("python3"));
        assert!(config.is_whitelisted("python3.11"));
        assert!(!config.is_whitelisted("malware"));
    }
}

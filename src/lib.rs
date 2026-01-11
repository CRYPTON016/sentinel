//! Sentinel - Real-time ransomware detection and prevention library
//!
//! This library provides the core functionality for detecting and preventing
//! ransomware attacks on Linux systems using entropy analysis, eBPF tracing,
//! and fanotify-based file system monitoring.
//!
//! # Features
//!
//! - **Entropy Detection** - Detect files transitioning from low to high entropy
//! - **eBPF Tracing** - Kernel-level process context tracking
//! - **fanotify Gating** - Block malicious writes before they complete
//! - **AIDE Integration** - Periodic baseline integrity verification
//!
//! # Example
//!
//! ```rust,no_run
//! use sentinel::{Config, Sentinel};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = Config::default();
//!     let sentinel = Sentinel::new(config)?;
//!
//!     sentinel.watch("/home/user/Documents")?;
//!     sentinel.run().await?;
//!
//!     Ok(())
//! }
//! ```

pub mod config;
pub mod daemon;
pub mod detector;
pub mod response;
pub mod watcher;

#[cfg(feature = "ebpf")]
pub mod ebpf;

pub use config::Config;
pub use detector::{entropy, Detector, ThreatLevel};
pub use response::{Response, ResponseAction};
pub use watcher::Watcher;

/// Main Sentinel engine
pub struct Sentinel {
    config: Config,
    watcher: Watcher,
    detector: Detector,
}

impl Sentinel {
    /// Create a new Sentinel instance
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let watcher = Watcher::new(&config)?;
        let detector = Detector::new(&config)?;

        Ok(Self {
            config,
            watcher,
            detector,
        })
    }

    /// Add a path to watch
    pub fn watch<P: AsRef<std::path::Path>>(&mut self, path: P) -> anyhow::Result<()> {
        self.watcher.add(path.as_ref())
    }

    /// Remove a path from watching
    pub fn unwatch<P: AsRef<std::path::Path>>(&mut self, path: P) -> anyhow::Result<()> {
        self.watcher.remove(path.as_ref())
    }

    /// Run the Sentinel event loop
    pub async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            if let Some(event) = self.watcher.next_event().await? {
                if let Some(threat) = self.detector.analyze(&event).await? {
                    response::handle(threat, &self.config).await?;
                }
            }
        }
    }

    /// Get current configuration
    pub fn config(&self) -> &Config {
        &self.config
    }
}

//! File system watching module
//!
//! Uses inotify for fast event notification and fanotify for
//! permission-based blocking.

mod inotify_watcher;
mod fanotify_watcher;

pub use inotify_watcher::InotifyWatcher;
pub use fanotify_watcher::FanotifyWatcher;

use std::path::{Path, PathBuf};
use crate::config::Config;

/// File system event
#[derive(Debug, Clone)]
pub struct FileEvent {
    /// Path of the affected file
    pub path: PathBuf,
    /// Type of event
    pub event_type: EventType,
    /// Process ID that caused the event (if available)
    pub pid: Option<u32>,
    /// Process name (if available)
    pub process_name: Option<String>,
    /// File descriptor (for fanotify responses)
    pub fd: Option<i32>,
}

/// Type of file system event
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// File was created
    Create,
    /// File was modified
    Modify,
    /// File was deleted
    Delete,
    /// File was renamed
    Rename,
    /// File was opened for writing
    OpenWrite,
    /// File was closed after writing
    CloseWrite,
    /// Access permission request (fanotify)
    AccessRequest,
}

/// Unified file system watcher
pub struct Watcher {
    /// inotify watcher for events
    inotify: InotifyWatcher,
    /// fanotify watcher for blocking (if available)
    #[cfg(feature = "fanotify")]
    fanotify: Option<FanotifyWatcher>,
    /// Watched paths
    watched_paths: Vec<PathBuf>,
}

impl Watcher {
    /// Create a new watcher
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        let inotify = InotifyWatcher::new()?;

        #[cfg(feature = "fanotify")]
        let fanotify = match FanotifyWatcher::new() {
            Ok(f) => Some(f),
            Err(e) => {
                tracing::warn!("fanotify not available: {} - falling back to inotify only", e);
                None
            }
        };

        let mut watcher = Self {
            inotify,
            #[cfg(feature = "fanotify")]
            fanotify,
            watched_paths: Vec::new(),
        };

        // Add configured watch paths
        for path in &config.watch {
            if let Err(e) = watcher.add(path) {
                tracing::warn!("Failed to watch {:?}: {}", path, e);
            }
        }

        Ok(watcher)
    }

    /// Add a path to watch
    pub fn add(&mut self, path: &Path) -> anyhow::Result<()> {
        self.inotify.add(path)?;

        #[cfg(feature = "fanotify")]
        if let Some(ref mut f) = self.fanotify {
            f.add(path)?;
        }

        self.watched_paths.push(path.to_path_buf());
        tracing::info!("Watching: {:?}", path);

        Ok(())
    }

    /// Remove a path from watching
    pub fn remove(&mut self, path: &Path) -> anyhow::Result<()> {
        self.inotify.remove(path)?;

        #[cfg(feature = "fanotify")]
        if let Some(ref mut f) = self.fanotify {
            f.remove(path)?;
        }

        self.watched_paths.retain(|p| p != path);
        tracing::info!("Unwatched: {:?}", path);

        Ok(())
    }

    /// Get next file system event
    pub async fn next_event(&mut self) -> anyhow::Result<Option<FileEvent>> {
        // Prefer fanotify if available (can block writes)
        #[cfg(feature = "fanotify")]
        if let Some(ref mut f) = self.fanotify {
            if let Some(event) = f.next_event().await? {
                return Ok(Some(event));
            }
        }

        // Fall back to inotify
        self.inotify.next_event().await
    }

    /// Allow a pending write (for fanotify)
    #[cfg(feature = "fanotify")]
    pub fn allow(&mut self, event: &FileEvent) -> anyhow::Result<()> {
        if let Some(ref mut f) = self.fanotify {
            f.allow(event)?;
        }
        Ok(())
    }

    /// Deny a pending write (for fanotify)
    #[cfg(feature = "fanotify")]
    pub fn deny(&mut self, event: &FileEvent) -> anyhow::Result<()> {
        if let Some(ref mut f) = self.fanotify {
            f.deny(event)?;
        }
        Ok(())
    }

    /// Get list of watched paths
    pub fn watched_paths(&self) -> &[PathBuf] {
        &self.watched_paths
    }
}
